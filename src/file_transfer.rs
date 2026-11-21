use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::ReadyServer;
use crate::auth::ClientIdentity;
use crate::file_store::{UploadLimits, UploadStore};
use crate::file_wire::{UploadErrorCode, UploadId, UploadRequest, UploadResponse};

/// Resource limits for the server-side file-transfer service.
///
/// Reservations include completed uploads until explicitly discarded.
/// These are logical byte reservations, not physical disk allocation.
#[derive(Debug, Clone, Copy)]
pub struct FileTransferLimits {
    pub max_file_size: u64,
    pub max_reserved_bytes: u64,
    pub max_uploads: usize,
    pub max_uploads_per_owner: usize,
}

/// Result of an explicit idle-upload cleanup pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FileCleanupReport {
    pub attempted: usize,
    pub removed: usize,
    pub failed: usize,
    pub released_bytes: u64,
}

/// Server-side chunked file uploads over authenticated BRN connections.
///
/// Keep one service alive across connections so an authenticated client
/// can resume an upload using its retained upload ID.
///
/// # Authorization and ownership
///
/// Every network request requires application authorization through
/// `serve_one`. Each upload is additionally bound to the authenticated
/// identity that created it. Possession of an upload ID alone does not
/// grant access.
///
/// The storage directory and its parents must be protected from
/// untrusted modification. File paths are never supplied by the
/// file-transfer wire protocol.
///
/// # Chunk acknowledgements
///
/// Chunks are sequential. The server accepts a chunk only at the
/// upload's current confirmed offset and within its declared size.
///
/// Before returning a successful chunk response, the server writes
/// the chunk, successfully calls `File::sync_all`, and commits the
/// confirmed offset in memory.
///
/// This is not a restart-recovery guarantee. Upload ownership,
/// expected digest, confirmed offsets, and lifecycle metadata are
/// not persisted by this version.
///
/// # Interrupted operations
///
/// Storage side effects can occur before a response is lost or a
/// timeout is reported. After an uncertain chunk result, reconnect,
/// authenticate, establish fresh application keys, and query status
/// before choosing which bytes to send next.
///
/// Do not blindly replay a chunk or infer its confirmed offset from
/// the stored file length.
///
/// A lost Begin response can leave an abandoned upload whose
/// server-generated ID is unknown to the client.
///
/// # Completion
///
/// Finish starts background whole-file size and SHA-256 verification.
/// Verifying is not success. Complete is returned only after the
/// measured size and digest match the upload's expected metadata.
///
/// Complete does not publish the file, provide access to its contents,
/// or make the upload recoverable after a server restart.
///
/// # Resource management
///
/// Limits reserve declared file sizes and upload slots, including
/// completed uploads. These are logical reservations, not physical
/// disk-space allocation.
///
/// Call `cleanup_idle` periodically to remove idle incomplete uploads.
/// No automatic expiration thread is started. Status polling does not
/// renew an upload's idle interval.
///
/// Uploads awaiting verification and completed uploads are excluded
/// from idle cleanup. Use `discard_completed` to delete completed
/// uploads and release their reservations.
///
/// Failed deletion retains registry metadata and reservations for
/// retry.
///
/// # Blocking work and shutdown
///
/// File creation, chunk writes, synchronization, and deletion perform
/// synchronous filesystem I/O. Whole-file verification runs on one
/// background worker with bounded queues.
///
/// Socket deadlines cannot interrupt a blocked filesystem operation.
///
/// Dropping the service does not delete stored files or wait for
/// background verification to finish.
///
/// # Current scope
///
/// This version requires a new storage directory. It does not recover
/// an existing registry after restart or publish completed files.
pub struct FileTransferService {
    store: UploadStore,
}

impl FileTransferService {
    /// Creates a service with a new private storage directory.
    ///
    /// The directory must not exist. Its parent must be trusted and
    /// protected from modification by untrusted users.
    ///
    /// On non-Unix platforms, configure appropriate parent ACLs.
    pub fn create(root: impl AsRef<Path>, limits: FileTransferLimits) -> io::Result<Self> {
        let store = UploadStore::create(
            root.as_ref(),
            UploadLimits {
                max_file_size: limits.max_file_size,
                max_reserved_bytes: limits.max_reserved_bytes,
                max_uploads: limits.max_uploads,
                max_uploads_per_owner: limits.max_uploads_per_owner,
            },
        )?;

        Ok(Self { store })
    }

    /// Opens a completed upload for trusted application-side reading.
    ///
    /// The owner must come from trusted application context, normally
    /// the authenticated connection identity.
    ///
    /// This is not a network download operation. The application must
    /// authorize access before receiving the read-only handle.
    ///
    /// The private storage directory must remain protected from
    /// modification. Opening does not rehash the contents.
    ///
    /// The returned handle starts at offset zero. Registry metadata
    /// and quota reservations are retained.
    ///
    /// The caller must coordinate handle lifetime with deletion.
    /// An already returned handle cannot be revoked by this service.
    pub fn open_completed(
        &mut self,
        owner: &ClientIdentity,
        upload_id: [u8; 16],
        authorize: impl FnOnce(&ClientIdentity) -> bool,
    ) -> io::Result<std::fs::File> {
        check_authorization(owner, authorize)?;

        self.store
            .open_completed(owner, UploadId(upload_id))
            .map_err(application_error)
    }

    /// Processes one file-transfer request on a ready connection.
    ///
    /// The connection must currently be awaiting a request.
    /// All requests handled here are interpreted as file-transfer
    /// messages; this method does not route other application protocols.
    ///
    /// `authorize` must grant file-transfer access to the authenticated
    /// identity. Ownership checks are additionally enforced per upload.
    ///
    /// Authorization happens before receiving the request. A denied
    /// connection is dropped without a file-transfer response.
    ///
    /// The budget covers authorization, receiving, processing, and
    /// responding. Each network phase receives only the remaining
    /// budget. Synchronous callbacks and filesystem operations cannot
    /// be interrupted; an overrun is detected when they return.
    ///
    /// An error consumes and drops the connection. Storage side effects
    /// may already have occurred; clients must query upload status on
    /// a fresh authenticated connection after an uncertain response.
    pub fn serve_one(
        &mut self,
        mut connection: ReadyServer,
        budget: Duration,
        authorize: impl FnOnce(&ClientIdentity) -> bool,
    ) -> io::Result<ReadyServer> {
        if budget.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file-transfer budget must be nonzero",
            ));
        }

        let started = Instant::now();
        let owner = connection.identity().clone();

        check_authorization(&owner, authorize)?;

        let request = connection.receive_request(remaining_budget(started, budget)?)?;

        let response = self.process_request(&owner, &request)?;

        connection.respond(&response, remaining_budget(started, budget)?)?;

        // Do not return a successful exchange after its total budget.
        remaining_budget(started, budget)?;

        Ok(connection)
    }

    /// Applies available background-verification results without waiting.
    ///
    /// Does not start a timer or block awaiting a verification result.
    pub fn poll_verifications(&mut self) {
        self.store.poll_verifications();
    }

    /// Removes idle, incomplete uploads.
    ///
    /// Status polling does not extend the idle interval. Successful
    /// chunks reset it. Pending verification and completed files are
    /// excluded.
    ///
    /// `max_removals` bounds deletion attempts, not elapsed wall time.
    /// Candidate discovery may inspect the entire bounded registry.
    ///
    /// Call periodically from application maintenance code. This
    /// service does not start an automatic cleanup thread.
    pub fn cleanup_idle(
        &mut self,
        idle_timeout: Duration,
        max_removals: usize,
    ) -> io::Result<FileCleanupReport> {
        let report = self.store.cleanup_idle(idle_timeout, max_removals)?;

        Ok(FileCleanupReport {
            attempted: report.attempted,
            removed: report.removed,
            failed: report.failed,
            released_bytes: report.released_bytes,
        })
    }

    /// Deletes a completed upload and releases its reservation.
    ///
    /// This is a trusted application-side operation, not a wire request.
    /// `owner` must come from trusted application context, not an
    /// unauthenticated caller claim.
    ///
    /// The authorization callback must permit permanent deletion.
    /// Knowing an upload ID alone grants no access.
    ///
    /// On failure, reservation metadata is retained for retry.
    pub fn discard_completed(
        &mut self,
        owner: &ClientIdentity,
        upload_id: [u8; 16],
        authorize: impl FnOnce(&ClientIdentity) -> bool,
    ) -> io::Result<()> {
        check_authorization(owner, authorize)?;

        self.store
            .remove_completed(owner, UploadId(upload_id))
            .map_err(application_error)
    }

    pub fn reserved_bytes(&self) -> u64 {
        self.store.reserved_bytes()
    }

    pub fn upload_count(&self) -> usize {
        self.store.upload_count()
    }

    /// Only called after the network-facing authorization check.
    fn process_request(&mut self, owner: &ClientIdentity, body: &[u8]) -> io::Result<Vec<u8>> {
        let response = match UploadRequest::decode(body) {
            Ok(request) => self.store.handle(owner, request),
            Err(_) => UploadResponse::Rejected {
                code: UploadErrorCode::InvalidRequest,
            },
        };

        response.encode()
    }
}

fn check_authorization(
    identity: &ClientIdentity,
    authorize: impl FnOnce(&ClientIdentity) -> bool,
) -> io::Result<()> {
    if !authorize(identity) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "file-transfer operation is not authorized",
        ));
    }

    Ok(())
}

fn remaining_budget(started: Instant, budget: Duration) -> io::Result<Duration> {
    budget
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "file-transfer operation budget expired",
            )
        })
}

pub(crate) fn application_error(code: UploadErrorCode) -> io::Error {
    let (kind, message) = match code {
        UploadErrorCode::InvalidRequest => {
            (io::ErrorKind::InvalidInput, "invalid file-transfer request")
        }
        UploadErrorCode::NotFound => (io::ErrorKind::NotFound, "upload not found"),
        UploadErrorCode::LimitExceeded => (
            io::ErrorKind::Other,
            "file-transfer resource limit exceeded",
        ),
        UploadErrorCode::OffsetMismatch => (io::ErrorKind::InvalidInput, "upload offset mismatch"),
        UploadErrorCode::Incomplete => (io::ErrorKind::InvalidData, "upload is incomplete"),
        UploadErrorCode::DigestMismatch => (io::ErrorKind::InvalidData, "upload digest mismatch"),
        UploadErrorCode::Unavailable => (io::ErrorKind::Other, "file-transfer service unavailable"),
        UploadErrorCode::Expired => (io::ErrorKind::NotFound, "upload expired"),
        UploadErrorCode::Conflict => (
            io::ErrorKind::InvalidInput,
            "upload operation conflicts with its current state",
        ),
    };

    io::Error::new(kind, message)
}

#[cfg(test)]
impl FileTransferService {
    /// Allows loopback tests to separate storage processing from
    /// response transmission and deliberately lose an acknowledgement.
    pub(crate) fn process_request_for_test(
        &mut self,
        owner: &ClientIdentity,
        body: &[u8],
    ) -> io::Result<Vec<u8>> {
        self.process_request(owner, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use aws_lc_rs::digest;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            loop {
                let number = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "brn-file-service-test-{}-{number}",
                    std::process::id()
                ));

                match fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        continue;
                    }
                    Err(error) => panic!("cannot create test directory: {error}"),
                }
            }
        }

        fn root(&self) -> PathBuf {
            self.path.join("uploads")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn limits() -> FileTransferLimits {
        FileTransferLimits {
            max_file_size: 100,
            max_reserved_bytes: 200,
            max_uploads: 4,
            max_uploads_per_owner: 2,
        }
    }

    fn owner() -> ClientIdentity {
        ClientIdentity::new("client:alice").unwrap()
    }

    fn begin(service: &mut FileTransferService) -> UploadId {
        let digest = digest::digest(&digest::SHA256, b"abc");
        let mut sha256 = [0; 32];
        sha256.copy_from_slice(digest.as_ref());

        let request = UploadRequest::Begin { size: 3, sha256 }.encode().unwrap();

        let response = service.process_request(&owner(), &request).unwrap();

        match UploadResponse::decode(&response).unwrap() {
            UploadResponse::Ready {
                id,
                size: 3,
                offset: 0,
            } => id,
            response => panic!("unexpected response: {response:?}"),
        }
    }

    #[test]
    fn malformed_request_gets_bounded_application_rejection() {
        let directory = TestDirectory::new();
        let mut service = FileTransferService::create(directory.root(), limits()).unwrap();

        let response = service
            .process_request(&owner(), b"not a file-transfer message")
            .unwrap();

        assert_eq!(
            UploadResponse::decode(&response).unwrap(),
            UploadResponse::Rejected {
                code: UploadErrorCode::InvalidRequest,
            }
        );
        assert_eq!(service.reserved_bytes(), 0);
        assert_eq!(service.upload_count(), 0);
    }

    #[test]
    fn encoded_requests_reach_registry_and_preserve_ownership() {
        let directory = TestDirectory::new();
        let mut service = FileTransferService::create(directory.root(), limits()).unwrap();

        let id = begin(&mut service);
        let status = UploadRequest::Status { id }.encode().unwrap();

        assert_eq!(service.reserved_bytes(), 3);
        assert_eq!(service.upload_count(), 1);

        let other = ClientIdentity::new("client:bob").unwrap();

        let response = service.process_request(&other, &status).unwrap();

        assert_eq!(
            UploadResponse::decode(&response).unwrap(),
            UploadResponse::Rejected {
                code: UploadErrorCode::NotFound,
            }
        );

        let abort = UploadRequest::Abort { id }.encode().unwrap();
        service.process_request(&owner(), &abort).unwrap();

        assert_eq!(service.reserved_bytes(), 0);
        assert_eq!(service.upload_count(), 0);
    }

    #[test]
    fn denied_discard_does_not_change_registry() {
        let directory = TestDirectory::new();
        let mut service = FileTransferService::create(directory.root(), limits()).unwrap();

        let id = begin(&mut service);

        let error = service
            .discard_completed(&owner(), id.0, |_| false)
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(service.reserved_bytes(), 3);
        assert_eq!(service.upload_count(), 1);
    }

    #[test]
    fn authorization_receives_identity_and_requires_explicit_allow() {
        let identity = owner();
        let mut called = false;

        check_authorization(&identity, |received| {
            called = true;
            assert_eq!(received, &identity);
            true
        })
        .unwrap();

        assert!(called);

        assert_eq!(
            check_authorization(&identity, |_| false)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn validates_limits_and_cleanup_options() {
        let directory = TestDirectory::new();
        let mut invalid = limits();
        invalid.max_uploads = 0;

        assert!(FileTransferService::create(directory.root(), invalid).is_err());
        assert!(!directory.root().exists());

        let mut service = FileTransferService::create(directory.root(), limits()).unwrap();

        assert!(service.cleanup_idle(Duration::ZERO, 1).is_err());
        assert!(service.cleanup_idle(Duration::from_secs(1), 0).is_err());

        assert_eq!(
            service.cleanup_idle(Duration::from_secs(1), 1).unwrap(),
            FileCleanupReport::default()
        );
    }

    #[test]
    fn exhausted_budget_is_rejected() {
        let error = remaining_budget(Instant::now(), Duration::ZERO).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        let remaining = remaining_budget(Instant::now(), Duration::from_secs(60)).unwrap();

        assert!(!remaining.is_zero());
        assert!(remaining <= Duration::from_secs(60));
    }
}
