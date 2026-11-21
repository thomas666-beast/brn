use std::collections::HashMap;
use std::fs::{self, DirBuilder};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc::TrySendError;
use std::time::{Duration, Instant};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::auth::ClientIdentity;
use crate::file_disk::UploadFile;
use crate::file_state::UploadState;
use crate::file_verify::{VerificationJob, VerificationResult, VerificationWorker};
use crate::file_wire::{UploadErrorCode, UploadId, UploadRequest, UploadResponse};

const MAX_HASH_INPUT_LEN: u64 = u64::MAX / 8;
const MAX_RESULTS_PER_POLL: usize = 64;
const MAX_WAITING_VERIFICATIONS: usize = 16;

/// Limits include completed uploads retained in the registry.
///
/// The byte budget reserves declared file sizes. It excludes
/// filesystem metadata and is not a physical disk-space measurement.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UploadLimits {
    pub(crate) max_file_size: u64,
    pub(crate) max_reserved_bytes: u64,
    pub(crate) max_uploads: usize,
    pub(crate) max_uploads_per_owner: usize,
}

impl UploadLimits {
    fn validate(self) -> io::Result<Self> {
        if self.max_file_size > MAX_HASH_INPUT_LEN
            || self.max_file_size > self.max_reserved_bytes
            || self.max_uploads == 0
            || self.max_uploads_per_owner == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid upload limits",
            ));
        }

        Ok(self)
    }
}

struct Entry {
    owner: ClientIdentity,
    state: UploadState,
    file: Option<UploadFile>,
    path: PathBuf,
    verifying: bool,
    failure: Option<UploadErrorCode>,

    // Start of the current idle/cleanup-retry interval.
    idle_since: Instant,
}

/// Upload registry with private disk storage and background verification.
///
/// Keep this registry alive independently of individual connections.
/// Mutable access serializes registry operations.
///
/// Hashing runs on one background worker. Creation, chunk writes,
/// synchronization, and deletion still perform synchronous disk I/O.
///
/// Dropping the store does not delete its files or wait for hashing.
/// Existing storage is not recovered after restart by this version.
pub(crate) struct UploadStore {
    root: PathBuf,
    limits: UploadLimits,
    reserved_bytes: u64,
    entries: HashMap<UploadId, Entry>,
    rng: SystemRandom,
    verifier: VerificationWorker,
    verifier_failed: bool,
    verifier_disconnected: bool,
}

impl UploadStore {
    /// Creates a new upload directory and verification worker.
    ///
    /// `root` must not exist. Its parent must be trusted and protected
    /// against modification by untrusted users.
    ///
    /// Non-Unix systems require suitable parent ACLs.
    pub(crate) fn create(root: &Path, limits: UploadLimits) -> io::Result<Self> {
        let limits = limits.validate()?;

        let queue_capacity = limits.max_uploads.min(MAX_WAITING_VERIFICATIONS);
        let verifier = VerificationWorker::new(queue_capacity)?;

        let mut builder = DirBuilder::new();

        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;

            builder.mode(0o700);
        }

        builder.create(root)?;
        let root = fs::canonicalize(root)?;

        Ok(Self {
            root,
            limits,
            reserved_bytes: 0,
            entries: HashMap::new(),
            rng: SystemRandom::new(),
            verifier,
            verifier_failed: false,
            verifier_disconnected: false,
        })
    }

    pub(crate) fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }

    pub(crate) fn upload_count(&self) -> usize {
        self.entries.len()
    }

    /// Handles a decoded file-transfer request.
    ///
    /// The caller must authorize file-transfer access separately from
    /// authentication before invoking this method.
    ///
    /// No whole-file hashing occurs on this calling thread.
    pub(crate) fn handle(
        &mut self,
        owner: &ClientIdentity,
        request: UploadRequest<'_>,
    ) -> UploadResponse {
        self.poll_verifications();

        let result = match request {
            UploadRequest::Begin { size, sha256 } => self.begin(owner, size, sha256),
            UploadRequest::Chunk { id, offset, bytes } => self.chunk(owner, id, offset, bytes),
            UploadRequest::Status { id } => self.status(owner, id),
            UploadRequest::Finish { id } => self.finish(owner, id),
            UploadRequest::Abort { id } => self.abort(owner, id),
        };

        match result {
            Ok(response) => response,
            Err(code) => UploadResponse::Rejected { code },
        }
    }

    /// Applies a bounded number of ready verification results.
    ///
    /// Call periodically if results should be processed without
    /// incoming upload requests. This method does not wait for results.
    pub(crate) fn poll_verifications(&mut self) {
        if self.verifier_disconnected {
            return;
        }

        for _ in 0..MAX_RESULTS_PER_POLL {
            match self.verifier.try_result() {
                Ok(Some(result)) => {
                    if !self.apply_verification(result) {
                        // Stop admitting new work, but keep draining
                        // known pending jobs before permitting cleanup.
                        self.fail_verifier();
                    }
                }
                Ok(None) => return,
                Err(_) => {
                    self.disconnect_verifier();
                    return;
                }
            }
        }
    }

    /// Opens verified contents for trusted application-side reading.
    ///
    /// The caller must separately authorize access.
    /// Keeps registry metadata and reservations unchanged.
    pub(crate) fn open_completed(
        &mut self,
        owner: &ClientIdentity,
        id: UploadId,
    ) -> Result<std::fs::File, UploadErrorCode> {
        self.poll_verifications();

        let entry = self.entry_mut(owner, id)?;
        ensure_healthy(entry)?;

        if entry.verifying || !entry.state.is_complete() {
            return Err(UploadErrorCode::Conflict);
        }

        let file = std::fs::File::open(&entry.path).map_err(|_| UploadErrorCode::Unavailable)?;

        let metadata = file.metadata().map_err(|_| UploadErrorCode::Unavailable)?;

        if !metadata.is_file() || metadata.len() != entry.state.size() {
            return Err(UploadErrorCode::Unavailable);
        }

        Ok(file)
    }

    /// Deletes a completed upload.
    ///
    /// This is an application-side lifecycle operation, not a wire
    /// request. The caller must separately authorize deletion.
    ///
    /// Failed removal retains metadata/quota for a cleanup retry.
    /// Successful removal does not guarantee crash-durable directory
    /// updates.
    pub(crate) fn remove_completed(
        &mut self,
        owner: &ClientIdentity,
        id: UploadId,
    ) -> Result<(), UploadErrorCode> {
        self.poll_verifications();

        let size;

        {
            let entry = self.entry_mut(owner, id)?;

            if entry.verifying || !entry.state.is_complete() {
                return Err(UploadErrorCode::Conflict);
            }

            size = entry.state.size();
            entry.failure = Some(UploadErrorCode::Unavailable);
            drop(entry.file.take());

            remove_if_present(&entry.path)?;
        }

        self.entries.remove(&id);
        self.reserved_bytes -= size;

        Ok(())
    }

    fn begin(
        &mut self,
        owner: &ClientIdentity,
        size: u64,
        sha256: [u8; 32],
    ) -> Result<UploadResponse, UploadErrorCode> {
        if self.verifier_failed {
            return Err(UploadErrorCode::Unavailable);
        }

        if size > self.limits.max_file_size || self.entries.len() >= self.limits.max_uploads {
            return Err(UploadErrorCode::LimitExceeded);
        }

        let owner_count = self
            .entries
            .values()
            .filter(|entry| &entry.owner == owner)
            .count();

        if owner_count >= self.limits.max_uploads_per_owner {
            return Err(UploadErrorCode::LimitExceeded);
        }

        let reserved = self
            .reserved_bytes
            .checked_add(size)
            .filter(|total| *total <= self.limits.max_reserved_bytes)
            .ok_or(UploadErrorCode::LimitExceeded)?;

        let state = UploadState::new(owner.clone(), size, sha256, self.limits.max_file_size)?;

        let (id, path, file) = self.create_file()?;

        self.entries.insert(
            id,
            Entry {
                owner: owner.clone(),
                state,
                file: Some(file),
                path,
                verifying: false,
                failure: None,
                idle_since: Instant::now(),
            },
        );
        self.reserved_bytes = reserved;

        Ok(UploadResponse::Ready {
            id,
            size,
            offset: 0,
        })
    }

    fn create_file(&self) -> Result<(UploadId, PathBuf, UploadFile), UploadErrorCode> {
        for _ in 0..16 {
            let mut bytes = [0_u8; 16];
            self.rng
                .fill(&mut bytes)
                .map_err(|_| UploadErrorCode::Unavailable)?;

            let id = UploadId(bytes);

            if self.entries.contains_key(&id) {
                continue;
            }

            let path = self.root.join(upload_filename(id));

            match UploadFile::create(&path) {
                Ok(file) => return Ok((id, path, file)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    continue;
                }
                Err(_) => return Err(UploadErrorCode::Unavailable),
            }
        }

        Err(UploadErrorCode::Unavailable)
    }

    fn chunk(
        &mut self,
        owner: &ClientIdentity,
        id: UploadId,
        offset: u64,
        bytes: &[u8],
    ) -> Result<UploadResponse, UploadErrorCode> {
        let entry = self.entry_mut(owner, id)?;
        ensure_healthy(entry)?;

        if entry.verifying {
            return Err(UploadErrorCode::Conflict);
        }

        let expected_end = entry.state.check_chunk(owner, offset, bytes.len())?;

        let Some(file) = entry.file.as_mut() else {
            entry.failure = Some(UploadErrorCode::Unavailable);
            return Err(UploadErrorCode::Unavailable);
        };

        match file.append_synced(offset, bytes) {
            Ok(end) if end == expected_end => {}
            Ok(_) | Err(_) => {
                entry.failure = Some(UploadErrorCode::Unavailable);
                return Err(UploadErrorCode::Unavailable);
            }
        }

        let end = match entry.state.commit_chunk(owner, offset, bytes.len()) {
            Ok(end) => end,
            Err(_) => {
                entry.failure = Some(UploadErrorCode::Unavailable);
                return Err(UploadErrorCode::Unavailable);
            }
        };

        entry.idle_since = Instant::now();

        Ok(UploadResponse::Progress { id, offset: end })
    }

    fn status(
        &mut self,
        owner: &ClientIdentity,
        id: UploadId,
    ) -> Result<UploadResponse, UploadErrorCode> {
        let entry = self.entry_mut(owner, id)?;
        ensure_healthy(entry)?;

        if entry.verifying {
            return Ok(UploadResponse::Verifying { id });
        }

        if entry.state.is_complete() {
            return Ok(completed_response(id, &entry.state));
        }

        Ok(UploadResponse::Ready {
            id,
            size: entry.state.size(),
            offset: entry.state.offset(),
        })
    }

    fn finish(
        &mut self,
        owner: &ClientIdentity,
        id: UploadId,
    ) -> Result<UploadResponse, UploadErrorCode> {
        let entry = self.entries.get_mut(&id).ok_or(UploadErrorCode::NotFound)?;

        entry.state.check_owner(owner)?;
        ensure_healthy(entry)?;

        if entry.verifying {
            return Ok(UploadResponse::Verifying { id });
        }

        if entry.state.is_complete() {
            return Ok(completed_response(id, &entry.state));
        }

        entry.state.check_finish(owner)?;

        if self.verifier_failed {
            return Err(UploadErrorCode::Unavailable);
        }

        let Some(file) = entry.file.take() else {
            entry.failure = Some(UploadErrorCode::Unavailable);
            return Err(UploadErrorCode::Unavailable);
        };

        match self.verifier.try_submit(VerificationJob { id, file }) {
            Ok(()) => {
                entry.verifying = true;
                Ok(UploadResponse::Verifying { id })
            }
            Err(TrySendError::Full(job)) => {
                // Submission did not happen. Restore ownership and
                // permit a later Finish retry.
                entry.file = Some(job.file);
                Err(UploadErrorCode::Unavailable)
            }
            Err(TrySendError::Disconnected(job)) => {
                entry.file = Some(job.file);

                // Stop new submissions. Pending jobs remain protected
                // until result-channel disconnection is observed.
                self.fail_verifier();

                Err(UploadErrorCode::Unavailable)
            }
        }
    }

    fn abort(
        &mut self,
        owner: &ClientIdentity,
        id: UploadId,
    ) -> Result<UploadResponse, UploadErrorCode> {
        let size;

        {
            let entry = self.entry_mut(owner, id)?;

            if entry.verifying {
                return Err(UploadErrorCode::Conflict);
            }

            // Failed uploads may still be explicitly cleaned up.
            entry.state.mark_aborted(owner)?;
            entry.failure = Some(UploadErrorCode::Unavailable);
            size = entry.state.size();

            drop(entry.file.take());
            remove_if_present(&entry.path)?;
        }

        self.entries.remove(&id);
        self.reserved_bytes -= size;

        Ok(UploadResponse::Aborted { id })
    }

    /// Returns false for an internal registry/worker mismatch.
    fn apply_verification(&mut self, result: VerificationResult) -> bool {
        let Some(entry) = self.entries.get_mut(&result.id) else {
            return false;
        };

        if !entry.verifying || entry.file.is_some() {
            return false;
        }

        // The worker closes the file before publishing its result.
        entry.verifying = false;
        entry.idle_since = Instant::now();

        if entry.failure.is_some() {
            // A prior service failure is terminal for this upload.
            return true;
        }

        match result.measured {
            Ok((actual_size, actual_sha256)) => {
                let owner = &entry.owner;

                if let Err(code) = entry
                    .state
                    .mark_complete(owner, actual_size, &actual_sha256)
                {
                    entry.failure = Some(code);
                }
            }
            Err(_) => {
                entry.failure = Some(UploadErrorCode::Unavailable);
            }
        }

        true
    }

    fn fail_verifier(&mut self) {
        self.verifier_failed = true;

        for entry in self.entries.values_mut() {
            if entry.verifying {
                entry.failure = Some(UploadErrorCode::Unavailable);
            }
        }
    }

    fn disconnect_verifier(&mut self) {
        self.fail_verifier();
        self.verifier_disconnected = true;

        // The sole result sender belonged to the worker. Once its
        // channel disconnects and buffered results have drained, no
        // further verification result can arrive.
        for entry in self.entries.values_mut() {
            if entry.verifying {
                entry.verifying = false;
                entry.failure = Some(UploadErrorCode::Unavailable);
                entry.idle_since = Instant::now();
            }
        }
    }

    fn entry_mut(
        &mut self,
        owner: &ClientIdentity,
        id: UploadId,
    ) -> Result<&mut Entry, UploadErrorCode> {
        let entry = self.entries.get_mut(&id).ok_or(UploadErrorCode::NotFound)?;

        entry.state.check_owner(owner)?;

        Ok(entry)
    }
}

fn ensure_healthy(entry: &Entry) -> Result<(), UploadErrorCode> {
    if let Some(code) = entry.failure {
        return Err(code);
    }

    if entry.state.is_aborted() {
        return Err(UploadErrorCode::Unavailable);
    }

    Ok(())
}

fn completed_response(id: UploadId, state: &UploadState) -> UploadResponse {
    UploadResponse::Complete {
        id,
        size: state.size(),
        sha256: *state.sha256(),
    }
}

fn remove_if_present(path: &Path) -> Result<(), UploadErrorCode> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(UploadErrorCode::Unavailable),
    }
}

fn upload_filename(id: UploadId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut name = String::with_capacity(37);

    for byte in id.0 {
        name.push(HEX[(byte >> 4) as usize] as char);
        name.push(HEX[(byte & 0x0f) as usize] as char);
    }

    name.push_str(".part");
    name
}

/// Outcome of one explicit cleanup pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CleanupReport {
    pub(crate) attempted: usize,
    pub(crate) removed: usize,
    pub(crate) failed: usize,
    pub(crate) released_bytes: u64,
}

impl UploadStore {
    /// Removes idle, incomplete uploads.
    ///
    /// No background expiration timer is started.
    ///
    /// `max_removals` bounds attempted deletions, including failures.
    /// Candidate discovery may inspect the full registry, whose size
    /// is bounded by max_uploads.
    ///
    /// Completed uploads and uploads still owned by the verification
    /// worker are excluded.
    ///
    /// A failed removal retains metadata/quota and starts a fresh
    /// cleanup-retry interval.
    ///
    /// Deletions perform synchronous filesystem I/O. This method is
    /// not a hard wall-clock-bounded operation.
    pub(crate) fn cleanup_idle(
        &mut self,
        idle_timeout: Duration,
        max_removals: usize,
    ) -> io::Result<CleanupReport> {
        validate_cleanup_options(idle_timeout, max_removals)?;

        self.poll_verifications();

        self.cleanup_idle_at(Instant::now(), idle_timeout, max_removals)
    }

    fn cleanup_idle_at(
        &mut self,
        now: Instant,
        idle_timeout: Duration,
        max_removals: usize,
    ) -> io::Result<CleanupReport> {
        validate_cleanup_options(idle_timeout, max_removals)?;

        // Snapshot only selected IDs and owners before mutating entries.
        // At most max_removals candidates are retained.
        let candidates: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, entry)| {
                if entry.verifying || entry.state.is_complete() {
                    return false;
                }

                now.checked_duration_since(entry.idle_since)
                    .is_some_and(|age| age >= idle_timeout)
            })
            .take(max_removals)
            .map(|(id, entry)| (*id, entry.owner.clone(), entry.state.size()))
            .collect();

        let mut report = CleanupReport::default();

        for (id, owner, size) in candidates {
            report.attempted += 1;

            // Reuse the same ownership, file-close, deletion, and
            // reservation-release ordering as explicit Abort.
            match self.abort(&owner, id) {
                Ok(_) => {
                    report.removed += 1;
                    report.released_bytes += size;
                }
                Err(_) => {
                    report.failed += 1;

                    if let Some(entry) = self.entries.get_mut(&id) {
                        entry.idle_since = now;
                    }
                }
            }
        }

        Ok(report)
    }
}

fn validate_cleanup_options(idle_timeout: Duration, max_removals: usize) -> io::Result<()> {
    if idle_timeout.is_zero() || max_removals == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "cleanup timeout and removal budget must be nonzero",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use aws_lc_rs::digest;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            loop {
                let number = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "brn-async-store-test-{}-{number}",
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

    fn assert_chunk_disk_failure_is_terminal(sync_failure: bool) {
        let directory = TestDirectory::new();
        let mut store = UploadStore::create(&directory.root(), limits()).unwrap();

        let identity = owner();
        let id = begin(&mut store, &identity, b"abcdefg");
        let path = store.entries[&id].path.clone();

        // Establish one acknowledged prefix.
        assert_eq!(
            store.handle(
                &identity,
                UploadRequest::Chunk {
                    id,
                    offset: 0,
                    bytes: b"abc",
                },
            ),
            UploadResponse::Progress { id, offset: 3 },
        );

        {
            let entry = store.entries.get_mut(&id).unwrap();
            let file = entry.file.as_mut().unwrap();

            if sync_failure {
                file.fail_next_sync_for_test();
            } else {
                file.fail_next_write_after_for_test(2);
            }
        }

        let rejected = UploadResponse::Rejected {
            code: UploadErrorCode::Unavailable,
        };

        // This must not return Progress, even though some or all of
        // the chunk's bytes reach the file.
        assert_eq!(
            store.handle(
                &identity,
                UploadRequest::Chunk {
                    id,
                    offset: 3,
                    bytes: b"defg",
                },
            ),
            rejected,
        );

        {
            let entry = &store.entries[&id];

            assert_eq!(entry.state.offset(), 3);
            assert_eq!(entry.file.as_ref().unwrap().confirmed_len(), 3,);
            assert_eq!(entry.failure, Some(UploadErrorCode::Unavailable),);
            assert!(!entry.verifying);
            assert!(!entry.state.is_complete());
        }

        let expected_contents: &[u8] = if sync_failure { b"abcdefg" } else { b"abcde" };

        assert_eq!(fs::read(&path).unwrap().as_slice(), expected_contents,);

        // Failed uploads continue consuming quota and an upload slot.
        assert_eq!(store.reserved_bytes(), 7);
        assert_eq!(store.upload_count(), 1);

        // Status cannot report a healthy receiving offset, Finish
        // cannot start verification, and retrying cannot append again.
        for request in [
            UploadRequest::Status { id },
            UploadRequest::Finish { id },
            UploadRequest::Chunk {
                id,
                offset: 3,
                bytes: b"defg",
            },
        ] {
            assert_eq!(store.handle(&identity, request), rejected);
        }

        assert_eq!(store.entries[&id].state.offset(), 3);
        assert!(!store.entries[&id].verifying);

        assert_eq!(fs::read(&path).unwrap().as_slice(), expected_contents,);
        assert_eq!(store.reserved_bytes(), 7);
        assert_eq!(store.upload_count(), 1);

        // Explicit Abort must remain available for terminal failures.
        assert_eq!(
            store.handle(&identity, UploadRequest::Abort { id }),
            UploadResponse::Aborted { id },
        );

        assert!(!path.exists());
        assert_eq!(store.reserved_bytes(), 0);
        assert_eq!(store.upload_count(), 0);

        assert_eq!(
            store.handle(&identity, UploadRequest::Status { id }),
            UploadResponse::Rejected {
                code: UploadErrorCode::NotFound,
            },
        );
    }

    fn owner() -> ClientIdentity {
        ClientIdentity::new("client:alice").unwrap()
    }

    fn other() -> ClientIdentity {
        ClientIdentity::new("client:bob").unwrap()
    }

    fn limits() -> UploadLimits {
        UploadLimits {
            max_file_size: 100,
            max_reserved_bytes: 200,
            max_uploads: 4,
            max_uploads_per_owner: 2,
        }
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let digest = digest::digest(&digest::SHA256, bytes);
        let mut output = [0; 32];
        output.copy_from_slice(digest.as_ref());
        output
    }

    fn begin(store: &mut UploadStore, identity: &ClientIdentity, bytes: &[u8]) -> UploadId {
        match store.handle(
            identity,
            UploadRequest::Begin {
                size: bytes.len() as u64,
                sha256: sha256(bytes),
            },
        ) {
            UploadResponse::Ready { id, offset: 0, .. } => id,
            response => panic!("unexpected Begin response: {response:?}"),
        }
    }

    fn send_all(store: &mut UploadStore, identity: &ClientIdentity, id: UploadId, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        assert_eq!(
            store.handle(
                identity,
                UploadRequest::Chunk {
                    id,
                    offset: 0,
                    bytes,
                },
            ),
            UploadResponse::Progress {
                id,
                offset: bytes.len() as u64,
            }
        );
    }

    fn wait_terminal(
        store: &mut UploadStore,
        identity: &ClientIdentity,
        id: UploadId,
    ) -> UploadResponse {
        let started = Instant::now();

        loop {
            let response = store.handle(identity, UploadRequest::Status { id });

            if !matches!(response, UploadResponse::Verifying { .. }) {
                return response;
            }

            assert!(
                started.elapsed() < Duration::from_secs(10),
                "verification did not finish within test timeout"
            );

            thread::sleep(Duration::from_millis(1));
        }
    }

    fn complete(store: &mut UploadStore, identity: &ClientIdentity, bytes: &[u8]) -> UploadId {
        let id = begin(store, identity, bytes);
        send_all(store, identity, id, bytes);

        assert_eq!(
            store.handle(identity, UploadRequest::Finish { id }),
            UploadResponse::Verifying { id }
        );

        assert_eq!(
            wait_terminal(store, identity, id),
            UploadResponse::Complete {
                id,
                size: bytes.len() as u64,
                sha256: sha256(bytes),
            }
        );

        id
    }

    #[test]
    fn upload_resumes_from_confirmed_offset() {
        let directory = TestDirectory::new();
        let mut store = UploadStore::create(&directory.root(), limits()).unwrap();
        let id = begin(&mut store, &owner(), b"hello");

        assert_eq!(
            store.handle(
                &owner(),
                UploadRequest::Chunk {
                    id,
                    offset: 0,
                    bytes: b"he",
                },
            ),
            UploadResponse::Progress { id, offset: 2 }
        );

        // A new connection authenticating as the same identity can
        // continue using this registry.
        assert_eq!(
            store.handle(&owner(), UploadRequest::Status { id }),
            UploadResponse::Ready {
                id,
                size: 5,
                offset: 2,
            }
        );

        assert_eq!(
            store.handle(
                &owner(),
                UploadRequest::Chunk {
                    id,
                    offset: 2,
                    bytes: b"llo",
                },
            ),
            UploadResponse::Progress { id, offset: 5 }
        );

        assert_eq!(
            store.handle(&owner(), UploadRequest::Finish { id }),
            UploadResponse::Verifying { id }
        );

        assert_eq!(
            wait_terminal(&mut store, &owner(), id),
            UploadResponse::Complete {
                id,
                size: 5,
                sha256: sha256(b"hello"),
            }
        );
    }

    #[test]
    fn verification_blocks_mutation_until_result_is_applied() {
        let directory = TestDirectory::new();
        let mut store = UploadStore::create(&directory.root(), limits()).unwrap();
        let id = begin(&mut store, &owner(), b"abc");
        send_all(&mut store, &owner(), id, b"abc");

        // Private methods intentionally avoid automatic result polling,
        // making the pending registry state deterministic.
        assert_eq!(
            store.finish(&owner(), id),
            Ok(UploadResponse::Verifying { id })
        );
        assert_eq!(
            store.finish(&owner(), id),
            Ok(UploadResponse::Verifying { id })
        );
        assert_eq!(
            store.status(&owner(), id),
            Ok(UploadResponse::Verifying { id })
        );
        assert_eq!(
            store.chunk(&owner(), id, 3, b"x"),
            Err(UploadErrorCode::Conflict)
        );
        assert_eq!(store.abort(&owner(), id), Err(UploadErrorCode::Conflict));

        assert!(store.entries[&id].file.is_none());
        assert!(store.entries[&id].verifying);

        assert!(matches!(
            wait_terminal(&mut store, &owner(), id),
            UploadResponse::Complete { .. }
        ));
    }

    #[test]
    fn completion_retains_metadata_without_open_handle() {
        let directory = TestDirectory::new();
        let mut store = UploadStore::create(&directory.root(), limits()).unwrap();
        let id = complete(&mut store, &owner(), b"abc");

        assert!(store.entries[&id].file.is_none());
        assert!(!store.entries[&id].verifying);
        assert!(store.entries[&id].path.exists());
        assert_eq!(store.reserved_bytes(), 3);
        assert_eq!(store.upload_count(), 1);

        let expected = UploadResponse::Complete {
            id,
            size: 3,
            sha256: sha256(b"abc"),
        };

        assert_eq!(
            store.handle(&owner(), UploadRequest::Finish { id }),
            expected
        );
        assert_eq!(
            store.handle(&owner(), UploadRequest::Status { id }),
            expected
        );
    }

    #[test]
    fn wrong_owner_and_unknown_id_return_not_found() {
        let directory = TestDirectory::new();
        let mut store = UploadStore::create(&directory.root(), limits()).unwrap();
        let id = begin(&mut store, &owner(), b"abc");

        let rejected = UploadResponse::Rejected {
            code: UploadErrorCode::NotFound,
        };

        for request in [
            UploadRequest::Status { id },
            UploadRequest::Finish { id },
            UploadRequest::Abort { id },
            UploadRequest::Chunk {
                id,
                offset: 0,
                bytes: b"abc",
            },
        ] {
            assert_eq!(store.handle(&other(), request), rejected);
        }

        let mut unknown = id;
        unknown.0[0] ^= 1;

        assert_eq!(
            store.handle(&owner(), UploadRequest::Status { id: unknown }),
            rejected
        );
        assert_eq!(store.reserved_bytes(), 3);
    }

    #[test]
    fn abort_releases_quota_and_upload_slot() {
        let directory = TestDirectory::new();
        let mut config = limits();
        config.max_uploads_per_owner = 1;

        let mut store = UploadStore::create(&directory.root(), config).unwrap();
        let id = begin(&mut store, &owner(), b"abc");
        let path = store.entries[&id].path.clone();

        assert_eq!(
            store.handle(
                &owner(),
                UploadRequest::Begin {
                    size: 1,
                    sha256: [0; 32],
                },
            ),
            UploadResponse::Rejected {
                code: UploadErrorCode::LimitExceeded,
            }
        );

        assert_eq!(
            store.handle(&owner(), UploadRequest::Abort { id }),
            UploadResponse::Aborted { id }
        );

        assert!(!path.exists());
        assert_eq!(store.reserved_bytes(), 0);
        assert_eq!(store.upload_count(), 0);

        begin(&mut store, &owner(), b"replacement");
    }

    #[test]
    fn enforces_file_byte_and_global_count_limits() {
        let directory = TestDirectory::new();
        let config = UploadLimits {
            max_file_size: 4,
            max_reserved_bytes: 5,
            max_uploads: 2,
            max_uploads_per_owner: 2,
        };

        let mut store = UploadStore::create(&directory.root(), config).unwrap();

        assert_eq!(
            store.handle(
                &owner(),
                UploadRequest::Begin {
                    size: 5,
                    sha256: [0; 32],
                },
            ),
            UploadResponse::Rejected {
                code: UploadErrorCode::LimitExceeded,
            }
        );

        begin(&mut store, &owner(), b"1234");

        assert_eq!(
            store.handle(
                &other(),
                UploadRequest::Begin {
                    size: 2,
                    sha256: [0; 32],
                },
            ),
            UploadResponse::Rejected {
                code: UploadErrorCode::LimitExceeded,
            }
        );

        begin(&mut store, &other(), b"x");

        assert_eq!(
            store.handle(
                &owner(),
                UploadRequest::Begin {
                    size: 0,
                    sha256: sha256(b""),
                },
            ),
            UploadResponse::Rejected {
                code: UploadErrorCode::LimitExceeded,
            }
        );
    }

    #[test]
    fn incomplete_finish_does_not_submit_verification() {
        let directory = TestDirectory::new();
        let mut store = UploadStore::create(&directory.root(), limits()).unwrap();
        let id = begin(&mut store, &owner(), b"abc");

        assert_eq!(
            store.handle(&owner(), UploadRequest::Finish { id }),
            UploadResponse::Rejected {
                code: UploadErrorCode::Incomplete,
            }
        );

        assert!(!store.entries[&id].verifying);
        assert!(store.entries[&id].file.is_some());

        assert_eq!(
            store.handle(&owner(), UploadRequest::Abort { id }),
            UploadResponse::Aborted { id }
        );
    }

    #[test]
    fn digest_mismatch_is_terminal_but_can_be_aborted() {
        let directory = TestDirectory::new();
        let mut store = UploadStore::create(&directory.root(), limits()).unwrap();
        let id = begin(&mut store, &owner(), b"abc");
        send_all(&mut store, &owner(), id, b"xyz");

        assert_eq!(
            store.handle(&owner(), UploadRequest::Finish { id }),
            UploadResponse::Verifying { id }
        );

        let rejected = UploadResponse::Rejected {
            code: UploadErrorCode::DigestMismatch,
        };

        assert_eq!(wait_terminal(&mut store, &owner(), id), rejected);
        assert_eq!(
            store.handle(&owner(), UploadRequest::Finish { id }),
            rejected
        );

        assert_eq!(
            store.handle(&owner(), UploadRequest::Abort { id }),
            UploadResponse::Aborted { id }
        );
        assert_eq!(store.reserved_bytes(), 0);
    }

    #[test]
    fn repeated_chunk_does_not_duplicate_contents() {
        let directory = TestDirectory::new();
        let mut store = UploadStore::create(&directory.root(), limits()).unwrap();
        let id = begin(&mut store, &owner(), b"abc");
        send_all(&mut store, &owner(), id, b"abc");

        assert_eq!(
            store.handle(
                &owner(),
                UploadRequest::Chunk {
                    id,
                    offset: 0,
                    bytes: b"abc",
                },
            ),
            UploadResponse::Rejected {
                code: UploadErrorCode::OffsetMismatch,
            }
        );

        assert_eq!(
            store.handle(&owner(), UploadRequest::Finish { id }),
            UploadResponse::Verifying { id }
        );

        assert!(matches!(
            wait_terminal(&mut store, &owner(), id),
            UploadResponse::Complete { .. }
        ));
    }

    #[test]
    fn empty_upload_verifies_successfully() {
        let directory = TestDirectory::new();
        let mut store = UploadStore::create(&directory.root(), limits()).unwrap();

        let id = complete(&mut store, &owner(), b"");

        assert_eq!(store.reserved_bytes(), 0);
        assert_eq!(store.upload_count(), 1);

        store.remove_completed(&owner(), id).unwrap();

        assert_eq!(store.upload_count(), 0);
    }

    #[test]
    fn completed_removal_checks_owner_and_releases_quota() {
        let directory = TestDirectory::new();
        let mut store = UploadStore::create(&directory.root(), limits()).unwrap();
        let id = complete(&mut store, &owner(), b"abc");
        let path = store.entries[&id].path.clone();

        assert_eq!(
            store.remove_completed(&other(), id),
            Err(UploadErrorCode::NotFound)
        );
        assert_eq!(store.reserved_bytes(), 3);

        store.remove_completed(&owner(), id).unwrap();

        assert!(!path.exists());
        assert_eq!(store.reserved_bytes(), 0);
        assert_eq!(store.upload_count(), 0);

        assert_eq!(
            store.handle(&owner(), UploadRequest::Status { id }),
            UploadResponse::Rejected {
                code: UploadErrorCode::NotFound,
            }
        );
    }

    #[test]
    fn completed_removal_failure_retains_quota_for_retry() {
        let directory = TestDirectory::new();
        let mut store = UploadStore::create(&directory.root(), limits()).unwrap();
        let id = complete(&mut store, &owner(), b"abc");
        let path = store.entries[&id].path.clone();

        // Deterministic removal failure for this test only.
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();

        assert_eq!(
            store.remove_completed(&owner(), id),
            Err(UploadErrorCode::Unavailable)
        );
        assert_eq!(store.reserved_bytes(), 3);
        assert_eq!(store.upload_count(), 1);

        assert_eq!(
            store.handle(&owner(), UploadRequest::Status { id }),
            UploadResponse::Rejected {
                code: UploadErrorCode::Unavailable,
            }
        );

        fs::remove_dir(&path).unwrap();
        store.remove_completed(&owner(), id).unwrap();

        assert_eq!(store.reserved_bytes(), 0);
        assert_eq!(store.upload_count(), 0);
    }

    #[test]
    fn incomplete_upload_cannot_be_removed_as_completed() {
        let directory = TestDirectory::new();
        let mut store = UploadStore::create(&directory.root(), limits()).unwrap();
        let id = begin(&mut store, &owner(), b"abc");

        assert_eq!(
            store.remove_completed(&owner(), id),
            Err(UploadErrorCode::Conflict)
        );

        assert_eq!(
            store.handle(&owner(), UploadRequest::Abort { id }),
            UploadResponse::Aborted { id }
        );
    }

    #[test]
    fn refuses_existing_directory_and_invalid_limits() {
        let directory = TestDirectory::new();
        let root = directory.root();

        let store = UploadStore::create(&root, limits()).unwrap();

        assert!(UploadStore::create(&root, limits()).is_err());
        drop(store);

        let invalid_root = directory.path.join("invalid");
        let mut config = limits();
        config.max_uploads = 0;

        assert!(UploadStore::create(&invalid_root, config).is_err());
        assert!(!invalid_root.exists());
    }

    #[test]
    fn partial_chunk_write_failure_is_terminal_until_abort() {
        assert_chunk_disk_failure_is_terminal(false);
    }

    #[test]
    fn chunk_sync_failure_is_terminal_until_abort() {
        assert_chunk_disk_failure_is_terminal(true);
    }

    #[test]
    fn completed_contents_can_be_opened_without_releasing_quota() {
        use std::io::Read;

        let directory = TestDirectory::new();
        let mut store = UploadStore::create(&directory.root(), limits()).unwrap();
        let identity = owner();
        let id = complete(&mut store, &identity, b"abc");

        let mut file = store.open_completed(&identity, id).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();

        assert_eq!(contents, b"abc");
        assert_eq!(store.reserved_bytes(), 3);
        assert_eq!(store.upload_count(), 1);

        drop(file);
        store.remove_completed(&identity, id).unwrap();
    }

    #[test]
    fn completed_contents_require_matching_owner() {
        let directory = TestDirectory::new();
        let mut store = UploadStore::create(&directory.root(), limits()).unwrap();
        let id = complete(&mut store, &owner(), b"abc");

        assert_eq!(
            store.open_completed(&other(), id).unwrap_err(),
            UploadErrorCode::NotFound,
        );
    }

    #[test]
    fn receiving_contents_cannot_be_opened_as_completed() {
        let directory = TestDirectory::new();
        let mut store = UploadStore::create(&directory.root(), limits()).unwrap();
        let id = begin(&mut store, &owner(), b"abc");

        assert_eq!(
            store.open_completed(&owner(), id).unwrap_err(),
            UploadErrorCode::Conflict,
        );
    }

    #[test]
    fn completed_contents_reject_changed_length() {
        let directory = TestDirectory::new();
        let mut store = UploadStore::create(&directory.root(), limits()).unwrap();
        let identity = owner();
        let id = complete(&mut store, &identity, b"abc");
        let path = store.entries[&id].path.clone();

        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_len(1)
            .unwrap();

        assert_eq!(
            store.open_completed(&identity, id).unwrap_err(),
            UploadErrorCode::Unavailable,
        );

        assert_eq!(store.reserved_bytes(), 3);
        assert_eq!(store.upload_count(), 1);
    }
}

#[cfg(test)]
mod verification_fault_tests {
    use super::*;

    use aws_lc_rs::digest;
    use std::sync::mpsc::{Receiver, SyncSender};

    struct Fixture {
        store: UploadStore,
        root: PathBuf,
        owner: ClientIdentity,
    }

    impl Fixture {
        fn new() -> Self {
            let rng = SystemRandom::new();
            let mut random = [0_u8; 16];
            rng.fill(&mut random).unwrap();

            let root = std::env::temp_dir().join(format!(
                "brn-verification-fault-{}-{}",
                std::process::id(),
                upload_filename(UploadId(random))
            ));

            let limits = UploadLimits {
                max_file_size: 100,
                max_reserved_bytes: 400,
                max_uploads: 4,
                max_uploads_per_owner: 4,
            };

            let store = UploadStore::create(&root, limits).unwrap();

            Self {
                store,
                root,
                owner: ClientIdentity::new("client:fault-test").unwrap(),
            }
        }

        fn install_controlled_worker(
            &mut self,
        ) -> (Receiver<VerificationJob>, SyncSender<VerificationResult>) {
            let (worker, jobs, results) = VerificationWorker::controlled_for_test(1);

            // The original worker is idle: no jobs have been submitted.
            self.store.verifier = worker;
            self.store.verifier_failed = false;
            self.store.verifier_disconnected = false;

            (jobs, results)
        }

        fn ready_upload(&mut self, bytes: &[u8]) -> UploadId {
            let digest = digest::digest(&digest::SHA256, bytes);
            let mut sha256 = [0_u8; 32];
            sha256.copy_from_slice(digest.as_ref());

            let response = self.store.handle(
                &self.owner,
                UploadRequest::Begin {
                    size: bytes.len() as u64,
                    sha256,
                },
            );

            let UploadResponse::Ready { id, .. } = response else {
                panic!("unexpected Begin response: {response:?}");
            };

            if !bytes.is_empty() {
                assert_eq!(
                    self.store.handle(
                        &self.owner,
                        UploadRequest::Chunk {
                            id,
                            offset: 0,
                            bytes,
                        },
                    ),
                    UploadResponse::Progress {
                        id,
                        offset: bytes.len() as u64,
                    }
                );
            }

            id
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.store.entries.clear();
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn complete_job(job: VerificationJob, results: &SyncSender<VerificationResult>) {
        let VerificationJob { id, mut file } = job;
        let measured = file.measure_sha256();

        // Match the real worker's ownership ordering.
        drop(file);

        assert!(results.send(VerificationResult { id, measured }).is_ok());
    }

    #[test]
    fn full_queue_restores_file_and_allows_finish_retry() {
        let mut fixture = Fixture::new();
        let (jobs, results) = fixture.install_controlled_worker();

        let first = fixture.ready_upload(b"first");
        let second = fixture.ready_upload(b"second");

        assert_eq!(
            fixture
                .store
                .handle(&fixture.owner, UploadRequest::Finish { id: first },),
            UploadResponse::Verifying { id: first }
        );

        // The controlled receiver has not consumed the first job.
        // Its one-slot input queue is therefore deterministically full.
        assert_eq!(
            fixture
                .store
                .handle(&fixture.owner, UploadRequest::Finish { id: second },),
            UploadResponse::Rejected {
                code: UploadErrorCode::Unavailable,
            }
        );

        let entry = &fixture.store.entries[&second];

        assert!(!entry.verifying);
        assert!(entry.failure.is_none());
        assert_eq!(entry.file.as_ref().unwrap().confirmed_len(), 6);
        assert!(!fixture.store.verifier_failed);

        assert_eq!(
            fixture
                .store
                .handle(&fixture.owner, UploadRequest::Status { id: second },),
            UploadResponse::Ready {
                id: second,
                size: 6,
                offset: 6,
            }
        );

        let first_job = jobs.try_recv().unwrap();
        assert_eq!(first_job.id, first);

        complete_job(first_job, &results);
        fixture.store.poll_verifications();

        assert!(fixture.store.entries[&first].state.is_complete());

        assert_eq!(
            fixture
                .store
                .handle(&fixture.owner, UploadRequest::Finish { id: second },),
            UploadResponse::Verifying { id: second }
        );

        let second_job = jobs.try_recv().unwrap();
        assert_eq!(second_job.id, second);

        complete_job(second_job, &results);
        fixture.store.poll_verifications();

        assert!(fixture.store.entries[&second].state.is_complete());

        fixture
            .store
            .remove_completed(&fixture.owner, first)
            .unwrap();
        fixture
            .store
            .remove_completed(&fixture.owner, second)
            .unwrap();

        assert_eq!(fixture.store.reserved_bytes(), 0);
        assert_eq!(fixture.store.upload_count(), 0);
    }

    #[test]
    fn disconnection_preserves_pending_protection_until_results_close() {
        let mut fixture = Fixture::new();
        let (jobs, results) = fixture.install_controlled_worker();

        let first = fixture.ready_upload(b"first");
        let second = fixture.ready_upload(b"second");

        assert_eq!(
            fixture
                .store
                .handle(&fixture.owner, UploadRequest::Finish { id: first },),
            UploadResponse::Verifying { id: first }
        );

        // Disconnect job submission and drop the queued first file.
        // Keep the result sender alive to exercise the intermediate
        // state where result-channel disconnection is not yet known.
        drop(jobs);

        assert_eq!(
            fixture
                .store
                .handle(&fixture.owner, UploadRequest::Finish { id: second },),
            UploadResponse::Rejected {
                code: UploadErrorCode::Unavailable,
            }
        );

        assert!(fixture.store.verifier_failed);
        assert!(!fixture.store.verifier_disconnected);

        // Failed submission restored the second file.
        assert!(fixture.store.entries[&second].file.is_some());
        assert!(!fixture.store.entries[&second].verifying);

        // The first upload must remain protected until the registry
        // observes result-channel disconnection.
        assert!(fixture.store.entries[&first].verifying);

        assert_eq!(
            fixture
                .store
                .handle(&fixture.owner, UploadRequest::Abort { id: first },),
            UploadResponse::Rejected {
                code: UploadErrorCode::Conflict,
            }
        );

        assert_eq!(fixture.store.reserved_bytes(), 11);

        drop(results);
        fixture.store.poll_verifications();

        assert!(fixture.store.verifier_disconnected);
        assert!(!fixture.store.entries[&first].verifying);

        for id in [first, second] {
            assert_eq!(
                fixture
                    .store
                    .handle(&fixture.owner, UploadRequest::Abort { id },),
                UploadResponse::Aborted { id }
            );
        }

        assert_eq!(fixture.store.reserved_bytes(), 0);
        assert_eq!(fixture.store.upload_count(), 0);

        // A disconnected verifier cannot admit new uploads.
        assert_eq!(
            fixture.store.handle(
                &fixture.owner,
                UploadRequest::Begin {
                    size: 0,
                    sha256: [0; 32],
                },
            ),
            UploadResponse::Rejected {
                code: UploadErrorCode::Unavailable,
            }
        );
    }

    #[test]
    fn verification_io_failure_is_terminal_and_cleanup_releases_quota() {
        let mut fixture = Fixture::new();
        let (jobs, results) = fixture.install_controlled_worker();

        let id = fixture.ready_upload(b"contents");

        assert_eq!(
            fixture
                .store
                .handle(&fixture.owner, UploadRequest::Finish { id },),
            UploadResponse::Verifying { id }
        );

        let job = jobs.try_recv().unwrap();
        assert_eq!(job.id, id);

        // Release the file as the real worker does before publishing
        // an error result.
        drop(job.file);

        assert!(
            results
                .send(VerificationResult {
                    id,
                    measured: Err(io::Error::other("injected verification read failure",)),
                })
                .is_ok()
        );

        fixture.store.poll_verifications();

        assert!(!fixture.store.entries[&id].verifying);
        assert!(!fixture.store.entries[&id].state.is_complete());
        assert_eq!(fixture.store.reserved_bytes(), 8);

        let rejected = UploadResponse::Rejected {
            code: UploadErrorCode::Unavailable,
        };

        for request in [
            UploadRequest::Status { id },
            UploadRequest::Finish { id },
            UploadRequest::Chunk {
                id,
                offset: 8,
                bytes: b"x",
            },
        ] {
            assert_eq!(fixture.store.handle(&fixture.owner, request), rejected);
        }

        // One failed file does not disable the verification service.
        assert!(!fixture.store.verifier_failed);

        assert_eq!(
            fixture
                .store
                .handle(&fixture.owner, UploadRequest::Abort { id },),
            UploadResponse::Aborted { id }
        );

        assert_eq!(fixture.store.reserved_bytes(), 0);
        assert_eq!(fixture.store.upload_count(), 0);
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;

    use aws_lc_rs::digest;
    use std::sync::mpsc::{Receiver, SyncSender};

    struct Fixture {
        store: UploadStore,
        root: PathBuf,
        owner: ClientIdentity,
        jobs: Receiver<VerificationJob>,
        results: SyncSender<VerificationResult>,
    }

    impl Fixture {
        fn new() -> Self {
            let rng = SystemRandom::new();
            let mut random = [0_u8; 16];
            rng.fill(&mut random).unwrap();

            let root = std::env::temp_dir().join(format!(
                "brn-cleanup-test-{}-{}",
                std::process::id(),
                upload_filename(UploadId(random))
            ));

            let limits = UploadLimits {
                max_file_size: 100,
                max_reserved_bytes: 400,
                max_uploads: 4,
                max_uploads_per_owner: 4,
            };

            let mut store = UploadStore::create(&root, limits).unwrap();

            let (worker, jobs, results) = VerificationWorker::controlled_for_test(4);

            store.verifier = worker;

            Self {
                store,
                root,
                owner: ClientIdentity::new("client:cleanup").unwrap(),
                jobs,
                results,
            }
        }

        fn begin(&mut self, bytes: &[u8]) -> UploadId {
            let digest = digest::digest(&digest::SHA256, bytes);
            let mut sha256 = [0; 32];
            sha256.copy_from_slice(digest.as_ref());

            match self.store.handle(
                &self.owner,
                UploadRequest::Begin {
                    size: bytes.len() as u64,
                    sha256,
                },
            ) {
                UploadResponse::Ready { id, .. } => id,
                response => panic!("unexpected response: {response:?}"),
            }
        }

        fn complete_one_job(&mut self) {
            let VerificationJob { id, mut file } = self.jobs.try_recv().unwrap();

            let measured = file.measure_sha256();
            drop(file);

            assert!(
                self.results
                    .send(VerificationResult { id, measured })
                    .is_ok()
            );

            self.store.poll_verifications();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // These tests drain submitted jobs before dropping fixtures.
            self.store.entries.clear();
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn expires_at_exact_idle_boundary_and_releases_quota() {
        let mut fixture = Fixture::new();
        let id = fixture.begin(b"abc");
        let since = fixture.store.entries[&id].idle_since;
        let timeout = Duration::from_secs(10);

        let early = fixture
            .store
            .cleanup_idle_at(since + Duration::from_secs(9), timeout, 1)
            .unwrap();

        assert_eq!(early, CleanupReport::default());

        let report = fixture
            .store
            .cleanup_idle_at(since + timeout, timeout, 1)
            .unwrap();

        assert_eq!(
            report,
            CleanupReport {
                attempted: 1,
                removed: 1,
                failed: 0,
                released_bytes: 3,
            }
        );

        assert_eq!(fixture.store.reserved_bytes(), 0);
        assert_eq!(fixture.store.upload_count(), 0);

        assert_eq!(
            fixture
                .store
                .handle(&fixture.owner, UploadRequest::Status { id },),
            UploadResponse::Rejected {
                code: UploadErrorCode::NotFound,
            }
        );
    }

    #[test]
    fn status_does_not_reset_idle_but_chunk_progress_does() {
        let mut fixture = Fixture::new();
        let id = fixture.begin(b"abc");

        let before = Instant::now();
        let old = before.checked_sub(Duration::from_secs(60)).unwrap();

        fixture.store.entries.get_mut(&id).unwrap().idle_since = old;

        assert!(matches!(
            fixture
                .store
                .handle(&fixture.owner, UploadRequest::Status { id },),
            UploadResponse::Ready { .. }
        ));

        assert_eq!(fixture.store.entries[&id].idle_since, old);

        assert_eq!(
            fixture.store.handle(
                &fixture.owner,
                UploadRequest::Chunk {
                    id,
                    offset: 0,
                    bytes: b"a",
                },
            ),
            UploadResponse::Progress { id, offset: 1 }
        );

        assert!(fixture.store.entries[&id].idle_since >= before);
    }

    #[test]
    fn cleanup_skips_pending_and_completed_verification() {
        let mut fixture = Fixture::new();
        let id = fixture.begin(b"");

        assert_eq!(
            fixture
                .store
                .handle(&fixture.owner, UploadRequest::Finish { id },),
            UploadResponse::Verifying { id }
        );

        let timeout = Duration::from_secs(10);
        let future = fixture.store.entries[&id].idle_since + Duration::from_secs(60);

        // This private helper deliberately does not poll results.
        let report = fixture.store.cleanup_idle_at(future, timeout, 4).unwrap();

        assert_eq!(report.attempted, 0);
        assert!(fixture.store.entries[&id].verifying);

        fixture.complete_one_job();
        assert!(fixture.store.entries[&id].state.is_complete());

        let future = fixture.store.entries[&id].idle_since + Duration::from_secs(60);

        let report = fixture.store.cleanup_idle_at(future, timeout, 4).unwrap();

        assert_eq!(report.attempted, 0);
        assert_eq!(fixture.store.upload_count(), 1);

        fixture.store.remove_completed(&fixture.owner, id).unwrap();
    }

    #[test]
    fn failed_cleanup_retains_quota_and_observes_retry_interval() {
        let mut fixture = Fixture::new();
        let id = fixture.begin(b"abc");

        let entry = fixture.store.entries.get_mut(&id).unwrap();
        let path = entry.path.clone();
        let since = entry.idle_since;

        // Close the handle before altering the test path.
        drop(entry.file.take());
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();

        let timeout = Duration::from_secs(10);
        let first_attempt = since + timeout;

        let report = fixture
            .store
            .cleanup_idle_at(first_attempt, timeout, 1)
            .unwrap();

        assert_eq!(report.attempted, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(report.removed, 0);
        assert_eq!(fixture.store.reserved_bytes(), 3);

        fs::remove_dir(&path).unwrap();

        let early = fixture
            .store
            .cleanup_idle_at(first_attempt + Duration::from_secs(9), timeout, 1)
            .unwrap();

        assert_eq!(early.attempted, 0);

        let retry = fixture
            .store
            .cleanup_idle_at(first_attempt + timeout, timeout, 1)
            .unwrap();

        assert_eq!(retry.removed, 1);
        assert_eq!(retry.released_bytes, 3);
        assert_eq!(fixture.store.reserved_bytes(), 0);
    }

    #[test]
    fn removal_budget_and_invalid_options_are_enforced() {
        let mut fixture = Fixture::new();
        fixture.begin(b"first");
        fixture.begin(b"second");

        let timeout = Duration::from_secs(10);
        let future = Instant::now() + Duration::from_secs(60);

        assert!(
            fixture
                .store
                .cleanup_idle_at(future, Duration::ZERO, 1)
                .is_err()
        );
        assert!(fixture.store.cleanup_idle_at(future, timeout, 0).is_err());

        let first = fixture.store.cleanup_idle_at(future, timeout, 1).unwrap();

        assert_eq!(first.attempted, 1);
        assert_eq!(first.removed, 1);
        assert_eq!(fixture.store.upload_count(), 1);

        let second = fixture.store.cleanup_idle_at(future, timeout, 1).unwrap();

        assert_eq!(second.removed, 1);
        assert_eq!(fixture.store.upload_count(), 0);
        assert_eq!(fixture.store.reserved_bytes(), 0);
    }
}
