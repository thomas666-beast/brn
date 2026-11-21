use crate::auth::ClientIdentity;
use crate::file_wire::{MAX_CHUNK_LEN, UploadErrorCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadPhase {
    Receiving,
    Complete,
    Aborted,
}

/// Server-side metadata for one upload.
///
/// This is not Clone or Copy. Storage must serialize operations on
/// each upload, including validation, disk I/O, and offset updates.
pub(crate) struct UploadState {
    owner: ClientIdentity,
    size: u64,
    sha256: [u8; 32],
    offset: u64,
    phase: UploadPhase,
}

impl UploadState {
    /// Creates metadata after the storage layer has admitted the upload.
    ///
    /// Storage must separately enforce aggregate quotas, upload counts,
    /// authorization to create uploads, and available storage policy.
    pub(crate) fn new(
        owner: ClientIdentity,
        size: u64,
        sha256: [u8; 32],
        max_file_size: u64,
    ) -> Result<Self, UploadErrorCode> {
        if size > max_file_size {
            return Err(UploadErrorCode::LimitExceeded);
        }

        Ok(Self {
            owner,
            size,
            sha256,
            offset: 0,
            phase: UploadPhase::Receiving,
        })
    }

    /// Unknown uploads and uploads owned by another identity should
    /// have the same public NotFound response.
    pub(crate) fn check_owner(&self, identity: &ClientIdentity) -> Result<(), UploadErrorCode> {
        if &self.owner != identity {
            return Err(UploadErrorCode::NotFound);
        }

        Ok(())
    }

    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn offset(&self) -> u64 {
        self.offset
    }

    pub(crate) fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.phase == UploadPhase::Complete
    }

    pub(crate) fn is_aborted(&self) -> bool {
        self.phase == UploadPhase::Aborted
    }

    /// Validates a chunk without advancing the confirmed offset.
    ///
    /// Returns the exclusive end offset that would result from
    /// successfully storing this chunk.
    pub(crate) fn check_chunk(
        &self,
        identity: &ClientIdentity,
        offset: u64,
        length: usize,
    ) -> Result<u64, UploadErrorCode> {
        self.check_owner(identity)?;
        self.check_receiving()?;

        if length == 0 || length > MAX_CHUNK_LEN {
            return Err(UploadErrorCode::InvalidRequest);
        }

        if offset != self.offset {
            return Err(UploadErrorCode::OffsetMismatch);
        }

        let length = u64::try_from(length).map_err(|_| UploadErrorCode::InvalidRequest)?;

        let end = offset
            .checked_add(length)
            .ok_or(UploadErrorCode::InvalidRequest)?;

        if end > self.size {
            return Err(UploadErrorCode::InvalidRequest);
        }

        Ok(end)
    }

    /// Advances metadata after the exact chunk has been stored.
    ///
    /// The caller must retain exclusive access to this upload across
    /// check_chunk(), disk I/O, and this call.
    ///
    /// This method performs no disk I/O and provides no durability
    /// guarantee by itself.
    pub(crate) fn commit_chunk(
        &mut self,
        identity: &ClientIdentity,
        offset: u64,
        length: usize,
    ) -> Result<u64, UploadErrorCode> {
        let end = self.check_chunk(identity, offset, length)?;
        self.offset = end;

        Ok(end)
    }

    /// Checks whether final verification may begin.
    ///
    /// A completed upload also passes, allowing storage to handle
    /// a repeated Finish request using retained completion metadata.
    pub(crate) fn check_finish(&self, identity: &ClientIdentity) -> Result<(), UploadErrorCode> {
        self.check_owner(identity)?;

        match self.phase {
            UploadPhase::Aborted => Err(UploadErrorCode::Conflict),
            UploadPhase::Complete => Ok(()),
            UploadPhase::Receiving if self.offset == self.size => Ok(()),
            UploadPhase::Receiving => Err(UploadErrorCode::Incomplete),
        }
    }

    /// Marks completion after storage verifies the actual file.
    ///
    /// `actual_size` and `actual_sha256` must be obtained by storage,
    /// never copied from client-provided completion claims.
    ///
    /// This transition records verified completion in memory only.
    /// It does not publish the file or persist recovery metadata.
    ///
    /// Applications that add publication or restart recovery must
    /// define and enforce those guarantees separately.
    pub(crate) fn mark_complete(
        &mut self,
        identity: &ClientIdentity,
        actual_size: u64,
        actual_sha256: &[u8; 32],
    ) -> Result<(), UploadErrorCode> {
        self.check_finish(identity)?;

        if actual_size != self.size {
            return Err(UploadErrorCode::Incomplete);
        }

        if actual_sha256 != &self.sha256 {
            return Err(UploadErrorCode::DigestMismatch);
        }

        self.phase = UploadPhase::Complete;

        Ok(())
    }

    /// Marks an incomplete upload cancelled.
    ///
    /// Repeating cancellation is allowed while metadata is retained.
    /// Storage must separately remove the temporary file and release
    /// quota before reporting successful cleanup.
    pub(crate) fn mark_aborted(
        &mut self,
        identity: &ClientIdentity,
    ) -> Result<(), UploadErrorCode> {
        self.check_owner(identity)?;

        if self.phase == UploadPhase::Complete {
            return Err(UploadErrorCode::Conflict);
        }

        self.phase = UploadPhase::Aborted;

        Ok(())
    }

    fn check_receiving(&self) -> Result<(), UploadErrorCode> {
        if self.phase != UploadPhase::Receiving {
            return Err(UploadErrorCode::Conflict);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> ClientIdentity {
        ClientIdentity::new("client:alice").unwrap()
    }

    fn other() -> ClientIdentity {
        ClientIdentity::new("client:bob").unwrap()
    }

    fn upload(size: u64) -> UploadState {
        UploadState::new(owner(), size, [0x55; 32], u64::MAX).unwrap()
    }

    #[test]
    fn enforces_file_size_limit_without_truncating_large_sizes() {
        let state = UploadState::new(owner(), 10_000_000_000, [0; 32], 10_000_000_000).unwrap();

        assert_eq!(state.size(), 10_000_000_000);
        assert_eq!(state.offset(), 0);
        assert_eq!(state.sha256(), &[0; 32]);

        assert!(matches!(
            UploadState::new(owner(), 10_000_000_001, [0; 32], 10_000_000_000),
            Err(UploadErrorCode::LimitExceeded)
        ));
    }

    #[test]
    fn validation_does_not_commit_bytes() {
        let mut state = upload(10);

        assert_eq!(state.check_chunk(&owner(), 0, 4), Ok(4));
        assert_eq!(state.offset(), 0);

        assert_eq!(state.commit_chunk(&owner(), 0, 4), Ok(4));
        assert_eq!(state.offset(), 4);

        assert_eq!(state.commit_chunk(&owner(), 4, 6), Ok(10));
        assert_eq!(state.offset(), 10);
        assert!(!state.is_complete());
    }

    #[test]
    fn rejects_wrong_offsets_lengths_and_file_overruns() {
        let mut state = upload(10);

        assert_eq!(
            state.check_chunk(&owner(), 1, 1),
            Err(UploadErrorCode::OffsetMismatch)
        );
        assert_eq!(
            state.check_chunk(&owner(), 0, 0),
            Err(UploadErrorCode::InvalidRequest)
        );
        assert_eq!(
            state.check_chunk(&owner(), 0, MAX_CHUNK_LEN + 1),
            Err(UploadErrorCode::InvalidRequest)
        );
        assert_eq!(
            state.check_chunk(&owner(), 0, 11),
            Err(UploadErrorCode::InvalidRequest)
        );

        state.commit_chunk(&owner(), 0, 4).unwrap();

        assert_eq!(
            state.commit_chunk(&owner(), 0, 4),
            Err(UploadErrorCode::OffsetMismatch)
        );
        assert_eq!(state.offset(), 4);
    }

    #[test]
    fn wrong_owner_cannot_read_or_change_upload_state() {
        let mut state = upload(10);

        assert_eq!(state.check_owner(&other()), Err(UploadErrorCode::NotFound));
        assert_eq!(
            state.check_chunk(&other(), 0, 1),
            Err(UploadErrorCode::NotFound)
        );
        assert_eq!(
            state.commit_chunk(&other(), 0, 1),
            Err(UploadErrorCode::NotFound)
        );
        assert_eq!(state.check_finish(&other()), Err(UploadErrorCode::NotFound));
        assert_eq!(
            state.mark_complete(&other(), 10, &[0x55; 32]),
            Err(UploadErrorCode::NotFound)
        );
        assert_eq!(state.mark_aborted(&other()), Err(UploadErrorCode::NotFound));

        assert_eq!(state.offset(), 0);
        assert!(!state.is_complete());
        assert!(!state.is_aborted());
    }

    #[test]
    fn completion_requires_all_bytes_and_verified_digest() {
        let mut state = upload(4);

        assert_eq!(
            state.check_finish(&owner()),
            Err(UploadErrorCode::Incomplete)
        );

        state.commit_chunk(&owner(), 0, 4).unwrap();

        assert_eq!(
            state.mark_complete(&owner(), 3, &[0x55; 32]),
            Err(UploadErrorCode::Incomplete)
        );
        assert_eq!(
            state.mark_complete(&owner(), 4, &[0x66; 32]),
            Err(UploadErrorCode::DigestMismatch)
        );
        assert!(!state.is_complete());

        state.mark_complete(&owner(), 4, &[0x55; 32]).unwrap();

        assert!(state.is_complete());
        assert!(state.check_finish(&owner()).is_ok());

        // Repeating a verified completion is allowed.
        state.mark_complete(&owner(), 4, &[0x55; 32]).unwrap();

        assert_eq!(
            state.check_chunk(&owner(), 4, 1),
            Err(UploadErrorCode::Conflict)
        );
        assert_eq!(state.mark_aborted(&owner()), Err(UploadErrorCode::Conflict));
    }

    #[test]
    fn aborted_upload_cannot_receive_or_finish() {
        let mut state = upload(10);

        state.mark_aborted(&owner()).unwrap();
        state.mark_aborted(&owner()).unwrap();

        assert!(state.is_aborted());
        assert_eq!(
            state.check_chunk(&owner(), 0, 1),
            Err(UploadErrorCode::Conflict)
        );
        assert_eq!(state.check_finish(&owner()), Err(UploadErrorCode::Conflict));
    }

    #[test]
    fn empty_file_still_requires_digest_verification() {
        let mut state = upload(0);

        assert!(state.check_finish(&owner()).is_ok());
        assert_eq!(
            state.mark_complete(&owner(), 0, &[0; 32]),
            Err(UploadErrorCode::DigestMismatch)
        );

        // Fixed test digest only; this test does not hash a file.
        state.mark_complete(&owner(), 0, &[0x55; 32]).unwrap();

        assert!(state.is_complete());
    }

    #[test]
    fn rejects_offset_addition_overflow() {
        let mut state = upload(u64::MAX);

        // Internal test setup avoids writing an enormous file.
        state.offset = u64::MAX;

        assert_eq!(
            state.check_chunk(&owner(), u64::MAX, 1),
            Err(UploadErrorCode::InvalidRequest)
        );
        assert_eq!(state.offset(), u64::MAX);
    }
}
