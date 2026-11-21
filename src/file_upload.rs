use std::io;
use std::time::Duration;

use crate::ReadyClient;
use crate::file_transfer::application_error;
use crate::file_wire::{MAX_CHUNK_LEN, UploadId, UploadRequest, UploadResponse};

/// Maximum file-data bytes in one upload chunk.
///
/// This excludes file-transfer message metadata.
pub const MAX_FILE_CHUNK_LEN: usize = MAX_CHUNK_LEN;

/// Server-reported state of an upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileUploadStatus {
    /// Next chunk must start at this exclusive confirmed offset.
    Receiving { confirmed_offset: u64 },

    /// Verification is queued, running, or awaiting result processing.
    Verifying,

    /// The server reports successful size and digest verification.
    ///
    /// This does not imply publication outside its private storage.
    Complete,
}

/// Identifies an upload and retains its expected file metadata.
///
/// This handle owns no connection. Retain it across reconnections.
///
/// An upload ID is not authorization. The server requires an
/// authenticated identity with access to the upload.
///
/// Clone permits retaining checkpoints; it does not make concurrent
/// chunk submissions safe. Coordinate one sequential uploader per ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileUpload {
    id: UploadId,
    size: u64,
    sha256: [u8; 32],
}

impl FileUpload {
    /// Begins an upload on a ready, sequential BRN connection.
    ///
    /// The caller supplies the complete file size and expected SHA-256.
    /// This method does not read or hash a local file.
    ///
    /// The budget is passed to BRN's complete request/response operation.
    ///
    /// On any error, the connection is consumed and dropped.
    ///
    /// If the Begin response is lost, this method cannot recover the
    /// unknown server-generated ID. The abandoned server upload must
    /// eventually be removed by idle cleanup.
    pub fn begin(
        mut connection: ReadyClient,
        size: u64,
        sha256: [u8; 32],
        budget: Duration,
    ) -> io::Result<(ReadyClient, Self)> {
        let response = exchange(
            &mut connection,
            UploadRequest::Begin { size, sha256 },
            budget,
        )?;

        let upload = Self::from_begin_response(size, sha256, response)?;

        Ok((connection, upload))
    }

    /// Restores a previously retained upload checkpoint.
    ///
    /// This does not contact the server or validate upload existence.
    /// Query status on a newly authenticated connection before resuming.
    ///
    /// Store checkpoints in trusted application storage. Supplying
    /// inconsistent metadata will cause later validation to fail.
    pub fn from_parts(upload_id: [u8; 16], size: u64, sha256: [u8; 32]) -> Self {
        Self {
            id: UploadId(upload_id),
            size,
            sha256,
        }
    }

    pub fn upload_id(&self) -> [u8; 16] {
        self.id.0
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// Sends one chunk and returns the confirmed next offset.
    ///
    /// Use an offset obtained from the last acknowledgement or a fresh
    /// status query. Do not blindly replay a chunk after losing its
    /// response.
    ///
    /// On any error, the connection is consumed and dropped. The server
    /// may already have accepted the chunk. Reconnect and query status
    /// before deciding which bytes to send next.
    pub fn send_chunk(
        &self,
        mut connection: ReadyClient,
        offset: u64,
        bytes: &[u8],
        budget: Duration,
    ) -> io::Result<(ReadyClient, u64)> {
        let expected_end = self.check_chunk(offset, bytes)?;

        let response = exchange(
            &mut connection,
            UploadRequest::Chunk {
                id: self.id,
                offset,
                bytes,
            },
            budget,
        )?;

        let confirmed = self.check_progress(expected_end, response)?;

        Ok((connection, confirmed))
    }

    /// Queries the server's confirmed state.
    ///
    /// Status polling does not extend the server's idle-upload timer.
    /// On error, the connection is consumed and dropped.
    pub fn status(
        &self,
        mut connection: ReadyClient,
        budget: Duration,
    ) -> io::Result<(ReadyClient, FileUploadStatus)> {
        let response = exchange(
            &mut connection,
            UploadRequest::Status { id: self.id },
            budget,
        )?;

        let status = self.check_status(response)?;

        Ok((connection, status))
    }

    /// Requests final verification or queries an already-started finish.
    ///
    /// Receiving Verifying is not completion. Poll status with an
    /// application-selected delay rather than a tight loop.
    ///
    /// Queue saturation may return an application error. Reconnect,
    /// query status, and retry Finish if all bytes remain received.
    ///
    /// On error, the connection is consumed and dropped.
    pub fn finish(
        &self,
        mut connection: ReadyClient,
        budget: Duration,
    ) -> io::Result<(ReadyClient, FileUploadStatus)> {
        let response = exchange(
            &mut connection,
            UploadRequest::Finish { id: self.id },
            budget,
        )?;

        let status = self.check_finish(response)?;

        Ok((connection, status))
    }

    /// Cancels an incomplete upload.
    ///
    /// Cancellation conflicts with pending verification and completed
    /// uploads. Repeating a successful cancellation returns NotFound
    /// because the current server retains no cancellation tombstone.
    ///
    /// On error, the connection is consumed and dropped.
    pub fn abort(&self, mut connection: ReadyClient, budget: Duration) -> io::Result<ReadyClient> {
        let response = exchange(
            &mut connection,
            UploadRequest::Abort { id: self.id },
            budget,
        )?;

        self.check_abort(response)?;

        Ok(connection)
    }

    fn from_begin_response(
        size: u64,
        sha256: [u8; 32],
        response: UploadResponse,
    ) -> io::Result<Self> {
        match response {
            UploadResponse::Ready {
                id,
                size: returned_size,
                offset: 0,
            } if returned_size == size => Ok(Self { id, size, sha256 }),
            UploadResponse::Rejected { code } => Err(application_error(code)),
            _ => Err(protocol_error("unexpected upload Begin response")),
        }
    }

    fn check_chunk(&self, offset: u64, bytes: &[u8]) -> io::Result<u64> {
        if bytes.is_empty() || bytes.len() > MAX_FILE_CHUNK_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid upload chunk length",
            ));
        }

        let length = u64::try_from(bytes.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "upload chunk length overflow")
        })?;

        offset
            .checked_add(length)
            .filter(|end| *end <= self.size)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "upload chunk exceeds declared file size",
                )
            })
    }

    fn check_progress(&self, expected_end: u64, response: UploadResponse) -> io::Result<u64> {
        match response {
            UploadResponse::Progress { id, offset } if id == self.id && offset == expected_end => {
                Ok(offset)
            }
            UploadResponse::Rejected { code } => Err(application_error(code)),
            _ => Err(protocol_error("unexpected upload chunk response")),
        }
    }

    fn check_status(&self, response: UploadResponse) -> io::Result<FileUploadStatus> {
        match response {
            UploadResponse::Ready { id, size, offset }
                if id == self.id && size == self.size && offset <= size =>
            {
                Ok(FileUploadStatus::Receiving {
                    confirmed_offset: offset,
                })
            }
            response => self.check_finish(response),
        }
    }

    fn check_finish(&self, response: UploadResponse) -> io::Result<FileUploadStatus> {
        match response {
            UploadResponse::Verifying { id } if id == self.id => Ok(FileUploadStatus::Verifying),
            UploadResponse::Complete { id, size, sha256 }
                if id == self.id && size == self.size && sha256 == self.sha256 =>
            {
                Ok(FileUploadStatus::Complete)
            }
            UploadResponse::Rejected { code } => Err(application_error(code)),
            _ => Err(protocol_error(
                "unexpected upload status or Finish response",
            )),
        }
    }

    fn check_abort(&self, response: UploadResponse) -> io::Result<()> {
        match response {
            UploadResponse::Aborted { id } if id == self.id => Ok(()),
            UploadResponse::Rejected { code } => Err(application_error(code)),
            _ => Err(protocol_error("unexpected upload Abort response")),
        }
    }
}

fn exchange(
    connection: &mut ReadyClient,
    request: UploadRequest<'_>,
    budget: Duration,
) -> io::Result<UploadResponse> {
    let encoded = request.encode()?;
    let response = connection.request(&encoded, budget)?;

    UploadResponse::decode(&response)
}

fn protocol_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::file_wire::UploadErrorCode;

    fn upload() -> FileUpload {
        FileUpload::from_parts([0x42; 16], 10, [0x55; 32])
    }

    fn other_id() -> UploadId {
        UploadId([0x43; 16])
    }

    #[test]
    fn checkpoint_preserves_upload_metadata() {
        let upload = upload();

        assert_eq!(upload.upload_id(), [0x42; 16]);
        assert_eq!(upload.size(), 10);
        assert_eq!(upload.sha256(), &[0x55; 32]);

        assert_eq!(
            FileUpload::from_parts(upload.upload_id(), upload.size(), *upload.sha256(),),
            upload
        );
    }

    #[test]
    fn begin_requires_matching_size_and_zero_offset() {
        let id = upload().id;

        assert!(
            FileUpload::from_begin_response(
                10,
                [0x55; 32],
                UploadResponse::Ready {
                    id,
                    size: 10,
                    offset: 0,
                },
            )
            .is_ok()
        );

        for (size, offset) in [(11, 0), (10, 1)] {
            assert!(
                FileUpload::from_begin_response(
                    10,
                    [0x55; 32],
                    UploadResponse::Ready { id, size, offset },
                )
                .is_err()
            );
        }

        assert!(
            FileUpload::from_begin_response(10, [0x55; 32], UploadResponse::Verifying { id },)
                .is_err()
        );
    }

    #[test]
    fn chunk_validation_rejects_invalid_lengths_and_ranges() {
        let upload = upload();

        assert_eq!(upload.check_chunk(0, b"abc").unwrap(), 3);
        assert_eq!(upload.check_chunk(9, b"x").unwrap(), 10);

        assert!(upload.check_chunk(0, b"").is_err());
        assert!(upload.check_chunk(10, b"x").is_err());
        assert!(upload.check_chunk(u64::MAX, b"x").is_err());

        let oversized = vec![0; MAX_FILE_CHUNK_LEN + 1];
        assert!(upload.check_chunk(0, &oversized).is_err());
    }

    #[test]
    fn progress_requires_exact_id_and_expected_offset() {
        let upload = upload();

        assert_eq!(
            upload
                .check_progress(
                    3,
                    UploadResponse::Progress {
                        id: upload.id,
                        offset: 3,
                    },
                )
                .unwrap(),
            3
        );

        for response in [
            UploadResponse::Progress {
                id: other_id(),
                offset: 3,
            },
            UploadResponse::Progress {
                id: upload.id,
                offset: 4,
            },
            UploadResponse::Verifying { id: upload.id },
        ] {
            assert!(upload.check_progress(3, response).is_err());
        }
    }

    #[test]
    fn receiving_status_requires_matching_metadata() {
        let upload = upload();

        assert_eq!(
            upload
                .check_status(UploadResponse::Ready {
                    id: upload.id,
                    size: 10,
                    offset: 7,
                })
                .unwrap(),
            FileUploadStatus::Receiving {
                confirmed_offset: 7,
            }
        );

        for response in [
            UploadResponse::Ready {
                id: other_id(),
                size: 10,
                offset: 0,
            },
            UploadResponse::Ready {
                id: upload.id,
                size: 11,
                offset: 0,
            },
            UploadResponse::Ready {
                id: upload.id,
                size: 10,
                offset: 11,
            },
        ] {
            assert!(upload.check_status(response).is_err());
        }
    }

    #[test]
    fn completion_requires_matching_id_size_and_digest() {
        let upload = upload();

        assert_eq!(
            upload
                .check_finish(UploadResponse::Complete {
                    id: upload.id,
                    size: 10,
                    sha256: [0x55; 32],
                })
                .unwrap(),
            FileUploadStatus::Complete
        );

        for response in [
            UploadResponse::Complete {
                id: other_id(),
                size: 10,
                sha256: [0x55; 32],
            },
            UploadResponse::Complete {
                id: upload.id,
                size: 11,
                sha256: [0x55; 32],
            },
            UploadResponse::Complete {
                id: upload.id,
                size: 10,
                sha256: [0x66; 32],
            },
        ] {
            assert!(upload.check_finish(response).is_err());
        }

        assert_eq!(
            upload
                .check_finish(UploadResponse::Verifying { id: upload.id })
                .unwrap(),
            FileUploadStatus::Verifying
        );

        assert!(
            upload
                .check_finish(UploadResponse::Verifying { id: other_id() })
                .is_err()
        );
    }

    #[test]
    fn finish_and_abort_reject_wrong_response_kinds() {
        let upload = upload();

        assert!(
            upload
                .check_finish(UploadResponse::Ready {
                    id: upload.id,
                    size: 10,
                    offset: 10,
                })
                .is_err()
        );

        assert!(
            upload
                .check_abort(UploadResponse::Aborted { id: upload.id })
                .is_ok()
        );
        assert!(
            upload
                .check_abort(UploadResponse::Aborted { id: other_id() })
                .is_err()
        );
        assert!(
            upload
                .check_abort(UploadResponse::Verifying { id: upload.id })
                .is_err()
        );
    }

    #[test]
    fn application_rejections_are_not_accepted_as_success() {
        let upload = upload();

        let rejection = || UploadResponse::Rejected {
            code: UploadErrorCode::NotFound,
        };

        assert_eq!(
            upload.check_status(rejection()).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            upload.check_finish(rejection()).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            upload.check_progress(3, rejection()).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            upload.check_abort(rejection()).unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        assert_eq!(
            FileUpload::from_begin_response(10, [0; 32], rejection())
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }
}
