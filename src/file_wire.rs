use std::io;

use crate::seal::MAX_PLAINTEXT_LEN;

// Application-level protocol marker and version.
// Carried inside ordinary encrypted BRN application messages.
const PREFIX: &[u8; 5] = b"BRNF\x01";

// Request operation tags.
const BEGIN: u8 = 1;
const CHUNK: u8 = 2;
const STATUS: u8 = 3;
const FINISH: u8 = 4;
const ABORT: u8 = 5;

// Response operation tags.
const READY: u8 = 0x81;
const PROGRESS: u8 = 0x82;
const COMPLETE: u8 = 0x83;
const ABORTED: u8 = 0x84;
const VERIFYING: u8 = 0x85;
const REJECTED: u8 = 0xff;

const BASE_LEN: usize = PREFIX.len() + 1;
const ID_LEN: usize = 16;
const OFFSET_LEN: usize = 8;
const CHUNK_HEADER_LEN: usize = BASE_LEN + ID_LEN + OFFSET_LEN;

/// Maximum file data in one chunk request, excluding its metadata.
pub(crate) const MAX_CHUNK_LEN: usize = MAX_PLAINTEXT_LEN.saturating_sub(CHUNK_HEADER_LEN);
const _: () = assert!(MAX_CHUNK_LEN > 0);

/// Opaque upload identifier.
///
/// An ID identifies an upload; it does not authorize access.
/// The server must separately check the authenticated owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct UploadId(pub(crate) [u8; ID_LEN]);

/// File-transfer request carried inside one BRN application request.
///
/// Decoded chunks borrow the existing plaintext buffer.
/// File paths are deliberately absent from this protocol.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UploadRequest<'a> {
    Begin {
        size: u64,
        sha256: [u8; 32],
    },
    Chunk {
        id: UploadId,
        offset: u64,
        bytes: &'a [u8],
    },
    Status {
        id: UploadId,
    },
    Finish {
        id: UploadId,
    },
    Abort {
        id: UploadId,
    },
}

impl UploadRequest<'_> {
    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        // Validate before allocating or copying chunk contents.
        if let Self::Chunk { offset, bytes, .. } = self {
            validate_chunk(*offset, bytes)?;
        }

        let length = match self {
            Self::Begin { .. } => BASE_LEN + 8 + 32,
            Self::Chunk { bytes, .. } => CHUNK_HEADER_LEN + bytes.len(),
            Self::Status { .. } | Self::Finish { .. } | Self::Abort { .. } => BASE_LEN + ID_LEN,
        };

        if length > MAX_PLAINTEXT_LEN {
            return Err(invalid("file-transfer request exceeds payload limit"));
        }

        let mut output = Vec::with_capacity(length);
        output.extend_from_slice(PREFIX);

        match self {
            Self::Begin { size, sha256 } => {
                output.push(BEGIN);
                output.extend_from_slice(&size.to_be_bytes());
                output.extend_from_slice(sha256);
            }
            Self::Chunk { id, offset, bytes } => {
                output.push(CHUNK);
                output.extend_from_slice(&id.0);
                output.extend_from_slice(&offset.to_be_bytes());
                output.extend_from_slice(bytes);
            }
            Self::Status { id } => {
                output.push(STATUS);
                output.extend_from_slice(&id.0);
            }
            Self::Finish { id } => {
                output.push(FINISH);
                output.extend_from_slice(&id.0);
            }
            Self::Abort { id } => {
                output.push(ABORT);
                output.extend_from_slice(&id.0);
            }
        }

        Ok(output)
    }
}

impl<'a> UploadRequest<'a> {
    pub(crate) fn decode(input: &'a [u8]) -> io::Result<Self> {
        if input.len() > MAX_PLAINTEXT_LEN {
            return Err(invalid("file-transfer request exceeds payload limit"));
        }

        let mut reader = Reader { remaining: input };

        if reader.take(PREFIX.len())? != PREFIX {
            return Err(invalid("unsupported file-transfer protocol"));
        }

        let operation = reader.array::<1>()?[0];

        let request = match operation {
            BEGIN => Self::Begin {
                size: u64::from_be_bytes(reader.array()?),
                sha256: reader.array()?,
            },
            CHUNK => {
                let id = UploadId(reader.array()?);
                let offset = u64::from_be_bytes(reader.array()?);
                let bytes = reader.take_remaining();

                validate_chunk(offset, bytes)?;

                Self::Chunk { id, offset, bytes }
            }
            STATUS => Self::Status {
                id: UploadId(reader.array()?),
            },
            FINISH => Self::Finish {
                id: UploadId(reader.array()?),
            },
            ABORT => Self::Abort {
                id: UploadId(reader.array()?),
            },
            _ => return Err(invalid("unknown file-transfer operation")),
        };

        if !reader.remaining.is_empty() {
            return Err(invalid("trailing file-transfer request bytes"));
        }

        Ok(request)
    }
}

/// Application-level rejection.
///
/// These messages contain no filesystem paths, backend errors,
/// credentials, or other implementation details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum UploadErrorCode {
    InvalidRequest = 1,
    NotFound = 2,
    LimitExceeded = 3,
    OffsetMismatch = 4,
    Incomplete = 5,
    DigestMismatch = 6,
    Unavailable = 7,
    Expired = 8,
    Conflict = 9,
}

impl UploadErrorCode {
    fn decode(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::InvalidRequest),
            2 => Ok(Self::NotFound),
            3 => Ok(Self::LimitExceeded),
            4 => Ok(Self::OffsetMismatch),
            5 => Ok(Self::Incomplete),
            6 => Ok(Self::DigestMismatch),
            7 => Ok(Self::Unavailable),
            8 => Ok(Self::Expired),
            9 => Ok(Self::Conflict),
            _ => Err(invalid("unknown file-transfer error code")),
        }
    }
}

/// File-transfer response carried inside one BRN application response.
///
/// Storage, ownership, and request/response correlation checks happen
/// outside this codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UploadResponse {
    /// Upload exists and is accepting chunks or awaiting Finish.
    ///
    /// `offset == size` means all bytes are present, but verification
    /// has not necessarily started.
    Ready {
        id: UploadId,
        size: u64,
        offset: u64,
    },

    /// A chunk was accepted through the returned exclusive offset.
    Progress { id: UploadId, offset: u64 },

    /// Verification is queued, running, or awaiting result processing.
    ///
    /// This does not mean that size or digest verification succeeded.
    /// The client should poll Status instead of resending file data.
    Verifying { id: UploadId },

    /// The file passed complete size and digest verification.
    ///
    /// Also usable for Status or repeated Finish requests while
    /// completion metadata remains retained.
    Complete {
        id: UploadId,
        size: u64,
        sha256: [u8; 32],
    },

    /// The upload was cancelled.
    Aborted { id: UploadId },

    /// An application-level rejection, not a transport failure.
    Rejected { code: UploadErrorCode },
}

impl UploadResponse {
    pub(crate) fn encode(&self) -> io::Result<Vec<u8>> {
        if let Self::Ready { size, offset, .. } = self {
            validate_upload_position(*size, *offset)?;
        }

        let length = match self {
            Self::Ready { .. } => BASE_LEN + ID_LEN + 8 + 8,
            Self::Progress { .. } => BASE_LEN + ID_LEN + 8,
            Self::Complete { .. } => BASE_LEN + ID_LEN + 8 + 32,
            Self::Verifying { .. } | Self::Aborted { .. } => BASE_LEN + ID_LEN,
            Self::Rejected { .. } => BASE_LEN + 1,
        };

        if length > MAX_PLAINTEXT_LEN {
            return Err(invalid("file-transfer response exceeds payload limit"));
        }

        let mut output = Vec::with_capacity(length);
        output.extend_from_slice(PREFIX);

        match self {
            Self::Ready { id, size, offset } => {
                output.push(READY);
                output.extend_from_slice(&id.0);
                output.extend_from_slice(&size.to_be_bytes());
                output.extend_from_slice(&offset.to_be_bytes());
            }
            Self::Progress { id, offset } => {
                output.push(PROGRESS);
                output.extend_from_slice(&id.0);
                output.extend_from_slice(&offset.to_be_bytes());
            }
            Self::Verifying { id } => {
                output.push(VERIFYING);
                output.extend_from_slice(&id.0);
            }
            Self::Complete { id, size, sha256 } => {
                output.push(COMPLETE);
                output.extend_from_slice(&id.0);
                output.extend_from_slice(&size.to_be_bytes());
                output.extend_from_slice(sha256);
            }
            Self::Aborted { id } => {
                output.push(ABORTED);
                output.extend_from_slice(&id.0);
            }
            Self::Rejected { code } => {
                output.push(REJECTED);
                output.push(*code as u8);
            }
        }

        Ok(output)
    }

    pub(crate) fn decode(input: &[u8]) -> io::Result<Self> {
        if input.len() > MAX_PLAINTEXT_LEN {
            return Err(invalid("file-transfer response exceeds payload limit"));
        }

        let mut reader = Reader { remaining: input };

        if reader.take(PREFIX.len())? != PREFIX {
            return Err(invalid("unsupported file-transfer protocol"));
        }

        let operation = reader.array::<1>()?[0];

        let response = match operation {
            READY => {
                let id = UploadId(reader.array()?);
                let size = u64::from_be_bytes(reader.array()?);
                let offset = u64::from_be_bytes(reader.array()?);

                validate_upload_position(size, offset)?;

                Self::Ready { id, size, offset }
            }
            PROGRESS => Self::Progress {
                id: UploadId(reader.array()?),
                offset: u64::from_be_bytes(reader.array()?),
            },
            VERIFYING => Self::Verifying {
                id: UploadId(reader.array()?),
            },
            COMPLETE => Self::Complete {
                id: UploadId(reader.array()?),
                size: u64::from_be_bytes(reader.array()?),
                sha256: reader.array()?,
            },
            ABORTED => Self::Aborted {
                id: UploadId(reader.array()?),
            },
            REJECTED => Self::Rejected {
                code: UploadErrorCode::decode(reader.array::<1>()?[0])?,
            },
            _ => return Err(invalid("unknown file-transfer response")),
        };

        if !reader.remaining.is_empty() {
            return Err(invalid("trailing file-transfer response bytes"));
        }

        Ok(response)
    }
}

fn validate_chunk(offset: u64, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_CHUNK_LEN {
        return Err(invalid("invalid file-transfer chunk length"));
    }

    let length =
        u64::try_from(bytes.len()).map_err(|_| invalid("file-transfer chunk length overflow"))?;

    offset
        .checked_add(length)
        .ok_or_else(|| invalid("file-transfer offset overflow"))?;

    Ok(())
}

fn validate_upload_position(size: u64, offset: u64) -> io::Result<()> {
    if offset > size {
        return Err(invalid("upload offset exceeds declared file size"));
    }

    Ok(())
}

/// Bounded reader over an already received application message.
struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        if length > self.remaining.len() {
            return Err(invalid("truncated file-transfer message"));
        }

        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;

        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| invalid("invalid file-transfer field"))
    }

    fn take_remaining(&mut self) -> &'a [u8] {
        let bytes = self.remaining;
        self.remaining = &[];
        bytes
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> UploadId {
        UploadId([0x42; ID_LEN])
    }

    #[test]
    fn every_operation_roundtrips() {
        let requests = [
            UploadRequest::Begin {
                size: 10_000_000_000,
                sha256: [0x55; 32],
            },
            UploadRequest::Chunk {
                id: id(),
                offset: 9_000_000_000,
                bytes: b"file contents",
            },
            UploadRequest::Status { id: id() },
            UploadRequest::Finish { id: id() },
            UploadRequest::Abort { id: id() },
        ];

        for request in requests {
            let encoded = request.encode().unwrap();
            let decoded = UploadRequest::decode(&encoded).unwrap();

            assert_eq!(decoded, request);
        }
    }

    #[test]
    fn begin_has_stable_wire_encoding() {
        let encoded = UploadRequest::Begin {
            size: 258,
            sha256: [0x55; 32],
        }
        .encode()
        .unwrap();

        let mut expected = b"BRNF\x01\x01".to_vec();
        expected.extend_from_slice(&258_u64.to_be_bytes());
        expected.extend_from_slice(&[0x55; 32]);

        assert_eq!(encoded, expected);
    }

    #[test]
    fn rejects_every_truncated_fixed_length_request() {
        for request in [
            UploadRequest::Begin {
                size: 10,
                sha256: [0; 32],
            },
            UploadRequest::Status { id: id() },
            UploadRequest::Finish { id: id() },
            UploadRequest::Abort { id: id() },
        ] {
            let encoded = request.encode().unwrap();

            for length in 0..encoded.len() {
                assert!(
                    UploadRequest::decode(&encoded[..length]).is_err(),
                    "accepted truncated request of length {length}"
                );
            }
        }
    }

    #[test]
    fn rejects_trailing_fixed_length_request_bytes() {
        for request in [
            UploadRequest::Begin {
                size: 0,
                sha256: [0; 32],
            },
            UploadRequest::Status { id: id() },
            UploadRequest::Finish { id: id() },
            UploadRequest::Abort { id: id() },
        ] {
            let mut encoded = request.encode().unwrap();
            encoded.push(0);

            assert!(UploadRequest::decode(&encoded).is_err());
        }
    }

    #[test]
    fn rejects_bad_marker_version_and_operation() {
        let encoded = UploadRequest::Status { id: id() }.encode().unwrap();

        for index in 0..BASE_LEN {
            let mut modified = encoded.clone();
            modified[index] = 0xff;

            assert!(UploadRequest::decode(&modified).is_err());
        }
    }

    #[test]
    fn maximum_chunk_fits_core_payload_and_roundtrips() {
        let bytes = vec![0x5a; MAX_CHUNK_LEN];
        let request = UploadRequest::Chunk {
            id: id(),
            offset: 0,
            bytes: &bytes,
        };

        let encoded = request.encode().unwrap();

        assert_eq!(encoded.len(), MAX_PLAINTEXT_LEN);
        assert_eq!(UploadRequest::decode(&encoded).unwrap(), request);
    }

    #[test]
    fn rejects_empty_chunks_on_encode_and_decode() {
        let request = UploadRequest::Chunk {
            id: id(),
            offset: 0,
            bytes: b"",
        };

        assert!(request.encode().is_err());

        let mut encoded = PREFIX.to_vec();
        encoded.push(CHUNK);
        encoded.extend_from_slice(&id().0);
        encoded.extend_from_slice(&0_u64.to_be_bytes());

        assert!(UploadRequest::decode(&encoded).is_err());
    }

    #[test]
    fn rejects_oversized_chunks_on_encode_and_decode() {
        let bytes = vec![0; MAX_CHUNK_LEN + 1];

        assert!(
            UploadRequest::Chunk {
                id: id(),
                offset: 0,
                bytes: &bytes,
            }
            .encode()
            .is_err()
        );

        let mut encoded = PREFIX.to_vec();
        encoded.push(CHUNK);
        encoded.extend_from_slice(&id().0);
        encoded.extend_from_slice(&0_u64.to_be_bytes());
        encoded.extend_from_slice(&bytes);

        assert!(UploadRequest::decode(&encoded).is_err());
    }

    #[test]
    fn rejects_offset_overflow_on_encode_and_decode() {
        assert!(
            UploadRequest::Chunk {
                id: id(),
                offset: u64::MAX,
                bytes: b"x",
            }
            .encode()
            .is_err()
        );

        let mut encoded = PREFIX.to_vec();
        encoded.push(CHUNK);
        encoded.extend_from_slice(&id().0);
        encoded.extend_from_slice(&u64::MAX.to_be_bytes());
        encoded.push(b'x');

        assert!(UploadRequest::decode(&encoded).is_err());
    }

    #[test]
    fn decoded_chunk_borrows_input_storage() {
        let encoded = UploadRequest::Chunk {
            id: id(),
            offset: 123,
            bytes: b"contents",
        }
        .encode()
        .unwrap();

        let UploadRequest::Chunk { bytes, .. } = UploadRequest::decode(&encoded).unwrap() else {
            panic!("expected a chunk");
        };

        assert_eq!(bytes.as_ptr(), encoded[CHUNK_HEADER_LEN..].as_ptr());
        assert_eq!(bytes, b"contents");
    }

    #[test]
    fn rejects_chunk_headers_without_data() {
        let encoded = UploadRequest::Chunk {
            id: id(),
            offset: 0,
            bytes: b"x",
        }
        .encode()
        .unwrap();

        for length in 0..=CHUNK_HEADER_LEN {
            assert!(UploadRequest::decode(&encoded[..length]).is_err());
        }
    }
}

#[cfg(test)]
mod response_tests {
    use super::*;

    fn id() -> UploadId {
        UploadId([0x42; ID_LEN])
    }

    fn responses() -> Vec<UploadResponse> {
        vec![
            UploadResponse::Ready {
                id: id(),
                size: 10_000_000_000,
                offset: 9_000_000_000,
            },
            UploadResponse::Progress {
                id: id(),
                offset: 9_000_000_001,
            },
            UploadResponse::Complete {
                id: id(),
                size: 10_000_000_000,
                sha256: [0x55; 32],
            },
            UploadResponse::Aborted { id: id() },
            UploadResponse::Rejected {
                code: UploadErrorCode::Unavailable,
            },
            UploadResponse::Verifying { id: id() },
        ]
    }

    #[test]
    fn every_response_roundtrips() {
        for response in responses() {
            let encoded = response.encode().unwrap();

            assert_eq!(UploadResponse::decode(&encoded).unwrap(), response);
        }
    }

    #[test]
    fn progress_has_stable_wire_encoding() {
        let encoded = UploadResponse::Progress {
            id: id(),
            offset: 258,
        }
        .encode()
        .unwrap();

        let mut expected = b"BRNF\x01\x82".to_vec();
        expected.extend_from_slice(&id().0);
        expected.extend_from_slice(&258_u64.to_be_bytes());

        assert_eq!(encoded, expected);
    }

    #[test]
    fn rejects_every_truncated_response() {
        for response in responses() {
            let encoded = response.encode().unwrap();

            for length in 0..encoded.len() {
                assert!(
                    UploadResponse::decode(&encoded[..length]).is_err(),
                    "accepted truncated response of length {length}"
                );
            }
        }
    }

    #[test]
    fn rejects_trailing_response_bytes() {
        for response in responses() {
            let mut encoded = response.encode().unwrap();
            encoded.push(0);

            assert!(UploadResponse::decode(&encoded).is_err());
        }
    }

    #[test]
    fn rejects_bad_response_marker_version_and_operation() {
        let encoded = UploadResponse::Aborted { id: id() }.encode().unwrap();

        for index in 0..BASE_LEN {
            let mut modified = encoded.clone();
            modified[index] = 0;

            assert!(UploadResponse::decode(&modified).is_err());
        }
    }

    #[test]
    fn validates_ready_offsets_on_encode_and_decode() {
        assert!(
            UploadResponse::Ready {
                id: id(),
                size: 10,
                offset: 11,
            }
            .encode()
            .is_err()
        );

        let mut encoded = UploadResponse::Ready {
            id: id(),
            size: 10,
            offset: 10,
        }
        .encode()
        .unwrap();

        let offset_start = BASE_LEN + ID_LEN + 8;
        encoded[offset_start..].copy_from_slice(&11_u64.to_be_bytes());

        assert!(UploadResponse::decode(&encoded).is_err());
    }

    #[test]
    fn accepts_empty_files_and_fully_received_pending_uploads() {
        for (size, offset) in [(0, 0), (10, 10), (u64::MAX, u64::MAX)] {
            let response = UploadResponse::Ready {
                id: id(),
                size,
                offset,
            };

            let encoded = response.encode().unwrap();

            assert_eq!(UploadResponse::decode(&encoded).unwrap(), response);
        }
    }

    #[test]
    fn error_codes_roundtrip_and_unknown_values_are_rejected() {
        let codes = [
            UploadErrorCode::InvalidRequest,
            UploadErrorCode::NotFound,
            UploadErrorCode::LimitExceeded,
            UploadErrorCode::OffsetMismatch,
            UploadErrorCode::Incomplete,
            UploadErrorCode::DigestMismatch,
            UploadErrorCode::Unavailable,
            UploadErrorCode::Expired,
            UploadErrorCode::Conflict,
        ];

        for code in codes {
            let response = UploadResponse::Rejected { code };
            let encoded = response.encode().unwrap();

            assert_eq!(UploadResponse::decode(&encoded).unwrap(), response);
        }

        for code in [0, 10, 127, 255] {
            let mut encoded = PREFIX.to_vec();
            encoded.push(REJECTED);
            encoded.push(code);

            assert!(UploadResponse::decode(&encoded).is_err());
        }
    }

    #[test]
    fn requests_and_responses_cannot_be_confused() {
        let request = UploadRequest::Status { id: id() }.encode().unwrap();

        assert!(UploadResponse::decode(&request).is_err());

        for response in responses() {
            let encoded = response.encode().unwrap();

            assert!(UploadRequest::decode(&encoded).is_err());
        }
    }

    #[test]
    fn rejects_responses_above_core_payload_limit() {
        let encoded = vec![0; MAX_PLAINTEXT_LEN + 1];

        assert!(UploadResponse::decode(&encoded).is_err());
    }
}

#[cfg(test)]
mod verification_response_tests {
    use super::*;

    #[test]
    fn verifying_has_stable_wire_encoding() {
        let id = UploadId([0x42; 16]);
        let response = UploadResponse::Verifying { id };

        let encoded = response.encode().unwrap();

        let mut expected = b"BRNF\x01\x85".to_vec();
        expected.extend_from_slice(&id.0);

        assert_eq!(encoded, expected);
        assert_eq!(UploadResponse::decode(&encoded).unwrap(), response);
        assert!(UploadRequest::decode(&encoded).is_err());
    }

    #[test]
    fn verifying_is_distinct_from_ready_and_complete() {
        let id = UploadId([0x42; 16]);

        let verifying = UploadResponse::Verifying { id };
        let ready = UploadResponse::Ready {
            id,
            size: 10,
            offset: 10,
        };
        let complete = UploadResponse::Complete {
            id,
            size: 10,
            sha256: [0x55; 32],
        };

        assert_ne!(verifying, ready);
        assert_ne!(verifying, complete);

        let encoded = verifying.encode().unwrap();

        assert_eq!(encoded.len(), BASE_LEN + ID_LEN);
        assert!(matches!(
            UploadResponse::decode(&encoded).unwrap(),
            UploadResponse::Verifying { id: decoded_id }
                if decoded_id == id
        ));
    }
}
