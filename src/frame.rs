use std::error::Error;
use std::fmt;

const MAGIC: [u8; 4] = *b"BRN\x01";

pub(crate) const HEADER_LEN: usize = 9;
pub(crate) const MAX_BODY_LEN: u32 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum FrameKind {
    Control = 1,
    Encrypted = 2,
}

impl TryFrom<u8> for FrameKind {
    type Error = FrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Control),
            2 => Ok(Self::Encrypted),
            other => Err(FrameError::UnknownKind(other)),
        }
    }
}

/// A validated outer frame header.
///
/// Fields are private so callers cannot bypass construction checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FrameHeader {
    kind: FrameKind,
    body_len: u32,
}

impl FrameHeader {
    pub(crate) fn new(kind: FrameKind, body_len: u32) -> Result<Self, FrameError> {
        if body_len == 0 {
            return Err(FrameError::EmptyBody);
        }

        if body_len > MAX_BODY_LEN {
            return Err(FrameError::BodyTooLarge {
                received: body_len,
                maximum: MAX_BODY_LEN,
            });
        }

        Ok(Self { kind, body_len })
    }

    pub(crate) fn kind(&self) -> FrameKind {
        self.kind
    }

    pub(crate) fn body_len(&self) -> u32 {
        self.body_len
    }

    pub(crate) fn encode(&self) -> [u8; HEADER_LEN] {
        let mut bytes = [0; HEADER_LEN];

        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4] = self.kind as u8;
        bytes[5..9].copy_from_slice(&self.body_len.to_be_bytes());

        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() != HEADER_LEN {
            return Err(FrameError::InvalidHeaderLength {
                received: bytes.len(),
            });
        }

        if bytes[..4] != MAGIC {
            return Err(FrameError::InvalidMagic);
        }

        let kind = FrameKind::try_from(bytes[4])?;
        let body_len = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);

        Self::new(kind, body_len)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FrameError {
    InvalidHeaderLength { received: usize },
    InvalidMagic,
    UnknownKind(u8),
    EmptyBody,
    BodyTooLarge { received: u32, maximum: u32 },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeaderLength { received } => write!(
                f,
                "invalid frame header length: expected {HEADER_LEN}, got {received}"
            ),
            Self::InvalidMagic => {
                write!(f, "invalid BRN magic or framing version")
            }
            Self::UnknownKind(kind) => {
                write!(f, "unknown frame kind: {kind}")
            }
            Self::EmptyBody => {
                write!(f, "frame body must not be empty")
            }
            Self::BodyTooLarge { received, maximum } => {
                write!(f, "frame body length {received} exceeds maximum {maximum}")
            }
        }
    }
}

impl Error for FrameError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_matches_wire_format() {
        let header = FrameHeader::new(FrameKind::Encrypted, 258).unwrap();

        assert_eq!(header.encode(), [b'B', b'R', b'N', 1, 2, 0, 0, 1, 2]);
    }

    #[test]
    fn valid_headers_round_trip() {
        for kind in [FrameKind::Control, FrameKind::Encrypted] {
            for body_len in [1, 258, MAX_BODY_LEN] {
                let header = FrameHeader::new(kind, body_len).unwrap();
                let decoded = FrameHeader::decode(&header.encode()).unwrap();

                assert_eq!(decoded, header);
                assert_eq!(decoded.kind(), kind);
                assert_eq!(decoded.body_len(), body_len);
            }
        }
    }

    #[test]
    fn rejects_incorrect_header_lengths() {
        for length in [0, 1, HEADER_LEN - 1, HEADER_LEN + 1, 32] {
            let bytes = vec![0; length];

            assert_eq!(
                FrameHeader::decode(&bytes),
                Err(FrameError::InvalidHeaderLength { received: length })
            );
        }
    }

    #[test]
    fn rejects_invalid_magic_or_version() {
        let valid = FrameHeader::new(FrameKind::Control, 1).unwrap().encode();

        for index in 0..4 {
            let mut bytes = valid;
            bytes[index] ^= 0xff;

            assert_eq!(FrameHeader::decode(&bytes), Err(FrameError::InvalidMagic));
        }
    }

    #[test]
    fn rejects_every_unknown_kind() {
        let valid = FrameHeader::new(FrameKind::Control, 1).unwrap().encode();

        for kind in 0..=u8::MAX {
            if kind == 1 || kind == 2 {
                continue;
            }

            let mut bytes = valid;
            bytes[4] = kind;

            assert_eq!(
                FrameHeader::decode(&bytes),
                Err(FrameError::UnknownKind(kind))
            );
        }
    }

    #[test]
    fn rejects_empty_and_oversized_bodies() {
        for body_len in [0, MAX_BODY_LEN + 1, u32::MAX] {
            let expected = if body_len == 0 {
                FrameError::EmptyBody
            } else {
                FrameError::BodyTooLarge {
                    received: body_len,
                    maximum: MAX_BODY_LEN,
                }
            };

            assert_eq!(
                FrameHeader::new(FrameKind::Control, body_len),
                Err(expected)
            );

            let mut bytes = [b'B', b'R', b'N', 1, 1, 0, 0, 0, 0];
            bytes[5..9].copy_from_slice(&body_len.to_be_bytes());

            assert_eq!(FrameHeader::decode(&bytes), Err(expected));
        }
    }
}
