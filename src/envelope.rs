use std::io;

use crate::frame::{FrameHeader, FrameKind};
use crate::seal::MAX_PLAINTEXT_LEN;
use crate::sequence::MAX_MESSAGES_PER_KEY;

pub(crate) const ENVELOPE_HEADER_LEN: usize = 11;
pub(crate) const AUTH_TAG_LEN: usize = 16;

const ENVELOPE_VERSION: u8 = 1;
const DOMAIN: &[u8] = b"BRN-AEAD-V1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Direction {
    ClientToServer = 1,
    ServerToClient = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum MessagePurpose {
    KeyConfirmation = 1,
    Request = 2,
    Response = 3,
}

/// Structurally validated metadata, not yet cryptographically verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EnvelopeHeader {
    direction: Direction,
    purpose: MessagePurpose,
    sequence: u64,
}

impl EnvelopeHeader {
    pub(crate) fn new(
        direction: Direction,
        purpose: MessagePurpose,
        sequence: u64,
    ) -> io::Result<Self> {
        if sequence >= MAX_MESSAGES_PER_KEY {
            return Err(invalid("envelope sequence exceeds key limit"));
        }

        let valid_direction = match purpose {
            MessagePurpose::KeyConfirmation => true,
            MessagePurpose::Request => direction == Direction::ClientToServer,
            MessagePurpose::Response => direction == Direction::ServerToClient,
        };

        if !valid_direction {
            return Err(invalid("message purpose is invalid for its direction"));
        }

        Ok(Self {
            direction,
            purpose,
            sequence,
        })
    }

    pub(crate) fn direction(&self) -> Direction {
        self.direction
    }

    pub(crate) fn purpose(&self) -> MessagePurpose {
        self.purpose
    }

    pub(crate) fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) fn encode(&self) -> [u8; ENVELOPE_HEADER_LEN] {
        let mut bytes = [0; ENVELOPE_HEADER_LEN];

        bytes[0] = ENVELOPE_VERSION;
        bytes[1] = self.direction as u8;
        bytes[2] = self.purpose as u8;
        bytes[3..].copy_from_slice(&self.sequence.to_be_bytes());

        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != ENVELOPE_HEADER_LEN {
            return Err(invalid("invalid envelope header length"));
        }

        if bytes[0] != ENVELOPE_VERSION {
            return Err(invalid("unsupported envelope version"));
        }

        let direction = match bytes[1] {
            1 => Direction::ClientToServer,
            2 => Direction::ServerToClient,
            _ => return Err(invalid("unknown envelope direction")),
        };

        let purpose = match bytes[2] {
            1 => MessagePurpose::KeyConfirmation,
            2 => MessagePurpose::Request,
            3 => MessagePurpose::Response,
            _ => return Err(invalid("unknown envelope purpose")),
        };

        let sequence_bytes: [u8; 8] = bytes[3..]
            .try_into()
            .map_err(|_| invalid("invalid envelope sequence encoding"))?;

        Self::new(direction, purpose, u64::from_be_bytes(sequence_bytes))
    }

    /// Constructs canonical AEAD associated data.
    ///
    /// Includes the exact canonical outer frame header and envelope header.
    /// `ciphertext_len` includes the authentication tag.
    pub(crate) fn authenticated_data(&self, ciphertext_len: usize) -> io::Result<Vec<u8>> {
        if !(AUTH_TAG_LEN..=MAX_PLAINTEXT_LEN + AUTH_TAG_LEN).contains(&ciphertext_len) {
            return Err(invalid("invalid encrypted body length"));
        }

        let body_len = ENVELOPE_HEADER_LEN + ciphertext_len;

        let outer = FrameHeader::new(FrameKind::Encrypted, body_len as u32)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

        let mut data =
            Vec::with_capacity(DOMAIN.len() + outer.encode().len() + ENVELOPE_HEADER_LEN);

        data.extend_from_slice(DOMAIN);
        data.extend_from_slice(&outer.encode());
        data.extend_from_slice(&self.encode());

        Ok(data)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_matches_wire_format_and_round_trips() {
        let header =
            EnvelopeHeader::new(Direction::ClientToServer, MessagePurpose::Request, 258).unwrap();

        assert_eq!(header.encode(), [1, 1, 2, 0, 0, 0, 0, 0, 0, 1, 2]);

        let decoded = EnvelopeHeader::decode(&header.encode()).unwrap();

        assert_eq!(decoded, header);
        assert_eq!(decoded.direction(), Direction::ClientToServer);
        assert_eq!(decoded.purpose(), MessagePurpose::Request);
        assert_eq!(decoded.sequence(), 258);
    }

    #[test]
    fn rejects_invalid_lengths_versions_and_tags() {
        for length in [0, 1, 10, 12] {
            assert!(EnvelopeHeader::decode(&vec![0; length]).is_err());
        }

        let valid = EnvelopeHeader::new(Direction::ClientToServer, MessagePurpose::Request, 0)
            .unwrap()
            .encode();

        for (index, value) in [(0, 2), (1, 0), (2, 0)] {
            let mut bytes = valid;
            bytes[index] = value;

            assert!(EnvelopeHeader::decode(&bytes).is_err());
        }
    }

    #[test]
    fn rejects_wrong_application_direction() {
        assert!(
            EnvelopeHeader::new(Direction::ServerToClient, MessagePurpose::Request, 0,).is_err()
        );

        assert!(
            EnvelopeHeader::new(Direction::ClientToServer, MessagePurpose::Response, 0,).is_err()
        );

        for direction in [Direction::ClientToServer, Direction::ServerToClient] {
            assert!(EnvelopeHeader::new(direction, MessagePurpose::KeyConfirmation, 0,).is_ok());
        }
    }

    #[test]
    fn rejects_out_of_range_sequences() {
        for sequence in [MAX_MESSAGES_PER_KEY, u64::MAX] {
            assert!(
                EnvelopeHeader::new(Direction::ClientToServer, MessagePurpose::Request, sequence,)
                    .is_err()
            );
        }
    }

    #[test]
    fn authenticated_data_binds_headers_and_length() {
        let first =
            EnvelopeHeader::new(Direction::ClientToServer, MessagePurpose::Request, 0).unwrap();

        let next =
            EnvelopeHeader::new(Direction::ClientToServer, MessagePurpose::Request, 1).unwrap();

        let data = first.authenticated_data(AUTH_TAG_LEN).unwrap();

        assert!(data.starts_with(DOMAIN));

        let outer = FrameHeader::new(
            FrameKind::Encrypted,
            (ENVELOPE_HEADER_LEN + AUTH_TAG_LEN) as u32,
        )
        .unwrap()
        .encode();

        let mut expected = DOMAIN.to_vec();
        expected.extend_from_slice(&outer);
        expected.extend_from_slice(&first.encode());

        assert_eq!(data, expected);
        assert_ne!(data, next.authenticated_data(AUTH_TAG_LEN).unwrap());
        assert_ne!(data, first.authenticated_data(AUTH_TAG_LEN + 1).unwrap());

        assert!(first.authenticated_data(AUTH_TAG_LEN - 1).is_err());
        assert!(
            first
                .authenticated_data(MAX_PLAINTEXT_LEN + AUTH_TAG_LEN + 1)
                .is_err()
        );
    }
}
