use std::io;

use zeroize::Zeroizing;

use crate::seal::MAX_PLAINTEXT_LEN;

const LENGTH_LEN: usize = 4;

/// Internal application-body padding configuration.
///
/// Installed from the negotiated connection profile.
/// Key-confirmation messages retain their separate representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PaddingMode {
    Disabled,
    Block { block_size: usize },
}

impl PaddingMode {
    #[cfg(test)]
    pub(crate) fn block(block_size: usize) -> io::Result<Self> {
        if !(LENGTH_LEN..=MAX_PLAINTEXT_LEN).contains(&block_size) {
            return Err(invalid_input("invalid padding block size"));
        }

        Ok(Self::Block { block_size })
    }

    pub(crate) fn encoded_len(self, payload_len: usize) -> io::Result<usize> {
        let encoded_len = match self {
            Self::Disabled => payload_len,
            Self::Block { block_size } => {
                // Validate here too: internal callers can construct the enum.
                if !(LENGTH_LEN..=MAX_PLAINTEXT_LEN).contains(&block_size) {
                    return Err(invalid_input("invalid padding block size"));
                }

                let base = payload_len
                    .checked_add(LENGTH_LEN)
                    .ok_or_else(|| invalid_input("padded length overflow"))?;

                let remainder = base % block_size;
                let extra = if remainder == 0 {
                    0
                } else {
                    block_size - remainder
                };

                base.checked_add(extra)
                    .ok_or_else(|| invalid_input("padded length overflow"))?
            }
        };

        if encoded_len > MAX_PLAINTEXT_LEN {
            return Err(invalid_input("padded plaintext exceeds message limit"));
        }

        Ok(encoded_len)
    }

    pub(crate) fn encode(self, payload: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let encoded_len = self.encoded_len(payload.len())?;

        match self {
            Self::Disabled => Ok(Zeroizing::new(payload.to_vec())),
            Self::Block { .. } => {
                let payload_len = u32::try_from(payload.len())
                    .map_err(|_| invalid_input("payload length is too large"))?;

                let mut encoded = Zeroizing::new(vec![0; encoded_len]);
                encoded[..LENGTH_LEN].copy_from_slice(&payload_len.to_be_bytes());
                encoded[LENGTH_LEN..LENGTH_LEN + payload.len()].copy_from_slice(payload);

                Ok(encoded)
            }
        }
    }

    /// Consumes authenticated plaintext and retains only its payload.
    ///
    /// The caller must authenticate/decrypt before invoking this method.
    pub(crate) fn decode(self, mut encoded: Zeroizing<Vec<u8>>) -> io::Result<Zeroizing<Vec<u8>>> {
        if encoded.len() > MAX_PLAINTEXT_LEN {
            return Err(invalid_data("decoded plaintext exceeds message limit"));
        }

        match self {
            Self::Disabled => Ok(encoded),
            Self::Block { .. } => {
                let length_bytes: [u8; LENGTH_LEN] = encoded
                    .get(..LENGTH_LEN)
                    .ok_or_else(|| invalid_data("missing payload length"))?
                    .try_into()
                    .map_err(|_| invalid_data("invalid payload length"))?;

                let payload_len = usize::try_from(u32::from_be_bytes(length_bytes))
                    .map_err(|_| invalid_data("payload length is not supported"))?;

                let expected_len = self
                    .encoded_len(payload_len)
                    .map_err(|_| invalid_data("invalid padded payload length"))?;

                if encoded.len() != expected_len {
                    return Err(invalid_data("unexpected padded plaintext length"));
                }

                let payload_end = LENGTH_LEN
                    .checked_add(payload_len)
                    .filter(|end| *end <= encoded.len())
                    .ok_or_else(|| invalid_data("payload exceeds padded plaintext"))?;

                if encoded[payload_end..].iter().any(|byte| *byte != 0) {
                    return Err(invalid_data("invalid padding bytes"));
                }

                encoded.copy_within(LENGTH_LEN..payload_end, 0);

                // Clear the tail before truncating, including bytes displaced
                // by the in-place move.
                encoded[payload_len..].fill(0);
                encoded.truncate(payload_len);

                Ok(encoded)
            }
        }
    }

    /// Maximum original payload that fits the encryption plaintext limit.
    pub(crate) fn max_payload_len(self) -> io::Result<usize> {
        // Also validates directly constructed Block variants.
        self.encoded_len(0)?;

        match self {
            Self::Disabled => Ok(MAX_PLAINTEXT_LEN),
            Self::Block { block_size } => {
                let usable = (MAX_PLAINTEXT_LEN / block_size) * block_size;

                let maximum = usable
                    .checked_sub(LENGTH_LEN)
                    .ok_or_else(|| invalid_input("padding block has no payload capacity"))?;

                Ok(maximum.min(u32::MAX as usize))
            }
        }
    }
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl From<crate::negotiation::v2::Profile> for PaddingMode {
    fn from(profile: crate::negotiation::v2::Profile) -> Self {
        match profile {
            crate::negotiation::v2::Profile::Unpadded => Self::Disabled,
            crate::negotiation::v2::Profile::Block256 => Self::Block { block_size: 256 },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_preserves_bytes() {
        let payload = b"\0hello\xff";
        let encoded = PaddingMode::Disabled.encode(payload).unwrap();

        assert_eq!(encoded.as_slice(), payload);

        let decoded = PaddingMode::Disabled.decode(encoded).unwrap();
        assert_eq!(decoded.as_slice(), payload);
    }

    #[test]
    fn text_binary_and_empty_payloads_round_trip() {
        let mode = PaddingMode::block(256).unwrap();
        let binary: Vec<u8> = (0..=255).collect();

        for payload in [b"".as_slice(), b"hello man".as_slice(), binary.as_slice()] {
            let encoded = mode.encode(payload).unwrap();

            assert_eq!(encoded.len() % 256, 0);
            assert!(encoded.len() >= LENGTH_LEN + payload.len());

            let decoded = mode.decode(encoded).unwrap();
            assert_eq!(decoded.as_slice(), payload);
        }
    }

    #[test]
    fn exact_boundary_does_not_add_another_block() {
        let mode = PaddingMode::block(256).unwrap();

        assert_eq!(mode.encoded_len(252).unwrap(), 256);
        assert_eq!(mode.encoded_len(253).unwrap(), 512);
    }

    #[test]
    fn rejects_invalid_block_sizes() {
        for block_size in [0, 1, 3, MAX_PLAINTEXT_LEN + 1] {
            assert!(PaddingMode::block(block_size).is_err());
        }
    }

    #[test]
    fn maximum_supported_payload_round_trips() {
        let mode = PaddingMode::block(256).unwrap();
        let payload = vec![0x5a; MAX_PLAINTEXT_LEN - LENGTH_LEN];
        let encoded = mode.encode(&payload).unwrap();

        assert_eq!(encoded.len(), MAX_PLAINTEXT_LEN);
        assert_eq!(mode.decode(encoded).unwrap().as_slice(), payload.as_slice());

        assert!(mode.encode(&vec![0; payload.len() + 1]).is_err());
    }

    #[test]
    fn rejects_length_overflow() {
        let mode = PaddingMode::block(256).unwrap();
        assert!(mode.encoded_len(usize::MAX).is_err());
    }

    #[test]
    fn rejects_truncation_and_appended_blocks() {
        let mode = PaddingMode::block(256).unwrap();

        let mut truncated = mode.encode(b"hello").unwrap();
        truncated.pop();
        assert!(mode.decode(truncated).is_err());

        let mut extended = mode.encode(b"hello").unwrap();
        extended.extend_from_slice(&[0; 256]);
        assert!(mode.decode(extended).is_err());
    }

    #[test]
    fn rejects_missing_or_impossible_payload_length() {
        let mode = PaddingMode::block(256).unwrap();

        assert!(mode.decode(Zeroizing::new(vec![0; 3])).is_err());

        let mut encoded = mode.encode(b"hello").unwrap();
        encoded[..LENGTH_LEN].copy_from_slice(&u32::MAX.to_be_bytes());

        assert!(mode.decode(encoded).is_err());
    }

    #[test]
    fn rejects_nonzero_padding() {
        let mode = PaddingMode::block(256).unwrap();
        let mut encoded = mode.encode(b"hello").unwrap();

        *encoded.last_mut().unwrap() = 1;

        assert!(mode.decode(encoded).is_err());
    }

    #[test]
    fn padded_payloads_round_trip_through_application_encryption() {
        use crate::envelope::{Direction, MessagePurpose};
        use crate::open::MessageOpener;
        use crate::seal::MessageSealer;

        let mode = PaddingMode::block(256).unwrap();

        // Fixed material for this test only.
        let key = [0x42; 32];
        let direction = Direction::ClientToServer;

        let mut sender = MessageSealer::new(&key, direction).unwrap();
        let mut receiver = MessageOpener::new(&key, direction).unwrap();

        let binary: Vec<u8> = (0..=255).collect();

        for payload in [b"".as_slice(), b"hello man".as_slice(), binary.as_slice()] {
            let padded = mode.encode(payload).unwrap();

            let sealed = sender
                .seal(MessagePurpose::Request, padded.as_slice())
                .unwrap();

            let opened = receiver
                .open(sealed.body(), MessagePurpose::Request)
                .unwrap();

            assert_eq!(opened.body(), padded.as_slice());

            let decoded = mode.decode(Zeroizing::new(opened.body().to_vec())).unwrap();

            assert_eq!(decoded.as_slice(), payload);
        }
    }

    #[test]
    fn encryption_capacity_counts_the_complete_padded_plaintext() {
        use crate::envelope::{Direction, MessagePurpose};
        use crate::open::MessageOpener;
        use crate::seal::{MAX_PLAINTEXT_BYTES_PER_KEY, MessageSealer};

        let mode = PaddingMode::block(256).unwrap();

        // Fixed material for this test only.
        let key = [0x43; 32];
        let direction = Direction::ClientToServer;

        let mut sender = MessageSealer::new(&key, direction).unwrap();
        let mut receiver = MessageOpener::new(&key, direction).unwrap();

        let padded = mode.encode(b"hello").unwrap();
        assert_eq!(padded.len(), 256);

        let sealed = sender
            .seal(MessagePurpose::Request, padded.as_slice())
            .unwrap();

        receiver
            .open(sealed.body(), MessagePurpose::Request)
            .unwrap();

        let expected_remaining = MAX_PLAINTEXT_BYTES_PER_KEY - 256;

        assert_eq!(sender.remaining_capacity().0, expected_remaining);
        assert_eq!(receiver.remaining_capacity().0, expected_remaining);
    }

    #[test]
    fn equal_bucket_payloads_have_equal_encrypted_body_lengths() {
        use crate::envelope::{AUTH_TAG_LEN, Direction, ENVELOPE_HEADER_LEN, MessagePurpose};
        use crate::seal::MessageSealer;

        let mode = PaddingMode::block(256).unwrap();

        // Fixed material for this test only.
        let mut sender = MessageSealer::new(&[0x44; 32], Direction::ClientToServer).unwrap();

        let short = mode.encode(b"hello").unwrap();
        let longer = mode.encode(&[0x5a; 200]).unwrap();

        let first = sender
            .seal(MessagePurpose::Request, short.as_slice())
            .unwrap();

        let second = sender
            .seal(MessagePurpose::Request, longer.as_slice())
            .unwrap();

        let expected_len = ENVELOPE_HEADER_LEN + 256 + AUTH_TAG_LEN;

        assert_eq!(first.body().len(), expected_len);
        assert_eq!(second.body().len(), expected_len);
    }

    #[test]
    fn authenticated_but_malformed_padding_is_rejected_by_codec() {
        use crate::envelope::{Direction, MessagePurpose};
        use crate::open::MessageOpener;
        use crate::seal::MessageSealer;

        let mode = PaddingMode::block(256).unwrap();

        // Fixed material for this test only.
        let key = [0x45; 32];
        let direction = Direction::ClientToServer;

        let mut sender = MessageSealer::new(&key, direction).unwrap();
        let mut receiver = MessageOpener::new(&key, direction).unwrap();

        let mut padded = mode.encode(b"hello").unwrap();
        *padded.last_mut().unwrap() = 1;

        // Encrypt the malformed representation with a valid test key.
        let sealed = sender
            .seal(MessagePurpose::Request, padded.as_slice())
            .unwrap();

        // Authentication succeeds, but inner-format validation must fail.
        let opened = receiver
            .open(sealed.body(), MessagePurpose::Request)
            .unwrap();

        assert!(mode.decode(Zeroizing::new(opened.body().to_vec())).is_err());
    }

    #[test]
    fn maximum_payload_matches_encoded_length_limit() {
        for mode in [
            PaddingMode::Disabled,
            PaddingMode::block(256).unwrap(),
            PaddingMode::block(257).unwrap(),
        ] {
            let maximum = mode.max_payload_len().unwrap();

            assert!(mode.encoded_len(maximum).is_ok());
            assert!(mode.encoded_len(maximum + 1).is_err());
        }
    }

    #[test]
    fn block256_reserves_four_bytes_at_current_limit() {
        let mode = PaddingMode::block(256).unwrap();

        assert_eq!(mode.max_payload_len().unwrap(), 61_436);
        assert_eq!(mode.encoded_len(61_436).unwrap(), 61_440);
        assert!(mode.encoded_len(61_437).is_err());
    }
}
