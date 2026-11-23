use std::fmt;
use std::io;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, UnboundKey};
use zeroize::Zeroizing;

use crate::envelope::{
    AUTH_TAG_LEN, Direction, ENVELOPE_HEADER_LEN, EnvelopeHeader, MessagePurpose,
};
use crate::padding::PaddingMode;
use crate::sequence::SendSequence;

pub(crate) const MAX_PLAINTEXT_LEN: usize = 60 * 1024;
pub(crate) const MAX_PLAINTEXT_BYTES_PER_KEY: u64 = 1 << 30;

// The complete encrypted envelope must fit inside one outer frame.
// Keep this checked even when building without tests.
const _: () = assert!(
    ENVELOPE_HEADER_LEN + MAX_PLAINTEXT_LEN + AUTH_TAG_LEN <= crate::frame::MAX_BODY_LEN as usize
);

/// Owns one directional encryption key and its sending counter.
///
/// Must be constructed exactly once for a given sending key.
/// Not Clone or Copy.
pub(crate) struct MessageSealer {
    key: LessSafeKey,
    direction: Direction,
    sequence: SendSequence,
    plaintext_bytes: u64,
    exhausted: bool,
    padding: PaddingMode,
}

impl MessageSealer {
    #[cfg(test)]
    pub(crate) fn new(key_bytes: &[u8], direction: Direction) -> io::Result<Self> {
        Self::new_with_padding(key_bytes, direction, PaddingMode::Disabled)
    }

    pub(crate) fn new_with_padding(
        key_bytes: &[u8],
        direction: Direction,
        padding: PaddingMode,
    ) -> io::Result<Self> {
        // Validate configuration before accepting it.
        padding.encoded_len(0)?;

        let key = UnboundKey::new(&AES_256_GCM, key_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid AES-256-GCM key"))?;

        Ok(Self {
            key: LessSafeKey::new(key),
            direction,
            sequence: SendSequence::new(),
            plaintext_bytes: 0,
            exhausted: false,
            padding,
        })
    }
    /// Returns a complete encrypted-frame body:
    ///
    /// envelope header || ciphertext || authentication tag
    ///
    /// The outer frame header is not included in the returned bytes,
    /// but its canonical encoding is authenticated.
    pub(crate) fn seal(
        &mut self,
        purpose: MessagePurpose,
        plaintext: &[u8],
    ) -> io::Result<SealedMessage> {
        if self.exhausted {
            return Err(key_exhausted());
        }

        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "plaintext exceeds the message limit",
            ));
        }

        // Validate direction/purpose before consuming a sequence.
        EnvelopeHeader::new(self.direction, purpose, 0)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

        // Confirmation retains its existing representation.
        // Request/response bodies use the negotiated padding mode.
        let padded_plaintext = match purpose {
            MessagePurpose::KeyConfirmation => None,
            MessagePurpose::Request | MessagePurpose::Response => match self.padding {
                PaddingMode::Disabled => None,
                _ => Some(self.padding.encode(plaintext)?),
            },
        };

        let plaintext = match padded_plaintext.as_ref() {
            Some(encoded) => encoded.as_slice(),
            None => plaintext,
        };

        let next_total = match self.plaintext_bytes.checked_add(plaintext.len() as u64) {
            Some(total) if total <= MAX_PLAINTEXT_BYTES_PER_KEY => total,
            _ => {
                self.exhausted = true;
                return Err(key_exhausted());
            }
        };

        let reserved = match self.sequence.reserve() {
            Ok(reserved) => reserved,
            Err(_) => {
                self.exhausted = true;
                return Err(key_exhausted());
            }
        };

        // Any failure after reservation makes this owner unusable.
        let result = (|| {
            let header = EnvelopeHeader::new(self.direction, purpose, reserved.number())?;

            let ciphertext_len = plaintext.len() + AUTH_TAG_LEN;
            let metadata = header.authenticated_data(ciphertext_len)?;

            let mut ciphertext = Zeroizing::new(Vec::with_capacity(ciphertext_len));

            ciphertext.extend_from_slice(plaintext);

            self.key
                .seal_in_place_append_tag(
                    reserved.into_nonce(),
                    Aad::from(metadata.as_slice()),
                    &mut *ciphertext,
                )
                .map_err(|_| io::Error::other("application message encryption failed"))?;

            let mut body =
                Zeroizing::new(Vec::with_capacity(ENVELOPE_HEADER_LEN + ciphertext.len()));

            body.extend_from_slice(&header.encode());
            body.extend_from_slice(ciphertext.as_slice());

            Ok(SealedMessage { header, body })
        })();

        match result {
            Ok(message) => {
                self.plaintext_bytes = next_total;
                Ok(message)
            }
            Err(error) => {
                self.exhausted = true;
                Err(error)
            }
        }
    }

    /// Maximum original request/response body for this sender's format.
    ///
    /// This is a format limit, not remaining key capacity.
    pub(crate) fn max_application_payload_len(&self) -> io::Result<usize> {
        self.padding.max_payload_len()
    }
}

impl fmt::Debug for MessageSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageSealer")
            .field("key", &"[REDACTED]")
            .field("direction", &self.direction)
            .field("plaintext_bytes", &self.plaintext_bytes)
            .field("exhausted", &self.exhausted)
            .finish()
    }
}

/// Complete body for an outer frame of kind Encrypted.
pub(crate) struct SealedMessage {
    header: EnvelopeHeader,
    body: Zeroizing<Vec<u8>>,
}

impl SealedMessage {
    #[cfg(test)]
    pub(crate) fn sequence(&self) -> u64 {
        self.header.sequence()
    }

    pub(crate) fn body(&self) -> &[u8] {
        self.body.as_slice()
    }
}

impl fmt::Debug for SealedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedMessage")
            .field("header", &self.header)
            .field("body", &"[REDACTED]")
            .finish()
    }
}

fn key_exhausted() -> io::Error {
    io::Error::other("application sending key is exhausted; reconnect with fresh keys")
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::aead::Nonce;

    use super::*;

    fn client_sealer() -> MessageSealer {
        MessageSealer::new(&[0x42; 32], Direction::ClientToServer).unwrap()
    }

    // Independent opening logic for sender tests.
    // This is not the production receiver.
    fn open_body(body: &[u8]) -> Result<Vec<u8>, aws_lc_rs::error::Unspecified> {
        let header = EnvelopeHeader::decode(&body[..ENVELOPE_HEADER_LEN]).unwrap();

        let mut ciphertext = body[ENVELOPE_HEADER_LEN..].to_vec();

        let metadata = header.authenticated_data(ciphertext.len()).unwrap();

        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&header.sequence().to_be_bytes());

        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &[0x42; 32]).unwrap());

        let plaintext = key.open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(metadata.as_slice()),
            &mut ciphertext,
        )?;

        Ok(plaintext.to_vec())
    }

    #[test]
    fn complete_envelope_round_trips() {
        let mut sealer = client_sealer();

        let sealed = sealer.seal(MessagePurpose::Request, b"hello BRN").unwrap();

        assert_eq!(sealed.sequence(), 0);

        assert_eq!(
            sealed.body().len(),
            ENVELOPE_HEADER_LEN + b"hello BRN".len() + AUTH_TAG_LEN
        );

        let header = EnvelopeHeader::decode(&sealed.body()[..ENVELOPE_HEADER_LEN]).unwrap();

        assert_eq!(header.direction(), Direction::ClientToServer);
        assert_eq!(header.purpose(), MessagePurpose::Request);
        assert_eq!(open_body(sealed.body()).unwrap(), b"hello BRN");
    }

    #[test]
    fn modified_purpose_fails_authentication() {
        let mut sealer = client_sealer();

        let sealed = sealer.seal(MessagePurpose::Request, b"hello").unwrap();

        let mut modified = sealed.body().to_vec();

        // Confirmation is structurally valid in this direction,
        // but changing the authenticated header must fail.
        modified[2] = MessagePurpose::KeyConfirmation as u8;

        assert!(open_body(&modified).is_err());
    }

    #[test]
    fn consecutive_messages_use_different_sequences() {
        let mut sealer = client_sealer();

        let first = sealer.seal(MessagePurpose::Request, b"same").unwrap();

        let second = sealer.seal(MessagePurpose::Request, b"same").unwrap();

        assert_eq!(first.sequence(), 0);
        assert_eq!(second.sequence(), 1);

        // Compare ciphertext/tag, not merely differing headers.
        assert_ne!(
            &first.body()[ENVELOPE_HEADER_LEN..],
            &second.body()[ENVELOPE_HEADER_LEN..]
        );
    }

    #[test]
    fn oversized_input_does_not_consume_sequence() {
        let mut sealer = client_sealer();
        let oversized = vec![0; MAX_PLAINTEXT_LEN + 1];

        assert_eq!(
            sealer
                .seal(MessagePurpose::Request, &oversized)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );

        let valid = sealer.seal(MessagePurpose::Request, b"valid").unwrap();

        assert_eq!(valid.sequence(), 0);
    }

    #[test]
    fn wrong_direction_does_not_consume_sequence() {
        let mut sealer = client_sealer();

        assert_eq!(
            sealer
                .seal(MessagePurpose::Response, b"wrong direction")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );

        let valid = sealer.seal(MessagePurpose::Request, b"valid").unwrap();

        assert_eq!(valid.sequence(), 0);
    }

    #[test]
    fn byte_budget_exhaustion_is_permanent() {
        let mut sealer = client_sealer();

        sealer.plaintext_bytes = MAX_PLAINTEXT_BYTES_PER_KEY;

        assert!(sealer.seal(MessagePurpose::Request, b"x").is_err());
        assert!(sealer.exhausted);

        assert!(sealer.seal(MessagePurpose::Request, b"").is_err());
    }

    #[test]
    fn rejects_invalid_key_lengths() {
        for length in [0, 16, 31, 33] {
            let bytes = vec![0; length];

            assert!(MessageSealer::new(&bytes, Direction::ClientToServer,).is_err());
        }
    }
}

#[cfg(test)]
#[path = "seal_adversarial_tests.rs"]
mod adversarial_tests;

impl MessageSealer {
    /// Remaining (plaintext bytes, messages) for this sending owner.
    ///
    /// Includes usage by all message purposes, including confirmation.
    /// Does not reserve capacity, change state, or inspect epoch age.
    pub(crate) fn remaining_capacity(&self) -> (u64, u64) {
        if self.exhausted {
            return (0, 0);
        }

        (
            MAX_PLAINTEXT_BYTES_PER_KEY.saturating_sub(self.plaintext_bytes),
            self.sequence.remaining(),
        )
    }
}

#[cfg(test)]
impl MessageSealer {
    /// Reduces remaining capacity without changing sequence allocation.
    pub(crate) fn restrict_plaintext_capacity_for_test(&mut self, remaining: u64) {
        let current = self.remaining_capacity().0;
        let remaining = current.min(remaining);

        self.plaintext_bytes = MAX_PLAINTEXT_BYTES_PER_KEY.saturating_sub(remaining);
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    use crate::sequence::MAX_MESSAGES_PER_KEY;

    fn sender() -> MessageSealer {
        MessageSealer::new(&[0x42; 32], Direction::ClientToServer).unwrap()
    }

    #[test]
    fn inspection_does_not_consume_capacity() {
        let mut sender = sender();

        let initial = (MAX_PLAINTEXT_BYTES_PER_KEY, MAX_MESSAGES_PER_KEY);

        assert_eq!(sender.remaining_capacity(), initial);
        assert_eq!(sender.remaining_capacity(), initial);

        let sealed = sender.seal(MessagePurpose::Request, b"abc").unwrap();

        assert_eq!(sealed.sequence(), 0);
        assert_eq!(
            sender.remaining_capacity(),
            (MAX_PLAINTEXT_BYTES_PER_KEY - 3, MAX_MESSAGES_PER_KEY - 1,)
        );
    }

    #[test]
    fn empty_message_consumes_a_message_but_no_plaintext_bytes() {
        let mut sender = sender();

        sender.seal(MessagePurpose::Request, b"").unwrap();

        assert_eq!(
            sender.remaining_capacity(),
            (MAX_PLAINTEXT_BYTES_PER_KEY, MAX_MESSAGES_PER_KEY - 1,)
        );
    }

    #[test]
    fn exhausted_owner_reports_no_usable_capacity() {
        let mut sender = sender();

        sender.exhausted = true;

        assert_eq!(sender.remaining_capacity(), (0, 0));
    }
}
