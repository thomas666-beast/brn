use std::fmt;
use std::io;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use zeroize::Zeroizing;

use crate::envelope::{
    AUTH_TAG_LEN, Direction, ENVELOPE_HEADER_LEN, EnvelopeHeader, MessagePurpose,
};
use crate::padding::PaddingMode;
use crate::seal::{MAX_PLAINTEXT_BYTES_PER_KEY, MAX_PLAINTEXT_LEN};
use crate::sequence::MAX_MESSAGES_PER_KEY;

/// Owns one directional receiving key and its expected sequence.
///
/// Not Clone or Copy. Must not be recreated for an existing key.
pub(crate) struct MessageOpener {
    key: LessSafeKey,
    direction: Direction,
    next_sequence: u64,
    plaintext_bytes: u64,
    failed: bool,
    padding: PaddingMode,
}

impl MessageOpener {
    #[cfg(test)]
    pub(crate) fn new(key_bytes: &[u8], direction: Direction) -> io::Result<Self> {
        Self::new_with_padding(key_bytes, direction, PaddingMode::Disabled)
    }

    pub(crate) fn new_with_padding(
        key_bytes: &[u8],
        direction: Direction,
        padding: PaddingMode,
    ) -> io::Result<Self> {
        padding.encoded_len(0)?;

        let key = UnboundKey::new(&AES_256_GCM, key_bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid AES-256-GCM key"))?;

        Ok(Self {
            key: LessSafeKey::new(key),
            direction,
            next_sequence: 0,
            plaintext_bytes: 0,
            failed: false,
            padding,
        })
    }

    /// Opens one complete encrypted-frame body.
    ///
    /// The caller must pass the exact body from an outer Encrypted frame.
    /// A failure permanently disables this receiving owner.
    pub(crate) fn open(
        &mut self,
        body: &[u8],
        expected_purpose: MessagePurpose,
    ) -> io::Result<OpenedMessage> {
        if self.failed {
            return Err(invalid("application receiving key is disabled"));
        }

        let result = self.open_inner(body, expected_purpose);

        if result.is_err() {
            self.failed = true;
        }

        result
    }

    fn open_inner(
        &mut self,
        body: &[u8],
        expected_purpose: MessagePurpose,
    ) -> io::Result<OpenedMessage> {
        let minimum = ENVELOPE_HEADER_LEN + AUTH_TAG_LEN;
        let maximum = minimum + MAX_PLAINTEXT_LEN;

        if !(minimum..=maximum).contains(&body.len()) {
            return Err(invalid("invalid encrypted envelope length"));
        }

        if self.next_sequence >= MAX_MESSAGES_PER_KEY {
            return Err(invalid("application receiving key is exhausted"));
        }

        let header = EnvelopeHeader::decode(&body[..ENVELOPE_HEADER_LEN])?;

        if header.direction() != self.direction {
            return Err(invalid("unexpected envelope direction"));
        }

        if header.purpose() != expected_purpose {
            return Err(invalid("unexpected envelope purpose"));
        }

        if header.sequence() != self.next_sequence {
            return Err(invalid("unexpected envelope sequence"));
        }

        let ciphertext = &body[ENVELOPE_HEADER_LEN..];
        let plaintext_len = ciphertext.len() - AUTH_TAG_LEN;

        let next_total = self
            .plaintext_bytes
            .checked_add(plaintext_len as u64)
            .filter(|total| *total <= MAX_PLAINTEXT_BYTES_PER_KEY)
            .ok_or_else(|| invalid("application receiving byte limit reached"))?;

        let metadata = header.authenticated_data(ciphertext.len())?;

        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&header.sequence().to_be_bytes());

        let mut plaintext = Zeroizing::new(ciphertext.to_vec());

        let verified_len = self
            .key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(metadata.as_slice()),
                plaintext.as_mut_slice(),
            )
            .map_err(|_| invalid("application message authentication failed"))?
            .len();

        plaintext.truncate(verified_len);

        let plaintext = match header.purpose() {
            MessagePurpose::KeyConfirmation => plaintext,
            MessagePurpose::Request | MessagePurpose::Response => self.padding.decode(plaintext)?,
        };

        // Commit only after authentication and inner-format validation.
        // next_total counts the complete encrypted plaintext, not merely
        // the extracted application payload.
        self.next_sequence += 1;
        self.plaintext_bytes = next_total;

        Ok(OpenedMessage { header, plaintext })
    }
}

impl fmt::Debug for MessageOpener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageOpener")
            .field("key", &"[REDACTED]")
            .field("direction", &self.direction)
            .field("next_sequence", &self.next_sequence)
            .field("plaintext_bytes", &self.plaintext_bytes)
            .field("failed", &self.failed)
            .finish()
    }
}

/// Authenticated plaintext owned by BRN.
///
/// Accessing or copying the bytes does not transfer cleanup
/// responsibility for those copies to this object.
pub(crate) struct OpenedMessage {
    header: EnvelopeHeader,
    plaintext: Zeroizing<Vec<u8>>,
}

impl OpenedMessage {
    pub(crate) fn body(&self) -> &[u8] {
        self.plaintext.as_slice()
    }
}

impl fmt::Debug for OpenedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedMessage")
            .field("header", &self.header)
            .field("plaintext", &"[REDACTED]")
            .finish()
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::MessageSealer;

    fn pair() -> (MessageSealer, MessageOpener) {
        let key = [0x42; 32];
        let direction = Direction::ClientToServer;

        (
            MessageSealer::new(&key, direction).unwrap(),
            MessageOpener::new(&key, direction).unwrap(),
        )
    }

    #[test]
    fn receives_consecutive_messages() {
        let (mut sender, mut receiver) = pair();

        for body in [b"first".as_slice(), b"second".as_slice()] {
            let sealed = sender.seal(MessagePurpose::Request, body).unwrap();

            let opened = receiver
                .open(sealed.body(), MessagePurpose::Request)
                .unwrap();

            assert_eq!(opened.body(), body);
        }

        assert_eq!(receiver.next_sequence, 2);
    }

    #[test]
    fn wrong_key_fails_and_disables_receiver() {
        let (mut sender, _) = pair();

        let mut receiver = MessageOpener::new(&[0x99; 32], Direction::ClientToServer).unwrap();

        let sealed = sender.seal(MessagePurpose::Request, b"secret").unwrap();

        assert!(
            receiver
                .open(sealed.body(), MessagePurpose::Request)
                .is_err()
        );

        assert!(receiver.failed);
        assert_eq!(receiver.next_sequence, 0);
    }

    #[test]
    fn modified_ciphertext_or_tag_is_rejected() {
        for modify_tag in [false, true] {
            let (mut sender, mut receiver) = pair();

            let sealed = sender.seal(MessagePurpose::Request, b"secret").unwrap();

            let mut modified = sealed.body().to_vec();

            let index = if modify_tag {
                modified.len() - 1
            } else {
                ENVELOPE_HEADER_LEN
            };

            modified[index] ^= 1;

            assert!(receiver.open(&modified, MessagePurpose::Request).is_err());

            assert!(receiver.failed);
            assert_eq!(receiver.next_sequence, 0);
        }
    }

    #[test]
    fn replay_is_rejected_permanently() {
        let (mut sender, mut receiver) = pair();

        let first = sender.seal(MessagePurpose::Request, b"first").unwrap();

        receiver
            .open(first.body(), MessagePurpose::Request)
            .unwrap();

        assert!(
            receiver
                .open(first.body(), MessagePurpose::Request)
                .is_err()
        );

        let second = sender.seal(MessagePurpose::Request, b"second").unwrap();

        assert!(
            receiver
                .open(second.body(), MessagePurpose::Request)
                .is_err()
        );
    }

    #[test]
    fn skipped_sequence_is_rejected() {
        let (mut sender, mut receiver) = pair();

        let _discarded = sender.seal(MessagePurpose::Request, b"first").unwrap();

        let second = sender.seal(MessagePurpose::Request, b"second").unwrap();

        assert!(
            receiver
                .open(second.body(), MessagePurpose::Request)
                .is_err()
        );

        assert!(receiver.failed);
    }

    #[test]
    fn wrong_direction_or_purpose_is_rejected() {
        let (mut sender, mut receiver) = pair();

        let sealed = sender.seal(MessagePurpose::Request, b"request").unwrap();

        assert!(
            receiver
                .open(sealed.body(), MessagePurpose::KeyConfirmation,)
                .is_err()
        );

        let mut opposite = MessageOpener::new(&[0x42; 32], Direction::ServerToClient).unwrap();

        assert!(
            opposite
                .open(sealed.body(), MessagePurpose::Request)
                .is_err()
        );
    }

    #[test]
    fn rejects_invalid_envelope_lengths() {
        for length in [
            0,
            ENVELOPE_HEADER_LEN - 1,
            ENVELOPE_HEADER_LEN + AUTH_TAG_LEN - 1,
            ENVELOPE_HEADER_LEN + AUTH_TAG_LEN + MAX_PLAINTEXT_LEN + 1,
        ] {
            let (_, mut receiver) = pair();

            assert!(
                receiver
                    .open(&vec![0; length], MessagePurpose::Request)
                    .is_err()
            );

            assert!(receiver.failed);
        }
    }

    #[test]
    fn receiving_byte_limit_is_enforced() {
        let (mut sender, mut receiver) = pair();

        receiver.plaintext_bytes = MAX_PLAINTEXT_BYTES_PER_KEY;

        let sealed = sender.seal(MessagePurpose::Request, b"x").unwrap();

        assert!(
            receiver
                .open(sealed.body(), MessagePurpose::Request)
                .is_err()
        );

        assert!(receiver.failed);
        assert_eq!(receiver.next_sequence, 0);
    }
}

#[cfg(test)]
#[path = "open_adversarial_tests.rs"]
mod adversarial_tests;

impl MessageOpener {
    /// Remaining (plaintext bytes, messages) for this receiving owner.
    ///
    /// Includes usage by all message purposes, including confirmation.
    /// Does not change state or inspect epoch age.
    pub(crate) fn remaining_capacity(&self) -> (u64, u64) {
        if self.failed {
            return (0, 0);
        }

        (
            MAX_PLAINTEXT_BYTES_PER_KEY.saturating_sub(self.plaintext_bytes),
            MAX_MESSAGES_PER_KEY.saturating_sub(self.next_sequence),
        )
    }
}

#[cfg(test)]
impl MessageOpener {
    /// Reduces remaining capacity without changing the expected sequence.
    pub(crate) fn restrict_plaintext_capacity_for_test(&mut self, remaining: u64) {
        let current = self.remaining_capacity().0;
        let remaining = current.min(remaining);

        self.plaintext_bytes = MAX_PLAINTEXT_BYTES_PER_KEY.saturating_sub(remaining);
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    use crate::seal::MessageSealer;

    fn receiver() -> MessageOpener {
        MessageOpener::new(&[0x42; 32], Direction::ClientToServer).unwrap()
    }

    #[test]
    fn inspection_tracks_authenticated_usage_without_consuming_it() {
        let mut receiver = receiver();

        let initial = (MAX_PLAINTEXT_BYTES_PER_KEY, MAX_MESSAGES_PER_KEY);

        assert_eq!(receiver.remaining_capacity(), initial);
        assert_eq!(receiver.remaining_capacity(), initial);

        let mut sender = MessageSealer::new(&[0x42; 32], Direction::ClientToServer).unwrap();

        let message = sender.seal(MessagePurpose::Request, b"abc").unwrap();

        receiver
            .open(message.body(), MessagePurpose::Request)
            .unwrap();

        assert_eq!(
            receiver.remaining_capacity(),
            (MAX_PLAINTEXT_BYTES_PER_KEY - 3, MAX_MESSAGES_PER_KEY - 1,)
        );
    }

    #[test]
    fn failed_owner_reports_no_usable_capacity() {
        let mut receiver = receiver();

        receiver.failed = true;

        assert_eq!(receiver.remaining_capacity(), (0, 0));
    }

    #[test]
    fn exhausted_message_counter_reports_zero_messages() {
        let mut receiver = receiver();

        receiver.next_sequence = MAX_MESSAGES_PER_KEY;

        assert_eq!(
            receiver.remaining_capacity(),
            (MAX_PLAINTEXT_BYTES_PER_KEY, 0)
        );
    }
}
