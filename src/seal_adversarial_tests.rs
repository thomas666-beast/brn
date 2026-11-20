use std::io;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

use super::{MAX_PLAINTEXT_BYTES_PER_KEY, MAX_PLAINTEXT_LEN, MessageSealer};
use crate::envelope::{
    AUTH_TAG_LEN, Direction, ENVELOPE_HEADER_LEN, EnvelopeHeader, MessagePurpose,
};
use crate::sequence::MAX_MESSAGES_PER_KEY;

// Fixed material and newly recreated owners are isolated test fixtures,
// never a pattern for production key or nonce management.
const KEY: [u8; 32] = [0x42; 32];

fn sender(direction: Direction) -> MessageSealer {
    MessageSealer::new(&KEY, direction).unwrap()
}

fn independently_open(body: &[u8]) -> Vec<u8> {
    let header = EnvelopeHeader::decode(&body[..ENVELOPE_HEADER_LEN]).unwrap();
    let mut ciphertext = body[ENVELOPE_HEADER_LEN..].to_vec();
    let aad = header.authenticated_data(ciphertext.len()).unwrap();
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&header.sequence().to_be_bytes());
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &KEY).unwrap());
    key.open_in_place(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad.as_slice()),
        &mut ciphertext,
    )
    .unwrap()
    .to_vec()
}

fn assert_exhausted(sender: &mut MessageSealer, expected_bytes: u64) {
    assert!(sender.exhausted);
    for purpose in [
        MessagePurpose::KeyConfirmation,
        MessagePurpose::Request,
        MessagePurpose::Response,
    ] {
        for plaintext in [b"".as_slice(), b"later".as_slice()] {
            let error = sender.seal(purpose, plaintext).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::Other);
            assert_eq!(
                error.to_string(),
                "application sending key is exhausted; reconnect with fresh keys"
            );
            assert_eq!(sender.plaintext_bytes, expected_bytes);
            assert!(sender.exhausted);
        }
    }
}

#[test]
fn aes256_sender_rejects_all_other_key_lengths_through_64() {
    for length in (0..=64).filter(|length| *length != KEY.len()) {
        assert_eq!(
            MessageSealer::new(&vec![0; length], Direction::ClientToServer)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

#[test]
fn all_valid_direction_purpose_pairs_produce_openable_envelopes() {
    for (direction, purpose) in [
        (Direction::ClientToServer, MessagePurpose::KeyConfirmation),
        (Direction::ClientToServer, MessagePurpose::Request),
        (Direction::ServerToClient, MessagePurpose::KeyConfirmation),
        (Direction::ServerToClient, MessagePurpose::Response),
    ] {
        let mut sender = sender(direction);
        let message = sender.seal(purpose, b"payload").unwrap();
        let header = EnvelopeHeader::decode(&message.body()[..ENVELOPE_HEADER_LEN]).unwrap();
        assert_eq!(header.direction(), direction);
        assert_eq!(header.purpose(), purpose);
        assert_eq!(header.sequence(), 0);
        assert_eq!(independently_open(message.body()), b"payload");
        assert_eq!(sender.plaintext_bytes, 7);
        assert!(!sender.exhausted);
    }
}

#[test]
fn empty_plaintext_consumes_one_sequence_and_no_byte_budget() {
    let mut sender = sender(Direction::ClientToServer);
    let empty = sender.seal(MessagePurpose::Request, b"").unwrap();
    assert_eq!(empty.sequence(), 0);
    assert_eq!(empty.body().len(), ENVELOPE_HEADER_LEN + AUTH_TAG_LEN);
    assert!(independently_open(empty.body()).is_empty());
    assert_eq!(sender.plaintext_bytes, 0);
    let next = sender.seal(MessagePurpose::Request, b"x").unwrap();
    assert_eq!(next.sequence(), 1);
    assert_eq!(sender.plaintext_bytes, 1);
}

#[test]
fn maximum_plaintext_fits_frame_and_opens_exactly() {
    let plaintext = vec![0xa5; MAX_PLAINTEXT_LEN];
    let mut sender = sender(Direction::ClientToServer);
    let message = sender.seal(MessagePurpose::Request, &plaintext).unwrap();
    assert_eq!(
        message.body().len(),
        ENVELOPE_HEADER_LEN + MAX_PLAINTEXT_LEN + AUTH_TAG_LEN
    );
    assert!(message.body().len() <= crate::frame::MAX_BODY_LEN as usize);
    assert_eq!(independently_open(message.body()), plaintext);
    assert_eq!(sender.plaintext_bytes, MAX_PLAINTEXT_LEN as u64);
    assert!(!sender.exhausted);
}

#[test]
fn binary_plaintext_round_trips_without_modifying_the_callers_buffer() {
    let plaintext: Vec<u8> = (0..=u8::MAX).collect();
    let before = plaintext.clone();
    let mut sender = sender(Direction::ClientToServer);
    let message = sender.seal(MessagePurpose::Request, &plaintext).unwrap();
    assert_eq!(plaintext, before);
    assert_eq!(independently_open(message.body()), before);
    assert_eq!(sender.plaintext_bytes, 256);
}

#[test]
fn oversized_input_after_success_preserves_byte_and_sequence_counters() {
    let mut sender = sender(Direction::ClientToServer);
    sender.seal(MessagePurpose::Request, b"first").unwrap();
    let oversized = vec![0; MAX_PLAINTEXT_LEN + 1];
    assert_eq!(
        sender
            .seal(MessagePurpose::Request, &oversized)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(sender.plaintext_bytes, 5);
    assert!(!sender.exhausted);
    let next = sender.seal(MessagePurpose::Request, b"next").unwrap();
    assert_eq!(next.sequence(), 1);
    assert_eq!(sender.plaintext_bytes, 9);
    assert_eq!(independently_open(next.body()), b"next");
}

#[test]
fn wrong_purpose_after_success_is_recoverable_in_both_directions() {
    for (direction, valid, invalid) in [
        (
            Direction::ClientToServer,
            MessagePurpose::Request,
            MessagePurpose::Response,
        ),
        (
            Direction::ServerToClient,
            MessagePurpose::Response,
            MessagePurpose::Request,
        ),
    ] {
        let mut sender = sender(direction);
        sender.seal(valid, b"first").unwrap();
        assert_eq!(
            sender.seal(invalid, b"wrong").unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(sender.plaintext_bytes, 5);
        assert!(!sender.exhausted);
        let next = sender.seal(valid, b"next").unwrap();
        assert_eq!(next.sequence(), 1);
        assert_eq!(sender.plaintext_bytes, 9);
        assert_eq!(independently_open(next.body()), b"next");
    }
}

#[test]
fn exact_byte_limit_succeeds_then_further_nonempty_input_exhausts() {
    let mut sender = sender(Direction::ClientToServer);
    sender.plaintext_bytes = MAX_PLAINTEXT_BYTES_PER_KEY - 1;
    let last = sender.seal(MessagePurpose::Request, b"x").unwrap();
    assert_eq!(last.sequence(), 0);
    assert_eq!(independently_open(last.body()), b"x");
    assert_eq!(sender.plaintext_bytes, MAX_PLAINTEXT_BYTES_PER_KEY);
    assert!(!sender.exhausted);
    assert!(sender.seal(MessagePurpose::Request, b"y").is_err());
    assert_exhausted(&mut sender, MAX_PLAINTEXT_BYTES_PER_KEY);
}

#[test]
fn empty_message_at_full_byte_budget_still_consumes_a_sequence() {
    let mut sender = sender(Direction::ClientToServer);
    sender.plaintext_bytes = MAX_PLAINTEXT_BYTES_PER_KEY;
    for expected in 0..2 {
        let message = sender.seal(MessagePurpose::Request, b"").unwrap();
        assert_eq!(message.sequence(), expected);
        assert!(independently_open(message.body()).is_empty());
        assert_eq!(sender.plaintext_bytes, MAX_PLAINTEXT_BYTES_PER_KEY);
        assert!(!sender.exhausted);
    }
    assert!(sender.seal(MessagePurpose::Request, b"x").is_err());
    assert_exhausted(&mut sender, MAX_PLAINTEXT_BYTES_PER_KEY);
}

#[test]
fn byte_counter_overflow_disables_without_wrapping() {
    let mut sender = sender(Direction::ClientToServer);
    // Synthetic state to reach checked_add's overflow branch directly.
    sender.plaintext_bytes = u64::MAX;
    assert!(sender.seal(MessagePurpose::Request, b"x").is_err());
    assert_exhausted(&mut sender, u64::MAX);
}

#[test]
fn last_reserved_sequence_encrypts_then_permanently_exhausts() {
    let mut sender = sender(Direction::ClientToServer);
    // Exercise the real allocator without exposing its private fields.
    // These reservations are discarded; no encryption occurs in this loop.
    for expected in 0..MAX_MESSAGES_PER_KEY - 1 {
        let reservation = sender.sequence.reserve().unwrap();
        assert_eq!(reservation.number(), expected);
    }
    let final_message = sender.seal(MessagePurpose::Request, b"last").unwrap();
    assert_eq!(final_message.sequence(), MAX_MESSAGES_PER_KEY - 1);
    assert_eq!(independently_open(final_message.body()), b"last");
    assert_eq!(sender.plaintext_bytes, 4);
    assert!(!sender.exhausted);
    assert!(sender.seal(MessagePurpose::Request, b"next").is_err());
    assert_exhausted(&mut sender, 4);
}

#[test]
fn confirmation_and_application_messages_share_one_sequence_space() {
    for (direction, application) in [
        (Direction::ClientToServer, MessagePurpose::Request),
        (Direction::ServerToClient, MessagePurpose::Response),
    ] {
        let mut sender = sender(direction);
        let confirmation = sender
            .seal(MessagePurpose::KeyConfirmation, b"confirm")
            .unwrap();
        let message = sender.seal(application, b"application").unwrap();
        assert_eq!(confirmation.sequence(), 0);
        assert_eq!(message.sequence(), 1);
        assert_eq!(sender.plaintext_bytes, 18);
        assert_eq!(independently_open(confirmation.body()), b"confirm");
        assert_eq!(independently_open(message.body()), b"application");
    }
}

#[test]
fn exhausted_owner_rejects_even_otherwise_invalid_input_as_exhausted() {
    let mut sender = sender(Direction::ClientToServer);
    sender.plaintext_bytes = MAX_PLAINTEXT_BYTES_PER_KEY;
    assert!(sender.seal(MessagePurpose::Request, b"x").is_err());
    let oversized = vec![0; MAX_PLAINTEXT_LEN + 1];
    assert_eq!(
        sender
            .seal(MessagePurpose::Response, &oversized)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Other
    );
    assert_exhausted(&mut sender, MAX_PLAINTEXT_BYTES_PER_KEY);
}

#[test]
fn sender_and_sealed_message_debug_redact_sensitive_fields() {
    let mut sender = sender(Direction::ClientToServer);
    let message = sender
        .seal(MessagePurpose::Request, b"do-not-print-this-plaintext")
        .unwrap();
    let sender_debug = format!("{sender:?}");
    let message_debug = format!("{message:?}");
    assert!(sender_debug.contains("key: \"[REDACTED]\""));
    assert!(message_debug.contains("body: \"[REDACTED]\""));
    assert!(!sender_debug.contains("do-not-print-this-plaintext"));
    assert!(!message_debug.contains("do-not-print-this-plaintext"));
}
