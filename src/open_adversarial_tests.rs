use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

use super::{MessageOpener, OpenedMessage};
use crate::envelope::{
    AUTH_TAG_LEN, Direction, ENVELOPE_HEADER_LEN, EnvelopeHeader, MessagePurpose,
};
use crate::seal::{MAX_PLAINTEXT_BYTES_PER_KEY, MAX_PLAINTEXT_LEN};
use crate::sequence::MAX_MESSAGES_PER_KEY;
use std::io;

// Fixed key and repeated fixture construction are test-only. Never reuse
// this pattern to recreate production directional key owners.
const KEY: [u8; 32] = [0x42; 32];

fn header(purpose: MessagePurpose, sequence: u64) -> EnvelopeHeader {
    EnvelopeHeader::new(Direction::ClientToServer, purpose, sequence).unwrap()
}

fn receiver() -> MessageOpener {
    MessageOpener::new(&KEY, Direction::ClientToServer).unwrap()
}

// Low-level encryption lets boundary tests select sequences without
// sending a million messages or changing production visibility.
fn encrypted(header: EnvelopeHeader, plaintext: &[u8], override_aad: Option<Vec<u8>>) -> Vec<u8> {
    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &KEY).unwrap());
    let aad = override_aad.unwrap_or_else(|| {
        header
            .authenticated_data(plaintext.len() + AUTH_TAG_LEN)
            .unwrap()
    });
    let mut nonce = [0; 12];
    nonce[4..].copy_from_slice(&header.sequence().to_be_bytes());
    let mut ciphertext = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad.as_slice()),
        &mut ciphertext,
    )
    .unwrap();
    let mut body = header.encode().to_vec();
    body.extend_from_slice(&ciphertext);
    body
}

fn assert_disabled(receiver: &mut MessageOpener, sequence: u64, bytes: u64) {
    assert!(receiver.failed);
    assert_eq!(receiver.next_sequence, sequence);
    assert_eq!(receiver.plaintext_bytes, bytes);
    let valid = encrypted(header(MessagePurpose::Request, 0), b"valid", None);
    let error = receiver.open(&valid, MessagePurpose::Request).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "application receiving key is disabled");
    assert_eq!(receiver.next_sequence, sequence);
    assert_eq!(receiver.plaintext_bytes, bytes);
}

#[test]
fn aes256_opener_rejects_all_other_key_lengths_through_64() {
    for length in (0..=64).filter(|length| *length != KEY.len()) {
        assert_eq!(
            MessageOpener::new(&vec![0; length], Direction::ClientToServer)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

#[test]
fn every_truncated_envelope_prefix_disables_without_committing_counters() {
    let valid = encrypted(header(MessagePurpose::Request, 0), b"secret payload", None);
    for length in 0..valid.len() {
        let mut receiver = receiver();
        assert!(
            receiver
                .open(&valid[..length], MessagePurpose::Request)
                .is_err()
        );
        assert_disabled(&mut receiver, 0, 0);
    }
}

#[test]
fn every_single_bit_mutation_of_a_sample_envelope_is_rejected() {
    let valid = encrypted(header(MessagePurpose::Request, 0), b"secret payload", None);
    for index in 0..valid.len() {
        for bit in 0..8 {
            let mut modified = valid.clone();
            modified[index] ^= 1 << bit;
            let mut receiver = receiver();
            assert!(
                receiver.open(&modified, MessagePurpose::Request).is_err(),
                "byte {index}, bit {bit}"
            );
            assert_disabled(&mut receiver, 0, 0);
        }
    }
}

#[test]
fn ciphertext_length_changes_fail_authentication_without_counter_commit() {
    let valid = encrypted(header(MessagePurpose::Request, 0), b"secret payload", None);
    let mut shortened = valid.clone();
    shortened.pop();
    let mut extended = valid;
    extended.push(0);
    for body in [shortened, extended] {
        let mut receiver = receiver();
        let error = receiver.open(&body, MessagePurpose::Request).unwrap_err();
        assert_eq!(
            error.to_string(),
            "application message authentication failed"
        );
        assert_disabled(&mut receiver, 0, 0);
    }
}

#[test]
fn every_associated_data_byte_is_cryptographically_bound() {
    let header = header(MessagePurpose::Request, 0);
    let plaintext = b"secret payload";
    let canonical = header
        .authenticated_data(plaintext.len() + AUTH_TAG_LEN)
        .unwrap();
    for index in 0..canonical.len() {
        let mut wrong_aad = canonical.clone();
        wrong_aad[index] ^= 1;
        let body = encrypted(header, plaintext, Some(wrong_aad));
        let mut receiver = receiver();
        let error = receiver.open(&body, MessagePurpose::Request).unwrap_err();
        assert_eq!(
            error.to_string(),
            "application message authentication failed",
            "AAD byte {index}"
        );
        assert_disabled(&mut receiver, 0, 0);
    }
}

#[test]
fn changing_purpose_cannot_bypass_authentication_by_changing_expectation() {
    let mut body = encrypted(header(MessagePurpose::Request, 0), b"payload", None);
    body[2] = MessagePurpose::KeyConfirmation as u8;
    let mut receiver = receiver();
    let error = receiver
        .open(&body, MessagePurpose::KeyConfirmation)
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "application message authentication failed"
    );
    assert_disabled(&mut receiver, 0, 0);
}

#[test]
fn changing_direction_cannot_bypass_authentication_with_same_test_key() {
    let mut body = encrypted(header(MessagePurpose::KeyConfirmation, 0), b"payload", None);
    body[1] = Direction::ServerToClient as u8;
    let mut receiver = MessageOpener::new(&KEY, Direction::ServerToClient).unwrap();
    let error = receiver
        .open(&body, MessagePurpose::KeyConfirmation)
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "application message authentication failed"
    );
    assert_disabled(&mut receiver, 0, 0);
}

#[test]
fn changing_sequence_cannot_bypass_authentication_by_matching_expected_counter() {
    let mut body = encrypted(header(MessagePurpose::Request, 0), b"payload", None);
    body[3..ENVELOPE_HEADER_LEN].copy_from_slice(&1_u64.to_be_bytes());
    let mut receiver = receiver();
    receiver.next_sequence = 1;
    let error = receiver.open(&body, MessagePurpose::Request).unwrap_err();
    assert_eq!(
        error.to_string(),
        "application message authentication failed"
    );
    assert_disabled(&mut receiver, 1, 0);
}

#[test]
fn failure_after_success_preserves_last_authenticated_counters() {
    let first = encrypted(header(MessagePurpose::Request, 0), b"first", None);
    let mut second = encrypted(header(MessagePurpose::Request, 1), b"second", None);
    let last = second.len() - 1;
    second[last] ^= 1;
    let mut receiver = receiver();
    assert_eq!(
        receiver
            .open(&first, MessagePurpose::Request)
            .unwrap()
            .body(),
        b"first"
    );
    assert!(receiver.open(&second, MessagePurpose::Request).is_err());
    assert_disabled(&mut receiver, 1, 5);
}

#[test]
fn replay_after_two_successes_preserves_counters_and_disables_owner() {
    let first = encrypted(header(MessagePurpose::Request, 0), b"first", None);
    let second = encrypted(header(MessagePurpose::Request, 1), b"second", None);
    let mut receiver = receiver();
    receiver.open(&first, MessagePurpose::Request).unwrap();
    receiver.open(&second, MessagePurpose::Request).unwrap();
    assert!(receiver.open(&first, MessagePurpose::Request).is_err());
    assert_disabled(&mut receiver, 2, 11);
}

#[test]
fn last_permitted_sequence_succeeds_then_owner_is_exhausted() {
    let final_sequence = MAX_MESSAGES_PER_KEY - 1;
    let body = encrypted(
        header(MessagePurpose::Request, final_sequence),
        b"last",
        None,
    );
    let mut receiver = receiver();
    receiver.next_sequence = final_sequence;
    assert_eq!(
        receiver
            .open(&body, MessagePurpose::Request)
            .unwrap()
            .body(),
        b"last"
    );
    assert_eq!(receiver.next_sequence, MAX_MESSAGES_PER_KEY);
    assert_eq!(receiver.plaintext_bytes, 4);
    assert!(!receiver.failed);
    assert!(receiver.open(&body, MessagePurpose::Request).is_err());
    assert_disabled(&mut receiver, MAX_MESSAGES_PER_KEY, 4);
}

#[test]
fn exact_plaintext_byte_limit_succeeds_then_nonempty_message_fails() {
    let first = encrypted(header(MessagePurpose::Request, 0), b"x", None);
    let second = encrypted(header(MessagePurpose::Request, 1), b"y", None);
    let mut receiver = receiver();
    receiver.plaintext_bytes = MAX_PLAINTEXT_BYTES_PER_KEY - 1;
    receiver.open(&first, MessagePurpose::Request).unwrap();
    assert_eq!(receiver.plaintext_bytes, MAX_PLAINTEXT_BYTES_PER_KEY);
    assert!(!receiver.failed);
    assert!(receiver.open(&second, MessagePurpose::Request).is_err());
    assert_disabled(&mut receiver, 1, MAX_PLAINTEXT_BYTES_PER_KEY);
}

#[test]
fn byte_total_overflow_is_rejected_without_wrapping() {
    let body = encrypted(header(MessagePurpose::Request, 0), b"x", None);
    let mut receiver = receiver();
    // Synthetic state specifically exercises checked_add's overflow branch.
    receiver.plaintext_bytes = u64::MAX;
    assert!(receiver.open(&body, MessagePurpose::Request).is_err());
    assert_disabled(&mut receiver, 0, u64::MAX);
}

#[test]
fn maximum_plaintext_opens_and_updates_counters_exactly() {
    let plaintext = vec![0x5a; MAX_PLAINTEXT_LEN];
    let body = encrypted(header(MessagePurpose::Request, 0), &plaintext, None);
    let mut receiver = receiver();
    assert_eq!(
        receiver
            .open(&body, MessagePurpose::Request)
            .unwrap()
            .body(),
        plaintext.as_slice()
    );
    assert_eq!(receiver.next_sequence, 1);
    assert_eq!(receiver.plaintext_bytes, MAX_PLAINTEXT_LEN as u64);
    assert!(!receiver.failed);
}

#[test]
fn authenticated_empty_plaintext_consumes_sequence_but_not_byte_budget() {
    let body = encrypted(header(MessagePurpose::Request, 0), b"", None);
    let mut receiver = receiver();
    assert!(
        receiver
            .open(&body, MessagePurpose::Request)
            .unwrap()
            .body()
            .is_empty()
    );
    assert_eq!(receiver.next_sequence, 1);
    assert_eq!(receiver.plaintext_bytes, 0);
    assert!(!receiver.failed);
}

#[test]
fn authenticated_plaintext_debug_is_redacted() {
    let secret = b"do-not-display-this-plaintext";
    let body = encrypted(header(MessagePurpose::Request, 0), secret, None);
    let mut receiver = receiver();
    let opened: OpenedMessage = receiver.open(&body, MessagePurpose::Request).unwrap();
    let debug = format!("{opened:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("do-not-display-this-plaintext"));
}
