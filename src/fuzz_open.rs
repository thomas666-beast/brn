//! Authenticated-envelope fuzz harnesses, absent from ordinary builds.

use crate::envelope::{
    AUTH_TAG_LEN, Direction, ENVELOPE_HEADER_LEN, EnvelopeHeader, MessagePurpose,
};
use crate::open::MessageOpener;
use crate::seal::{MAX_PLAINTEXT_LEN, MessageSealer};

// Fixed keys, recreated owners, and repeated nonces are fuzz fixtures only.
// Never copy this construction pattern into production key management.
const KEY: [u8; 32] = [0x42; 32];
const WRONG_KEY: [u8; 32] = [0x99; 32];

fn sender() -> MessageSealer {
    MessageSealer::new(&KEY, Direction::ClientToServer).unwrap()
}

fn receiver() -> MessageOpener {
    MessageOpener::new(&KEY, Direction::ClientToServer).unwrap()
}

fn assert_disabled(receiver: &mut MessageOpener, valid_zero: &[u8]) {
    let error = receiver
        .open(valid_zero, MessagePurpose::Request)
        .unwrap_err();
    assert_eq!(error.to_string(), "application receiving key is disabled");
}

pub fn open_arbitrary(data: &[u8]) {
    let mut sender = sender();
    let zero = sender
        .seal(MessagePurpose::Request, b"known valid zero")
        .unwrap();
    let one = sender
        .seal(MessagePurpose::Request, b"known valid one")
        .unwrap();
    let mut receiver = receiver();
    match receiver.open(data, MessagePurpose::Request) {
        Ok(opened) => {
            let header = EnvelopeHeader::decode(&data[..ENVELOPE_HEADER_LEN]).unwrap();
            assert_eq!(header.direction(), Direction::ClientToServer);
            assert_eq!(header.purpose(), MessagePurpose::Request);
            assert_eq!(header.sequence(), 0);
            assert_eq!(
                opened.body().len() + ENVELOPE_HEADER_LEN + AUTH_TAG_LEN,
                data.len()
            );
            assert!(opened.body().len() <= MAX_PLAINTEXT_LEN);
            let next = receiver.open(one.body(), MessagePurpose::Request).unwrap();
            assert_eq!(next.body(), b"known valid one");
            assert!(receiver.open(data, MessagePurpose::Request).is_err());
            assert_disabled(&mut receiver, zero.body());
        }
        Err(_) => assert_disabled(&mut receiver, zero.body()),
    }
}

pub fn open_mutated(data: &[u8]) {
    let mode = data.first().copied().unwrap_or(0) % 8;
    let control = usize::from(u16::from_be_bytes([
        data.get(1).copied().unwrap_or(0),
        data.get(2).copied().unwrap_or(0),
    ]));
    let payload = data.get(3..).unwrap_or_default();
    let payload = &payload[..payload.len().min(MAX_PLAINTEXT_LEN)];
    let mut sender = sender();
    let valid = sender.seal(MessagePurpose::Request, payload).unwrap();
    let mut baseline = receiver();
    let opened = baseline
        .open(valid.body(), MessagePurpose::Request)
        .unwrap();
    assert_eq!(opened.body(), payload);

    let mut receiver = if mode == 5 {
        MessageOpener::new(&WRONG_KEY, Direction::ClientToServer).unwrap()
    } else {
        receiver()
    };
    let mut modified = valid.body().to_vec();
    let mut expected = MessagePurpose::Request;
    match mode {
        0 => {
            let length = modified.len() - ENVELOPE_HEADER_LEN;
            let index = ENVELOPE_HEADER_LEN + control % length;
            modified[index] ^= 1_u8 << ((control / length) % 8);
        }
        1 => {
            let index = control % ENVELOPE_HEADER_LEN;
            modified[index] ^= 1_u8 << ((control / ENVELOPE_HEADER_LEN) % 8);
        }
        2 => {
            let length = control % modified.len();
            modified.truncate(length);
        }
        3 => modified.push(control as u8),
        4 => expected = MessagePurpose::KeyConfirmation,
        5 => {} // Unmodified envelope with the wrong receiving key.
        6 => {
            let first = receiver
                .open(valid.body(), MessagePurpose::Request)
                .unwrap();
            assert_eq!(first.body(), payload);
        }
        7 => {
            let next = sender.seal(MessagePurpose::Request, payload).unwrap();
            let header = EnvelopeHeader::decode(&next.body()[..ENVELOPE_HEADER_LEN]).unwrap();
            assert_eq!(header.sequence(), 1);
            modified = next.body().to_vec();
        }
        _ => unreachable!(),
    }
    assert!(receiver.open(&modified, expected).is_err());
    assert_disabled(&mut receiver, valid.body());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_harness_checks_valid_and_malformed_inputs() {
        open_arbitrary(&[]);
        open_arbitrary(&[0; 128]);
        let mut sender = sender();
        let valid = sender
            .seal(MessagePurpose::Request, b"valid fuzz seed")
            .unwrap();
        open_arbitrary(valid.body());
        let mut tampered = valid.body().to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        open_arbitrary(&tampered);
    }

    #[test]
    fn mutation_harness_exercises_all_modes_and_payload_boundaries() {
        for mode in 0..8 {
            for length in [0, 1, 256, MAX_PLAINTEXT_LEN] {
                let mut input = vec![mode, 0xff, 0xff];
                input.extend(vec![0xa5; length]);
                open_mutated(&input);
            }
        }
    }
}
