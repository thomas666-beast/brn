use std::error::Error;
use std::fmt;

use aws_lc_rs::aead::Nonce;

/// Initial BRN policy, including key-confirmation messages.
///
/// This is a message-count cap, not a complete cryptographic usage policy.
/// Byte limits, message sizes, failed verification limits, and expiration
/// still need separate enforcement.
pub(crate) const MAX_MESSAGES_PER_KEY: u64 = 1 << 20;

/// Owns sending sequence allocation for exactly one directional key.
///
/// Not Clone or Copy. Must never be recreated for an existing key.
#[derive(Debug)]
pub(crate) struct SendSequence {
    next: u64,
}

impl SendSequence {
    pub(crate) fn new() -> Self {
        Self { next: 0 }
    }

    /// Reserves and permanently consumes a sequence number.
    ///
    /// Discarding the reservation does not return it to the counter.
    /// Encryption or transmission failures must not rewind this counter.
    pub(crate) fn reserve(&mut self) -> Result<ReservedSequence, SequenceExhausted> {
        if self.next >= MAX_MESSAGES_PER_KEY {
            return Err(SequenceExhausted);
        }

        let sequence = self.next;

        // Safe because the limit is strictly below u64::MAX.
        self.next += 1;

        Ok(ReservedSequence { sequence })
    }
}

/// One reserved encryption sequence.
///
/// Its nonce conversion consumes this value. It is not Clone or Copy.
#[derive(Debug)]
pub(crate) struct ReservedSequence {
    sequence: u64,
}

impl ReservedSequence {
    pub(crate) fn number(&self) -> u64 {
        self.sequence
    }

    pub(crate) fn into_nonce(self) -> Nonce {
        let mut bytes = [0; 12];

        bytes[4..].copy_from_slice(&self.sequence.to_be_bytes());

        Nonce::assume_unique_for_key(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SequenceExhausted;

impl fmt::Display for SequenceExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "application-key message limit reached")
    }
}

impl Error for SequenceExhausted {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_nonce_is_zero_and_second_encodes_one() {
        let mut sequence = SendSequence::new();

        let first = sequence.reserve().unwrap();
        assert_eq!(first.number(), 0);

        let first_nonce = first.into_nonce();
        assert_eq!(first_nonce.as_ref(), &[0; 12]);

        let second = sequence.reserve().unwrap();
        assert_eq!(second.number(), 1);

        let second_nonce = second.into_nonce();

        assert_eq!(second_nonce.as_ref(), &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn sequence_numbers_increase_monotonically() {
        let mut sequence = SendSequence::new();

        for expected in 0..1000 {
            let reserved = sequence.reserve().unwrap();

            assert_eq!(reserved.number(), expected);
        }
    }

    #[test]
    fn discarded_reservation_is_not_reused() {
        let mut sequence = SendSequence::new();

        {
            let unused = sequence.reserve().unwrap();
            assert_eq!(unused.number(), 0);
        }

        assert_eq!(sequence.reserve().unwrap().number(), 1);
    }

    #[test]
    fn final_allowed_sequence_is_followed_by_permanent_exhaustion() {
        let mut sequence = SendSequence {
            next: MAX_MESSAGES_PER_KEY - 1,
        };

        let final_reservation = sequence.reserve().unwrap();

        assert_eq!(final_reservation.number(), MAX_MESSAGES_PER_KEY - 1);

        for _ in 0..3 {
            assert!(matches!(sequence.reserve(), Err(SequenceExhausted)));
        }
    }

    #[test]
    fn invalid_high_counter_cannot_wrap() {
        let mut sequence = SendSequence { next: u64::MAX };

        assert!(matches!(sequence.reserve(), Err(SequenceExhausted)));

        assert_eq!(sequence.next, u64::MAX);
    }
}

impl SendSequence {
    /// Remaining reservations before this sending sequence is exhausted.
    ///
    /// Does not reserve a sequence or change state.
    pub(crate) fn remaining(&self) -> u64 {
        MAX_MESSAGES_PER_KEY.saturating_sub(self.next)
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;

    #[test]
    fn inspection_does_not_consume_sequence() {
        let mut sequence = SendSequence::new();

        assert_eq!(sequence.remaining(), MAX_MESSAGES_PER_KEY);
        assert_eq!(sequence.remaining(), MAX_MESSAGES_PER_KEY);

        let reserved = sequence.reserve().unwrap();

        assert_eq!(reserved.number(), 0);
        assert_eq!(sequence.remaining(), MAX_MESSAGES_PER_KEY - 1);
    }

    #[test]
    fn exhausted_or_invalid_counter_reports_zero() {
        for next in [MAX_MESSAGES_PER_KEY, u64::MAX] {
            let sequence = SendSequence { next };

            assert_eq!(sequence.remaining(), 0);
        }
    }
}
