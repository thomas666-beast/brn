use std::fmt;
use std::io;

use zeroize::Zeroizing;

use crate::epoch::KEY_LIFETIME;
use crate::keys::{KEY_MATERIAL_LEN, TemporaryKeys};

const OFFER_TAG: u8 = 0x20;
const OFFER_FORMAT: u8 = 1;
const AES_256_GCM_SUITE: u8 = 1;

const OFFER_HEADER_LEN: usize = 11;
const OFFER_LEN: usize = OFFER_HEADER_LEN + KEY_MATERIAL_LEN;

/// An outgoing key offer containing secret key material.
///
/// Never send outside the established authenticated TLS channel.
/// Debug output is redacted, and owned bytes are wiped on drop.
pub(crate) struct KeyOffer {
    body: Zeroizing<Vec<u8>>,
}

impl KeyOffer {
    pub(crate) fn from_keys(keys: &TemporaryKeys) -> Self {
        let mut body = Zeroizing::new(Vec::with_capacity(OFFER_LEN));

        body.push(OFFER_TAG);
        body.push(OFFER_FORMAT);
        body.push(AES_256_GCM_SUITE);

        body.extend_from_slice(&KEY_LIFETIME.as_secs().to_be_bytes());

        body.extend_from_slice(keys.as_bytes());

        Self { body }
    }

    pub(crate) fn body(&self) -> &[u8] {
        self.body.as_slice()
    }

    /// Validates a received offer and copies its keys into owned storage.
    ///
    /// The source buffer remains the caller's cleanup responsibility.
    /// This function does not establish trust in the transport.
    pub(crate) fn decode(body: &[u8]) -> io::Result<TemporaryKeys> {
        if body.len() != OFFER_LEN {
            return Err(invalid("invalid key-offer length"));
        }

        if body[0] != OFFER_TAG {
            return Err(invalid("unexpected key-offer message tag"));
        }

        if body[1] != OFFER_FORMAT {
            return Err(invalid("unsupported key-offer format"));
        }

        if body[2] != AES_256_GCM_SUITE {
            return Err(invalid("unsupported application encryption suite"));
        }

        if body[3..OFFER_HEADER_LEN] != KEY_LIFETIME.as_secs().to_be_bytes() {
            return Err(invalid("unsupported application-key lifetime"));
        }

        TemporaryKeys::from_bytes(&body[OFFER_HEADER_LEN..])
    }
}

impl fmt::Debug for KeyOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyOffer")
            .field("body", &"[REDACTED]")
            .finish()
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> TemporaryKeys {
        let mut bytes = [0x11; KEY_MATERIAL_LEN];
        bytes[32..].fill(0x22);

        TemporaryKeys::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn offer_matches_format_and_round_trips() {
        let original = keys();
        let offer = KeyOffer::from_keys(&original);

        assert_eq!(offer.body().len(), OFFER_LEN);
        assert_eq!(&offer.body()[..3], &[0x20, 1, 1]);
        assert_eq!(&offer.body()[3..OFFER_HEADER_LEN], &900_u64.to_be_bytes());

        let decoded = KeyOffer::decode(offer.body()).unwrap();

        assert_eq!(decoded.client_to_server(), original.client_to_server());
        assert_eq!(decoded.server_to_client(), original.server_to_client());
    }

    #[test]
    fn rejects_incorrect_lengths() {
        for length in [0, 1, OFFER_LEN - 1, OFFER_LEN + 1] {
            let error = KeyOffer::decode(&vec![0; length]).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn rejects_unsupported_header_values() {
        let original = keys();
        let offer = KeyOffer::from_keys(&original);

        for index in [0, 1, 2, OFFER_HEADER_LEN - 1] {
            let mut modified = offer.body().to_vec();
            modified[index] ^= 0xff;

            assert!(KeyOffer::decode(&modified).is_err());
        }
    }

    #[test]
    fn debug_output_is_redacted() {
        let original = keys();
        let offer = KeyOffer::from_keys(&original);

        assert_eq!(format!("{offer:?}"), "KeyOffer { body: \"[REDACTED]\" }");
    }
}
