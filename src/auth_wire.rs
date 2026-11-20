use std::error::Error;
use std::fmt;

use zeroize::Zeroizing;

const REQUEST_TAG: u8 = 0x10;
const ACCEPTED_TAG: u8 = 0x11;
const REJECTED_TAG: u8 = 0x12;

pub(crate) const MAX_CREDENTIAL_BYTES: usize = 4096;

/// A validated, borrowed credential payload.
///
/// Debug output deliberately excludes credential contents.
pub(crate) struct AuthenticationRequest<'a> {
    credentials: &'a [u8],
}

impl<'a> AuthenticationRequest<'a> {
    pub(crate) fn new(credentials: &'a [u8]) -> Result<Self, AuthenticationWireError> {
        if credentials.is_empty() || credentials.len() > MAX_CREDENTIAL_BYTES {
            return Err(AuthenticationWireError::InvalidCredentialLength);
        }

        Ok(Self { credentials })
    }

    pub(crate) fn credentials(&self) -> &'a [u8] {
        self.credentials
    }

    /// Owns an encoded credential copy that is zeroized on drop.
    /// Never log the returned bytes.
    pub(crate) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(1 + self.credentials.len()));

        bytes.push(REQUEST_TAG);
        bytes.extend_from_slice(self.credentials);

        bytes
    }

    pub(crate) fn decode(bytes: &'a [u8]) -> Result<Self, AuthenticationWireError> {
        let Some((&tag, credentials)) = bytes.split_first() else {
            return Err(AuthenticationWireError::InvalidMessage);
        };

        if tag != REQUEST_TAG {
            return Err(AuthenticationWireError::InvalidMessage);
        }

        Self::new(credentials)
    }
}

impl fmt::Debug for AuthenticationRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticationRequest")
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticationReply {
    Accepted,
    Rejected,
}

impl AuthenticationReply {
    pub(crate) fn encode(self) -> [u8; 1] {
        match self {
            Self::Accepted => [ACCEPTED_TAG],
            Self::Rejected => [REJECTED_TAG],
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, AuthenticationWireError> {
        match bytes {
            [ACCEPTED_TAG] => Ok(Self::Accepted),
            [REJECTED_TAG] => Ok(Self::Rejected),
            _ => Err(AuthenticationWireError::InvalidMessage),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthenticationWireError {
    InvalidMessage,
    InvalidCredentialLength,
}

impl fmt::Display for AuthenticationWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMessage => {
                write!(f, "invalid authentication message")
            }
            Self::InvalidCredentialLength => {
                write!(f, "credentials must contain 1..=4096 bytes")
            }
        }
    }
}

impl Error for AuthenticationWireError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_matches_wire_format_and_round_trips() {
        let request = AuthenticationRequest::new(b"example").unwrap();
        let encoded = request.encode();

        assert_eq!(encoded.as_slice(), b"\x10example");

        let decoded = AuthenticationRequest::decode(&encoded).unwrap();

        assert_eq!(decoded.credentials(), b"example");
    }

    #[test]
    fn accepts_maximum_credential_length() {
        let credentials = vec![42; MAX_CREDENTIAL_BYTES];
        let request = AuthenticationRequest::new(&credentials).unwrap();
        let encoded = request.encode();

        assert_eq!(encoded.len(), MAX_CREDENTIAL_BYTES + 1);
        assert_eq!(
            AuthenticationRequest::decode(&encoded)
                .unwrap()
                .credentials(),
            credentials.as_slice()
        );
    }

    #[test]
    fn rejects_empty_and_oversized_credentials() {
        for credentials in [Vec::new(), vec![0; MAX_CREDENTIAL_BYTES + 1]] {
            assert!(matches!(
                AuthenticationRequest::new(&credentials),
                Err(AuthenticationWireError::InvalidCredentialLength)
            ));

            let mut encoded = vec![REQUEST_TAG];
            encoded.extend_from_slice(&credentials);

            assert!(matches!(
                AuthenticationRequest::decode(&encoded),
                Err(AuthenticationWireError::InvalidCredentialLength)
            ));
        }
    }

    #[test]
    fn request_rejects_missing_or_wrong_tag() {
        for bytes in [
            &[][..],
            &[ACCEPTED_TAG][..],
            &[REJECTED_TAG, 42][..],
            &[0xff, 42][..],
        ] {
            assert!(matches!(
                AuthenticationRequest::decode(bytes),
                Err(AuthenticationWireError::InvalidMessage)
            ));
        }
    }

    #[test]
    fn replies_match_wire_format_and_round_trip() {
        for (reply, expected) in [
            (AuthenticationReply::Accepted, [ACCEPTED_TAG]),
            (AuthenticationReply::Rejected, [REJECTED_TAG]),
        ] {
            assert_eq!(reply.encode(), expected);

            assert_eq!(AuthenticationReply::decode(&expected), Ok(reply));
        }
    }

    #[test]
    fn replies_reject_invalid_lengths_and_tags() {
        for bytes in [
            &[][..],
            &[REQUEST_TAG][..],
            &[0xff][..],
            &[ACCEPTED_TAG, 0][..],
            &[REJECTED_TAG, 0][..],
        ] {
            assert_eq!(
                AuthenticationReply::decode(bytes),
                Err(AuthenticationWireError::InvalidMessage)
            );
        }
    }

    #[test]
    fn request_debug_redacts_credentials() {
        let request = AuthenticationRequest::new(b"do-not-print-this").unwrap();

        let debug = format!("{request:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("do-not-print-this"));
    }

    #[test]
    fn encoded_request_uses_zeroizing_owned_storage() {
        let request = AuthenticationRequest::new(b"test-credential").unwrap();
        let encoded: Zeroizing<Vec<u8>> = request.encode();
        assert_eq!(encoded.as_slice(), b"\x10test-credential");
        let decoded = AuthenticationRequest::decode(encoded.as_slice()).unwrap();
        assert_eq!(decoded.credentials(), b"test-credential");
    }
}
