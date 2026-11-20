use std::error::Error;
use std::fmt;

pub(crate) const PROTOCOL_VERSION: u16 = 1;
const MESSAGE_LEN: usize = 3;

const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;

/// Version-negotiation messages for the current application protocol.
///
/// Successful decoding validates the encoding and supported version.
/// It does not establish peer identity or complete negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NegotiationMessage {
    ClientHello,
    ServerHello,
}

impl NegotiationMessage {
    pub(crate) fn encode(self) -> [u8; MESSAGE_LEN] {
        let tag = match self {
            Self::ClientHello => CLIENT_HELLO,
            Self::ServerHello => SERVER_HELLO,
        };

        let version = PROTOCOL_VERSION.to_be_bytes();

        [tag, version[0], version[1]]
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, NegotiationError> {
        if bytes.len() != MESSAGE_LEN {
            return Err(NegotiationError::InvalidLength {
                received: bytes.len(),
            });
        }

        let message = match bytes[0] {
            CLIENT_HELLO => Self::ClientHello,
            SERVER_HELLO => Self::ServerHello,
            tag => return Err(NegotiationError::UnknownTag(tag)),
        };

        let version = u16::from_be_bytes([bytes[1], bytes[2]]);

        if version != PROTOCOL_VERSION {
            return Err(NegotiationError::UnsupportedVersion(version));
        }

        Ok(message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NegotiationError {
    InvalidLength { received: usize },
    UnknownTag(u8),
    UnsupportedVersion(u16),
}

impl fmt::Display for NegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { received } => write!(
                f,
                "invalid negotiation message length: expected {MESSAGE_LEN}, got {received}"
            ),
            Self::UnknownTag(tag) => {
                write!(f, "unknown negotiation message tag: {tag}")
            }
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported BRN protocol version: {version}")
            }
        }
    }
}

impl Error for NegotiationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_matches_wire_format() {
        assert_eq!(NegotiationMessage::ClientHello.encode(), [1, 0, 1]);
    }

    #[test]
    fn server_hello_matches_wire_format() {
        assert_eq!(NegotiationMessage::ServerHello.encode(), [2, 0, 1]);
    }

    #[test]
    fn both_messages_round_trip() {
        for message in [
            NegotiationMessage::ClientHello,
            NegotiationMessage::ServerHello,
        ] {
            assert_eq!(NegotiationMessage::decode(&message.encode()), Ok(message));
        }
    }

    #[test]
    fn rejects_incorrect_lengths() {
        for length in [0, 1, 2, 4, 16] {
            let bytes = vec![0; length];

            assert_eq!(
                NegotiationMessage::decode(&bytes),
                Err(NegotiationError::InvalidLength { received: length })
            );
        }
    }

    #[test]
    fn rejects_every_unknown_tag() {
        for tag in 0..=u8::MAX {
            if tag == CLIENT_HELLO || tag == SERVER_HELLO {
                continue;
            }

            assert_eq!(
                NegotiationMessage::decode(&[tag, 0, 1]),
                Err(NegotiationError::UnknownTag(tag))
            );
        }
    }

    #[test]
    fn rejects_every_unsupported_version() {
        for version in 0..=u16::MAX {
            if version == PROTOCOL_VERSION {
                continue;
            }

            let encoded_version = version.to_be_bytes();

            for tag in [CLIENT_HELLO, SERVER_HELLO] {
                let bytes = [tag, encoded_version[0], encoded_version[1]];

                assert_eq!(
                    NegotiationMessage::decode(&bytes),
                    Err(NegotiationError::UnsupportedVersion(version))
                );
            }
        }
    }
}
