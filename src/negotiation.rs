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

pub(crate) mod v2 {
    use std::io;

    pub(crate) const VERSION: u16 = 2;
    const MESSAGE_LEN: usize = 5;

    const CLIENT_HELLO: u8 = 1;
    const SERVER_HELLO: u8 = 2;

    const UNPADDED_BIT: u16 = 1;
    const BLOCK256_BIT: u16 = 2;
    const KNOWN_BITS: u16 = UNPADDED_BIT | BLOCK256_BIT;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Profile {
        Unpadded,
        Block256,
    }

    impl Profile {
        fn bit(self) -> u16 {
            match self {
                Self::Unpadded => UNPADDED_BIT,
                Self::Block256 => BLOCK256_BIT,
            }
        }

        fn decode(bits: u16) -> io::Result<Self> {
            match bits {
                UNPADDED_BIT => Ok(Self::Unpadded),
                BLOCK256_BIT => Ok(Self::Block256),
                _ => Err(invalid("invalid selected padding profile")),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Profiles(u16);

    impl Profiles {
        pub(crate) const UNPADDED_ONLY: Self = Self(UNPADDED_BIT);
        pub(crate) const PADDED_ONLY: Self = Self(BLOCK256_BIT);
        pub(crate) const BOTH: Self = Self(KNOWN_BITS);

        fn decode(bits: u16) -> io::Result<Self> {
            if bits == 0 || bits & !KNOWN_BITS != 0 {
                return Err(invalid("invalid supported padding profiles"));
            }

            Ok(Self(bits))
        }

        pub(crate) fn contains(self, profile: Profile) -> bool {
            self.0 & profile.bit() != 0
        }

        /// Server policy intersected with the client's offer.
        /// Prefer padding whenever both sides permit it.
        pub(crate) fn select(self, offered: Self) -> io::Result<Profile> {
            let common = self.0 & offered.0;

            if common & BLOCK256_BIT != 0 {
                Ok(Profile::Block256)
            } else if common & UNPADDED_BIT != 0 {
                Ok(Profile::Unpadded)
            } else {
                Err(invalid("no common padding profile"))
            }
        }

        /// Client-side validation of the server's selection.
        pub(crate) fn accept(self, selected: Profile) -> io::Result<Profile> {
            if !self.contains(selected) {
                return Err(invalid("server selected an unoffered padding profile"));
            }

            Ok(selected)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Hello {
        Client { supported: Profiles },
        Server { selected: Profile },
    }

    impl Hello {
        pub(crate) fn encode(self) -> [u8; MESSAGE_LEN] {
            let (tag, profiles) = match self {
                Self::Client { supported } => (CLIENT_HELLO, supported.0),
                Self::Server { selected } => (SERVER_HELLO, selected.bit()),
            };

            let version = VERSION.to_be_bytes();
            let profiles = profiles.to_be_bytes();

            [tag, version[0], version[1], profiles[0], profiles[1]]
        }

        pub(crate) fn decode(bytes: &[u8]) -> io::Result<Self> {
            if bytes.len() != MESSAGE_LEN {
                return Err(invalid("invalid v2 hello length"));
            }

            let version = u16::from_be_bytes([bytes[1], bytes[2]]);

            if version != VERSION {
                return Err(invalid("unsupported v2 hello version"));
            }

            let bits = u16::from_be_bytes([bytes[3], bytes[4]]);

            match bytes[0] {
                CLIENT_HELLO => Ok(Self::Client {
                    supported: Profiles::decode(bits)?,
                }),
                SERVER_HELLO => Ok(Self::Server {
                    selected: Profile::decode(bits)?,
                }),
                _ => Err(invalid("unknown v2 hello tag")),
            }
        }
    }

    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn wire_format_is_explicit() {
            assert_eq!(
                Hello::Client {
                    supported: Profiles::BOTH,
                }
                .encode(),
                [1, 0, 2, 0, 3]
            );

            assert_eq!(
                Hello::Server {
                    selected: Profile::Block256,
                }
                .encode(),
                [2, 0, 2, 0, 2]
            );
        }

        #[test]
        fn all_supported_messages_round_trip() {
            let messages = [
                Hello::Client {
                    supported: Profiles::UNPADDED_ONLY,
                },
                Hello::Client {
                    supported: Profiles::PADDED_ONLY,
                },
                Hello::Client {
                    supported: Profiles::BOTH,
                },
                Hello::Server {
                    selected: Profile::Unpadded,
                },
                Hello::Server {
                    selected: Profile::Block256,
                },
            ];

            for message in messages {
                assert_eq!(Hello::decode(&message.encode()).unwrap(), message);
            }
        }

        #[test]
        fn selection_obeys_both_peers_policies() {
            use Profile::{Block256, Unpadded};

            let cases = [
                (
                    Profiles::UNPADDED_ONLY,
                    Profiles::UNPADDED_ONLY,
                    Some(Unpadded),
                ),
                (Profiles::UNPADDED_ONLY, Profiles::PADDED_ONLY, None),
                (Profiles::UNPADDED_ONLY, Profiles::BOTH, Some(Unpadded)),
                (Profiles::PADDED_ONLY, Profiles::UNPADDED_ONLY, None),
                (Profiles::PADDED_ONLY, Profiles::PADDED_ONLY, Some(Block256)),
                (Profiles::PADDED_ONLY, Profiles::BOTH, Some(Block256)),
                (Profiles::BOTH, Profiles::UNPADDED_ONLY, Some(Unpadded)),
                (Profiles::BOTH, Profiles::PADDED_ONLY, Some(Block256)),
                (Profiles::BOTH, Profiles::BOTH, Some(Block256)),
            ];

            for (allowed, offered, expected) in cases {
                assert_eq!(allowed.select(offered).ok(), expected);
            }
        }

        #[test]
        fn client_rejects_unoffered_selection() {
            assert!(Profiles::PADDED_ONLY.accept(Profile::Unpadded).is_err());

            assert!(Profiles::UNPADDED_ONLY.accept(Profile::Block256).is_err());

            assert_eq!(
                Profiles::BOTH.accept(Profile::Block256).unwrap(),
                Profile::Block256
            );
        }

        #[test]
        fn rejects_empty_unknown_or_multiple_selected_profiles() {
            for bits in [0u16, 4, 0x8000, 0xffff] {
                let encoded = bits.to_be_bytes();

                assert!(Hello::decode(&[1, 0, 2, encoded[0], encoded[1]]).is_err());

                assert!(Hello::decode(&[2, 0, 2, encoded[0], encoded[1]]).is_err());
            }

            // A server must select one profile, not advertise both.
            assert!(Hello::decode(&[2, 0, 2, 0, 3]).is_err());
        }

        #[test]
        fn rejects_wrong_lengths_versions_and_tags() {
            let valid = [1, 0, 2, 0, 3];

            for length in 0..valid.len() {
                assert!(Hello::decode(&valid[..length]).is_err());
            }

            assert!(Hello::decode(&[1, 0, 2, 0, 3, 0]).is_err());
            assert!(Hello::decode(&[1, 0, 1, 0, 3]).is_err());
            assert!(Hello::decode(&[99, 0, 2, 0, 3]).is_err());
        }

        #[test]
        fn v1_and_v2_codecs_reject_each_others_hello() {
            let old = super::super::NegotiationMessage::ClientHello.encode();

            assert!(Hello::decode(&old).is_err());

            let new = Hello::Client {
                supported: Profiles::BOTH,
            }
            .encode();

            assert!(super::super::NegotiationMessage::decode(&new).is_err());
        }
    }
}
