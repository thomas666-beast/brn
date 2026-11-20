use std::error::Error;
use std::fmt;

const MAX_IDENTITY_BYTES: usize = 256;

/// An application-defined identity assigned after authentication.
///
/// This is an identifier, not a credential or encryption key.
/// Constructing one does not authenticate a connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientIdentity {
    value: String,
}

impl ClientIdentity {
    /// Creates an identity containing 1..=256 UTF-8 bytes.
    ///
    /// Control characters are rejected.
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidIdentity> {
        let value = value.into();

        if value.is_empty()
            || value.len() > MAX_IDENTITY_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(InvalidIdentity);
        }

        Ok(Self { value })
    }

    pub fn as_str(&self) -> &str {
        &self.value
    }
}

/// An invalid application identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidIdentity;

impl fmt::Display for InvalidIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "client identity must contain 1..=256 UTF-8 bytes \
             and no control characters"
        )
    }
}

impl Error for InvalidIdentity {}

/// A server-side authentication failure.
///
/// These variants deliberately contain no credentials or backend details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationError {
    /// Credentials were not accepted.
    Rejected,

    /// Authentication could not be completed, such as a backend outage.
    Unavailable,
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected => write!(f, "authentication rejected"),
            Self::Unavailable => write!(f, "authentication unavailable"),
        }
    }
}

impl Error for AuthenticationError {}

/// Application-provided client authentication.
///
/// BRN will supply a bounded credential payload received through the
/// verified TLS connection.
///
/// Implementations must:
/// - validate credentials using their chosen authentication mechanism;
/// - apply expiration and revocation rules where applicable;
/// - return the identity derived from successful verification;
/// - avoid logging the credential payload.
///
/// There is no default implementation.
///
/// This is a synchronous interface. Implementations must bound their
/// own backend operations; BRN cannot interrupt a blocked callback.
pub trait Authenticator: Send + Sync {
    fn authenticate(&self, credentials: &[u8]) -> Result<ClientIdentity, AuthenticationError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_identity_and_preserves_value() {
        let identity = ClientIdentity::new("service:inventory").unwrap();

        assert_eq!(identity.as_str(), "service:inventory");
    }

    #[test]
    fn rejects_empty_identity() {
        assert_eq!(ClientIdentity::new(""), Err(InvalidIdentity));
    }

    #[test]
    fn enforces_identity_byte_limit() {
        assert!(ClientIdentity::new("a".repeat(256)).is_ok());

        assert_eq!(ClientIdentity::new("a".repeat(257)), Err(InvalidIdentity));

        // Each character occupies two UTF-8 bytes.
        assert!(ClientIdentity::new("é".repeat(128)).is_ok());

        assert_eq!(ClientIdentity::new("é".repeat(129)), Err(InvalidIdentity));
    }

    #[test]
    fn rejects_control_characters() {
        for value in [
            "client\nname",
            "client\rname",
            "client\tname",
            "client\0name",
        ] {
            assert_eq!(ClientIdentity::new(value), Err(InvalidIdentity));
        }
    }

    #[test]
    fn authentication_errors_have_generic_messages() {
        assert_eq!(
            AuthenticationError::Rejected.to_string(),
            "authentication rejected"
        );

        assert_eq!(
            AuthenticationError::Unavailable.to_string(),
            "authentication unavailable"
        );
    }
}
