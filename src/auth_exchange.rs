use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use crate::auth::{Authenticator, ClientIdentity};
use crate::auth_wire::{AuthenticationReply, AuthenticationRequest};
use crate::frame::FrameKind;
use crate::phase::PhaseDeadline;
use crate::session::Session;
use crate::state::{ConnectionEvent, ConnectionState};

impl<S: Read + Write + PhaseDeadline> Session<S> {
    pub(crate) fn authenticate_client(
        &mut self,
        credentials: &[u8],
        budget: Duration,
    ) -> io::Result<()> {
        self.run_phase(budget, |session| {
            require_authenticating(session.state())?;

            {
                let request = AuthenticationRequest::new(credentials)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
                let encoded = request.encode();
                session.send(FrameKind::Control, encoded.as_slice())?;
            }

            let frame = session
                .receive()?
                .ok_or_else(|| unexpected_eof("peer closed before authentication reply"))?;

            let reply = AuthenticationReply::decode(frame.body())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

            if reply == AuthenticationReply::Rejected {
                return Err(authentication_rejected());
            }

            session
                .advance(ConnectionEvent::ClientAuthenticated)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        })
    }

    pub(crate) fn authenticate_server(
        &mut self,
        authenticator: &dyn Authenticator,
        budget: Duration,
    ) -> io::Result<ClientIdentity> {
        let started = Instant::now();

        self.run_phase(budget, |session| {
            require_authenticating(session.state())?;

            let verification = {
                let frame = session
                    .receive()?
                    .ok_or_else(|| unexpected_eof("peer closed before authentication request"))?;

                let request = AuthenticationRequest::decode(frame.body())
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

                authenticator.authenticate(request.credentials())
            };

            // A synchronous callback cannot be interrupted. If it
            // returns too late, do not send an acceptance message.
            if started.elapsed() >= budget {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "authentication deadline expired",
                ));
            }

            let identity = match verification {
                Ok(identity) => identity,
                Err(_) => {
                    session.send(FrameKind::Control, &AuthenticationReply::Rejected.encode())?;

                    return Err(authentication_rejected());
                }
            };

            session.send(FrameKind::Control, &AuthenticationReply::Accepted.encode())?;

            session
                .advance(ConnectionEvent::ClientAuthenticated)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

            Ok(identity)
        })
    }
}

fn require_authenticating(state: ConnectionState) -> io::Result<()> {
    if state != ConnectionState::Authenticating {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "authentication requires the Authenticating state",
        ));
    }

    Ok(())
}

fn authentication_rejected() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "authentication rejected")
}

fn unexpected_eof(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, message)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::auth::AuthenticationError;
    use crate::wire::write_frame;

    struct TestStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for TestStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for TestStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl PhaseDeadline for TestStream {
        fn start_phase(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }

        fn finish_phase(&mut self) {}
    }

    fn authenticating_session(body: &[u8]) -> Session<TestStream> {
        let mut input = Vec::new();

        write_frame(&mut input, FrameKind::Control, body).unwrap();

        let mut session = Session::new(TestStream {
            input: Cursor::new(input),
            output: Vec::new(),
        });

        session.advance(ConnectionEvent::TlsEstablished).unwrap();

        session.advance(ConnectionEvent::VersionAccepted).unwrap();

        session
    }

    // Test double only: this is not an authentication mechanism.
    struct RecordingAuthenticator;

    impl Authenticator for RecordingAuthenticator {
        fn authenticate(&self, credentials: &[u8]) -> Result<ClientIdentity, AuthenticationError> {
            assert_eq!(credentials, b"test-credential");

            ClientIdentity::new("test-client").map_err(|_| AuthenticationError::Unavailable)
        }
    }

    struct RejectingAuthenticator;

    impl Authenticator for RejectingAuthenticator {
        fn authenticate(&self, _: &[u8]) -> Result<ClientIdentity, AuthenticationError> {
            Err(AuthenticationError::Rejected)
        }
    }

    #[test]
    fn client_advances_only_after_accepted_reply() {
        let mut session = authenticating_session(&AuthenticationReply::Accepted.encode());

        session
            .authenticate_client(b"test-credential", Duration::from_secs(1))
            .unwrap();

        assert_eq!(session.state(), ConnectionState::EstablishingKeys);
    }

    #[test]
    fn client_closes_after_rejected_reply() {
        let mut session = authenticating_session(&AuthenticationReply::Rejected.encode());

        let error = session
            .authenticate_client(b"test-credential", Duration::from_secs(1))
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(session.state(), ConnectionState::Closed);
    }

    #[test]
    fn server_returns_verified_identity() {
        let request = AuthenticationRequest::new(b"test-credential")
            .unwrap()
            .encode();

        let mut session = authenticating_session(&request);

        let identity = session
            .authenticate_server(&RecordingAuthenticator, Duration::from_secs(1))
            .unwrap();

        assert_eq!(identity.as_str(), "test-client");
        assert_eq!(session.state(), ConnectionState::EstablishingKeys);
    }

    #[test]
    fn server_closes_when_authenticator_rejects() {
        let request = AuthenticationRequest::new(b"test-credential")
            .unwrap()
            .encode();

        let mut session = authenticating_session(&request);

        let error = session
            .authenticate_server(&RejectingAuthenticator, Duration::from_secs(1))
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(session.state(), ConnectionState::Closed);
    }
}

#[cfg(test)]
#[path = "auth_adversarial_tests.rs"]
mod adversarial_tests;
