use std::io::{self, Read, Write};

use crate::frame::FrameKind;
use crate::negotiation::NegotiationMessage;
use crate::session::Session;
use crate::state::{ConnectionEvent, ConnectionState};

#[derive(Debug, Clone, Copy)]
enum Role {
    Client,
    Server,
}

impl<S: Read + Write> Session<S> {
    pub(crate) fn negotiate_as_client(&mut self) -> io::Result<()> {
        self.negotiate(Role::Client)
    }

    pub(crate) fn negotiate_as_server(&mut self) -> io::Result<()> {
        self.negotiate(Role::Server)
    }

    fn negotiate(&mut self, role: Role) -> io::Result<()> {
        let result = self.exchange_version(role);

        if result.is_err() {
            self.close();
        }

        result
    }

    fn exchange_version(&mut self, role: Role) -> io::Result<()> {
        if self.state() != ConnectionState::Negotiating {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "version negotiation requires the Negotiating state",
            ));
        }

        match role {
            Role::Client => {
                self.send(
                    FrameKind::Control,
                    &NegotiationMessage::ClientHello.encode(),
                )?;

                self.expect_hello(NegotiationMessage::ServerHello)?;
            }
            Role::Server => {
                self.expect_hello(NegotiationMessage::ClientHello)?;

                self.send(
                    FrameKind::Control,
                    &NegotiationMessage::ServerHello.encode(),
                )?;
            }
        }

        self.advance(ConnectionEvent::VersionAccepted)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    fn expect_hello(&mut self, expected: NegotiationMessage) -> io::Result<()> {
        let frame = self.receive()?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed before version negotiation completed",
            )
        })?;

        if frame.kind() != FrameKind::Control {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected a control frame during version negotiation",
            ));
        }

        let message = NegotiationMessage::decode(frame.body())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

        if message != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected negotiation message for peer role",
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::Cursor;
    use std::rc::Rc;

    use super::*;
    use crate::wire::write_frame;

    struct TestStream {
        input: Cursor<Vec<u8>>,
        output: Rc<RefCell<Vec<u8>>>,
    }

    impl Read for TestStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.input.read(bytes)
        }
    }

    impl Write for TestStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.output.borrow_mut().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn control_frame(body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, FrameKind::Control, body).unwrap();
        bytes
    }

    fn new_session(input: Vec<u8>) -> Session<TestStream> {
        Session::new(TestStream {
            input: Cursor::new(input),
            output: Rc::new(RefCell::new(Vec::new())),
        })
    }

    fn negotiating_session(input: Vec<u8>) -> Session<TestStream> {
        let mut session = new_session(input);

        session.advance(ConnectionEvent::TlsEstablished).unwrap();

        session
    }

    #[test]
    fn client_sends_hello_and_accepts_server_hello() {
        let output = Rc::new(RefCell::new(Vec::new()));

        let mut session = Session::new(TestStream {
            input: Cursor::new(control_frame(&NegotiationMessage::ServerHello.encode())),
            output: Rc::clone(&output),
        });

        session.advance(ConnectionEvent::TlsEstablished).unwrap();

        session.negotiate_as_client().unwrap();

        assert_eq!(session.state(), ConnectionState::Authenticating);
        assert_eq!(
            output.borrow().as_slice(),
            control_frame(&NegotiationMessage::ClientHello.encode()).as_slice()
        );
    }

    #[test]
    fn server_accepts_client_hello_and_sends_hello() {
        let output = Rc::new(RefCell::new(Vec::new()));

        let mut session = Session::new(TestStream {
            input: Cursor::new(control_frame(&NegotiationMessage::ClientHello.encode())),
            output: Rc::clone(&output),
        });

        session.advance(ConnectionEvent::TlsEstablished).unwrap();

        session.negotiate_as_server().unwrap();

        assert_eq!(session.state(), ConnectionState::Authenticating);
        assert_eq!(
            output.borrow().as_slice(),
            control_frame(&NegotiationMessage::ServerHello.encode()).as_slice()
        );
    }

    #[test]
    fn rejects_wrong_peer_role() {
        let mut client =
            negotiating_session(control_frame(&NegotiationMessage::ClientHello.encode()));

        let mut server =
            negotiating_session(control_frame(&NegotiationMessage::ServerHello.encode()));

        assert_eq!(
            client.negotiate_as_client().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            server.negotiate_as_server().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        assert_eq!(client.state(), ConnectionState::Closed);
        assert_eq!(server.state(), ConnectionState::Closed);
    }

    #[test]
    fn rejects_malformed_or_unsupported_hello() {
        for body in [vec![2], vec![99, 0, 1], vec![2, 0, 2], vec![2, 0, 1, 0]] {
            let mut session = negotiating_session(control_frame(&body));

            assert_eq!(
                session.negotiate_as_client().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(session.state(), ConnectionState::Closed);
        }
    }

    #[test]
    fn eof_during_negotiation_closes_session() {
        let mut session = negotiating_session(Vec::new());

        assert_eq!(
            session.negotiate_as_server().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(session.state(), ConnectionState::Closed);
    }

    #[test]
    fn negotiation_requires_correct_state_and_cannot_repeat() {
        let mut before_tls = new_session(Vec::new());

        assert_eq!(
            before_tls.negotiate_as_client().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(before_tls.state(), ConnectionState::Closed);

        let mut session =
            negotiating_session(control_frame(&NegotiationMessage::ServerHello.encode()));

        session.negotiate_as_client().unwrap();

        assert_eq!(
            session.negotiate_as_client().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(session.state(), ConnectionState::Closed);
    }
}
