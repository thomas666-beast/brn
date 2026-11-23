use std::io::{self, Read, Write};

use crate::frame::FrameKind;
use crate::negotiation::NegotiationMessage;
use crate::negotiation::v2::{Hello, Profiles};
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

impl<S: Read + Write> Session<S> {
    pub(crate) fn negotiate_v2_as_client(&mut self, supported: Profiles) -> io::Result<()> {
        let result = (|| {
            self.require_v2_negotiating()?;

            self.send(FrameKind::Control, &Hello::Client { supported }.encode())?;

            let selected = match self.receive_v2_hello()? {
                Hello::Server { selected } => supported.accept(selected)?,
                Hello::Client { .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "expected v2 server hello",
                    ));
                }
            };

            self.install_padding_profile(selected)?;

            self.advance(ConnectionEvent::VersionAccepted)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        })();

        if result.is_err() {
            self.close();
        }

        result
    }

    pub(crate) fn negotiate_v2_as_server(&mut self, allowed: Profiles) -> io::Result<()> {
        let result = (|| {
            self.require_v2_negotiating()?;

            let offered = match self.receive_v2_hello()? {
                Hello::Client { supported } => supported,
                Hello::Server { .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "expected v2 client hello",
                    ));
                }
            };

            let selected = allowed.select(offered)?;

            self.send(FrameKind::Control, &Hello::Server { selected }.encode())?;

            self.install_padding_profile(selected)?;

            self.advance(ConnectionEvent::VersionAccepted)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        })();

        if result.is_err() {
            self.close();
        }

        result
    }

    fn require_v2_negotiating(&self) -> io::Result<()> {
        if self.state() != ConnectionState::Negotiating {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "v2 negotiation requires the Negotiating state",
            ));
        }

        if self.padding_profile().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "v2 padding profile is already installed",
            ));
        }

        Ok(())
    }

    fn receive_v2_hello(&mut self) -> io::Result<Hello> {
        let frame = self.receive()?.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "peer closed before v2 negotiation completed",
            )
        })?;

        if frame.kind() != FrameKind::Control {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected control frame during v2 negotiation",
            ));
        }

        Hello::decode(frame.body())
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

    #[test]
    fn v2_client_accepts_offered_padding_profile() {
        use crate::negotiation::v2::{Hello, Profile, Profiles};

        let input = control_frame(
            &Hello::Server {
                selected: Profile::Block256,
            }
            .encode(),
        );

        let mut session = negotiating_session(input);

        session.negotiate_v2_as_client(Profiles::BOTH).unwrap();

        assert_eq!(session.state(), ConnectionState::Authenticating);
        assert_eq!(session.padding_profile(), Some(Profile::Block256));
    }

    #[test]
    fn v2_server_selects_padding_when_both_allow_it() {
        use crate::negotiation::v2::{Hello, Profile, Profiles};

        let output = Rc::new(RefCell::new(Vec::new()));

        let mut session = Session::new(TestStream {
            input: Cursor::new(control_frame(
                &Hello::Client {
                    supported: Profiles::BOTH,
                }
                .encode(),
            )),
            output: Rc::clone(&output),
        });

        session.advance(ConnectionEvent::TlsEstablished).unwrap();

        session.negotiate_v2_as_server(Profiles::BOTH).unwrap();

        assert_eq!(session.state(), ConnectionState::Authenticating);
        assert_eq!(session.padding_profile(), Some(Profile::Block256));

        assert_eq!(
            output.borrow().as_slice(),
            control_frame(
                &Hello::Server {
                    selected: Profile::Block256,
                }
                .encode(),
            )
            .as_slice()
        );
    }

    #[test]
    fn v2_client_rejects_unoffered_profile_and_closes() {
        use crate::negotiation::v2::{Hello, Profile, Profiles};

        let input = control_frame(
            &Hello::Server {
                selected: Profile::Unpadded,
            }
            .encode(),
        );

        let mut session = negotiating_session(input);

        assert!(
            session
                .negotiate_v2_as_client(Profiles::PADDED_ONLY)
                .is_err()
        );

        assert_eq!(session.state(), ConnectionState::Closed);
        assert_eq!(session.padding_profile(), None);
    }

    #[test]
    fn v2_server_rejects_no_common_profile_without_replying() {
        use crate::negotiation::v2::{Hello, Profiles};

        let output = Rc::new(RefCell::new(Vec::new()));

        let mut session = Session::new(TestStream {
            input: Cursor::new(control_frame(
                &Hello::Client {
                    supported: Profiles::UNPADDED_ONLY,
                }
                .encode(),
            )),
            output: Rc::clone(&output),
        });

        session.advance(ConnectionEvent::TlsEstablished).unwrap();

        assert!(
            session
                .negotiate_v2_as_server(Profiles::PADDED_ONLY)
                .is_err()
        );

        assert_eq!(session.state(), ConnectionState::Closed);
        assert_eq!(session.padding_profile(), None);
        assert!(output.borrow().is_empty());
    }

    #[test]
    fn closing_session_clears_negotiated_profile() {
        use crate::negotiation::v2::{Hello, Profile, Profiles};

        let mut session = negotiating_session(control_frame(
            &Hello::Server {
                selected: Profile::Block256,
            }
            .encode(),
        ));

        session.negotiate_v2_as_client(Profiles::BOTH).unwrap();

        session.close();

        assert_eq!(session.padding_profile(), None);
        assert_eq!(session.state(), ConnectionState::Closed);
    }

    #[test]
    fn v2_rejects_wrong_peer_role_and_eof() {
        use crate::negotiation::v2::{Hello, Profile, Profiles};

        for client_side in [true, false] {
            let wrong_role = if client_side {
                Hello::Client {
                    supported: Profiles::BOTH,
                }
                .encode()
            } else {
                Hello::Server {
                    selected: Profile::Block256,
                }
                .encode()
            };

            for (input, expected_error) in [
                (control_frame(&wrong_role), io::ErrorKind::InvalidData),
                (Vec::new(), io::ErrorKind::UnexpectedEof),
            ] {
                let mut session = negotiating_session(input);

                let result = if client_side {
                    session.negotiate_v2_as_client(Profiles::BOTH)
                } else {
                    session.negotiate_v2_as_server(Profiles::BOTH)
                };

                assert_eq!(result.unwrap_err().kind(), expected_error);
                assert_eq!(session.state(), ConnectionState::Closed);
                assert_eq!(session.padding_profile(), None);

                assert_eq!(
                    session.receive().unwrap_err().kind(),
                    io::ErrorKind::NotConnected
                );
            }
        }
    }

    #[test]
    fn v2_negotiation_requires_correct_state_and_cannot_repeat() {
        use crate::negotiation::v2::{Hello, Profile, Profiles};

        for client_side in [true, false] {
            // Negotiation before TLS establishment must fail and close.
            let mut before_tls = new_session(Vec::new());

            let result = if client_side {
                before_tls.negotiate_v2_as_client(Profiles::BOTH)
            } else {
                before_tls.negotiate_v2_as_server(Profiles::BOTH)
            };

            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
            assert_eq!(before_tls.state(), ConnectionState::Closed);
            assert_eq!(before_tls.padding_profile(), None);

            // Complete one valid negotiation.
            let peer_hello = if client_side {
                Hello::Server {
                    selected: Profile::Block256,
                }
                .encode()
            } else {
                Hello::Client {
                    supported: Profiles::BOTH,
                }
                .encode()
            };

            let mut session = negotiating_session(control_frame(&peer_hello));

            let result = if client_side {
                session.negotiate_v2_as_client(Profiles::BOTH)
            } else {
                session.negotiate_v2_as_server(Profiles::BOTH)
            };

            result.unwrap();

            assert_eq!(session.state(), ConnectionState::Authenticating);
            assert_eq!(session.padding_profile(), Some(Profile::Block256));

            // Repeating negotiation must close and clear the installed profile.
            let result = if client_side {
                session.negotiate_v2_as_client(Profiles::BOTH)
            } else {
                session.negotiate_v2_as_server(Profiles::BOTH)
            };

            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
            assert_eq!(session.state(), ConnectionState::Closed);
            assert_eq!(session.padding_profile(), None);
        }
    }

    #[test]
    fn v2_malformed_hellos_close_session_and_prevent_reuse() {
        use crate::negotiation::v2::{Hello, Profile, Profiles};

        for client_side in [true, false] {
            let valid = if client_side {
                Hello::Server {
                    selected: Profile::Block256,
                }
                .encode()
            } else {
                Hello::Client {
                    supported: Profiles::BOTH,
                }
                .encode()
            };

            let mut malformed: Vec<Vec<u8>> = Vec::new();

            // Nonempty truncated hellos. An empty body is rejected by
            // outer framing, so it cannot use the control_frame helper.
            for length in 1..valid.len() {
                malformed.push(valid[..length].to_vec());
            }

            let mut trailing = valid.to_vec();
            trailing.push(0);
            malformed.push(trailing);

            let mut wrong_version = valid;
            wrong_version[1..3].copy_from_slice(&1u16.to_be_bytes());
            malformed.push(wrong_version.to_vec());

            let mut unknown_tag = valid;
            unknown_tag[0] = 99;
            malformed.push(unknown_tag.to_vec());

            for bits in [0u16, 4, 0x8000, 0xffff] {
                let mut invalid_profiles = valid;
                invalid_profiles[3..5].copy_from_slice(&bits.to_be_bytes());
                malformed.push(invalid_profiles.to_vec());
            }

            if client_side {
                // A server must select exactly one profile.
                malformed.push(vec![2, 0, 2, 0, 3]);
            }

            for body in malformed {
                let output = Rc::new(RefCell::new(Vec::new()));

                let mut session = Session::new(TestStream {
                    input: Cursor::new(control_frame(&body)),
                    output: Rc::clone(&output),
                });

                session.advance(ConnectionEvent::TlsEstablished).unwrap();

                let result = if client_side {
                    session.negotiate_v2_as_client(Profiles::BOTH)
                } else {
                    session.negotiate_v2_as_server(Profiles::BOTH)
                };

                assert_eq!(
                    result.unwrap_err().kind(),
                    io::ErrorKind::InvalidData,
                    "client_side={client_side}, body={body:?}",
                );

                assert_eq!(session.state(), ConnectionState::Closed);
                assert_eq!(session.padding_profile(), None);

                if client_side {
                    // Only the initial client hello may have been written.
                    assert_eq!(
                        output.borrow().as_slice(),
                        control_frame(
                            &Hello::Client {
                                supported: Profiles::BOTH,
                            }
                            .encode(),
                        )
                        .as_slice(),
                    );
                } else {
                    // A malformed client hello must receive no reply.
                    assert!(output.borrow().is_empty());
                }

                let written_before_retry = output.borrow().len();

                assert_eq!(
                    session.receive().unwrap_err().kind(),
                    io::ErrorKind::NotConnected,
                );

                assert_eq!(
                    session
                        .send(FrameKind::Control, b"retry")
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::NotConnected,
                );

                assert_eq!(output.borrow().len(), written_before_retry);
                assert_eq!(session.padding_profile(), None);
            }
        }
    }
}
