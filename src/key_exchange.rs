use std::io::{self, Read, Write};
use std::time::Duration;

use aws_lc_rs::rand::SecureRandom;

use crate::envelope::MessagePurpose;
use crate::epoch::KeyEpoch;
use crate::frame::FrameKind;
use crate::key_wire::KeyOffer;
use crate::keys::TemporaryKeys;
use crate::padding::PaddingMode;
use crate::phase::PhaseDeadline;
use crate::session::Session;
use crate::state::{ConnectionEvent, ConnectionState};

#[cfg(test)]
use crate::negotiation::v2::Profile;

const CLIENT_CONFIRMATION: &[u8] = b"BRN client key confirmation v1";
const SERVER_CONFIRMATION: &[u8] = b"BRN server key confirmation v1";

impl<S: Read + Write + PhaseDeadline> Session<S> {
    /// Receives application keys through TLS and confirms possession.
    ///
    /// Returns the same epoch used for confirmation, without resetting
    /// its sending or receiving counters.
    pub(crate) fn establish_client_keys(&mut self, budget: Duration) -> io::Result<KeyEpoch> {
        self.run_phase(budget, |session| {
            require_key_establishment(session.state())?;

            // Release the received secret-bearing frame before proceeding.
            let keys = {
                let frame = session
                    .receive()?
                    .ok_or_else(|| unexpected_eof("peer closed before key offer"))?;

                KeyOffer::decode(frame.body())?
            };

            let padding = session
                .padding_profile()
                .map(PaddingMode::from)
                .unwrap_or(PaddingMode::Disabled);

            let mut epoch = KeyEpoch::for_client_with_padding(keys, padding)?;

            session
                .advance(ConnectionEvent::KeyMaterialInstalled)
                .map_err(protocol_error)?;

            let confirmation = epoch.seal(MessagePurpose::KeyConfirmation, CLIENT_CONFIRMATION)?;

            session.send(FrameKind::Encrypted, confirmation.body())?;

            receive_confirmation(session, &mut epoch, SERVER_CONFIRMATION)?;

            session
                .advance(ConnectionEvent::KeysConfirmed)
                .map_err(protocol_error)?;

            Ok(epoch)
        })
    }

    /// Generates application keys, delivers them through TLS, and
    /// confirms possession in both directions.
    ///
    /// Production callers supply the approved AWS-LC RNG.
    pub(crate) fn establish_server_keys(
        &mut self,
        rng: &dyn SecureRandom,
        budget: Duration,
    ) -> io::Result<KeyEpoch> {
        self.run_phase(budget, |session| {
            require_key_establishment(session.state())?;

            let keys = TemporaryKeys::generate(rng)?;
            let offer = KeyOffer::from_keys(&keys);

            let padding = session
                .padding_profile()
                .map(PaddingMode::from)
                .unwrap_or(PaddingMode::Disabled);

            let mut epoch = KeyEpoch::for_server_with_padding(keys, padding)?;

            session.send(FrameKind::Control, offer.body())?;

            // Release BRN's outgoing raw-key buffer promptly.
            drop(offer);

            session
                .advance(ConnectionEvent::KeyMaterialInstalled)
                .map_err(protocol_error)?;

            receive_confirmation(session, &mut epoch, CLIENT_CONFIRMATION)?;

            let confirmation = epoch.seal(MessagePurpose::KeyConfirmation, SERVER_CONFIRMATION)?;

            session.send(FrameKind::Encrypted, confirmation.body())?;

            session
                .advance(ConnectionEvent::KeysConfirmed)
                .map_err(protocol_error)?;

            Ok(epoch)
        })
    }
}

fn receive_confirmation<S: Read + Write>(
    session: &mut Session<S>,
    epoch: &mut KeyEpoch,
    expected_body: &[u8],
) -> io::Result<()> {
    let frame = session
        .receive()?
        .ok_or_else(|| unexpected_eof("peer closed before key confirmation"))?;

    let opened = epoch.open(frame.body(), MessagePurpose::KeyConfirmation)?;

    // These confirmation bodies are public protocol constants.
    if opened.body() != expected_body {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid key-confirmation body",
        ));
    }

    Ok(())
}

fn require_key_establishment(state: ConnectionState) -> io::Result<()> {
    if state != ConnectionState::EstablishingKeys {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "key exchange requires the EstablishingKeys state",
        ));
    }

    Ok(())
}

fn protocol_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

fn unexpected_eof(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, message)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use aws_lc_rs::rand::SystemRandom;

    use super::*;
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

    // These tests exercise exchange logic, not socket deadlines.
    impl PhaseDeadline for TestStream {
        fn start_phase(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }

        fn finish_phase(&mut self) {}
    }

    fn session(input: Vec<u8>) -> Session<TestStream> {
        let mut session = Session::new(TestStream {
            input: Cursor::new(input),
            output: Vec::new(),
        });

        // Simulate completed prerequisite phases for this isolated test.
        for event in [
            ConnectionEvent::TlsEstablished,
            ConnectionEvent::VersionAccepted,
            ConnectionEvent::ClientAuthenticated,
        ] {
            session.advance(event).unwrap();
        }

        session
    }

    fn server_messages(confirmation_body: &[u8], tamper: bool) -> Vec<u8> {
        // Fixed test material only, never production key generation.
        let mut bytes = [0x11; 64];
        bytes[32..].fill(0x22);

        let keys = TemporaryKeys::from_bytes(&bytes).unwrap();
        let offer = KeyOffer::from_keys(&keys);
        let mut server_epoch = KeyEpoch::for_server(keys).unwrap();

        let confirmation = server_epoch
            .seal(MessagePurpose::KeyConfirmation, confirmation_body)
            .unwrap();

        let mut confirmation_bytes = confirmation.body().to_vec();

        if tamper {
            let last = confirmation_bytes.len() - 1;
            confirmation_bytes[last] ^= 1;
        }

        let mut input = Vec::new();

        write_frame(&mut input, FrameKind::Control, offer.body()).unwrap();

        write_frame(&mut input, FrameKind::Encrypted, &confirmation_bytes).unwrap();

        input
    }

    #[test]
    fn client_completes_confirmation_and_preserves_counter() {
        let mut session = session(server_messages(SERVER_CONFIRMATION, false));

        let mut epoch = session
            .establish_client_keys(Duration::from_secs(1))
            .unwrap();

        assert_eq!(session.state(), ConnectionState::Ready);

        let request = epoch
            .seal(MessagePurpose::Request, b"first request")
            .unwrap();

        assert_eq!(request.sequence(), 1);
    }

    #[test]
    fn tampered_confirmation_closes_session() {
        let mut session = session(server_messages(SERVER_CONFIRMATION, true));

        assert!(
            session
                .establish_client_keys(Duration::from_secs(1))
                .is_err()
        );

        assert_eq!(session.state(), ConnectionState::Closed);
    }

    #[test]
    fn authenticated_but_wrong_confirmation_body_is_rejected() {
        let mut session = session(server_messages(b"not the server confirmation", false));

        assert!(
            session
                .establish_client_keys(Duration::from_secs(1))
                .is_err()
        );

        assert_eq!(session.state(), ConnectionState::Closed);
    }

    #[test]
    fn malformed_offer_closes_session() {
        let mut input = Vec::new();

        write_frame(&mut input, FrameKind::Control, b"invalid offer").unwrap();

        let mut session = session(input);

        assert!(
            session
                .establish_client_keys(Duration::from_secs(1))
                .is_err()
        );

        assert_eq!(session.state(), ConnectionState::Closed);
    }

    #[test]
    fn server_closes_if_client_does_not_confirm() {
        let mut session = session(Vec::new());
        let rng = SystemRandom::new();

        let error = session
            .establish_server_keys(&rng, Duration::from_secs(1))
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(session.state(), ConnectionState::Closed);
    }

    #[test]
    fn client_key_establishment_uses_installed_block256_profile() {
        let mut session = Session::new(TestStream {
            input: Cursor::new(server_messages(SERVER_CONFIRMATION, false)),
            output: Vec::new(),
        });

        session.advance(ConnectionEvent::TlsEstablished).unwrap();

        assert_eq!(session.state(), ConnectionState::Negotiating);

        session.install_padding_profile(Profile::Block256).unwrap();

        for event in [
            ConnectionEvent::VersionAccepted,
            ConnectionEvent::ClientAuthenticated,
        ] {
            session.advance(event).unwrap();
        }

        let mut epoch = session
            .establish_client_keys(Duration::from_secs(1))
            .unwrap();

        assert_eq!(session.state(), ConnectionState::Ready);

        let payload = b"first request";
        let request = epoch.seal(MessagePurpose::Request, payload).unwrap();

        assert_eq!(request.sequence(), 1);

        let mut unpadded_session = self::session(server_messages(SERVER_CONFIRMATION, false));

        let mut unpadded_epoch = unpadded_session
            .establish_client_keys(Duration::from_secs(1))
            .unwrap();

        let unpadded_request = unpadded_epoch
            .seal(MessagePurpose::Request, payload)
            .unwrap();

        assert_eq!(unpadded_request.sequence(), 1);

        assert_eq!(
            request.body().len(),
            unpadded_request.body().len() - payload.len() + 256,
            "the returned epoch must encode the small request in a 256-byte bucket",
        );
    }
}

#[cfg(test)]
#[path = "key_adversarial_tests.rs"]
mod adversarial_tests;
