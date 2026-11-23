use std::io::{self, Read, Write};

use crate::frame::FrameKind;
use crate::state::{ConnectionEvent, ConnectionLifecycle, ConnectionState, TransitionError};
use crate::wire::{Frame, read_frame_checked, write_frame};
use std::time::{Duration, Instant};

use crate::negotiation::v2::Profile;
use crate::phase::PhaseDeadline;

/// Owns the stream and enforces connection lifecycle ordering.
///
/// This component does not implement TLS, client authentication,
/// or application-body encryption.
#[derive(Debug)]
pub(crate) struct Session<S> {
    stream: Option<S>,
    lifecycle: ConnectionLifecycle,
    padding_profile: Option<Profile>,
}

impl<S> Session<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            stream: Some(stream),
            lifecycle: ConnectionLifecycle::new(),
            padding_profile: None,
        }
    }

    pub(crate) fn state(&self) -> ConnectionState {
        self.lifecycle.state()
    }

    /// Called by internal protocol code only after an operation succeeds.
    pub(crate) fn advance(&mut self, event: ConnectionEvent) -> Result<(), TransitionError> {
        let result = self.lifecycle.advance(event);

        if self.lifecycle.state() == ConnectionState::Closed {
            self.stream = None;
            self.padding_profile = None;
        }

        result
    }

    pub(crate) fn close(&mut self) {
        self.advance(ConnectionEvent::Close)
            .expect("closing a session must always succeed");
    }

    /// None means no v2 padding profile has been negotiated.
    pub(crate) fn padding_profile(&self) -> Option<Profile> {
        self.padding_profile
    }

    /// Internal negotiation hook, called before VersionAccepted.
    pub(crate) fn install_padding_profile(&mut self, profile: Profile) -> io::Result<()> {
        if self.state() != ConnectionState::Negotiating {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "padding profile requires the Negotiating state",
            ));
        }

        if self.padding_profile.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "padding profile is already installed",
            ));
        }

        self.padding_profile = Some(profile);
        Ok(())
    }
}

impl<S: Read + Write> Session<S> {
    /// Receives one frame after validating its header against policy.
    ///
    /// A returned body remains untrusted until its message-specific
    /// validation or authenticated decryption succeeds.
    pub(crate) fn receive(&mut self) -> io::Result<Option<Frame>> {
        let result = {
            let stream = self.stream.as_mut().ok_or_else(closed_error)?;
            let lifecycle = &mut self.lifecycle;

            read_frame_checked(stream, |header| {
                lifecycle
                    .check_frame_kind(header.kind())
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
            })
        };

        match result {
            Ok(Some(frame)) => Ok(Some(frame)),
            Ok(None) => {
                self.close();
                Ok(None)
            }
            Err(error) => {
                self.close();
                Err(error)
            }
        }
    }

    /// Sends and flushes one frame after checking lifecycle policy.
    ///
    /// The caller must supply the correctly encoded control message
    /// or authenticated-encryption envelope.
    pub(crate) fn send(&mut self, kind: FrameKind, body: &[u8]) -> io::Result<()> {
        let result = (|| {
            let stream = self.stream.as_mut().ok_or_else(closed_error)?;

            self.lifecycle
                .check_frame_kind(kind)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

            write_frame(stream, kind, body)?;
            stream.flush()
        })();

        if result.is_err() {
            self.close();
        }

        result
    }
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "BRN session is closed")
}

impl<S: PhaseDeadline> Session<S> {
    /// Runs one non-nested protocol phase under an absolute deadline.
    ///
    /// Any operation error, invalid budget, or expired deadline closes
    /// the session. Successful completion clears the phase deadline.
    pub(crate) fn run_phase<T>(
        &mut self,
        budget: Duration,
        operation: impl FnOnce(&mut Self) -> io::Result<T>,
    ) -> io::Result<T> {
        let result = (|| {
            if budget.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "phase budget must be greater than zero",
                ));
            }

            let started = Instant::now();

            self.stream
                .as_mut()
                .ok_or_else(closed_error)?
                .start_phase(budget)?;

            let value = operation(self)?;

            if started.elapsed() >= budget {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "protocol phase deadline expired",
                ));
            }

            // A phase must not report success after closing its session.
            self.stream
                .as_mut()
                .ok_or_else(closed_error)?
                .finish_phase();

            Ok(value)
        })();

        if result.is_err() {
            self.close();
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::io::Cursor;
    use std::rc::Rc;

    use super::*;
    use crate::frame::{FrameHeader, HEADER_LEN};

    struct TestStream {
        input: Cursor<Vec<u8>>,
        output: Rc<RefCell<Vec<u8>>>,
        bytes_read: Rc<Cell<usize>>,
        dropped: Rc<Cell<bool>>,
    }

    impl Read for TestStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.input.read(buffer)?;
            self.bytes_read.set(self.bytes_read.get() + count);
            Ok(count)
        }
    }

    impl Write for TestStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.output.borrow_mut().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for TestStream {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }

    fn stream(input: Vec<u8>) -> TestStream {
        TestStream {
            input: Cursor::new(input),
            output: Rc::new(RefCell::new(Vec::new())),
            bytes_read: Rc::new(Cell::new(0)),
            dropped: Rc::new(Cell::new(false)),
        }
    }

    fn encoded(kind: FrameKind, body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, kind, body).unwrap();
        bytes
    }

    #[test]
    fn setup_frames_can_be_received_and_sent_after_tls() {
        let transport = stream(encoded(FrameKind::Control, b"incoming"));
        let output = Rc::clone(&transport.output);
        let mut session = Session::new(transport);

        session.advance(ConnectionEvent::TlsEstablished).unwrap();

        let frame = session.receive().unwrap().unwrap();
        assert_eq!(frame.body(), b"incoming");

        session.send(FrameKind::Control, b"outgoing").unwrap();

        assert_eq!(
            output.borrow().as_slice(),
            encoded(FrameKind::Control, b"outgoing").as_slice()
        );
        assert_eq!(session.state(), ConnectionState::Negotiating);
    }

    #[test]
    fn forbidden_incoming_frame_drops_stream_before_body_read() {
        let transport = stream(encoded(FrameKind::Encrypted, b"forbidden"));
        let bytes_read = Rc::clone(&transport.bytes_read);
        let dropped = Rc::clone(&transport.dropped);
        let mut session = Session::new(transport);

        session.advance(ConnectionEvent::TlsEstablished).unwrap();

        let error = session.receive().unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(bytes_read.get(), HEADER_LEN);
        assert!(dropped.get());
        assert_eq!(session.state(), ConnectionState::Closed);
    }

    #[test]
    fn forbidden_outgoing_frame_writes_nothing_and_drops_stream() {
        let transport = stream(Vec::new());
        let output = Rc::clone(&transport.output);
        let dropped = Rc::clone(&transport.dropped);
        let mut session = Session::new(transport);

        let error = session.send(FrameKind::Control, b"too early").unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(output.borrow().is_empty());
        assert!(dropped.get());
        assert_eq!(session.state(), ConnectionState::Closed);
    }

    #[test]
    fn truncated_frame_drops_stream() {
        let bytes = FrameHeader::new(FrameKind::Control, 10)
            .unwrap()
            .encode()
            .to_vec();

        let transport = stream(bytes);
        let dropped = Rc::clone(&transport.dropped);
        let mut session = Session::new(transport);

        session.advance(ConnectionEvent::TlsEstablished).unwrap();

        let error = session.receive().unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        assert!(dropped.get());
        assert_eq!(session.state(), ConnectionState::Closed);
    }

    #[test]
    fn eof_closes_session_and_prevents_further_io() {
        let transport = stream(Vec::new());
        let dropped = Rc::clone(&transport.dropped);
        let mut session = Session::new(transport);

        session.advance(ConnectionEvent::TlsEstablished).unwrap();

        assert!(session.receive().unwrap().is_none());
        assert!(dropped.get());
        assert_eq!(session.state(), ConnectionState::Closed);

        assert_eq!(
            session.receive().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );

        assert_eq!(
            session
                .send(FrameKind::Control, b"late")
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
    }

    #[test]
    fn invalid_transition_drops_stream_and_cannot_restart() {
        let transport = stream(Vec::new());
        let dropped = Rc::clone(&transport.dropped);
        let mut session = Session::new(transport);

        assert!(session.advance(ConnectionEvent::KeysConfirmed).is_err());

        assert!(dropped.get());
        assert_eq!(session.state(), ConnectionState::Closed);

        assert!(session.advance(ConnectionEvent::TlsEstablished).is_err());

        session.close();
        assert_eq!(session.state(), ConnectionState::Closed);
    }

    #[test]
    fn invalid_incoming_body_lengths_close_before_body_read() {
        use crate::frame::MAX_BODY_LEN;

        let events = [
            ConnectionEvent::TlsEstablished,
            ConnectionEvent::VersionAccepted,
            ConnectionEvent::ClientAuthenticated,
            ConnectionEvent::KeyMaterialInstalled,
            ConnectionEvent::KeysConfirmed,
        ];

        // Use a permitted frame kind for each lifecycle state so
        // rejection is caused by the length, not frame-kind policy.
        for (completed_events, kind) in [
            (1, FrameKind::Control),
            (2, FrameKind::Control),
            (3, FrameKind::Control),
            (4, FrameKind::Encrypted),
            (5, FrameKind::Encrypted),
        ] {
            for declared_length in [0, MAX_BODY_LEN + 1, u32::MAX] {
                // Start with a valid header, then corrupt its length.
                // FrameHeader::new correctly refuses these lengths.
                let mut header = FrameHeader::new(kind, 1).unwrap().encode();

                header[5..9].copy_from_slice(&declared_length.to_be_bytes());

                let mut input = header.to_vec();

                // If receive reads beyond the header, the byte counter
                // will detect it. No large body allocation is needed
                // to construct this malformed input.
                input.extend_from_slice(b"must not be read");

                let transport = stream(input);
                let bytes_read = Rc::clone(&transport.bytes_read);
                let dropped = Rc::clone(&transport.dropped);
                let mut session = Session::new(transport);

                for event in events.iter().take(completed_events) {
                    session.advance(*event).unwrap();
                }

                let error = session.receive().unwrap_err();

                assert_eq!(
                    error.kind(),
                    io::ErrorKind::InvalidData,
                    "declared length: {declared_length}, \
                     completed events: {completed_events}"
                );

                assert_eq!(bytes_read.get(), HEADER_LEN);
                assert!(dropped.get());
                assert_eq!(session.state(), ConnectionState::Closed);

                assert_eq!(
                    session.receive().unwrap_err().kind(),
                    io::ErrorKind::NotConnected
                );

                assert_eq!(bytes_read.get(), HEADER_LEN);
            }
        }
    }

    #[test]
    fn oversized_outgoing_frame_writes_nothing_and_closes() {
        use crate::frame::MAX_BODY_LEN;

        let transport = stream(Vec::new());
        let output = Rc::clone(&transport.output);
        let dropped = Rc::clone(&transport.dropped);
        let mut session = Session::new(transport);

        for event in [
            ConnectionEvent::TlsEstablished,
            ConnectionEvent::VersionAccepted,
            ConnectionEvent::ClientAuthenticated,
            ConnectionEvent::KeyMaterialInstalled,
            ConnectionEvent::KeysConfirmed,
        ] {
            session.advance(event).unwrap();
        }

        let oversized = vec![0; MAX_BODY_LEN as usize + 1];

        assert!(session.send(FrameKind::Encrypted, &oversized).is_err());

        assert!(output.borrow().is_empty());
        assert!(dropped.get());
        assert_eq!(session.state(), ConnectionState::Closed);

        assert_eq!(
            session
                .send(FrameKind::Encrypted, b"retry")
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );

        assert!(output.borrow().is_empty());
    }

    // Test-only lifecycle setup. This does not perform a handshake,
    // authenticate a client, or establish actual application keys.
    fn advance_to_ready(session: &mut Session<TestStream>) {
        for event in [
            ConnectionEvent::TlsEstablished,
            ConnectionEvent::VersionAccepted,
            ConnectionEvent::ClientAuthenticated,
            ConnectionEvent::KeyMaterialInstalled,
            ConnectionEvent::KeysConfirmed,
        ] {
            session.advance(event).unwrap();
        }

        assert_eq!(session.state(), ConnectionState::Ready);
    }

    #[test]
    fn ready_rejects_control_frame_before_reading_body() {
        let transport = stream(encoded(
            FrameKind::Control,
            b"forbidden application-phase control message",
        ));

        let bytes_read = Rc::clone(&transport.bytes_read);
        let dropped = Rc::clone(&transport.dropped);
        let mut session = Session::new(transport);

        advance_to_ready(&mut session);

        let error = session.receive().unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(bytes_read.get(), HEADER_LEN);
        assert!(dropped.get());
        assert_eq!(session.state(), ConnectionState::Closed);

        // Rejection must leave the connection permanently unusable.
        assert_eq!(
            session.receive().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );

        assert_eq!(
            session
                .send(FrameKind::Encrypted, b"late")
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );

        assert_eq!(bytes_read.get(), HEADER_LEN);
    }

    #[test]
    fn ready_rejects_outgoing_control_frame_without_writing() {
        let transport = stream(Vec::new());

        let output = Rc::clone(&transport.output);
        let dropped = Rc::clone(&transport.dropped);
        let mut session = Session::new(transport);

        advance_to_ready(&mut session);

        let error = session.send(FrameKind::Control, b"forbidden").unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(output.borrow().is_empty());
        assert!(dropped.get());
        assert_eq!(session.state(), ConnectionState::Closed);

        assert_eq!(
            session
                .send(FrameKind::Encrypted, b"late")
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );

        assert!(output.borrow().is_empty());
    }

    #[test]
    fn ready_allows_encrypted_frame_kind_in_both_directions() {
        // These are intentionally not valid encrypted envelopes.
        // This test covers outer framing policy only. KeyEpoch
        // remains responsible for authenticating envelope contents.
        let transport = stream(encoded(
            FrameKind::Encrypted,
            b"incoming envelope placeholder",
        ));

        let output = Rc::clone(&transport.output);
        let dropped = Rc::clone(&transport.dropped);
        let mut session = Session::new(transport);

        advance_to_ready(&mut session);

        let frame = session.receive().unwrap().unwrap();

        assert_eq!(frame.body(), b"incoming envelope placeholder");

        session
            .send(FrameKind::Encrypted, b"outgoing envelope placeholder")
            .unwrap();

        assert_eq!(
            output.borrow().as_slice(),
            encoded(FrameKind::Encrypted, b"outgoing envelope placeholder",).as_slice()
        );

        assert!(!dropped.get());
        assert_eq!(session.state(), ConnectionState::Ready);
    }

    #[test]
    fn padding_profile_requires_negotiating_state_and_single_installation() {
        let mut session = Session::new(stream(Vec::new()));

        assert_eq!(session.padding_profile(), None);

        // Installation before negotiation must fail without installing a profile.
        let error = session
            .install_padding_profile(Profile::Block256)
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(session.padding_profile(), None);

        session.advance(ConnectionEvent::TlsEstablished).unwrap();

        session.install_padding_profile(Profile::Block256).unwrap();

        assert_eq!(session.padding_profile(), Some(Profile::Block256));

        // A duplicate installation must not replace the original selection.
        let error = session
            .install_padding_profile(Profile::Unpadded)
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(session.padding_profile(), Some(Profile::Block256));

        for event in [
            ConnectionEvent::VersionAccepted,
            ConnectionEvent::ClientAuthenticated,
            ConnectionEvent::KeyMaterialInstalled,
            ConnectionEvent::KeysConfirmed,
        ] {
            session.advance(event).unwrap();

            assert_eq!(session.padding_profile(), Some(Profile::Block256));

            // Installation must also fail after negotiation has completed.
            let error = session
                .install_padding_profile(Profile::Unpadded)
                .unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(session.padding_profile(), Some(Profile::Block256));
        }

        assert_eq!(session.state(), ConnectionState::Ready);
    }

    #[test]
    fn padding_profile_is_cleared_on_explicit_close() {
        for profile in [Profile::Unpadded, Profile::Block256] {
            let transport = stream(Vec::new());
            let dropped = Rc::clone(&transport.dropped);
            let mut session = Session::new(transport);

            session.advance(ConnectionEvent::TlsEstablished).unwrap();
            session.install_padding_profile(profile).unwrap();

            assert_eq!(session.padding_profile(), Some(profile));

            session.close();

            assert_eq!(session.state(), ConnectionState::Closed);
            assert_eq!(session.padding_profile(), None);
            assert!(dropped.get());

            // Closing again must remain harmless.
            session.close();

            assert_eq!(session.state(), ConnectionState::Closed);
            assert_eq!(session.padding_profile(), None);

            let error = session.install_padding_profile(profile).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(session.padding_profile(), None);
        }
    }

    #[test]
    fn padding_profile_is_cleared_on_invalid_transition() {
        for profile in [Profile::Unpadded, Profile::Block256] {
            let transport = stream(Vec::new());
            let dropped = Rc::clone(&transport.dropped);
            let mut session = Session::new(transport);

            session.advance(ConnectionEvent::TlsEstablished).unwrap();
            session.install_padding_profile(profile).unwrap();

            // KeysConfirmed is invalid while still negotiating.
            assert!(session.advance(ConnectionEvent::KeysConfirmed).is_err());

            assert_eq!(session.state(), ConnectionState::Closed);
            assert_eq!(session.padding_profile(), None);
            assert!(dropped.get());

            // An attempted restart must not restore the profile.
            assert!(session.advance(ConnectionEvent::TlsEstablished).is_err());

            assert_eq!(session.state(), ConnectionState::Closed);
            assert_eq!(session.padding_profile(), None);
        }
    }
}

#[cfg(test)]
#[path = "session_adversarial_tests.rs"]
mod adversarial_tests;
