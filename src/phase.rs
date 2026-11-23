use std::io::{self, Read, Write};
use std::time::Duration;

use rustls::{ClientConnection, ServerConnection, StreamOwned};

use crate::negotiation::v2::Profiles;
use crate::session::Session;
use crate::transport::DeadlineTcpStream;

/// Internal support for applying deadlines to protocol phases.
pub(crate) trait PhaseDeadline {
    fn start_phase(&mut self, budget: Duration) -> io::Result<()>;
    fn finish_phase(&mut self);
}

impl PhaseDeadline for StreamOwned<ClientConnection, DeadlineTcpStream> {
    fn start_phase(&mut self, budget: Duration) -> io::Result<()> {
        self.sock.start_deadline(budget)
    }

    fn finish_phase(&mut self) {
        self.sock.clear_deadline();
    }
}

impl PhaseDeadline for StreamOwned<ServerConnection, DeadlineTcpStream> {
    fn start_phase(&mut self, budget: Duration) -> io::Result<()> {
        self.sock.start_deadline(budget)
    }

    fn finish_phase(&mut self) {
        self.sock.clear_deadline();
    }
}

impl<S: Read + Write + PhaseDeadline> Session<S> {
    pub(crate) fn negotiate_client_with_deadline(&mut self, budget: Duration) -> io::Result<()> {
        self.run_phase(budget, |session| session.negotiate_as_client())
    }

    pub(crate) fn negotiate_server_with_deadline(&mut self, budget: Duration) -> io::Result<()> {
        self.run_phase(budget, |session| session.negotiate_as_server())
    }

    pub(crate) fn negotiate_v2_client_with_deadline(
        &mut self,
        supported: Profiles,
        budget: Duration,
    ) -> io::Result<()> {
        self.run_phase(budget, |session| session.negotiate_v2_as_client(supported))
    }

    pub(crate) fn negotiate_v2_server_with_deadline(
        &mut self,
        allowed: Profiles,
        budget: Duration,
    ) -> io::Result<()> {
        self.run_phase(budget, |session| session.negotiate_v2_as_server(allowed))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::state::ConnectionState;

    // These tests exercise phase orchestration without real sockets.
    // Deadline arithmetic is tested separately in transport.rs.
    impl PhaseDeadline for Cursor<Vec<u8>> {
        fn start_phase(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }

        fn finish_phase(&mut self) {}
    }

    #[test]
    fn successful_phase_preserves_session() {
        let mut session = Session::new(Cursor::new(Vec::new()));

        let result = session
            .run_phase(Duration::from_secs(1), |_| Ok(42))
            .unwrap();

        assert_eq!(result, 42);
        assert_eq!(session.state(), ConnectionState::AwaitingTls);
    }

    #[test]
    fn phase_error_closes_session() {
        let mut session = Session::new(Cursor::new(Vec::new()));

        let result: io::Result<()> = session.run_phase(Duration::from_secs(1), |_| {
            Err(io::Error::new(io::ErrorKind::InvalidData, "phase failed"))
        });

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(session.state(), ConnectionState::Closed);
    }

    #[test]
    fn zero_budget_closes_without_running_operation() {
        let mut session = Session::new(Cursor::new(Vec::new()));
        let mut ran = false;

        let result = session.run_phase(Duration::ZERO, |_| {
            ran = true;
            Ok(())
        });

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(!ran);
        assert_eq!(session.state(), ConnectionState::Closed);
    }
}

#[cfg(test)]
#[path = "phase_adversarial_tests.rs"]
mod adversarial_tests;
