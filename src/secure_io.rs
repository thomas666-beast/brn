use std::io;
use std::time::Duration;

use crate::epoch::KeyEpoch;
use crate::phase::PhaseDeadline;
use crate::session::Session;

/// Runs one non-nested application operation under both the requested
/// timeout and the remaining application-key lifetime.
///
/// Any returned error closes the session and disables the epoch.
///
/// This does not manage application request/response turns. The public
/// connection operation must close its Exchange on error as well.
pub(crate) fn run_encrypted_phase<S, T>(
    session: &mut Session<S>,
    epoch: &mut KeyEpoch,
    requested_budget: Duration,
    operation: impl FnOnce(&mut Session<S>, &mut KeyEpoch) -> io::Result<T>,
) -> io::Result<T>
where
    S: PhaseDeadline,
{
    let result = (|| {
        let budget = epoch.operation_budget(requested_budget)?;

        session.run_phase(budget, |session| {
            let value = operation(session, epoch)?;

            // Never return a successful application result after expiry.
            epoch.verify_live()?;

            Ok(value)
        })
    })();

    if result.is_err() {
        session.close();
        epoch.disable();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::keys::TemporaryKeys;
    use crate::state::ConnectionState;

    // No actual I/O is performed in these orchestration tests.
    struct TestTransport;

    impl PhaseDeadline for TestTransport {
        fn start_phase(&mut self, _: Duration) -> io::Result<()> {
            Ok(())
        }

        fn finish_phase(&mut self) {}
    }

    fn epoch() -> KeyEpoch {
        let mut bytes = [0x11; 64];
        bytes[32..].fill(0x22);

        KeyEpoch::for_client(TemporaryKeys::from_bytes(&bytes).unwrap()).unwrap()
    }

    #[test]
    fn successful_operation_returns_value_and_preserves_epoch() {
        let mut session = Session::new(TestTransport);
        let mut epoch = epoch();

        let value =
            run_encrypted_phase(&mut session, &mut epoch, Duration::from_secs(1), |_, _| {
                Ok(42)
            })
            .unwrap();

        assert_eq!(value, 42);
        assert!(epoch.verify_live().is_ok());
        assert_eq!(session.state(), ConnectionState::AwaitingTls);
    }

    #[test]
    fn operation_error_closes_session_and_disables_epoch() {
        let mut session = Session::new(TestTransport);
        let mut epoch = epoch();

        let result: io::Result<()> =
            run_encrypted_phase(&mut session, &mut epoch, Duration::from_secs(1), |_, _| {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "test operation failed",
                ))
            });

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(session.state(), ConnectionState::Closed);
        assert!(epoch.verify_live().is_err());
    }

    #[test]
    fn invalid_budget_closes_without_running_operation() {
        let mut session = Session::new(TestTransport);
        let mut epoch = epoch();
        let mut ran = false;

        let result = run_encrypted_phase(&mut session, &mut epoch, Duration::ZERO, |_, _| {
            ran = true;
            Ok(())
        });

        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(!ran);
        assert_eq!(session.state(), ConnectionState::Closed);
        assert!(epoch.verify_live().is_err());
    }
}

#[cfg(test)]
#[path = "secure_io_adversarial_tests.rs"]
mod adversarial_tests;
