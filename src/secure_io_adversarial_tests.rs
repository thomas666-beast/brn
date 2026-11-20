use std::cell::{Cell, RefCell};
use std::io;
use std::rc::Rc;
use std::time::{Duration, Instant};

use super::run_encrypted_phase;
use crate::envelope::MessagePurpose;
use crate::epoch::{KEY_LIFETIME, KeyEpoch};
use crate::keys::TemporaryKeys;
use crate::phase::PhaseDeadline;
use crate::session::Session;
use crate::state::ConnectionState;

const BUDGET: Duration = Duration::from_secs(3600);

#[derive(Default)]
struct Observed {
    budgets: Vec<Duration>,
    finishes: usize,
    drops: usize,
    active: bool,
}

struct Probe {
    observed: Rc<RefCell<Observed>>,
    fail_start: bool,
}

impl PhaseDeadline for Probe {
    fn start_phase(&mut self, budget: Duration) -> io::Result<()> {
        let mut observed = self.observed.borrow_mut();
        observed.budgets.push(budget);
        if self.fail_start {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "deadline start marker",
            ));
        }
        if observed.active {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nested deadline",
            ));
        }
        observed.active = true;
        Ok(())
    }
    fn finish_phase(&mut self) {
        let mut observed = self.observed.borrow_mut();
        assert!(observed.active);
        observed.active = false;
        observed.finishes += 1;
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.observed.borrow_mut().drops += 1;
    }
}

fn material() -> TemporaryKeys {
    // Fixed test material only.
    let mut bytes = [0x11; 64];
    bytes[32..].fill(0x22);
    TemporaryKeys::from_bytes(&bytes).unwrap()
}

fn fixture(fail_start: bool) -> (Session<Probe>, KeyEpoch, Rc<RefCell<Observed>>) {
    let observed = Rc::new(RefCell::new(Observed::default()));
    let session = Session::new(Probe {
        observed: Rc::clone(&observed),
        fail_start,
    });
    (session, KeyEpoch::for_client(material()).unwrap(), observed)
}

fn assert_terminal(
    session: &mut Session<Probe>,
    epoch: &mut KeyEpoch,
    observed: &Rc<RefCell<Observed>>,
) {
    assert_eq!(session.state(), ConnectionState::Closed);
    assert_eq!(observed.borrow().drops, 1);
    assert!(epoch.verify_live().is_err());
    assert!(epoch.seal(MessagePurpose::Request, b"later").is_err());
    assert!(epoch.open(b"invalid", MessagePurpose::Response).is_err());
    let starts = observed.borrow().budgets.len();
    let finishes = observed.borrow().finishes;
    let result = run_encrypted_phase(session, epoch, BUDGET, |_, _| -> io::Result<()> {
        panic!("terminal operation must not run callback")
    });
    assert!(result.is_err());
    assert_eq!(observed.borrow().budgets.len(), starts);
    assert_eq!(observed.borrow().finishes, finishes);
    assert_eq!(observed.borrow().drops, 1);
}

#[derive(Debug)]
struct ReturnedValue(Rc<Cell<usize>>);
impl Drop for ReturnedValue {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

#[test]
fn requested_budget_is_capped_before_transport_deadline_start() {
    let (mut session, mut epoch, observed) = fixture(false);
    let value = run_encrypted_phase(&mut session, &mut epoch, BUDGET, |_, _| Ok(42)).unwrap();
    assert_eq!(value, 42);
    let observed = observed.borrow();
    assert_eq!(observed.budgets.len(), 1);
    assert!(!observed.budgets[0].is_zero());
    assert!(observed.budgets[0] <= KEY_LIFETIME);
    assert!(observed.budgets[0] < BUDGET);
    assert_eq!(observed.finishes, 1);
    assert_eq!(observed.drops, 0);
    assert!(!observed.active);
    assert!(epoch.verify_live().is_ok());
}

#[test]
fn deadline_start_failure_preserves_error_and_disables_both_layers() {
    let (mut session, mut epoch, observed) = fixture(true);
    let error = run_encrypted_phase(&mut session, &mut epoch, BUDGET, |_, _| -> io::Result<()> {
        panic!("failed start must not run callback")
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "deadline start marker");
    assert_eq!(observed.borrow().finishes, 0);
    assert_terminal(&mut session, &mut epoch, &observed);
}

#[test]
fn disabled_epoch_closes_session_before_start_or_callback() {
    let (mut session, mut epoch, observed) = fixture(false);
    epoch.disable();
    let result = run_encrypted_phase(&mut session, &mut epoch, BUDGET, |_, _| -> io::Result<()> {
        panic!("disabled epoch must not run callback")
    });
    assert!(result.is_err());
    assert!(observed.borrow().budgets.is_empty());
    assert_terminal(&mut session, &mut epoch, &observed);
}

#[test]
fn already_closed_session_disables_otherwise_live_epoch() {
    let (mut session, mut epoch, observed) = fixture(false);
    session.close();
    assert!(epoch.verify_live().is_ok());
    let error = run_encrypted_phase(&mut session, &mut epoch, BUDGET, |_, _| -> io::Result<()> {
        panic!("closed session must not run callback")
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    assert!(observed.borrow().budgets.is_empty());
    assert_terminal(&mut session, &mut epoch, &observed);
}

#[test]
fn callback_cannot_disable_epoch_and_return_successful_value() {
    let (mut session, mut epoch, observed) = fixture(false);
    let drops = Rc::new(Cell::new(0));
    let error = run_encrypted_phase(&mut session, &mut epoch, BUDGET, |_, epoch| {
        epoch.disable();
        Ok(ReturnedValue(Rc::clone(&drops)))
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert_eq!(drops.get(), 1);
    assert_eq!(observed.borrow().finishes, 0);
    assert_terminal(&mut session, &mut epoch, &observed);
}

#[test]
fn callback_cannot_close_session_and_return_successful_value() {
    let (mut session, mut epoch, observed) = fixture(false);
    let drops = Rc::new(Cell::new(0));
    let error = run_encrypted_phase(&mut session, &mut epoch, BUDGET, |session, _| {
        session.close();
        Ok(ReturnedValue(Rc::clone(&drops)))
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    assert_eq!(drops.get(), 1);
    assert_eq!(observed.borrow().finishes, 0);
    assert_terminal(&mut session, &mut epoch, &observed);
}

#[test]
fn phase_timeout_drops_late_value_and_disables_epoch() {
    let (mut session, mut epoch, observed) = fixture(false);
    let drops = Rc::new(Cell::new(0));
    let budget = Duration::from_millis(2);
    let error = run_encrypted_phase(&mut session, &mut epoch, budget, |_, _| {
        let started = Instant::now();
        while started.elapsed() <= budget {
            std::thread::yield_now();
        }
        Ok(ReturnedValue(Rc::clone(&drops)))
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(drops.get(), 1);
    assert_eq!(observed.borrow().finishes, 0);
    assert_terminal(&mut session, &mut epoch, &observed);
}

#[test]
fn callback_error_is_preserved_even_after_it_disables_both_layers() {
    let (mut session, mut epoch, observed) = fixture(false);
    let error = run_encrypted_phase(
        &mut session,
        &mut epoch,
        BUDGET,
        |session, epoch| -> io::Result<()> {
            session.close();
            epoch.disable();
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "operation marker",
            ))
        },
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "operation marker");
    assert_eq!(observed.borrow().finishes, 0);
    assert_terminal(&mut session, &mut epoch, &observed);
}

#[test]
fn rejected_nested_encrypted_phase_disables_both_layers() {
    let (mut session, mut epoch, observed) = fixture(false);
    let error = run_encrypted_phase(&mut session, &mut epoch, BUDGET, |session, epoch| {
        run_encrypted_phase(session, epoch, BUDGET, |_, _| -> io::Result<()> {
            panic!("nested phase callback must not run")
        })
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(observed.borrow().budgets.len(), 2);
    assert_eq!(observed.borrow().finishes, 0);
    assert_terminal(&mut session, &mut epoch, &observed);
}

#[test]
fn repeated_successful_phases_preserve_crypto_counter_continuity() {
    let (mut session, mut client, observed) = fixture(false);
    let mut server = KeyEpoch::for_server(material()).unwrap();
    for expected in 0..3 {
        let value = run_encrypted_phase(&mut session, &mut client, BUDGET, |_, client| {
            let request = client.seal(MessagePurpose::Request, b"request")?;
            assert_eq!(request.sequence(), expected);
            assert_eq!(
                server.open(request.body(), MessagePurpose::Request)?.body(),
                b"request"
            );
            let response = server.seal(MessagePurpose::Response, b"response")?;
            assert_eq!(response.sequence(), expected);
            Ok(client
                .open(response.body(), MessagePurpose::Response)?
                .body()
                .to_vec())
        })
        .unwrap();
        assert_eq!(value, b"response");
    }
    assert_eq!(observed.borrow().budgets.len(), 3);
    assert_eq!(observed.borrow().finishes, 3);
    assert_eq!(observed.borrow().drops, 0);
    assert!(client.verify_live().is_ok());
    assert!(server.verify_live().is_ok());
}
