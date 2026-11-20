use std::cell::{Cell, RefCell};
use std::io;
use std::rc::Rc;
use std::time::{Duration, Instant};

use super::PhaseDeadline;
use crate::session::Session;
use crate::state::ConnectionState;

const LONG_BUDGET: Duration = Duration::from_secs(3600);

#[derive(Default)]
struct Observed {
    attempts: Vec<Duration>,
    accepted: Vec<Duration>,
    finishes: usize,
    drops: usize,
    active: bool,
}

struct DeadlineProbe {
    observed: Rc<RefCell<Observed>>,
    start_error: Option<io::ErrorKind>,
}

impl PhaseDeadline for DeadlineProbe {
    fn start_phase(&mut self, budget: Duration) -> io::Result<()> {
        let mut observed = self.observed.borrow_mut();
        observed.attempts.push(budget);
        if let Some(kind) = self.start_error {
            return Err(io::Error::new(kind, "injected deadline start failure"));
        }
        if observed.active {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "phase already active",
            ));
        }
        observed.active = true;
        observed.accepted.push(budget);
        Ok(())
    }

    fn finish_phase(&mut self) {
        let mut observed = self.observed.borrow_mut();
        assert!(observed.active, "cannot finish an inactive phase");
        observed.finishes += 1;
        observed.active = false;
    }
}

impl Drop for DeadlineProbe {
    fn drop(&mut self) {
        self.observed.borrow_mut().drops += 1;
    }
}

fn probe() -> (Session<DeadlineProbe>, Rc<RefCell<Observed>>) {
    let observed = Rc::new(RefCell::new(Observed::default()));
    let session = Session::new(DeadlineProbe {
        observed: Rc::clone(&observed),
        start_error: None,
    });
    (session, observed)
}

fn assert_closed_and_inert(session: &mut Session<DeadlineProbe>, observed: &Rc<RefCell<Observed>>) {
    assert_eq!(session.state(), ConnectionState::Closed);
    assert_eq!(observed.borrow().drops, 1);
    let attempts = observed.borrow().attempts.len();
    let finishes = observed.borrow().finishes;
    let result = session.run_phase(LONG_BUDGET, |_| -> io::Result<()> {
        panic!("closed session must not run callback")
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::NotConnected);
    session.close();
    assert_eq!(observed.borrow().attempts.len(), attempts);
    assert_eq!(observed.borrow().finishes, finishes);
    assert_eq!(observed.borrow().drops, 1);
}

fn wait_past(budget: Duration) {
    let started = Instant::now();
    while started.elapsed() <= budget {
        std::thread::yield_now();
    }
}

#[test]
fn success_passes_budget_returns_value_and_finishes_once() {
    let (mut session, observed) = probe();
    let value = session
        .run_phase(LONG_BUDGET, |_| Ok(String::from("result")))
        .unwrap();
    assert_eq!(value, "result");
    assert_eq!(observed.borrow().attempts, vec![LONG_BUDGET]);
    assert_eq!(observed.borrow().accepted, vec![LONG_BUDGET]);
    assert_eq!(observed.borrow().finishes, 1);
    assert!(!observed.borrow().active);
    assert_eq!(observed.borrow().drops, 0);
    assert_eq!(session.state(), ConnectionState::AwaitingTls);
}

#[test]
fn consecutive_successful_phases_each_start_and_finish() {
    let (mut session, observed) = probe();
    for _ in 0..2 {
        session.run_phase(LONG_BUDGET, |_| Ok(())).unwrap();
    }
    assert_eq!(observed.borrow().attempts, vec![LONG_BUDGET; 2]);
    assert_eq!(observed.borrow().accepted, vec![LONG_BUDGET; 2]);
    assert_eq!(observed.borrow().finishes, 2);
    assert!(!observed.borrow().active);
    assert_eq!(observed.borrow().drops, 0);
}

#[test]
fn zero_budget_never_starts_deadline_or_callback() {
    let (mut session, observed) = probe();
    let error = session
        .run_phase(Duration::ZERO, |_| -> io::Result<()> {
            panic!("zero budget must not run callback")
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert!(observed.borrow().attempts.is_empty());
    assert_eq!(observed.borrow().finishes, 0);
    assert_closed_and_inert(&mut session, &observed);
}

#[test]
fn deadline_start_error_is_preserved_without_running_callback() {
    let observed = Rc::new(RefCell::new(Observed::default()));
    let mut session = Session::new(DeadlineProbe {
        observed: Rc::clone(&observed),
        start_error: Some(io::ErrorKind::PermissionDenied),
    });
    let error = session
        .run_phase(LONG_BUDGET, |_| -> io::Result<()> {
            panic!("failed deadline start must not run callback")
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "injected deadline start failure");
    assert_eq!(observed.borrow().attempts, vec![LONG_BUDGET]);
    assert!(observed.borrow().accepted.is_empty());
    assert_eq!(observed.borrow().finishes, 0);
    assert_closed_and_inert(&mut session, &observed);
}

#[test]
fn callback_error_is_preserved_and_deadline_is_not_finished() {
    let (mut session, observed) = probe();
    let error = session
        .run_phase(LONG_BUDGET, |_| -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "callback marker",
            ))
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "callback marker");
    assert_eq!(observed.borrow().accepted, vec![LONG_BUDGET]);
    assert_eq!(observed.borrow().finishes, 0);
    assert_closed_and_inert(&mut session, &observed);
}

#[test]
fn callback_cannot_close_session_and_report_success() {
    let (mut session, observed) = probe();
    let error = session
        .run_phase(LONG_BUDGET, |session| {
            session.close();
            Ok(42)
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    assert_eq!(observed.borrow().finishes, 0);
    assert_closed_and_inert(&mut session, &observed);
}

#[test]
fn callback_error_after_explicit_close_remains_the_original_error() {
    let (mut session, observed) = probe();
    let error = session
        .run_phase(LONG_BUDGET, |session| -> io::Result<()> {
            session.close();
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "closed callback marker",
            ))
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "closed callback marker");
    assert_eq!(observed.borrow().finishes, 0);
    assert_closed_and_inert(&mut session, &observed);
}

#[test]
fn nested_phase_rejection_closes_without_replacing_accepted_budget() {
    let (mut session, observed) = probe();
    let inner_budget = Duration::from_secs(7200);
    let error = session
        .run_phase(LONG_BUDGET, |session| {
            session.run_phase(inner_budget, |_| -> io::Result<()> {
                panic!("rejected nested phase must not run callback")
            })
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(observed.borrow().attempts, vec![LONG_BUDGET, inner_budget]);
    assert_eq!(observed.borrow().accepted, vec![LONG_BUDGET]);
    assert_eq!(observed.borrow().finishes, 0);
    assert_closed_and_inert(&mut session, &observed);
}

#[test]
fn swallowing_nested_phase_error_cannot_restore_success() {
    let (mut session, observed) = probe();
    let error = session
        .run_phase(LONG_BUDGET, |session| {
            assert!(session.run_phase(LONG_BUDGET, |_| Ok(())).is_err());
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    assert_eq!(observed.borrow().accepted, vec![LONG_BUDGET]);
    assert_eq!(observed.borrow().finishes, 0);
    assert_closed_and_inert(&mut session, &observed);
}

#[test]
fn late_success_times_out_without_finishing_deadline() {
    let (mut session, observed) = probe();
    let budget = Duration::from_millis(2);
    let error = session
        .run_phase(budget, |_| {
            wait_past(budget);
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(observed.borrow().finishes, 0);
    assert_closed_and_inert(&mut session, &observed);
}

#[test]
fn late_callback_error_is_preserved_instead_of_replaced_by_timeout() {
    let (mut session, observed) = probe();
    let budget = Duration::from_millis(2);
    let error = session
        .run_phase(budget, |_| -> io::Result<()> {
            wait_past(budget);
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "late callback marker",
            ))
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "late callback marker");
    assert_eq!(observed.borrow().finishes, 0);
    assert_closed_and_inert(&mut session, &observed);
}

struct ReturnedValue(Rc<Cell<usize>>);

impl Drop for ReturnedValue {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

#[test]
fn value_from_late_success_is_dropped_instead_of_returned() {
    let (mut session, observed) = probe();
    let dropped = Rc::new(Cell::new(0));
    let budget = Duration::from_millis(2);
    let result = session.run_phase(budget, |_| {
        wait_past(budget);
        Ok(ReturnedValue(Rc::clone(&dropped)))
    });
    let error = match result {
        Ok(_) => panic!("late result must not escape the phase"),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(dropped.get(), 1);
    assert_closed_and_inert(&mut session, &observed);
}
