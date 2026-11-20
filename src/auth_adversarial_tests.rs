use std::cell::RefCell;
use std::io::{self, Cursor, Read, Write};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::*;
use crate::auth::AuthenticationError;
use crate::auth_wire::{AuthenticationWireError, MAX_CREDENTIAL_BYTES};
use crate::wire::write_frame;

const BUDGET: Duration = Duration::from_secs(3600);
const CREDENTIALS: &[u8] = b"test-credential";

#[derive(Default)]
struct Observed {
    reads: usize,
    writes: usize,
    output: Vec<u8>,
    flushes: usize,
    starts: usize,
    finishes: usize,
    drops: usize,
}

struct ProbeStream {
    input: Cursor<Vec<u8>>,
    observed: Rc<RefCell<Observed>>,
    write_error: bool,
    flush_error: bool,
}

impl Read for ProbeStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.observed.borrow_mut().reads += 1;
        self.input.read(bytes)
    }
}

impl Write for ProbeStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut observed = self.observed.borrow_mut();
        observed.writes += 1;
        if self.write_error {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        observed.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.observed.borrow_mut().flushes += 1;
        if self.flush_error {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        } else {
            Ok(())
        }
    }
}

impl PhaseDeadline for ProbeStream {
    fn start_phase(&mut self, _: Duration) -> io::Result<()> {
        self.observed.borrow_mut().starts += 1;
        Ok(())
    }

    fn finish_phase(&mut self) {
        self.observed.borrow_mut().finishes += 1;
    }
}

impl Drop for ProbeStream {
    fn drop(&mut self) {
        self.observed.borrow_mut().drops += 1;
    }
}

fn framed(body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_frame(&mut bytes, FrameKind::Control, body).unwrap();
    bytes
}

fn request(credentials: &[u8]) -> Vec<u8> {
    let encoded = AuthenticationRequest::new(credentials).unwrap().encode();
    framed(encoded.as_slice())
}

fn probe(input: Vec<u8>) -> (ProbeStream, Rc<RefCell<Observed>>) {
    let observed = Rc::new(RefCell::new(Observed::default()));
    (
        ProbeStream {
            input: Cursor::new(input),
            observed: Rc::clone(&observed),
            write_error: false,
            flush_error: false,
        },
        observed,
    )
}

fn session_at(stream: ProbeStream, count: usize) -> Session<ProbeStream> {
    let mut session = Session::new(stream);
    for event in [
        ConnectionEvent::TlsEstablished,
        ConnectionEvent::VersionAccepted,
        ConnectionEvent::ClientAuthenticated,
        ConnectionEvent::KeyMaterialInstalled,
        ConnectionEvent::KeysConfirmed,
    ]
    .into_iter()
    .take(count)
    {
        session.advance(event).unwrap();
    }
    session
}

#[derive(Clone, Copy)]
enum Outcome {
    Accept,
    Reject,
    Unavailable,
}

struct Verifier {
    calls: AtomicUsize,
    outcome: Outcome,
    delay: Duration,
    expected: Vec<u8>,
}

impl Verifier {
    fn new(outcome: Outcome) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            outcome,
            delay: Duration::ZERO,
            expected: CREDENTIALS.to_vec(),
        }
    }
}

impl Authenticator for Verifier {
    fn authenticate(&self, credentials: &[u8]) -> Result<ClientIdentity, AuthenticationError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        assert_eq!(credentials, self.expected.as_slice());
        let started = Instant::now();
        while started.elapsed() < self.delay {
            std::thread::yield_now();
        }
        match self.outcome {
            Outcome::Accept => {
                ClientIdentity::new("verified-client").map_err(|_| AuthenticationError::Unavailable)
            }
            Outcome::Reject => Err(AuthenticationError::Rejected),
            Outcome::Unavailable => Err(AuthenticationError::Unavailable),
        }
    }
}

fn assert_closed(session: &mut Session<ProbeStream>, observed: &Rc<RefCell<Observed>>) {
    assert_eq!(session.state(), ConnectionState::Closed);
    assert_eq!(observed.borrow().drops, 1);
    assert_eq!(observed.borrow().finishes, 0);
    let before = {
        let o = observed.borrow();
        (o.reads, o.writes, o.flushes, o.starts, o.output.len())
    };
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
    assert_eq!(
        session
            .authenticate_client(CREDENTIALS, BUDGET)
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
    let verifier = Verifier::new(Outcome::Accept);
    assert_eq!(
        session
            .authenticate_server(&verifier, BUDGET)
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 0);
    let o = observed.borrow();
    assert_eq!(
        (o.reads, o.writes, o.flushes, o.starts, o.output.len()),
        before
    );
    assert_eq!(o.drops, 1);
}

#[test]
fn client_rejects_every_unknown_reply_tag_and_trailing_bytes() {
    let accepted = AuthenticationReply::Accepted.encode()[0];
    let rejected = AuthenticationReply::Rejected.encode()[0];
    let mut bodies: Vec<Vec<u8>> = (0..=u8::MAX)
        .filter(|tag| *tag != accepted && *tag != rejected)
        .map(|tag| vec![tag])
        .collect();
    bodies.extend([vec![accepted, 0], vec![rejected, 0]]);
    for body in bodies {
        let (stream, observed) = probe(framed(&body));
        let mut session = session_at(stream, 2);
        assert_eq!(
            session
                .authenticate_client(CREDENTIALS, BUDGET)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(observed.borrow().output, request(CREDENTIALS));
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn client_invalid_credentials_close_before_any_io() {
    for credentials in [Vec::new(), vec![0; MAX_CREDENTIAL_BYTES + 1]] {
        let (stream, observed) = probe(framed(&AuthenticationReply::Accepted.encode()));
        let mut session = session_at(stream, 2);
        assert_eq!(
            session
                .authenticate_client(&credentials, BUDGET)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(observed.borrow().reads, 0);
        assert_eq!(observed.borrow().writes, 0);
        assert_eq!(observed.borrow().flushes, 0);
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn client_eof_and_every_truncated_reply_close() {
    let bytes = framed(&AuthenticationReply::Accepted.encode());
    for offset in 0..bytes.len() {
        let (stream, observed) = probe(bytes[..offset].to_vec());
        let mut session = session_at(stream, 2);
        assert_eq!(
            session
                .authenticate_client(CREDENTIALS, BUDGET)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(observed.borrow().output, request(CREDENTIALS));
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn server_eof_and_every_truncated_request_skip_verifier_and_reply() {
    let bytes = request(CREDENTIALS);
    for offset in 0..bytes.len() {
        let (stream, observed) = probe(bytes[..offset].to_vec());
        let mut session = session_at(stream, 2);
        let verifier = Verifier::new(Outcome::Accept);
        assert_eq!(
            session
                .authenticate_server(&verifier, BUDGET)
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(verifier.calls.load(Ordering::Relaxed), 0);
        assert!(observed.borrow().output.is_empty());
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn malformed_requests_skip_verifier_and_reply() {
    let tag = AuthenticationRequest::new(CREDENTIALS).unwrap().encode()[0];
    let mut bodies: Vec<Vec<u8>> = (0..=u8::MAX)
        .filter(|value| *value != tag)
        .map(|value| vec![value, 42])
        .collect();
    bodies.push(vec![tag]);
    let mut oversized = vec![tag];
    oversized.extend(vec![0; MAX_CREDENTIAL_BYTES + 1]);
    bodies.push(oversized);
    for body in bodies {
        let (stream, observed) = probe(framed(&body));
        let mut session = session_at(stream, 2);
        let verifier = Verifier::new(Outcome::Accept);
        assert_eq!(
            session
                .authenticate_server(&verifier, BUDGET)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(verifier.calls.load(Ordering::Relaxed), 0);
        assert!(observed.borrow().output.is_empty());
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn both_roles_reject_wrong_lifecycle_states_without_io() {
    for count in [0, 1, 3, 4, 5] {
        for server in [false, true] {
            let (stream, observed) = probe(request(CREDENTIALS));
            let mut session = session_at(stream, count);
            let verifier = Verifier::new(Outcome::Accept);
            let error = if server {
                session
                    .authenticate_server(&verifier, BUDGET)
                    .map(|_| ())
                    .unwrap_err()
            } else {
                session
                    .authenticate_client(CREDENTIALS, BUDGET)
                    .unwrap_err()
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(verifier.calls.load(Ordering::Relaxed), 0);
            assert_eq!(observed.borrow().reads, 0);
            assert_eq!(observed.borrow().writes, 0);
            assert_eq!(observed.borrow().flushes, 0);
            assert_closed(&mut session, &observed);
        }
    }
}

#[test]
fn rejected_and_unavailable_verifiers_produce_same_generic_rejection() {
    for outcome in [Outcome::Reject, Outcome::Unavailable] {
        let (stream, observed) = probe(request(CREDENTIALS));
        let mut session = session_at(stream, 2);
        let verifier = Verifier::new(outcome);
        let error = session.authenticate_server(&verifier, BUDGET).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "authentication rejected");
        assert_eq!(verifier.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            observed.borrow().output,
            framed(&AuthenticationReply::Rejected.encode())
        );
        assert_eq!(observed.borrow().flushes, 1);
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn late_verifier_result_sends_neither_acceptance_nor_rejection() {
    for outcome in [Outcome::Accept, Outcome::Reject, Outcome::Unavailable] {
        let (stream, observed) = probe(request(CREDENTIALS));
        let mut session = session_at(stream, 2);
        let mut verifier = Verifier::new(outcome);
        verifier.delay = Duration::from_millis(2);
        let error = session
            .authenticate_server(&verifier, Duration::from_millis(1))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(verifier.calls.load(Ordering::Relaxed), 1);
        assert!(observed.borrow().output.is_empty());
        assert_eq!(observed.borrow().flushes, 0);
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn client_request_write_or_flush_failure_prevents_reply_read() {
    for flush_error in [false, true] {
        let (mut stream, observed) = probe(framed(&AuthenticationReply::Accepted.encode()));
        stream.write_error = !flush_error;
        stream.flush_error = flush_error;
        let mut session = session_at(stream, 2);
        assert_eq!(
            session
                .authenticate_client(CREDENTIALS, BUDGET)
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(observed.borrow().reads, 0);
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn server_reply_write_or_flush_failure_never_returns_identity() {
    for outcome in [Outcome::Accept, Outcome::Reject, Outcome::Unavailable] {
        for flush_error in [false, true] {
            let (mut stream, observed) = probe(request(CREDENTIALS));
            stream.write_error = !flush_error;
            stream.flush_error = flush_error;
            let mut session = session_at(stream, 2);
            let verifier = Verifier::new(outcome);
            assert_eq!(
                session
                    .authenticate_server(&verifier, BUDGET)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::BrokenPipe
            );
            assert_eq!(verifier.calls.load(Ordering::Relaxed), 1);
            assert_closed(&mut session, &observed);
        }
    }
}

#[test]
fn zero_budget_for_both_roles_skips_deadline_io_and_verifier() {
    for server in [false, true] {
        let (stream, observed) = probe(request(CREDENTIALS));
        let mut session = session_at(stream, 2);
        let verifier = Verifier::new(Outcome::Accept);
        let error = if server {
            session
                .authenticate_server(&verifier, Duration::ZERO)
                .map(|_| ())
                .unwrap_err()
        } else {
            session
                .authenticate_client(CREDENTIALS, Duration::ZERO)
                .unwrap_err()
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(observed.borrow().starts, 0);
        assert_eq!(observed.borrow().reads, 0);
        assert_eq!(observed.borrow().writes, 0);
        assert_eq!(verifier.calls.load(Ordering::Relaxed), 0);
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn maximum_credentials_succeed_for_both_roles_and_finish_deadline() {
    let credentials = vec![42; MAX_CREDENTIAL_BYTES];
    let (stream, observed) = probe(framed(&AuthenticationReply::Accepted.encode()));
    let mut client = session_at(stream, 2);
    client.authenticate_client(&credentials, BUDGET).unwrap();
    assert_eq!(client.state(), ConnectionState::EstablishingKeys);
    assert_eq!(observed.borrow().output, request(&credentials));
    assert_eq!(observed.borrow().finishes, 1);
    assert_eq!(observed.borrow().drops, 0);

    let (stream, observed) = probe(request(&credentials));
    let mut server = session_at(stream, 2);
    let mut verifier = Verifier::new(Outcome::Accept);
    verifier.expected = credentials;
    let identity = server.authenticate_server(&verifier, BUDGET).unwrap();
    assert_eq!(identity.as_str(), "verified-client");
    assert_eq!(verifier.calls.load(Ordering::Relaxed), 1);
    assert_eq!(server.state(), ConnectionState::EstablishingKeys);
    assert_eq!(
        observed.borrow().output,
        framed(&AuthenticationReply::Accepted.encode())
    );
    assert_eq!(observed.borrow().finishes, 1);
    assert_eq!(observed.borrow().drops, 0);
}

#[test]
fn request_decoding_preserves_all_binary_byte_values() {
    let credentials: Vec<u8> = (0..=u8::MAX).collect();
    let encoded = AuthenticationRequest::new(&credentials).unwrap().encode();
    assert_eq!(
        AuthenticationRequest::decode(&encoded)
            .unwrap()
            .credentials(),
        credentials.as_slice()
    );
}

#[test]
fn reply_decoder_accepts_only_the_two_defined_single_byte_tags() {
    let accepted = AuthenticationReply::Accepted.encode()[0];
    let rejected = AuthenticationReply::Rejected.encode()[0];
    assert_eq!(
        AuthenticationReply::decode(&[]),
        Err(AuthenticationWireError::InvalidMessage)
    );
    for tag in 0..=u8::MAX {
        let expected = if tag == accepted {
            Ok(AuthenticationReply::Accepted)
        } else if tag == rejected {
            Ok(AuthenticationReply::Rejected)
        } else {
            Err(AuthenticationWireError::InvalidMessage)
        };
        assert_eq!(AuthenticationReply::decode(&[tag]), expected);
        assert_eq!(
            AuthenticationReply::decode(&[tag, 0]),
            Err(AuthenticationWireError::InvalidMessage)
        );
    }
}
