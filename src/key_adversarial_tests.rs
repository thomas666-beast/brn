use std::cell::RefCell;
use std::io::{self, Cursor, Read, Write};
use std::rc::Rc;

use aws_lc_rs::rand::SystemRandom;

use super::*;
use crate::wire::{read_frame, write_frame};

const BUDGET: Duration = Duration::from_secs(3600);

#[derive(Default)]
struct Observed {
    reads: usize,
    writes: usize,
    flushes: usize,
    starts: usize,
    finishes: usize,
    drops: usize,
    output: Vec<u8>,
}

#[derive(Clone, Copy)]
enum ReplyMode {
    Good,
    WrongBody,
    WrongPurpose,
    Tampered,
}

struct ProbeStream {
    input: Cursor<Vec<u8>>,
    observed: Rc<RefCell<Observed>>,
    fail_write: Option<usize>,
    fail_flush: Option<usize>,
    reply: Option<ReplyMode>,
    peer_epoch: Rc<RefCell<Option<KeyEpoch>>>,
}

impl Read for ProbeStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.observed.borrow_mut().reads += 1;
        self.input.read(buffer)
    }
}

impl Write for ProbeStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut observed = self.observed.borrow_mut();
        observed.writes += 1;
        if self.fail_write == Some(observed.writes) {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        observed.output.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let flushes = {
            let mut observed = self.observed.borrow_mut();
            observed.flushes += 1;
            observed.flushes
        };
        if self.fail_flush == Some(flushes) {
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        if let Some(mode) = self.reply.take() {
            // Test-only peer: derive its keys from the actual generated offer.
            let output = self.observed.borrow().output.clone();
            let mut reader = Cursor::new(output);
            let offer = read_frame(&mut reader)?.expect("server must send an offer");
            assert_eq!(offer.kind(), FrameKind::Control);
            let mut epoch = KeyEpoch::for_client(KeyOffer::decode(offer.body())?)?;
            let purpose = match mode {
                ReplyMode::WrongPurpose => MessagePurpose::Request,
                _ => MessagePurpose::KeyConfirmation,
            };
            let body = match mode {
                ReplyMode::WrongBody => SERVER_CONFIRMATION,
                _ => CLIENT_CONFIRMATION,
            };
            let confirmation = epoch.seal(purpose, body)?;
            let mut bytes = confirmation.body().to_vec();
            if matches!(mode, ReplyMode::Tampered) {
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
            }
            write_frame(self.input.get_mut(), FrameKind::Encrypted, &bytes)?;
            *self.peer_epoch.borrow_mut() = Some(epoch);
        }
        Ok(())
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

fn probe(input: Vec<u8>) -> (ProbeStream, Rc<RefCell<Observed>>) {
    let observed = Rc::new(RefCell::new(Observed::default()));
    (
        ProbeStream {
            input: Cursor::new(input),
            observed: Rc::clone(&observed),
            fail_write: None,
            fail_flush: None,
            reply: None,
            peer_epoch: Rc::new(RefCell::new(None)),
        },
        observed,
    )
}

fn at_state(stream: ProbeStream, count: usize) -> Session<ProbeStream> {
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

fn fixed_keys() -> TemporaryKeys {
    // Fixed material is exclusively for isolated tests.
    let mut bytes = [0x11; 64];
    bytes[32..].fill(0x22);
    TemporaryKeys::from_bytes(&bytes).unwrap()
}

fn offer_frame() -> Vec<u8> {
    let offer = KeyOffer::from_keys(&fixed_keys());
    framed(FrameKind::Control, offer.body())
}

fn framed(kind: FrameKind, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_frame(&mut bytes, kind, body).unwrap();
    bytes
}

fn server_input(
    purpose: MessagePurpose,
    body: &[u8],
    tamper: bool,
    skip: bool,
) -> (Vec<u8>, KeyEpoch) {
    let mut input = offer_frame();
    let mut epoch = KeyEpoch::for_server(fixed_keys()).unwrap();
    if skip {
        let _ = epoch
            .seal(MessagePurpose::KeyConfirmation, SERVER_CONFIRMATION)
            .unwrap();
    }
    let confirmation = epoch.seal(purpose, body).unwrap();
    let mut bytes = confirmation.body().to_vec();
    if tamper {
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
    }
    write_frame(&mut input, FrameKind::Encrypted, &bytes).unwrap();
    (input, epoch)
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
            .send(FrameKind::Encrypted, b"late")
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
    assert_eq!(
        session.establish_client_keys(BUDGET).unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    assert_eq!(
        session
            .establish_server_keys(&SystemRandom::new(), BUDGET)
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
    let o = observed.borrow();
    assert_eq!(
        (o.reads, o.writes, o.flushes, o.starts, o.output.len()),
        before
    );
    assert_eq!(o.drops, 1);
}

#[test]
fn client_eof_and_every_truncated_offer_close_without_writing() {
    let bytes = offer_frame();
    for offset in 0..bytes.len() {
        let (stream, observed) = probe(bytes[..offset].to_vec());
        let mut session = at_state(stream, 3);
        assert_eq!(
            session.establish_client_keys(BUDGET).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert!(observed.borrow().output.is_empty());
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn client_rejects_all_corrupted_offer_header_bytes_without_writing() {
    let offer = KeyOffer::from_keys(&fixed_keys());
    for index in 0..11 {
        let mut body = offer.body().to_vec();
        body[index] ^= 0xff;
        let (stream, observed) = probe(framed(FrameKind::Control, &body));
        let mut session = at_state(stream, 3);
        assert_eq!(
            session.establish_client_keys(BUDGET).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(observed.borrow().output.is_empty());
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn client_eof_and_every_truncated_confirmation_close() {
    let (bytes, _) = server_input(
        MessagePurpose::KeyConfirmation,
        SERVER_CONFIRMATION,
        false,
        false,
    );
    let offer_len = offer_frame().len();
    for end in offer_len..bytes.len() {
        let (stream, observed) = probe(bytes[..end].to_vec());
        let mut session = at_state(stream, 3);
        assert_eq!(
            session.establish_client_keys(BUDGET).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert!(!observed.borrow().output.is_empty());
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn client_rejects_wrong_body_purpose_tampering_and_skipped_sequence() {
    for (purpose, body, tamper, skip) in [
        (
            MessagePurpose::KeyConfirmation,
            CLIENT_CONFIRMATION,
            false,
            false,
        ),
        (MessagePurpose::Response, SERVER_CONFIRMATION, false, false),
        (
            MessagePurpose::KeyConfirmation,
            SERVER_CONFIRMATION,
            true,
            false,
        ),
        (
            MessagePurpose::KeyConfirmation,
            SERVER_CONFIRMATION,
            false,
            true,
        ),
    ] {
        let (input, _) = server_input(purpose, body, tamper, skip);
        let (stream, observed) = probe(input);
        let mut session = at_state(stream, 3);
        assert!(session.establish_client_keys(BUDGET).is_err());
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn client_rejects_confirmation_encrypted_in_the_wrong_direction() {
    let mut input = offer_frame();
    let mut wrong_epoch = KeyEpoch::for_client(fixed_keys()).unwrap();
    let confirmation = wrong_epoch
        .seal(MessagePurpose::KeyConfirmation, SERVER_CONFIRMATION)
        .unwrap();
    write_frame(&mut input, FrameKind::Encrypted, confirmation.body()).unwrap();
    let (stream, observed) = probe(input);
    let mut session = at_state(stream, 3);
    assert!(session.establish_client_keys(BUDGET).is_err());
    assert_closed(&mut session, &observed);
}

#[test]
fn wrong_outer_frame_kinds_close_in_both_client_stages() {
    let offer = KeyOffer::from_keys(&fixed_keys());
    let mut wrong_confirmation = offer_frame();
    write_frame(
        &mut wrong_confirmation,
        FrameKind::Control,
        b"not encrypted",
    )
    .unwrap();
    for input in [
        framed(FrameKind::Encrypted, offer.body()),
        wrong_confirmation,
    ] {
        let (stream, observed) = probe(input);
        let mut session = at_state(stream, 3);
        assert_eq!(
            session.establish_client_keys(BUDGET).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn both_roles_reject_wrong_states_without_io() {
    for count in [0, 1, 2, 4, 5] {
        for server in [false, true] {
            let (stream, observed) = probe(offer_frame());
            let mut session = at_state(stream, count);
            let result = if server {
                session.establish_server_keys(&SystemRandom::new(), BUDGET)
            } else {
                session.establish_client_keys(BUDGET)
            };
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
            assert_eq!(observed.borrow().reads, 0);
            assert_eq!(observed.borrow().writes, 0);
            assert_eq!(observed.borrow().flushes, 0);
            assert_closed(&mut session, &observed);
        }
    }
}

#[test]
fn zero_budget_for_both_roles_performs_no_io_or_deadline_start() {
    for server in [false, true] {
        let (stream, observed) = probe(offer_frame());
        let mut session = at_state(stream, 3);
        let result = if server {
            session.establish_server_keys(&SystemRandom::new(), Duration::ZERO)
        } else {
            session.establish_client_keys(Duration::ZERO)
        };
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(observed.borrow().starts, 0);
        assert_eq!(observed.borrow().reads, 0);
        assert_eq!(observed.borrow().writes, 0);
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn client_confirmation_write_and_flush_failures_close() {
    for flush in [false, true] {
        let (input, _) = server_input(
            MessagePurpose::KeyConfirmation,
            SERVER_CONFIRMATION,
            false,
            false,
        );
        let (mut stream, observed) = probe(input);
        if flush {
            stream.fail_flush = Some(1);
        } else {
            stream.fail_write = Some(1);
        }
        let mut session = at_state(stream, 3);
        assert_eq!(
            session.establish_client_keys(BUDGET).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn server_offer_write_and_flush_failures_prevent_confirmation_read() {
    for flush in [false, true] {
        let (mut stream, observed) = probe(Vec::new());
        if flush {
            stream.fail_flush = Some(1);
        } else {
            stream.fail_write = Some(1);
        }
        let mut session = at_state(stream, 3);
        assert_eq!(
            session
                .establish_server_keys(&SystemRandom::new(), BUDGET)
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(observed.borrow().reads, 0);
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn server_rejects_authenticated_wrong_body_wrong_purpose_and_tampering() {
    for mode in [
        ReplyMode::WrongBody,
        ReplyMode::WrongPurpose,
        ReplyMode::Tampered,
    ] {
        let (mut stream, observed) = probe(Vec::new());
        stream.reply = Some(mode);
        let mut session = at_state(stream, 3);
        assert!(
            session
                .establish_server_keys(&SystemRandom::new(), BUDGET)
                .is_err()
        );
        assert_eq!(observed.borrow().flushes, 1);
        let mut output = Cursor::new(observed.borrow().output.clone());
        assert_eq!(
            read_frame(&mut output).unwrap().unwrap().kind(),
            FrameKind::Control
        );
        assert!(read_frame(&mut output).unwrap().is_none());
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn server_final_confirmation_write_and_flush_failures_never_return_epoch() {
    for flush in [false, true] {
        let (mut stream, observed) = probe(Vec::new());
        stream.reply = Some(ReplyMode::Good);
        // Each nonempty frame uses one header write and one body write.
        if flush {
            stream.fail_flush = Some(2);
        } else {
            stream.fail_write = Some(3);
        }
        let mut session = at_state(stream, 3);
        assert_eq!(
            session
                .establish_server_keys(&SystemRandom::new(), BUDGET)
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_closed(&mut session, &observed);
    }
}

#[test]
fn successful_server_exchange_preserves_both_directional_counters() {
    let (mut stream, observed) = probe(Vec::new());
    stream.reply = Some(ReplyMode::Good);
    let peer = Rc::clone(&stream.peer_epoch);
    let mut session = at_state(stream, 3);
    let mut epoch = session
        .establish_server_keys(&SystemRandom::new(), BUDGET)
        .unwrap();
    assert_eq!(session.state(), ConnectionState::Ready);
    assert_eq!(observed.borrow().finishes, 1);
    assert_eq!(observed.borrow().drops, 0);
    let mut output = Cursor::new(observed.borrow().output.clone());
    let _offer = read_frame(&mut output).unwrap().unwrap();
    let confirmation = read_frame(&mut output).unwrap().unwrap();
    assert_eq!(confirmation.kind(), FrameKind::Encrypted);
    assert!(read_frame(&mut output).unwrap().is_none());
    let mut peer = peer.borrow_mut();
    let peer = peer.as_mut().unwrap();
    let opened = peer
        .open(confirmation.body(), MessagePurpose::KeyConfirmation)
        .unwrap();
    assert_eq!(opened.body(), SERVER_CONFIRMATION);
    let request = peer
        .seal(MessagePurpose::Request, b"first request")
        .unwrap();
    assert_eq!(request.sequence(), 1);
    let opened = epoch.open(request.body(), MessagePurpose::Request).unwrap();
    assert_eq!(opened.body(), b"first request");
    let response = epoch
        .seal(MessagePurpose::Response, b"first response")
        .unwrap();
    assert_eq!(response.sequence(), 1);
    let opened = peer
        .open(response.body(), MessagePurpose::Response)
        .unwrap();
    assert_eq!(opened.body(), b"first response");
}

#[test]
fn successful_client_exchange_preserves_receive_counter_and_rejects_replay() {
    let (input, mut server_epoch) = server_input(
        MessagePurpose::KeyConfirmation,
        SERVER_CONFIRMATION,
        false,
        false,
    );
    let (stream, observed) = probe(input);
    let mut session = at_state(stream, 3);
    let mut epoch = session.establish_client_keys(BUDGET).unwrap();
    assert_eq!(session.state(), ConnectionState::Ready);
    assert_eq!(observed.borrow().finishes, 1);
    let mut output = Cursor::new(observed.borrow().output.clone());
    let confirmation = read_frame(&mut output).unwrap().unwrap();
    let opened = server_epoch
        .open(confirmation.body(), MessagePurpose::KeyConfirmation)
        .unwrap();
    assert_eq!(opened.body(), CLIENT_CONFIRMATION);
    let response = server_epoch
        .seal(MessagePurpose::Response, b"first response")
        .unwrap();
    assert_eq!(response.sequence(), 1);
    let opened = epoch
        .open(response.body(), MessagePurpose::Response)
        .unwrap();
    assert_eq!(opened.body(), b"first response");
    assert!(
        epoch
            .open(response.body(), MessagePurpose::Response)
            .is_err()
    );
    // This last assertion is epoch-level replay handling, not session closure.
}

#[test]
fn offer_decoder_rejects_every_truncated_prefix_and_trailing_data() {
    let offer = KeyOffer::from_keys(&fixed_keys());
    for length in 0..offer.body().len() {
        assert_eq!(
            KeyOffer::decode(&offer.body()[..length])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }
    let mut extended = offer.body().to_vec();
    extended.push(0);
    assert_eq!(
        KeyOffer::decode(&extended).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn offer_decoder_rejects_every_unsupported_tag_format_and_suite() {
    let offer = KeyOffer::from_keys(&fixed_keys());
    for index in 0..3 {
        for value in 0..=u8::MAX {
            if value == offer.body()[index] {
                continue;
            }
            let mut modified = offer.body().to_vec();
            modified[index] = value;
            assert_eq!(
                KeyOffer::decode(&modified).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
