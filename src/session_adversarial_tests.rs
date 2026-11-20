use std::cell::RefCell;
use std::io::{self, Read, Write};
use std::rc::Rc;

use super::Session;
use crate::frame::{FrameHeader, FrameKind, HEADER_LEN};
use crate::state::{ConnectionEvent, ConnectionState};
use crate::wire::write_frame;

#[derive(Default)]
struct Observations {
    read_calls: usize,
    bytes_read: usize,
    write_calls: usize,
    output: Vec<u8>,
    flush_calls: usize,
    drops: usize,
}

struct ProbeStream {
    input: Vec<u8>,
    read_fault: Option<(usize, io::ErrorKind)>,
    write_fault: Option<(usize, io::ErrorKind)>,
    flush_fault: Option<io::ErrorKind>,
    observed: Rc<RefCell<Observations>>,
}

impl Read for ProbeStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let mut observed = self.observed.borrow_mut();
        observed.read_calls += 1;
        if let Some((offset, kind)) = self.read_fault
            && observed.bytes_read == offset
        {
            self.read_fault = None;
            return Err(io::Error::new(kind, "injected session read failure"));
        }
        if observed.bytes_read == self.input.len() {
            return Ok(0);
        }
        buffer[0] = self.input[observed.bytes_read];
        observed.bytes_read += 1;
        Ok(1)
    }
}

impl Write for ProbeStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let mut observed = self.observed.borrow_mut();
        observed.write_calls += 1;
        if let Some((offset, kind)) = self.write_fault
            && observed.output.len() == offset
        {
            self.write_fault = None;
            return if kind == io::ErrorKind::WriteZero {
                Ok(0)
            } else {
                Err(io::Error::new(kind, "injected session write failure"))
            };
        }
        observed.output.push(buffer[0]);
        Ok(1)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.observed.borrow_mut().flush_calls += 1;
        match self.flush_fault {
            Some(kind) => Err(io::Error::new(kind, "injected session flush failure")),
            None => Ok(()),
        }
    }
}

impl Drop for ProbeStream {
    fn drop(&mut self) {
        self.observed.borrow_mut().drops += 1;
    }
}

fn probe(input: Vec<u8>) -> (ProbeStream, Rc<RefCell<Observations>>) {
    let observed = Rc::new(RefCell::new(Observations::default()));
    let stream = ProbeStream {
        input,
        read_fault: None,
        write_fault: None,
        flush_fault: None,
        observed: Rc::clone(&observed),
    };
    (stream, observed)
}

fn negotiating(stream: ProbeStream) -> Session<ProbeStream> {
    let mut session = Session::new(stream);
    session.advance(ConnectionEvent::TlsEstablished).unwrap();
    session
}

fn encoded(body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_frame(&mut bytes, FrameKind::Control, body).unwrap();
    bytes
}

fn counts(observed: &Rc<RefCell<Observations>>) -> (usize, usize, usize, usize, usize, usize) {
    let observed = observed.borrow();
    (
        observed.read_calls,
        observed.bytes_read,
        observed.write_calls,
        observed.output.len(),
        observed.flush_calls,
        observed.drops,
    )
}

fn assert_closed_and_inert(
    session: &mut Session<ProbeStream>,
    observed: &Rc<RefCell<Observations>>,
) {
    assert_eq!(session.state(), ConnectionState::Closed);
    assert_eq!(observed.borrow().drops, 1);
    let before = counts(observed);
    for _ in 0..2 {
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
        session.close();
    }
    assert_eq!(counts(observed), before);
}

#[test]
fn every_nonempty_truncated_prefix_closes_and_disables_io() {
    let bytes = encoded(b"payload");
    for offset in 1..bytes.len() {
        let (stream, observed) = probe(bytes[..offset].to_vec());
        let mut session = negotiating(stream);
        assert_eq!(
            session.receive().unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(observed.borrow().bytes_read, offset);
        assert_closed_and_inert(&mut session, &observed);
    }
}

#[test]
fn read_failures_at_every_offset_close_and_disable_io() {
    let bytes = encoded(b"payload");
    for kind in [
        io::ErrorKind::TimedOut,
        io::ErrorKind::WouldBlock,
        io::ErrorKind::ConnectionReset,
    ] {
        for offset in 0..bytes.len() {
            let (mut stream, observed) = probe(bytes.clone());
            stream.read_fault = Some((offset, kind));
            let mut session = negotiating(stream);
            assert_eq!(
                session.receive().unwrap_err().kind(),
                kind,
                "offset {offset}"
            );
            assert_eq!(observed.borrow().bytes_read, offset);
            assert_closed_and_inert(&mut session, &observed);
        }
    }
}

#[test]
fn write_failures_at_every_offset_close_without_flushing() {
    let bytes = encoded(b"payload");
    for kind in [
        io::ErrorKind::TimedOut,
        io::ErrorKind::WouldBlock,
        io::ErrorKind::BrokenPipe,
        io::ErrorKind::WriteZero,
    ] {
        for offset in 0..bytes.len() {
            let (mut stream, observed) = probe(Vec::new());
            stream.write_fault = Some((offset, kind));
            let mut session = negotiating(stream);
            assert_eq!(
                session
                    .send(FrameKind::Control, b"payload")
                    .unwrap_err()
                    .kind(),
                kind,
                "offset {offset}"
            );
            assert_eq!(observed.borrow().output.as_slice(), &bytes[..offset]);
            assert_eq!(observed.borrow().flush_calls, 0);
            assert_closed_and_inert(&mut session, &observed);
        }
    }
}

#[test]
fn flush_failure_after_complete_write_closes_and_disables_io() {
    for kind in [io::ErrorKind::TimedOut, io::ErrorKind::BrokenPipe] {
        let (mut stream, observed) = probe(Vec::new());
        stream.flush_fault = Some(kind);
        let mut session = negotiating(stream);
        assert_eq!(
            session
                .send(FrameKind::Control, b"payload")
                .unwrap_err()
                .kind(),
            kind
        );
        assert_eq!(observed.borrow().output, encoded(b"payload"));
        assert_eq!(observed.borrow().flush_calls, 1);
        assert_closed_and_inert(&mut session, &observed);
    }
}

#[test]
fn malformed_magic_and_kind_close_before_body_read() {
    let valid = FrameHeader::new(FrameKind::Control, 7).unwrap().encode();
    for index in 0..5 {
        let mut header = valid;
        header[index] ^= 0xff;
        let mut input = header.to_vec();
        input.extend_from_slice(b"payload");
        let (stream, observed) = probe(input);
        let mut session = negotiating(stream);
        assert_eq!(
            session.receive().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(observed.borrow().bytes_read, HEADER_LEN);
        assert_closed_and_inert(&mut session, &observed);
    }
}

#[test]
fn empty_outgoing_body_closes_without_writing_or_flushing() {
    let (stream, observed) = probe(Vec::new());
    let mut session = negotiating(stream);
    assert_eq!(
        session.send(FrameKind::Control, b"").unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(observed.borrow().write_calls, 0);
    assert_eq!(observed.borrow().flush_calls, 0);
    assert_closed_and_inert(&mut session, &observed);
}

#[test]
fn explicit_close_is_idempotent_and_performs_no_io() {
    let (stream, observed) = probe(encoded(b"unread"));
    let mut session = negotiating(stream);
    session.close();
    assert_closed_and_inert(&mut session, &observed);
    assert_eq!(counts(&observed), (0, 0, 0, 0, 0, 1));
    drop(session);
    assert_eq!(observed.borrow().drops, 1);
}

#[test]
fn dropping_an_open_session_drops_its_stream_once_without_io() {
    let (stream, observed) = probe(encoded(b"unread"));
    let session = negotiating(stream);
    assert_eq!(observed.borrow().drops, 0);
    drop(session);
    assert_eq!(counts(&observed), (0, 0, 0, 0, 0, 1));
}

#[test]
fn successful_fragmented_send_flushes_once_and_keeps_session_open() {
    let (stream, observed) = probe(Vec::new());
    let mut session = negotiating(stream);
    session.send(FrameKind::Control, b"payload").unwrap();
    assert_eq!(observed.borrow().output, encoded(b"payload"));
    assert_eq!(observed.borrow().flush_calls, 1);
    assert_eq!(observed.borrow().drops, 0);
    assert_eq!(session.state(), ConnectionState::Negotiating);
    session.close();
    assert_closed_and_inert(&mut session, &observed);
}

#[test]
fn clean_eof_closes_once_and_later_operations_do_not_touch_transport() {
    let (stream, observed) = probe(Vec::new());
    let mut session = negotiating(stream);
    assert!(session.receive().unwrap().is_none());
    assert_eq!(observed.borrow().read_calls, 1);
    assert_closed_and_inert(&mut session, &observed);
}
