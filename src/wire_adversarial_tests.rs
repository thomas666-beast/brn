use std::io::{self, Cursor, Read, Write};

use super::{read_frame, read_frame_checked, write_frame};
use crate::frame::{FrameHeader, FrameKind, HEADER_LEN, MAX_BODY_LEN};

fn encoded(kind: FrameKind, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_frame(&mut bytes, kind, body).unwrap();
    bytes
}

struct ProbeReader {
    bytes: Vec<u8>,
    position: usize,
    interrupt_next: bool,
    interrupt_each_byte: bool,
    fault: Option<(usize, io::ErrorKind)>,
}

impl ProbeReader {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            position: 0,
            interrupt_next: false,
            interrupt_each_byte: false,
            fault: None,
        }
    }
}

impl Read for ProbeReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if let Some((position, kind)) = self.fault
            && self.position == position
        {
            self.fault = None;
            return Err(io::Error::new(kind, "injected read failure"));
        }
        if self.interrupt_next {
            self.interrupt_next = false;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        if self.position == self.bytes.len() {
            return Ok(0);
        }
        buffer[0] = self.bytes[self.position];
        self.position += 1;
        self.interrupt_next = self.interrupt_each_byte;
        Ok(1)
    }
}

struct ProbeWriter {
    bytes: Vec<u8>,
    interrupt_next: bool,
    interrupt_each_byte: bool,
    fault: Option<(usize, io::ErrorKind)>,
}

impl ProbeWriter {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            interrupt_next: false,
            interrupt_each_byte: false,
            fault: None,
        }
    }
}

impl Write for ProbeWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if let Some((position, kind)) = self.fault
            && self.bytes.len() == position
        {
            self.fault = None;
            return if kind == io::ErrorKind::WriteZero {
                Ok(0)
            } else {
                Err(io::Error::new(kind, "injected write failure"))
            };
        }
        if self.interrupt_next {
            self.interrupt_next = false;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        self.bytes.push(buffer[0]);
        self.interrupt_next = self.interrupt_each_byte;
        Ok(1)
    }

    fn flush(&mut self) -> io::Result<()> {
        panic!("write_frame must not flush")
    }
}

#[test]
fn interrupted_reads_retry_at_header_and_body_boundaries() {
    let bytes = encoded(FrameKind::Encrypted, b"payload");
    let mut reader = ProbeReader::new(bytes.clone());
    reader.interrupt_next = true;
    reader.interrupt_each_byte = true;

    let frame = read_frame(&mut reader).unwrap().unwrap();
    assert_eq!(frame.kind(), FrameKind::Encrypted);
    assert_eq!(frame.body(), b"payload");
    assert_eq!(reader.position, bytes.len());
    assert!(read_frame(&mut reader).unwrap().is_none());
}

#[test]
fn interrupted_writes_retry_without_duplicating_bytes() {
    let mut writer = ProbeWriter::new();
    writer.interrupt_next = true;
    writer.interrupt_each_byte = true;

    write_frame(&mut writer, FrameKind::Control, b"payload").unwrap();
    assert_eq!(writer.bytes, encoded(FrameKind::Control, b"payload"));
}

#[test]
fn read_failures_propagate_at_every_frame_offset() {
    let bytes = encoded(FrameKind::Control, b"payload");
    for kind in [
        io::ErrorKind::TimedOut,
        io::ErrorKind::WouldBlock,
        io::ErrorKind::ConnectionReset,
    ] {
        for offset in 0..bytes.len() {
            let mut reader = ProbeReader::new(bytes.clone());
            reader.fault = Some((offset, kind));
            let error = read_frame(&mut reader).unwrap_err();
            assert_eq!(error.kind(), kind, "offset {offset}");
            assert_eq!(reader.position, offset);
        }
    }
}

#[test]
fn write_failures_propagate_and_preserve_only_the_written_prefix() {
    let bytes = encoded(FrameKind::Control, b"payload");
    for kind in [
        io::ErrorKind::TimedOut,
        io::ErrorKind::WouldBlock,
        io::ErrorKind::BrokenPipe,
    ] {
        for offset in 0..bytes.len() {
            let mut writer = ProbeWriter::new();
            writer.fault = Some((offset, kind));
            let error = write_frame(&mut writer, FrameKind::Control, b"payload").unwrap_err();
            assert_eq!(error.kind(), kind, "offset {offset}");
            assert_eq!(writer.bytes.as_slice(), &bytes[..offset]);
        }
    }
}

#[test]
fn zero_progress_writes_fail_at_every_frame_offset() {
    let bytes = encoded(FrameKind::Control, b"payload");
    for offset in 0..bytes.len() {
        let mut writer = ProbeWriter::new();
        writer.fault = Some((offset, io::ErrorKind::WriteZero));
        let error = write_frame(&mut writer, FrameKind::Control, b"payload").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WriteZero, "offset {offset}");
        assert_eq!(writer.bytes.as_slice(), &bytes[..offset]);
    }
}

#[test]
fn all_invalid_header_categories_skip_policy_and_body_reads() {
    let valid = FrameHeader::new(FrameKind::Control, 1).unwrap().encode();
    let mut headers = Vec::new();
    let mut bad_magic = valid;
    bad_magic[0] ^= 0xff;
    headers.push(bad_magic);
    let mut bad_kind = valid;
    bad_kind[4] = 0xff;
    headers.push(bad_kind);
    for length in [0, MAX_BODY_LEN + 1, u32::MAX] {
        let mut header = valid;
        header[5..9].copy_from_slice(&length.to_be_bytes());
        headers.push(header);
    }

    for header in headers {
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(b"unread body");
        let mut reader = Cursor::new(bytes);
        let error = read_frame_checked(&mut reader, |_| {
            panic!("invalid header must not reach policy check")
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(reader.position(), HEADER_LEN as u64);
    }
}

#[test]
fn policy_rejection_preserves_its_error_and_does_not_read_body() {
    let bytes = encoded(FrameKind::Control, b"unread body");
    let mut reader = Cursor::new(bytes);
    let error = read_frame_checked(&mut reader, |header| {
        assert_eq!(header.kind(), FrameKind::Control);
        assert_eq!(header.body_len(), b"unread body".len() as u32);
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "policy rejection",
        ))
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "policy rejection");
    assert_eq!(reader.position(), HEADER_LEN as u64);
}

#[test]
fn eof_and_truncated_headers_never_reach_policy_check() {
    let bytes = encoded(FrameKind::Control, b"payload");
    for length in 0..HEADER_LEN {
        let mut reader = Cursor::new(&bytes[..length]);
        let result = read_frame_checked(&mut reader, |_| {
            panic!("incomplete header must not reach policy check")
        });
        if length == 0 {
            assert!(result.unwrap().is_none());
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        }
    }
}

#[test]
fn policy_is_called_once_before_a_truncated_body_is_read() {
    let mut bytes = encoded(FrameKind::Control, b"payload");
    bytes.pop();
    let mut reader = Cursor::new(bytes);
    let mut checks = 0;
    let error = read_frame_checked(&mut reader, |_| {
        checks += 1;
        Ok(())
    })
    .unwrap_err();
    assert_eq!(checks, 1);
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn frame_debug_does_not_expose_body_contents() {
    let mut reader = Cursor::new(encoded(FrameKind::Control, b"secret-credential-123"));
    let frame = read_frame(&mut reader).unwrap().unwrap();
    let debug = format!("{frame:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("secret-credential-123"));
}
