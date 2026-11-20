use std::io::{self, Read, Write};

use crate::frame::{FrameHeader, FrameKind, HEADER_LEN, MAX_BODY_LEN};
use std::fmt;
use zeroize::Zeroizing;

pub(crate) struct Frame {
    header: FrameHeader,
    body: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("header", &self.header)
            .field("body", &"[REDACTED]")
            .finish()
    }
}

impl PartialEq for Frame {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header && self.body.as_slice() == other.body.as_slice()
    }
}

impl Eq for Frame {}

impl Frame {
    pub(crate) fn kind(&self) -> FrameKind {
        self.header.kind()
    }

    pub(crate) fn body(&self) -> &[u8] {
        self.body.as_slice()
    }
}

/// Reads one complete frame without checking connection lifecycle policy.
///
/// Intended for framing tests. The session implementation must use
/// `read_frame_checked` instead.
#[cfg(test)]
pub(crate) fn read_frame<R: Read>(reader: &mut R) -> io::Result<Option<Frame>> {
    read_frame_checked(reader, |_| Ok(()))
}

/// Reads one frame, checking its validated header before body allocation.
///
/// Returns `Ok(None)` only if the stream ends before the first header byte.
///
/// If the header check fails, the body remains unread. After any error,
/// the caller must discard the connection rather than resume parsing.
pub(crate) fn read_frame_checked<R, F>(reader: &mut R, check_header: F) -> io::Result<Option<Frame>>
where
    R: Read,
    F: FnOnce(&FrameHeader) -> io::Result<()>,
{
    let mut bytes = [0; HEADER_LEN];

    match reader.read_exact(&mut bytes[..1]) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    }

    reader.read_exact(&mut bytes[1..])?;

    let header = FrameHeader::decode(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

    check_header(&header)?;

    let mut body = Zeroizing::new(vec![0; header.body_len() as usize]);

    reader.read_exact(body.as_mut_slice())?;

    Ok(Some(Frame { header, body }))
}

/// Writes one complete frame without flushing.
///
/// After an error, the caller must discard the connection: a prefix of
/// the frame may already have been written.
pub(crate) fn write_frame<W: Write>(
    writer: &mut W,
    kind: FrameKind,
    body: &[u8],
) -> io::Result<()> {
    if body.len() > MAX_BODY_LEN as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame body exceeds maximum length",
        ));
    }

    let header = FrameHeader::new(kind, body.len() as u32)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

    writer.write_all(&header.encode())?;
    writer.write_all(body)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    /// Forces reads to return at most one byte.
    struct FragmentedReader<R> {
        inner: R,
    }

    impl<R: Read> Read for FragmentedReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let length = buffer.len().min(1);
            self.inner.read(&mut buffer[..length])
        }
    }

    /// Forces writes to accept at most one byte.
    struct FragmentedWriter {
        bytes: Vec<u8>,
    }

    impl Write for FragmentedWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let length = buffer.len().min(1);
            self.bytes.extend_from_slice(&buffer[..length]);
            Ok(length)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn encoded_frame(kind: FrameKind, body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, kind, body).unwrap();
        bytes
    }

    #[test]
    fn empty_stream_is_clean_eof() {
        let mut reader = Cursor::new(Vec::<u8>::new());

        assert_eq!(read_frame(&mut reader).unwrap(), None);
    }

    #[test]
    fn frame_round_trip() {
        let bytes = encoded_frame(FrameKind::Control, b"hello");
        let mut reader = Cursor::new(bytes);

        let frame = read_frame(&mut reader).unwrap().unwrap();

        assert_eq!(frame.kind(), FrameKind::Control);
        assert_eq!(frame.body(), b"hello");
        assert_eq!(read_frame(&mut reader).unwrap(), None);
    }

    #[test]
    fn reads_fragmented_input() {
        let bytes = encoded_frame(FrameKind::Encrypted, b"opaque body");
        let mut reader = FragmentedReader {
            inner: Cursor::new(bytes),
        };

        let frame = read_frame(&mut reader).unwrap().unwrap();

        assert_eq!(frame.kind(), FrameKind::Encrypted);
        assert_eq!(frame.body(), b"opaque body");
    }

    #[test]
    fn writes_fragmented_output() {
        let mut writer = FragmentedWriter { bytes: Vec::new() };

        write_frame(&mut writer, FrameKind::Control, b"hello").unwrap();

        assert_eq!(writer.bytes, encoded_frame(FrameKind::Control, b"hello"));
    }

    #[test]
    fn rejects_every_nonempty_truncated_prefix() {
        let bytes = encoded_frame(FrameKind::Control, b"hello");

        for length in 1..bytes.len() {
            let mut reader = Cursor::new(&bytes[..length]);

            let error = read_frame(&mut reader).unwrap_err();

            assert_eq!(
                error.kind(),
                io::ErrorKind::UnexpectedEof,
                "prefix length: {length}"
            );
        }
    }

    #[test]
    fn reads_consecutive_frames_separately() {
        let mut bytes = encoded_frame(FrameKind::Control, b"first");

        write_frame(&mut bytes, FrameKind::Encrypted, b"second").unwrap();

        let mut reader = Cursor::new(bytes);

        let first = read_frame(&mut reader).unwrap().unwrap();
        let second = read_frame(&mut reader).unwrap().unwrap();

        assert_eq!(first.body(), b"first");
        assert_eq!(second.body(), b"second");
        assert_eq!(read_frame(&mut reader).unwrap(), None);
    }

    #[test]
    fn invalid_header_is_rejected_before_reading_body() {
        let mut bytes = FrameHeader::new(FrameKind::Control, 1).unwrap().encode();

        bytes[5..9].copy_from_slice(&(MAX_BODY_LEN + 1).to_be_bytes());

        let mut reader = Cursor::new(bytes);
        let error = read_frame(&mut reader).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(reader.position(), HEADER_LEN as u64);
    }

    #[test]
    fn invalid_outbound_bodies_write_nothing() {
        for body in [Vec::new(), vec![0; MAX_BODY_LEN as usize + 1]] {
            let mut writer = Vec::new();

            let error = write_frame(&mut writer, FrameKind::Control, &body).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(writer.is_empty());
        }
    }

    #[test]
    fn maximum_body_round_trip() {
        let body = vec![42; MAX_BODY_LEN as usize];
        let bytes = encoded_frame(FrameKind::Encrypted, &body);
        let mut reader = Cursor::new(bytes);

        let frame = read_frame(&mut reader).unwrap().unwrap();

        assert_eq!(frame.body(), body.as_slice());
    }

    #[test]
    fn rejected_header_leaves_body_unread() {
        use crate::state::{ConnectionEvent, ConnectionLifecycle, ConnectionState};

        let bytes = encoded_frame(FrameKind::Encrypted, b"forbidden");
        let mut reader = Cursor::new(bytes);

        let mut lifecycle = ConnectionLifecycle::new();
        lifecycle.advance(ConnectionEvent::TlsEstablished).unwrap();

        let error = read_frame_checked(&mut reader, |header| {
            lifecycle
                .check_frame_kind(header.kind())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        })
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(reader.position(), HEADER_LEN as u64);
        assert_eq!(lifecycle.state(), ConnectionState::Closed);
    }

    #[test]
    fn accepted_header_allows_body_read() {
        use crate::state::{ConnectionEvent, ConnectionLifecycle};

        let bytes = encoded_frame(FrameKind::Control, b"setup");
        let mut reader = Cursor::new(bytes);

        let mut lifecycle = ConnectionLifecycle::new();
        lifecycle.advance(ConnectionEvent::TlsEstablished).unwrap();

        let frame = read_frame_checked(&mut reader, |header| {
            lifecycle
                .check_frame_kind(header.kind())
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        })
        .unwrap()
        .unwrap();

        assert_eq!(frame.kind(), FrameKind::Control);
        assert_eq!(frame.body(), b"setup");
        assert_eq!(reader.position(), (HEADER_LEN + b"setup".len()) as u64);
    }

    #[test]
    fn invalid_header_does_not_reach_policy_check() {
        let mut bytes = FrameHeader::new(FrameKind::Control, 1).unwrap().encode();

        bytes[0] = 0;

        let mut reader = Cursor::new(bytes);
        let mut checked = false;

        let error = read_frame_checked(&mut reader, |_| {
            checked = true;
            Ok(())
        })
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!checked);
    }
}

#[cfg(test)]
#[path = "wire_adversarial_tests.rs"]
mod adversarial_tests;
