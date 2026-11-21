use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use super::{DeadlineTcpStream, operation_timeout};

fn sockets() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client =
        TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_secs(5))
            .unwrap();
    let (peer, _) = listener.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    (client, peer)
}

#[test]
fn constructor_rejects_zero_io_timeout() {
    let (socket, _peer) = sockets();
    let error = DeadlineTcpStream::new(socket, Duration::ZERO).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn zero_budget_leaves_no_deadline_and_allows_a_later_valid_start() {
    let (socket, _peer) = sockets();
    let mut transport = DeadlineTcpStream::new(socket, Duration::from_secs(2)).unwrap();
    assert_eq!(
        transport.start_deadline(Duration::ZERO).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(transport.deadline.is_none());
    transport.start_deadline(Duration::from_secs(3600)).unwrap();
    assert!(transport.deadline.is_some());
}

#[test]
fn maximum_budget_obeys_platform_instant_representability() {
    let (socket, _peer) = sockets();
    let mut transport = DeadlineTcpStream::new(socket, Duration::from_secs(2)).unwrap();
    // Instant's representable range is platform dependent.
    let representable = Instant::now().checked_add(Duration::MAX).is_some();
    let result = transport.start_deadline(Duration::MAX);
    if representable {
        result.unwrap();
        assert!(transport.deadline.is_some());
    } else {
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(transport.deadline.is_none());
        transport.start_deadline(Duration::from_secs(3600)).unwrap();
    }
}

#[test]
fn rejected_zero_budget_cannot_modify_an_active_deadline() {
    let (socket, _peer) = sockets();
    let mut transport = DeadlineTcpStream::new(socket, Duration::from_secs(2)).unwrap();
    transport.start_deadline(Duration::from_secs(3600)).unwrap();
    let original = transport.deadline;
    assert_eq!(
        transport.start_deadline(Duration::ZERO).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(transport.deadline, original);
}

#[test]
fn expired_deadline_cannot_be_replaced_until_explicitly_cleared() {
    let (socket, _peer) = sockets();
    let mut transport = DeadlineTcpStream::new(socket, Duration::from_secs(2)).unwrap();
    let expired = Instant::now();
    transport.deadline = Some(expired);
    assert_eq!(
        transport
            .start_deadline(Duration::from_secs(3600))
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(transport.deadline, Some(expired));
    transport.clear_deadline();
    transport.start_deadline(Duration::from_secs(3600)).unwrap();
    assert!(transport.deadline.is_some());
}

#[test]
fn expired_read_preserves_buffer_and_does_not_consume_queued_data() {
    let (socket, mut peer) = sockets();
    let mut transport = DeadlineTcpStream::new(socket, Duration::from_secs(5)).unwrap();
    peer.write_all(b"queued").unwrap();
    transport.deadline = Some(Instant::now());
    let mut buffer = [0xa5; 6];
    assert_eq!(
        transport.read(&mut buffer).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(buffer, [0xa5; 6]);
    transport.clear_deadline();
    transport.read_exact(&mut buffer).unwrap();
    assert_eq!(&buffer, b"queued");
}

#[test]
fn expired_write_sends_nothing_and_clear_allows_later_writing() {
    let (socket, mut peer) = sockets();
    let mut transport = DeadlineTcpStream::new(socket, Duration::from_secs(5)).unwrap();
    transport.deadline = Some(Instant::now());
    assert_eq!(
        transport.write(b"forbidden").unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    peer.set_nonblocking(true).unwrap();
    let mut byte = [0];
    assert_eq!(
        peer.read(&mut byte).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    peer.set_nonblocking(false).unwrap();
    transport.clear_deadline();
    transport.write_all(b"allowed").unwrap();
    let mut buffer = [0; 7];
    peer.read_exact(&mut buffer).unwrap();
    assert_eq!(&buffer, b"allowed");
}

#[test]
fn expired_flush_fails_and_clear_is_idempotent() {
    let (socket, _peer) = sockets();
    let io_timeout = Duration::from_secs(5);
    let mut transport = DeadlineTcpStream::new(socket, io_timeout).unwrap();
    transport.deadline = Some(Instant::now());
    assert_eq!(
        transport.flush().unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    transport.clear_deadline();
    transport.clear_deadline();
    assert!(transport.deadline.is_none());
    assert_eq!(transport.next_timeout().unwrap(), io_timeout);
    transport.flush().unwrap();
}

#[test]
fn repeated_real_io_preserves_absolute_deadline_and_base_timeout() {
    let (socket, mut peer) = sockets();
    let io_timeout = Duration::from_secs(5);
    let mut transport = DeadlineTcpStream::new(socket, io_timeout).unwrap();
    transport.start_deadline(Duration::from_secs(3600)).unwrap();
    let original = transport.deadline;
    for value in [1_u8, 2, 3] {
        peer.write_all(&[value]).unwrap();
        let mut incoming = [0];
        transport.read_exact(&mut incoming).unwrap();
        assert_eq!(incoming, [value]);
        transport.write_all(&[value]).unwrap();
        transport.flush().unwrap();
        let mut outgoing = [0];
        peer.read_exact(&mut outgoing).unwrap();
        assert_eq!(outgoing, [value]);
        assert_eq!(transport.deadline, original);
        assert_eq!(transport.io_timeout, io_timeout);
    }
    transport.clear_deadline();
    assert_eq!(transport.next_timeout().unwrap(), io_timeout);
}

#[test]
fn timeout_arithmetic_handles_subsecond_and_final_nanosecond_budgets() {
    let now = Instant::now();
    let deadline = now.checked_add(Duration::from_millis(10)).unwrap();
    for (elapsed, expected) in [
        (Duration::ZERO, Duration::from_millis(3)),
        (Duration::from_millis(8), Duration::from_millis(2)),
        (Duration::from_nanos(9_999_999), Duration::from_nanos(1)),
    ] {
        let current = now.checked_add(elapsed).unwrap();
        assert_eq!(
            operation_timeout(Duration::from_millis(3), Some(deadline), current).unwrap(),
            expected
        );
    }
    assert_eq!(
        operation_timeout(Duration::from_millis(3), Some(deadline), deadline)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
}

#[test]
fn constructor_enables_tcp_nodelay() {
    let (socket, _peer) = sockets();

    socket.set_nodelay(false).unwrap();
    assert!(!socket.nodelay().unwrap());

    let transport = DeadlineTcpStream::new(socket, Duration::from_secs(2)).unwrap();

    assert!(transport.socket.nodelay().unwrap());
}
