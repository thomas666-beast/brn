use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// A blocking TCP transport with per-operation timeouts and an optional
/// absolute deadline.
///
/// The absolute deadline is checked before every underlying read/write.
/// It does not preempt CPU work or provide hard real-time guarantees.
#[derive(Debug)]
pub(crate) struct DeadlineTcpStream {
    socket: TcpStream,
    io_timeout: Duration,
    deadline: Option<Instant>,
}

impl DeadlineTcpStream {
    pub(crate) fn new(socket: TcpStream, io_timeout: Duration) -> io::Result<Self> {
        if io_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "I/O timeout must be greater than zero",
            ));
        }

        // BRN uses sequential request/response exchanges.
        socket.set_nodelay(true)?;

        Ok(Self {
            socket,
            io_timeout,
            deadline: None,
        })
    }

    /// Starts a deadline for a protocol phase, such as the TLS handshake.
    pub(crate) fn start_deadline(&mut self, budget: Duration) -> io::Result<()> {
        if self.deadline.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a protocol phase deadline is already active",
            ));
        }

        if budget.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "deadline budget must be greater than zero",
            ));
        }

        let deadline = Instant::now().checked_add(budget).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "deadline budget is too large")
        })?;

        self.deadline = Some(deadline);

        Ok(())
    }

    /// Removes the phase deadline while retaining per-operation timeouts.
    pub(crate) fn clear_deadline(&mut self) {
        self.deadline = None;
    }

    fn next_timeout(&self) -> io::Result<Duration> {
        operation_timeout(self.io_timeout, self.deadline, Instant::now())
    }
}

impl Read for DeadlineTcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let timeout = self.next_timeout()?;
        self.socket.set_read_timeout(Some(timeout))?;
        self.socket.read(buffer)
    }
}

impl Write for DeadlineTcpStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let timeout = self.next_timeout()?;
        self.socket.set_write_timeout(Some(timeout))?;
        self.socket.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        let timeout = self.next_timeout()?;
        self.socket.set_write_timeout(Some(timeout))?;
        self.socket.flush()
    }
}

fn operation_timeout(
    io_timeout: Duration,
    deadline: Option<Instant>,
    now: Instant,
) -> io::Result<Duration> {
    if io_timeout.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "I/O timeout must be greater than zero",
        ));
    }

    let Some(deadline) = deadline else {
        return Ok(io_timeout);
    };

    let remaining = deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::TimedOut, "protocol phase deadline expired")
        })?;

    Ok(io_timeout.min(remaining))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_deadline_uses_operation_timeout() {
        let now = Instant::now();

        assert_eq!(
            operation_timeout(Duration::from_secs(5), None, now).unwrap(),
            Duration::from_secs(5)
        );

        assert_eq!(
            operation_timeout(Duration::ZERO, None, now)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn shorter_deadline_limits_operation_timeout() {
        let now = Instant::now();
        let deadline = now.checked_add(Duration::from_secs(2)).unwrap();

        assert_eq!(
            operation_timeout(Duration::from_secs(10), Some(deadline), now,).unwrap(),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn longer_deadline_preserves_operation_timeout() {
        let now = Instant::now();
        let deadline = now.checked_add(Duration::from_secs(10)).unwrap();

        assert_eq!(
            operation_timeout(Duration::from_secs(2), Some(deadline), now,).unwrap(),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn reached_or_expired_deadline_is_rejected() {
        let deadline = Instant::now();
        let later = deadline.checked_add(Duration::from_secs(1)).unwrap();

        for now in [deadline, later] {
            assert_eq!(
                operation_timeout(Duration::from_secs(5), Some(deadline), now,)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );
        }
    }

    #[test]
    fn remaining_budget_decreases_without_restarting_deadline() {
        let started = Instant::now();
        let deadline = started.checked_add(Duration::from_secs(10)).unwrap();

        for elapsed_seconds in [0, 3, 9] {
            let now = started
                .checked_add(Duration::from_secs(elapsed_seconds))
                .unwrap();

            assert_eq!(
                operation_timeout(Duration::from_secs(30), Some(deadline), now,).unwrap(),
                Duration::from_secs(10 - elapsed_seconds)
            );
        }

        assert_eq!(
            operation_timeout(Duration::from_secs(30), Some(deadline), deadline,)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn active_deadline_cannot_be_replaced_but_can_be_cleared() {
        use std::net::TcpListener;

        // Establish a local socket pair without starting worker threads.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();

        let mut transport = DeadlineTcpStream::new(socket, Duration::from_secs(2)).unwrap();

        transport.start_deadline(Duration::from_secs(5)).unwrap();

        let original = transport.deadline;
        assert!(original.is_some());

        let error = transport
            .start_deadline(Duration::from_secs(60))
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(transport.deadline, original);

        transport.clear_deadline();
        assert!(transport.deadline.is_none());

        transport.start_deadline(Duration::from_secs(5)).unwrap();

        assert!(transport.deadline.is_some());
    }
}

#[cfg(test)]
#[path = "transport_adversarial_tests.rs"]
mod adversarial_tests;
