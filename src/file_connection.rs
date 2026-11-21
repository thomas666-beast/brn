use std::io;
use std::time::Duration;

use crate::seal::MAX_PLAINTEXT_LEN;
use crate::{ApplicationKeyCapacity, FileUpload, FileUploadSource, FileUploadStatus, ReadyClient};

/// Additional application-side connection rotation policy.
///
/// Actual key byte/message limits are checked independently.
/// This policy never increases those limits.
#[derive(Debug, Clone, Copy)]
pub struct FileUploadRotation {
    /// Rotate before another exchange once this many successful
    /// upload exchanges have used the current connection.
    pub max_exchanges: u64,

    /// Additional local lifetime required beyond the operation budget.
    pub lifetime_margin: Duration,
}

impl Default for FileUploadRotation {
    fn default() -> Self {
        Self {
            max_exchanges: 1024,
            lifetime_margin: Duration::from_secs(5),
        }
    }
}

/// Owns a dedicated upload connection and reconnects before exchanges
/// when local capacity or the configured rotation policy requires it.
///
/// The connector must return a newly connected, authenticated client
/// with newly established application keys. It must apply its own
/// connection/setup timeouts.
///
/// Upload handles and local file sources remain owned by the caller.
///
/// Failed operations leave this wrapper without a connection. They
/// are never automatically replayed. Query upload status before
/// resuming after an uncertain chunk result.
pub struct FileUploadConnection<C>
where
    C: FnMut() -> io::Result<ReadyClient>,
{
    connect: C,
    policy: FileUploadRotation,
    connection: Option<ReadyClient>,
    successful_exchanges: u64,
}

impl<C> FileUploadConnection<C>
where
    C: FnMut() -> io::Result<ReadyClient>,
{
    /// Creates a lazy connection wrapper without performing network I/O.
    pub fn new(connect: C, policy: FileUploadRotation) -> io::Result<Self> {
        if policy.max_exchanges == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "upload rotation exchange limit must be nonzero",
            ));
        }

        Ok(Self {
            connect,
            policy,
            connection: None,
            successful_exchanges: 0,
        })
    }

    pub fn begin(&mut self, source: &FileUploadSource, budget: Duration) -> io::Result<FileUpload> {
        let connection = self.prepare(budget)?;
        let (connection, upload) = source.begin(connection, budget)?;

        self.commit_success(connection);

        Ok(upload)
    }

    /// Sends one source chunk using an already confirmed server offset.
    ///
    /// On error, do not reuse an assumed offset. Call status() on the
    /// retained upload handle before deciding what to send next.
    pub fn send_next(
        &mut self,
        source: &mut FileUploadSource,
        upload: &FileUpload,
        confirmed_offset: u64,
        budget: Duration,
    ) -> io::Result<u64> {
        let connection = self.prepare(budget)?;

        let (connection, next_offset) =
            source.send_next(upload, connection, confirmed_offset, budget)?;

        self.commit_success(connection);

        Ok(next_offset)
    }

    pub fn status(
        &mut self,
        upload: &FileUpload,
        budget: Duration,
    ) -> io::Result<FileUploadStatus> {
        let connection = self.prepare(budget)?;
        let (connection, status) = upload.status(connection, budget)?;

        self.commit_success(connection);

        Ok(status)
    }

    pub fn finish(
        &mut self,
        upload: &FileUpload,
        budget: Duration,
    ) -> io::Result<FileUploadStatus> {
        let connection = self.prepare(budget)?;
        let (connection, status) = upload.finish(connection, budget)?;

        self.commit_success(connection);

        Ok(status)
    }

    pub fn abort(&mut self, upload: &FileUpload, budget: Duration) -> io::Result<()> {
        let connection = self.prepare(budget)?;
        let connection = upload.abort(connection, budget)?;

        self.commit_success(connection);

        Ok(())
    }

    /// Drops the current connection but retains the connector.
    ///
    /// The next operation establishes a fresh connection.
    pub fn close(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.close();
        }

        self.successful_exchanges = 0;
    }

    /// Number of successful upload exchanges on the retained connection.
    ///
    /// This is an application rotation counter, not the cryptographic
    /// message counter. Failed exchanges are not retained.
    pub fn successful_exchanges(&self) -> u64 {
        self.successful_exchanges
    }

    fn prepare(&mut self, budget: Duration) -> io::Result<ReadyClient> {
        validate_budget(budget, self.policy.lifetime_margin)?;

        if let Some(mut connection) = self.connection.take() {
            let usable = self.successful_exchanges < self.policy.max_exchanges
                && connection.application_key_capacity().is_ok_and(|capacity| {
                    capacity_sufficient(capacity, budget, self.policy.lifetime_margin)
                });

            if usable {
                // Ownership leaves the wrapper during the operation.
                // If it fails, no uncertain connection is retained.
                self.successful_exchanges =
                    self.successful_exchanges.min(self.policy.max_exchanges);

                return Ok(connection);
            }

            connection.close();
        }

        self.successful_exchanges = 0;

        let mut connection = (self.connect)()?;
        let capacity = connection.application_key_capacity()?;

        if !capacity_sufficient(capacity, budget, self.policy.lifetime_margin) {
            // Do not repeatedly reconnect when even a fresh connection
            // cannot satisfy the requested operation budget.
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fresh upload connection has insufficient key capacity",
            ));
        }

        Ok(connection)
    }

    fn commit_success(&mut self, connection: ReadyClient) {
        // prepare() only permits counts below max_exchanges, so this
        // addition cannot overflow, even when the limit is u64::MAX.
        self.successful_exchanges += 1;
        self.connection = Some(connection);
    }
}

fn validate_budget(budget: Duration, lifetime_margin: Duration) -> io::Result<()> {
    if budget.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "upload operation budget must be nonzero",
        ));
    }

    budget.checked_add(lifetime_margin).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "upload lifetime requirement overflow",
        )
    })?;

    Ok(())
}

fn capacity_sufficient(
    capacity: ApplicationKeyCapacity,
    budget: Duration,
    lifetime_margin: Duration,
) -> bool {
    if budget.is_zero() {
        return false;
    }

    let Some(required_lifetime) = budget.checked_add(lifetime_margin) else {
        return false;
    };

    let required_bytes = MAX_PLAINTEXT_LEN as u64;

    capacity.send_plaintext_bytes >= required_bytes
        && capacity.receive_plaintext_bytes >= required_bytes
        && capacity.send_messages >= 1
        && capacity.receive_messages >= 1
        && capacity.remaining_lifetime > required_lifetime
}

#[cfg(test)]
impl<C> FileUploadConnection<C>
where
    C: FnMut() -> io::Result<ReadyClient>,
{
    pub(crate) fn restrict_current_capacity_for_test(
        &mut self,
        send_bytes: u64,
        receive_bytes: u64,
        remaining_lifetime: Option<Duration>,
    ) -> io::Result<()> {
        let connection = self.connection.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotConnected, "no retained upload connection")
        })?;

        connection.restrict_capacity_for_test(send_bytes, receive_bytes, remaining_lifetime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;
    use std::rc::Rc;

    fn capacity() -> ApplicationKeyCapacity {
        ApplicationKeyCapacity {
            send_plaintext_bytes: MAX_PLAINTEXT_LEN as u64,
            send_messages: 1,
            receive_plaintext_bytes: MAX_PLAINTEXT_LEN as u64,
            receive_messages: 1,
            remaining_lifetime: Duration::from_secs(30),
        }
    }

    #[test]
    fn accepts_capacity_for_one_maximum_exchange() {
        assert!(capacity_sufficient(
            capacity(),
            Duration::from_secs(5),
            Duration::from_secs(5),
        ));
    }

    #[test]
    fn requires_bytes_in_both_directions() {
        let mut sending_short = capacity();
        sending_short.send_plaintext_bytes -= 1;

        let mut receiving_short = capacity();
        receiving_short.receive_plaintext_bytes -= 1;

        for snapshot in [sending_short, receiving_short] {
            assert!(!capacity_sufficient(
                snapshot,
                Duration::from_secs(5),
                Duration::ZERO,
            ));
        }
    }

    #[test]
    fn requires_message_slots_in_both_directions() {
        let mut sending_empty = capacity();
        sending_empty.send_messages = 0;

        let mut receiving_empty = capacity();
        receiving_empty.receive_messages = 0;

        for snapshot in [sending_empty, receiving_empty] {
            assert!(!capacity_sufficient(
                snapshot,
                Duration::from_secs(5),
                Duration::ZERO,
            ));
        }
    }

    #[test]
    fn lifetime_must_exceed_budget_plus_margin() {
        let mut snapshot = capacity();
        snapshot.remaining_lifetime = Duration::from_secs(10);

        assert!(!capacity_sufficient(
            snapshot,
            Duration::from_secs(5),
            Duration::from_secs(5),
        ));

        snapshot.remaining_lifetime += Duration::from_nanos(1);

        assert!(capacity_sufficient(
            snapshot,
            Duration::from_secs(5),
            Duration::from_secs(5),
        ));
    }

    #[test]
    fn rejects_zero_and_overflowing_budgets() {
        assert!(validate_budget(Duration::ZERO, Duration::ZERO).is_err());
        assert!(validate_budget(Duration::MAX, Duration::from_secs(1)).is_err());

        assert!(!capacity_sufficient(
            capacity(),
            Duration::ZERO,
            Duration::ZERO,
        ));
        assert!(!capacity_sufficient(
            capacity(),
            Duration::MAX,
            Duration::from_secs(1),
        ));
    }

    #[test]
    fn construction_is_lazy_and_rejects_zero_exchange_limit() {
        let calls = Rc::new(Cell::new(0));
        let connector_calls = Rc::clone(&calls);

        let connector = move || -> io::Result<ReadyClient> {
            connector_calls.set(connector_calls.get() + 1);
            Err(io::Error::other("test connector"))
        };

        let mut connection =
            FileUploadConnection::new(connector, FileUploadRotation::default()).unwrap();

        assert_eq!(calls.get(), 0);
        assert_eq!(connection.successful_exchanges(), 0);

        connection.close();
        assert_eq!(calls.get(), 0);

        assert!(
            FileUploadConnection::new(
                || -> io::Result<ReadyClient> { Err(io::Error::other("must not connect")) },
                FileUploadRotation {
                    max_exchanges: 0,
                    lifetime_margin: Duration::ZERO,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn connector_failure_is_returned_without_automatic_retry() {
        let calls = Rc::new(Cell::new(0));
        let connector_calls = Rc::clone(&calls);

        let mut connection = FileUploadConnection::new(
            move || -> io::Result<ReadyClient> {
                connector_calls.set(connector_calls.get() + 1);
                Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "injected connection failure",
                ))
            },
            FileUploadRotation::default(),
        )
        .unwrap();

        let error = match connection.prepare(Duration::from_secs(5)) {
            Err(error) => error,
            Ok(_) => panic!("expected connection failure"),
        };

        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(calls.get(), 1);
        assert!(connection.connection.is_none());

        // A later explicit attempt may call the connector again.
        assert!(connection.prepare(Duration::from_secs(5)).is_err());
        assert_eq!(calls.get(), 2);
    }
}
