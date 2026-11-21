use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use brn::{ConnectionTimeouts, PendingClient, ReadyClient};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const AUTHENTICATION_BUDGET: Duration = Duration::from_secs(10);
pub const KEY_ESTABLISHMENT_BUDGET: Duration = Duration::from_secs(10);
pub const FILE_OPERATION_BUDGET: Duration = Duration::from_secs(10);

pub fn connection_timeouts() -> io::Result<ConnectionTimeouts> {
    ConnectionTimeouts::new(
        Duration::from_secs(10),
        Duration::from_secs(10),
        Duration::from_secs(10),
    )
}

pub struct ClientConfig {
    pub address: SocketAddr,
    pub server_name: String,
    pub trusted_ca_der: Vec<u8>,
    pub credentials: Vec<u8>,
}

impl ClientConfig {
    /// Creates a fresh authenticated connection with fresh application keys.
    pub fn connect(&self) -> io::Result<ReadyClient> {
        PendingClient::connect(
            self.address,
            &self.server_name,
            &[self.trusted_ca_der.as_slice()],
            CONNECT_TIMEOUT,
            connection_timeouts()?,
        )?
        .authenticate(&self.credentials, AUTHENTICATION_BUDGET)?
        .establish_keys(KEY_ESTABLISHMENT_BUDGET)
    }
}
