//! Core-owned network entry points and connection metadata.

use std::io;
use std::net::{TcpListener, TcpStream};

pub use std::net::{IpAddr, SocketAddr};

/// A blocking listener for incoming BRN connections.
///
/// Accepting a connection does not complete TLS, authentication,
/// or application-key establishment.
pub struct Listener {
    inner: TcpListener,
}

impl Listener {
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            inner: TcpListener::bind(address)?,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    pub fn accept(&self) -> io::Result<AcceptedConnection> {
        let (stream, _) = self.inner.accept()?;

        Ok(AcceptedConnection { stream })
    }
}

/// An accepted TCP connection awaiting BRN setup.
///
/// The socket remains encapsulated inside core.
pub struct AcceptedConnection {
    stream: TcpStream,
}

impl AcceptedConnection {
    pub(crate) fn into_stream(self) -> TcpStream {
        self.stream
    }
}

/// Socket addresses captured when core accepts a connection.
///
/// These describe transport endpoints, not authenticated identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionInfo {
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl ConnectionInfo {
    pub(crate) fn from_stream(stream: &TcpStream) -> io::Result<Self> {
        Ok(Self {
            peer_addr: stream.peer_addr()?,
            local_addr: stream.local_addr()?,
        })
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub fn peer_ip(&self) -> IpAddr {
        self.peer_addr.ip()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}
