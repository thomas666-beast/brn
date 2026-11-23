use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::{ProtocolVersion, ServerConfig, ServerConnection, StreamOwned};

use crate::session::Session;
use crate::state::ConnectionEvent;
use crate::tls::BrnVersion;
use crate::transport::DeadlineTcpStream;

pub(crate) type ServerTlsStream = StreamOwned<ServerConnection, DeadlineTcpStream>;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ServerTimeouts {
    handshake: Duration,
    io: Duration,
}

impl ServerTimeouts {
    pub(crate) fn new(handshake: Duration, io: Duration) -> io::Result<Self> {
        if handshake.is_zero() || io.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "server timeouts must all be greater than zero",
            ));
        }

        Ok(Self { handshake, io })
    }
}

/// Completes TLS on an already accepted TCP socket for BRN v1.
///
/// The configuration should come from `build_server_config`.
///
/// This function does not accept sockets, perform BRN negotiation,
/// authenticate the BRN client, or establish application keys.
pub(crate) fn accept_tls(
    socket: TcpStream,
    config: Arc<ServerConfig>,
    timeouts: ServerTimeouts,
) -> io::Result<Session<ServerTlsStream>> {
    accept_tls_for_version(socket, config, timeouts, BrnVersion::V1)
}

/// Completes TLS for exactly one BRN version.
///
/// The configuration must advertise only the selected version.
/// The caller must run the matching BRN negotiation afterward.
pub(crate) fn accept_tls_for_version(
    socket: TcpStream,
    config: Arc<ServerConfig>,
    timeouts: ServerTimeouts,
    version: BrnVersion,
) -> io::Result<Session<ServerTlsStream>> {
    if config.alpn_protocols.len() != 1 || config.alpn_protocols[0].as_slice() != version.alpn() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "server TLS ALPN configuration does not match the selected BRN version",
        ));
    }

    let mut connection = ServerConnection::new(config)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

    let mut transport = DeadlineTcpStream::new(socket, timeouts.io)?;

    let started = Instant::now();
    transport.start_deadline(timeouts.handshake)?;

    while connection.is_handshaking() {
        connection.complete_io(&mut transport)?;

        if started.elapsed() >= timeouts.handshake {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "TLS handshake deadline expired",
            ));
        }
    }

    if connection.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "BRN requires TLS 1.3",
        ));
    }

    if connection.alpn_protocol() != Some(version.alpn()) {
        let message = match version {
            BrnVersion::V1 => "TLS peer did not negotiate brn/1",
            BrnVersion::V2 => "TLS peer did not negotiate brn/2",
        };

        return Err(io::Error::new(io::ErrorKind::InvalidData, message));
    }

    transport.clear_deadline();

    let stream = StreamOwned::new(connection, transport);
    let mut session = Session::new(stream);

    session
        .advance(ConnectionEvent::TlsEstablished)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

    Ok(session)
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_nonzero_timeouts() {
        let timeouts = ServerTimeouts::new(Duration::from_secs(5), Duration::from_secs(2)).unwrap();

        assert_eq!(timeouts.handshake, Duration::from_secs(5));
        assert_eq!(timeouts.io, Duration::from_secs(2));
    }

    #[test]
    fn rejects_zero_in_any_timeout_field() {
        let second = Duration::from_secs(1);

        for (handshake, io) in [(Duration::ZERO, second), (second, Duration::ZERO)] {
            let error = ServerTimeouts::new(handshake, io).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }
}
