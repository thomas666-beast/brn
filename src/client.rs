use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ProtocolVersion, StreamOwned};

use crate::session::Session;
use crate::state::ConnectionEvent;
use crate::tls::{BrnVersion, build_client_config_for_version};
use crate::transport::DeadlineTcpStream;

pub(crate) type ClientTlsStream = StreamOwned<ClientConnection, DeadlineTcpStream>;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ClientTimeouts {
    connect: Duration,
    handshake: Duration,
    io: Duration,
}

impl ClientTimeouts {
    pub(crate) fn new(connect: Duration, handshake: Duration, io: Duration) -> io::Result<Self> {
        if connect.is_zero() || handshake.is_zero() || io.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "client timeouts must all be greater than zero",
            ));
        }

        Ok(Self {
            connect,
            handshake,
            io,
        })
    }
}

/// Establishes and verifies TLS for BRN v1, then returns a session.
///
/// `address` is the network destination.
/// `expected_server_name` is the certificate identity to verify.
///
/// This function does not perform DNS resolution, BRN negotiation,
/// client authentication, or application-key establishment.
pub(crate) fn connect_tls(
    address: SocketAddr,
    expected_server_name: &str,
    trusted_ca_certificates: &[&[u8]],
    timeouts: ClientTimeouts,
) -> io::Result<Session<ClientTlsStream>> {
    connect_tls_for_version(
        address,
        expected_server_name,
        trusted_ca_certificates,
        timeouts,
        BrnVersion::V1,
    )
}

/// Establishes and verifies TLS for exactly one BRN version.
///
/// The caller must run the matching BRN negotiation afterward.
/// No automatic retry or fallback to another version is performed.
pub(crate) fn connect_tls_for_version(
    address: SocketAddr,
    expected_server_name: &str,
    trusted_ca_certificates: &[&[u8]],
    timeouts: ClientTimeouts,
    version: BrnVersion,
) -> io::Result<Session<ClientTlsStream>> {
    let server_name = ServerName::try_from(expected_server_name.to_owned())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

    let config = build_client_config_for_version(trusted_ca_certificates, version)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

    let mut connection = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

    let socket = TcpStream::connect_timeout(&address, timeouts.connect)?;

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
        let timeouts = ClientTimeouts::new(
            Duration::from_secs(3),
            Duration::from_secs(5),
            Duration::from_secs(2),
        )
        .unwrap();

        assert_eq!(timeouts.connect, Duration::from_secs(3));
        assert_eq!(timeouts.handshake, Duration::from_secs(5));
        assert_eq!(timeouts.io, Duration::from_secs(2));
    }

    #[test]
    fn rejects_zero_in_any_timeout_field() {
        let second = Duration::from_secs(1);

        for (connect, handshake, io) in [
            (Duration::ZERO, second, second),
            (second, Duration::ZERO, second),
            (second, second, Duration::ZERO),
        ] {
            let error = ClientTimeouts::new(connect, handshake, io).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn rejects_invalid_server_name_before_connecting() {
        let timeouts = ClientTimeouts::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();

        let result = connect_tls(
            "127.0.0.1:0".parse().unwrap(),
            "invalid name with spaces",
            &[],
            timeouts,
        );

        let error = match result {
            Ok(_) => panic!("invalid server name unexpectedly accepted"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        // An empty trust list would produce a different error.
        // This confirms that name parsing happened first.
        assert_ne!(
            error.to_string(),
            "at least one trusted CA certificate is required"
        );
    }

    #[test]
    fn versioned_clients_reject_invalid_server_name_before_connecting() {
        let timeouts = ClientTimeouts::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();

        for version in [BrnVersion::V1, BrnVersion::V2] {
            let result = connect_tls_for_version(
                "127.0.0.1:0".parse().unwrap(),
                "invalid name with spaces",
                &[],
                timeouts,
                version,
            );

            let error = match result {
                Ok(_) => panic!("invalid server name unexpectedly accepted"),
                Err(error) => error,
            };

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

            assert_ne!(
                error.to_string(),
                "at least one trusted CA certificate is required"
            );
        }
    }
}
