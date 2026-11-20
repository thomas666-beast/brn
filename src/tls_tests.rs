use std::error::Error;
use std::io::{self, Cursor};
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

use crate::tls::{ALPN_PROTOCOL, build_client_config, build_server_config};

type TestResult<T> = Result<T, Box<dyn Error>>;

fn development_file(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("certs")
        .join(name);

    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "cannot read development fixture {}: {error}; \
             generate the certificates from Task 13",
            path.display()
        )
    })
}

fn configurations() -> TestResult<(ClientConfig, ServerConfig)> {
    let ca = development_file("ca.cert.der");
    let certificate = development_file("server.cert.der");
    let key = development_file("server.key.der");

    let client = build_client_config(&[ca.as_slice()])?;
    let server = build_server_config(&[certificate.as_slice()], &key)?;

    Ok((client, server))
}

/// Exchanges real TLS records using memory buffers.
///
/// The iteration limit is a test-harness safeguard, not a production
/// handshake timeout.
fn handshake(
    client_config: ClientConfig,
    server_config: ServerConfig,
    server_name: &'static str,
) -> TestResult<(ClientConnection, ServerConnection)> {
    let name = ServerName::try_from(server_name)?;

    let mut client = ClientConnection::new(Arc::new(client_config), name)?;

    let mut server = ServerConnection::new(Arc::new(server_config))?;

    for _ in 0..64 {
        let mut transferred = 0;

        let mut client_records = Vec::new();

        while client.wants_write() {
            let count = client.write_tls(&mut client_records)?;

            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "client made no TLS write progress",
                )
                .into());
            }
        }

        transferred += client_records.len();

        let mut client_records = Cursor::new(client_records);

        while client_records.position() < client_records.get_ref().len() as u64 {
            let count = server.read_tls(&mut client_records)?;

            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "server made no TLS read progress",
                )
                .into());
            }

            server.process_new_packets()?;
        }

        let mut server_records = Vec::new();

        while server.wants_write() {
            let count = server.write_tls(&mut server_records)?;

            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "server made no TLS write progress",
                )
                .into());
            }
        }

        transferred += server_records.len();

        let mut server_records = Cursor::new(server_records);

        while server_records.position() < server_records.get_ref().len() as u64 {
            let count = client.read_tls(&mut server_records)?;

            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client made no TLS read progress",
                )
                .into());
            }

            client.process_new_packets()?;
        }

        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok((client, server));
        }

        if transferred == 0 {
            return Err(io::Error::other("TLS handshake stalled").into());
        }
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "TLS handshake exceeded the test iteration limit",
    )
    .into())
}

#[test]
fn trusted_localhost_completes_tls13_with_brn_alpn() -> TestResult<()> {
    let (client_config, server_config) = configurations()?;

    let (client, server) = handshake(client_config, server_config, "localhost")?;

    assert!(!client.is_handshaking());
    assert!(!server.is_handshaking());

    assert_eq!(
        client.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        server.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );

    assert_eq!(client.alpn_protocol(), Some(ALPN_PROTOCOL));
    assert_eq!(server.alpn_protocol(), Some(ALPN_PROTOCOL));

    Ok(())
}

#[test]
fn incorrect_server_name_is_rejected() -> TestResult<()> {
    let (client_config, server_config) = configurations()?;

    let error = handshake(client_config, server_config, "not-localhost.invalid").unwrap_err();

    assert!(
        matches!(
            error.downcast_ref::<rustls::Error>(),
            Some(rustls::Error::InvalidCertificate(_))
        ),
        "expected a certificate verification failure, got: {error}"
    );

    Ok(())
}

#[test]
fn incompatible_alpn_is_rejected() -> TestResult<()> {
    let (mut client_config, server_config) = configurations()?;

    client_config.alpn_protocols = vec![b"other-protocol/1".to_vec()];

    let error = handshake(client_config, server_config, "localhost").unwrap_err();

    assert!(
        matches!(
            error.downcast_ref::<rustls::Error>(),
            Some(rustls::Error::NoApplicationProtocol)
        ),
        "expected an ALPN negotiation failure, got: {error}"
    );

    Ok(())
}
