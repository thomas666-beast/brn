use std::fs;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::client::{ClientTimeouts, connect_tls};
use crate::server::{ServerTimeouts, accept_tls};
use crate::state::ConnectionState;
use crate::tls::build_server_config;

fn development_file(name: &str) -> io::Result<Vec<u8>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("certs")
        .join(name);

    fs::read(&path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot read development fixture {}: {error}",
                path.display()
            ),
        )
    })
}

/// Bounds how long the test server waits for a TCP connection.
fn accept_with_timeout(listener: &TcpListener, timeout: Duration) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;

    let started = Instant::now();

    loop {
        if started.elapsed() >= timeout {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "test server timed out waiting for a connection",
            ));
        }

        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false)?;
                return Ok(socket);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
}

#[test]
fn loopback_tls_and_brn_negotiation_succeed() -> io::Result<()> {
    let ca = development_file("ca.cert.der")?;
    let certificate = development_file("server.cert.der")?;
    let private_key = development_file("server.key.der")?;

    let server_config = Arc::new(
        build_server_config(&[certificate.as_slice()], &private_key).map_err(io::Error::other)?,
    );

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;

    let server_timeouts = ServerTimeouts::new(Duration::from_secs(5), Duration::from_secs(2))?;

    let client_timeouts = ClientTimeouts::new(
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(2),
    )?;

    let server_thread = thread::spawn(move || -> io::Result<ConnectionState> {
        let socket = accept_with_timeout(&listener, Duration::from_secs(5))?;

        let mut session = accept_tls(socket, server_config, server_timeouts)?;

        if session.state() != ConnectionState::Negotiating {
            return Err(io::Error::other(
                "server did not enter Negotiating after TLS",
            ));
        }

        session.negotiate_server_with_deadline(Duration::from_secs(3))?;

        let state = session.state();
        session.close();

        Ok(state)
    });

    // Keep this result without returning early so the server thread
    // is joined even when the client operation fails.
    let client_result = (|| -> io::Result<ConnectionState> {
        let mut session = connect_tls(address, "localhost", &[ca.as_slice()], client_timeouts)?;

        if session.state() != ConnectionState::Negotiating {
            return Err(io::Error::other(
                "client did not enter Negotiating after TLS",
            ));
        }

        session.negotiate_client_with_deadline(Duration::from_secs(3))?;

        let state = session.state();
        session.close();

        Ok(state)
    })();

    let server_result = server_thread
        .join()
        .map_err(|_| io::Error::other("test server thread panicked"))?;

    let client_state = client_result?;
    let server_state = server_result?;

    assert_eq!(client_state, ConnectionState::Authenticating);
    assert_eq!(server_state, ConnectionState::Authenticating);

    Ok(())
}

#[test]
fn public_api_authentication_succeeds_over_tls() -> io::Result<()> {
    use crate::{
        AuthenticationError, Authenticator, ClientIdentity, ConnectionTimeouts, PendingClient,
        Server,
    };

    // Test double only. This is not a credential-verification algorithm.
    struct TestAuthenticator;

    impl Authenticator for TestAuthenticator {
        fn authenticate(&self, credentials: &[u8]) -> Result<ClientIdentity, AuthenticationError> {
            assert_eq!(credentials, b"loopback-test-credential");

            ClientIdentity::new("loopback-client").map_err(|_| AuthenticationError::Unavailable)
        }
    }

    let ca = development_file("ca.cert.der")?;
    let certificate = development_file("server.cert.der")?;
    let key = development_file("server.key.der")?;

    let timeouts = ConnectionTimeouts::new(
        Duration::from_secs(5),
        Duration::from_secs(3),
        Duration::from_secs(2),
    )?;

    let server = Server::new(&[certificate.as_slice()], &key, timeouts)?;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;

    let server_thread = thread::spawn(move || -> io::Result<String> {
        let socket = accept_with_timeout(&listener, Duration::from_secs(5))?;

        let pending = server.accept(socket)?;

        let authenticated = pending.authenticate(&TestAuthenticator, Duration::from_secs(3))?;

        let identity = authenticated.identity().as_str().to_owned();

        authenticated.close();

        Ok(identity)
    });

    let client_result = (|| -> io::Result<()> {
        let pending = PendingClient::connect(
            address,
            "localhost",
            &[ca.as_slice()],
            Duration::from_secs(2),
            timeouts,
        )?;

        let authenticated =
            pending.authenticate(b"loopback-test-credential", Duration::from_secs(3))?;

        authenticated.close();

        Ok(())
    })();

    // Join even if the client operation failed.
    let server_result = server_thread
        .join()
        .map_err(|_| io::Error::other("authentication test server panicked"))?;

    client_result?;

    assert_eq!(server_result?, "loopback-client");

    Ok(())
}

#[test]
fn public_api_completes_authentication_and_key_confirmation() -> io::Result<()> {
    use crate::{
        AuthenticationError, Authenticator, ClientIdentity, ConnectionTimeouts, PendingClient,
        Server,
    };

    // Test double only; not a production credential verifier.
    struct TestAuthenticator;

    impl Authenticator for TestAuthenticator {
        fn authenticate(&self, credentials: &[u8]) -> Result<ClientIdentity, AuthenticationError> {
            assert_eq!(credentials, b"full-setup-test");

            ClientIdentity::new("confirmed-client").map_err(|_| AuthenticationError::Unavailable)
        }
    }

    let ca = development_file("ca.cert.der")?;
    let certificate = development_file("server.cert.der")?;
    let key = development_file("server.key.der")?;

    let timeouts = ConnectionTimeouts::new(
        Duration::from_secs(5),
        Duration::from_secs(3),
        Duration::from_secs(2),
    )?;

    let server = Server::new(&[certificate.as_slice()], &key, timeouts)?;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;

    let server_thread = thread::spawn(move || -> io::Result<String> {
        let socket = accept_with_timeout(&listener, Duration::from_secs(5))?;

        let mut ready = server
            .accept(socket)?
            .authenticate(&TestAuthenticator, Duration::from_secs(3))?
            .establish_keys(Duration::from_secs(3))?;

        let identity = ready.identity().as_str().to_owned();

        for (request, response) in [
            (b"ping".as_slice(), b"pong".as_slice()),
            (b"second request".as_slice(), b"second response".as_slice()),
        ] {
            assert_eq!(ready.receive_request(Duration::from_secs(3))?, request);
            ready.respond(response, Duration::from_secs(3))?;
        }

        ready.close();

        Ok(identity)
    });

    let client_result = (|| -> io::Result<()> {
        let mut ready = PendingClient::connect(
            address,
            "localhost",
            &[ca.as_slice()],
            Duration::from_secs(2),
            timeouts,
        )?
        .authenticate(b"full-setup-test", Duration::from_secs(3))?
        .establish_keys(Duration::from_secs(3))?;

        for (request, response) in [
            (b"ping".as_slice(), b"pong".as_slice()),
            (b"second request".as_slice(), b"second response".as_slice()),
        ] {
            assert_eq!(ready.request(request, Duration::from_secs(3))?, response);
        }

        ready.close();

        Ok(())
    })();

    let server_result = server_thread
        .join()
        .map_err(|_| io::Error::other("full-setup test server panicked"))?;

    client_result?;

    assert_eq!(server_result?, "confirmed-client");

    Ok(())
}

/// Runs public-API operations on a fresh authenticated loopback pair.
/// Both endpoints use the existing development certificate fixtures.
fn with_ready_pair<C, S>(client_operation: C, server_operation: S) -> io::Result<()>
where
    C: FnOnce(crate::api::ReadyClient) -> io::Result<()>,
    S: FnOnce(crate::api::ReadyServer) -> io::Result<()> + Send + 'static,
{
    use crate::{
        AuthenticationError, Authenticator, ClientIdentity, ConnectionTimeouts, PendingClient,
        Server,
    };

    struct TestAuthenticator;

    impl Authenticator for TestAuthenticator {
        fn authenticate(&self, credentials: &[u8]) -> Result<ClientIdentity, AuthenticationError> {
            if credentials != b"failure-path-test" {
                return Err(AuthenticationError::Unavailable);
            }

            ClientIdentity::new("failure-path-client").map_err(|_| AuthenticationError::Unavailable)
        }
    }

    let ca = development_file("ca.cert.der")?;
    let certificate = development_file("server.cert.der")?;
    let key = development_file("server.key.der")?;
    let timeouts = ConnectionTimeouts::new(
        Duration::from_secs(5),
        Duration::from_secs(3),
        Duration::from_secs(2),
    )?;
    let server = Server::new(&[certificate.as_slice()], &key, timeouts)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;

    let server_thread = thread::spawn(move || -> io::Result<()> {
        let socket = accept_with_timeout(&listener, Duration::from_secs(5))?;
        let ready = server
            .accept(socket)?
            .authenticate(&TestAuthenticator, Duration::from_secs(3))?
            .establish_keys(Duration::from_secs(3))?;

        server_operation(ready)
    });

    // Join the server even when client setup fails or a client assertion panics.
    let client_result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> io::Result<()> {
            let ready = PendingClient::connect(
                address,
                "localhost",
                &[ca.as_slice()],
                Duration::from_secs(2),
                timeouts,
            )?
            .authenticate(b"failure-path-test", Duration::from_secs(3))?
            .establish_keys(Duration::from_secs(3))?;

            client_operation(ready)
        }));

    let server_result = server_thread.join();

    let client_result = match client_result {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    };
    let server_result =
        server_result.map_err(|_| io::Error::other("failure-path test server panicked"))?;

    client_result?;
    server_result
}

#[test]
fn public_api_rejects_response_without_request() -> io::Result<()> {
    let (done_tx, done_rx) = std::sync::mpsc::channel();

    with_ready_pair(
        move |ready| {
            // Keep the client alive until the server checks local misuse.
            let outcome = done_rx.recv_timeout(Duration::from_secs(5));
            ready.close();
            outcome.map_err(io::Error::other)?;
            Ok(())
        },
        move |mut ready| {
            let first = ready
                .respond(b"unsolicited", Duration::from_secs(1))
                .unwrap_err();
            assert_eq!(first.kind(), io::ErrorKind::InvalidInput);

            // Failure must make even a normally valid next operation fail.
            assert!(ready.receive_request(Duration::from_secs(1)).is_err());
            assert!(ready.respond(b"retry", Duration::from_secs(1)).is_err());

            done_tx.send(()).map_err(io::Error::other)?;
            ready.close();
            Ok(())
        },
    )
}

#[test]
fn public_api_rejects_second_receive_before_response() -> io::Result<()> {
    with_ready_pair(
        |mut ready| {
            assert!(ready.request(b"first", Duration::from_secs(3)).is_err());
            assert!(ready.request(b"retry", Duration::from_secs(1)).is_err());
            ready.close();
            Ok(())
        },
        |mut ready| {
            assert_eq!(ready.receive_request(Duration::from_secs(3))?, b"first");

            let error = ready.receive_request(Duration::from_secs(1)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(ready.respond(b"too late", Duration::from_secs(1)).is_err());

            ready.close();
            Ok(())
        },
    )
}

#[test]
fn public_api_request_fails_when_peer_closes_before_response() -> io::Result<()> {
    with_ready_pair(
        |mut ready| {
            let error = ready
                .request(b"close instead of responding", Duration::from_secs(3))
                .unwrap_err();

            // Abrupt TLS/TCP close details can vary. It must not succeed
            // or wait until the request deadline in this orderly test case.
            assert!(matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ));
            assert!(ready.request(b"retry", Duration::from_secs(1)).is_err());

            ready.close();
            Ok(())
        },
        |mut ready| {
            assert_eq!(
                ready.receive_request(Duration::from_secs(3))?,
                b"close instead of responding"
            );
            ready.close();
            Ok(())
        },
    )
}

#[test]
fn public_api_response_timeout_prevents_connection_reuse() -> io::Result<()> {
    let (release_tx, release_rx) = std::sync::mpsc::channel();

    with_ready_pair(
        move |mut ready| {
            let result = ready.request(b"withhold response", Duration::from_millis(300));

            // Release the server before any assertion can panic. It stays
            // connected during the request, rather than using EOF to end it.
            let released = release_tx.send(());
            let error = result.unwrap_err();

            assert!(matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ));
            released.map_err(io::Error::other)?;
            assert!(ready.request(b"retry", Duration::from_secs(1)).is_err());

            ready.close();
            Ok(())
        },
        move |mut ready| {
            assert_eq!(
                ready.receive_request(Duration::from_secs(3))?,
                b"withhold response"
            );

            // Deliberately do not respond. Synchronization, not a sleep,
            // keeps the connection open until the client operation ends.
            release_rx
                .recv_timeout(Duration::from_secs(5))
                .map_err(io::Error::other)?;

            ready.close();
            Ok(())
        },
    )
}

#[test]
fn public_api_zero_request_budget_prevents_connection_reuse() -> io::Result<()> {
    with_ready_pair(
        |mut ready| {
            let error = ready
                .request(b"must not be sent", Duration::ZERO)
                .unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

            assert!(ready.request(b"retry", Duration::from_secs(1)).is_err());

            ready.close();
            Ok(())
        },
        |mut ready| {
            // The client rejects its zero budget and closes without
            // sending an application request.
            assert!(ready.receive_request(Duration::from_secs(3)).is_err());

            assert!(ready.receive_request(Duration::from_secs(1)).is_err());

            ready.close();
            Ok(())
        },
    )
}

#[test]
fn public_api_zero_receive_budget_prevents_connection_reuse() -> io::Result<()> {
    let (done_tx, done_rx) = std::sync::mpsc::channel();

    with_ready_pair(
        move |ready| {
            // Keep the client connected without sending anything.
            // The server must reject its local budget, not rely on EOF.
            let result = done_rx.recv_timeout(Duration::from_secs(5));

            ready.close();

            result.map_err(io::Error::other)?;
            Ok(())
        },
        move |mut ready| {
            let error = ready.receive_request(Duration::ZERO).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

            assert!(ready.receive_request(Duration::from_secs(1)).is_err());

            assert!(ready.respond(b"retry", Duration::from_secs(1)).is_err());

            done_tx.send(()).map_err(io::Error::other)?;

            ready.close();
            Ok(())
        },
    )
}

#[test]
fn public_api_zero_response_budget_prevents_connection_reuse() -> io::Result<()> {
    with_ready_pair(
        |mut ready| {
            assert!(ready.request(b"request", Duration::from_secs(3)).is_err());

            assert!(ready.request(b"retry", Duration::from_secs(1)).is_err());

            ready.close();
            Ok(())
        },
        |mut ready| {
            assert_eq!(ready.receive_request(Duration::from_secs(3))?, b"request");

            // There is a pending request, so the application turn
            // permits responding. The zero budget must cause failure.
            let error = ready
                .respond(b"must not be sent", Duration::ZERO)
                .unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

            assert!(ready.respond(b"retry", Duration::from_secs(1)).is_err());

            assert!(ready.receive_request(Duration::from_secs(1)).is_err());

            ready.close();
            Ok(())
        },
    )
}

#[test]
fn public_api_payload_boundaries_round_trip() -> io::Result<()> {
    with_ready_pair(
        |mut ready| {
            // Run multiple exchanges on the same connection to verify
            // that boundary-sized messages preserve turn ordering.
            for length in [0, crate::seal::MAX_PLAINTEXT_LEN, 1] {
                let request = vec![0x35; length];
                let expected_response = vec![0xa7; length];

                let response = ready.request(&request, Duration::from_secs(5))?;

                assert_eq!(
                    response, expected_response,
                    "response mismatch for payload length {length}"
                );
            }

            ready.close();
            Ok(())
        },
        |mut ready| {
            for length in [0, crate::seal::MAX_PLAINTEXT_LEN, 1] {
                let expected_request = vec![0x35; length];

                let request = ready.receive_request(Duration::from_secs(5))?;

                assert_eq!(
                    request, expected_request,
                    "request mismatch for payload length {length}"
                );

                let response = vec![0xa7; length];

                ready.respond(&response, Duration::from_secs(5))?;
            }

            ready.close();
            Ok(())
        },
    )
}

#[test]
fn public_api_payload_oversized_request_prevents_reuse() -> io::Result<()> {
    with_ready_pair(
        |mut ready| {
            let oversized = vec![0x35; crate::seal::MAX_PLAINTEXT_LEN + 1];

            assert!(ready.request(&oversized, Duration::from_secs(3),).is_err());

            // A valid-sized retry must not revive the connection.
            assert!(
                ready
                    .request(b"valid-sized retry", Duration::from_secs(1),)
                    .is_err()
            );

            ready.close();
            Ok(())
        },
        |mut ready| {
            // The client must fail locally rather than deliver a
            // truncated or otherwise successful application request.
            assert!(ready.receive_request(Duration::from_secs(3)).is_err());

            assert!(ready.receive_request(Duration::from_secs(1)).is_err());

            ready.close();
            Ok(())
        },
    )
}

#[test]
fn public_api_payload_oversized_response_prevents_reuse() -> io::Result<()> {
    with_ready_pair(
        |mut ready| {
            assert!(
                ready
                    .request(b"send an oversized response", Duration::from_secs(3),)
                    .is_err()
            );

            assert!(
                ready
                    .request(b"valid-sized retry", Duration::from_secs(1),)
                    .is_err()
            );

            ready.close();
            Ok(())
        },
        |mut ready| {
            assert_eq!(
                ready.receive_request(Duration::from_secs(3))?,
                b"send an oversized response"
            );

            let oversized = vec![0xa7; crate::seal::MAX_PLAINTEXT_LEN + 1];

            assert!(ready.respond(&oversized, Duration::from_secs(3),).is_err());

            // A response was pending before the oversized operation.
            // Neither responding again nor receiving may now succeed.
            assert!(
                ready
                    .respond(b"valid-sized retry", Duration::from_secs(1),)
                    .is_err()
            );

            assert!(ready.receive_request(Duration::from_secs(1)).is_err());

            ready.close();
            Ok(())
        },
    )
}

#[test]
fn public_api_closed_status_tracks_local_failure() -> io::Result<()> {
    with_ready_pair(
        |mut ready| {
            assert!(!ready.is_closed());

            let error = ready.request(b"not sent", Duration::ZERO).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

            assert!(ready.is_closed());

            // Another operation must not revive the connection.
            assert!(ready.request(b"retry", Duration::from_secs(1)).is_err());

            assert!(ready.is_closed());

            ready.close();
            Ok(())
        },
        |mut ready| {
            // This reports local state. The peer may already have
            // closed, but this session has not observed that yet.
            assert!(!ready.is_closed());

            assert!(ready.receive_request(Duration::from_secs(3)).is_err());

            assert!(ready.is_closed());

            ready.close();
            Ok(())
        },
    )
}

/// Runs public TLS + BRN negotiation without authentication.
///
/// None selects the existing v1 API.
/// Some(policy) selects the explicit v2 API.
fn run_public_version_pair(
    client_policy: Option<crate::api::PaddingPolicy>,
    server_policy: Option<crate::api::PaddingPolicy>,
) -> io::Result<(io::Result<()>, io::Result<()>)> {
    use crate::{ConnectionTimeouts, PendingClient, Server};

    let ca = development_file("ca.cert.der")?;
    let certificate = development_file("server.cert.der")?;
    let key = development_file("server.key.der")?;

    let timeouts = ConnectionTimeouts::new(
        Duration::from_secs(5),
        Duration::from_secs(3),
        Duration::from_secs(2),
    )?;

    let server = Server::new(&[certificate.as_slice()], &key, timeouts)?;

    let server = match server_policy {
        None => server,
        Some(policy) => server.with_padding(policy),
    };

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;

    let server_thread = thread::spawn(move || -> io::Result<()> {
        let socket = accept_with_timeout(&listener, Duration::from_secs(5))?;
        let pending = server.accept(socket)?;
        pending.close();
        Ok(())
    });

    let client_result = (|| -> io::Result<()> {
        let pending = match client_policy {
            None => PendingClient::connect(
                address,
                "localhost",
                &[ca.as_slice()],
                Duration::from_secs(2),
                timeouts,
            )?,
            Some(policy) => PendingClient::connect_with_padding(
                address,
                "localhost",
                &[ca.as_slice()],
                Duration::from_secs(2),
                timeouts,
                policy,
            )?,
        };

        pending.close();
        Ok(())
    })();

    let server_result = server_thread
        .join()
        .map_err(|_| io::Error::other("version-boundary server panicked"))?;

    Ok((client_result, server_result))
}

#[test]
fn public_alpn_v1_to_v1_succeeds() -> io::Result<()> {
    let (client_result, server_result) = run_public_version_pair(None, None)?;

    client_result?;
    server_result?;

    Ok(())
}

#[test]
fn public_alpn_v2_matching_policies_succeed() -> io::Result<()> {
    use crate::api::PaddingPolicy;

    for policy in [
        PaddingPolicy::Disabled,
        PaddingPolicy::Optional,
        PaddingPolicy::Required,
    ] {
        let (client_result, server_result) = run_public_version_pair(Some(policy), Some(policy))?;

        assert!(
            client_result.is_ok(),
            "v2 client failed for {policy:?}: {client_result:?}"
        );
        assert!(
            server_result.is_ok(),
            "v2 server failed for {policy:?}: {server_result:?}"
        );
    }

    Ok(())
}

/// Requires a local TLS no-overlapping-ALPN error, rather than
/// accepting any arbitrary connection failure as a passing test.
fn assert_server_alpn_mismatch(error: &io::Error) {
    let tls_error = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>());

    assert!(
        matches!(tls_error, Some(rustls::Error::NoApplicationProtocol)),
        "expected server TLS NoApplicationProtocol, got: {error:?}"
    );
}

#[test]
fn public_alpn_v1_client_to_v2_server_is_rejected() -> io::Result<()> {
    use crate::api::PaddingPolicy;

    for policy in [
        PaddingPolicy::Disabled,
        PaddingPolicy::Optional,
        PaddingPolicy::Required,
    ] {
        let (client_result, server_result) = run_public_version_pair(None, Some(policy))?;

        assert!(
            client_result.is_err(),
            "v1 client unexpectedly connected to v2 server with {policy:?}"
        );

        let server_error = server_result.expect_err("v2 server unexpectedly accepted a v1 client");

        assert_server_alpn_mismatch(&server_error);
    }

    Ok(())
}

#[test]
fn public_alpn_v2_client_to_v1_server_is_rejected() -> io::Result<()> {
    use crate::api::PaddingPolicy;

    for policy in [
        PaddingPolicy::Disabled,
        PaddingPolicy::Optional,
        PaddingPolicy::Required,
    ] {
        let (client_result, server_result) = run_public_version_pair(Some(policy), None)?;

        assert!(
            client_result.is_err(),
            "v2 client with {policy:?} unexpectedly connected to v1 server"
        );

        let server_error = server_result.expect_err("v1 server unexpectedly accepted a v2 client");

        assert_server_alpn_mismatch(&server_error);
    }

    Ok(())
}

#[test]
fn public_v2_incompatible_padding_policies_are_rejected() -> io::Result<()> {
    use crate::api::PaddingPolicy::{Disabled, Required};

    for (client_policy, server_policy) in [(Required, Disabled), (Disabled, Required)] {
        let (client_result, server_result) =
            run_public_version_pair(Some(client_policy), Some(server_policy))?;

        let client_error =
            client_result.expect_err("client accepted incompatible padding policies");

        let server_error =
            server_result.expect_err("server accepted incompatible padding policies");

        assert_eq!(
            server_error.kind(),
            io::ErrorKind::InvalidData,
            "unexpected server error for client={client_policy:?}, \
             server={server_policy:?}: {server_error:?}",
        );

        assert_eq!(
            server_error.to_string(),
            "no common padding profile",
            "server must reject the profile intersection, \
             not fail for an unrelated reason",
        );

        // The server closes without selecting a profile. The client's
        // transport error can vary, but negotiation must not succeed.
        assert!(
            matches!(
                client_error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ),
            "unexpected client error for client={client_policy:?}, \
             server={server_policy:?}: {client_error:?}",
        );
    }

    Ok(())
}

#[test]
fn public_v2_required_padding_preserves_application_payloads() -> io::Result<()> {
    use crate::api::PaddingPolicy;
    use crate::{
        AuthenticationError, Authenticator, ClientIdentity, ConnectionTimeouts, PendingClient,
        Server,
    };

    struct TestAuthenticator;

    impl Authenticator for TestAuthenticator {
        fn authenticate(&self, credentials: &[u8]) -> Result<ClientIdentity, AuthenticationError> {
            if credentials != b"v2-padding-round-trip" {
                return Err(AuthenticationError::Unavailable);
            }

            ClientIdentity::new("v2-padding-client").map_err(|_| AuthenticationError::Unavailable)
        }
    }

    let ca = development_file("ca.cert.der")?;
    let certificate = development_file("server.cert.der")?;
    let key = development_file("server.key.der")?;

    let timeouts = ConnectionTimeouts::new(
        Duration::from_secs(5),
        Duration::from_secs(3),
        Duration::from_secs(2),
    )?;

    let server = Server::new(&[certificate.as_slice()], &key, timeouts)?
        .with_padding(PaddingPolicy::Required);

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let budget = Duration::from_secs(5);
    let payloads: Vec<Vec<u8>> = [0usize, 1, 251, 252, 253, 507, 508, 509, 513, 61_436]
        .into_iter()
        .map(|length| (0..length).map(|index| (index % 256) as u8).collect())
        .collect();

    let expected_requests = payloads.clone();

    let server_thread = thread::spawn(move || -> io::Result<()> {
        let socket = accept_with_timeout(&listener, budget)?;

        let mut ready = server
            .accept(socket)?
            .authenticate(&TestAuthenticator, budget)?
            .establish_keys(budget)?;

        for expected in expected_requests {
            let actual = ready.receive_request(budget)?;

            if actual != expected {
                return Err(io::Error::other("v2 request payload was not preserved"));
            }

            let response: Vec<u8> = expected.iter().map(|byte| byte ^ 0xff).collect();

            ready.respond(&response, budget)?;
        }

        ready.close();
        Ok(())
    });

    let client_result = (|| -> io::Result<()> {
        let mut ready = PendingClient::connect_with_padding(
            address,
            "localhost",
            &[ca.as_slice()],
            Duration::from_secs(2),
            timeouts,
            PaddingPolicy::Required,
        )?
        .authenticate(b"v2-padding-round-trip", budget)?
        .establish_keys(budget)?;

        for request in payloads {
            let expected_response: Vec<u8> = request.iter().map(|byte| byte ^ 0xff).collect();

            let actual = ready.request(&request, budget)?;

            if actual != expected_response {
                return Err(io::Error::other("v2 response payload was not preserved"));
            }
        }

        ready.close();
        Ok(())
    })();

    let server_result = server_thread
        .join()
        .map_err(|_| io::Error::other("v2 round-trip server panicked"))?;

    client_result?;
    server_result?;

    Ok(())
}

#[test]
fn public_v2_oversized_padded_request_prevents_reuse() -> io::Result<()> {
    use crate::api::PaddingPolicy;
    use crate::{
        AuthenticationError, Authenticator, ClientIdentity, ConnectionTimeouts, PendingClient,
        Server,
    };

    struct TestAuthenticator;

    impl Authenticator for TestAuthenticator {
        fn authenticate(&self, credentials: &[u8]) -> Result<ClientIdentity, AuthenticationError> {
            if credentials != b"v2-oversized-request" {
                return Err(AuthenticationError::Unavailable);
            }

            ClientIdentity::new("v2-oversized-client").map_err(|_| AuthenticationError::Unavailable)
        }
    }

    let ca = development_file("ca.cert.der")?;
    let certificate = development_file("server.cert.der")?;
    let key = development_file("server.key.der")?;

    let timeouts = ConnectionTimeouts::new(
        Duration::from_secs(5),
        Duration::from_secs(3),
        Duration::from_secs(2),
    )?;

    let server = Server::new(&[certificate.as_slice()], &key, timeouts)?
        .with_padding(PaddingPolicy::Required);

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let budget = Duration::from_secs(5);

    let server_thread = thread::spawn(move || -> io::Result<()> {
        let socket = accept_with_timeout(&listener, budget)?;

        let mut ready = server
            .accept(socket)?
            .authenticate(&TestAuthenticator, budget)?
            .establish_keys(budget)?;

        // The client should reject its request locally and close.
        // No application request should be delivered successfully.
        assert!(ready.receive_request(budget).is_err());
        assert!(ready.is_closed());

        assert!(ready.receive_request(budget).is_err());
        assert!(ready.respond(b"late response", budget).is_err());

        ready.close();
        Ok(())
    });

    // Catch client assertions so the server thread is still joined.
    let client_result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> io::Result<()> {
            let mut ready = PendingClient::connect_with_padding(
                address,
                "localhost",
                &[ca.as_slice()],
                Duration::from_secs(2),
                timeouts,
                PaddingPolicy::Required,
            )?
            .authenticate(b"v2-oversized-request", budget)?
            .establish_keys(budget)?;

            let oversized = vec![0xa5; 61_437];

            let error = ready
                .request(&oversized, budget)
                .expect_err("oversized padded request unexpectedly succeeded");

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(ready.is_closed());

            assert!(ready.request(b"valid-sized retry", budget).is_err());
            assert!(ready.is_closed());

            ready.close();
            Ok(())
        }));

    let server_result = server_thread.join();

    let client_result = match client_result {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    };

    let server_result =
        server_result.map_err(|_| io::Error::other("oversized-request server panicked"))?;

    client_result?;
    server_result?;

    Ok(())
}

#[test]
fn public_v2_oversized_padded_response_prevents_reuse() -> io::Result<()> {
    use crate::api::PaddingPolicy;
    use crate::{
        AuthenticationError, Authenticator, ClientIdentity, ConnectionTimeouts, PendingClient,
        Server,
    };

    struct TestAuthenticator;

    impl Authenticator for TestAuthenticator {
        fn authenticate(&self, credentials: &[u8]) -> Result<ClientIdentity, AuthenticationError> {
            if credentials != b"v2-oversized-response" {
                return Err(AuthenticationError::Unavailable);
            }

            ClientIdentity::new("v2-oversized-client").map_err(|_| AuthenticationError::Unavailable)
        }
    }

    let ca = development_file("ca.cert.der")?;
    let certificate = development_file("server.cert.der")?;
    let key = development_file("server.key.der")?;

    let timeouts = ConnectionTimeouts::new(
        Duration::from_secs(5),
        Duration::from_secs(3),
        Duration::from_secs(2),
    )?;

    let server = Server::new(&[certificate.as_slice()], &key, timeouts)?
        .with_padding(PaddingPolicy::Required);

    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let budget = Duration::from_secs(5);

    let server_thread = thread::spawn(move || -> io::Result<()> {
        let socket = accept_with_timeout(&listener, budget)?;

        let mut ready = server
            .accept(socket)?
            .authenticate(&TestAuthenticator, budget)?
            .establish_keys(budget)?;

        // Receive a valid request before attempting the oversized response.
        let _request = ready.receive_request(budget)?;

        let oversized = vec![0xa5; 61_437];

        let error = ready
            .respond(&oversized, budget)
            .expect_err("oversized padded response unexpectedly succeeded");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(ready.is_closed());

        // Neither sending nor receiving may revive the connection.
        assert!(ready.respond(b"valid-sized retry", budget).is_err());
        assert!(ready.receive_request(budget).is_err());
        assert!(ready.is_closed());

        ready.close();
        Ok(())
    });

    // Catch client assertions so the server thread is still joined.
    let client_result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> io::Result<()> {
            let mut ready = PendingClient::connect_with_padding(
                address,
                "localhost",
                &[ca.as_slice()],
                Duration::from_secs(2),
                timeouts,
                PaddingPolicy::Required,
            )?
            .authenticate(b"v2-oversized-response", budget)?
            .establish_keys(budget)?;

            // The server receives this request, but its oversized
            // response must fail rather than reach the client.
            assert!(ready.request(b"valid request", budget).is_err());
            assert!(ready.is_closed());

            // A valid-sized retry must not revive the connection.
            assert!(ready.request(b"valid-sized retry", budget).is_err());
            assert!(ready.is_closed());

            ready.close();
            Ok(())
        }));

    let server_result = server_thread.join();

    let client_result = match client_result {
        Ok(result) => result,
        Err(payload) => std::panic::resume_unwind(payload),
    };

    let server_result =
        server_result.map_err(|_| io::Error::other("oversized-response server panicked"))?;

    client_result?;
    server_result?;

    Ok(())
}
