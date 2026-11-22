use std::io;
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use aws_lc_rs::rand::SystemRandom;

use crate::auth::{Authenticator, ClientIdentity};
use crate::client::{ClientTimeouts, ClientTlsStream, connect_tls};
use crate::envelope::MessagePurpose;
use crate::epoch::KeyEpoch;
use crate::frame::FrameKind;
use crate::net::{AcceptedConnection, ConnectionInfo};
use crate::secure_io::run_encrypted_phase;
use crate::server::{ServerTimeouts, ServerTlsStream, accept_tls};
use crate::session::Session;
use crate::state::ConnectionState;
use crate::tls::build_server_config;
use crate::turn::{Exchange, TurnEvent, TurnState};

static APPLICATION_KEY_RNG: OnceLock<SystemRandom> = OnceLock::new();

/// Timeout policy shared by BRN client and server connections.
///
/// Values apply independently:
/// - handshake: the TLS handshake budget
/// - negotiation: the BRN version-negotiation budget
/// - io: the underlying per-operation socket timeout
#[derive(Debug, Clone, Copy)]
pub struct ConnectionTimeouts {
    handshake: Duration,
    negotiation: Duration,
    io: Duration,
}

impl ConnectionTimeouts {
    pub fn new(handshake: Duration, negotiation: Duration, io: Duration) -> io::Result<Self> {
        if handshake.is_zero() || negotiation.is_zero() || io.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "connection timeouts must all be greater than zero",
            ));
        }

        Ok(Self {
            handshake,
            negotiation,
            io,
        })
    }
}

/// A client connection awaiting BRN application authentication.
///
/// TLS and version negotiation have completed.
/// Application requests are not yet available.
pub struct PendingClient {
    session: Session<ClientTlsStream>,
}

impl PendingClient {
    /// Connects, verifies the server, and negotiates BRN version 1.
    ///
    /// Each trusted CA must be one DER-encoded certificate.
    /// The expected server name is checked independently of the address.
    pub fn connect(
        address: SocketAddr,
        expected_server_name: &str,
        trusted_ca_certificates: &[&[u8]],
        connect_timeout: Duration,
        timeouts: ConnectionTimeouts,
    ) -> io::Result<Self> {
        let client_timeouts =
            ClientTimeouts::new(connect_timeout, timeouts.handshake, timeouts.io)?;

        let mut session = connect_tls(
            address,
            expected_server_name,
            trusted_ca_certificates,
            client_timeouts,
        )?;

        session.negotiate_client_with_deadline(timeouts.negotiation)?;

        Ok(Self { session })
    }

    /// Sends credentials through the established TLS connection.
    ///
    /// Credentials must contain 1..=4096 bytes.
    ///
    /// On failure, this connection is consumed and closed.
    pub fn authenticate(
        mut self,
        credentials: &[u8],
        budget: Duration,
    ) -> io::Result<AuthenticatedClient> {
        self.session.authenticate_client(credentials, budget)?;

        Ok(AuthenticatedClient {
            session: self.session,
        })
    }

    /// Releases the connection without a graceful TLS shutdown.
    pub fn close(mut self) {
        self.session.close();
    }
}

/// Reusable server configuration.
///
/// This does not bind a listener or start worker threads.
/// The application supplies accepted TCP sockets.
pub struct Server {
    config: Arc<rustls::ServerConfig>,
    timeouts: ConnectionTimeouts,
}

impl Server {
    /// Creates a server from a DER certificate chain and PKCS#8 DER key.
    ///
    /// The chain must be ordered leaf first, followed by intermediates.
    /// Do not include the root CA.
    pub fn new(
        certificate_chain: &[&[u8]],
        private_key_pkcs8: &[u8],
        timeouts: ConnectionTimeouts,
    ) -> io::Result<Self> {
        let config = build_server_config(certificate_chain, private_key_pkcs8)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

        Ok(Self {
            config: Arc::new(config),
            timeouts,
        })
    }

    /// Completes TLS and BRN negotiation on an accepted blocking socket.
    ///
    /// The application owns listener policy and connection concurrency.
    /// Completes TLS and BRN negotiation on an accepted blocking socket.
    ///
    /// Retained for applications managing their own TCP listener.
    pub fn accept(&self, socket: TcpStream) -> io::Result<PendingServer> {
        socket.set_nonblocking(false)?;

        let connection_info = ConnectionInfo::from_stream(&socket)?;

        let server_timeouts = ServerTimeouts::new(self.timeouts.handshake, self.timeouts.io)?;

        let mut session = accept_tls(socket, Arc::clone(&self.config), server_timeouts)?;

        session.negotiate_server_with_deadline(self.timeouts.negotiation)?;

        Ok(PendingServer {
            session,
            connection_info,
        })
    }

    /// Completes TLS and BRN negotiation on a core-owned connection.
    pub fn accept_connection(&self, connection: AcceptedConnection) -> io::Result<PendingServer> {
        self.accept(connection.into_stream())
    }
}

/// A server connection awaiting BRN application authentication.
///
/// No client identity has been accepted, and application messages
/// are not yet available.
pub struct PendingServer {
    session: Session<ServerTlsStream>,
    connection_info: ConnectionInfo,
}

impl PendingServer {
    /// Authenticates the client using the application's verifier.
    ///
    /// The verifier must enforce its own backend-operation timeouts.
    ///
    /// On failure, this connection is consumed and closed.
    pub fn authenticate(
        mut self,
        authenticator: &dyn Authenticator,
        budget: Duration,
    ) -> io::Result<AuthenticatedServer> {
        let identity = self.session.authenticate_server(authenticator, budget)?;

        Ok(AuthenticatedServer {
            session: self.session,
            identity,
            connection_info: self.connection_info,
        })
    }

    /// Releases the connection without a graceful TLS shutdown.
    pub fn close(mut self) {
        self.session.close();
    }
}

/// A client connection whose credentials the server has accepted.
///
/// Temporary application keys have not yet been established.
/// Application requests are not available.
pub struct AuthenticatedClient {
    session: Session<ClientTlsStream>,
}

impl AuthenticatedClient {
    /// Receives temporary keys and completes encrypted confirmation.
    ///
    /// On failure, this connection is consumed and closed.
    pub fn establish_keys(mut self, budget: Duration) -> io::Result<ReadyClient> {
        let epoch = self.session.establish_client_keys(budget)?;

        Ok(ReadyClient {
            session: self.session,
            epoch,
            exchange: Exchange::client(),
        })
    }

    /// Releases the connection without a graceful TLS shutdown.
    pub fn close(mut self) {
        self.session.close();
    }
}

/// A server connection associated with an authenticated client identity.
///
/// Temporary application keys have not yet been established.
/// Application requests are not available.
pub struct AuthenticatedServer {
    session: Session<ServerTlsStream>,
    identity: ClientIdentity,
    connection_info: ConnectionInfo,
}

impl AuthenticatedServer {
    /// Returns the identity provided by the application authenticator.
    ///
    /// This does not imply permission to perform any particular operation.
    pub fn identity(&self) -> &ClientIdentity {
        &self.identity
    }

    /// Generates temporary keys, delivers them through TLS, and
    /// completes encrypted confirmation.
    ///
    /// On failure, this connection is consumed and closed.
    pub fn establish_keys(mut self, budget: Duration) -> io::Result<ReadyServer> {
        let rng = APPLICATION_KEY_RNG.get_or_init(SystemRandom::new);

        let epoch = self.session.establish_server_keys(rng, budget)?;

        Ok(ReadyServer {
            session: self.session,
            epoch,
            identity: self.identity,
            exchange: Exchange::server(),
            connection_info: self.connection_info,
        })
    }

    /// Releases the connection without a graceful TLS shutdown.
    pub fn close(mut self) {
        self.session.close();
    }
}

/// A client connection with completed application-key confirmation.
///
/// Requests are sequential: each request must receive its response
/// before another request can begin.
pub struct ReadyClient {
    session: Session<ClientTlsStream>,
    epoch: KeyEpoch,
    exchange: Exchange,
}

impl ReadyClient {
    /// Sends one request and receives its response.
    ///
    /// The budget covers the complete exchange, not each individual
    /// read or write. The epoch's remaining lifetime also limits it.
    ///
    /// Any error permanently closes this connection.
    pub fn request(&mut self, body: &[u8], budget: Duration) -> io::Result<Vec<u8>> {
        let result = (|| {
            if self.exchange.state() != TurnState::ClientCanSend {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "client is not ready to send a request",
                ));
            }

            let exchange = &mut self.exchange;

            run_encrypted_phase(
                &mut self.session,
                &mut self.epoch,
                budget,
                |session, epoch| {
                    let request = epoch.seal(MessagePurpose::Request, body)?;

                    session.send(FrameKind::Encrypted, request.body())?;

                    exchange
                        .advance(TurnEvent::RequestSent)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

                    let frame = session.receive()?.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed before response")
                    })?;

                    let response = epoch.open(frame.body(), MessagePurpose::Response)?;

                    Ok(response.body().to_vec())
                },
            )
            .and_then(|response| {
                // The phase wrapper has checked epoch validity.
                self.exchange
                    .advance(TurnEvent::ResponseReceived)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

                Ok(response)
            })
        })();

        if result.is_err() {
            self.abort_application_exchange();
        }

        result
    }

    /// Releases the connection without a graceful TLS shutdown.
    pub fn close(mut self) {
        self.exchange.close();
        self.session.close();
        drop(self.epoch);
    }

    fn abort_application_exchange(&mut self) {
        self.exchange.close();
        self.session.close();
        self.epoch.disable();
    }

    /// Returns whether BRN has marked this local session closed.
    ///
    /// This does not perform network I/O, detect an unobserved peer
    /// disconnection, or check application-key expiration.
    ///
    /// A false result does not guarantee that the next request
    /// will succeed.
    pub fn is_closed(&self) -> bool {
        self.session.state() == ConnectionState::Closed
    }
}

/// A server connection with an authenticated client and confirmed keys.
///
/// Each received request must be answered before another request
/// can be received.
pub struct ReadyServer {
    session: Session<ServerTlsStream>,
    epoch: KeyEpoch,
    identity: ClientIdentity,
    exchange: Exchange,
    connection_info: ConnectionInfo,
}

impl ReadyServer {
    /// Returns the identity provided by the application authenticator.
    ///
    /// This does not imply permission to perform any particular operation.
    pub fn identity(&self) -> &ClientIdentity {
        &self.identity
    }

    /// Receives and authenticates the next request.
    ///
    /// A response must be sent before receiving another request.
    ///
    /// Any error permanently closes this connection.
    pub fn receive_request(&mut self, budget: Duration) -> io::Result<Vec<u8>> {
        let result = (|| {
            if self.exchange.state() != TurnState::ServerAwaitingRequest {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "server must finish the current response before receiving another request",
                ));
            }

            let request = run_encrypted_phase(
                &mut self.session,
                &mut self.epoch,
                budget,
                |session, epoch| {
                    let frame = session.receive()?.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed before request")
                    })?;

                    let request = epoch.open(frame.body(), MessagePurpose::Request)?;

                    Ok(request.body().to_vec())
                },
            )?;

            self.exchange
                .advance(TurnEvent::RequestReceived)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

            Ok(request)
        })();

        if result.is_err() {
            self.abort_application_exchange();
        }

        result
    }

    /// Sends the response to the most recently received request.
    ///
    /// Any error permanently closes this connection.
    pub fn respond(&mut self, body: &[u8], budget: Duration) -> io::Result<()> {
        let result = (|| {
            if self.exchange.state() != TurnState::ServerMustRespond {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "server cannot respond without a pending request",
                ));
            }

            run_encrypted_phase(
                &mut self.session,
                &mut self.epoch,
                budget,
                |session, epoch| {
                    let response = epoch.seal(MessagePurpose::Response, body)?;

                    session.send(FrameKind::Encrypted, response.body())
                },
            )?;

            self.exchange
                .advance(TurnEvent::ResponseSent)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

            Ok(())
        })();

        if result.is_err() {
            self.abort_application_exchange();
        }

        result
    }

    /// Releases the connection without a graceful TLS shutdown.
    pub fn close(mut self) {
        self.exchange.close();
        self.session.close();
        drop(self.epoch);
    }

    fn abort_application_exchange(&mut self) {
        self.exchange.close();
        self.session.close();
        self.epoch.disable();
    }

    /// Returns whether BRN has marked this local session closed.
    ///
    /// This does not perform network I/O, detect an unobserved peer
    /// disconnection, or check application-key expiration.
    ///
    /// A false result does not guarantee that the next operation
    /// will succeed.
    pub fn is_closed(&self) -> bool {
        self.session.state() == ConnectionState::Closed
    }

    /// Returns the endpoint addresses captured during connection setup.
    ///
    /// Performs no network I/O.
    pub fn connection_info(&self) -> &ConnectionInfo {
        &self.connection_info
    }
}

impl ReadyClient {
    /// Reports this endpoint's remaining local application-key capacity.
    ///
    /// Performs no network I/O and consumes no message counters.
    /// Unlike is_closed(), this checks local key expiration.
    ///
    /// On error, the application exchange is permanently aborted.
    ///
    /// A successful snapshot does not reserve capacity or guarantee
    /// peer availability or successful completion of the next request.
    pub fn application_key_capacity(&mut self) -> io::Result<crate::epoch::ApplicationKeyCapacity> {
        let result = if self.session.state() == ConnectionState::Closed {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "BRN session is closed",
            ))
        } else {
            self.epoch.capacity()
        };

        if result.is_err() {
            self.abort_application_exchange();
        }

        result
    }
}

impl ReadyServer {
    /// Reports this endpoint's remaining local application-key capacity.
    ///
    /// Performs no network I/O and consumes no message counters.
    /// Observed expiration or another reporting error aborts the
    /// application exchange.
    ///
    /// Sending/receiving are relative to this server endpoint.
    pub fn application_key_capacity(&mut self) -> io::Result<crate::epoch::ApplicationKeyCapacity> {
        let result = if self.session.state() == ConnectionState::Closed {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "BRN session is closed",
            ))
        } else {
            self.epoch.capacity()
        };

        if result.is_err() {
            self.abort_application_exchange();
        }

        result
    }
}

#[cfg(test)]
impl ReadyClient {
    pub(crate) fn restrict_capacity_for_test(
        &mut self,
        send_bytes: u64,
        receive_bytes: u64,
        remaining_lifetime: Option<Duration>,
    ) -> io::Result<()> {
        self.epoch
            .restrict_capacity_for_test(send_bytes, receive_bytes, remaining_lifetime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_zero_connection_timeouts() {
        let second = Duration::from_secs(1);

        for (handshake, negotiation, io) in [
            (Duration::ZERO, second, second),
            (second, Duration::ZERO, second),
            (second, second, Duration::ZERO),
        ] {
            let result = ConnectionTimeouts::new(handshake, negotiation, io);

            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn server_rejects_missing_identity() {
        let timeouts = ConnectionTimeouts::new(
            Duration::from_secs(5),
            Duration::from_secs(3),
            Duration::from_secs(2),
        )
        .unwrap();

        let error = match Server::new(&[], &[], timeouts) {
            Ok(_) => panic!("missing server identity was accepted"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn client_rejects_missing_trust_before_connecting() {
        let timeouts = ConnectionTimeouts::new(
            Duration::from_secs(5),
            Duration::from_secs(3),
            Duration::from_secs(2),
        )
        .unwrap();

        let result = PendingClient::connect(
            "127.0.0.1:0".parse().unwrap(),
            "localhost",
            &[],
            Duration::from_secs(1),
            timeouts,
        );

        let error = match result {
            Ok(_) => panic!("missing client trust was accepted"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let tls_error = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
            .expect("expected a wrapped rustls error");

        assert!(
            matches!(
                tls_error,
                rustls::Error::General(message)
                    if message == "at least one trusted CA certificate is required"
            ),
            "unexpected underlying error: {tls_error:?}"
        );
    }
}
