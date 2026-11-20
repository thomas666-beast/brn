//! BRN provides blocking, authenticated client/server communication.
//!
//! # Connection setup
//!
//! A client progresses through these public connection types:
//!
//! - [`PendingClient`]: TLS and BRN version negotiation have completed.
//! - [`AuthenticatedClient`]: the server has accepted the credentials.
//! - [`ReadyClient`]: application keys have been established and confirmed.
//!
//! The server uses the corresponding [`PendingServer`],
//! [`AuthenticatedServer`], and [`ReadyServer`] types.
//!
//! Application operations are available only on ready connections.
//!
//! # Sequential request/response
//!
//! [`ReadyClient::request`] sends one request and receives its response.
//! Its operation budget covers the complete exchange.
//!
//! The server calls [`ReadyServer::receive_request`] and then
//! [`ReadyServer::respond`]. It must respond before receiving another
//! request. Each server operation has its own budget; application work
//! between them is not included in either operation's budget.
//!
//! BRN does not provide multiplexed requests or server-initiated
//! application messages through this API.
//!
//! # Application payloads
//!
//! Each request or response may contain at most
//! [`MAX_APPLICATION_PAYLOAD_LEN`] plaintext bytes. Empty payloads are
//! supported. The limit counts bytes, not characters.
//!
//! Returned application payloads are owned `Vec<u8>` values. Applications
//! are responsible for their use, copies, storage, and cleanup; these
//! returned vectors are not automatically zeroized by BRN.
//!
//! # Timeouts and expiration
//!
//! [`ConnectionTimeouts`] configures TLS-handshake, BRN-negotiation,
//! and underlying per-operation socket timeouts.
//!
//! Authentication, key establishment, and application operations also
//! accept explicit phase budgets. Application-operation budgets are
//! capped by the remaining application-key lifetime.
//!
//! Deadlines do not provide hard real-time guarantees or preempt
//! arbitrary application CPU work. Application authentication verifiers
//! must enforce their own backend-operation timeouts.
//!
//! Key expiration is checked during operations. BRN does not run a
//! background timer that automatically closes idle ready connections.
//!
//! # Failure behavior
//!
//! An error from a ready connection's application operation closes its
//! local session and disables its application-key epoch. That connection
//! cannot be reused; establish a new connection instead.
//!
//! A failed request does not establish whether the peer already processed
//! it. BRN does not automatically retry application requests.
//!
//! # Identity and shutdown
//!
//! A server-side [`ClientIdentity`] identifies the authenticated client;
//! it does not by itself authorize a particular application operation.
//!
//! The public connection `close` methods release the connection without
//! performing a graceful TLS shutdown.

mod api;
mod auth;
mod auth_exchange;
mod auth_wire;
mod client;
mod envelope;
mod epoch;
mod frame;
mod handshake;
mod key_exchange;
mod key_wire;
mod keys;
mod negotiation;
mod open;
mod phase;
mod policy;
mod seal;
mod secure_io;
mod sequence;
mod server;
mod session;
mod state;
mod tls;
mod transport;
mod turn;
mod wire;

pub use api::{
    AuthenticatedClient, AuthenticatedServer, ConnectionTimeouts, PendingClient, PendingServer,
    ReadyClient, ReadyServer, Server,
};

pub use auth::{AuthenticationError, Authenticator, ClientIdentity, InvalidIdentity};

/// Maximum plaintext payload size for one application request or response.
///
/// This limit excludes BRN framing, encrypted-envelope metadata, and
/// the authentication tag. It counts bytes, not characters.
///
/// Empty payloads are supported. Applications may check this limit before
/// calling a sending operation. Passing an oversized payload to a ready
/// connection's sending operation returns an error and closes that
/// connection.
pub const MAX_APPLICATION_PAYLOAD_LEN: usize = seal::MAX_PLAINTEXT_LEN;

#[cfg(test)]
mod tls_tests;

#[cfg(test)]
mod connection_tests;

// Parser harnesses are available only to tests and fuzzing builds.
#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod fuzz_support;

#[cfg(any(test, fuzzing))]
#[doc(hidden)]
pub mod fuzz_open;
