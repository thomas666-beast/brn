# BRN

BRN is a Rust library for blocking, authenticated client/server communication with sequential encrypted request/response exchanges.

It combines authenticated TLS 1.3, application-level client authentication, and short-lived directional application-encryption keys. Application-operation failures permanently close the local connection rather than permitting reuse of a partially completed exchange.

**Status:** version 0.1.0, under development. Targeted reviews, regression tests, and initial local fuzz campaigns have been performed; BRN has not undergone an independent security audit. This is not a claim of production security readiness.

## Current scope

- Blocking TCP communication through rustls.
- TLS 1.3 with certificate-chain and expected-server-name verification.
- Required ALPN protocol: `brn/1`.
- Application-supplied client credential verification.
- Authenticated client identities supplied by the verifier.
- Temporary AES-256-GCM application keys, separated by direction.
- Encrypted, role-specific key confirmation.
- Sequential client request followed by server response.
- Bounded payload sizes, message counts, and plaintext-byte usage.
- Per-operation socket timeouts and absolute protocol-phase deadlines.
- Fail-closed application operations and local closed-state reporting.
- Deterministic regression tests and six fuzz targets.

BRN does not currently provide async I/O, multiplexed requests, server-initiated application messages, streaming bodies, automatic reconnection, or in-connection application-key renewal.

## Architecture

```text
Application request/response bytes
              |
              v
Temporary application-key encryption
AES-256-GCM + direction + purpose + sequence
              |
              v
BRN framing
              |
              v
Authenticated TLS 1.3 (rustls)
              |
              v
Blocking TCP
```

The server generates temporary application keys and delivers them inside the established authenticated TLS connection. This is not an independent public-key key-agreement protocol. Its trust and confidentiality depend on the authenticated TLS channel.

The application-key layer provides explicit application-message authentication, direction/purpose binding, sequencing, and bounded key usage. It does not replace TLS verification or protect plaintext from a compromised endpoint.

## Connection lifecycle

### Client

```text
PendingClient::connect(...)
    -> PendingClient
    -> authenticate(...)
    -> AuthenticatedClient
    -> establish_keys(...)
    -> ReadyClient
    -> request(...) repeatedly
```

### Server

```text
Server::new(...)
    -> accept(an accepted TCP socket)
    -> PendingServer
    -> authenticate(...)
    -> AuthenticatedServer
    -> establish_keys(...)
    -> ReadyServer
    -> receive_request(...)
    -> respond(...)
    -> repeat
```

Application operations are exposed only on ready connection types. A successful server authentication supplies a `ClientIdentity`; the application remains responsible for authorizing individual operations.

The application owns its listener, connection-admission policy, and connection concurrency. `Server` does not bind a listener or start worker threads.

## Using BRN

BRN uses Rust edition 2024. For a local checkout, add it to another project's `Cargo.toml` using the appropriate relative path:

```toml
[dependencies]
brn = { path = "../brn" }
```

This example does not assume a crates.io release exists.

### Client request

```rust
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use brn::{ConnectionTimeouts, PendingClient};

fn exchange(
    address: SocketAddr,
    expected_server_name: &str,
    trusted_ca_der: &[u8],
    credentials: &[u8],
    request_body: &[u8],
) -> io::Result<Vec<u8>> {
    let timeouts = ConnectionTimeouts::new(
        Duration::from_secs(5), // TLS handshake
        Duration::from_secs(3), // BRN negotiation
        Duration::from_secs(2), // Per-operation socket timeout
    )?;

    let mut client = PendingClient::connect(
        address,
        expected_server_name,
        &[trusted_ca_der],
        Duration::from_secs(2), // TCP connect timeout
        timeouts,
    )?
    .authenticate(credentials, Duration::from_secs(3))?
    .establish_keys(Duration::from_secs(3))?;

    let response = client.request(request_body, Duration::from_secs(5))?;
    client.close();
    Ok(response)
}
```

Each trust input must contain one DER-encoded certificate. The expected server name is verified independently of the destination socket address. Obtain credentials securely; do not log or hard-code production credentials.

### Server responsibilities

1. Create a `Server` using its DER certificate chain, unencrypted PKCS#8 DER private key, and timeout policy.
2. Accept TCP sockets under the application's admission policy.
3. Pass each accepted socket to `Server::accept`.
4. Supply an `Authenticator` implementation to verify the client's credentials.
5. Establish application keys.
6. Alternate `receive_request` and `respond` on the ready connection.

An `Authenticator` returns either a `ClientIdentity` or an `AuthenticationError`. Its synchronous callback must enforce its own backend-operation timeouts. A BRN phase budget cannot interrupt a callback that does not return.

## Limits

These are the current implementation policies, not a general security proof:

| Item | Current limit |
|---|---:|
| Application request or response plaintext | 60 KiB / 61,440 bytes |
| Client credentials | 1 through 4,096 bytes |
| Outer frame body | 64 KiB / 65,536 bytes |
| Application-key epoch lifetime | 15 minutes |
| Messages per directional application key | 2^20 / 1,048,576 |
| Plaintext bytes per directional application key | 1 GiB / 1,073,741,824 bytes |

Key-confirmation messages consume the same directional message counters and plaintext-byte budgets as later application messages. Counters are not reset after confirmation.

Empty application payloads are supported. They consume message sequences even though they add no plaintext bytes to the byte budget.

Use `brn::MAX_APPLICATION_PAYLOAD_LEN` rather than duplicating the payload limit in application code. An oversized send through a ready connection is a terminal operation error.

## Timeouts and expiration

`ConnectionTimeouts` separately configures the TLS handshake, BRN negotiation, and underlying per-operation socket timeout. The client also supplies a separate TCP connection timeout.

Authentication, key establishment, and ready-connection operations accept explicit phase budgets.

- A client request budget covers sending the request and receiving its response together.
- Server receive and respond operations each have their own budget.
- Application processing between server receive and respond is not included in either operation's budget.
- Application-operation budgets are capped by the epoch's remaining lifetime.
- Phase deadlines are absolute; repeated I/O does not restart them.
- Deadline checks do not provide hard real-time execution or preempt arbitrary CPU work.

Expiration is checked during operations. There is no background timer that automatically closes an idle expired connection. Reconnect and establish fresh keys when the current connection becomes unusable.

## Failure and shutdown behavior

Any error from a ready connection's application operation closes its local session, closes its exchange state, and disables its application-key epoch. Do not retry on that connection.

A failed request does not establish whether the server already processed it. BRN does not automatically retry requests or provide exactly-once application execution. Applications must decide whether retrying an operation on a new connection is safe.

`is_closed()` reports local session state only. It performs no network I/O, does not detect an unobserved peer disconnect, and does not check key expiration. A false result is not a promise that the next operation will succeed.

Public `close` methods release the connection without performing a graceful TLS shutdown.

## Security boundaries

- TLS authenticates the server to the client; application credentials authenticate the client to the server.
- The current TLS configuration does not require client certificates.
- Client identity does not itself grant authorization.
- Credential and key-bearing BRN buffers use zeroizing storage where implemented; sensitive debug fields are redacted.
- Returned application payloads are ordinary owned `Vec<u8>` values and are not automatically zeroized.
- Cleanup does not guarantee erasure of caller copies, verifier copies, provider-internal buffers, operating-system memory, or previously logged data.
- Dropping key owners releases BRN's ownership; it is not a blanket claim about all copies of key material.
- Application key owners and sequence allocators must never be recreated for an existing key.

Do not log credentials, raw keys, or encoded credential/key offers. Never use the repository's disposable fixture keys as deployment credentials.

## Development and tests

The TLS tests require:

```text
certs/ca.cert.der
certs/server.cert.der
certs/server.key.der
```

Generate disposable fixtures using OpenSSL:

```sh
bash scripts/generate-test-certs.sh
```

The script refuses to replace existing fixtures. To intentionally regenerate only those disposable test files:

```sh
bash scripts/generate-test-certs.sh --force
```

Do not use `--force` against deployment credentials. The script creates short-lived fixtures; regenerate them when needed.

Run the checks:

```sh
cargo fmt --all --check
cargo fmt --manifest-path fuzz/Cargo.toml --all --check
cargo test --locked --all-targets
cargo test --locked --release --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo doc --locked --no-deps
```

Run the adversarial regression batches:

```sh
cargo test --locked --lib adversarial_tests
```

The suite includes framing, session failures, phase orchestration, transport deadlines, authentication, key establishment, envelope opening, sealing, epoch lifecycle, and encrypted-phase cleanup.

Tests and fuzz campaigns improve confidence but do not establish the absence of vulnerabilities.

## Fuzzing

Install the tooling without changing the default development toolchain:

```sh
rustup toolchain install nightly
cargo install --locked cargo-fuzz
```

Build the fuzz targets from the project root:

```sh
cargo +nightly fuzz build
```

Available targets:

| Target | Coverage |
|---|---|
| `frame_header` | Outer-header parsing and canonical encoding |
| `authentication` | Credential-message and reply parsing |
| `key_offer` | Key-offer validation and canonical reconstruction |
| `envelope_header` | Envelope metadata and associated-data layout |
| `open_arbitrary` | Arbitrary input, successful-opening invariants, and disabled-owner behavior |
| `open_mutated` | Valid round-trips followed by tampering, wrong-key/purpose, replay, or skipped-sequence cases |

Example bounded campaign:

```sh
cargo +nightly fuzz run open_mutated -- \
  -max_total_time=60 \
  -max_len=65536
```

Preserve useful regression seeds in `fuzz/corpus/`. Keep both the root and fuzz-project lockfiles committed. Generated findings and logs may contain fuzz input; review artifacts before sharing them.

Fuzz-only access modules are compiled for tests or `cfg(fuzzing)` and are absent from ordinary library builds.

## GitHub Actions

The workflow setup consists of:

- `.github/workflows/ci.yml`: formatting, debug/release tests, strict Clippy, and documentation, with fresh disposable TLS fixtures.
- `.github/workflows/fuzz.yml`: short campaigns across all six fuzz targets on pushes and pull requests, longer weekly campaigns, and manual execution.

Check the repository's Actions tab for the actual results. Workflow configuration alone is not evidence that a GitHub run has passed.

## Roadmap

The immediate focus is consolidating the blocking request/response core:

1. Validate CI on clean GitHub runners.
2. Extend fuzz campaigns and turn findings into regression tests.
3. Document and measure latency, throughput, and resource use.
4. Define bounded multi-client admission and shutdown policy.
5. Consider a separate native async API if measured requirements justify it.

Multiplexing, server-initiated messaging, streaming, and in-connection rekeying require separate designs and are not commitments of the current API.

## Contributing

Keep changes focused and include regression tests for bug fixes. Preserve protocol ordering, key-owner uniqueness, bounded resource use, and terminal-failure behavior. Changes to the wire format or security policy need explicit review.

Never include deployment keys, live credentials, or sensitive production payloads in issues, tests, logs, or fuzz corpora.
