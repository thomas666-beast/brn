# BRN security contract

Status: draft
Protocol version: 1

## Purpose

BRN provides application-to-application communication with:

1. A mandatory authenticated TLS connection.
2. Additional authenticated encryption of application message bodies.
3. Temporary application keys issued by the server through TLS.

BRN is not considered production-ready until its implementation,
tests, dependency choices, and security design have been reviewed.

## Trust boundaries

- Clients must verify the server's identity.
- TLS must terminate in the BRN endpoint for the initial implementation.
- There is no plaintext mode or automatic security downgrade.
- Additional body encryption does not protect against a compromised
  endpoint that can access plaintext or application keys.
- Client authentication does not grant permission for every operation.
- Application keys are secrets, not client identity credentials.

## Connection lifecycle

The intended sequence is:

1. Establish TCP.
2. Complete TLS 1.3 and verify the server.
3. Exchange BRN version information.
4. Authenticate the client.
5. Server issues temporary application keys through TLS.
6. Client proves receipt using an authenticated confirmation.
7. Exchange body-encrypted application messages.
8. Close the connection and release session resources.

Application requests are forbidden before step 6 succeeds.

TLS early data is disabled.

The client authentication mechanism will be selected before this
sequence is implemented.

## Application keys

- Keys must come from an operating-system-backed cryptographic RNG.
- Each connection receives fresh application keys.
- Client-to-server and server-to-client keys are distinct.
- Keys must not be reused across connections.
- Keys must not appear in logs or public debugging output.
- Keys must not be saved to disk by the BRN library.
- A key identifier is not a secret and must not contain key material.

## Temporary-key policy

The first implementation uses one application-key epoch per connection.

A connection must close when its key lifetime or cryptographic usage
limit is reached. Continuing requires a new authenticated connection
and fresh application keys.

In-place key rotation is deferred until a separate, tested transition
protocol exists.

Exact lifetime, byte, and message limits must be selected before
encryption is enabled. Limits must respect the selected algorithm.

## Encrypted messages

- Use a maintained authenticated-encryption implementation.
- Never repeat a nonce under the same key.
- Maintain independent send and receive sequence counters.
- Do not allow counters to wrap.
- Authenticate security-relevant frame metadata as associated data.
- Reject unexpected sequence numbers.
- Do not deliver plaintext before authentication succeeds.
- Close on authentication failure or invalid protocol state.

Sequence checking does not guarantee exactly-once application
execution across retries or reconnections.

## Resource limits

Before accepting untrusted traffic, define and enforce:

- Maximum frame size.
- Maximum plaintext body size.
- Maximum simultaneous connections.
- Maximum in-flight requests per connection.
- Maximum queued outbound bytes per connection.
- TLS handshake deadline.
- BRN negotiation and authentication deadlines.
- Incomplete-frame deadline.
- Idle connection deadline.

Peer-supplied lengths must be validated before allocating body buffers.

## Failure behavior

- Fail closed.
- Do not silently retry using weaker settings.
- Never log credentials, application keys, or plaintext bodies by default.
- Expose structured errors without secret material.
- Reject unsupported versions explicitly.

## Unresolved decisions

These must be resolved before the relevant implementation:

- Server certificate provisioning and trust configuration.
- Client authentication mechanism.
- Application authenticated-encryption algorithm.
- Key lifetime and algorithm-specific usage limits.
- Wire format and authenticated metadata.
- Post-quantum requirements.

No post-quantum security claim is made by this draft.
