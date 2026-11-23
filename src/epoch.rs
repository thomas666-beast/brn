use std::io;
use std::time::{Duration, Instant};

use crate::envelope::{Direction, MessagePurpose};
use crate::keys::TemporaryKeys;
use crate::open::{MessageOpener, OpenedMessage};
use crate::padding::PaddingMode;
use crate::seal::{MessageSealer, SealedMessage};

pub(crate) const KEY_LIFETIME: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, Copy)]
enum EndpointRole {
    Client,
    Server,
}

/// Directional owners are removed together when their epoch is disabled.
#[derive(Debug)]
struct EpochKeys {
    sender: MessageSealer,
    receiver: MessageOpener,
}

/// Owns application encryption for one endpoint of one connection.
///
/// Not Clone or Copy. A sealing/opening error, observed expiration,
/// or explicit disablement drops both directional key owners.
/// The connection owner must also close its session on failure.
///
/// Expiration is checked on use; no background timer runs here.
#[derive(Debug)]
pub(crate) struct KeyEpoch {
    keys: Option<EpochKeys>,
    expires_at: Instant,
}

impl KeyEpoch {
    #[cfg(test)]
    pub(crate) fn for_client(keys: TemporaryKeys) -> io::Result<Self> {
        Self::new_at(keys, EndpointRole::Client, Instant::now())
    }

    #[cfg(test)]
    pub(crate) fn for_server(keys: TemporaryKeys) -> io::Result<Self> {
        Self::new_at(keys, EndpointRole::Server, Instant::now())
    }

    pub(crate) fn for_client_with_padding(
        keys: TemporaryKeys,
        padding: PaddingMode,
    ) -> io::Result<Self> {
        Self::new_at_with_padding(keys, EndpointRole::Client, Instant::now(), padding)
    }

    pub(crate) fn for_server_with_padding(
        keys: TemporaryKeys,
        padding: PaddingMode,
    ) -> io::Result<Self> {
        Self::new_at_with_padding(keys, EndpointRole::Server, Instant::now(), padding)
    }

    #[cfg(test)]
    fn new_at(keys: TemporaryKeys, role: EndpointRole, now: Instant) -> io::Result<Self> {
        Self::new_at_with_padding(keys, role, now, PaddingMode::Disabled)
    }

    fn new_at_with_padding(
        keys: TemporaryKeys,
        role: EndpointRole,
        now: Instant,
        padding: PaddingMode,
    ) -> io::Result<Self> {
        let expires_at = now.checked_add(KEY_LIFETIME).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "application-key lifetime is too large",
            )
        })?;

        let (sender, receiver) = match role {
            EndpointRole::Client => (
                MessageSealer::new_with_padding(
                    keys.client_to_server(),
                    Direction::ClientToServer,
                    padding,
                )?,
                MessageOpener::new_with_padding(
                    keys.server_to_client(),
                    Direction::ServerToClient,
                    padding,
                )?,
            ),
            EndpointRole::Server => (
                MessageSealer::new_with_padding(
                    keys.server_to_client(),
                    Direction::ServerToClient,
                    padding,
                )?,
                MessageOpener::new_with_padding(
                    keys.client_to_server(),
                    Direction::ClientToServer,
                    padding,
                )?,
            ),
        };

        Ok(Self {
            keys: Some(EpochKeys { sender, receiver }),
            expires_at,
        })
    }

    pub(crate) fn seal(
        &mut self,
        purpose: MessagePurpose,
        plaintext: &[u8],
    ) -> io::Result<SealedMessage> {
        self.ensure_live_at(Instant::now())?;

        let result = self
            .keys
            .as_mut()
            .ok_or_else(disabled_error)?
            .sender
            .seal(purpose, plaintext);

        if result.is_err() {
            self.disable();
            return result;
        }

        // A successful result is dropped if expiration occurred during work.
        self.ensure_live_at(Instant::now())?;
        result
    }

    pub(crate) fn open(
        &mut self,
        body: &[u8],
        expected_purpose: MessagePurpose,
    ) -> io::Result<OpenedMessage> {
        self.ensure_live_at(Instant::now())?;

        let result = self
            .keys
            .as_mut()
            .ok_or_else(disabled_error)?
            .receiver
            .open(body, expected_purpose);

        if result.is_err() {
            self.disable();
            return result;
        }

        // Verified plaintext is dropped rather than returned if expired.
        self.ensure_live_at(Instant::now())?;
        result
    }

    fn ensure_live_at(&mut self, now: Instant) -> io::Result<()> {
        if self.keys.is_none() {
            return Err(disabled_error());
        }

        if now >= self.expires_at {
            self.disable();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "application-key epoch expired; reconnect with fresh keys",
            ));
        }

        Ok(())
    }

    /// Returns the smaller of the requested budget and remaining lifetime.
    /// A zero budget is rejected; the phase wrapper handles connection cleanup.
    pub(crate) fn operation_budget(&mut self, requested: Duration) -> io::Result<Duration> {
        self.operation_budget_at(requested, Instant::now())
    }

    /// Checks the epoch immediately before returning an operation result.
    pub(crate) fn verify_live(&mut self) -> io::Result<()> {
        self.ensure_live_at(Instant::now())
    }

    /// Permanently disables the epoch and drops both directional owners.
    /// This releases BRN's ownership, not a guarantee about all provider copies.
    pub(crate) fn disable(&mut self) {
        drop(self.keys.take());
    }

    fn operation_budget_at(&mut self, requested: Duration, now: Instant) -> io::Result<Duration> {
        if requested.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "operation budget must be greater than zero",
            ));
        }

        self.ensure_live_at(now)?;

        let remaining = match self.expires_at.checked_duration_since(now) {
            Some(remaining) if !remaining.is_zero() => remaining,
            _ => {
                self.disable();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "application-key epoch expired",
                ));
            }
        };

        Ok(requested.min(remaining))
    }

    /// Reports the sender's application-body format limit.
    ///
    /// Does not reserve capacity or check expiration.
    pub(crate) fn max_application_payload_len(&self) -> io::Result<usize> {
        self.keys
            .as_ref()
            .ok_or_else(disabled_error)?
            .sender
            .max_application_payload_len()
    }
}

fn disabled_error() -> io::Error {
    io::Error::other("application-key epoch is disabled")
}

#[cfg(test)]
impl KeyEpoch {
    pub(crate) fn restrict_capacity_for_test(
        &mut self,
        send_bytes: u64,
        receive_bytes: u64,
        remaining_lifetime: Option<Duration>,
    ) -> io::Result<()> {
        let now = Instant::now();
        self.ensure_live_at(now)?;

        if let Some(lifetime) = remaining_lifetime {
            let requested_expiration = now.checked_add(lifetime).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "test lifetime overflow")
            })?;

            // Never extend the existing epoch.
            self.expires_at = self.expires_at.min(requested_expiration);
        }

        let keys = self.keys.as_mut().ok_or_else(disabled_error)?;

        keys.sender.restrict_plaintext_capacity_for_test(send_bytes);

        keys.receiver
            .restrict_plaintext_capacity_for_test(receive_bytes);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material() -> TemporaryKeys {
        // Fixed test data only, never production key generation.
        let mut bytes = [0x11; 64];
        bytes[32..].fill(0x22);

        TemporaryKeys::from_bytes(&bytes).unwrap()
    }

    fn pair() -> (KeyEpoch, KeyEpoch) {
        (
            KeyEpoch::for_client(material()).unwrap(),
            KeyEpoch::for_server(material()).unwrap(),
        )
    }

    #[test]
    fn maps_request_and_response_keys_correctly() {
        let (mut client, mut server) = pair();

        let request = client.seal(MessagePurpose::Request, b"request").unwrap();

        let opened_request = server
            .open(request.body(), MessagePurpose::Request)
            .unwrap();

        assert_eq!(opened_request.body(), b"request");

        let response = server.seal(MessagePurpose::Response, b"response").unwrap();

        let opened_response = client
            .open(response.body(), MessagePurpose::Response)
            .unwrap();

        assert_eq!(opened_response.body(), b"response");
    }

    #[test]
    fn confirmation_consumes_sequences_in_both_directions() {
        let (mut client, mut server) = pair();

        let client_confirmation = client
            .seal(MessagePurpose::KeyConfirmation, b"client-confirm")
            .unwrap();

        assert_eq!(client_confirmation.sequence(), 0);

        server
            .open(client_confirmation.body(), MessagePurpose::KeyConfirmation)
            .unwrap();

        let server_confirmation = server
            .seal(MessagePurpose::KeyConfirmation, b"server-confirm")
            .unwrap();

        assert_eq!(server_confirmation.sequence(), 0);

        client
            .open(server_confirmation.body(), MessagePurpose::KeyConfirmation)
            .unwrap();

        let request = client.seal(MessagePurpose::Request, b"request").unwrap();

        assert_eq!(request.sequence(), 1);

        server
            .open(request.body(), MessagePurpose::Request)
            .unwrap();

        let response = server.seal(MessagePurpose::Response, b"response").unwrap();

        assert_eq!(response.sequence(), 1);

        client
            .open(response.body(), MessagePurpose::Response)
            .unwrap();
    }

    #[test]
    fn expires_at_the_exact_boundary_and_stays_disabled() {
        let now = Instant::now();

        let mut epoch = KeyEpoch::new_at(material(), EndpointRole::Client, now).unwrap();

        let boundary = now.checked_add(KEY_LIFETIME).unwrap();

        assert!(epoch.ensure_live_at(now).is_ok());

        assert_eq!(
            epoch.ensure_live_at(boundary).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );

        // A later check cannot reactivate the epoch, even if the
        // supplied test instant is earlier.
        assert!(epoch.ensure_live_at(now).is_err());

        assert!(epoch.seal(MessagePurpose::Request, b"x").is_err());
    }

    #[test]
    fn authentication_failure_disables_both_directions() {
        let (mut client, mut server) = pair();

        let request = client.seal(MessagePurpose::Request, b"request").unwrap();

        let mut modified = request.body().to_vec();
        let last = modified.len() - 1;
        modified[last] ^= 1;

        assert!(server.open(&modified, MessagePurpose::Request).is_err());

        assert!(server.seal(MessagePurpose::Response, b"response").is_err());

        assert!(
            server
                .open(request.body(), MessagePurpose::Request)
                .is_err()
        );
    }

    #[test]
    fn invalid_sending_purpose_disables_epoch() {
        let (mut client, _) = pair();

        assert!(client.seal(MessagePurpose::Response, b"invalid").is_err());

        assert!(client.seal(MessagePurpose::Request, b"valid").is_err());
    }

    #[test]
    fn operation_budget_is_capped_by_remaining_lifetime() {
        let now = Instant::now();

        let mut epoch = KeyEpoch::new_at(material(), EndpointRole::Client, now).unwrap();

        let near_expiry = now
            .checked_add(KEY_LIFETIME - Duration::from_secs(2))
            .unwrap();

        assert_eq!(
            epoch
                .operation_budget_at(Duration::from_secs(10), near_expiry,)
                .unwrap(),
            Duration::from_secs(2)
        );

        assert_eq!(
            epoch
                .operation_budget_at(Duration::from_secs(1), near_expiry,)
                .unwrap(),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn zero_operation_budget_is_rejected() {
        let mut epoch = KeyEpoch::for_client(material()).unwrap();

        assert_eq!(
            epoch.operation_budget(Duration::ZERO).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn maximum_configured_payload_round_trips_in_both_directions() {
        use crate::envelope::{AUTH_TAG_LEN, ENVELOPE_HEADER_LEN};
        use crate::frame::MAX_BODY_LEN;
        use crate::seal::MAX_PLAINTEXT_LEN;

        let overhead = ENVELOPE_HEADER_LEN + AUTH_TAG_LEN;
        assert!(MAX_PLAINTEXT_LEN <= MAX_BODY_LEN as usize - overhead);

        let (mut client, mut server) = pair();
        let payload = vec![0x5a; MAX_PLAINTEXT_LEN];

        let request = client.seal(MessagePurpose::Request, &payload).unwrap();
        assert_eq!(request.body().len(), payload.len() + overhead);
        let opened = server
            .open(request.body(), MessagePurpose::Request)
            .unwrap();
        assert_eq!(opened.body(), payload.as_slice());

        let response = server.seal(MessagePurpose::Response, &payload).unwrap();
        assert_eq!(response.body().len(), payload.len() + overhead);
        let opened = client
            .open(response.body(), MessagePurpose::Response)
            .unwrap();
        assert_eq!(opened.body(), payload.as_slice());
    }

    #[test]
    fn empty_application_payloads_round_trip_in_both_directions() {
        use crate::envelope::{AUTH_TAG_LEN, ENVELOPE_HEADER_LEN};

        let (mut client, mut server) = pair();

        let request = client.seal(MessagePurpose::Request, b"").unwrap();
        assert_eq!(request.body().len(), ENVELOPE_HEADER_LEN + AUTH_TAG_LEN);
        let opened = server
            .open(request.body(), MessagePurpose::Request)
            .unwrap();
        assert!(opened.body().is_empty());

        let response = server.seal(MessagePurpose::Response, b"").unwrap();
        assert_eq!(response.body().len(), ENVELOPE_HEADER_LEN + AUTH_TAG_LEN);
        let opened = client
            .open(response.body(), MessagePurpose::Response)
            .unwrap();
        assert!(opened.body().is_empty());
    }

    #[test]
    fn oversized_request_disables_client_epoch_in_both_directions() {
        let (mut client, mut server) = pair();
        let valid_response = server.seal(MessagePurpose::Response, b"valid").unwrap();
        let oversized = vec![0; crate::seal::MAX_PLAINTEXT_LEN + 1];

        assert!(client.seal(MessagePurpose::Request, &oversized).is_err());
        assert!(client.seal(MessagePurpose::Request, b"retry").is_err());
        assert!(
            client
                .open(valid_response.body(), MessagePurpose::Response)
                .is_err()
        );
        assert!(client.verify_live().is_err());
    }

    #[test]
    fn oversized_response_disables_server_epoch_in_both_directions() {
        let (mut client, mut server) = pair();
        let valid_request = client.seal(MessagePurpose::Request, b"valid").unwrap();
        let oversized = vec![0; crate::seal::MAX_PLAINTEXT_LEN + 1];

        assert!(server.seal(MessagePurpose::Response, &oversized).is_err());
        assert!(server.seal(MessagePurpose::Response, b"retry").is_err());
        assert!(
            server
                .open(valid_request.body(), MessagePurpose::Request)
                .is_err()
        );
        assert!(server.verify_live().is_err());
    }

    #[test]
    fn expired_epoch_rejects_sealing_and_disables_receiving() {
        let (mut client, mut server) = pair();

        // Prepare a valid incoming message before expiring the client.
        let response = server
            .seal(MessagePurpose::Response, b"valid response")
            .unwrap();

        // No sleep: the next operation must observe expiration.
        client.expires_at = Instant::now();

        let error = client
            .seal(MessagePurpose::Request, b"must not be sealed")
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        assert!(
            client
                .open(response.body(), MessagePurpose::Response)
                .is_err()
        );

        assert!(client.seal(MessagePurpose::Request, b"retry").is_err());

        assert!(client.verify_live().is_err());
    }

    #[test]
    fn expired_epoch_rejects_opening_and_disables_sending() {
        let (mut client, mut server) = pair();

        let request = client
            .seal(MessagePurpose::Request, b"valid request")
            .unwrap();

        server.expires_at = Instant::now();

        let error = server
            .open(request.body(), MessagePurpose::Request)
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        assert!(
            server
                .seal(MessagePurpose::Response, b"must not be sealed")
                .is_err()
        );

        assert!(
            server
                .open(request.body(), MessagePurpose::Request)
                .is_err()
        );

        assert!(server.verify_live().is_err());
    }

    #[test]
    fn operation_budget_at_expiration_permanently_disables_epoch() {
        let created_at = Instant::now();

        let mut epoch = KeyEpoch::new_at(material(), EndpointRole::Client, created_at).unwrap();

        let expires_at = epoch.expires_at;

        let error = epoch
            .operation_budget_at(Duration::from_secs(1), expires_at)
            .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        // An earlier supplied instant must not revive an epoch
        // once expiration has disabled it.
        assert!(
            epoch
                .operation_budget_at(Duration::from_secs(1), created_at,)
                .is_err()
        );

        assert!(epoch.seal(MessagePurpose::Request, b"retry").is_err());

        assert!(epoch.verify_live().is_err());
    }

    #[test]
    fn replayed_request_disables_server_epoch() {
        let (mut client, mut server) = pair();

        let request = client
            .seal(MessagePurpose::Request, b"original request")
            .unwrap();

        let opened = server
            .open(request.body(), MessagePurpose::Request)
            .unwrap();

        assert_eq!(opened.body(), b"original request");
        drop(opened);

        // The exact same authenticated envelope must not be
        // accepted a second time.
        assert!(
            server
                .open(request.body(), MessagePurpose::Request)
                .is_err()
        );

        // Prepare the genuinely next message. A replay failure
        // must disable the epoch, not merely reject one envelope.
        let next_request = client
            .seal(MessagePurpose::Request, b"next request")
            .unwrap();

        assert!(
            server
                .open(next_request.body(), MessagePurpose::Request)
                .is_err()
        );

        assert!(server.seal(MessagePurpose::Response, b"response").is_err());

        assert!(server.verify_live().is_err());
    }

    #[test]
    fn replayed_response_disables_client_epoch() {
        let (mut client, mut server) = pair();

        let response = server
            .seal(MessagePurpose::Response, b"original response")
            .unwrap();

        let opened = client
            .open(response.body(), MessagePurpose::Response)
            .unwrap();

        assert_eq!(opened.body(), b"original response");
        drop(opened);

        assert!(
            client
                .open(response.body(), MessagePurpose::Response)
                .is_err()
        );

        let next_response = server
            .seal(MessagePurpose::Response, b"next response")
            .unwrap();

        assert!(
            client
                .open(next_response.body(), MessagePurpose::Response)
                .is_err()
        );

        assert!(client.seal(MessagePurpose::Request, b"request").is_err());

        assert!(client.verify_live().is_err());
    }

    #[test]
    fn reflected_request_is_not_accepted_as_response() {
        let (mut client, mut server) = pair();

        let request = client
            .seal(MessagePurpose::Request, b"outgoing request")
            .unwrap();

        // Simulate receiving our own outgoing request envelope
        // where an incoming response is expected.
        assert!(
            client
                .open(request.body(), MessagePurpose::Response)
                .is_err()
        );

        // Even a genuine response must not revive the client epoch.
        let response = server
            .seal(MessagePurpose::Response, b"genuine response")
            .unwrap();

        assert!(
            client
                .open(response.body(), MessagePurpose::Response)
                .is_err()
        );

        assert!(client.seal(MessagePurpose::Request, b"retry").is_err());

        assert!(client.verify_live().is_err());
    }

    #[test]
    fn skipped_request_sequence_disables_server_epoch() {
        let (mut client, mut server) = pair();

        let first = client.seal(MessagePurpose::Request, b"first").unwrap();

        let second = client.seal(MessagePurpose::Request, b"second").unwrap();

        assert_eq!(first.sequence(), 0);
        assert_eq!(second.sequence(), 1);

        // The server expects sequence zero, not sequence one.
        assert!(server.open(second.body(), MessagePurpose::Request).is_err());

        // Delivering the missing message afterward must not
        // recover an epoch that has already failed.
        assert!(server.open(first.body(), MessagePurpose::Request).is_err());

        assert!(server.seal(MessagePurpose::Response, b"response").is_err());

        assert!(server.verify_live().is_err());
    }

    #[test]
    fn skipped_response_sequence_disables_client_epoch() {
        let (mut client, mut server) = pair();

        let first = server.seal(MessagePurpose::Response, b"first").unwrap();

        let second = server.seal(MessagePurpose::Response, b"second").unwrap();

        assert_eq!(first.sequence(), 0);
        assert_eq!(second.sequence(), 1);

        assert!(
            client
                .open(second.body(), MessagePurpose::Response)
                .is_err()
        );

        assert!(client.open(first.body(), MessagePurpose::Response).is_err());

        assert!(client.seal(MessagePurpose::Request, b"request").is_err());

        assert!(client.verify_live().is_err());
    }

    #[test]
    fn envelopes_from_different_keys_are_rejected_in_both_directions() {
        let (mut client_a, mut server_a) = pair();

        // Distinct fixed material for the second test connection.
        // Neither set of fixed keys is suitable for production.
        let other_material = || {
            let mut bytes = [0x33; 64];
            bytes[32..].fill(0x44);
            TemporaryKeys::from_bytes(&bytes).unwrap()
        };

        let mut client_b = KeyEpoch::for_client(other_material()).unwrap();

        let mut server_b = KeyEpoch::for_server(other_material()).unwrap();

        let request_a = client_a
            .seal(MessagePurpose::Request, b"connection A request")
            .unwrap();

        let response_a = server_a
            .seal(MessagePurpose::Response, b"connection A response")
            .unwrap();

        // Directions, purposes, and initial sequence numbers match.
        // The receiving connection has different key material.
        assert!(
            server_b
                .open(request_a.body(), MessagePurpose::Request)
                .is_err()
        );

        assert!(
            client_b
                .open(response_a.body(), MessagePurpose::Response)
                .is_err()
        );

        // Both receiving epochs must remain disabled.
        assert!(server_b.verify_live().is_err());
        assert!(client_b.verify_live().is_err());

        assert!(server_b.seal(MessagePurpose::Response, b"retry").is_err());

        assert!(client_b.seal(MessagePurpose::Request, b"retry").is_err());

        // Failure on B must not affect the original A epochs.
        let request = server_a
            .open(request_a.body(), MessagePurpose::Request)
            .unwrap();

        assert_eq!(request.body(), b"connection A request");

        let response = client_a
            .open(response_a.body(), MessagePurpose::Response)
            .unwrap();

        assert_eq!(response.body(), b"connection A response");
    }

    #[test]
    fn modified_envelope_header_disables_receiving_epoch() {
        use crate::envelope::ENVELOPE_HEADER_LEN;

        for index in 0..ENVELOPE_HEADER_LEN {
            // Each malformed input gets a fresh epoch so a previous
            // failure cannot mask acceptance of a later test case.
            let (mut client, mut server) = pair();

            let request = client
                .seal(MessagePurpose::Request, b"authenticated body")
                .unwrap();

            let mut modified = request.body().to_vec();
            modified[index] ^= 1;

            assert!(
                server.open(&modified, MessagePurpose::Request).is_err(),
                "modified header byte {index} was accepted"
            );

            // Restoring the original message must not revive
            // the failed receiving epoch.
            assert!(
                server
                    .open(request.body(), MessagePurpose::Request)
                    .is_err(),
                "epoch recovered after header byte {index} failed"
            );

            assert!(server.seal(MessagePurpose::Response, b"response").is_err());

            assert!(server.verify_live().is_err());
        }
    }

    #[test]
    fn every_truncated_request_envelope_is_rejected() {
        let (mut source, _) = pair();

        let request = source
            .seal(MessagePurpose::Request, b"truncation test")
            .unwrap();

        // Test every proper prefix, including an empty input,
        // a partial header, and an incomplete authentication tag.
        for length in 0..request.body().len() {
            let mut server = KeyEpoch::for_server(material()).unwrap();

            assert!(
                server
                    .open(&request.body()[..length], MessagePurpose::Request,)
                    .is_err(),
                "truncated envelope of length {length} was accepted"
            );

            assert!(
                server
                    .open(request.body(), MessagePurpose::Request)
                    .is_err(),
                "epoch recovered after truncation to {length} bytes"
            );

            assert!(server.seal(MessagePurpose::Response, b"response").is_err());

            assert!(server.verify_live().is_err());
        }

        // Confirm the unmodified fixture itself is valid.
        let mut server = KeyEpoch::for_server(material()).unwrap();

        let opened = server
            .open(request.body(), MessagePurpose::Request)
            .unwrap();

        assert_eq!(opened.body(), b"truncation test");
    }

    #[test]
    fn modified_ciphertext_disables_receiving_epoch() {
        use crate::envelope::{AUTH_TAG_LEN, ENVELOPE_HEADER_LEN};

        let plaintext = b"ciphertext modification test";

        // Mutate each ciphertext byte while leaving the envelope
        // header and authentication tag unchanged.
        for offset in 0..plaintext.len() {
            let (mut client, mut server) = pair();

            let request = client.seal(MessagePurpose::Request, plaintext).unwrap();

            assert_eq!(
                request.body().len(),
                ENVELOPE_HEADER_LEN + plaintext.len() + AUTH_TAG_LEN
            );

            let mut modified = request.body().to_vec();
            modified[ENVELOPE_HEADER_LEN + offset] ^= 1;

            assert!(
                server.open(&modified, MessagePurpose::Request).is_err(),
                "modified ciphertext byte {offset} was accepted"
            );

            assert!(
                server
                    .open(request.body(), MessagePurpose::Request)
                    .is_err()
            );

            assert!(server.seal(MessagePurpose::Response, b"response").is_err());

            assert!(server.verify_live().is_err());
        }
    }

    #[test]
    fn explicit_disable_removes_key_owners_and_is_idempotent() {
        let mut epoch = KeyEpoch::for_client(material()).unwrap();
        assert!(epoch.keys.is_some());

        epoch.disable();
        assert!(epoch.keys.is_none());
        epoch.disable();
        assert!(epoch.keys.is_none());
        assert!(epoch.verify_live().is_err());
        assert!(epoch.seal(MessagePurpose::Request, b"retry").is_err());
    }

    #[test]
    fn sealing_failure_removes_both_key_owners() {
        let mut epoch = KeyEpoch::for_client(material()).unwrap();
        assert!(
            epoch
                .seal(MessagePurpose::Response, b"wrong direction")
                .is_err()
        );
        assert!(epoch.keys.is_none());
        assert!(epoch.verify_live().is_err());
    }

    #[test]
    fn authentication_failure_removes_both_key_owners() {
        let (mut client, mut server) = pair();
        let request = client.seal(MessagePurpose::Request, b"request").unwrap();
        let mut modified = request.body().to_vec();
        let last = modified.len() - 1;
        modified[last] ^= 1;

        assert!(server.open(&modified, MessagePurpose::Request).is_err());
        assert!(server.keys.is_none());
        assert!(server.verify_live().is_err());
        assert!(client.keys.is_some());
    }

    #[test]
    fn observed_expiration_removes_both_key_owners() {
        let created_at = Instant::now();
        let mut epoch = KeyEpoch::new_at(material(), EndpointRole::Client, created_at).unwrap();
        let boundary = epoch.expires_at;

        assert_eq!(
            epoch
                .operation_budget_at(Duration::from_secs(1), boundary)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(epoch.keys.is_none());
        assert!(epoch.ensure_live_at(created_at).is_err());
        assert!(epoch.keys.is_none());
    }

    #[test]
    fn successful_operations_preserve_key_owners() {
        let (mut client, mut server) = pair();
        let request = client.seal(MessagePurpose::Request, b"request").unwrap();
        let opened = server
            .open(request.body(), MessagePurpose::Request)
            .unwrap();
        assert_eq!(opened.body(), b"request");
        assert!(client.keys.is_some());
        assert!(server.keys.is_some());
        assert!(client.verify_live().is_ok());
        assert!(server.verify_live().is_ok());
    }

    #[test]
    fn padded_epoch_round_trips_and_counts_encoded_bytes() {
        let mode = PaddingMode::block(256).unwrap();

        let mut client = KeyEpoch::for_client_with_padding(material(), mode).unwrap();
        let mut server = KeyEpoch::for_server_with_padding(material(), mode).unwrap();

        let before = client.capacity().unwrap();

        let request = client.seal(MessagePurpose::Request, b"hello man").unwrap();

        assert_eq!(
            request.body().len(),
            crate::envelope::ENVELOPE_HEADER_LEN + 256 + crate::envelope::AUTH_TAG_LEN
        );

        let opened = server
            .open(request.body(), MessagePurpose::Request)
            .unwrap();

        assert_eq!(opened.body(), b"hello man");

        let client_after = client.capacity().unwrap();
        let server_after = server.capacity().unwrap();

        assert_eq!(
            client_after.send_plaintext_bytes,
            before.send_plaintext_bytes - 256
        );
        assert_eq!(
            server_after.receive_plaintext_bytes,
            client_after.send_plaintext_bytes
        );

        let response = server
            .seal(MessagePurpose::Response, &[0, 255, 0, 17])
            .unwrap();

        let opened = client
            .open(response.body(), MessagePurpose::Response)
            .unwrap();

        assert_eq!(opened.body(), &[0, 255, 0, 17]);
    }

    #[test]
    fn padded_epoch_keeps_confirmation_representation_unchanged() {
        let mode = PaddingMode::block(256).unwrap();

        let mut client = KeyEpoch::for_client_with_padding(material(), mode).unwrap();
        let mut server = KeyEpoch::for_server_with_padding(material(), mode).unwrap();

        let confirmation = client
            .seal(MessagePurpose::KeyConfirmation, b"confirm")
            .unwrap();

        assert_eq!(
            confirmation.body().len(),
            crate::envelope::ENVELOPE_HEADER_LEN + b"confirm".len() + crate::envelope::AUTH_TAG_LEN
        );

        let opened = server
            .open(confirmation.body(), MessagePurpose::KeyConfirmation)
            .unwrap();

        assert_eq!(opened.body(), b"confirm");

        let request = client
            .seal(MessagePurpose::Request, b"after confirmation")
            .unwrap();

        assert_eq!(request.sequence(), 1);

        let opened = server
            .open(request.body(), MessagePurpose::Request)
            .unwrap();

        assert_eq!(opened.body(), b"after confirmation");
    }

    #[test]
    fn authenticated_invalid_padding_disables_both_epoch_directions() {
        let mode = PaddingMode::block(256).unwrap();

        // Unpadded sender deliberately constructs a malformed inner
        // representation, then authenticates it with the valid test key.
        let mut source = KeyEpoch::for_client(material()).unwrap();
        let mut receiver = KeyEpoch::for_server_with_padding(material(), mode).unwrap();

        let mut malformed = mode.encode(b"hello").unwrap();
        *malformed.last_mut().unwrap() = 1;

        let sealed = source
            .seal(MessagePurpose::Request, malformed.as_slice())
            .unwrap();

        assert!(
            receiver
                .open(sealed.body(), MessagePurpose::Request)
                .is_err()
        );

        assert!(receiver.keys.is_none());
        assert!(receiver.verify_live().is_err());
        assert!(
            receiver
                .seal(MessagePurpose::Response, b"must fail")
                .is_err()
        );
    }

    #[test]
    fn padded_epoch_preserves_payloads_at_bucket_boundaries() {
        let mode = PaddingMode::block(256).unwrap();

        let mut client = KeyEpoch::for_client_with_padding(material(), mode).unwrap();
        let mut server = KeyEpoch::for_server_with_padding(material(), mode).unwrap();

        let overhead = crate::envelope::ENVELOPE_HEADER_LEN + crate::envelope::AUTH_TAG_LEN;

        // Four bytes of inner length metadata precede each payload.
        let cases = [
            (0usize, 256usize),
            (251, 256),
            (252, 256),
            (253, 512),
            (507, 512),
            (508, 512),
            (509, 768),
            (61_436, 61_440),
        ];

        for (index, (payload_len, encoded_len)) in cases.into_iter().enumerate() {
            let payload: Vec<u8> = (0..payload_len).map(|i| (i % 256) as u8).collect();

            let request = client.seal(MessagePurpose::Request, &payload).unwrap();

            assert_eq!(request.sequence(), index as u64);
            assert_eq!(
                request.body().len(),
                overhead + encoded_len,
                "wrong request bucket for payload length {payload_len}",
            );

            let opened = server
                .open(request.body(), MessagePurpose::Request)
                .unwrap();

            assert_eq!(
                opened.body(),
                payload.as_slice(),
                "request changed at payload length {payload_len}",
            );

            let response = server.seal(MessagePurpose::Response, &payload).unwrap();

            assert_eq!(response.sequence(), index as u64);
            assert_eq!(
                response.body().len(),
                overhead + encoded_len,
                "wrong response bucket for payload length {payload_len}",
            );

            let opened = client
                .open(response.body(), MessagePurpose::Response)
                .unwrap();

            assert_eq!(
                opened.body(),
                payload.as_slice(),
                "response changed at payload length {payload_len}",
            );
        }
    }
}

#[cfg(test)]
#[path = "epoch_adversarial_tests.rs"]
mod adversarial_tests;

/// Byte budgets count the complete plaintext passed to application
/// encryption, including application protocol metadata, key-confirmation
/// plaintext, and any inner padding-format metadata and padding.
///
/// They do not count TLS bytes, ciphertext authentication tags, or outer
/// frame headers.
///
/// With padding enabled, remaining plaintext bytes are not the same as
/// the remaining capacity for original application payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationKeyCapacity {
    pub send_plaintext_bytes: u64,
    pub send_messages: u64,
    pub receive_plaintext_bytes: u64,
    pub receive_messages: u64,
    pub remaining_lifetime: Duration,
}

impl KeyEpoch {
    /// Reports current local capacity without consuming counters.
    ///
    /// Observed expiration disables the epoch and drops both owners,
    /// just like other epoch operations.
    pub(crate) fn capacity(&mut self) -> io::Result<ApplicationKeyCapacity> {
        self.capacity_at(Instant::now())
    }

    fn capacity_at(&mut self, now: Instant) -> io::Result<ApplicationKeyCapacity> {
        self.ensure_live_at(now)?;

        let remaining_lifetime = match self.expires_at.checked_duration_since(now) {
            Some(remaining) if !remaining.is_zero() => remaining,
            _ => {
                self.disable();

                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "application-key epoch expired",
                ));
            }
        };

        let keys = self.keys.as_ref().ok_or_else(disabled_error)?;

        let (send_plaintext_bytes, send_messages) = keys.sender.remaining_capacity();

        let (receive_plaintext_bytes, receive_messages) = keys.receiver.remaining_capacity();

        Ok(ApplicationKeyCapacity {
            send_plaintext_bytes,
            send_messages,
            receive_plaintext_bytes,
            receive_messages,
            remaining_lifetime,
        })
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;

    use crate::seal::MAX_PLAINTEXT_BYTES_PER_KEY;
    use crate::sequence::MAX_MESSAGES_PER_KEY;

    fn material() -> TemporaryKeys {
        let mut bytes = [0x11; 64];
        bytes[32..].fill(0x22);

        TemporaryKeys::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn inspection_does_not_consume_capacity_or_drop_owners() {
        let now = Instant::now();

        let mut epoch = KeyEpoch::new_at(material(), EndpointRole::Client, now).unwrap();

        let first = epoch.capacity_at(now).unwrap();
        let second = epoch.capacity_at(now).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.send_plaintext_bytes, MAX_PLAINTEXT_BYTES_PER_KEY);
        assert_eq!(first.receive_plaintext_bytes, MAX_PLAINTEXT_BYTES_PER_KEY);
        assert_eq!(first.send_messages, MAX_MESSAGES_PER_KEY);
        assert_eq!(first.receive_messages, MAX_MESSAGES_PER_KEY);
        assert_eq!(first.remaining_lifetime, KEY_LIFETIME);
        assert!(epoch.keys.is_some());

        let message = epoch.seal(MessagePurpose::Request, b"abc").unwrap();

        assert_eq!(message.sequence(), 0);
    }

    #[test]
    fn request_and_response_usage_are_endpoint_relative() {
        let mut client = KeyEpoch::for_client(material()).unwrap();
        let mut server = KeyEpoch::for_server(material()).unwrap();

        let request = client.seal(MessagePurpose::Request, b"abc").unwrap();

        server
            .open(request.body(), MessagePurpose::Request)
            .unwrap();

        let response = server.seal(MessagePurpose::Response, b"hello").unwrap();

        client
            .open(response.body(), MessagePurpose::Response)
            .unwrap();

        let client_capacity = client.capacity().unwrap();
        let server_capacity = server.capacity().unwrap();

        assert_eq!(
            client_capacity.send_plaintext_bytes,
            MAX_PLAINTEXT_BYTES_PER_KEY - 3
        );
        assert_eq!(
            client_capacity.receive_plaintext_bytes,
            MAX_PLAINTEXT_BYTES_PER_KEY - 5
        );
        assert_eq!(
            server_capacity.send_plaintext_bytes,
            client_capacity.receive_plaintext_bytes
        );
        assert_eq!(
            server_capacity.receive_plaintext_bytes,
            client_capacity.send_plaintext_bytes
        );

        assert_eq!(client_capacity.send_messages, MAX_MESSAGES_PER_KEY - 1);
        assert_eq!(client_capacity.receive_messages, MAX_MESSAGES_PER_KEY - 1);
        assert_eq!(server_capacity.send_messages, MAX_MESSAGES_PER_KEY - 1);
        assert_eq!(server_capacity.receive_messages, MAX_MESSAGES_PER_KEY - 1);
    }

    #[test]
    fn key_confirmation_counts_toward_reported_capacity() {
        let mut client = KeyEpoch::for_client(material()).unwrap();
        let mut server = KeyEpoch::for_server(material()).unwrap();

        let confirmation = client
            .seal(MessagePurpose::KeyConfirmation, b"confirm")
            .unwrap();

        server
            .open(confirmation.body(), MessagePurpose::KeyConfirmation)
            .unwrap();

        let client_capacity = client.capacity().unwrap();
        let server_capacity = server.capacity().unwrap();

        assert_eq!(
            client_capacity.send_plaintext_bytes,
            MAX_PLAINTEXT_BYTES_PER_KEY - 7
        );
        assert_eq!(client_capacity.send_messages, MAX_MESSAGES_PER_KEY - 1);

        assert_eq!(
            server_capacity.receive_plaintext_bytes,
            MAX_PLAINTEXT_BYTES_PER_KEY - 7
        );
        assert_eq!(server_capacity.receive_messages, MAX_MESSAGES_PER_KEY - 1);

        assert_eq!(
            client_capacity.receive_plaintext_bytes,
            MAX_PLAINTEXT_BYTES_PER_KEY
        );
        assert_eq!(
            server_capacity.send_plaintext_bytes,
            MAX_PLAINTEXT_BYTES_PER_KEY
        );
    }

    #[test]
    fn reports_remaining_lifetime_without_renewing_it() {
        let now = Instant::now();

        let mut epoch = KeyEpoch::new_at(material(), EndpointRole::Client, now).unwrap();

        let near_expiry = now + KEY_LIFETIME - Duration::from_secs(2);

        assert_eq!(
            epoch.capacity_at(near_expiry).unwrap().remaining_lifetime,
            Duration::from_secs(2)
        );
        assert_eq!(
            epoch.capacity_at(near_expiry).unwrap().remaining_lifetime,
            Duration::from_secs(2)
        );

        assert_eq!(epoch.expires_at, now + KEY_LIFETIME);
        assert!(epoch.keys.is_some());
    }

    #[test]
    fn capacity_observes_expiration_and_removes_both_owners() {
        let now = Instant::now();

        let mut epoch = KeyEpoch::new_at(material(), EndpointRole::Client, now).unwrap();

        let boundary = epoch.expires_at;

        assert_eq!(
            epoch.capacity_at(boundary).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );

        assert!(epoch.keys.is_none());

        // Earlier test time cannot reactivate a disabled epoch.
        assert!(epoch.capacity_at(now).is_err());
        assert!(epoch.keys.is_none());
    }

    #[test]
    fn explicitly_disabled_epoch_cannot_report_live_capacity() {
        let mut epoch = KeyEpoch::for_client(material()).unwrap();

        epoch.disable();

        assert!(epoch.capacity().is_err());
        assert!(epoch.keys.is_none());
    }
}
