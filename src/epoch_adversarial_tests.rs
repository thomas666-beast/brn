use std::io;
use std::time::{Duration, Instant};

use super::{EndpointRole, KEY_LIFETIME, KeyEpoch};
use crate::envelope::MessagePurpose;
use crate::keys::TemporaryKeys;

fn material() -> TemporaryKeys {
    // Fixed test material only; never use in production.
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

fn assert_disabled(epoch: &mut KeyEpoch) {
    assert!(epoch.keys.is_none());
    let expiry = epoch.expires_at;
    assert_eq!(
        epoch.verify_live().unwrap_err().kind(),
        io::ErrorKind::Other
    );
    assert_eq!(
        epoch
            .operation_budget(Duration::from_secs(1))
            .unwrap_err()
            .kind(),
        io::ErrorKind::Other
    );
    assert_eq!(
        epoch
            .seal(MessagePurpose::KeyConfirmation, b"later")
            .unwrap_err()
            .kind(),
        io::ErrorKind::Other
    );
    assert_eq!(
        epoch
            .open(b"invalid", MessagePurpose::KeyConfirmation)
            .unwrap_err()
            .kind(),
        io::ErrorKind::Other
    );
    epoch.disable();
    assert!(epoch.keys.is_none());
    assert_eq!(epoch.expires_at, expiry);
}

#[test]
fn both_roles_expire_exactly_one_lifetime_after_supplied_creation_time() {
    let created = Instant::now();
    let expected = created.checked_add(KEY_LIFETIME).unwrap();
    for role in [EndpointRole::Client, EndpointRole::Server] {
        let epoch = KeyEpoch::new_at(material(), role, created).unwrap();
        assert_eq!(epoch.expires_at, expected);
        assert!(epoch.keys.is_some());
    }
}

#[test]
fn final_nanosecond_is_live_but_exact_boundary_removes_owners() {
    let created = Instant::now();
    for role in [EndpointRole::Client, EndpointRole::Server] {
        let mut epoch = KeyEpoch::new_at(material(), role, created).unwrap();
        let boundary = epoch.expires_at;
        let before = boundary.checked_sub(Duration::from_nanos(1)).unwrap();
        epoch.ensure_live_at(before).unwrap();
        assert!(epoch.keys.is_some());
        assert_eq!(
            epoch.ensure_live_at(boundary).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_disabled(&mut epoch);
        assert!(epoch.ensure_live_at(created).is_err());
        assert!(epoch.keys.is_none());
    }
}

#[test]
fn successful_bidirectional_traffic_and_live_checks_never_extend_expiry() {
    let (mut client, mut server) = pair();
    let client_expiry = client.expires_at;
    let server_expiry = server.expires_at;
    for _ in 0..3 {
        let request = client.seal(MessagePurpose::Request, b"request").unwrap();
        assert_eq!(
            server
                .open(request.body(), MessagePurpose::Request)
                .unwrap()
                .body(),
            b"request"
        );
        let response = server.seal(MessagePurpose::Response, b"response").unwrap();
        assert_eq!(
            client
                .open(response.body(), MessagePurpose::Response)
                .unwrap()
                .body(),
            b"response"
        );
        client.verify_live().unwrap();
        server.verify_live().unwrap();
        assert_eq!(client.expires_at, client_expiry);
        assert_eq!(server.expires_at, server_expiry);
        assert!(client.keys.is_some());
        assert!(server.keys.is_some());
    }
}

#[test]
fn budget_queries_shrink_to_one_nanosecond_without_refreshing_expiry() {
    let created = Instant::now();
    let mut epoch = KeyEpoch::new_at(material(), EndpointRole::Client, created).unwrap();
    let expiry = epoch.expires_at;
    for remaining in [
        Duration::from_secs(10),
        Duration::from_millis(2),
        Duration::from_nanos(1),
    ] {
        let now = expiry.checked_sub(remaining).unwrap();
        assert_eq!(
            epoch.operation_budget_at(KEY_LIFETIME, now).unwrap(),
            remaining
        );
        assert_eq!(epoch.expires_at, expiry);
        assert!(epoch.keys.is_some());
    }
    assert_eq!(
        epoch
            .operation_budget_at(Duration::from_secs(1), expiry)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    assert_disabled(&mut epoch);
}

#[test]
fn zero_budget_on_live_epoch_preserves_owners_and_later_crypto_still_works() {
    let (mut client, mut server) = pair();
    let original_expiry = client.expires_at;
    assert_eq!(
        client.operation_budget(Duration::ZERO).unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert!(client.keys.is_some());
    assert_eq!(client.expires_at, original_expiry);
    let request = client.seal(MessagePurpose::Request, b"still live").unwrap();
    assert_eq!(request.sequence(), 0);
    assert_eq!(
        server
            .open(request.body(), MessagePurpose::Request)
            .unwrap()
            .body(),
        b"still live"
    );
}

#[test]
fn verify_live_itself_observes_expiration_and_removes_owners() {
    for role in [EndpointRole::Client, EndpointRole::Server] {
        let mut epoch = KeyEpoch::new_at(material(), role, Instant::now()).unwrap();
        epoch.expires_at = Instant::now();
        // Setting the test deadline does not itself run cleanup.
        assert!(epoch.keys.is_some());
        assert_eq!(
            epoch.verify_live().unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_disabled(&mut epoch);
    }
}

#[test]
fn disabled_epoch_rejects_all_crypto_and_positive_budget_entry_points() {
    for role in [EndpointRole::Client, EndpointRole::Server] {
        let mut epoch = KeyEpoch::new_at(material(), role, Instant::now()).unwrap();
        epoch.disable();
        assert_disabled(&mut epoch);
    }
}

#[test]
fn unexpected_purpose_on_valid_incoming_message_removes_both_owners() {
    for server_receives in [false, true] {
        let (mut client, mut server) = pair();
        if server_receives {
            let request = client.seal(MessagePurpose::Request, b"request").unwrap();
            assert_eq!(
                server
                    .open(request.body(), MessagePurpose::KeyConfirmation)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_disabled(&mut server);
            assert!(client.keys.is_some());
            client.verify_live().unwrap();
        } else {
            let response = server.seal(MessagePurpose::Response, b"response").unwrap();
            assert_eq!(
                client
                    .open(response.body(), MessagePurpose::KeyConfirmation)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_disabled(&mut client);
            assert!(server.keys.is_some());
            server.verify_live().unwrap();
        }
    }
}
