//! Internal parser fuzz entry points. Not included in ordinary builds.

use crate::auth_wire::{AuthenticationReply, AuthenticationRequest, MAX_CREDENTIAL_BYTES};
use crate::envelope::{AUTH_TAG_LEN, ENVELOPE_HEADER_LEN, EnvelopeHeader};
use crate::frame::{FrameHeader, FrameKind, HEADER_LEN, MAX_BODY_LEN};
use crate::key_wire::KeyOffer;

pub fn frame_header(data: &[u8]) {
    if let Ok(header) = FrameHeader::decode(data) {
        assert_eq!(data.len(), HEADER_LEN);
        assert!((1..=MAX_BODY_LEN).contains(&header.body_len()));
        assert_eq!(header.encode().as_slice(), data);
        assert_eq!(
            FrameHeader::new(header.kind(), header.body_len()).unwrap(),
            header
        );
    }
}

pub fn authentication(data: &[u8]) {
    if let Ok(request) = AuthenticationRequest::decode(data) {
        assert!((1..=MAX_CREDENTIAL_BYTES).contains(&request.credentials().len()));
        let encoded = request.encode();
        assert_eq!(encoded.as_slice(), data);
        let rebuilt = AuthenticationRequest::new(request.credentials()).unwrap();
        assert_eq!(rebuilt.credentials(), request.credentials());
    }
    if let Ok(reply) = AuthenticationReply::decode(data) {
        assert_eq!(reply.encode().as_slice(), data);
    }
}

pub fn key_offer(data: &[u8]) {
    if let Ok(keys) = KeyOffer::decode(data) {
        let canonical = KeyOffer::from_keys(&keys);
        assert_eq!(canonical.body(), data);
    }
}

pub fn envelope_header(data: &[u8]) {
    if let Ok(header) = EnvelopeHeader::decode(data) {
        assert_eq!(data.len(), ENVELOPE_HEADER_LEN);
        assert_eq!(header.encode().as_slice(), data);
        assert_eq!(
            EnvelopeHeader::new(header.direction(), header.purpose(), header.sequence()).unwrap(),
            header
        );
        let domain = b"BRN-AEAD-V1\0";
        let aad = header.authenticated_data(AUTH_TAG_LEN).unwrap();
        let outer = FrameHeader::new(
            FrameKind::Encrypted,
            (ENVELOPE_HEADER_LEN + AUTH_TAG_LEN) as u32,
        )
        .unwrap();
        assert_eq!(&aad[..domain.len()], domain);
        assert_eq!(
            &aad[domain.len()..domain.len() + HEADER_LEN],
            &outer.encode()
        );
        assert_eq!(&aad[domain.len() + HEADER_LEN..], data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Direction, MessagePurpose};
    use crate::keys::TemporaryKeys;

    #[test]
    fn valid_seed_inputs_exercise_each_parser_harness() {
        frame_header(&FrameHeader::new(FrameKind::Control, 1).unwrap().encode());
        frame_header(
            &FrameHeader::new(FrameKind::Encrypted, MAX_BODY_LEN)
                .unwrap()
                .encode(),
        );
        let request = AuthenticationRequest::new(b"disposable-fuzz-fixture")
            .unwrap()
            .encode();
        authentication(request.as_slice());
        authentication(&AuthenticationReply::Accepted.encode());
        authentication(&AuthenticationReply::Rejected.encode());
        let mut bytes = [0x11; 64];
        bytes[32..].fill(0x22);
        let keys = TemporaryKeys::from_bytes(&bytes).unwrap();
        key_offer(KeyOffer::from_keys(&keys).body());
        for (direction, purpose) in [
            (Direction::ClientToServer, MessagePurpose::KeyConfirmation),
            (Direction::ServerToClient, MessagePurpose::KeyConfirmation),
            (Direction::ClientToServer, MessagePurpose::Request),
            (Direction::ServerToClient, MessagePurpose::Response),
        ] {
            envelope_header(&EnvelopeHeader::new(direction, purpose, 0).unwrap().encode());
        }
    }

    #[test]
    fn malformed_smoke_inputs_return_without_panicking() {
        for length in 0..=128 {
            for fill in [0, 0xff] {
                let data = vec![fill; length];
                frame_header(&data);
                authentication(&data);
                key_offer(&data);
                envelope_header(&data);
            }
        }
    }
}
