use std::sync::Arc;

use rustls::client::Resumption;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

pub(crate) const ALPN_PROTOCOL: &[u8] = b"brn/1";
pub(crate) const ALPN_PROTOCOL_V2: &[u8] = b"brn/2";

/// Internal selection shared by TLS setup and BRN negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BrnVersion {
    V1,
    V2,
}

impl BrnVersion {
    pub(crate) fn alpn(self) -> &'static [u8] {
        match self {
            Self::V1 => ALPN_PROTOCOL,
            Self::V2 => ALPN_PROTOCOL_V2,
        }
    }
}

#[cfg(test)]
pub(crate) fn build_client_config(
    trusted_ca_certificates: &[&[u8]],
) -> Result<ClientConfig, rustls::Error> {
    build_client_config_for_version(trusted_ca_certificates, BrnVersion::V1)
}

/// Builds a TLS client configuration offering exactly one BRN version.
pub(crate) fn build_client_config_for_version(
    trusted_ca_certificates: &[&[u8]],
    version: BrnVersion,
) -> Result<ClientConfig, rustls::Error> {
    if trusted_ca_certificates.is_empty() {
        return Err(rustls::Error::General(
            "at least one trusted CA certificate is required".into(),
        ));
    }

    let mut roots = RootCertStore::empty();

    for certificate in trusted_ca_certificates {
        roots.add(CertificateDer::from(*certificate))?;
    }

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();

    config.alpn_protocols = vec![version.alpn().to_vec()];
    config.enable_early_data = false;
    config.resumption = Resumption::disabled();

    Ok(config)
}

pub(crate) fn build_server_config(
    certificate_chain: &[&[u8]],
    private_key_pkcs8: &[u8],
) -> Result<ServerConfig, rustls::Error> {
    build_server_config_for_version(certificate_chain, private_key_pkcs8, BrnVersion::V1)
}

/// Builds a TLS server configuration offering exactly one BRN version.
pub(crate) fn build_server_config_for_version(
    certificate_chain: &[&[u8]],
    private_key_pkcs8: &[u8],
    version: BrnVersion,
) -> Result<ServerConfig, rustls::Error> {
    if certificate_chain.is_empty() {
        return Err(rustls::Error::General(
            "at least one server certificate is required".into(),
        ));
    }

    if private_key_pkcs8.is_empty() {
        return Err(rustls::Error::General(
            "server private key must not be empty".into(),
        ));
    }

    let certificates: Vec<CertificateDer<'static>> = certificate_chain
        .iter()
        .map(|certificate| CertificateDer::from(certificate.to_vec()))
        .collect();

    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_pkcs8.to_vec()));

    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;

    config.alpn_protocols = vec![version.alpn().to_vec()];
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    config.send_half_rtt_data = false;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_missing_trust_anchors() {
        let result = build_client_config(&[]);

        assert!(matches!(
            result,
            Err(rustls::Error::General(message))
                if message == "at least one trusted CA certificate is required"
        ));
    }

    #[test]
    fn rejects_malformed_trust_anchors() {
        let malformed_inputs: [&[u8]; 3] = [b"", b"not a certificate", &[0x30, 0x03, 0x01]];

        for certificate in malformed_inputs {
            assert!(build_client_config(&[certificate]).is_err());
        }
    }

    fn development_file(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
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

    #[test]
    fn builds_client_config_with_development_ca() {
        let ca = development_file("ca.cert.der");

        let config = build_client_config(&[ca.as_slice()]).unwrap();

        assert_eq!(config.alpn_protocols, vec![ALPN_PROTOCOL.to_vec()]);
        assert!(!config.enable_early_data);
    }

    #[test]
    fn builds_server_config_with_development_identity() {
        let certificate = development_file("server.cert.der");
        let key = development_file("server.key.der");

        let config = build_server_config(&[certificate.as_slice()], &key).unwrap();

        assert_eq!(config.alpn_protocols, vec![ALPN_PROTOCOL.to_vec()]);
        assert_eq!(config.max_early_data_size, 0);
        assert_eq!(config.send_tls13_tickets, 0);
        assert!(!config.send_half_rtt_data);
    }

    #[test]
    fn rejects_missing_server_certificate() {
        let result = build_server_config(&[], b"placeholder");

        assert!(matches!(
            result,
            Err(rustls::Error::General(message))
                if message == "at least one server certificate is required"
        ));
    }

    #[test]
    fn rejects_missing_server_private_key() {
        let result = build_server_config(&[b"placeholder"], b"");

        assert!(matches!(
            result,
            Err(rustls::Error::General(message))
                if message == "server private key must not be empty"
        ));
    }

    #[test]
    fn rejects_malformed_server_private_key() {
        let certificate = development_file("server.cert.der");

        let result = build_server_config(&[certificate.as_slice()], b"not a PKCS#8 private key");

        assert!(result.is_err());
    }

    #[test]
    fn versions_map_to_distinct_alpn_identifiers() {
        assert_eq!(BrnVersion::V1.alpn(), b"brn/1");
        assert_eq!(BrnVersion::V2.alpn(), b"brn/2");
        assert_ne!(BrnVersion::V1.alpn(), BrnVersion::V2.alpn());
    }

    #[test]
    fn versioned_client_configs_offer_exactly_one_protocol() {
        let ca = development_file("ca.cert.der");

        for version in [BrnVersion::V1, BrnVersion::V2] {
            let config = build_client_config_for_version(&[ca.as_slice()], version).unwrap();

            assert_eq!(config.alpn_protocols, vec![version.alpn().to_vec()]);
            assert!(!config.enable_early_data);
        }
    }

    #[test]
    fn versioned_server_configs_offer_exactly_one_protocol() {
        let certificate = development_file("server.cert.der");
        let key = development_file("server.key.der");

        for version in [BrnVersion::V1, BrnVersion::V2] {
            let config =
                build_server_config_for_version(&[certificate.as_slice()], &key, version).unwrap();

            assert_eq!(config.alpn_protocols, vec![version.alpn().to_vec()]);
            assert_eq!(config.max_early_data_size, 0);
            assert_eq!(config.send_tls13_tickets, 0);
            assert!(!config.send_half_rtt_data);
        }
    }
}
