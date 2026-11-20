use std::fmt;
use std::io;

use aws_lc_rs::rand::SecureRandom;
use zeroize::Zeroizing;

pub(crate) const APPLICATION_KEY_LEN: usize = 32;
pub(crate) const KEY_MATERIAL_LEN: usize = APPLICATION_KEY_LEN * 2;

/// Temporary raw application keys for one connection.
///
/// The material is allocated once and never resized by this type.
/// It is not Clone or Copy.
///
/// Key lifetime, usage limits, and confirmation are enforced by the
/// future key-epoch owner, not by this storage container.
pub(crate) struct TemporaryKeys {
    material: Zeroizing<Vec<u8>>,
}

impl TemporaryKeys {
    /// Generates fresh material using the supplied cryptographic RNG.
    ///
    /// Production callers must use the approved AWS-LC RNG.
    pub(crate) fn generate(rng: &dyn SecureRandom) -> io::Result<Self> {
        let mut material = Zeroizing::new(vec![0; KEY_MATERIAL_LEN]);

        rng.fill(material.as_mut_slice())
            .map_err(|_| io::Error::other("temporary application-key generation failed"))?;

        Ok(Self { material })
    }

    /// Copies material received through the authenticated TLS channel.
    ///
    /// The caller remains responsible for cleaning up the source buffer.
    pub(crate) fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != KEY_MATERIAL_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid temporary application-key material length",
            ));
        }

        let mut material = Zeroizing::new(vec![0; KEY_MATERIAL_LEN]);

        material.as_mut_slice().copy_from_slice(bytes);

        Ok(Self { material })
    }

    /// Raw material for the internal TLS-protected key-delivery message.
    ///
    /// Never log this value or expose it through the public API.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.material.as_slice()
    }

    pub(crate) fn client_to_server(&self) -> &[u8] {
        &self.material[..APPLICATION_KEY_LEN]
    }

    pub(crate) fn server_to_client(&self) -> &[u8] {
        &self.material[APPLICATION_KEY_LEN..]
    }
}

impl fmt::Debug for TemporaryKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TemporaryKeys")
            .field("material", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::rand::SystemRandom;

    use super::*;

    #[test]
    fn generates_correctly_sized_material() {
        let rng = SystemRandom::new();
        let keys = TemporaryKeys::generate(&rng).unwrap();

        assert_eq!(keys.as_bytes().len(), KEY_MATERIAL_LEN);
        assert_eq!(keys.client_to_server().len(), APPLICATION_KEY_LEN);
        assert_eq!(keys.server_to_client().len(), APPLICATION_KEY_LEN);
    }

    #[test]
    fn imported_material_preserves_direction_boundaries() {
        let mut bytes = [0x11; KEY_MATERIAL_LEN];
        bytes[APPLICATION_KEY_LEN..].fill(0x22);

        let keys = TemporaryKeys::from_bytes(&bytes).unwrap();

        assert_eq!(keys.client_to_server(), &[0x11; APPLICATION_KEY_LEN]);
        assert_eq!(keys.server_to_client(), &[0x22; APPLICATION_KEY_LEN]);
        assert_eq!(keys.as_bytes(), bytes.as_slice());

        // Changing the source does not change the owned key material.
        bytes.fill(0);

        assert_eq!(keys.client_to_server(), &[0x11; APPLICATION_KEY_LEN]);
    }

    #[test]
    fn rejects_incorrect_material_lengths() {
        for length in [
            0,
            APPLICATION_KEY_LEN,
            KEY_MATERIAL_LEN - 1,
            KEY_MATERIAL_LEN + 1,
            1024,
        ] {
            let bytes = vec![0; length];

            let error = TemporaryKeys::from_bytes(&bytes).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn debug_output_contains_no_key_material() {
        let keys = TemporaryKeys::from_bytes(&[0x41; KEY_MATERIAL_LEN]).unwrap();

        assert_eq!(
            format!("{keys:?}"),
            "TemporaryKeys { material: \"[REDACTED]\" }"
        );
    }
}
