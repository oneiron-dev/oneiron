//! Pairing derives a distinct transport signer; only the public endpoint key is recorded.
use ed25519_dalek::{Signer, SigningKey};
use zeroize::Zeroizing;

use crate::MachineId;

const DOMAIN: &str = "oneiron/mesh-transport-ed25519/v1";

/// Device-side key material. Never persist the derived seed or hand it to a relay.
/// Retain the parent device seed in the platform's protected device-key custody;
/// re-derive on restart instead of copying this secret into a MACHINE body.
pub struct TransportKey(Zeroizing<[u8; 32]>);
impl std::fmt::Debug for TransportKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransportKey([redacted])")
    }
}
impl TransportKey {
    /// The device signer is the pairing connection key, not the host root.
    pub fn derive(device_signer: &SigningKey) -> Self {
        Self(Zeroizing::new(blake3::derive_key(
            DOMAIN,
            device_signer.as_bytes(),
        )))
    }
    pub fn endpoint_key(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.0).verifying_key().to_bytes()
    }
    /// Both keys prove possession over the same bound MACHINE and endpoint.
    pub fn binding_proofs(
        &self,
        device_signer: &SigningKey,
        machine: MachineId,
    ) -> ([u8; 64], [u8; 64]) {
        let transcript = binding_transcript(machine, self.endpoint_key());
        (
            device_signer.sign(&transcript).to_bytes(),
            SigningKey::from_bytes(&self.0).sign(&transcript).to_bytes(),
        )
    }
    #[cfg(feature = "iroh")]
    pub(crate) fn into_iroh_secret(self) -> iroh::SecretKey {
        iroh::SecretKey::from_bytes(&self.0)
    }
}
/// Transcript used by the authority binding door, including vault-local MACHINE id.
fn binding_transcript(machine: MachineId, endpoint_key: [u8; 32]) -> Vec<u8> {
    let mut out = b"oneiron/mesh-machine-binding/v1\0".to_vec();
    out.extend_from_slice(machine.as_bytes());
    out.extend_from_slice(&endpoint_key);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stable_distinct_device_transport_signers_and_redacted_debug() {
        let device = SigningKey::from_bytes(&[7; 32]);
        let a = TransportKey::derive(&device);
        assert_ne!(a.endpoint_key(), device.verifying_key().to_bytes());
        assert_eq!(
            a.endpoint_key(),
            TransportKey::derive(&device).endpoint_key()
        );
        assert_ne!(
            a.endpoint_key(),
            TransportKey::derive(&SigningKey::from_bytes(&[8; 32])).endpoint_key()
        );
        assert_eq!(format!("{a:?}"), "TransportKey([redacted])");
    }
    #[cfg(feature = "iroh")]
    #[test]
    fn derived_endpoint_matches_iroh_handshake_identity() {
        let key = TransportKey::derive(&SigningKey::from_bytes(&[7; 32]));
        let endpoint = key.endpoint_key();
        assert_eq!(*key.into_iroh_secret().public().as_bytes(), endpoint);
    }
}
