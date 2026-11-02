//! The host issuer's own independent seed (FIX-LIST 3018): per-vault
//! host issuer isolation, so one vault's host key never derives from
//! another vault's material.

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::authority::invalid_authority;
use crate::error::Result;

/// Length of a vault's independent host-issuer seed.
pub const HOST_ISSUER_SEED_BYTES: usize = 32;
/// BLAKE3 context for the host issuer's Ed25519 signing subkey.
pub const HOST_ISSUER_SIGNING_CONTEXT: &str = "oneiron/vault-host-authority-signing/v1";

/// A dedicated host signing key. It signs with a subkey of its vault's own
/// independent 32-byte seed, never auth_secret, the DEK or vault_id.
pub struct HostSlipIssuer {
    pub(super) secret: Zeroizing<Vec<u8>>,
    pub(super) signing: SigningKey,
}

impl HostSlipIssuer {
    /// Derive one issuer from its vault's independent seed.
    pub fn from_seed(seed: &[u8; HOST_ISSUER_SEED_BYTES]) -> Result<Self> {
        if seed == &[0u8; HOST_ISSUER_SEED_BYTES] {
            return Err(invalid_authority());
        }
        let subkey = Zeroizing::new(blake3::derive_key(HOST_ISSUER_SIGNING_CONTEXT, seed));
        Ok(Self {
            secret: Zeroizing::new(seed.to_vec()),
            signing: SigningKey::from_bytes(&subkey),
        })
    }

    /// Derive one issuer from the configured root secret.
    /// Production callers move to the vault loader (FIX-LIST 3018).
    pub fn from_secret(secret: &[u8]) -> Result<Self> {
        if secret.is_empty() {
            return Err(invalid_authority());
        }
        let seed = Zeroizing::new(blake3::derive_key(
            "oneiron/host-authority-signing/v2",
            secret,
        ));
        Ok(Self {
            secret: Zeroizing::new(secret.to_vec()),
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// This issuer's genesis recovery material, as logged at bootstrap.
    pub(super) fn genesis_recovery(&self) -> [u8; 32] {
        blake3::derive_key("oneiron/host-genesis-recovery/v2", &self.secret)
    }

    /// A twin of this issuer: the same retained bytes, the same signing key.
    pub(crate) fn duplicate(&self) -> Result<Self> {
        Ok(Self {
            secret: self.secret.clone(),
            signing: SigningKey::from_bytes(&self.signing.to_bytes()),
        })
    }
}

/// A fresh independent host-issuer seed from the OS CSPRNG.
pub(super) fn new_host_issuer_seed() -> Result<Zeroizing<[u8; HOST_ISSUER_SEED_BYTES]>> {
    let mut seed = Zeroizing::new([0u8; HOST_ISSUER_SEED_BYTES]);
    crate::world_keys::os_fill(&mut seed[..])?;
    Ok(seed)
}
