//! The owner's recovery root: 32 random bytes that only the recovery kit carries.
//!
//! One seed gives two keys, each with its own label:
//! - the recovery keypair (hybrid). World keys are wrapped to its public half, and
//!   the kit opens them with the secret half;
//! - the owner anchor (Ed25519). It signs the root record and an Owned mark at kit
//!   issue or restore (E2).
//!
//! The engine never stores the seed. How the kit's pieces carry the 32 bytes is the
//! kit's business; this module only needs them back.

use oneiron_crypto::{HybridPublicKey, HybridSecretKey};
use zeroize::Zeroizing;

pub use oneiron_authority::authority::RecoveryRootId;

use super::{os_fill, refused};
use crate::authority::OwnerRootRecord;
use crate::error::Result;

const RECOVERY_KEY_LABEL: &[u8] = b"oneiron/world-recovery-root/v1";
const ANCHOR_CONTEXT: &str = "oneiron/owner-anchor/v1";

/// The kit's secret. `Debug` is redacted and the bytes are wiped on drop.
pub struct RecoveryRootSeed(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for RecoveryRootSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryRootSeed(<redacted>)")
    }
}

impl RecoveryRootSeed {
    /// A fresh seed from the OS RNG.
    pub fn generate() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        os_fill(&mut seed[..])?;
        if *seed == [0u8; 32] {
            return Err(refused("os entropy unavailable"));
        }
        Ok(Self(seed))
    }

    /// The bytes, for the kit issuer only.
    #[must_use]
    pub fn kit_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.0)
    }

    /// The seed back from the kit. An all-zero seed is refused.
    pub fn from_kit_bytes(bytes: Zeroizing<[u8; 32]>) -> Result<Self> {
        if *bytes == [0u8; 32] {
            return Err(refused("an all-zero recovery seed"));
        }
        Ok(Self(bytes))
    }

    /// The recovery keypair's secret half. It opens the root's wraps.
    pub fn recovery_secret(&self) -> Result<HybridSecretKey> {
        HybridSecretKey::from_seed(&self.0, RECOVERY_KEY_LABEL)
            .map_err(|_| refused("the recovery seed does not expand"))
    }

    /// The owner anchor's signing key.
    #[must_use]
    pub fn anchor(&self) -> ed25519_dalek::SigningKey {
        let mut bytes = Zeroizing::new(blake3::derive_key(ANCHOR_CONTEXT, &self.0[..]));
        let key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        zeroize::Zeroize::zeroize(&mut *bytes);
        key
    }

    /// The public facts `vault_id` records about this root.
    pub fn public(&self, vault_id: &[u8; 32]) -> Result<RecoveryRoot> {
        let recovery_key = self.recovery_secret()?.public_key().clone();
        let anchor_key = self.anchor().verifying_key().to_bytes();
        Ok(RecoveryRoot {
            id: RecoveryRootId::of(vault_id, &recovery_key, &anchor_key),
            recovery_key,
            anchor_key,
        })
    }
}

/// A root's public half: what the vault stores and replicates.
#[derive(Clone, Debug, PartialEq)]
pub struct RecoveryRoot {
    pub id: RecoveryRootId,
    pub recovery_key: HybridPublicKey,
    pub anchor_key: [u8; 32],
}

impl RecoveryRoot {
    /// A stored root record is this root: the same id and both keys.
    #[must_use]
    pub fn matches(&self, record: &OwnerRootRecord) -> bool {
        record.root == self.id
            && record.anchor_key == self.anchor_key
            && record.recovery_key.suite == crate::authority::MACHINE_ENCRYPTION_SUITE_HYBRID_V1
            && record.recovery_key.key == self.recovery_key.to_bytes()
    }
}
