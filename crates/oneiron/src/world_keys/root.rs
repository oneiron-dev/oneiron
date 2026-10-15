//! The owner's recovery root: 32 random bytes that only the recovery kit carries.
//!
//! One seed gives two keys, each with its own label:
//! - the recovery keypair (hybrid). World keys are wrapped to its public half, and
//!   the kit opens them with the secret half;
//! - the owner anchor (Ed25519). It signs the root record and an Owned mark at kit
//!   issue or restore (E2).
//!
//! The engine never stores the seed. How the kit's pieces carry the 32 bytes is the
//! kit's business; this module takes back only the kit's whole restore, never bare
//! bytes, so it knows the kit's kind and how many genuine pieces rebuilt it.

use oneiron_crypto::{HybridPublicKey, HybridSecretKey};
use zeroize::Zeroizing;

pub use oneiron_authority::authority::RecoveryRootId;

use super::{os_fill, refused};
use crate::authority::OwnerRootRecord;
use crate::error::Result;
use crate::recovery::{KitSecretKind, RestoredKitSecret};

const RECOVERY_KEY_LABEL: &[u8] = b"oneiron/world-recovery-root/v1";
const ANCHOR_CONTEXT: &str = "oneiron/owner-anchor/v1";

/// The kit's secret. `Debug` is redacted and the bytes are wiped on drop.
pub struct RecoveryRootSeed {
    bytes: Zeroizing<[u8; 32]>,
    origin: SeedOrigin,
}

/// Where a seed came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedOrigin {
    /// Drawn here, by the root's issuer.
    Drawn,
    /// Rebuilt by the kit, from this many genuine stored pieces.
    Kit { stored_pieces: u8 },
}

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
        Ok(Self {
            bytes: seed,
            origin: SeedOrigin::Drawn,
        })
    }

    /// The bytes, for the kit issuer only. The engine never stores them.
    #[must_use]
    pub fn kit_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.bytes)
    }

    /// The seed back from the kit's restore. A kit that carries another secret, and an
    /// all-zero seed, are refused before anything is kept.
    pub fn from_restored_kit(secret: RestoredKitSecret) -> Result<Self> {
        if secret.kind() != KitSecretKind::RecoveryRoot {
            return Err(refused("the kit carries another secret"));
        }
        if *secret.as_bytes() == [0u8; 32] {
            return Err(refused("an all-zero recovery seed"));
        }
        let stored_pieces = secret.stored_pieces();
        Ok(Self {
            bytes: secret.into_bytes(),
            origin: SeedOrigin::Kit { stored_pieces },
        })
    }

    /// Rebuilt from two or more genuine stored pieces. With one, the passphrase gave the
    /// other point, and anyone who knows it could have written that piece for a seed of
    /// their own. A `Drawn` seed is the issuer's, not a kit's.
    #[must_use]
    pub fn authenticated(&self) -> bool {
        matches!(self.origin, SeedOrigin::Kit { stored_pieces } if stored_pieces >= 2)
    }

    /// Where the seed came from.
    #[must_use]
    pub fn origin(&self) -> SeedOrigin {
        self.origin
    }

    /// The recovery keypair's secret half. It opens the root's wraps.
    pub fn recovery_secret(&self) -> Result<HybridSecretKey> {
        HybridSecretKey::from_seed(&self.bytes, RECOVERY_KEY_LABEL)
            .map_err(|_| refused("the recovery seed does not expand"))
    }

    /// The owner anchor's signing key.
    #[must_use]
    pub fn anchor(&self) -> ed25519_dalek::SigningKey {
        let key = anchor_key(&self.bytes);
        zeroize::zeroize_stack::<ANCHOR_STACK_WIPE>();
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

/// Stack bytes wiped after the owner anchor's key is built: in a release build the
/// build leaves the anchor's secret below its caller (Wonder code-R4 W4-F1). Stack
/// painting (`root::tests`, x86_64 Linux, rustc 1.96, 2026-10-14): the build reached 4,408
/// bytes below its caller in a release build and 4,567 in a dev build, so about 1.8x.
/// Signing leaves no anchor secret below its caller in either build, so it wipes nothing.
const ANCHOR_STACK_WIPE: usize = 8 * 1024;

/// Out of line, so the wipe in [`RecoveryRootSeed::anchor`] covers its frames.
#[inline(never)]
fn anchor_key(seed: &[u8; 32]) -> ed25519_dalek::SigningKey {
    let mut hasher = blake3::Hasher::new_derive_key(ANCHOR_CONTEXT);
    hasher.update(seed);
    let mut digest = hasher.finalize();
    let key = ed25519_dalek::SigningKey::from_bytes(digest.as_bytes());
    // The hasher's block buffer still holds the seed, and the digest is the anchor's
    // secret (Wonder W2-F2).
    zeroize::Zeroize::zeroize(&mut hasher);
    zeroize::Zeroize::zeroize(&mut digest);
    key
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

#[cfg(all(
    test,
    any(target_arch = "x86_64", target_arch = "aarch64"),
    any(target_os = "linux", target_os = "macos")
))]
mod tests;
