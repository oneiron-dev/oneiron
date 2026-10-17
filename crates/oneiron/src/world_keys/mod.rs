//! Per-world keys: a private world's own data key, wrapped to the machines that may
//! read the world and to the owner's recovery root (world privacy P6b, ruling fix 1).
//!
//! Three secrets, three homes:
//! - A **world key** is 32 random bytes for one world and one key generation. It lives
//!   only in memory, in the session of a machine that may read the world.
//! - A **machine secret** is a 32-byte seed in this install's this-device-only keystore
//!   (`oneiron-keystore`). It expands to the hybrid keypair whose public half is the
//!   machine's encryption key.
//! - A **recovery root seed** is 32 random bytes that only the recovery kit carries.
//!   It expands to the recovery keypair and to the owner anchor.
//!
//! The root is asymmetric. Wrapping a world key to it needs only its public key, so no
//! machine holds a secret that opens a world it may not read. None of the three
//! secrets is derived from the vault key, the host root or an install key. What
//! replicates is public keys and sealed envelopes (`oneiron-crypto`, purpose
//! `WorldDek`). An unwrapped key or a seed never replicates.

mod content;
#[cfg(feature = "sync")]
mod content_window;
mod doors;
mod kit;
mod machine;
mod pads;
mod reassert;
mod repin;
mod root;
mod root_doors;
mod root_issue;
mod session;
mod state;
mod vault_doors;
mod vault_key;
mod wrap;

#[cfg(test)]
mod tests;

pub use self::content::{
    OpenedSealedContent, SEALED_RETENTION_SECS, SealedContentBinding, SealedContentId,
    SealedContentKind, SealedResidenceContent,
};
#[cfg(feature = "sync")]
pub use self::content_window::SealedTake;
pub use self::doors::WorldKeyStatus;
pub(crate) use self::doors::{MachineSecret, SequenceCounter, open_counted, recipients};
pub use self::kit::{
    ConfirmedWorldKit, IssuedWorldKit, StoredCost, StoredKit, WORLD_KIT_ESCROW, WorldKitRestore,
    WorldKitStatus,
};
pub(crate) use self::machine::{keystore_error, slot_seed};
pub use self::machine::{machine_encryption_key, machine_secret};
pub use self::pads::{WorldKeyDestroyCause, WorldKeyDestruction};
pub(crate) use self::pads::{
    destroy_world_keys_in_txn, late_pad_in_txn, pad_body_world, validate_pad_put_in_txn,
    world_keys_destroyed_in_txn,
};
pub use self::repin::{NarrowedWorld, RepinReport, Withheld};
pub use self::root::{RecoveryRoot, RecoveryRootId, RecoveryRootSeed, SeedOrigin};
pub use self::root_doors::{ActivatedRoot, AnchoredMachine, KitConfirmation, RootRestore};
pub use self::root_issue::PreparedRoot;
pub use self::session::WorldKeyFrontierCheck;
pub(crate) use self::session::WorldKeySession;
pub use self::state::{WorldRecoveryState, recovery_state};
pub(crate) use self::vault_key::CarriedVaultKey;
pub use self::vault_key::{
    NewVaultKeyWrap, VaultKeyStatus, VaultKeyUnlock, VaultKeyWrapInfo, VaultKeyWrapKind,
    escrow_recipient, passkey_prf_input,
};
pub(crate) use self::wrap::{open_world_key, seal_world_key};
pub use crate::error::KitRecord;
pub use oneiron_authority::authority::{
    FIRST_GENERATION, PolicyRevision, WORLD_KEY_EPOCH, WorldKeyId, WrapRecipient,
};
pub use oneiron_crypto::{HybridPublicKey, HybridSecretKey};

use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};

/// Everything a wrap is bound to. A reader states it from its own records; the
/// envelope's claims are never the expectation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorldKeyBinding {
    pub vault_id: [u8; 32],
    pub key: WorldKeyId,
    /// The vault owner PERSON. A WORLD row names no owner.
    pub owner: EntityId,
    pub policy: PolicyRevision,
    /// The key's commitment, fixed by its mint record: a wrap that opens to other
    /// bytes is refused.
    pub commitment: [u8; 32],
}

/// An unwrapped world key. It has no `Clone` and no `Serialize`, its `Debug` prints
/// only the id, and its bytes are wiped on drop.
pub struct WorldKey {
    id: WorldKeyId,
    bytes: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for WorldKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorldKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl WorldKey {
    /// A fresh key for `world` at `generation`, with a random mint id, from the OS RNG.
    pub fn mint(world: EntityId, generation: u64) -> Result<Self> {
        if world == base_world() {
            return Err(refused("base reality has no world key"));
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        let mut mint = [0u8; 16];
        os_fill(&mut bytes[..])?;
        os_fill(&mut mint)?;
        Ok(Self {
            id: WorldKeyId {
                world,
                generation,
                mint,
            },
            bytes,
        })
    }

    /// Fresh bytes under `id`: what someone who knows only a key's id mints
    /// to replace it.
    #[cfg(test)]
    pub(crate) fn other_bytes_for_test(id: WorldKeyId) -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        os_fill(&mut bytes[..])?;
        Ok(Self { id, bytes })
    }

    #[must_use]
    pub fn id(&self) -> &WorldKeyId {
        &self.id
    }

    /// `BLAKE3-derive_key("oneiron/world-key-commitment/v1", key_id ‖ key)`. It reveals
    /// nothing about a random 256-bit key, and it pins which bytes the id names.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        commitment(&self.id, &self.bytes)
    }

    /// The key bytes, for the code that seals world content under it.
    pub(crate) fn expose(&self) -> &[u8; 32] {
        &self.bytes
    }
}

fn commitment(id: &WorldKeyId, key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("oneiron/world-key-commitment/v1");
    hasher.update(&id.envelope_key_id());
    hasher.update(key);
    let commitment = *hasher.finalize().as_bytes();
    // The hasher's block buffer still holds the key's bytes (Wonder W2-F2).
    zeroize::Zeroize::zeroize(&mut hasher);
    commitment
}

/// The reserved base-reality scope. It is never private and has no key.
fn base_world() -> EntityId {
    oneiron_contracts::claim::base_world_id()
}

pub(crate) fn refused(reason: &'static str) -> Error {
    Error::Secret(SecretError::WorldKeyRefused(reason))
}

/// Fills `buf` from the OS CSPRNG. A failure is an error, never a weaker key.
pub(crate) fn os_fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| refused("os entropy unavailable"))
}
