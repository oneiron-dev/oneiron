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

mod machine;
mod root;
mod root_issue;
mod state;
mod vault_doors;
mod wrap;

#[cfg(test)]
mod tests;

pub use self::machine::{machine_encryption_key, machine_secret};
pub(crate) use self::root::sign_as_anchor;
pub use self::root::{RecoveryRoot, RecoveryRootId, RecoveryRootSeed, SeedOrigin};
pub use self::root_issue::PreparedRoot;
pub use self::state::{WorldRecoveryState, recovery_state};
pub use self::wrap::{open_world_key, seal_world_key};

use zeroize::Zeroizing;

use crate::entity_id::EntityId;
use crate::error::{Error, Result, SecretError};

/// The crypto epoch every world-key envelope is sealed at.
pub const WORLD_KEY_EPOCH: u64 = 1;
/// The key generation P6b mints. Rotation (P11) is not ratified; the field is bound
/// now so that rotation does not change the format.
pub const FIRST_GENERATION: u64 = 1;

/// One world key: the world, its generation, and the random id of the mint that made it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorldKeyId {
    pub world: EntityId,
    pub generation: u64,
    pub mint: [u8; 16],
}

impl WorldKeyId {
    /// The envelope `key_id`: world (16) ‖ generation (8, big-endian) ‖ mint (16).
    #[must_use]
    pub fn envelope_key_id(&self) -> [u8; 40] {
        let mut out = [0u8; 40];
        out[..16].copy_from_slice(self.world.as_bytes());
        out[16..24].copy_from_slice(&self.generation.to_be_bytes());
        out[24..].copy_from_slice(&self.mint);
        out
    }
}

/// The world's settings as the wrapping machine saw them: a digest of the world's live
/// settings edits (P2). All zero means no edit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyRevision(pub [u8; 32]);

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

/// Who one envelope opens for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WrapRecipient {
    /// A machine (its MACHINE row) through its machine secret.
    Machine(EntityId),
    /// The recovery root, through the kit.
    RecoveryRoot(RecoveryRootId),
}

impl WrapRecipient {
    /// The envelope `recipient`: 0x01 ‖ machine id (17 B), or 0x02 ‖ root id (33 B).
    #[must_use]
    pub fn envelope_recipient(&self) -> Vec<u8> {
        let (tag, id): (u8, &[u8]) = match self {
            Self::Machine(machine) => (0x01, &machine.as_bytes()[..]),
            Self::RecoveryRoot(root) => (0x02, &root.0[..]),
        };
        let mut out = Vec::with_capacity(1 + id.len());
        out.push(tag);
        out.extend_from_slice(id);
        out
    }
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
