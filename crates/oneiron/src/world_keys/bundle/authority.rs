//! A private world's authority inside the sealed bundle (FIX 4211): its signed
//! settings and key wrap entries, sealed to the machines that read the world and
//! to the pinned recovery root, never under the world's own key, which those
//! wraps open. A publisher that may not read the world carries the capsule of
//! the latest generation unchanged, so the kit still restores the world's keys
//! once its settings no longer ride the base section.
//!
//! - A capsule is a sealed object of its own (purpose `SealedWorldAuthority`):
//!   a fresh key in anonymous capsules to its readers, the body under it, padded
//!   to [`SEALED_WORLD_AUTHORITY_STEP_BYTES`]. Its frame names the generation that
//!   sealed it, which a carry keeps.
//! - It rides inside the bundle's signed, sealed body after the sections, filed
//!   under its world's id. A machine that opens the outer layer learns no more
//!   than its own authority names; only a reader or the kit opens the entries.
//! - Its body repeats the vault and the world, so a capsule filed under another
//!   world or vault does not open.

#[cfg(feature = "sync")]
use oneiron_crypto::HybridSecretKey;
use zeroize::Zeroizing;

#[cfg(feature = "sync")]
use super::open_outer;
use super::{
    Cursor, Kind, OpenedKeyPads, OpenedVaultBundle, SealPlan, SealedBundleGeneration, SealedObject,
    parse_frame, put_counted, seal_outer, seal_slots,
};
use crate::entity_id::EntityId;
use crate::error::Result;
#[cfg(feature = "sync")]
use crate::error::{Error, SecretError};
#[cfg(feature = "sync")]
use crate::world_keys::RecoveryRootSeed;
use crate::world_keys::{os_fill, refused};

/// A world capsule's size step, inside the bundle's own padding.
const SEALED_WORLD_AUTHORITY_STEP_BYTES: usize = 4 * 1024;

const AUTHORITY_LABEL: &[u8] = b"oneiron/sealed-world-authority/v1\0";

pub(super) const AUTHORITY: Kind = Kind {
    magic: b"OSWA",
    purpose: oneiron_crypto::Purpose::SealedWorldAuthority,
    step: SEALED_WORLD_AUTHORITY_STEP_BYTES,
};

/// What a kit restore does with a world capsule the kit does not open, one
/// sealed before that root was pinned (CALLS: SEALED_AUTHORITY_KIT_MISS).
#[cfg(feature = "sync")]
enum KitMiss {
    /// Restore every other world; that world's keys do not restore from this
    /// kit, and its section stays shut.
    SkipWorld,
}

#[cfg(feature = "sync")]
const SEALED_AUTHORITY_KIT_MISS: KitMiss = KitMiss::SkipWorld;

/// One private world's signed authority entries, sealed to its readers and the
/// root. A holder of the outer layer reads only the world it is filed under.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SealedWorldAuthority {
    world: EntityId,
    object: SealedObject,
}

impl std::fmt::Debug for SealedWorldAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedWorldAuthority")
            .field("world", &self.world)
            .field("object", &self.object)
            .finish()
    }
}

/// What one seal carries on besides sections: the pad object of the latest
/// generation, and each world's authority (FIX 4211).
#[derive(Default)]
pub(crate) struct BundleCarry<'a> {
    /// The pad object of the generation the carried sections come from.
    pub(crate) latest: Option<&'a OpenedKeyPads>,
    /// Each world's signed settings and key wrap entries held here, parents
    /// first: sealed fresh to the world's readers and the root.
    pub(crate) fresh_authority: Vec<(EntityId, &'a [Vec<u8>])>,
    /// Capsules of the latest generation, carried unchanged.
    pub(crate) carried_authority: Vec<&'a SealedWorldAuthority>,
}

impl SealedWorldAuthority {
    /// The world the capsule is filed under.
    #[cfg(feature = "sync")]
    pub(crate) fn world(&self) -> EntityId {
        self.world
    }

    /// `label ‖ vault (32) ‖ world (16) ‖ entry count (4) ‖ each entry
    /// u32-length-prefixed`, under a fresh key sealed to `readers`.
    fn seal(
        vault_id: &[u8; 32],
        generation: SealedBundleGeneration,
        world: EntityId,
        readers: &[oneiron_crypto::HybridPublicKey],
        entries: &[Vec<u8>],
    ) -> Result<Self> {
        let mut body = Zeroizing::new(Vec::new());
        body.extend_from_slice(AUTHORITY_LABEL);
        body.extend_from_slice(vault_id);
        body.extend_from_slice(world.as_bytes());
        let count =
            u32::try_from(entries.len()).map_err(|_| refused("too many authority entries"))?;
        body.extend_from_slice(&count.to_be_bytes());
        for entry in entries {
            put_counted(&mut body, entry)?;
        }
        let mut outer = Zeroizing::new([0u8; 32]);
        os_fill(&mut outer[..])?;
        let slots = seal_slots(AUTHORITY, vault_id, generation, &outer, readers)?;
        let bytes = seal_outer(AUTHORITY, vault_id, generation, &outer, &slots, body, None)?;
        Ok(Self {
            world,
            object: SealedObject { generation, bytes },
        })
    }

    /// The signed entries, with `secret`'s capsule. A secret with no capsule here
    /// gets the typed [`SecretError::SealedBundleNoCapsule`].
    #[cfg(feature = "sync")]
    fn open(&self, vault_id: &[u8; 32], secret: &HybridSecretKey) -> Result<Vec<Vec<u8>>> {
        let malformed = || refused("the world authority capsule is malformed");
        let opened = open_outer(AUTHORITY, vault_id, &self.object.bytes, secret)?;
        let mut cursor = Cursor {
            bytes: &opened.body[..],
            at: 0,
        };
        if cursor.take(AUTHORITY_LABEL.len()) != Some(AUTHORITY_LABEL)
            || cursor.take(32) != Some(&vault_id[..])
            || cursor.take(self.world.as_bytes().len()) != Some(&self.world.as_bytes()[..])
        {
            return Err(refused("the capsule names another vault or world"));
        }
        let count = u32::from_be_bytes(cursor.array().ok_or_else(malformed)?);
        let mut entries = Vec::new();
        for _ in 0..count {
            entries.push(cursor.counted().ok_or_else(malformed)?.to_vec());
        }
        if !cursor.rest_is_zero() {
            return Err(malformed());
        }
        Ok(entries)
    }

    /// `world (16) ‖ the capsule u32-length-prefixed`.
    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(self.world.as_bytes());
        put_counted(out, &self.object.bytes)
    }

    /// `count (4) ‖ each capsule ([`Self::encode`])`; a world appears once.
    pub(super) fn parse_all(cursor: &mut Cursor<'_>) -> Result<Vec<Self>> {
        let malformed = || refused("the bundle's body is malformed");
        let count = u32::from_be_bytes(cursor.array().ok_or_else(malformed)?);
        let mut out: Vec<Self> = Vec::new();
        for _ in 0..count {
            let capsule = Self::parse(cursor)?;
            if out.iter().any(|kept| kept.world == capsule.world) {
                return Err(malformed());
            }
            out.push(capsule);
        }
        Ok(out)
    }

    fn parse(cursor: &mut Cursor<'_>) -> Result<Self> {
        let malformed = || refused("the bundle's body is malformed");
        let world =
            EntityId::from_bytes(cursor.array().ok_or_else(malformed)?).map_err(|_| malformed())?;
        let bytes = cursor.counted().ok_or_else(malformed)?;
        let generation = parse_frame(AUTHORITY, bytes)?.generation;
        Ok(Self {
            world,
            object: SealedObject {
                generation,
                bytes: bytes.to_vec(),
            },
        })
    }
}

/// The capsules one seal files: each fresh world's sealed under `generation` to
/// its readers in `plan` (none when no machine and no kit could open it), then
/// each carried one unchanged. A world appears once.
pub(super) fn seal_authorities(
    plan: &SealPlan,
    generation: SealedBundleGeneration,
    carry: &BundleCarry<'_>,
) -> Result<Vec<SealedWorldAuthority>> {
    let mut out: Vec<SealedWorldAuthority> =
        Vec::with_capacity(carry.fresh_authority.len() + carry.carried_authority.len());
    let twice = || refused("a world's authority appears twice in one bundle");
    for &(world, entries) in &carry.fresh_authority {
        if out.iter().any(|kept| kept.world == world) {
            return Err(twice());
        }
        let readers = plan
            .authority_readers
            .iter()
            .find(|(planned, _)| *planned == world)
            .map_or(&[][..], |(_, readers)| &readers[..]);
        if readers.is_empty() {
            continue;
        }
        out.push(SealedWorldAuthority::seal(
            &plan.vault_id,
            generation,
            world,
            readers,
            entries,
        )?);
    }
    for capsule in &carry.carried_authority {
        if out.iter().any(|kept| kept.world == capsule.world) {
            return Err(twice());
        }
        out.push((*capsule).clone());
    }
    Ok(out)
}

impl OpenedVaultBundle {
    /// The world authority capsules this bundle files, one per world.
    #[cfg(feature = "sync")]
    pub(crate) fn world_authorities(&self) -> &[SealedWorldAuthority] {
        &self.authorities
    }

    /// Kit restore: the signed entries of every world capsule the kit's root
    /// opens, for the import that precedes the restore's fold. A capsule the kit
    /// does not open goes by [`SEALED_AUTHORITY_KIT_MISS`].
    #[cfg(feature = "sync")]
    pub(crate) fn authority_history_with_kit(
        &self,
        seed: &RecoveryRootSeed,
    ) -> Result<Vec<Vec<u8>>> {
        let secret = seed.recovery_secret()?;
        let mut out = Vec::new();
        for capsule in &self.authorities {
            match capsule.open(&self.vault_id, &secret) {
                Ok(entries) => out.extend(entries),
                Err(Error::Secret(SecretError::SealedBundleNoCapsule)) => {
                    match SEALED_AUTHORITY_KIT_MISS {
                        KitMiss::SkipWorld => {}
                    }
                }
                Err(other) => return Err(other),
            }
        }
        Ok(out)
    }
}
