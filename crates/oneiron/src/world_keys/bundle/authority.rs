//! A private world's authority inside the sealed bundle (FIX 4211): its signed
//! key wrap entries, sealed to the machines that read the world and to the
//! pinned recovery root, never under the world's own key, which those wraps
//! open. A publisher that may not read the world carries the capsule of the
//! latest generation unchanged, so the kit still restores the world's keys.
//! The world's settings are main-log metadata every linked machine folds
//! (PR1a #2961): they ride the base section, not the capsule.
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
//! - Beside it the bundle files the recovery root its sealer sealed it to, as
//!   that sealer recorded it, so an owner's machine sees which capsules still
//!   wait for a reader to seal them to the root pinned now (FIX 4496).
//! - A reader's fresh capsule merges the entries of the capsule it replaces,
//!   and is sealed only from a history that names no parent it lacks; else the
//!   replaced capsule rides on (FIX 4497). An ordinary take imports each
//!   capsule this machine opens (FIX 4495).

use std::collections::{BTreeMap, BTreeSet};

use oneiron_crypto::HybridSecretKey;
use zeroize::Zeroizing;

#[cfg(feature = "sync")]
use super::WorldCapsuleImport;
use super::{
    Cursor, Kind, OpenedKeyPads, OpenedVaultBundle, SealPlan, SealedBundleGeneration, SealedObject,
    open_outer, parse_frame, put_counted, seal_outer, seal_slots,
};
use crate::Vault;
use crate::authority::{AuthorityEntryHash, authority_entry_hash, decode_authority_log_entry_body};
use crate::entity_id::EntityId;
#[cfg(feature = "sync")]
use crate::error::SecretError;
use crate::error::{Error, Result};
#[cfg(feature = "sync")]
use crate::world_keys::RecoveryRootSeed;
use crate::world_keys::{RecoveryRootId, os_fill, refused};

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
    /// kit, its section stays shut, and the restore names it as awaiting a
    /// reader (FIX 4496).
    SkipWorld,
}

#[cfg(feature = "sync")]
const SEALED_AUTHORITY_KIT_MISS: KitMiss = KitMiss::SkipWorld;

/// One private world's signed authority entries, sealed to its readers and the
/// root. A holder of the outer layer reads only the world it is filed under.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SealedWorldAuthority {
    world: EntityId,
    /// The recovery root its sealer sealed it to, as that sealer recorded it
    /// (FIX 4496); `None` when no root was pinned there.
    root: Option<RecoveryRootId>,
    object: SealedObject,
}

impl std::fmt::Debug for SealedWorldAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedWorldAuthority")
            .field("world", &self.world)
            .field("root", &self.root)
            .field("object", &self.object)
            .finish()
    }
}

/// One signed authority entry and the parents it names.
struct HashedEntry {
    bytes: Vec<u8>,
    parents: Vec<AuthorityEntryHash>,
}

/// Signed authority entries by entry hash, each once.
type HashedEntries = BTreeMap<AuthorityEntryHash, HashedEntry>;

/// What one seal carries on besides sections: the pad object of the latest
/// generation, each world's authority (FIX 4211), and the owner work request
/// the upload publishes for.
#[derive(Default)]
pub(crate) struct BundleCarry<'a> {
    /// The pad object of the generation the carried sections come from.
    pub(crate) latest: Option<&'a OpenedKeyPads>,
    /// Each world's signed key wrap entries held here, parents first: sealed
    /// fresh to the world's readers and the root, once whole (FIX 4497).
    pub(crate) fresh_authority: Vec<(EntityId, &'a [Vec<u8>])>,
    /// Capsules of the latest generation, carried unchanged.
    pub(crate) carried_authority: Vec<&'a SealedWorldAuthority>,
    /// Each fresh world's capsule in the latest generation, which its fresh
    /// one replaces: opened with this machine's key and merged into it, or
    /// carried unchanged when the merged history is incomplete (FIX 4497).
    pub(crate) replaced_authority: Vec<&'a SealedWorldAuthority>,
    /// The counted bundle publication request naming this install that the
    /// upload is for, signed into its provenance (WILL L04 row 03); `None`
    /// for the cadence's own upload.
    pub(crate) request: Option<crate::authority::AuthorityEntryHash>,
}

impl SealedWorldAuthority {
    /// The world the capsule is filed under.
    #[cfg(feature = "sync")]
    pub(crate) fn world(&self) -> EntityId {
        self.world
    }

    /// `label ‖ vault (32) ‖ world (16) ‖ entry count (4) ‖ each entry
    /// u32-length-prefixed`, under a fresh key sealed to `readers`, among them
    /// `root`'s key when a root is pinned.
    fn seal(
        vault_id: &[u8; 32],
        generation: SealedBundleGeneration,
        world: EntityId,
        root: Option<RecoveryRootId>,
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
            root,
            object: SealedObject { generation, bytes },
        })
    }

    /// The signed entries, with `secret`'s capsule. A secret with no capsule here
    /// gets the typed `SecretError::SealedBundleNoCapsule`.
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

    /// `world (16) ‖ root (1 ‖ the root's id (32), or 0) ‖ the capsule
    /// u32-length-prefixed`.
    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(self.world.as_bytes());
        match self.root {
            Some(root) => {
                out.push(1);
                out.extend_from_slice(&root.0);
            }
            None => out.push(0),
        }
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
        let root = match cursor.take(1) {
            Some([0]) => None,
            Some([1]) => Some(RecoveryRootId(cursor.array().ok_or_else(malformed)?)),
            _ => return Err(malformed()),
        };
        let bytes = cursor.counted().ok_or_else(malformed)?;
        let generation = parse_frame(AUTHORITY, bytes)?.generation;
        Ok(Self {
            world,
            root,
            object: SealedObject {
                generation,
                bytes: bytes.to_vec(),
            },
        })
    }
}

impl Vault {
    /// The capsules one seal files: each fresh world's sealed under
    /// `generation` to its readers in `plan` (none when no machine and no kit
    /// could open it), then each carried one unchanged. A world appears once.
    /// A fresh world's entries held here merge, each once and parents first,
    /// with those of the capsule it replaces, opened with `secret`, this
    /// machine's key (FIX 4497). A merged history that is not whole here
    /// ([`Self::holds_whole_history`]) is never sealed: the replaced capsule
    /// rides unchanged, or none when there is none, and the world is named
    /// beside the capsules.
    pub(super) fn seal_world_authorities(
        &self,
        secret: &HybridSecretKey,
        plan: &SealPlan,
        generation: SealedBundleGeneration,
        carry: &BundleCarry<'_>,
    ) -> Result<(Vec<SealedWorldAuthority>, Vec<EntityId>)> {
        let mut out: Vec<SealedWorldAuthority> =
            Vec::with_capacity(carry.fresh_authority.len() + carry.carried_authority.len());
        let mut incomplete: Vec<EntityId> = Vec::new();
        let twice = || refused("a world's authority appears twice in one bundle");
        for &(world, entries) in &carry.fresh_authority {
            if out.iter().any(|kept| kept.world == world) || incomplete.contains(&world) {
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
            let replaced = carry
                .replaced_authority
                .iter()
                .find(|capsule| capsule.world == world)
                .copied();
            let mut merged = by_entry_hash(entries.iter().cloned())?;
            // A replaced capsule that does not open here, or holds an entry
            // that does not decode, adds nothing: the closure check judges
            // what is held.
            let old = replaced
                .and_then(|capsule| capsule.open(&plan.vault_id, secret).ok())
                .and_then(|old| by_entry_hash(old).ok())
                .unwrap_or_default();
            for (hash, entry) in old {
                merged.entry(hash).or_insert(entry);
            }
            if !self.holds_whole_history(&merged)? {
                incomplete.push(world);
                out.extend(replaced.cloned());
                continue;
            }
            out.push(SealedWorldAuthority::seal(
                &plan.vault_id,
                generation,
                world,
                plan.kit_root,
                readers,
                &parents_first(merged)?,
            )?);
        }
        for capsule in &carry.carried_authority {
            if out.iter().any(|kept| kept.world == capsule.world)
                || incomplete.contains(&capsule.world)
            {
                return Err(twice());
            }
            out.push((*capsule).clone());
        }
        Ok((out, incomplete))
    }

    /// Whether `merged`, one world's signed key wrap entries, holds that
    /// world's whole history as this vault knows it (FIX 4497): every parent
    /// an entry names is among them or held here as a signed row
    /// ([`Self::authority_history_coverage`]). A parent not held here may be
    /// one of the world's own entries, so a history naming one is not whole:
    /// a machine not yet hydrated holds the tail of the world's entries, and
    /// their parents only as its checkpoint image attests them.
    fn holds_whole_history(&self, merged: &HashedEntries) -> Result<bool> {
        let outside: BTreeSet<AuthorityEntryHash> = merged
            .values()
            .flat_map(|entry| entry.parents.iter().copied())
            .filter(|parent| !merged.contains_key(parent))
            .collect();
        if outside.is_empty() {
            return Ok(true);
        }
        Ok(self
            .authority_history_coverage(&outside)?
            .unavailable
            .is_empty())
    }

    /// Ordinary take (FIX 4495): imports the signed entries of each world
    /// capsule of `opened` that this machine's key opens, through the normal
    /// admission, as a kit restore imports those its kit opens. A capsule
    /// with no capsule for this machine is skipped: this machine reads no such
    /// world. Entries held here already are not imported again, and each
    /// capsule imports in a transaction of its own, so one the admission
    /// refuses keeps no other out and fails no take. Runs with no transaction
    /// open.
    #[cfg(feature = "sync")]
    pub(crate) fn import_opened_world_capsules(
        &self,
        opened: &OpenedVaultBundle,
    ) -> Result<WorldCapsuleImport> {
        let secret = self.machine_secret_outside_txn()?;
        let mut import = WorldCapsuleImport::default();
        for capsule in &opened.authorities {
            let entries = match capsule.open(&opened.vault_id, &secret.secret) {
                Ok(entries) => entries,
                Err(Error::Secret(SecretError::SealedBundleNoCapsule)) => continue,
                Err(_) => {
                    import.refused += 1;
                    continue;
                }
            };
            import.opened += 1;
            let Ok(mut arriving) = by_entry_hash(entries) else {
                import.refused += 1;
                continue;
            };
            let requested: BTreeSet<AuthorityEntryHash> = arriving.keys().copied().collect();
            let held = self.authority_history_coverage(&requested)?.scaffold;
            arriving.retain(|hash, _| !held.contains(hash));
            if arriving.is_empty() {
                continue;
            }
            let blobs: Vec<Vec<u8>> = arriving.into_values().map(|entry| entry.bytes).collect();
            match self.import_signed_authority_history(&blobs) {
                Ok(_) => import.imported += blobs.len(),
                Err(_) => import.refused += 1,
            }
        }
        Ok(import)
    }
}

/// `entries` by entry hash, each once, with the parents each names.
fn by_entry_hash(entries: impl IntoIterator<Item = Vec<u8>>) -> Result<HashedEntries> {
    let mut out = HashedEntries::new();
    for bytes in entries {
        let entry = decode_authority_log_entry_body(&bytes)?;
        let hash = authority_entry_hash(&entry)?;
        out.entry(hash).or_insert(HashedEntry {
            bytes,
            parents: entry.parent_hashes,
        });
    }
    Ok(out)
}

/// The bytes of `entries`, each after every parent it names among them.
fn parents_first(mut entries: HashedEntries) -> Result<Vec<Vec<u8>>> {
    let named: BTreeSet<AuthorityEntryHash> = entries.keys().copied().collect();
    let mut emitted = BTreeSet::new();
    let mut out = Vec::with_capacity(entries.len());
    while !entries.is_empty() {
        let Some(hash) = entries.iter().find_map(|(hash, entry)| {
            entry
                .parents
                .iter()
                .all(|parent| emitted.contains(parent) || !named.contains(parent))
                .then_some(*hash)
        }) else {
            return Err(Error::InvariantViolation(
                "world authority entries name each other as parents",
            ));
        };
        if let Some(entry) = entries.remove(&hash) {
            out.push(entry.bytes);
        }
        emitted.insert(hash);
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
    /// opens, for the import that precedes the restore's fold, and the worlds
    /// whose capsule the kit does not open, which go by
    /// [`SEALED_AUTHORITY_KIT_MISS`] (FIX 4496).
    #[cfg(feature = "sync")]
    pub(crate) fn authority_history_with_kit(
        &self,
        seed: &RecoveryRootSeed,
    ) -> Result<(Vec<Vec<u8>>, Vec<EntityId>)> {
        let secret = seed.recovery_secret()?;
        let mut out = Vec::new();
        let mut skipped = Vec::new();
        for capsule in &self.authorities {
            match capsule.open(&self.vault_id, &secret) {
                Ok(entries) => out.extend(entries),
                Err(Error::Secret(SecretError::SealedBundleNoCapsule)) => {
                    match SEALED_AUTHORITY_KIT_MISS {
                        KitMiss::SkipWorld => skipped.push(capsule.world),
                    }
                }
                Err(other) => return Err(other),
            }
        }
        Ok((out, skipped))
    }

    /// The worlds whose capsule here is not sealed to `pinned`, the recovery
    /// root pinned now, by the root each capsule's sealer recorded (FIX
    /// 4496): the current kit restores each only once a machine that reads
    /// it publishes again. None when no root is pinned.
    #[cfg(feature = "sync")]
    pub(crate) fn worlds_awaiting_reader(&self, pinned: Option<RecoveryRootId>) -> Vec<EntityId> {
        let Some(pinned) = pinned else {
            return Vec::new();
        };
        self.authorities
            .iter()
            .filter(|capsule| capsule.root != Some(pinned))
            .map(|capsule| capsule.world)
            .collect()
    }
}
