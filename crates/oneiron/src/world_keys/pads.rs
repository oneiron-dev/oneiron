//! A world key's erasable half, and the world erase that destroys it (world
//! privacy fix 7).
//!
//! The signed `WorldKeyWraps` records are immutable, so no wrap in them can be
//! erased. A wrap therefore never seals the key whole: it seals `key ⊕ pad`. The
//! pad is 32 random bytes minted with the key, and it rides its own engine row,
//! `WORLD_KEY_PAD`, one immutable row per key. That row replicates in its
//! world's window of the month it was learned (`ITEM11_LIVE_PAD_CARRIER`), so
//! it goes only where the world's rows go; a kit restore on a new machine takes
//! the pads from the sealed cloud bundle's pad object (`bundle`), each with the
//! time its row was learned, so it rides the same window there. A machine that
//! syncs what it opened takes every pad of a world with a promotion of any of
//! the world's windows (`PROMOTED_WORLD_PAD_SET`). A pad alone is noise, and
//! so is an opened wrap without it.
//!
//! The pad is also published into exterior key custody when its key is minted
//! here (KS-5, FIX 346: `crate::store` world pad custody), and a reader falls
//! back to that custody when the row is not here. The row keeps its pad until
//! the owner's other machines can take a pad from custody (an L03 pad
//! hydration channel); then the row names its custody entry alone.
//!
//! Erasing a world (a hard purge, a batch delete, or a peer's hard tombstone)
//! purges every pad of the world on each replica that applies the erase, and
//! queues a hard tombstone for each, so every wrap of every generation, old root
//! and old machine stops opening. The erase also leaves a permanent destroyed
//! fact: it refuses a late pad for the world, a new key and an open, and carries
//! the receipt, ids only. It stages the retirement of every pad of the world
//! custody holds here, a row or none (FIX 346), carried out after it commits.
//! It also purges the world's sealing mirrors here
//! (`content`), and each machine of the owner's strips the world's pads from
//! every pad object the sealed cloud bundle keeps. Old offline backups and a key
//! a caller already holds are outside what the erasure reaches. A legal hold
//! on the world, or on a claim its key seals, refuses the erase before any pad
//! goes (ARCH-0038 #legal-hold).
//!
//! Deleting a world destroys nothing: its keys, pads and sealed copies stay, so
//! the world restores from old bundles until they age out (DEC-0006). Its
//! content stays hidden by the ordinary delete marker. The delete also records
//! when it happened, and for [`DELETED_WORLD_KEEP_SECS`] after that a pin change
//! still rewraps the world's keys to the new root (`repin`), so the new kit
//! restores it too.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{SEALED_BUNDLE_KEEP, SEALED_BUNDLE_UPLOAD_INTERVAL_SECS, WorldKeyId, os_fill, refused};
use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::deletion::{
    TombstoneReason, TombstoneValueV2, stage_engine_row_hard_erasure_at_in_txn,
    window_label_from_timestamp,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::{DeletionMarker, EntityStoreRead, TombstoneStoreRead};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_WORLD, ENTITY_TYPE_WORLD_KEY_PAD};
use crate::side_table::{self, HexId, Named, Raw, SideTable};
use crate::store::Store;
use crate::temporal::TimeRange;

const PAD_LABEL: &[u8] = b"oneiron/world-key-pad/v1\0";
const PAD_ROW_DOMAIN: &[u8] = b"oneiron/world-key-pad-row/v1";
/// label ‖ world (16) ‖ generation (8, big-endian) ‖ mint (16) ‖ pad (32).
const PAD_BODY_LEN: usize = PAD_LABEL.len() + 16 + 8 + 16 + 32;

const DESTROYED: SideTable<HexId, WorldKeyDestruction, Named> =
    SideTable::new(&side_table::WORLD_KEY_DESTROYED);
/// When a world was soft-deleted here, in vault seconds.
const DELETED: SideTable<HexId, u64, Raw> = SideTable::new(&side_table::WORLD_KEY_DELETED);

/// How long after a soft delete a pin change still rewraps the world's keys:
/// while the bundles that hold the world are kept, 90 daily generations
/// (DEC-0006; the Engine's call, 10-18).
pub(crate) const DELETED_WORLD_KEEP_SECS: u64 =
    SEALED_BUNDLE_KEEP as u64 * SEALED_BUNDLE_UPLOAD_INTERVAL_SECS;

/// One key's pad. It has no `Clone` and no `Serialize`, its `Debug` prints
/// nothing, and its bytes are wiped on drop.
pub(crate) struct WorldKeyPad(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for WorldKeyPad {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WorldKeyPad(..)")
    }
}

impl WorldKeyPad {
    /// A fresh pad from the OS RNG, for a key being minted.
    pub(crate) fn mint() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        os_fill(&mut bytes[..])?;
        Ok(Self(bytes))
    }

    /// A pad back from a sealed pad object (`bundle`).
    pub(super) fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    /// The pad's own bytes, for the sealed pad object (`bundle`).
    pub(super) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `bytes ⊕ pad`: a key to the half its wraps seal, and that half back.
    pub(crate) fn apply(&self, bytes: &[u8; 32]) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        for (slot, (byte, pad)) in out.iter_mut().zip(bytes.iter().zip(self.0.iter())) {
            *slot = byte ^ pad;
        }
        out
    }
}

/// Why a world's keys were destroyed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldKeyDestroyCause {
    /// This vault erased the world through the delete door.
    LocalDelete,
    /// A peer's hard tombstone for the world was applied here.
    ReplayedTombstone,
    /// A batch delete removed the world's row.
    BatchDelete,
}

/// The receipt, and permanent fact, that an erased world's keys were destroyed
/// here. Ids only: never a key, a pad or an envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorldKeyDestruction {
    pub receipt_id: String,
    /// The WORLD row, as hex.
    pub world: String,
    pub cause: WorldKeyDestroyCause,
    /// Each key whose pad was erased, as `generation:mint` with the mint in hex.
    pub keys: Vec<String>,
    /// The erased pad rows, as hex. Each also has a queued hard tombstone.
    pub pad_rows: Vec<String>,
    /// The delete request this erasure rode, as hex, when it had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// The vault's recorded-at clock when the fact was first written.
    pub at: u64,
}

fn hex(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The deterministic row id of `key`'s pad.
pub(crate) fn pad_row_id(key: &WorldKeyId) -> Result<EntityId> {
    EntityId::derive(
        PAD_ROW_DOMAIN,
        &[
            key.world.as_bytes(),
            &key.generation.to_be_bytes(),
            &key.mint,
        ],
    )
}

/// The custody item `key`'s pad rests under: its world, then its mint id
/// (KS-5, FIX 346).
fn pad_item(key: &WorldKeyId) -> [u8; 32] {
    let mut item = [0u8; 32];
    item[..16].copy_from_slice(key.world.as_bytes());
    item[16..].copy_from_slice(&key.mint);
    item
}

fn encode_pad_body(key: &WorldKeyId, pad: &WorldKeyPad) -> Vec<u8> {
    let mut body = Vec::with_capacity(PAD_BODY_LEN);
    body.extend_from_slice(PAD_LABEL);
    body.extend_from_slice(key.world.as_bytes());
    body.extend_from_slice(&key.generation.to_be_bytes());
    body.extend_from_slice(&key.mint);
    body.extend_from_slice(&pad.0[..]);
    body
}

fn decode_pad_body(body: &[u8]) -> Result<(WorldKeyId, WorldKeyPad)> {
    let malformed = || Error::CorruptedIndex("world key pad body");
    if body.len() != PAD_BODY_LEN || !body.starts_with(PAD_LABEL) {
        return Err(malformed());
    }
    let rest = &body[PAD_LABEL.len()..];
    let world = EntityId::from_bytes(rest[..16].try_into().map_err(|_| malformed())?)
        .map_err(|_| malformed())?;
    let generation = u64::from_be_bytes(rest[16..24].try_into().map_err(|_| malformed())?);
    let mint: [u8; 16] = rest[24..40].try_into().map_err(|_| malformed())?;
    let mut pad = Zeroizing::new([0u8; 32]);
    pad.copy_from_slice(&rest[40..72]);
    Ok((
        WorldKeyId {
            world,
            generation,
            mint,
        },
        WorldKeyPad(pad),
    ))
}

/// Whether `world`'s keys were destroyed here, or the world was erased here: a
/// hard-delete marker. A soft delete keeps the keys, so a soft-deleted world
/// still takes its own pads. Absence of the WORLD row alone is not
/// destruction: a first sync can bring a pad before its world.
pub(crate) fn world_keys_destroyed_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    world: EntityId,
) -> Result<bool> {
    let id = HexId(world);
    Ok(DESTROYED.contains(store, txn, &id)?
        || store.port_deletion_marked(txn, DeletionMarker::HardDelete, &world)?)
}

/// Records when `world` was soft-deleted, in the delete's own transaction, so a
/// pin change keeps its keys restorable for [`DELETED_WORLD_KEEP_SECS`]. A row
/// that is not a WORLD is skipped, and the first record stands.
pub(crate) fn note_world_deleted_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    world: EntityId,
    deleted_at: u64,
) -> Result<()> {
    let is_world = store
        .port_entity_with_raw(wtxn, &world, |raw| {
            Ok(EntityMetadataHeader::parse(raw)
                .is_some_and(|header| header.entity_type == ENTITY_TYPE_WORLD))
        })?
        .unwrap_or(false);
    let key = HexId(world);
    if is_world && !DELETED.contains(store, wtxn, &key)? {
        DELETED.put(store, wtxn, &key, &deleted_at)?;
    }
    Ok(())
}

/// Whether `world` was soft-deleted here less than [`DELETED_WORLD_KEEP_SECS`]
/// before `now`, and its keys were not destroyed since: a pin change still
/// rewraps them, so the new kit restores the world from old bundles. An erased
/// world stays shredded.
pub(crate) fn deleted_world_keys_kept_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    world: EntityId,
    now: u64,
) -> Result<bool> {
    let Some(deleted_at) = DELETED.get(store, txn, &HexId(world))? else {
        return Ok(false);
    };
    Ok(now < deleted_at.saturating_add(DELETED_WORLD_KEEP_SECS)
        && !world_keys_destroyed_in_txn(store, txn, world)?)
}

/// The world whose key a pad row `raw` splits: `None` for a row that is not
/// a pad, an error for a pad whose body does not decode. Sync reads it to place
/// a live pad in its world's windows and to keep a destroyed world's late pad
/// out of every window.
pub(crate) fn pad_body_world(raw: &[u8]) -> Option<Result<EntityId>> {
    let header = EntityMetadataHeader::parse(raw)?;
    if header.entity_type != ENTITY_TYPE_WORLD_KEY_PAD {
        return None;
    }
    Some(
        raw.get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("world key pad body"))
            .and_then(pad_world_in_body),
    )
}

/// The world a pad row's `body`, with no header, names; an error for a body
/// that does not decode.
pub(crate) fn pad_world_in_body(body: &[u8]) -> Result<EntityId> {
    decode_pad_body(body).map(|(key, _)| key.world)
}

/// The window a pad of `world` learned at `learned_at` rides: the world's
/// window of that month (`ITEM11_LIVE_PAD_CARRIER`).
fn pad_window(world: EntityId, learned_at: u64) -> String {
    format!(
        "{}@{}",
        window_label_from_timestamp(learned_at),
        world.to_hex()
    )
}

/// Whether `raw` is a late pad: a pad row of a world whose keys this replica
/// has destroyed, or a pad whose body names no world anyone can check. Any
/// other row is not.
pub(crate) fn late_pad_in_txn(store: &Store, txn: &heed::RoTxn<'_>, raw: &[u8]) -> Result<bool> {
    match pad_body_world(raw) {
        None => Ok(false),
        Some(Err(_)) => Ok(true),
        Some(Ok(world)) => world_keys_destroyed_in_txn(store, txn, world),
    }
}

/// `key`'s pad on this replica: its row's, or else the one current custody
/// holds for it (FIX 346). Custody's is never read for a world whose keys
/// were destroyed here: its retirement may still be finishing.
pub(crate) fn pad_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &WorldKeyId,
) -> Result<Option<WorldKeyPad>> {
    if let Some((pad, _)) = pad_row_in_txn(store, txn, key)? {
        return Ok(Some(pad));
    }
    if world_keys_destroyed_in_txn(store, txn, key.world)? {
        return Ok(None);
    }
    Ok(store.world_pad_in_custody(&pad_item(key))?.map(WorldKeyPad))
}

/// [`pad_in_txn`] with the time its row was learned, which files it in its
/// world's window of that month: a sealed pad object carries it (FIX 3790).
pub(super) fn pad_row_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &WorldKeyId,
) -> Result<Option<(WorldKeyPad, u64)>> {
    let id = pad_row_id(key)?;
    let Some(raw) = store.port_entity_raw(txn, &id)?.map(Zeroizing::new) else {
        return Ok(None);
    };
    let header =
        EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("world key pad header"))?;
    if header.entity_type != ENTITY_TYPE_WORLD_KEY_PAD {
        return Err(Error::CorruptedIndex("world key pad row of another kind"));
    }
    let (named, pad) = decode_pad_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
    if named != *key {
        return Err(Error::CorruptedIndex("world key pad names another key"));
    }
    Ok(Some((pad, header.learned_at)))
}

/// `key`'s pad, or the typed refusal: destroyed with its world, or not here yet.
pub(crate) fn require_pad_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &WorldKeyId,
) -> Result<WorldKeyPad> {
    if let Some(pad) = pad_in_txn(store, txn, key)? {
        return Ok(pad);
    }
    if world_keys_destroyed_in_txn(store, txn, key.world)? {
        return Err(refused("the world's keys were destroyed with the world"));
    }
    Err(refused("the key's pad has not reached this machine"))
}

/// The put door's check for a pad row, on every path, local or replicated: the
/// body is one well-formed pad, the row id is the one its key derives, a pad
/// row never changes, and no pad lands for a world whose keys were destroyed.
pub(crate) fn validate_pad_put_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    data: &[u8],
) -> Result<()> {
    let (key, _pad) = decode_pad_body(data)?;
    if pad_row_id(&key)? != *id {
        return Err(refused("a pad row's id is not the one its key derives"));
    }
    if world_keys_destroyed_in_txn(store, txn, key.world)? {
        return Err(refused("the world's keys were destroyed with the world"));
    }
    if let Some(raw) = store.port_entity_raw(txn, id)?.map(Zeroizing::new)
        && raw.get(ENTITY_METADATA_HEADER_LEN..) != Some(data)
    {
        return Err(refused("a world key's pad never changes"));
    }
    Ok(())
}

/// Every pad row of `world` on this replica.
fn world_pad_rows_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    world: EntityId,
) -> Result<Vec<(EntityId, WorldKeyId, u64)>> {
    let mut out = Vec::new();
    for id in store.port_entity_ids_by_type(txn, ENTITY_TYPE_WORLD_KEY_PAD, None)? {
        let id = id?;
        let Some(raw) = store.port_entity_raw(txn, &id)?.map(Zeroizing::new) else {
            continue;
        };
        // A soft-erased pad keeps its header only: its pad is gone already, and
        // it names no world.
        if raw.len() == ENTITY_METADATA_HEADER_LEN {
            continue;
        }
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("world key pad header"))?;
        let (key, _) = decode_pad_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if key.world == world {
            out.push((id, key, header.learned_at));
        }
    }
    Ok(out)
}

/// Whether `world` has a pad here an erase of it would take (FIX 349): a pad
/// row whose body names the world, or a pad of the world custody still
/// holds, with or without a row. Both headerless delete probes read it, so a
/// world whose WORLD row is gone still reaches its pads. A pad row that does
/// not read names no world here.
pub(crate) fn world_pad_scope_exists_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    world: &EntityId,
) -> Result<bool> {
    for id in store.port_entity_ids_by_type(txn, ENTITY_TYPE_WORLD_KEY_PAD, None)? {
        let id = id?;
        let named = store
            .port_entity_with_raw(txn, &id, |raw| {
                Ok(raw.len() > ENTITY_METADATA_HEADER_LEN
                    && matches!(pad_body_world(raw), Some(Ok(of)) if of == *world))
            })?
            .unwrap_or(false);
        if named {
            return Ok(true);
        }
    }
    store.world_pad_custody_held(world)
}

/// The window each pad row of `world` on this replica rides: an erase stages
/// each pad's tombstone there.
pub(crate) fn world_pad_windows_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    world: EntityId,
) -> Result<Vec<String>> {
    Ok(world_pad_rows_in_txn(store, txn, world)?
        .into_iter()
        .map(|(_, _, learned_at)| pad_window(world, learned_at))
        .collect())
}

/// Refuses destroying `world`'s keys while a legal hold stands on the world or
/// on a claim its key seals: destroying the key destroys every such claim's
/// sealed bytes, and every path that destroys bytes reads the hold. Of the rows
/// a key seals, only a claim body names a world (`sync::types::entity_world`).
fn reject_held_world_in_txn(store: &Store, txn: &heed::RoTxn<'_>, world: EntityId) -> Result<()> {
    let mut sealed = vec![world];
    let claims = store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_CLAIM, None)?
        .collect::<Result<Vec<_>>>()?;
    for id in claims {
        let Some(raw) = store.port_entity_raw(txn, &id)? else {
            continue;
        };
        if matches!(crate::sync::types::entity_world(&raw), Ok(Some(of)) if of == world) {
            sealed.push(id);
        }
    }
    store.reject_legal_holds_in_txn(
        txn,
        &sealed,
        &crate::store::legal_hold::HoldActor::UNATTRIBUTED,
    )
}

/// Whether `world`'s keys were destroyed here: the destroyed fact alone, never
/// a delete marker. The world's holds were read when the fact was written.
fn world_keys_destroyed_fact_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    world: EntityId,
) -> Result<bool> {
    DESTROYED.contains(store, txn, &HexId(world))
}

/// Refuses erasing a pad row among `ids` while a legal hold stands on the pad's
/// world or on a claim its key seals ([`reject_held_world_in_txn`]): the pad is
/// the world key's erasable half, so erasing it destroys those sealed bytes too
/// (OF-470). A missing row, a row of another kind and a header-only pad shell,
/// whose pad is already gone, pass; so does a world whose keys were destroyed
/// already, as in [`destroy_world_keys_in_txn`]. A hold on an id itself stays
/// the caller's check. No pad byte leaves its row.
pub(crate) fn reject_held_pad_world_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    ids: &[EntityId],
) -> Result<()> {
    let mut worlds = std::collections::BTreeSet::<EntityId>::new();
    for id in ids {
        let world = store
            .port_entity_with_raw(txn, id, |raw| {
                // A soft-erased pad keeps its header only.
                if raw.len() == ENTITY_METADATA_HEADER_LEN {
                    return Ok(None);
                }
                pad_body_world(raw).transpose()
            })?
            .flatten();
        worlds.extend(world);
    }
    for world in worlds {
        if !world_keys_destroyed_fact_in_txn(store, txn, world)? {
            reject_held_world_in_txn(store, txn, world)?;
        }
    }
    Ok(())
}

/// Whether a legal hold stands on the world of the pad row `raw` or on a claim
/// its key seals: [`reject_held_pad_world_in_txn`]'s read as a bool, for a walk
/// that keeps the pad rather than refusing (OF-470). A row of another kind, a
/// header-only pad shell and a world whose keys were destroyed already read
/// false. A hold on the pad id itself stays the caller's check.
pub(crate) fn held_pad_world_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    raw: &[u8],
) -> Result<bool> {
    if raw.len() == ENTITY_METADATA_HEADER_LEN {
        return Ok(false);
    }
    let Some(world) = pad_body_world(raw).transpose()? else {
        return Ok(false);
    };
    if world_keys_destroyed_fact_in_txn(store, txn, world)? {
        return Ok(false);
    }
    if crate::store::legal_hold::held_in_txn(store, txn, world.as_bytes())? {
        return Ok(true);
    }
    let claims = store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_CLAIM, None)?
        .collect::<Result<Vec<_>>>()?;
    for id in claims {
        let Some(claim) = store.port_entity_raw(txn, &id)? else {
            continue;
        };
        if matches!(crate::sync::types::entity_world(&claim), Ok(Some(of)) if of == world)
            && crate::store::legal_hold::held_in_txn(store, txn, id.as_bytes())?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Destroys `world`'s keys on this replica, in the caller's write transaction:
/// purges every pad row of the world, stages each one's hard tombstone, and
/// writes the permanent destroyed fact with its receipt. `target` is any row
/// being erased; nothing happens unless it is a WORLD here or has pads here.
/// Only an erase calls it: a soft delete keeps the world's keys. Idempotent: a
/// second call keeps the first receipt and purges any pad left.
pub(crate) fn destroy_world_keys_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    target: EntityId,
    cause: WorldKeyDestroyCause,
    request_id: Option<[u8; 16]>,
    deleted_at: u64,
) -> Result<Option<WorldKeyDestruction>> {
    if target == crate::claim::base_world_id() {
        return Ok(None);
    }
    let is_world = store
        .port_entity_with_raw(wtxn, &target, |raw| {
            Ok(EntityMetadataHeader::parse(raw)
                .is_some_and(|header| header.entity_type == ENTITY_TYPE_WORLD))
        })?
        .unwrap_or(false);
    let rows = world_pad_rows_in_txn(store, wtxn, target)?;
    let fact = HexId(target);
    let existing = DESTROYED.get(store, wtxn, &fact)?;
    // A pad custody holds with no row naming it is the world's too (FIX 349).
    if !is_world
        && rows.is_empty()
        && existing.is_none()
        && !store.world_pad_custody_held(&target)?
    {
        return Ok(None);
    }
    // Destroyed once already, only a late pad is left to purge.
    if existing.is_none() {
        reject_held_world_in_txn(store, wtxn, target)?;
    }
    let tombstone = TombstoneValueV2 {
        reason: TombstoneReason::UserHardDelete,
        deleted_at,
        request_id: request_id.unwrap_or(*target.as_bytes()),
    };
    for (id, _, learned_at) in &rows {
        crate::batch::deindex_entity(store, wtxn, id)?;
        let window = pad_window(target, *learned_at);
        stage_engine_row_hard_erasure_at_in_txn(store, wtxn, id, window.clone(), &tombstone)?;
        // The batch that owns this transaction publishes the window once it
        // commits (FIX 3334); an erase door publishes its own (FIX 343).
        crate::batch::queue_pad_tombstone_window(store, wtxn, window);
    }
    super::content::purge_world_mirrors_in_txn(store, wtxn, target)?;
    // Every pad of the world custody holds retires once this commits, a row
    // or none, a late one too (FIX 346).
    store.stage_world_pad_erase_in_txn(wtxn, &target)?;
    if let Some(existing) = existing {
        return Ok(Some(existing));
    }
    let receipt = WorldKeyDestruction {
        receipt_id: store.clock.entity_id()?.to_hex(),
        world: target.to_hex(),
        cause,
        keys: rows
            .iter()
            .map(|(_, key, _)| format!("{}:{}", key.generation, hex(&key.mint)))
            .collect(),
        pad_rows: rows.iter().map(|(id, _, _)| id.to_hex()).collect(),
        request_id: request_id.as_ref().map(hex),
        at: crate::ports::recorded_at_in_txn(store, wtxn)?,
    };
    DESTROYED.put(store, wtxn, &fact, &receipt)?;
    Ok(Some(receipt))
}

/// Which of a world's pads a home serves with a promotion of one of the
/// world's windows (CALLS: `PROMOTED_WORLD_PAD_SET`, FIX 3789).
#[cfg(feature = "sync")]
enum PromotedWorldPads {
    /// Every pad row of the world the home holds, of every key generation: an
    /// old month's rows may name an old key. Never another world's pad, and
    /// never the content of the month a key was minted in.
    AllHeldKeyGenerationsOfThatWorld,
}

#[cfg(feature = "sync")]
const PROMOTED_WORLD_PAD_SET: PromotedWorldPads =
    PromotedWorldPads::AllHeldKeyGenerationsOfThatWorld;

/// One pad row a home serves with a promotion (FIX 3789).
#[cfg(feature = "sync")]
pub struct PromotedWorldPad {
    pub id: EntityId,
    /// The window the row rides: its world's window of the month it was
    /// learned.
    pub window: String,
    /// The row, header and body, as the home holds it.
    pub row: Zeroizing<Vec<u8>>,
}

#[cfg(feature = "sync")]
impl Vault {
    /// The pad rows a home serves with a promotion of one of `world`'s
    /// windows ([`PROMOTED_WORLD_PAD_SET`]): a machine that syncs what it
    /// opened holds a pad only once it promoted the window of the month the
    /// pad was learned, and a key opens only with its pad. None once the
    /// world's keys were destroyed here.
    pub fn promoted_world_pads(&self, world: EntityId) -> Result<Vec<PromotedWorldPad>> {
        let txn = self.store.env.read_txn()?;
        if world_keys_destroyed_in_txn(&self.store, &txn, world)? {
            return Ok(Vec::new());
        }
        let rows = match PROMOTED_WORLD_PAD_SET {
            PromotedWorldPads::AllHeldKeyGenerationsOfThatWorld => {
                world_pad_rows_in_txn(&self.store, &txn, world)?
            }
        };
        let mut pads = Vec::with_capacity(rows.len());
        for (id, _, learned_at) in rows {
            if let Some(row) = self.store.port_entity_raw(&txn, &id)?.map(Zeroizing::new) {
                pads.push(PromotedWorldPad {
                    id,
                    window: pad_window(world, learned_at),
                    row,
                });
            }
        }
        Ok(pads)
    }

    /// Whether a key of `world` this vault's authority names has no pad here
    /// while the world's keys stand: a window of the world promoted here asks
    /// the home for its pads again (FIX 3789).
    pub(crate) fn world_pads_missing(&self, world: EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        if world_keys_destroyed_in_txn(&self.store, &txn, world)? {
            return Ok(false);
        }
        let fold = self.authority_view_readonly_in_txn(&txn)?;
        for key in fold.all_world_keys().filter(|key| key.id.world == world) {
            if pad_in_txn(&self.store, &txn, &key.id)?.is_none() {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

impl Vault {
    /// Stages `key`'s pad row, learned at `learned_at`, in the caller's
    /// transaction: a fresh pad beside the key's first wraps, or a kit-restored
    /// one at the time its row was first learned (FIX 3790). The pad is
    /// published into custody first, synced and journaled before the row
    /// commits (FIX 346); while the row still carries its pad, a custody
    /// fault is warned and the row lands as before.
    pub(super) fn put_pad_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        key: &WorldKeyId,
        pad: &WorldKeyPad,
        learned_at: u64,
    ) -> Result<()> {
        if let Err(error) = self
            .store
            .publish_world_pad_in_txn(txn, &pad_item(key), pad.bytes())
        {
            tracing::warn!(
                kind = ?error.kind(),
                "a world key's pad was not mirrored into key custody; its row carries it"
            );
        }
        let ops = vec![BatchOp::Put {
            id: pad_row_id(key)?,
            entity_type: ENTITY_TYPE_WORLD_KEY_PAD,
            occurred: TimeRange {
                start: learned_at,
                end: learned_at,
            },
            learned_at,
            data: encode_pad_body(key, pad),
            allow_maintenance: true,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }];
        apply_ops(
            &self.store,
            &self.config,
            &self.analyzer,
            txn,
            ops,
            self.text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            false,
            true,
        )
    }

    /// [`destroy_world_keys_in_txn`] for an erase door that holds the vault:
    /// it also drops the world's opened keys from this handle's ring.
    pub(crate) fn destroy_world_keys_for_delete_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        target: EntityId,
        cause: WorldKeyDestroyCause,
        request_id: Option<[u8; 16]>,
    ) -> Result<Option<WorldKeyDestruction>> {
        let deleted_at = self.instant_in_txn(wtxn)?.secs();
        let destroyed =
            destroy_world_keys_in_txn(&self.store, wtxn, target, cause, request_id, deleted_at)?;
        if destroyed.is_some() {
            self.world_key_ring().retain(|id, _| id.world != target);
        }
        Ok(destroyed)
    }

    /// Every world whose keys were destroyed here, with its receipt.
    pub fn world_key_destructions(&self) -> Result<Vec<WorldKeyDestruction>> {
        let txn = self.store.env.read_txn()?;
        Ok(DESTROYED
            .scan(&self.store, &txn)?
            .into_iter()
            .map(|(_, receipt)| receipt)
            .collect())
    }
}
