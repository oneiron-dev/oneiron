//! A world key's erasable half, and the world delete that destroys it (world
//! privacy fix 7).
//!
//! The signed `WorldKeyWraps` records are immutable, so no wrap in them can be
//! erased. A wrap therefore never seals the key whole: it seals `key ⊕ pad`. The
//! pad is 32 random bytes minted with the key, and it rides its own engine row,
//! `WORLD_KEY_PAD`, one immutable row per key. That row replicates with the
//! vault's base rows, the host included, so a kit restore on a new machine can
//! rebuild the key. A pad alone is noise, and so is an opened wrap without it.
//!
//! Deleting a world purges every pad of the world on each replica that applies
//! the delete, and queues a hard tombstone for each, so every wrap of every
//! generation, old root and old machine stops opening. The delete also leaves a
//! permanent destroyed fact: it refuses a late pad for the world, a new key and
//! an open, and carries the receipt, ids only. It also purges the world's sealed
//! copies on this replica's shelf and its sealing mirrors (`content`). Old offline
//! backups and a key a caller already holds are outside what the erasure reaches.
//! A legal hold on the world, or on a claim its key seals, refuses the delete
//! before any pad goes (ARCH-0038 #legal-hold).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{WorldKeyId, os_fill, refused};
use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::deletion::{
    HARD_DELETE_MARKER, IDENTITY_SOFT_DELETE_MARKER, TombstoneReason, TombstoneValueV2,
    stage_engine_row_hard_erasure_in_txn,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_WORLD, ENTITY_TYPE_WORLD_KEY_PAD};
use crate::side_table::{self, HexId, Named, SideTable};
use crate::store::Store;
use crate::temporal::TimeRange;

const PAD_LABEL: &[u8] = b"oneiron/world-key-pad/v1\0";
const CONTENT_TAG_CONTEXT: &str = "oneiron/sealed-world-content-tag/v1";
const PAD_ROW_DOMAIN: &[u8] = b"oneiron/world-key-pad-row/v1";
/// label ‖ world (16) ‖ generation (8, big-endian) ‖ mint (16) ‖ pad (32).
const PAD_BODY_LEN: usize = PAD_LABEL.len() + 16 + 8 + 16 + 32;

const DESTROYED: SideTable<HexId, WorldKeyDestruction, Named> =
    SideTable::new(&side_table::WORLD_KEY_DESTROYED);

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

    /// The tag `key`'s sealed content is filed under: `BLAKE3-derive_key(
    /// "oneiron/sealed-world-content-tag/v1", key id ‖ pad)`. Every replica that
    /// holds the pad can compute it; none can open content with it.
    pub(super) fn content_tag(&self, key: &WorldKeyId) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(CONTENT_TAG_CONTEXT);
        hasher.update(&key.envelope_key_id());
        hasher.update(&self.0[..]);
        let tag = *hasher.finalize().as_bytes();
        zeroize::Zeroize::zeroize(&mut hasher);
        tag
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
    /// This vault deleted the world through the delete door.
    LocalDelete,
    /// A peer's tombstone for the world was applied here.
    ReplayedTombstone,
    /// A batch delete removed the world's row.
    BatchDelete,
}

/// The receipt, and permanent fact, that a deleted world's keys were destroyed
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
    /// The tags of the world's sealed copies, as hex: a holder without the pads
    /// purges its copies by these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sealed_tags: Vec<String>,
    /// Sealed copies purged from this replica's shelf.
    #[serde(default)]
    pub sealed_copies: u64,
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

/// Whether `world`'s keys were destroyed here, or the world was deleted here in
/// a way that forbids its keys: a hard-delete marker, or a soft delete once
/// applied. Absence of the WORLD row alone is not destruction: a first sync
/// can bring a pad before its world.
pub(crate) fn world_keys_destroyed_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    world: EntityId,
) -> Result<bool> {
    let id = HexId(world);
    Ok(DESTROYED.contains(store, txn, &id)?
        || HARD_DELETE_MARKER.contains(store, txn, &id)?
        || IDENTITY_SOFT_DELETE_MARKER.contains(store, txn, &id)?)
}

/// The world whose key a pad row `raw` splits: `None` for a row that is not
/// a pad, an error for a pad whose body does not decode. Sync reads it to keep
/// a destroyed world's late pad out of every window.
pub(crate) fn pad_body_world(raw: &[u8]) -> Option<Result<EntityId>> {
    let header = EntityMetadataHeader::parse(raw)?;
    if header.entity_type != ENTITY_TYPE_WORLD_KEY_PAD {
        return None;
    }
    Some(
        raw.get(ENTITY_METADATA_HEADER_LEN..)
            .ok_or(Error::CorruptedIndex("world key pad body"))
            .and_then(decode_pad_body)
            .map(|(key, _)| key.world),
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

/// `key`'s pad on this replica, if its row is here.
pub(crate) fn pad_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key: &WorldKeyId,
) -> Result<Option<WorldKeyPad>> {
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
    Ok(Some(pad))
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

/// Every pad row of `world` on this replica, with its sealed-content tag.
fn world_pad_rows_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    world: EntityId,
) -> Result<Vec<(EntityId, WorldKeyId, u64, [u8; 32])>> {
    let mut out = Vec::new();
    for id in store.port_entity_ids_by_type(txn, ENTITY_TYPE_WORLD_KEY_PAD, None)? {
        let id = id?;
        let Some(raw) = store.port_entity_raw(txn, &id)?.map(Zeroizing::new) else {
            continue;
        };
        let header = EntityMetadataHeader::parse(&raw)
            .ok_or(Error::CorruptedIndex("world key pad header"))?;
        let (key, pad) = decode_pad_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if key.world == world {
            let tag = pad.content_tag(&key);
            out.push((id, key, header.learned_at, tag));
        }
    }
    Ok(out)
}

/// Whether some key whose pad is on this replica files its sealed content
/// under `tag`.
pub(super) fn live_pad_tag_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    tag: &[u8; 32],
) -> Result<bool> {
    for id in store.port_entity_ids_by_type(txn, ENTITY_TYPE_WORLD_KEY_PAD, None)? {
        let id = id?;
        let Some(raw) = store.port_entity_raw(txn, &id)?.map(Zeroizing::new) else {
            continue;
        };
        let (key, pad) = decode_pad_body(
            raw.get(ENTITY_METADATA_HEADER_LEN..)
                .ok_or(Error::CorruptedIndex("world key pad header"))?,
        )?;
        if pad.content_tag(&key) == *tag {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Refuses destroying `world`'s keys while a legal hold stands on the world or
/// on a claim its key seals: destroying the key destroys every such claim's
/// sealed bytes, and every path that destroys bytes reads the hold. Only a
/// claim body names a world (`sync::types::entity_world`).
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

/// Destroys `world`'s keys on this replica, in the caller's write transaction:
/// purges every pad row of the world, stages each one's hard tombstone, and
/// writes the permanent destroyed fact with its receipt. `target` is any row
/// being deleted; nothing happens unless it is a WORLD here or has pads here.
/// Idempotent: a second call keeps the first receipt and purges any pad left.
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
        .port_entity_raw(wtxn, &target)?
        .and_then(|raw| EntityMetadataHeader::parse(&raw).map(|header| header.entity_type))
        == Some(ENTITY_TYPE_WORLD);
    let rows = world_pad_rows_in_txn(store, wtxn, target)?;
    let fact = HexId(target);
    let existing = DESTROYED.get(store, wtxn, &fact)?;
    if !is_world && rows.is_empty() && existing.is_none() {
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
    for (id, _, learned_at, _) in &rows {
        crate::batch::deindex_entity(store, wtxn, id)?;
        stage_engine_row_hard_erasure_in_txn(store, wtxn, id, *learned_at, &tombstone)?;
    }
    let tags: Vec<[u8; 32]> = rows.iter().map(|(_, _, _, tag)| *tag).collect();
    let sealed_copies =
        super::content::purge_sealed_world_content_in_txn(store, wtxn, target, &tags)?;
    if let Some(existing) = existing {
        return Ok(Some(existing));
    }
    let receipt = WorldKeyDestruction {
        receipt_id: store.clock.entity_id()?.to_hex(),
        world: target.to_hex(),
        cause,
        keys: rows
            .iter()
            .map(|(_, key, _, _)| format!("{}:{}", key.generation, hex(&key.mint)))
            .collect(),
        pad_rows: rows.iter().map(|(id, _, _, _)| id.to_hex()).collect(),
        sealed_tags: tags
            .iter()
            .map(|tag| tag.iter().map(|byte| format!("{byte:02x}")).collect())
            .collect(),
        sealed_copies,
        request_id: request_id.as_ref().map(hex),
        at: crate::ports::recorded_at_in_txn(store, wtxn)?,
    };
    DESTROYED.put(store, wtxn, &fact, &receipt)?;
    Ok(Some(receipt))
}

impl Vault {
    /// Stages `key`'s fresh pad row in the caller's transaction, beside the
    /// key's first wraps.
    pub(super) fn put_pad_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        key: &WorldKeyId,
        pad: &WorldKeyPad,
        now: u64,
    ) -> Result<()> {
        let ops = vec![BatchOp::Put {
            id: pad_row_id(key)?,
            entity_type: ENTITY_TYPE_WORLD_KEY_PAD,
            occurred: TimeRange {
                start: now,
                end: now,
            },
            learned_at: now,
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

    /// [`destroy_world_keys_in_txn`] for a delete door that holds the vault:
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
