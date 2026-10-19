//! Which rows of a window a federation peer's import brought (Docs Q04).
//! Window admission judges a peer's rows in a read transaction before the
//! import; a door that must judge one again in its own writer transaction,
//! after a local change that committed in between, asks here. The import
//! records each such row with the exact bytes the peer brought before it
//! lands any of them, so the door tells the peer's row from this vault's own
//! by id and bytes, as the birth watch does, and forward rematerialization
//! after a crash still finds it.
//!
//! The record is this machine's. So window admission also carries each such
//! row's digest in the admitted part's `peer_origins` map (FIX 2902), and a
//! staged import lands it with the pinned bytes (FIX 2904). The entity door
//! records a carried digest that matches the bytes it lands in its writer
//! transaction, so another machine of the owner's that gets the row by its
//! own sync judges it as the peer's too. Only this vault's admission mints
//! the map; federation copies none in or out, and a proved machine of this
//! vault's gets it beside the rows it is sent. A local write that re-authors
//! the row drops its carried and recorded origin.

use loro::{LoroDoc, LoroMap, LoroValue, ValueOrContainer};

use crate::batch::EntityMetadataHeader;
use crate::error::{Error, Result};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_EMBEDDING_SETUP};
use crate::side_table::{self, Raw, SideTable};
use crate::sync::loro_support::{
    map_delete, map_for_each_value_bytes, map_get_bytes, map_insert_bytes,
};
use crate::{EntityId, Vault};

/// The window root map that carries, under a row's id, the digest of the
/// bytes a peer's import brought for it (FIX 2902; a call, the wire key).
pub(in crate::sync) const PEER_ORIGIN_MAP: &str = "peer_origins";

/// The kinds whose door judges a peer's row apart from this vault's own.
const PEER_JUDGED_KINDS: [u8; 2] = [ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_EMBEDDING_SETUP];

/// The blake3 digest of the bytes a peer's import brought for one row of a
/// window. Key: hex32 (entity id) ":" window key.
const PEER_ORIGIN: SideTable<String, [u8; 32], Raw> = SideTable::new(&side_table::SYNC_PEER_ORIGIN);

fn origin_key(window_key: &str, id: &EntityId) -> String {
    format!("{}:{window_key}", id.to_hex())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn judged(blob: &[u8]) -> bool {
    EntityMetadataHeader::parse(blob)
        .is_some_and(|header| PEER_JUDGED_KINDS.contains(&header.entity_type))
}

/// The rows of a peer's admitted entities map whose door judges them by
/// origin, each with the digest of the bytes the peer brought.
fn peer_rows(entities: &LoroMap) -> Vec<(EntityId, [u8; 32])> {
    let mut rows = Vec::new();
    map_for_each_value_bytes(entities, |key, value| {
        if let (Ok(id), Some(blob)) = (EntityId::from_hex(key), value)
            && judged(blob)
        {
            rows.push((id, digest(blob)));
        }
    });
    rows
}

/// [`peer_rows`] of a part window admission copied, each also carried in
/// the part's [`PEER_ORIGIN_MAP`] before it commits. The map is minted here
/// from the copied rows, never taken from the sender.
pub(in crate::sync) fn carry_peer_rows(admitted: &LoroDoc) -> Result<Vec<(EntityId, [u8; 32])>> {
    let rows = peer_rows(&admitted.get_map("entities"));
    if !rows.is_empty() {
        let carried = admitted.get_map(PEER_ORIGIN_MAP);
        for (id, sent) in &rows {
            map_insert_bytes(&carried, &id.to_hex(), sent)?;
        }
    }
    Ok(rows)
}

/// Records the rows a peer's import brings into `window_key`, committed
/// before the import lands any of them. A later import of the same row
/// supersedes its record.
pub(in crate::sync) fn record_peer_rows(
    vault: &Vault,
    window_key: &str,
    rows: &[(EntityId, [u8; 32])],
) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|wtxn| {
        for (id, sent) in rows {
            PEER_ORIGIN.put(&vault.store, wtxn, &origin_key(window_key, id), sent)?;
        }
        Ok(())
    })
}

/// Whether `blob` at `id` in `window_key` holds the exact bytes a peer's
/// import brought. A record whose row now holds other bytes is dropped: its
/// carrier was replaced.
pub(in crate::sync) fn peer_row_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &EntityId,
    blob: &[u8],
) -> Result<bool> {
    let key = origin_key(window_key, id);
    let Some(held) = PEER_ORIGIN.get(&vault.store, wtxn, &key)? else {
        return Ok(false);
    };
    if held == digest(blob) {
        return Ok(true);
    }
    PEER_ORIGIN.delete(&vault.store, wtxn, &key)?;
    Ok(false)
}

/// Drops the record of each carrier a local path removes, in any window,
/// when it holds those exact bytes.
pub(in crate::sync) fn forget_peer_rows(
    vault: &Vault,
    carriers: &[(EntityId, Vec<u8>)],
) -> Result<()> {
    if !carriers.iter().any(|(_, carrier)| judged(carrier)) {
        return Ok(());
    }
    vault.with_write_txn_grouped(|wtxn| {
        for (id, carrier) in carriers.iter().filter(|(_, carrier)| judged(carrier)) {
            let removed = digest(carrier);
            let prefix = format!("{}:", id.to_hex());
            for (key, held) in PEER_ORIGIN.scan_from(&vault.store, wtxn, prefix.as_bytes())? {
                if held == removed {
                    PEER_ORIGIN.delete(&vault.store, wtxn, &key)?;
                }
            }
        }
        Ok(())
    })
}

/// Whether `doc` holds a peer origin map. Looking a root up by name creates
/// it: look first.
fn carries_origins(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(PEER_ORIGIN_MAP))
}

/// Records, in the writer's transaction, the origin `doc` carries for `blob`
/// at `id` in `window_key` when it names those exact bytes: an import of
/// this vault's judged them a peer's.
pub(in crate::sync) fn carried_origin_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    doc: &LoroDoc,
    window_key: &str,
    id: &EntityId,
    blob: &[u8],
) -> Result<()> {
    if !judged(blob) || !carries_origins(doc) {
        return Ok(());
    }
    let sent = digest(blob);
    if map_get_bytes(&doc.get_map(PEER_ORIGIN_MAP), &id.to_hex()).as_deref() == Some(&sent[..]) {
        PEER_ORIGIN.put(&vault.store, wtxn, &origin_key(window_key, id), &sent)?;
    }
    Ok(())
}

/// Copies into `out` the origin `source` carries for each row `out` holds
/// with the exact bytes it names. The caller commits.
pub(in crate::sync) fn copy_peer_origins(source: &LoroDoc, out: &LoroDoc) -> Result<()> {
    if !carries_origins(source) {
        return Ok(());
    }
    let carried = source.get_map(PEER_ORIGIN_MAP);
    let mut rows = Vec::new();
    map_for_each_value_bytes(&out.get_map("entities"), |key, blob| {
        if let Some(sent) = blob.map(digest)
            && map_get_bytes(&carried, key).as_deref() == Some(&sent[..])
        {
            rows.push((key.to_owned(), sent));
        }
    });
    if rows.is_empty() {
        return Ok(());
    }
    let copied = out.get_map(PEER_ORIGIN_MAP);
    for (key, sent) in &rows {
        map_insert_bytes(&copied, key, sent)?;
    }
    Ok(())
}

/// Drops the origin `doc` carries for `id` and every record of it here: a
/// local write re-authored the row, `blob` now, so it is this vault's own
/// and its owner may turn it back on.
pub(in crate::sync) fn forget_peer_origin(
    vault: &Vault,
    doc: &LoroDoc,
    id: &EntityId,
    blob: &[u8],
) -> Result<()> {
    if !judged(blob) {
        return Ok(());
    }
    if carries_origins(doc) {
        let carried = doc.get_map(PEER_ORIGIN_MAP);
        if carried.get(&id.to_hex()).is_some() {
            map_delete(&carried, &id.to_hex())?;
        }
    }
    let prefix = format!("{}:", id.to_hex());
    vault.with_write_txn_grouped(|wtxn| {
        PEER_ORIGIN.delete_from(&vault.store, wtxn, prefix.as_bytes())?;
        Ok(())
    })
}

/// Drops the origin `doc` carries for each of `ids` whose row it no longer
/// holds with the bytes that origin names: a local path removed the carrier,
/// or left only a deleted row's shell (FIX 4550). An origin names a peer's
/// exact bytes, so one whose row holds other bytes is as stale as one whose
/// row is gone. Returns whether any went; the caller commits.
pub(crate) fn forget_stale_peer_origins(
    doc: &LoroDoc,
    ids: impl IntoIterator<Item = EntityId>,
) -> Result<bool> {
    if !carries_origins(doc) {
        return Ok(false);
    }
    let carried = doc.get_map(PEER_ORIGIN_MAP);
    let entities = doc.get_map("entities");
    let mut dropped = false;
    for id in ids {
        let key = id.to_hex();
        if carried.get(&key).is_none() {
            continue;
        }
        let sent = map_get_bytes(&carried, &key);
        if map_get_bytes(&entities, &key)
            .is_none_or(|blob| sent.as_deref() != Some(&digest(&blob)[..]))
        {
            map_delete(&carried, &key)?;
            dropped = true;
        }
    }
    Ok(dropped)
}

fn refused() -> Error {
    Error::InvalidConfig("peer origin refused: not a digest filed under its row".into())
}

/// Admits one insert into a window's [`PEER_ORIGIN_MAP`]: a 32-byte digest
/// filed under the canonical id of its row.
pub(in crate::sync) fn admit_peer_origin_carrier(map_key: &str, value: &LoroValue) -> Result<()> {
    let filed = EntityId::from_hex(map_key).is_ok_and(|id| id.to_hex() == map_key);
    if filed && matches!(value, LoroValue::Binary(bytes) if bytes.len() == 32) {
        return Ok(());
    }
    Err(refused())
}

/// [`admit_peer_origin_carrier`] over every row `map` holds.
pub(in crate::sync) fn admit_peer_origin_map(map: &LoroMap) -> Result<()> {
    let mut admitted = Ok(());
    map.for_each(|map_key, value| {
        if admitted.is_ok() {
            admitted = match value {
                ValueOrContainer::Value(value) => admit_peer_origin_carrier(map_key, &value),
                ValueOrContainer::Container(_) => Err(refused()),
            };
        }
    });
    admitted
}
