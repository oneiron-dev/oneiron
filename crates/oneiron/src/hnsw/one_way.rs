//! Orphan-protection one-way exception index.

use std::collections::HashMap;

use heed::{RoTxn, RwTxn};

use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::store::ManifestDbs;

use super::keys::{ERR_ONE_WAY_EXCEPTION_BYTES, ONE_WAY_EXCEPTION_PREFIX};
use super::storage::scrub_backlinks_in_place;

/// `hnsw_meta` key for the one-way-link exception record of `target`: the set
/// of holders whose single surviving link points at `target` one-way.
fn one_way_exception_key(target: &EntityId) -> Vec<u8> {
    let mut key = Vec::with_capacity(ONE_WAY_EXCEPTION_PREFIX.len() + ENTITY_ID_LEN);
    key.extend_from_slice(ONE_WAY_EXCEPTION_PREFIX);
    key.extend_from_slice(target.as_bytes());
    key
}

fn decode_exception_holders(raw: &[u8]) -> Result<Vec<EntityId>> {
    let (chunks, rem) = raw.as_chunks::<ENTITY_ID_LEN>();
    if !rem.is_empty() {
        return Err(Error::CorruptedIndex(ERR_ONE_WAY_EXCEPTION_BYTES));
    }
    let mut holders = Vec::with_capacity(chunks.len());
    for bytes in chunks {
        match EntityId::from_bytes(*bytes) {
            Ok(holder) => holders.push(holder),
            Err(_) => return Err(Error::CorruptedIndex(ERR_ONE_WAY_EXCEPTION_BYTES)),
        }
    }
    Ok(holders)
}

/// Holders whose single one-way link points at `target` (`holder -> target`
/// without the reverse). Empty when no exception record exists.
pub(super) fn read_one_way_exception_holders(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    target: &EntityId,
) -> Result<Vec<EntityId>> {
    match store.hnsw_meta().get(txn, &one_way_exception_key(target))? {
        Some(raw) => decode_exception_holders(&raw),
        None => Ok(Vec::new()),
    }
}

/// Records that `holder` keeps a one-way link to `target` (orphan protection).
/// Idempotent: a holder already present is not duplicated.
pub(super) fn record_one_way_exception(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    target: &EntityId,
    holder: &EntityId,
    ops: &mut u64,
) -> Result<()> {
    *ops += 1;
    let mut holders = read_one_way_exception_holders(store, &*wtxn, target)?;
    if holders.contains(holder) {
        return Ok(());
    }
    holders.push(*holder);
    let mut bytes = Vec::with_capacity(holders.len() * ENTITY_ID_LEN);
    for holder in &holders {
        bytes.extend_from_slice(holder.as_bytes());
    }
    store
        .hnsw_meta()
        .put(wtxn, &one_way_exception_key(target), &bytes)?;
    *ops += 1;
    Ok(())
}

/// Scrubs a node being deleted out of every holder that kept a one-way link to
/// it (orphan protection), then drops the exception record. This is the half
/// of a symmetric delete that the deleted node's own forward list cannot reach
/// (the holders are, by definition, NOT in it). Bounded by the holder count.
pub(super) fn purge_one_way_exceptions_for_target(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    ops: &mut u64,
) -> Result<()> {
    *ops += 1;
    let holders = read_one_way_exception_holders(store, &*wtxn, id)?;
    if holders.is_empty() {
        return Ok(());
    }
    // `scrub_neighbor_bytes` no-ops on a holder whose link was already removed
    // (e.g. it later became bidirectional and was pruned), so a stale holder is
    // harmless.
    scrub_backlinks_in_place(store, wtxn, id, &holders, ops)?;
    store.hnsw_meta().delete(wtxn, &one_way_exception_key(id))?;
    *ops += 1;
    Ok(())
}

/// Drops every persisted one-way exception record. Used before a full rebuild,
/// which replaces the whole graph shape and so invalidates the old records;
/// the symmetric paths re-derive them from the rebuilt rows. Only the
/// `ONE_WAY_EXCEPTION_PREFIX` keyspace is touched — unrelated `hnsw_meta` rows
/// (graph/model/schema markers) are preserved.
pub(super) fn clear_one_way_exceptions(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
) -> Result<()> {
    let mut stale_keys: Vec<Vec<u8>> = Vec::new();
    for entry in store.hnsw_meta().iter(wtxn)? {
        let (key, _) = entry?;
        if key.starts_with(ONE_WAY_EXCEPTION_PREFIX) {
            stale_keys.push(key.to_vec());
        }
    }
    for key in stale_keys {
        store.hnsw_meta().delete(wtxn, &key)?;
    }
    Ok(())
}

/// Re-derives the one-way exception records from a freshly rebuilt symmetric
/// graph: every link `node -> neighbor` whose neighbor row does not point back
/// is a tracked orphan-protection exception keyed by `neighbor`.
pub(super) fn rebuild_one_way_exception_index(
    store: &impl ManifestDbs,
    wtxn: &mut RwTxn<'_>,
    neighbors: &[(EntityId, Vec<EntityId>)],
) -> Result<()> {
    let forward: HashMap<EntityId, &Vec<EntityId>> =
        neighbors.iter().map(|(id, list)| (*id, list)).collect();
    let mut holders_by_target: HashMap<EntityId, Vec<EntityId>> = HashMap::new();
    for (node, list) in neighbors {
        for neighbor in list {
            // A one-way exception requires the neighbor row to exist but lack
            // the reverse link; a missing row is dangling corruption, which the
            // graph never emits and the symmetry assertion would catch.
            let is_one_way = forward
                .get(neighbor)
                .is_some_and(|back| !back.contains(node));
            if is_one_way {
                holders_by_target.entry(*neighbor).or_default().push(*node);
            }
        }
    }
    for (target, holders) in holders_by_target {
        let mut bytes = Vec::with_capacity(holders.len() * ENTITY_ID_LEN);
        for holder in &holders {
            bytes.extend_from_slice(holder.as_bytes());
        }
        store
            .hnsw_meta()
            .put(wtxn, &one_way_exception_key(&target), &bytes)?;
    }
    Ok(())
}
