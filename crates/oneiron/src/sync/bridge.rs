//! Entity bridge: CRDT ↔ LMDB materialization observers.
//!
//! **Observer A** (`subscribe_local_update`): Fires for ALL local commits.
//! Persists update bytes to sync_state and broadcasts.
//!
//! **Observer B** (`doc.subscribe(container_id)` × 3): Fires for all commits.
//! Subscribes to each of the three map containers (entities, edges, tombstones)
//! via the doc's container event system. Materializes key-level changes to LMDB,
//! skipping bridge-origin writes.
//!
//! Origin tracking: bridge writes use `commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN))`.
//! Observer B callbacks check the event origin and skip bridge-tagged events
//! to avoid circular LMDB→CRDT→LMDB loops.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use loro::{ContainerTrait, LoroDoc, LoroMap, Subscription};

use super::loro_support::{map_contains_key, map_get_bytes};
use crate::batch::{self, BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::store::Store;
use crate::types::{
    DecodedEdgeValue, EdgeKind, EdgeProvenanceFlags, EntityId, Vad, decode_edge_value,
    decode_edge_value_for_kind, encode_edge_value,
};
use crate::{Error, Result, Vault};

/// Origin tag used for LMDB→CRDT bridge writes.
pub const BRIDGE_ORIGIN: &str = "bridge";

/// Shared materializer state for serializing LMDB writes across observers.
pub struct Materializer {
    /// Mutex serializing all Observer B callbacks + direct bridge-origin deletes.
    /// Uses `std::sync::Mutex` (NOT `tokio::sync::Mutex`) per spec.
    mutex: Mutex<()>,
}

impl Default for Materializer {
    fn default() -> Self {
        Self {
            mutex: Mutex::new(()),
        }
    }
}

impl Materializer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Acquires the materializer lock.
    ///
    /// Recovers from a poisoned mutex (prior panic in Observer B callback)
    /// instead of cascading the panic to all future callbacks.
    pub fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.mutex.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Observer A state: tracks pending bytes for compaction signaling.
pub struct ObserverAState {
    /// Pending bytes since last compaction (AtomicU32 for Send+Sync).
    pub pending_bytes: AtomicU32,
}

impl Default for ObserverAState {
    fn default() -> Self {
        Self {
            pending_bytes: AtomicU32::new(0),
        }
    }
}

impl ObserverAState {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Registers Observer A on a Doc: persists all local updates to sync_state.
///
/// Returns the Subscription handle (must be kept alive for the observer to fire).
pub fn register_observer_a(
    doc: &LoroDoc,
    vault: &Arc<Vault>,
    window_key: &str,
    state: Arc<ObserverAState>,
) -> Subscription {
    let vault = vault.clone();
    let window_key = window_key.to_string();

    doc.subscribe_local_update(Box::new(move |update_bytes| {
        let result = vault.with_write_txn(|wtxn| {
            let seq_key = format!("m:u_seq:w:{window_key}");
            // Distinguish a missing key (fresh window — start at 0) from a
            // present-but-malformed seq row (on-disk corruption). The latter
            // must not silently reset to 0; doing so would let next_seq=1
            // collide with whatever update was already persisted at
            // `u:w:{window}:00000001` before the row was corrupted.
            let seq: u32 = match vault.store.sync_state.get(wtxn, &seq_key)? {
                None => 0,
                Some(raw) if raw.len() == 4 => u32::from_le_bytes(raw.try_into().unwrap()),
                Some(_) => return Err(Error::CorruptedIndex("observer a u_seq row")),
            };
            // checked_add surfaces overflow as a typed error rather than
            // `wrapping_add`-ing to 0 and silently overwriting update key
            // `u:w:{window}:00000000`. Matches SyncQueue's update-seq policy.
            // u32 widening to u64 is tracked as a follow-up schema change.
            let next_seq = seq
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow("observer a u_seq"))?;
            vault
                .store
                .sync_state
                .put(wtxn, &seq_key, &next_seq.to_le_bytes())?;

            let update_key = format!("u:w:{window_key}:{next_seq:08x}");
            vault
                .store
                .sync_state
                .put(wtxn, &update_key, update_bytes)?;

            let svf_key = format!("svf:w:{window_key}");
            vault.store.sync_state.put(wtxn, &svf_key, &[0u8])?;

            Ok(())
        });

        if let Err(e) = result {
            tracing::error!(
                window = %window_key,
                error = %e,
                "observer-a: CRITICAL — failed to persist update, CRDT committed but LMDB may diverge"
            );
        }

        state
            .pending_bytes
            .fetch_add(update_bytes.len() as u32, Ordering::Relaxed);

        true // keep subscription alive
    }))
}

/// Registers Observer B on a window Doc: materializes CRDT changes to LMDB.
///
/// Loro subscriptions work on
/// container IDs. We subscribe to each of the three maps (entities, edges,
/// tombstones) and skip events whose origin matches `BRIDGE_ORIGIN`.
///
/// Returns three Subscription handles (entities, edges, tombstones).
pub fn register_observer_b(
    doc: &LoroDoc,
    vault: &Arc<Vault>,
    materializer: &Arc<Materializer>,
) -> (Subscription, Subscription, Subscription) {
    let entities_map = doc.get_map("entities");
    let edges_map = doc.get_map("edges");
    let tombstones_map = doc.get_map("tombstones");

    let entity_sub = subscribe_map_observer(
        doc,
        &entities_map,
        vault,
        materializer,
        materialize_entities_from_delta,
    );
    let edge_sub = subscribe_map_observer(
        doc,
        &edges_map,
        vault,
        materializer,
        materialize_edges_from_delta,
    );
    let tombstone_sub = subscribe_map_observer(
        doc,
        &tombstones_map,
        vault,
        materializer,
        materialize_tombstones_from_delta,
    );

    (entity_sub, edge_sub, tombstone_sub)
}

/// Subscribes to a map's changes, filtering out bridge-origin events and
/// delegating to a materializer function under the materializer lock.
fn subscribe_map_observer(
    doc: &LoroDoc,
    map: &LoroMap,
    vault: &Arc<Vault>,
    materializer: &Arc<Materializer>,
    materialize: fn(&LoroDoc, &loro::event::MapDelta<'_>, &Vault),
) -> Subscription {
    let callback_doc = doc.clone();
    let subscription_doc = doc.clone();
    let vault = vault.clone();
    let materializer = materializer.clone();
    let cid = map.id();
    subscription_doc.subscribe(
        &cid,
        Arc::new(move |event| {
            if event.origin == BRIDGE_ORIGIN {
                return;
            }
            let _guard = materializer.lock();
            for cdiff in &event.events {
                if let Some(map_delta) = cdiff.diff.as_map() {
                    materialize(&callback_doc, map_delta, &vault);
                }
            }
        }),
    )
}

/// Materialize entity changes from a Loro MapDelta to LMDB.
///
/// Accumulates all entity ops from the delta into a single LMDB write
/// transaction instead of committing per-entity.
fn materialize_entities_from_delta(
    doc: &LoroDoc,
    delta: &loro::event::MapDelta<'_>,
    vault: &Vault,
) {
    let tombstones_map = doc.get_map("tombstones");
    let result = vault.with_write_txn(|wtxn| {
        for (key, new_val) in &delta.updated {
            match new_val {
                Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(blob))) => {
                    let Ok(id) = EntityId::from_hex(key.as_ref()) else {
                        tracing::warn!(entity = %key, "observer-b: entity invalid hex id");
                        continue;
                    };
                    // ONE-1133 (ARCH-0038): a tombstone always wins over
                    // concurrent entities-map state. A re-put merged after
                    // the delete must never (re)materialize the body — no
                    // further tombstone event would fire to scrub it. The
                    // check uses the normalized lowercase id so an
                    // uppercase-alias key cannot dodge it.
                    if map_contains_binary(&tombstones_map, &id.to_hex()) {
                        tracing::debug!(
                            entity = %key,
                            "observer-b: entity update suppressed by tombstone (delete wins)"
                        );
                        continue;
                    }
                    let materialize_result = materialize_entity_blob_in_txn(
                        vault,
                        wtxn,
                        &tombstones_map,
                        key.as_ref(),
                        blob,
                    );
                    if let Err(e) = materialize_result {
                        tracing::warn!(
                            entity = %key,
                            error = %e,
                            "observer-b: entity materialization failed"
                        );
                    }
                }
                None => {
                    // Deleted — no action for entities (use tombstones instead)
                }
                _ => {
                    tracing::warn!(entity = %key, "observer-b: entity unexpected value type");
                }
            }
        }
        Ok(())
    });

    if let Err(e) = result {
        tracing::error!(error = %e, "observer-b: entity batch commit failed");
    }
}

/// Materialize edge changes from a Loro MapDelta to LMDB.
///
/// Accumulates all edge ops from the delta into a single LMDB write
/// transaction instead of committing per-edge.
fn materialize_edges_from_delta(doc: &LoroDoc, delta: &loro::event::MapDelta<'_>, vault: &Vault) {
    let result = vault.with_write_txn(|wtxn| {
        let entities_map = doc.get_map("entities");
        let tombstones_map = doc.get_map("tombstones");
        let mut ops = Vec::<BatchOp>::new();
        for (key, new_val) in &delta.updated {
            match new_val {
                Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(buf))) => {
                    let Some((src, kind, tgt)) = parse_edge_key(key.as_ref()) else {
                        tracing::warn!(edge = %key, "observer-b: edge invalid key format");
                        continue;
                    };

                    let src_ready = ensure_entity_materialized_from_crdt(
                        vault,
                        wtxn,
                        &entities_map,
                        &tombstones_map,
                        &src,
                    );
                    let tgt_ready = ensure_entity_materialized_from_crdt(
                        vault,
                        wtxn,
                        &entities_map,
                        &tombstones_map,
                        &tgt,
                    );
                    match (src_ready, tgt_ready) {
                        (Ok(true), Ok(true)) => {}
                        (Ok(_), Ok(_)) => continue,
                        (Err(e), _) | (_, Err(e)) => {
                            tracing::warn!(
                                edge = %key,
                                error = %e,
                                "observer-b: edge endpoint materialization failed"
                            );
                            continue;
                        }
                    }

                    let decoded = match decode_edge_value_for_kind(kind, buf) {
                        Ok(v) => v,
                        Err(_) => {
                            tracing::warn!(edge = %key, "observer-b: edge malformed value");
                            continue;
                        }
                    };
                    ops.push(BatchOp::EdgeWithCreatedAt {
                        src,
                        kind,
                        tgt,
                        weight: decoded.weight,
                        created_at: decoded.created_at,
                        vad: decoded.vad.unwrap_or(Vad::NEUTRAL),
                        provenance: decoded.provenance,
                    });
                }
                None => {
                    // Deleted
                    let Some((src, kind, tgt)) = parse_edge_key(key.as_ref()) else {
                        continue;
                    };
                    ops.push(BatchOp::DeleteEdge { src, kind, tgt });
                }
                _ => {}
            }
        }
        apply_materialized_edge_ops(vault, wtxn, ops);
        Ok(())
    });

    if let Err(e) = result {
        tracing::error!(error = %e, "observer-b: edge batch commit failed");
    }
}

#[derive(Clone)]
struct PendingChildOfOp {
    index: usize,
    src: EntityId,
    tgt: EntityId,
    op: BatchOp,
}

fn apply_materialized_edge_ops(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, ops: Vec<BatchOp>) {
    let mut child_of_adds = Vec::<PendingChildOfOp>::new();
    let mut child_of_deletes = Vec::<PendingChildOfOp>::new();

    for (index, op) in ops.into_iter().enumerate() {
        match &op {
            BatchOp::EdgeWithCreatedAt { src, kind, tgt, .. }
            | BatchOp::Edge { src, kind, tgt, .. }
                if *kind == EdgeKind::ChildOf =>
            {
                child_of_adds.push(PendingChildOfOp {
                    index,
                    src: *src,
                    tgt: *tgt,
                    op,
                });
            }
            BatchOp::DeleteEdge { src, kind, tgt } if *kind == EdgeKind::ChildOf => {
                child_of_deletes.push(PendingChildOfOp {
                    index,
                    src: *src,
                    tgt: *tgt,
                    op,
                });
            }
            _ => {
                let apply_result =
                    batch::apply_ops(&vault.store, &vault.config, &vault.analyzer, wtxn, vec![op]);
                if let Err(e) = apply_result {
                    tracing::warn!(error = %e, "observer-b: edge materialization failed");
                }
            }
        }
    }

    child_of_deletes.sort_by(cmp_pending_child_of_ops);
    for pending in child_of_deletes {
        let apply_result = batch::apply_ops(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            wtxn,
            vec![pending.op],
        );
        if let Err(e) = apply_result {
            tracing::warn!(error = %e, "observer-b: edge materialization failed");
        }
    }

    let mut components = child_of_components(&child_of_adds);
    components.sort_by(|left, right| {
        child_of_component_sort_key(left)
            .cmp(&child_of_component_sort_key(right))
            .then_with(|| left.len().cmp(&right.len()))
    });
    for component in components {
        let mut component_ops = component;
        component_ops.sort_by(cmp_pending_child_of_ops);
        let ops = component_ops.into_iter().map(|entry| entry.op).collect();
        let apply_result =
            batch::apply_ops(&vault.store, &vault.config, &vault.analyzer, wtxn, ops);
        if let Err(e) = apply_result {
            tracing::warn!(error = %e, "observer-b: edge materialization failed");
        }
    }
}

fn child_of_components(ops: &[PendingChildOfOp]) -> Vec<Vec<PendingChildOfOp>> {
    let mut adjacency = HashMap::<EntityId, HashSet<EntityId>>::new();
    for op in ops {
        adjacency.entry(op.src).or_default().insert(op.tgt);
        adjacency.entry(op.tgt).or_default().insert(op.src);
    }

    let mut components = Vec::new();
    let mut visited = HashSet::<EntityId>::new();
    let mut starts = adjacency.keys().copied().collect::<Vec<_>>();
    starts.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    for start in starts {
        if !visited.insert(start) {
            continue;
        }

        let mut stack = vec![start];
        let mut nodes = HashSet::from([start]);
        while let Some(node) = stack.pop() {
            if let Some(neighbors) = adjacency.get(&node) {
                let mut sorted_neighbors = neighbors.iter().copied().collect::<Vec<_>>();
                sorted_neighbors.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
                for neighbor in sorted_neighbors {
                    if visited.insert(neighbor) {
                        stack.push(neighbor);
                        nodes.insert(neighbor);
                    }
                }
            }
        }

        components.push(
            ops.iter()
                .filter(|op| nodes.contains(&op.src))
                .cloned()
                .collect(),
        );
    }

    components
}

fn pending_child_of_sort_key(op: &PendingChildOfOp) -> [u8; 33] {
    Store::encode_edge_key(&op.src, EdgeKind::ChildOf, &op.tgt)
}

fn cmp_pending_child_of_ops(
    left: &PendingChildOfOp,
    right: &PendingChildOfOp,
) -> std::cmp::Ordering {
    pending_child_of_sort_key(left)
        .cmp(&pending_child_of_sort_key(right))
        .then_with(|| left.index.cmp(&right.index))
}

fn child_of_component_sort_key(component: &[PendingChildOfOp]) -> [u8; 33] {
    component
        .iter()
        .map(pending_child_of_sort_key)
        .min()
        .expect("child-of component must be non-empty")
}

/// Materialize tombstone changes — apply deletes to LMDB.
///
/// ONE-1133 (ARCH-0038): each tombstone routes through the reason-aware
/// replay primitive [`Vault::apply_replayed_tombstone`], never a bare
/// purge. The VALUE decides the effect: a known-soft `user_delete` value
/// keeps the 25 B shell (SoftErase + D16 refresh); every other shape —
/// hard reasons, legacy 8-byte, reserved 0, unknown bytes, malformed,
/// and non-binary values — hard-purges and, when local state was erased,
/// writes the LOCAL REDACTION_AUDIT receipt and `h:` sweep row.
fn materialize_tombstones_from_delta(
    _doc: &LoroDoc,
    delta: &loro::event::MapDelta<'_>,
    vault: &Vault,
) {
    for (key, new_val) in &delta.updated {
        match new_val {
            Some(value) => {
                // New tombstone added
                let id = match EntityId::from_hex(key.as_ref()) {
                    Ok(id) => id,
                    Err(_) => {
                        tracing::warn!(tombstone = %key, "observer-b: tombstone invalid hex id");
                        continue;
                    }
                };

                // A non-binary tombstone value has no decodable reason —
                // it replays as the empty value, which decodes HARD
                // (fail-closed: over-purge, never under-delete).
                let raw_value: &[u8] = match value {
                    loro::ValueOrContainer::Value(loro::LoroValue::Binary(blob)) => blob,
                    _ => &[],
                };

                let delete_result = vault.apply_replayed_tombstone(&id, raw_value);
                if let Err(e) = delete_result {
                    tracing::warn!(
                        tombstone = %key,
                        error = %e,
                        "observer-b: tombstone replay failed"
                    );
                }
            }
            None => {
                // Tombstone REMOVAL — protocol violation: tombstones are
                // permanent and no engine version emits removals (crafted /
                // malicious update only). The `dt:` marker gate keeps the
                // local hard delete closed regardless; quarantine of the
                // offending update is ONE-1124's `x:` machinery (folded in
                // at merge-train integration). Deliberately NOT re-asserting
                // the tombstone here — doc writes inside an Observer-B
                // callback re-enter Loro.
                tracing::warn!(
                    tombstone = %key,
                    "observer-b: tombstone removal delta — protocol violation, ignoring"
                );
            }
        }
    }
}

fn materialize_entity_blob_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    tombstones_map: &LoroMap,
    key: &str,
    blob: &[u8],
) -> Result<()> {
    // Tombstone gate — fires BEFORE the put, never heals after (ARCH-0023b:
    // "If tombstoned in CRDT → never resurrect"; contracts.ts
    // `user_hard_delete`: "Tombstone-first prevents sync resurrection").
    // Hard delete purges LMDB but leaves the stale blob in the live CRDT
    // entities map (`write_crdt_tombstone` only inserts into `tombstones`),
    // so ANY later commit touching this entity key would otherwise
    // rematerialize the purged body into LMDB with no compensating purge —
    // tombstone deltas only fire when the tombstones map CHANGES.
    // Presence is ANY-value (fail closed): non-binary tombstones gate too.
    if map_contains_key(tombstones_map, key) {
        tracing::debug!(entity = %key, "observer-b: entity tombstoned in CRDT, skipping put");
        return Ok(());
    }

    let id = EntityId::from_hex(key).map_err(|_| crate::Error::InvalidKey)?;

    // `dt:` local hard-delete marker gate (ONE-1122): the CRDT tombstones
    // map is MUTABLE remote input — a crafted update can REMOVE a tombstone
    // and re-put the entity key, passing the map check above and resurrecting
    // a hard-deleted body permanently (no tombstone left to re-fire). The
    // dt: row is local-only truth written in the origin purge txn; checked
    // SECOND (LMDB point read) only when the in-memory map says absent.
    // PRESENCE-ONLY — never decode the value. Canonical lowercase hex via
    // the parsed id, so a case-shifted map key cannot dodge the point read.
    let marker_key = crate::deletion::local_hard_delete_marker_key(&id);
    if vault.store.sync_state.get(wtxn, &marker_key)?.is_some() {
        tracing::warn!(
            entity = %key,
            "observer-b: entity locally hard-deleted (dt: marker), refusing materialization"
        );
        return Ok(());
    }

    let Some(header) = EntityMetadataHeader::parse(blob) else {
        return Err(crate::Error::CorruptedIndex("entity metadata"));
    };
    let data = if blob.len() > ENTITY_METADATA_HEADER_LEN {
        &blob[ENTITY_METADATA_HEADER_LEN..]
    } else {
        &[]
    };

    // Replicated put: Observer B mirrors whatever the unfiltered CRDT
    // entities map holds, including the engine-authored maintenance band
    // (REDACTION_AUDIT = 120) and reserved-predicate `edge.provenance`
    // truth-Claims. The public gate would warn-skip those, losing GDPR
    // receipts / edge-provenance truth on sync; `put_replicated` admits both
    // engine-authored bands while still running full structural validation
    // (unknown type bytes, ungrammatical predicates, and malformed CLAIM
    // bodies all still fail typed).
    vault
        .batch_in()
        .put_replicated(
            &id,
            header.entity_type,
            crate::types::TimeRange {
                start: header.occurred_start,
                end: header.occurred_end,
            },
            header.learned_at,
            data,
        )
        .apply(wtxn)
}

fn ensure_entity_materialized_from_crdt(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entities_map: &LoroMap,
    tombstones_map: &LoroMap,
    id: &EntityId,
) -> Result<bool> {
    // Tombstone gate FIRST: a tombstoned OR locally hard-deleted (`dt:`
    // marker) endpoint must never count as "ready", even while a stale LMDB
    // row survives (crash window between the tombstone CRDT commit and the
    // purge txn, or a failed purge). Checking row existence first would
    // materialize an edge onto the stale row — re-adding an active carrier
    // ARCH-0038 requires purged. Presence is ANY-value (fail closed):
    // non-binary tombstones gate too. Without the dt: leg, a crafted
    // tombstone removal would make the silent gate-skip read as "ready" and
    // push an edge op against a missing endpoint;
    // `materialize_entity_blob_in_txn` re-checks both as the structural
    // fail-closed gate before its put.
    let hex_id = id.to_hex();
    if map_contains_key(tombstones_map, &hex_id)
        || vault
            .store
            .sync_state
            .get(wtxn, &crate::deletion::local_hard_delete_marker_key(id))?
            .is_some()
    {
        return Ok(false);
    }

    if vault.store.entities.get(&*wtxn, id.as_bytes())?.is_some() {
        return Ok(true);
    }

    let Some(blob) = map_get_bytes(entities_map, &hex_id) else {
        return Ok(false);
    };
    materialize_entity_blob_in_txn(vault, wtxn, tombstones_map, &hex_id, &blob)?;
    Ok(true)
}

/// Parses an edge key: `{src_hex}:{kind_u8:02}:{tgt_hex}` → (src, kind, tgt).
///
/// Uses `:` delimiter splitting instead of byte-index slicing for panic safety.
pub fn parse_edge_key(key: &str) -> Option<(EntityId, EdgeKind, EntityId)> {
    let mut parts = key.splitn(3, ':');
    let src_hex = parts.next()?;
    let kind_str = parts.next()?;
    let tgt_hex = parts.next()?;

    // Validate expected segment lengths (32-char hex IDs, 2-char kind)
    if src_hex.len() != 32 || kind_str.len() != 2 || tgt_hex.len() != 32 {
        return None;
    }

    let src = EntityId::from_hex(src_hex).ok()?;
    let kind_u8: u8 = kind_str.parse().ok()?;
    let kind = EdgeKind::try_from_u8(kind_u8)?;
    let tgt = EntityId::from_hex(tgt_hex).ok()?;
    Some((src, kind, tgt))
}

/// Parses a 12/24/26-byte edge value.
pub fn parse_edge_value(buf: &[u8]) -> Option<DecodedEdgeValue> {
    decode_edge_value(buf).ok()
}

/// Encodes an edge value for CRDT map storage using the ARCH-0034 layout class.
pub fn encode_edge_value_for_crdt(
    kind: EdgeKind,
    weight: f32,
    created_at: u64,
    vad: Option<Vad>,
    provenance: Option<EdgeProvenanceFlags>,
) -> Result<Vec<u8>> {
    encode_edge_value(
        kind,
        weight,
        created_at,
        vad.unwrap_or(Vad::NEUTRAL),
        provenance,
    )
}

/// Formats an edge key for CRDT map: `{src_hex}:{kind:02}:{tgt_hex}`.
pub fn format_edge_key(src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> String {
    format!("{}:{:02}:{}", src.to_hex(), kind as u8, tgt.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vault;
    use crate::sync::loro_support::{
        doc_from_snapshot, doc_version_vector, export_snapshot, export_updates_since, import_doc,
        map_contains_binary, map_insert_bytes,
    };
    use crate::types::{ENTITY_TYPE_TASK, TimeRange, VaultConfig};
    use std::sync::Arc;

    fn test_vault() -> Arc<Vault> {
        let dir = tempfile::tempdir().unwrap();
        Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap())
    }

    /// Minimal WARN-level event capture: collects `message` fields so tests
    /// can assert a specific warn fired without a subscriber dependency.
    #[derive(Clone, Default)]
    struct WarnCapture {
        messages: Arc<Mutex<Vec<String>>>,
    }

    impl tracing::Subscriber for WarnCapture {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() != tracing::Level::WARN {
                return;
            }
            struct MessageVisitor(Option<String>);
            impl tracing::field::Visit for MessageVisitor {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0 = Some(format!("{value:?}"));
                    }
                }
            }
            let mut visitor = MessageVisitor(None);
            event.record(&mut visitor);
            if let Some(message) = visitor.0 {
                self.messages.lock().unwrap().push(message);
            }
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    fn read_dt_marker(vault: &Vault, id: &EntityId) -> Option<Vec<u8>> {
        let rtxn = vault.store.env.read_txn().unwrap();
        vault
            .store
            .sync_state
            .get(&rtxn, &crate::deletion::local_hard_delete_marker_key(id))
            .unwrap()
            .map(<[u8]>::to_vec)
    }

    fn entity_blob(entity_type: u8, occurred: TimeRange, learned_at: u64, data: &[u8]) -> Vec<u8> {
        let mut blob = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
        blob.push(entity_type);
        blob.extend_from_slice(&occurred.start.to_be_bytes());
        blob.extend_from_slice(&occurred.end.to_be_bytes());
        blob.extend_from_slice(&learned_at.to_be_bytes());
        blob.extend_from_slice(data);
        blob
    }

    #[test]
    fn parse_edge_key_valid() {
        let src = EntityId::from_bytes_unchecked([0x11; 16]);
        let tgt = EntityId::from_bytes_unchecked([0x22; 16]);
        let key = format_edge_key(&src, EdgeKind::Mentions, &tgt);
        let (s, k, t) = parse_edge_key(&key).unwrap();
        assert_eq!(s, src);
        assert_eq!(k, EdgeKind::Mentions);
        assert_eq!(t, tgt);
    }

    #[test]
    fn parse_edge_key_invalid_length() {
        assert!(parse_edge_key("too-short").is_none());
    }

    #[test]
    fn edge_value_round_trip() {
        let vad = Vad {
            valence: 0.5,
            arousal: 0.3,
            dominance: 0.7,
        };
        let buf =
            encode_edge_value_for_crdt(EdgeKind::Mentions, 0.8, 12345, Some(vad), None).unwrap();
        let decoded = parse_edge_value(&buf).unwrap();
        assert!((decoded.weight - 0.8).abs() < f32::EPSILON);
        assert_eq!(decoded.created_at, 12345);
        let v = decoded.vad.unwrap();
        assert!((v.valence - 0.5).abs() < f32::EPSILON);
        assert!((v.arousal - 0.3).abs() < f32::EPSILON);
        assert!((v.dominance - 0.7).abs() < f32::EPSILON);
    }

    #[test]
    fn apply_materialized_edge_ops_keeps_other_edges_after_child_of_failure() {
        let vault = test_vault();
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        vault
            .batch()
            .put(
                &a,
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                2,
                b"a",
            )
            .put(
                &b,
                ENTITY_TYPE_TASK,
                TimeRange { start: 3, end: 3 },
                4,
                b"b",
            )
            .put(
                &c,
                ENTITY_TYPE_TASK,
                TimeRange { start: 5, end: 5 },
                6,
                b"c",
            )
            .edge(&b, EdgeKind::ChildOf, &a, 1.0)
            .commit()
            .unwrap();

        vault
            .with_write_txn(|wtxn| {
                apply_materialized_edge_ops(
                    &vault,
                    wtxn,
                    vec![
                        BatchOp::EdgeWithCreatedAt {
                            src: a,
                            kind: EdgeKind::ChildOf,
                            tgt: b,
                            weight: 1.0,
                            created_at: 10,
                            vad: Vad::NEUTRAL,
                            provenance: None,
                        },
                        BatchOp::EdgeWithCreatedAt {
                            src: c,
                            kind: EdgeKind::Mentions,
                            tgt: a,
                            weight: 0.8,
                            created_at: 11,
                            vad: Vad::NEUTRAL,
                            provenance: None,
                        },
                    ],
                );
                Ok(())
            })
            .unwrap();

        assert!(!vault.edge_exists(&a, EdgeKind::ChildOf, &b).unwrap());
        assert!(vault.edge_exists(&c, EdgeKind::Mentions, &a).unwrap());
    }

    #[test]
    fn apply_materialized_edge_ops_keeps_valid_child_of_delete_when_add_fails() {
        let vault = test_vault();
        let a = EntityId::now();
        let b = EntityId::now();
        let c = EntityId::now();

        vault
            .batch()
            .put(
                &a,
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                2,
                b"a",
            )
            .put(
                &b,
                ENTITY_TYPE_TASK,
                TimeRange { start: 3, end: 3 },
                4,
                b"b",
            )
            .put(
                &c,
                ENTITY_TYPE_TASK,
                TimeRange { start: 5, end: 5 },
                6,
                b"c",
            )
            .edge(&c, EdgeKind::ChildOf, &b, 1.0)
            .edge(&b, EdgeKind::ChildOf, &a, 1.0)
            .commit()
            .unwrap();

        vault
            .with_write_txn(|wtxn| {
                apply_materialized_edge_ops(
                    &vault,
                    wtxn,
                    vec![
                        BatchOp::DeleteEdge {
                            src: c,
                            kind: EdgeKind::ChildOf,
                            tgt: b,
                        },
                        BatchOp::EdgeWithCreatedAt {
                            src: a,
                            kind: EdgeKind::ChildOf,
                            tgt: b,
                            weight: 1.0,
                            created_at: 10,
                            vad: Vad::NEUTRAL,
                            provenance: None,
                        },
                    ],
                );
                Ok(())
            })
            .unwrap();

        assert!(!vault.edge_exists(&c, EdgeKind::ChildOf, &b).unwrap());
        assert!(!vault.edge_exists(&a, EdgeKind::ChildOf, &b).unwrap());
    }

    #[test]
    fn apply_materialized_edge_ops_child_of_subset_is_deterministic() {
        let vault = test_vault();
        let a = EntityId::from_bytes_unchecked([1; 16]);
        let x = EntityId::from_bytes_unchecked([2; 16]);
        let b = EntityId::from_bytes_unchecked([3; 16]);
        let y = EntityId::from_bytes_unchecked([4; 16]);

        vault
            .batch()
            .put(
                &a,
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                2,
                b"a",
            )
            .put(
                &x,
                ENTITY_TYPE_TASK,
                TimeRange { start: 3, end: 3 },
                4,
                b"x",
            )
            .put(
                &b,
                ENTITY_TYPE_TASK,
                TimeRange { start: 5, end: 5 },
                6,
                b"b",
            )
            .put(
                &y,
                ENTITY_TYPE_TASK,
                TimeRange { start: 7, end: 7 },
                8,
                b"y",
            )
            .edge(&a, EdgeKind::ChildOf, &x, 1.0)
            .edge(&b, EdgeKind::ChildOf, &y, 1.0)
            .commit()
            .unwrap();

        vault
            .with_write_txn(|wtxn| {
                apply_materialized_edge_ops(
                    &vault,
                    wtxn,
                    vec![
                        BatchOp::EdgeWithCreatedAt {
                            src: y,
                            kind: EdgeKind::ChildOf,
                            tgt: a,
                            weight: 1.0,
                            created_at: 10,
                            vad: Vad::NEUTRAL,
                            provenance: None,
                        },
                        BatchOp::EdgeWithCreatedAt {
                            src: x,
                            kind: EdgeKind::ChildOf,
                            tgt: b,
                            weight: 1.0,
                            created_at: 11,
                            vad: Vad::NEUTRAL,
                            provenance: None,
                        },
                    ],
                );
                Ok(())
            })
            .unwrap();

        assert!(vault.edge_exists(&x, EdgeKind::ChildOf, &b).unwrap());
        assert!(!vault.edge_exists(&y, EdgeKind::ChildOf, &a).unwrap());
    }

    #[test]
    fn observer_b_hydrates_edge_endpoints_from_current_crdt_state() {
        let vault = test_vault();
        let doc = LoroDoc::new();
        let entities = doc.get_map("entities");
        let edges = doc.get_map("edges");
        let a = EntityId::now();
        let b = EntityId::now();

        map_insert_bytes(
            &entities,
            &a.to_hex(),
            &entity_blob(ENTITY_TYPE_TASK, TimeRange { start: 1, end: 1 }, 2, b"a"),
        )
        .unwrap();
        map_insert_bytes(
            &entities,
            &b.to_hex(),
            &entity_blob(ENTITY_TYPE_TASK, TimeRange { start: 3, end: 3 }, 4, b"b"),
        )
        .unwrap();
        doc.commit();

        let materializer = Arc::new(Materializer::new());
        let _subs = register_observer_b(&doc, &vault, &materializer);

        map_insert_bytes(
            &edges,
            &format_edge_key(&a, EdgeKind::Mentions, &b),
            &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.8, 10, Some(Vad::NEUTRAL), None)
                .unwrap(),
        )
        .unwrap();
        doc.commit();

        assert!(vault.get(&a).unwrap().is_some());
        assert!(vault.get(&b).unwrap().is_some());
        assert!(vault.edge_exists(&a, EdgeKind::Mentions, &b).unwrap());
    }

    #[test]
    fn observer_b_does_not_rehydrate_tombstoned_edge_endpoint() {
        let vault = test_vault();
        let doc = LoroDoc::new();
        let entities = doc.get_map("entities");
        let edges = doc.get_map("edges");
        let tombstones = doc.get_map("tombstones");
        let deleted = EntityId::now();
        let live = EntityId::now();

        map_insert_bytes(
            &entities,
            &deleted.to_hex(),
            &entity_blob(
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                2,
                b"deleted",
            ),
        )
        .unwrap();
        map_insert_bytes(
            &entities,
            &live.to_hex(),
            &entity_blob(ENTITY_TYPE_TASK, TimeRange { start: 3, end: 3 }, 4, b"live"),
        )
        .unwrap();
        tombstones.insert(&deleted.to_hex(), b"1").unwrap();
        doc.commit();

        let materializer = Arc::new(Materializer::new());
        let _subs = register_observer_b(&doc, &vault, &materializer);

        map_insert_bytes(
            &edges,
            &format_edge_key(&deleted, EdgeKind::Mentions, &live),
            &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.8, 10, Some(Vad::NEUTRAL), None)
                .unwrap(),
        )
        .unwrap();
        doc.commit();

        assert!(vault.get(&deleted).unwrap().is_none());
        assert!(
            !vault
                .edge_exists(&deleted, EdgeKind::Mentions, &live)
                .unwrap()
        );
    }

    /// The endpoint-ready check must run the tombstone gate BEFORE the
    /// LMDB-row shortcut: a tombstoned endpoint whose stale local row
    /// survives (crash window between the tombstone CRDT commit and the
    /// purge txn, or a failed purge) must never count as "ready". Pre-fix
    /// code returned true on ANY existing row and materialized the edge.
    /// Covers binary AND non-binary tombstone values (fail closed).
    #[test]
    fn observer_b_does_not_materialize_edge_to_tombstoned_endpoint_with_stale_row() {
        let vault = test_vault();
        let doc = LoroDoc::new();
        let edges = doc.get_map("edges");
        let tombstones = doc.get_map("tombstones");
        let live = EntityId::now();
        let del_bin = EntityId::now(); // binary (legacy hard) tombstone
        let del_str = EntityId::now(); // non-binary tombstone — must gate too

        // All three rows exist locally — the deleted ones are the stale
        // survivors of an interrupted purge.
        for (id, body) in [
            (&live, b"live".as_slice()),
            (&del_bin, b"stale-bin".as_slice()),
            (&del_str, b"stale-str".as_slice()),
        ] {
            vault
                .put_entity(
                    id,
                    ENTITY_TYPE_TASK,
                    TimeRange { start: 1, end: 1 },
                    2,
                    body,
                )
                .unwrap();
        }
        tombstones.insert(&del_bin.to_hex(), b"1").unwrap();
        tombstones.insert(&del_str.to_hex(), "corrupt").unwrap();
        doc.commit();

        let materializer = Arc::new(Materializer::new());
        let _subs = register_observer_b(&doc, &vault, &materializer);

        for (src, tgt) in [(&live, &del_bin), (&live, &del_str), (&del_bin, &live)] {
            map_insert_bytes(
                &edges,
                &format_edge_key(src, EdgeKind::Mentions, tgt),
                &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.8, 10, Some(Vad::NEUTRAL), None)
                    .unwrap(),
            )
            .unwrap();
        }
        doc.commit();

        assert!(
            !vault
                .edge_exists(&live, EdgeKind::Mentions, &del_bin)
                .unwrap(),
            "edge to tombstoned target with stale row must not materialize"
        );
        assert!(
            !vault
                .edge_exists(&live, EdgeKind::Mentions, &del_str)
                .unwrap(),
            "non-binary tombstone must gate the target too (fail closed)"
        );
        assert!(
            !vault
                .edge_exists(&del_bin, EdgeKind::Mentions, &live)
                .unwrap(),
            "edge FROM a tombstoned source with stale row must not materialize"
        );
    }

    /// ONE-1122 AC2 — ARCH-0023b: "If tombstoned in CRDT → never resurrect";
    /// contracts.ts `user_hard_delete`: "Tombstone-first prevents sync
    /// resurrection". Hard delete writes the CRDT tombstone and (ONE-1132)
    /// removes the live `entities[id]` map copy in the SAME CRDT commit, so
    /// a later remote commit re-touching the entity key must NOT
    /// rematerialize the purged body into LMDB.
    #[test]
    fn observer_b_never_resurrects_hard_deleted_entity_on_entity_key_retouch() {
        let vault = test_vault();
        let materializer = Arc::new(Materializer::new());

        let id = EntityId::now();
        let learned_at = 1_772_400_000u64; // 2026-03 window
        let occurred = TimeRange { start: 1, end: 1 };
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_TASK,
                occurred,
                learned_at,
                b"hard-delete-me",
            )
            .unwrap();

        // Mirror LMDB → CRDT, then persist, so `write_crdt_tombstone` (which
        // loads the persisted window doc) operates on a doc holding the blob.
        let window_key = crate::sync::types::WindowKey::from_timestamp(learned_at);
        let window = crate::sync::window::LoadedWindow::new(
            "local",
            window_key.clone(),
            &vault,
            &materializer,
        );
        let mirrored =
            crate::sync::window::reverse_rematerialize(&vault, &window.doc, &window_key).unwrap();
        assert_eq!(mirrored, 1);
        window.persist_state(&vault).unwrap();
        drop(window);

        // Hard delete: CRDT tombstone FIRST, then active-store purge.
        let outcome = vault
            .delete_entity_with_reason(&id, crate::DeleteReason::UserHardDelete)
            .unwrap();
        assert!(outcome.existed);
        assert!(vault.get(&id).unwrap().is_none());

        let doc =
            crate::sync::window::load_window_from_state(&vault, "local", &window_key).unwrap();
        let hex_id = id.to_hex();
        assert!(
            map_get_bytes(&doc.get_map("entities"), &hex_id).is_none(),
            "precondition: hard delete removes the live entities-map copy in the same CRDT commit (ONE-1132)"
        );
        assert!(
            map_contains_binary(&doc.get_map("tombstones"), &hex_id),
            "precondition: hard delete writes the CRDT tombstone"
        );

        // Remote commit re-touches the entity key after Observer B attaches.
        let window =
            crate::sync::window::LoadedWindow::from_doc(doc, window_key, &vault, &materializer);
        let entities = window.doc.get_map("entities");
        map_insert_bytes(
            &entities,
            &hex_id,
            &entity_blob(
                ENTITY_TYPE_TASK,
                occurred,
                learned_at,
                b"resurrection-attempt",
            ),
        )
        .unwrap();
        window.doc.commit();

        assert!(
            vault.get(&id).unwrap().is_none(),
            "tombstoned entity must never resurrect into LMDB"
        );
    }

    /// ONE-1122 AC3 — SoftErased-shell variant: a 25 B envelope shell in
    /// LMDB + the full blob arriving via an entities-map delta + the
    /// tombstone present in the doc → the body is NOT restored. The gate
    /// fires BEFORE the put; nothing heals after.
    #[test]
    fn observer_b_does_not_restore_soft_erased_body_when_tombstoned() {
        let vault = test_vault();
        let id = EntityId::now();
        let learned_at = 1_772_400_000u64;
        let occurred = TimeRange { start: 1, end: 1 };
        vault
            .put_entity(&id, ENTITY_TYPE_TASK, occurred, learned_at, b"private-body")
            .unwrap();

        // SoftErase (`user_delete`): scrubs the body, keeps the 25 B shell.
        let outcome = vault
            .delete_entity_with_reason(&id, crate::DeleteReason::UserDelete)
            .unwrap();
        assert!(outcome.existed);
        assert_eq!(
            vault.get_raw(&id).unwrap().expect("shell row").len(),
            ENTITY_METADATA_HEADER_LEN,
            "SoftErase must leave the bare 25 B envelope shell"
        );

        // Doc already tombstoned BEFORE observers attach; then the full blob
        // arrives via a delta re-touching the entity key.
        let doc = LoroDoc::new();
        let tombstones = doc.get_map("tombstones");
        tombstones.insert(&id.to_hex(), b"1").unwrap();
        doc.commit();

        let materializer = Arc::new(Materializer::new());
        let _subs = register_observer_b(&doc, &vault, &materializer);

        let entities = doc.get_map("entities");
        map_insert_bytes(
            &entities,
            &id.to_hex(),
            &entity_blob(ENTITY_TYPE_TASK, occurred, learned_at, b"private-body"),
        )
        .unwrap();
        doc.commit();

        let raw = vault.get_raw(&id).unwrap().expect("shell must remain");
        assert_eq!(
            raw.len(),
            ENTITY_METADATA_HEADER_LEN,
            "tombstoned entity body must NOT be restored over the SoftErase shell"
        );
        assert_eq!(
            vault.get(&id).unwrap().as_deref(),
            Some(&[][..]),
            "entity body must stay empty after the gated delta"
        );
    }

    /// ONE-1115 AC7 — sync replay (observer-b edge materialization →
    /// `apply_edge_with_created_at`) routes through the same contract \[0, 1\]
    /// weight gate as local batch writes: an in-range replayed edge lands in
    /// `edges_out` with its weight and `created_at` intact.
    #[test]
    fn observer_b_replays_in_range_edge_weight_through_write_gate() {
        let vault = test_vault();
        let doc = LoroDoc::new();
        let entities = doc.get_map("entities");
        let edges = doc.get_map("edges");
        let a = EntityId::now();
        let b = EntityId::now();

        map_insert_bytes(
            &entities,
            &a.to_hex(),
            &entity_blob(ENTITY_TYPE_TASK, TimeRange { start: 1, end: 1 }, 2, b"a"),
        )
        .unwrap();
        map_insert_bytes(
            &entities,
            &b.to_hex(),
            &entity_blob(ENTITY_TYPE_TASK, TimeRange { start: 3, end: 3 }, 4, b"b"),
        )
        .unwrap();
        doc.commit();

        let materializer = Arc::new(Materializer::new());
        let _subs = register_observer_b(&doc, &vault, &materializer);

        map_insert_bytes(
            &edges,
            &format_edge_key(&a, EdgeKind::Mentions, &b),
            &encode_edge_value_for_crdt(EdgeKind::Mentions, 0.6, 10, Some(Vad::NEUTRAL), None)
                .unwrap(),
        )
        .unwrap();
        doc.commit();

        let out = vault.edges_out(&a).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, EdgeKind::Mentions);
        assert_eq!(out[0].target, b);
        assert_eq!(
            out[0].weight.to_bits(),
            0.6_f32.to_bits(),
            "replayed in-range weight must survive the write gate verbatim"
        );
        assert_eq!(out[0].created_at, 10);
    }

    /// ONE-1122 resurrection regression (handoff §8c.5): a crafted update
    /// that REMOVES the CRDT tombstone and re-puts the entity key must NOT
    /// rematerialize the hard-deleted body. The CRDT map is mutable remote
    /// input; the `dt:` marker written in the origin purge txn is the local
    /// truth the gate falls back to, and the removal is warn-logged as a
    /// protocol violation.
    #[test]
    fn observer_b_refuses_resurrection_after_crafted_tombstone_removal() {
        let vault = test_vault();
        let materializer = Arc::new(Materializer::new());

        let id = EntityId::now();
        let learned_at = 1_772_400_000u64; // 2026-03 window
        let occurred = TimeRange { start: 1, end: 1 };
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_TASK,
                occurred,
                learned_at,
                b"hard-delete-me",
            )
            .unwrap();

        // Mirror LMDB → CRDT and persist so the hard delete operates on a
        // window doc holding the blob.
        let window_key = crate::sync::types::WindowKey::from_timestamp(learned_at);
        let window = crate::sync::window::LoadedWindow::new(
            "local",
            window_key.clone(),
            &vault,
            &materializer,
        );
        let mirrored =
            crate::sync::window::reverse_rematerialize(&vault, &window.doc, &window_key).unwrap();
        assert_eq!(mirrored, 1);
        window.persist_state(&vault).unwrap();
        drop(window);

        // Hard delete: CRDT tombstone + dt: marker + active-store purge.
        let outcome = vault
            .delete_entity_with_reason(&id, crate::DeleteReason::UserHardDelete)
            .unwrap();
        assert!(outcome.existed);
        assert!(vault.get(&id).unwrap().is_none());
        assert!(
            read_dt_marker(&vault, &id).is_some(),
            "precondition: hard delete writes the dt: marker"
        );

        let hex_id = id.to_hex();
        let local_doc =
            crate::sync::window::load_window_from_state(&vault, "local", &window_key).unwrap();
        assert!(
            map_contains_binary(&local_doc.get_map("tombstones"), &hex_id),
            "precondition: hard delete writes the CRDT tombstone"
        );

        // Crafted attacker update: fork the local doc state, REMOVE the
        // tombstone, re-put the entity key, export the delta.
        let fork = doc_from_snapshot(&export_snapshot(&local_doc).unwrap()).unwrap();
        fork.get_map("tombstones").delete(&hex_id).unwrap();
        map_insert_bytes(
            &fork.get_map("entities"),
            &hex_id,
            &entity_blob(
                ENTITY_TYPE_TASK,
                occurred,
                learned_at,
                b"resurrection-attempt",
            ),
        )
        .unwrap();
        fork.commit();
        let crafted = export_updates_since(&fork, &doc_version_vector(&local_doc)).unwrap();

        // Apply the crafted update with observers attached, capturing warns.
        let window = crate::sync::window::LoadedWindow::from_doc(
            local_doc,
            window_key,
            &vault,
            &materializer,
        );
        let warns = WarnCapture::default();
        tracing::subscriber::with_default(warns.clone(), || {
            import_doc(&window.doc, &crafted).unwrap();
        });

        // The removal landed in the CRDT map (no tombstone left to re-fire)…
        assert!(
            !map_contains_binary(&window.doc.get_map("tombstones"), &hex_id),
            "crafted removal must actually clear the CRDT tombstone"
        );
        // …but the dt: marker gate refused the re-put.
        assert!(
            vault.get(&id).unwrap().is_none(),
            "hard-deleted entity must not rematerialize after crafted tombstone removal"
        );
        let messages = warns.messages.lock().unwrap();
        assert!(
            messages
                .iter()
                .any(|m| m.contains("tombstone removal delta")),
            "protocol-violation warn must fire, got: {messages:?}"
        );
        assert!(
            messages.iter().any(|m| m.contains("dt: marker")),
            "dt: gate refusal warn must fire, got: {messages:?}"
        );
    }

    /// ONE-1122 `dt:` marker shape: written in the purge txn on HARD
    /// outcomes (pinned `[reason:1][deleted_at:8 LE][request_id:16]`
    /// layout), absent on SoftErase, and pure LMDB truth — independent of
    /// any CRDT map state.
    #[test]
    fn hard_delete_writes_dt_marker_soft_delete_does_not() {
        let vault = test_vault();
        let occurred = TimeRange { start: 1, end: 1 };
        let learned_at = 1_772_400_000u64;
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let hard = EntityId::now();
        vault
            .put_entity(&hard, ENTITY_TYPE_TASK, occurred, learned_at, b"hard")
            .unwrap();
        vault
            .delete_entity_with_reason(&hard, crate::DeleteReason::UserHardDelete)
            .unwrap();

        let marker = read_dt_marker(&vault, &hard).expect("dt: row written on hard delete");
        assert_eq!(
            marker.len(),
            25,
            "pinned [reason:1][deleted_at:8 LE][request_id:16] layout"
        );
        assert_eq!(marker[0], 2, "user_hard_delete reason byte");
        let deleted_at = u64::from_le_bytes(marker[1..9].try_into().unwrap());
        assert!(
            deleted_at >= before && deleted_at <= before + 60,
            "deleted_at must be the request time"
        );
        assert_ne!(&marker[9..25], &[0u8; 16][..], "request id present");

        // GDPR delete is also HARD — marker with reason byte 3.
        let gdpr = EntityId::now();
        vault
            .put_entity(&gdpr, ENTITY_TYPE_TASK, occurred, learned_at, b"gdpr")
            .unwrap();
        vault
            .delete_entity_with_reason(&gdpr, crate::DeleteReason::GdprDelete)
            .unwrap();
        let marker = read_dt_marker(&vault, &gdpr).expect("dt: row written on gdpr delete");
        assert_eq!(marker[0], 3, "gdpr_delete reason byte");

        // SoftErase writes NO marker.
        let soft = EntityId::now();
        vault
            .put_entity(&soft, ENTITY_TYPE_TASK, occurred, learned_at, b"soft")
            .unwrap();
        vault
            .delete_entity_with_reason(&soft, crate::DeleteReason::UserDelete)
            .unwrap();
        assert!(
            read_dt_marker(&vault, &soft).is_none(),
            "soft delete must not write a dt: marker"
        );

        // The marker is LMDB truth: dropping the tombstone from the loaded
        // window doc leaves the dt: row untouched.
        let window_key = crate::sync::types::WindowKey::from_timestamp(learned_at);
        let doc =
            crate::sync::window::load_window_from_state(&vault, "local", &window_key).unwrap();
        doc.get_map("tombstones").delete(&hard.to_hex()).unwrap();
        doc.commit();
        assert!(
            read_dt_marker(&vault, &hard).is_some(),
            "dt: marker survives independently of the CRDT tombstone map"
        );
    }

    /// ONE-1122 `dt:` marker, headerless leg: a hard delete that routes
    /// through `delete_entity_without_header` (active residue, entity row /
    /// 25 B header missing) writes NO CRDT tombstone — the `dt:` marker
    /// written in the purge txn is the only local delete truth for that id.
    /// It must exist after the delete, and the Observer-B gate must refuse
    /// a crafted re-put on its strength alone.
    #[test]
    fn headerless_hard_delete_writes_dt_marker_and_gate_refuses_reput() {
        let vault = test_vault();
        let occurred = TimeRange { start: 1, end: 1 };
        let learned_at = 1_772_400_000u64;

        let id = EntityId::now();
        vault
            .put_entity(&id, ENTITY_TYPE_TASK, occurred, learned_at, b"residue")
            .unwrap();
        // Strip ONLY the entity row, leaving index residue (short-id
        // reverse row) — the exact shape `delete_entity_without_header`
        // exists for: active data present, no parseable header.
        {
            let mut wtxn = vault.store.env.write_txn().unwrap();
            assert!(
                vault
                    .store
                    .entities
                    .delete(&mut wtxn, id.as_bytes())
                    .unwrap()
            );
            wtxn.commit().unwrap();
        }

        let outcome = vault
            .delete_entity_with_reason(&id, crate::DeleteReason::UserHardDelete)
            .unwrap();
        assert!(
            outcome.receipt_id.is_some(),
            "headerless residue purge must write a receipt (not the missing no-op)"
        );
        let marker = read_dt_marker(&vault, &id)
            .expect("headerless hard delete must write the dt: marker in the purge txn");
        assert_eq!(
            marker.len(),
            25,
            "pinned [reason:1][deleted_at:8 LE][request_id:16] layout"
        );
        assert_eq!(marker[0], 2, "user_hard_delete reason byte");

        // Crafted re-put through Observer B: no CRDT tombstone exists for a
        // headerless delete, so ONLY the dt: leg of the OR-gate can refuse.
        let doc = LoroDoc::new();
        let materializer = Arc::new(Materializer::new());
        let _subs = register_observer_b(&doc, &vault, &materializer);
        let warns = WarnCapture::default();
        tracing::subscriber::with_default(warns.clone(), || {
            map_insert_bytes(
                &doc.get_map("entities"),
                &id.to_hex(),
                &entity_blob(ENTITY_TYPE_TASK, occurred, learned_at, b"reput-attempt"),
            )
            .unwrap();
            doc.commit();
        });

        assert!(
            vault.get(&id).unwrap().is_none(),
            "dt: gate must refuse rematerialization of a headerless hard delete"
        );
        let messages = warns.messages.lock().unwrap();
        assert!(
            messages.iter().any(|m| m.contains("dt: marker")),
            "dt: gate refusal warn must fire, got: {messages:?}"
        );
    }

    /// Negative: an entity that was never deleted materializes through the
    /// unchanged honest path — the dt: OR-gate adds no false refusals.
    #[test]
    fn observer_b_materializes_never_deleted_entity_normally() {
        let vault = test_vault();
        let doc = LoroDoc::new();
        let materializer = Arc::new(Materializer::new());
        let _subs = register_observer_b(&doc, &vault, &materializer);

        let id = EntityId::now();
        map_insert_bytes(
            &doc.get_map("entities"),
            &id.to_hex(),
            &entity_blob(
                ENTITY_TYPE_TASK,
                TimeRange { start: 1, end: 1 },
                2,
                b"honest-path",
            ),
        )
        .unwrap();
        doc.commit();

        assert_eq!(
            vault.get(&id).unwrap().as_deref(),
            Some(&b"honest-path"[..]),
            "never-deleted entity must materialize normally"
        );
    }

    /// ONE-1123: Observer B materializes a remote reserved-predicate
    /// `edge.provenance` Claim — the truth behind the 26 B edge flag cache
    /// (contracts.ts edgeProvenanceClaim: "the edge flags are a DERIVED
    /// CACHE of that Claim, and the Claim is truth") — byte-identical,
    /// instead of warn-skipping it at the public reserved-namespace gate.
    ///
    /// FAILS against pre-fix code: `materialize_entity_blob_in_txn` routed
    /// the type-0 Claim through `put_internal`
    /// (`allow_reserved_predicate: false`), `validate_claim_body_bytes`
    /// rejected it with ReservedPredicate, and the observer warn-skipped it
    /// — the Claim never reached the replica's LMDB.
    #[test]
    fn observer_b_materializes_remote_edge_provenance_claim() {
        let vault = test_vault();
        let doc = LoroDoc::new();
        let entities = doc.get_map("entities");

        let src = EntityId::now();
        let tgt = EntityId::now();
        let claim_id = EntityId::now();

        let body = crate::claim::ClaimBody::new(
            "edge.provenance",
            crate::claim::ClaimSubject::Edge {
                source: src,
                kind: EdgeKind::Mentions,
                target: tgt,
            },
            rmpv::Value::from("remote provenance payload"),
            0.9,
            crate::claim::ClaimApprovalStatus::Auto,
            crate::claim::ClaimLifecycleStatus::Active,
        );
        let body_bytes = crate::claim::encode_claim_body(&body).unwrap();
        let claim_blob = entity_blob(
            crate::types::ENTITY_TYPE_CLAIM,
            TimeRange { start: 5, end: 5 },
            6,
            &body_bytes,
        );

        let materializer = Arc::new(Materializer::new());
        let _subs = register_observer_b(&doc, &vault, &materializer);

        map_insert_bytes(&entities, &claim_id.to_hex(), &claim_blob).unwrap();
        doc.commit();

        assert_eq!(
            vault.get_raw(&claim_id).unwrap().as_deref(),
            Some(claim_blob.as_slice()),
            "remote edge.provenance Claim must materialize byte-identical via Observer B"
        );
        let read = vault
            .get_claim(&claim_id)
            .unwrap()
            .expect("materialized Claim must read back through get_claim");
        assert_eq!(read.predicate, "edge.provenance");
    }
}
