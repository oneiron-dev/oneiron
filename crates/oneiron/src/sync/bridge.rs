//! Entity bridge: CRDT ↔ LMDB materialization observers.
//!
//! **Observer A** (`subscribe_local_updates`): Fires for ALL local commits.
//! Persists update bytes to sync_state and broadcasts.
//!
//! **Observer B** (`doc.subscribe(container_id)` × 3): Fires for all commits.
//! Subscribes to each of the three map containers (entities, edges, tombstones)
//! via the doc's container event system. Materializes key-level changes to LMDB,
//! skipping bridge-origin writes.
//!
//! Origin tracking: bridge writes use `commit_with_origin(BRIDGE_ORIGIN)`.
//! Observer B callbacks check the event origin and skip bridge-tagged events
//! to avoid circular LMDB→CRDT→LMDB loops.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use super::engine::{CrdtDoc, CrdtMap, Subscription};
use super::loro_engine::LoroDocument;
use crate::batch::{self, BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::store::Store;
use crate::types::{EdgeKind, EntityId, Vad};
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
    doc: &LoroDocument,
    vault: &Arc<Vault>,
    window_key: &str,
    state: Arc<ObserverAState>,
) -> Subscription {
    let vault = vault.clone();
    let window_key = window_key.to_string();

    doc.subscribe_local_updates(Box::new(move |update_bytes| {
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
    doc: &LoroDocument,
    vault: &Arc<Vault>,
    materializer: &Arc<Materializer>,
) -> (Subscription, Subscription, Subscription) {
    let entities_map = doc.get_or_create_map("entities");
    let edges_map = doc.get_or_create_map("edges");
    let tombstones_map = doc.get_or_create_map("tombstones");

    // Loro's CrdtMap `subscribe_changes` does not expose origin info, so we
    // subscribe via the doc's container event system directly. This lets us
    // skip bridge-origin events and avoid circular LMDB->CRDT->LMDB loops.

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
    doc: &LoroDocument,
    map: &super::loro_engine::LoroMapHandle,
    vault: &Arc<Vault>,
    materializer: &Arc<Materializer>,
    materialize: fn(&LoroDocument, &loro::event::MapDelta<'_>, &Vault),
) -> Subscription {
    use loro::ContainerTrait;

    let callback_doc = LoroDocument(doc.0.clone());
    let subscription_doc = doc.0.clone();
    let vault = vault.clone();
    let materializer = materializer.clone();
    let cid = map.map.id();
    let sub = subscription_doc.subscribe(
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
    );
    Subscription::new(sub)
}

/// Materialize entity changes from a Loro MapDelta to LMDB.
///
/// Accumulates all entity ops from the delta into a single LMDB write
/// transaction instead of committing per-entity.
fn materialize_entities_from_delta(
    _doc: &LoroDocument,
    delta: &loro::event::MapDelta<'_>,
    vault: &Vault,
) {
    let result = vault.with_write_txn(|wtxn| {
        for (key, new_val) in &delta.updated {
            match new_val {
                Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(blob))) => {
                    let materialize_result =
                        materialize_entity_blob_in_txn(vault, wtxn, key.as_ref(), blob);
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
fn materialize_edges_from_delta(
    doc: &LoroDocument,
    delta: &loro::event::MapDelta<'_>,
    vault: &Vault,
) {
    let result = vault.with_write_txn(|wtxn| {
        let entities_map = doc.get_or_create_map("entities");
        let tombstones_map = doc.get_or_create_map("tombstones");
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

                    let (weight, created_at, vad) = match parse_edge_value(buf) {
                        Some(v) => v,
                        None => {
                            tracing::warn!(edge = %key, "observer-b: edge malformed value");
                            continue;
                        }
                    };
                    if !weight.is_finite() || !vad.is_finite() || !vad.is_in_range() {
                        tracing::warn!(edge = %key, "observer-b: edge invalid value");
                        continue;
                    }
                    ops.push(BatchOp::EdgeWithCreatedAt {
                        src,
                        kind,
                        tgt,
                        weight,
                        created_at,
                        vad,
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

/// Materialize tombstone changes — delete entities from LMDB.
///
/// Each tombstone triggers a delete_entity which involves multiple LMDB
/// writes (entity + edges + indexes). These are already internally
/// transactional via delete_entity, so we just replace the logging.
fn materialize_tombstones_from_delta(
    _doc: &LoroDocument,
    delta: &loro::event::MapDelta<'_>,
    vault: &Vault,
) {
    for (key, new_val) in &delta.updated {
        match new_val {
            Some(_) => {
                // New tombstone added
                let id = match EntityId::from_hex(key.as_ref()) {
                    Ok(id) => id,
                    Err(_) => {
                        tracing::warn!(tombstone = %key, "observer-b: tombstone invalid hex id");
                        continue;
                    }
                };

                let delete_result = vault.delete_entity(&id);
                if let Err(e) = delete_result {
                    tracing::warn!(
                        tombstone = %key,
                        error = %e,
                        "observer-b: tombstone delete failed"
                    );
                }
            }
            None => {
                // Tombstone removed — unusual, ignore
            }
        }
    }
}

fn materialize_entity_blob_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &str,
    blob: &[u8],
) -> Result<()> {
    let Some(header) = EntityMetadataHeader::parse(blob) else {
        return Err(crate::Error::CorruptedIndex("entity metadata"));
    };

    let id = EntityId::from_hex(key).map_err(|_| crate::Error::InvalidKey)?;
    let data = if blob.len() > ENTITY_METADATA_HEADER_LEN {
        &blob[ENTITY_METADATA_HEADER_LEN..]
    } else {
        &[]
    };

    vault
        .batch_in()
        .put(
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
    entities_map: &super::loro_engine::LoroMapHandle,
    tombstones_map: &super::loro_engine::LoroMapHandle,
    id: &EntityId,
) -> Result<bool> {
    if vault.store.entities.get(&*wtxn, id.as_bytes())?.is_some() {
        return Ok(true);
    }

    let hex_id = id.to_hex();
    if tombstones_map.get(&hex_id).is_some() {
        return Ok(false);
    }

    let Some(blob) = entities_map.get(&hex_id) else {
        return Ok(false);
    };
    materialize_entity_blob_in_txn(vault, wtxn, &hex_id, &blob)?;
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

/// Parses a 24-byte edge value.
///
/// Returns `None` if the buffer is too short (< 24 bytes) instead of
/// fabricating default values from truncated data.
pub fn parse_edge_value(buf: &[u8]) -> Option<(f32, u64, Vad)> {
    if buf.len() < 24 {
        return None;
    }
    let weight = f32::from_le_bytes(buf[..4].try_into().unwrap());
    let created_at = u64::from_le_bytes(buf[4..12].try_into().unwrap());
    let vad = Vad {
        valence: f32::from_le_bytes(buf[12..16].try_into().unwrap()),
        arousal: f32::from_le_bytes(buf[16..20].try_into().unwrap()),
        dominance: f32::from_le_bytes(buf[20..24].try_into().unwrap()),
    };
    Some((weight, created_at, vad))
}

/// Encodes an edge value as 24 bytes for CRDT map storage.
pub fn encode_edge_value_for_crdt(weight: f32, created_at: u64, vad: Vad) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24);
    buf.extend_from_slice(&weight.to_le_bytes());
    buf.extend_from_slice(&created_at.to_le_bytes());
    buf.extend_from_slice(&vad.valence.to_le_bytes());
    buf.extend_from_slice(&vad.arousal.to_le_bytes());
    buf.extend_from_slice(&vad.dominance.to_le_bytes());
    buf
}

/// Formats an edge key for CRDT map: `{src_hex}:{kind:02}:{tgt_hex}`.
pub fn format_edge_key(src: &EntityId, kind: EdgeKind, tgt: &EntityId) -> String {
    format!("{}:{:02}:{}", src.to_hex(), kind as u8, tgt.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vault;
    use crate::types::{TimeRange, VaultConfig};
    use std::sync::Arc;

    fn test_vault() -> Arc<Vault> {
        let dir = tempfile::tempdir().unwrap();
        Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap())
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
        let buf = encode_edge_value_for_crdt(0.8, 12345, vad);
        let (w, c, v) = parse_edge_value(&buf).unwrap();
        assert!((w - 0.8).abs() < f32::EPSILON);
        assert_eq!(c, 12345);
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
            .put(&a, 61, TimeRange { start: 1, end: 1 }, 2, b"a")
            .put(&b, 61, TimeRange { start: 3, end: 3 }, 4, b"b")
            .put(&c, 61, TimeRange { start: 5, end: 5 }, 6, b"c")
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
                        },
                        BatchOp::EdgeWithCreatedAt {
                            src: c,
                            kind: EdgeKind::Mentions,
                            tgt: a,
                            weight: 0.8,
                            created_at: 11,
                            vad: Vad::NEUTRAL,
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
            .put(&a, 61, TimeRange { start: 1, end: 1 }, 2, b"a")
            .put(&b, 61, TimeRange { start: 3, end: 3 }, 4, b"b")
            .put(&c, 61, TimeRange { start: 5, end: 5 }, 6, b"c")
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
            .put(&a, 61, TimeRange { start: 1, end: 1 }, 2, b"a")
            .put(&x, 61, TimeRange { start: 3, end: 3 }, 4, b"x")
            .put(&b, 61, TimeRange { start: 5, end: 5 }, 6, b"b")
            .put(&y, 61, TimeRange { start: 7, end: 7 }, 8, b"y")
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
                        },
                        BatchOp::EdgeWithCreatedAt {
                            src: x,
                            kind: EdgeKind::ChildOf,
                            tgt: b,
                            weight: 1.0,
                            created_at: 11,
                            vad: Vad::NEUTRAL,
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
        let doc = LoroDocument::new();
        let entities = doc.get_or_create_map("entities");
        let edges = doc.get_or_create_map("edges");
        let a = EntityId::now();
        let b = EntityId::now();

        entities
            .insert(
                &a.to_hex(),
                &entity_blob(61, TimeRange { start: 1, end: 1 }, 2, b"a"),
            )
            .unwrap();
        entities
            .insert(
                &b.to_hex(),
                &entity_blob(61, TimeRange { start: 3, end: 3 }, 4, b"b"),
            )
            .unwrap();
        doc.commit();

        let materializer = Arc::new(Materializer::new());
        let _subs = register_observer_b(&doc, &vault, &materializer);

        edges
            .insert(
                &format_edge_key(&a, EdgeKind::Mentions, &b),
                &encode_edge_value_for_crdt(0.8, 10, Vad::NEUTRAL),
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
        let doc = LoroDocument::new();
        let entities = doc.get_or_create_map("entities");
        let edges = doc.get_or_create_map("edges");
        let tombstones = doc.get_or_create_map("tombstones");
        let deleted = EntityId::now();
        let live = EntityId::now();

        entities
            .insert(
                &deleted.to_hex(),
                &entity_blob(61, TimeRange { start: 1, end: 1 }, 2, b"deleted"),
            )
            .unwrap();
        entities
            .insert(
                &live.to_hex(),
                &entity_blob(61, TimeRange { start: 3, end: 3 }, 4, b"live"),
            )
            .unwrap();
        tombstones.insert(&deleted.to_hex(), b"1").unwrap();
        doc.commit();

        let materializer = Arc::new(Materializer::new());
        let _subs = register_observer_b(&doc, &vault, &materializer);

        edges
            .insert(
                &format_edge_key(&deleted, EdgeKind::Mentions, &live),
                &encode_edge_value_for_crdt(0.8, 10, Vad::NEUTRAL),
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
}
