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

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use super::engine::{CrdtDoc, Subscription};
use super::loro_engine::LoroDocument;
use crate::batch::{EntityMetadataHeader, ENTITY_METADATA_HEADER_LEN};
use crate::types::{EdgeKind, EntityId, Vad};
use crate::Vault;

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
            let seq_key = format!("m:u_seq:w:{}", window_key);
            let seq: u32 = match vault.store.sync_state.get(wtxn, &seq_key)? {
                Some(raw) if raw.len() == 4 => u32::from_le_bytes(raw.try_into().unwrap()),
                _ => 0,
            };
            let next_seq = seq.wrapping_add(1);
            vault
                .store
                .sync_state
                .put(wtxn, &seq_key, &next_seq.to_le_bytes())?;

            let update_key = format!("u:w:{}:{:08x}", window_key, next_seq);
            vault
                .store
                .sync_state
                .put(wtxn, &update_key, update_bytes)?;

            let svf_key = format!("svf:w:{}", window_key);
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
        doc, &entities_map, vault, materializer, materialize_entities_from_delta,
    );
    let edge_sub = subscribe_map_observer(
        doc, &edges_map, vault, materializer, materialize_edges_from_delta,
    );
    let tombstone_sub = subscribe_map_observer(
        doc, &tombstones_map, vault, materializer, materialize_tombstones_from_delta,
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
    materialize: fn(&loro::event::MapDelta<'_>, &Vault),
) -> Subscription {
    use loro::ContainerTrait;

    let vault = vault.clone();
    let materializer = materializer.clone();
    let cid = map.map.id();
    let sub = doc.0.subscribe(
        &cid,
        Arc::new(move |event| {
            if event.origin == BRIDGE_ORIGIN {
                return;
            }
            let _guard = materializer.lock();
            for cdiff in &event.events {
                if let Some(map_delta) = cdiff.diff.as_map() {
                    materialize(map_delta, &vault);
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
    delta: &loro::event::MapDelta<'_>,
    vault: &Vault,
) {
    let result = vault.with_write_txn(|wtxn| {
        for (key, new_val) in &delta.updated {
            match new_val {
                Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(blob))) => {
                    let Some(header) = EntityMetadataHeader::parse(blob) else {
                        tracing::warn!(
                            entity = %key,
                            blob_len = blob.len(),
                            "observer-b: entity invalid header"
                        );
                        continue;
                    };

                    let id = match EntityId::from_hex(key.as_ref()) {
                        Ok(id) => id,
                        Err(_) => {
                            tracing::warn!(entity = %key, "observer-b: entity invalid hex id");
                            continue;
                        }
                    };

                    let data = if blob.len() > ENTITY_METADATA_HEADER_LEN { &blob[ENTITY_METADATA_HEADER_LEN..] } else { &[] };

                    if let Err(e) = vault
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
                    {
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
    delta: &loro::event::MapDelta<'_>,
    vault: &Vault,
) {
    let result = vault.with_write_txn(|wtxn| {
        for (key, new_val) in &delta.updated {
            match new_val {
                Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(buf))) => {
                    let Some((src, kind, tgt)) = parse_edge_key(key.as_ref()) else {
                        tracing::warn!(edge = %key, "observer-b: edge invalid key format");
                        continue;
                    };

                    match (vault.entity_exists(&src), vault.entity_exists(&tgt)) {
                        (Ok(true), Ok(true)) => {}
                        _ => continue,
                    }

                    let (weight, created_at, vad) = match parse_edge_value(buf) {
                        Some(v) => v,
                        None => {
                            tracing::warn!(edge = %key, "observer-b: edge malformed value");
                            continue;
                        }
                    };

                    if let Err(e) = vault
                        .batch_in()
                        .edge_with_created_at_and_vad(&src, kind, &tgt, weight, created_at, vad)
                        .apply(wtxn)
                    {
                        tracing::warn!(
                            edge = %key,
                            error = %e,
                            "observer-b: edge materialization failed"
                        );
                    }
                }
                None => {
                    // Deleted
                    let Some((src, kind, tgt)) = parse_edge_key(key.as_ref()) else {
                        continue;
                    };
                    if let Err(e) = vault.batch_in().delete_edge(&src, kind, &tgt).apply(wtxn) {
                        tracing::warn!(edge = %key, error = %e, "observer-b: edge remove failed");
                    }
                }
                _ => {}
            }
        }
        Ok(())
    });

    if let Err(e) = result {
        tracing::error!(error = %e, "observer-b: edge batch commit failed");
    }
}

/// Materialize tombstone changes — delete entities from LMDB.
///
/// Each tombstone triggers a delete_entity which involves multiple LMDB
/// writes (entity + edges + indexes). These are already internally
/// transactional via delete_entity, so we just replace the logging.
fn materialize_tombstones_from_delta(
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

                if let Err(e) = vault.delete_entity(&id) {
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

    #[test]
    fn parse_edge_key_valid() {
        let src = EntityId::from_bytes([0x11; 16]);
        let tgt = EntityId::from_bytes([0x22; 16]);
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
}
