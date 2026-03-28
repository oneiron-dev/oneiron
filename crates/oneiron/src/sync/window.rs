//! Window lifecycle management for the CRDT sync layer.
//!
//! Windows partition entities by `learned_at` month. Each window has an
//! independent CRDT Doc (Loro). Only 2 windows are loaded by default
//! (current + previous month); older windows are ON-DISK in sync_state.

use std::sync::Arc;

use super::bridge::{
    self, encode_edge_value_for_crdt, format_edge_key, Materializer, ObserverAState,
    BRIDGE_ORIGIN,
};
use super::engine::{CrdtDoc, CrdtMap, Subscription};
use super::loro_engine::LoroDocument;
use super::schema::create_window_doc;
use super::types::WindowKey;
use crate::batch::EntityMetadataHeader;
use crate::error::{Error, Result};
use crate::types::EntityId;
use crate::Vault;

/// A loaded window Doc with its observer subscriptions.
pub struct LoadedWindow {
    /// The Loro Doc for this window.
    pub doc: LoroDocument,
    /// Window key (YYYY-MM).
    pub key: WindowKey,
    /// Observer A subscription (persistence + broadcast).
    _observer_a: Subscription,
    /// Observer B subscriptions (entities, edges, tombstones materialization).
    _observer_b: (Subscription, Subscription, Subscription),
    /// Observer A state for pending bytes tracking.
    pub observer_a_state: Arc<ObserverAState>,
}

impl LoadedWindow {
    /// Creates a new window with fresh Doc and registered observers.
    pub fn new(
        user_id: &str,
        key: WindowKey,
        vault: &Arc<Vault>,
        materializer: &Arc<Materializer>,
    ) -> Self {
        let doc = create_window_doc(user_id, &key);
        Self::from_doc(doc, key, vault, materializer)
    }

    /// Creates a window from an existing Doc (e.g., loaded from sync_state).
    pub fn from_doc(
        doc: LoroDocument,
        key: WindowKey,
        vault: &Arc<Vault>,
        materializer: &Arc<Materializer>,
    ) -> Self {
        let observer_a_state = Arc::new(ObserverAState::new());
        let observer_a =
            bridge::register_observer_a(&doc, vault, key.as_str(), observer_a_state.clone());
        let observer_b = bridge::register_observer_b(&doc, vault, materializer);

        Self {
            doc,
            key,
            _observer_a: observer_a,
            _observer_b: observer_b,
            observer_a_state,
        }
    }

    /// Persists the window Doc state to sync_state and returns the encoded state.
    pub fn persist_state(&self, vault: &Vault) -> Result<Vec<u8>> {
        // Export full snapshot for persistence
        let state = self.doc.export_snapshot()?;
        let vv = self.doc.version_vector();

        vault.with_write_txn(|wtxn| {
            let doc_key = format!("d:w:{}", self.key);
            vault.store.sync_state.put(wtxn, &doc_key, &state)?;

            let sv_key = format!("sv:w:{}", self.key);
            vault.store.sync_state.put(wtxn, &sv_key, &vv)?;

            let svf_key = format!("svf:w:{}", self.key);
            vault.store.sync_state.put(wtxn, &svf_key, &[1u8])?;
            Ok(())
        })?;

        Ok(state)
    }
}

/// Loads a window Doc from persisted state in sync_state.
pub fn load_window_from_state(vault: &Vault, _user_id: &str, key: &WindowKey) -> Result<LoroDocument> {
    let rtxn = vault.store.env.read_txn()?;

    let doc_key = format!("d:w:{}", key);
    let state = vault
        .store
        .sync_state
        .get(&rtxn, &doc_key)?
        .ok_or_else(|| Error::WindowNotFound(key.as_str().to_string()))?;

    // Load from snapshot
    let doc = LoroDocument::from_snapshot(state)?;

    // Apply pending updates
    let prefix = format!("u:w:{}:", key);
    let iter = vault.store.sync_state.iter(&rtxn)?;
    for entry in iter {
        let (k, v) = entry?;
        if !k.starts_with(&prefix) {
            continue;
        }
        doc.import(v)?;
    }

    Ok(doc)
}

/// Replays pending-mirror markers (pm:*) for crash recovery.
pub fn replay_pending_mirrors(
    vault: &Vault,
    doc: &LoroDocument,
    window_key: &WindowKey,
) -> Result<u32> {
    let rtxn = vault.store.env.read_txn()?;
    let prefix = format!("pm:{}:", window_key);

    let mut markers: Vec<(String, EntityId)> = Vec::new();

    let iter = vault.store.sync_state.iter(&rtxn)?;
    for entry in iter {
        let (k, _) = entry?;
        if !k.starts_with(&prefix) {
            continue;
        }
        let hex = &k[prefix.len()..];
        if let Ok(id) = EntityId::from_hex(hex) {
            markers.push((k.to_string(), id));
        }
    }
    drop(rtxn);

    let entities_map = doc.get_or_create_map("entities");
    let tombstones_map = doc.get_or_create_map("tombstones");
    let edges_map = doc.get_or_create_map("edges");

    let mut replayed = 0u32;

    for (marker_key, id) in &markers {
        let hex_id = id.to_hex();

        // Read entity from LMDB
        let raw = match vault.get_raw(id)? {
            Some(r) => r,
            None => {
                // Stale marker — clear it
                vault.with_write_txn(|wtxn| {
                    vault.store.sync_state.delete(wtxn, marker_key)?;
                    Ok(())
                })?;
                continue;
            }
        };

        // Check if tombstoned in CRDT
        if tombstones_map.get(&hex_id).is_some() {
            vault.with_write_txn(|wtxn| {
                vault.store.sync_state.delete(wtxn, marker_key)?;
                Ok(())
            })?;
            continue;
        }

        // Byte-compare with existing CRDT value
        if let Some(existing) = entities_map.get(&hex_id) {
            if existing.as_slice() == raw.as_slice() {
                vault.with_write_txn(|wtxn| {
                    vault.store.sync_state.delete(wtxn, marker_key)?;
                    Ok(())
                })?;
                continue;
            }
        }

        // Mirror to CRDT under bridge origin
        entities_map.insert(hex_id.as_str(), raw.as_slice()).unwrap();

        let edges_out = vault.edges_out(id)?;
        for edge in &edges_out {
            let edge_key = format_edge_key(id, edge.kind, &edge.target);
            let edge_val = encode_edge_value_for_crdt(edge.weight, edge.created_at, edge.vad);
            edges_map.insert(edge_key.as_str(), &edge_val).unwrap();
        }

        doc.commit_with_origin(BRIDGE_ORIGIN);

        // Clear the marker
        vault.with_write_txn(|wtxn| {
            vault.store.sync_state.delete(wtxn, marker_key)?;
            Ok(())
        })?;

        replayed += 1;
    }

    Ok(replayed)
}

/// Forward re-materialization: CRDT→LMDB.
pub fn forward_rematerialize(
    vault: &Vault,
    doc: &LoroDocument,
    materializer: &Materializer,
) -> Result<u32> {
    let _guard = materializer.lock();
    let entities_map = doc.get_or_create_map("entities");
    let edges_map = doc.get_or_create_map("edges");
    let tombstones_map = doc.get_or_create_map("tombstones");

    let mut count = 0u32;

    // Entities
    entities_map.for_each(&mut |key, blob| {
        let id = match EntityId::from_hex(key) {
            Ok(id) => id,
            Err(_) => return,
        };

        let lmdb_blob = match vault.get_raw(&id) {
            Ok(v) => v,
            Err(_) => return,
        };
        if lmdb_blob.as_deref() == Some(blob) {
            return;
        }

        let header = match EntityMetadataHeader::parse(blob) {
            Some(h) => h,
            None => return,
        };
        let data = if blob.len() > 25 { &blob[25..] } else { &[] };
        let result = vault
            .batch()
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
            .commit();
        if result.is_ok() {
            count += 1;
        }
    });

    // Edges (with endpoint filtering)
    edges_map.for_each(&mut |key, buf| {
        let Some((src, kind, tgt)) = bridge::parse_edge_key(key) else {
            return;
        };

        let src_exists = vault.entity_exists(&src).unwrap_or(false);
        let tgt_exists = vault.entity_exists(&tgt).unwrap_or(false);
        if !src_exists || !tgt_exists {
            return;
        }

        let (weight, created_at, vad) = bridge::parse_edge_value(buf);

        if vault.edge_exists(&src, kind, &tgt).unwrap_or(false) {
            return;
        }

        let result = vault
            .batch()
            .edge_with_created_at_and_vad(&src, kind, &tgt, weight, created_at, vad)
            .commit();
        if result.is_ok() {
            count += 1;
        }
    });

    // Tombstones
    tombstones_map.for_each(&mut |key, _| {
        let id = match EntityId::from_hex(key) {
            Ok(id) => id,
            Err(_) => return,
        };

        if vault.entity_exists(&id).unwrap_or(false)
            && vault.delete_entity(&id).is_ok()
        {
            count += 1;
        }
    });

    Ok(count)
}

/// Reverse re-materialization: LMDB→CRDT (missing only).
pub fn reverse_rematerialize(
    vault: &Vault,
    doc: &LoroDocument,
    window_key: &WindowKey,
) -> Result<u32> {
    let start_ts = window_key
        .start_timestamp()
        .ok_or_else(|| Error::InvalidConfig("invalid window key".to_string()))?;
    let end_ts = window_key
        .end_timestamp()
        .ok_or_else(|| Error::InvalidConfig("invalid window key".to_string()))?;

    let entities_in_range = vault.entities_in_learned_range(start_ts, end_ts)?;

    let entities_map = doc.get_or_create_map("entities");
    let edges_map = doc.get_or_create_map("edges");
    let tombstones_map = doc.get_or_create_map("tombstones");

    let mut count = 0u32;

    for id in &entities_in_range {
        let hex_id = id.to_hex();

        if tombstones_map.get(&hex_id).is_some() {
            continue;
        }
        if entities_map.get(&hex_id).is_some() {
            continue;
        }

        let raw = match vault.get_raw(id)? {
            Some(r) => r,
            None => continue,
        };

        entities_map.insert(hex_id.as_str(), raw.as_slice()).unwrap();

        let edges_out = vault.edges_out(id)?;
        for edge in &edges_out {
            let edge_key = format_edge_key(id, edge.kind, &edge.target);
            if edges_map.get(&edge_key).is_some() {
                continue;
            }
            let edge_val = encode_edge_value_for_crdt(edge.weight, edge.created_at, edge.vad);
            edges_map.insert(edge_key.as_str(), &edge_val).unwrap();
        }

        count += 1;
    }

    // Commit all bridge writes with origin tag
    if count > 0 {
        doc.commit_with_origin(BRIDGE_ORIGIN);
    }

    Ok(count)
}
