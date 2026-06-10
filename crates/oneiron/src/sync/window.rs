//! Window lifecycle management for the CRDT sync layer.
//!
//! Windows partition entities by `learned_at` month. Each window has an
//! independent CRDT Doc (Loro). Only 2 windows are loaded by default
//! (current + previous month); older windows are ON-DISK in sync_state.

use std::collections::HashMap;
use std::sync::Arc;

use super::bridge::{
    self, BRIDGE_ORIGIN, Materializer, ObserverAState, encode_edge_value_for_crdt, format_edge_key,
};
use super::loro_support::{
    doc_from_snapshot, doc_version_vector, export_snapshot, import_doc, map_contains_binary,
    map_for_each_bytes, map_get_bytes, map_insert_bytes,
};
use super::schema::create_window_doc;
use super::types::WindowKey;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EdgeValueFields, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::types::{EntityId, decode_edge_value_for_kind};
use loro::{CommitOptions, LoroDoc, Subscription};

/// A loaded window Doc with its observer subscriptions.
pub struct LoadedWindow {
    /// The Loro Doc for this window.
    pub doc: LoroDoc,
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
        doc: LoroDoc,
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
        let state = export_snapshot(&self.doc)?;
        let vv = doc_version_vector(&self.doc);

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
pub fn load_window_from_state(vault: &Vault, _user_id: &str, key: &WindowKey) -> Result<LoroDoc> {
    let rtxn = vault.store.env.read_txn()?;

    let doc_key = format!("d:w:{key}");
    let state = vault
        .store
        .sync_state
        .get(&rtxn, &doc_key)?
        .ok_or_else(|| Error::WindowNotFound {
            window_key: key.as_str().to_string(),
        })?;

    // Load from snapshot
    let doc = doc_from_snapshot(state)?;

    // Apply pending updates using prefix iterator (B-tree range seek)
    let prefix = format!("u:w:{key}:");
    let iter = vault.store.sync_state.prefix_iter(&rtxn, &prefix)?;
    for entry in iter {
        let (_k, v) = entry?;
        import_doc(&doc, v)?;
    }

    Ok(doc)
}

/// Replays pending-mirror markers (pm:*) for crash recovery.
pub fn replay_pending_mirrors(vault: &Vault, doc: &LoroDoc, window_key: &WindowKey) -> Result<u32> {
    let rtxn = vault.store.env.read_txn()?;
    let prefix = format!("pm:{window_key}:");

    let mut markers: Vec<(String, EntityId)> = Vec::new();

    let iter = vault.store.sync_state.prefix_iter(&rtxn, &prefix)?;
    for entry in iter {
        let (k, _) = entry?;
        let hex = &k[prefix.len()..];
        let parsed_id = EntityId::from_hex(hex);
        if let Ok(id) = parsed_id {
            markers.push((k.to_string(), id));
        }
    }
    drop(rtxn);

    let entities_map = doc.get_map("entities");
    let tombstones_map = doc.get_map("tombstones");
    let edges_map = doc.get_map("edges");

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
        if map_contains_binary(&tombstones_map, &hex_id) {
            vault.with_write_txn(|wtxn| {
                vault.store.sync_state.delete(wtxn, marker_key)?;
                Ok(())
            })?;
            continue;
        }

        // Byte-compare with existing CRDT value
        if let Some(existing) = map_get_bytes(&entities_map, &hex_id)
            && existing.as_slice() == raw.as_slice()
        {
            vault.with_write_txn(|wtxn| {
                vault.store.sync_state.delete(wtxn, marker_key)?;
                Ok(())
            })?;
            continue;
        }

        // Mirror to CRDT under bridge origin
        map_insert_bytes(&entities_map, hex_id.as_str(), raw.as_slice())
            .map_err(|e| Error::SyncProtocolError(format!("pm replay entity insert: {e}")))?;

        let edges_out = vault.edges_out(id)?;
        for edge in &edges_out {
            let edge_key = format_edge_key(id, edge.kind, &edge.target);
            let edge_val = encode_edge_value_for_crdt(
                edge.kind,
                edge.weight,
                edge.created_at,
                edge.vad,
                edge.provenance,
            )?;
            map_insert_bytes(&edges_map, edge_key.as_str(), &edge_val)
                .map_err(|e| Error::SyncProtocolError(format!("pm replay edge insert: {e}")))?;
        }

        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));

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
    doc: &LoroDoc,
    materializer: &Materializer,
) -> Result<u32> {
    let _guard = materializer.lock();
    let entities_map = doc.get_map("entities");
    let edges_map = doc.get_map("edges");
    let tombstones_map = doc.get_map("tombstones");

    let mut count = 0u32;

    // Entities
    {
        let rtxn = vault.store.env.read_txn()?;
        let mut materialized_blobs = HashMap::<EntityId, Vec<u8>>::new();
        let mut entity_read_error = None;
        map_for_each_bytes(&entities_map, |key, blob| {
            if entity_read_error.is_some() {
                return;
            }

            let id = match EntityId::from_hex(key) {
                Ok(id) => id,
                Err(_) => return,
            };

            if let Some(latest) = materialized_blobs.get(&id) {
                if latest.as_slice() == blob {
                    return;
                }
            } else {
                let lmdb_blob = match vault.get_raw_in(&rtxn, &id) {
                    Ok(v) => v,
                    Err(err) => {
                        entity_read_error = Some(err);
                        return;
                    }
                };
                if lmdb_blob.as_deref() == Some(blob) {
                    return;
                }
            }

            let header = match EntityMetadataHeader::parse(blob) {
                Some(h) => h,
                None => return,
            };
            let data = if blob.len() > ENTITY_METADATA_HEADER_LEN {
                &blob[ENTITY_METADATA_HEADER_LEN..]
            } else {
                &[]
            };
            // Internal put: the CRDT mirror is unfiltered, so the maintenance
            // band (REDACTION_AUDIT = 120) reaches here on the way back into
            // LMDB. Routing through the public gate would silently drop GDPR
            // receipts on cross-node sync / replay; `put_internal` admits the
            // registered maintenance band while still rejecting unknown bytes.
            let result = vault
                .batch()
                .put_internal(
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
                materialized_blobs.insert(id, blob.to_vec());
                count += 1;
            }
        });
        if let Some(err) = entity_read_error {
            return Err(err);
        }
    }

    // Edges (with endpoint filtering)
    map_for_each_bytes(&edges_map, |key, buf| {
        let Some((src, kind, tgt)) = bridge::parse_edge_key(key) else {
            return;
        };

        let src_exists = vault.entity_exists(&src).unwrap_or(false);
        let tgt_exists = vault.entity_exists(&tgt).unwrap_or(false);
        if !src_exists || !tgt_exists {
            return;
        }

        let Ok(decoded) = decode_edge_value_for_kind(kind, buf) else {
            return;
        };

        if vault.edge_exists(&src, kind, &tgt).unwrap_or(false) {
            return;
        }

        let result = vault
            .batch()
            .edge_with_value_fields(&src, kind, &tgt, EdgeValueFields::from_decoded(decoded))
            .commit();
        if result.is_ok() {
            count += 1;
        }
    });

    // Tombstones
    map_for_each_bytes(&tombstones_map, |key, _| {
        let id = match EntityId::from_hex(key) {
            Ok(id) => id,
            Err(_) => return,
        };

        if vault.entity_exists(&id).unwrap_or(false) && vault.purge_entity_active_store(&id).is_ok()
        {
            count += 1;
        }
    });

    Ok(count)
}

/// Reverse re-materialization: LMDB→CRDT (missing only).
pub fn reverse_rematerialize(vault: &Vault, doc: &LoroDoc, window_key: &WindowKey) -> Result<u32> {
    let start_ts = window_key
        .start_timestamp()
        .ok_or_else(|| Error::InvalidConfig("invalid window key".to_string()))?;
    let end_ts = window_key
        .end_timestamp()
        .ok_or_else(|| Error::InvalidConfig("invalid window key".to_string()))?;

    let entities_in_range = vault.entities_in_learned_range(start_ts, end_ts)?;

    let entities_map = doc.get_map("entities");
    let edges_map = doc.get_map("edges");
    let tombstones_map = doc.get_map("tombstones");

    let mut count = 0u32;

    for id in &entities_in_range {
        let hex_id = id.to_hex();

        if map_contains_binary(&tombstones_map, &hex_id) {
            continue;
        }
        if map_contains_binary(&entities_map, &hex_id) {
            continue;
        }

        let raw = match vault.get_raw(id)? {
            Some(r) => r,
            None => continue,
        };

        map_insert_bytes(&entities_map, hex_id.as_str(), raw.as_slice())
            .map_err(|e| Error::SyncProtocolError(format!("reverse remat entity insert: {e}")))?;

        let edges_out = vault.edges_out(id)?;
        for edge in &edges_out {
            let edge_key = format_edge_key(id, edge.kind, &edge.target);
            if map_contains_binary(&edges_map, &edge_key) {
                continue;
            }
            let edge_val = encode_edge_value_for_crdt(
                edge.kind,
                edge.weight,
                edge.created_at,
                edge.vad,
                edge.provenance,
            )?;
            map_insert_bytes(&edges_map, edge_key.as_str(), &edge_val)
                .map_err(|e| Error::SyncProtocolError(format!("reverse remat edge insert: {e}")))?;
        }

        count += 1;
    }

    // Commit all bridge writes with origin tag
    if count > 0 {
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }

    Ok(count)
}
