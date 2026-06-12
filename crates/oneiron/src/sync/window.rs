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
    map_contains_key, map_for_each_bytes, map_get_bytes, map_insert_bytes,
};
use super::schema::create_window_doc;
use super::types::WindowKey;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EdgeValueFields, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::store::Store;
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

        // Check if tombstoned in CRDT. Presence check is fail closed: ANY
        // tombstone value gates, not just Binary (a non-binary tombstone
        // must never let the marker entity remirror).
        if map_contains_key(&tombstones_map, &hex_id) {
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
            // The entity bytes already reached the CRDT, but the marker may
            // cover a crash between the entity insert and its edge inserts
            // (ARCH-0023b step 3 mirrors entity + edges as one unit). Replay
            // any missing `edges_out` entries BEFORE clearing the marker —
            // clearing early would silently drop the un-mirrored edges.
            let mut wrote_edges = false;
            let edges_out = vault.edges_out(id)?;
            for edge in &edges_out {
                // Never backfill an edge whose TARGET is tombstoned —
                // matching forward remat's both-endpoint filter. A surviving
                // local S→E row (crash between the tombstone CRDT commit and
                // the purge txn, or a failed purge) must not be re-inserted
                // into the replicated edges map (ARCH-0038 active-carrier
                // purge). Plain containment = skip on this branch (legacy
                // values are hard); becomes reason-aware (skip iff the
                // tombstone decodes HARD) once tombstone v2 lands in M4-06.
                if map_contains_key(&tombstones_map, &edge.target.to_hex()) {
                    continue;
                }
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
                    .map_err(|e| Error::SyncProtocolError(format!("pm replay edge insert: {e}")))?;
                wrote_edges = true;
            }
            if wrote_edges {
                doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
                replayed += 1;
            }

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
            // Same tombstoned-target gate as the byte-equal path above:
            // the full mirror must not re-insert edges to deleted targets.
            if map_contains_key(&tombstones_map, &edge.target.to_hex()) {
                continue;
            }
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
///
/// ARCH-0023b crash-recovery step 5: iterate the `entities`, `edges` and
/// `tombstones` maps, byte-compare against LMDB and write any that differ.
/// Step 3's deletion rule binds here too — "if tombstoned in CRDT → never
/// resurrect": a tombstoned entity's bytes are never written to LMDB (not
/// even transiently), and no edge with a tombstoned endpoint is re-added.
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

            // ARCH-0023b: "if tombstoned in CRDT → never resurrect". Checked
            // BEFORE any put so a hard-deleted entity's bytes never reach
            // LMDB, not even transiently (a durable put-then-re-purge would
            // briefly resurrect deleted content). The raw map key is checked
            // alongside the canonical hex so a non-canonical entity alias
            // cannot dodge a canonical tombstone — fail closed. Presence is
            // ANY-value (`map_contains_key`): a non-binary tombstone must
            // gate too, never fail open.
            if map_contains_key(&tombstones_map, key)
                || map_contains_key(&tombstones_map, &id.to_hex())
            {
                return;
            }

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
                // SoftErase shell guard: `user_delete` truncates the local
                // record to the 25 B header shell and writes NO CRDT record
                // (contracts.ts deleteReasons user_delete: "Tombstone
                // revision (empty content); keep the message shell" —
                // cross-device propagation is deferred to ONE-1090), so the
                // CRDT mirror still carries the pre-delete body. Replaying
                // that body over the shell would resurrect deleted content —
                // delete wins. Interim guard until reason-aware tombstones
                // land in M4-06.
                if let Some(local) = &lmdb_blob
                    && local.len() == ENTITY_METADATA_HEADER_LEN
                    && blob.len() > ENTITY_METADATA_HEADER_LEN
                {
                    tracing::warn!(
                        entity = %id.to_hex(),
                        "forward remat: kept local SoftErase shell over longer CRDT body (reason-aware tombstones land in M4-06)"
                    );
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
            // Replicated put: the CRDT mirror is unfiltered, so the
            // maintenance band (REDACTION_AUDIT = 120) and reserved-predicate
            // `edge.provenance` truth-Claims reach here on the way back into
            // LMDB. Routing through the public gate would silently drop them
            // on cross-node sync / replay; `put_replicated` admits both
            // engine-authored bands while still running full structural
            // validation (unknown type bytes, ungrammatical predicates, and
            // malformed CLAIM bodies all still fail typed).
            let result = vault
                .batch()
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
                .commit();
            match result {
                Ok(()) => {
                    materialized_blobs.insert(id, blob.to_vec());
                    count += 1;
                }
                Err(err) => {
                    tracing::warn!(
                        entity = %id.to_hex(),
                        error = %err,
                        "forward remat: entity put failed"
                    );
                }
            }
        });
        if let Some(err) = entity_read_error {
            return Err(err);
        }
    }

    // Edges (endpoint + tombstone filtering, stored-value byte-compare).
    // ARCH-0023b step 5 byte-compares edges too ("write any that differ"):
    // an exists-skip would let a CRDT edge carrying confirmation_status =
    // retracted (value[24] == 3) lose to a stale local Active stamp, and the
    // PPR retracted gate would keep propagating withdrawn provenance.
    {
        let rtxn = vault.store.env.read_txn()?;
        let mut edge_error = None;
        map_for_each_bytes(&edges_map, |key, buf| {
            if edge_error.is_some() {
                return;
            }
            let Some((src, kind, tgt)) = bridge::parse_edge_key(key) else {
                return;
            };

            // Never re-add an edge whose endpoint is tombstoned in the CRDT.
            // ANY-value presence — a non-binary tombstone gates too.
            if map_contains_key(&tombstones_map, &src.to_hex())
                || map_contains_key(&tombstones_map, &tgt.to_hex())
            {
                return;
            }

            // Local LMDB read errors are typed failures, not `false` — a
            // conflated read error would silently skip (or re-add) edges.
            let edge_state = (|| -> Result<(bool, Option<Vec<u8>>)> {
                let src_exists = vault.store.entities.get(&rtxn, src.as_bytes())?.is_some();
                let tgt_exists = vault.store.entities.get(&rtxn, tgt.as_bytes())?.is_some();
                if !src_exists || !tgt_exists {
                    return Ok((false, None));
                }
                let stored = vault
                    .store
                    .edges_out
                    .get(&rtxn, &Store::encode_edge_key(&src, kind, &tgt))?
                    .map(<[u8]>::to_vec);
                Ok((true, stored))
            })();
            let (endpoints_exist, stored) = match edge_state {
                Ok(state) => state,
                Err(err) => {
                    edge_error = Some(err);
                    return;
                }
            };
            if !endpoints_exist {
                return;
            }

            let Ok(decoded) = decode_edge_value_for_kind(kind, buf) else {
                tracing::warn!(edge = %key, "forward remat: edge malformed value");
                return;
            };

            // Byte-equal → nothing to do; missing or differing → write the
            // CRDT bytes with flags VERBATIM (no re-derivation).
            if stored.as_deref() == Some(buf) {
                return;
            }

            let result = vault
                .batch()
                .edge_with_value_fields(&src, kind, &tgt, EdgeValueFields::from_decoded(decoded))
                .commit();
            match result {
                Ok(()) => count += 1,
                Err(err) => {
                    tracing::warn!(
                        edge = %key,
                        error = %err,
                        "forward remat: edge write failed"
                    );
                }
            }
        });
        if let Some(err) = edge_error {
            return Err(err);
        }
    }

    // Tombstones — purge any stale local row a tombstoned id still has.
    {
        let rtxn = vault.store.env.read_txn()?;
        let mut tombstone_error = None;
        let mut to_purge = Vec::new();
        map_for_each_bytes(&tombstones_map, |key, _| {
            if tombstone_error.is_some() {
                return;
            }
            let id = match EntityId::from_hex(key) {
                Ok(id) => id,
                Err(_) => return,
            };
            // A local read error must not be conflated with "absent" — that
            // would silently leave a tombstoned row behind.
            match vault.store.entities.get(&rtxn, id.as_bytes()) {
                Ok(Some(_)) => to_purge.push(id),
                Ok(None) => {}
                Err(err) => tombstone_error = Some(Error::from(err)),
            }
        });
        drop(rtxn);
        if let Some(err) = tombstone_error {
            return Err(err);
        }
        for id in to_purge {
            match vault.purge_entity_active_store(&id) {
                Ok(_) => count += 1,
                Err(err) => {
                    // Surfaced loudly; durable retry via rm: markers lands in
                    // M4-04 — this path must never fail silent in the interim.
                    tracing::error!(
                        entity = %id.to_hex(),
                        error = %err,
                        "forward remat: tombstone purge failed"
                    );
                }
            }
        }
    }

    Ok(count)
}

/// Reverse re-materialization: LMDB→CRDT (insert-missing only).
///
/// ARCH-0023b crash-recovery step 4: scan LMDB entities + `edges_out` in the
/// window's `learned_at` range and "mirror ANYTHING present in LMDB but
/// missing from CRDT" — edge backfill runs for EVERY non-tombstoned in-range
/// entity, not just entities the CRDT is missing (an already-mirrored entity
/// can still have locally-written edges the CRDT lacks). Differing edge
/// values are left alone: this pass inserts missing records only.
///
/// Returns the number of entities newly mirrored into the CRDT.
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
    let mut wrote_any = false;

    for id in &entities_in_range {
        let hex_id = id.to_hex();

        // ANY-value tombstone presence gates the SOURCE (fail closed): a
        // non-binary tombstone must never let a surviving local row
        // re-insert the deleted body into the replicated entities map.
        if map_contains_key(&tombstones_map, &hex_id) {
            continue;
        }

        if !map_contains_binary(&entities_map, &hex_id) {
            let raw = match vault.get_raw(id)? {
                Some(r) => r,
                None => continue,
            };

            map_insert_bytes(&entities_map, hex_id.as_str(), raw.as_slice()).map_err(|e| {
                Error::SyncProtocolError(format!("reverse remat entity insert: {e}"))
            })?;
            wrote_any = true;
            count += 1;
        }

        let edges_out = vault.edges_out(id)?;
        for edge in &edges_out {
            // Never backfill an edge whose TARGET is tombstoned — matching
            // forward remat's both-endpoint filter (the source is gated
            // above). A surviving local S→E row from the tombstone-commit/
            // purge-txn crash window must not re-enter the replicated edges
            // map. Plain containment = skip on this branch; reason-aware
            // (skip iff HARD) once tombstone v2 lands in M4-06.
            if map_contains_key(&tombstones_map, &edge.target.to_hex()) {
                continue;
            }
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
            wrote_any = true;
        }
    }

    // Commit all bridge writes with origin tag
    if wrote_any {
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }

    Ok(count)
}
