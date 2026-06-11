//! Window lifecycle management for the CRDT sync layer.
//!
//! Windows partition entities by `learned_at` month. Each window has an
//! independent CRDT Doc (Loro). Only 2 windows are loaded by default
//! (current + previous month); older windows are ON-DISK in sync_state.

use std::collections::HashMap;
use std::sync::Arc;

use super::bridge::{
    self, BRIDGE_ORIGIN, Materializer, ObserverAState, OutboundSink, encode_edge_value_for_crdt,
    format_edge_key,
};
use super::loro_support::{
    doc_from_snapshot, doc_version_vector, export_snapshot, import_doc, map_contains_binary,
    map_delete, map_for_each_bytes, map_for_each_tombstone_value, map_get_bytes, map_insert_bytes,
    tombstone_map_contains_id, tombstone_values_for_id,
};
use super::schema::create_window_doc;
use super::types::WindowKey;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EdgeValueFields, EntityMetadataHeader};
use crate::deletion::{PENDING_TOMBSTONE_PREFIX, decode_tombstone_value};
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
    ///
    /// Test/bootstrap convenience only: the fresh doc skips recovery, but
    /// LMDB may still be ahead of a window that has no persisted CRDT state
    /// (first open, or `sync_state` lost). Production opens go through
    /// [`crate::sync::manager::WindowManager::open_window`], which runs the
    /// pinned recovery order on the bare doc before observers attach.
    pub fn new(
        user_id: &str,
        key: WindowKey,
        vault: &Arc<Vault>,
        materializer: &Arc<Materializer>,
    ) -> Self {
        let doc = create_window_doc(user_id, &key);
        Self::from_doc(doc, key, vault, materializer)
    }

    /// Creates a window from an existing Doc (e.g., loaded from sync_state),
    /// attaching Observer A + B — ARCH-0023b startup step 6.
    ///
    /// Observer registration is deliberately split from recovery: the pinned
    /// startup order requires pm replay → reverse remat → forward remat
    /// (steps 3 → 4 → 5) to run on the bare doc BEFORE observers attach, so
    /// this constructor must only be handed a pre-recovered doc.
    /// [`crate::sync::manager::WindowManager::open_window`] is the
    /// production path that enforces that order.
    pub fn from_doc(
        doc: LoroDoc,
        key: WindowKey,
        vault: &Arc<Vault>,
        materializer: &Arc<Materializer>,
    ) -> Self {
        Self::from_doc_with_outbound(doc, key, vault, materializer, None)
    }

    /// [`Self::from_doc`] with an [`OutboundSink`] for Observer A: persisted
    /// local updates are routed outbound (connection channel when attached,
    /// durable `SyncQueue` otherwise). The production
    /// [`crate::sync::manager::WindowManager`] open path always passes its
    /// shared sink; the sink-less constructors exist for tests/bootstrap.
    pub fn from_doc_with_outbound(
        doc: LoroDoc,
        key: WindowKey,
        vault: &Arc<Vault>,
        materializer: &Arc<Materializer>,
        outbound: Option<Arc<OutboundSink>>,
    ) -> Self {
        let observer_a_state = Arc::new(ObserverAState::new());
        let observer_a = bridge::register_observer_a(
            &doc,
            vault,
            key.as_str(),
            observer_a_state.clone(),
            outbound,
        );
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
    drop(rtxn);

    // Apply pending updates on top of the snapshot (startup step 2).
    apply_pending_window_updates(vault, &doc, key)?;

    Ok(doc)
}

/// Applies pending `u:w:{key}:*` update rows to a window doc in sequence
/// order (ARCH-0023b startup step 2). Returns the number of updates applied.
///
/// Also used by the manager's fresh-doc fallback: pending update rows can
/// exist WITHOUT a `d:w:{key}` snapshot (remote updates persisted before
/// the window was ever unloaded/compacted), and skipping the replay there
/// would silently drop accepted sync data — tombstones especially, whose
/// LMDB purge already ran and which reverse re-materialization can never
/// reconstruct.
pub(crate) fn apply_pending_window_updates(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
) -> Result<u32> {
    let rtxn = vault.store.env.read_txn()?;
    // Prefix iterator (B-tree range seek); `{seq:08x}` keys sort in order.
    let prefix = format!("u:w:{key}:");
    let mut applied = 0u32;
    let iter = vault.store.sync_state.prefix_iter(&rtxn, &prefix)?;
    for entry in iter {
        let (_k, v) = entry?;
        import_doc(doc, v)?;
        applied += 1;
    }
    Ok(applied)
}

/// Applies one tombstone (raw v2/legacy wire value) to a window doc IN
/// MEMORY — the caller commits. ONE-1132 write-side semantics, shared by
/// the local delete path and the `pt:` boot replay so the two can never
/// diverge:
///
/// 1. **Never-downgrade** (read-before-write): a tombstone that decodes
///    HARD is never replaced by a soft one — hard-once-seen is
///    irreversible. The raw bytes are inserted verbatim (never re-encoded),
///    so unknown future layouts survive untouched.
/// 2. **Entities-map removal**: the live `entities[id]` copy is an ACTIVE
///    carrier of the deleted payload, not history — it is deleted in the
///    SAME commit as the tombstone insert (op-history bytes remain for the
///    bounded `h:` sweep, ONE-1091).
/// 3. **Edges-map removal (hard only)**: every edge key touching the
///    entity is removed — those values are active carriers too. Soft
///    deletes keep edge keys: the local shell keeps its live edges
///    (ARCH-0038 user_delete keeps the message shell).
pub fn apply_tombstone_to_window_doc(doc: &LoroDoc, id: &EntityId, raw_value: &[u8]) -> Result<()> {
    let incoming = decode_tombstone_value(raw_value);
    let hex_id = id.to_hex();

    let tombstones = doc.get_map("tombstones");
    // Tombstone-aware read across EVERY hex-casing alias of the id: a
    // PRESENT non-Binary value reads as the empty slice, which decodes HARD
    // (fail closed) — a garbage tombstone must block a soft downgrade
    // exactly like a hard binary one, and a crafted UPPERCASE-key hard
    // tombstone must block it exactly like the canonical lowercase one.
    let existing_hard = tombstone_values_for_id(&tombstones, id)
        .iter()
        .any(|existing| decode_tombstone_value(existing).is_hard());
    let downgrade_blocked = existing_hard && !incoming.is_hard();
    if !downgrade_blocked {
        map_insert_bytes(&tombstones, &hex_id, raw_value)?;
    }

    let entities = doc.get_map("entities");
    if entities.get(&hex_id).is_some() {
        map_delete(&entities, &hex_id)?;
    }

    // Edge keys are swept on the EFFECTIVE hardness, not just the incoming
    // value's: a REJECTED soft arriving over an effective hard tombstone
    // must still sweep carrier edges a peer re-added since the original
    // hard sweep (delete semantics never weaken; over-sweep is the
    // fail-closed direction).
    if incoming.is_hard() || existing_hard {
        let edges = doc.get_map("edges");
        let mut doomed = Vec::new();
        map_for_each_bytes(&edges, |key, _| {
            if let Some((src, _, tgt)) = bridge::parse_edge_key(key)
                && (src == *id || tgt == *id)
            {
                doomed.push(key.to_owned());
            }
        });
        for key in &doomed {
            map_delete(&edges, key)?;
        }
    }

    Ok(())
}

/// Replays pending-tombstone markers (`pt:{window}:{entity_hex}`) into the
/// window doc. OWNER-DECISION (ONE-1132 cfg-off durability): the marker is
/// written UNCONDITIONALLY in the purge / shell-scrub txn — a build without
/// the `sync` feature cannot write the CRDT record, so the marker is the
/// deletion's durable propagation intent, and it doubles as the crash
/// marker between the purge txn and the CRDT commit on sync-enabled builds.
///
/// A sync-enabled boot calls this BEFORE [`replay_pending_mirrors`] (so a
/// freshly replayed tombstone suppresses any pending mirror of the same
/// entity). Idempotent: guarded tombstone insert + entities-key removal
/// (+ edges-key removal for hard values). The doc state is persisted to
/// `sync_state` BEFORE the markers are cleared — a marker may only vanish
/// once the CRDT record is durable. Malformed marker keys are left in
/// place (a deletion intent is never silently dropped) and logged.
pub fn replay_pending_tombstones(
    vault: &Vault,
    doc: &LoroDoc,
    window_key: &WindowKey,
) -> Result<u32> {
    let prefix = format!("{PENDING_TOMBSTONE_PREFIX}{window_key}:");
    let mut markers: Vec<(String, EntityId, Vec<u8>)> = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        let iter = vault.store.sync_state.prefix_iter(&rtxn, &prefix)?;
        for entry in iter {
            let (k, v) = entry?;
            let hex = &k[prefix.len()..];
            match EntityId::from_hex(hex) {
                Ok(id) => markers.push((k.to_string(), id, v.to_vec())),
                Err(_) => {
                    tracing::warn!(
                        marker = %k,
                        "pt replay: malformed pending-tombstone marker left in place"
                    );
                }
            }
        }
    }
    if markers.is_empty() {
        return Ok(0);
    }

    for (_, id, value) in &markers {
        apply_tombstone_to_window_doc(doc, id, value)?;
    }
    // Bridge origin: local LMDB already reflects the delete (the marker was
    // written in the purge/scrub txn itself), so Observer B must not re-run
    // the hard purge against a soft shell.
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));

    // Persist BEFORE clearing the markers — the marker may only be cleared
    // after CRDT commit + snapshot persistence succeed.
    let snapshot = export_snapshot(doc)?;
    let vv = doc_version_vector(doc);
    vault.with_write_txn(|wtxn| {
        let doc_key = format!("d:w:{window_key}");
        vault.store.sync_state.put(wtxn, &doc_key, &snapshot)?;
        let sv_key = format!("sv:w:{window_key}");
        vault.store.sync_state.put(wtxn, &sv_key, &vv)?;
        let svf_key = format!("svf:w:{window_key}");
        vault.store.sync_state.put(wtxn, &svf_key, &[1_u8])?;
        for (marker_key, _, _) in &markers {
            vault.store.sync_state.delete(wtxn, marker_key)?;
        }
        Ok(())
    })?;

    Ok(u32::try_from(markers.len()).unwrap_or(u32::MAX))
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

        // Check if tombstoned in CRDT — value-agnostic, entity-canonical
        // presence: a non-binary tombstone still decodes HARD downstream
        // and a case-shifted hex alias still names this id, so both must
        // suppress the mirror exactly like a canonical binary one (fail
        // closed).
        if tombstone_map_contains_id(&tombstones_map, id) {
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
                if tombstone_map_contains_id(&tombstones_map, &edge.target) {
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
            if tombstone_map_contains_id(&tombstones_map, &edge.target) {
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

            // Tombstone gate (delete wins): a tombstoned id must never
            // re-materialize from a lingering entities-map body — without
            // this gate every boot would re-put the purged body and the
            // tombstone pass below would purge it again, multiplying
            // receipts forever. Presence is value-agnostic (a non-binary
            // tombstone decodes HARD downstream) AND entity-canonical (a
            // case-shifted hex tombstone key still names this id), and
            // OR'd with the permanent local `dt:` marker so a hostile peer
            // that REMOVES the tombstone from the map cannot resurrect the
            // body either. A failed marker read fails CLOSED (skip).
            if tombstone_map_contains_id(&tombstones_map, &id) {
                return;
            }
            let locally_hard_deleted =
                match vault.local_hard_delete_marker_exists_in_txn(&rtxn, &id) {
                    Ok(present) => present,
                    Err(e) => {
                        tracing::warn!(
                            entity = %key,
                            error = %e,
                            "forward remat: dt: marker read failed — failing closed"
                        );
                        true
                    }
                };
            if locally_hard_deleted {
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
            // ANY-value, entity-canonical presence — a non-binary tombstone
            // gates too, and a case-shifted hex alias still names the id.
            if tombstone_map_contains_id(&tombstones_map, &src)
                || tombstone_map_contains_id(&tombstones_map, &tgt)
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

    // Tombstones — reason-aware replay (ONE-1133 / ARCH-0038): the VALUE
    // decides the effect, routed through the shared primitive, never a
    // bare purge. Known-soft `user_delete` keeps the 25 B shell (SoftErase
    // + D16 refresh); every other shape hard-purges and — when local state
    // was erased — writes the LOCAL REDACTION_AUDIT receipt and `h:` sweep
    // row. The tombstone-aware iterator visits EVERY value: a non-Binary
    // tombstone replays as the empty slice, which decodes HARD — a
    // malformed remote tombstone must never be skipped (it would leave the
    // entity pass's re-materialized body live forever = durable
    // resurrection). The primitive is idempotent (no receipt when nothing
    // local remains), so this every-boot pass cannot multiply receipts.
    map_for_each_tombstone_value(&tombstones_map, |key, value| {
        let id = match EntityId::from_hex(key) {
            Ok(id) => id,
            Err(_) => return,
        };

        match vault.apply_replayed_tombstone(&id, value) {
            Ok(outcome) => {
                if outcome.changed_local_state() {
                    count += 1;
                }
            }
            Err(err) => {
                tracing::warn!(
                    tombstone = %key,
                    error = %err,
                    "forward remat: tombstone replay failed"
                );
            }
        }
    });

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

        // Value-agnostic, entity-canonical tombstone presence (fail
        // closed): a non-binary tombstone decodes HARD on replay and a
        // case-shifted hex alias still names this id, so reverse remat
        // must never re-insert the still-live local body over either —
        // that would ship a hard-deleted payload fleet-wide. Entities-map
        // check below stays Binary-only by design.
        if tombstone_map_contains_id(&tombstones_map, id) {
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
            if tombstone_map_contains_id(&tombstones_map, &edge.target) {
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
