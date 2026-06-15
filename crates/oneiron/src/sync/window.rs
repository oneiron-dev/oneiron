//! Window lifecycle management for the CRDT sync layer.
//!
//! Windows partition entities by `learned_at` month. Each window has an
//! independent CRDT Doc (Loro). Only 2 windows are loaded by default
//! (current + previous month); older windows are ON-DISK in sync_state.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::bridge::{
    self, BRIDGE_ORIGIN, Materializer, ObserverAState, OutboundSink, encode_edge_value_for_crdt,
    format_edge_key,
};
use super::loro_support::{
    doc_from_snapshot, doc_version_vector, export_snapshot, export_updates_from, import_doc,
    map_contains_binary, map_delete, map_for_each_bytes, map_for_each_tombstone_value,
    map_for_each_value_bytes, map_get_bytes, map_insert_bytes, tombstone_map_contains_id,
    tombstone_values_for_id,
};
use super::quarantine::{self, QuarantineContainer};
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
        let observer_b = bridge::register_observer_b(&doc, vault, materializer, key.as_str());

        Self {
            doc,
            key,
            _observer_a: observer_a,
            _observer_b: observer_b,
            observer_a_state,
        }
    }

    /// Persists the window Doc state to sync_state and returns the encoded state.
    ///
    /// Clobber guard (ONE-1135 AC2): the persisted state (`d:w:` snapshot +
    /// pending `u:` rows) is import-MERGED into the doc BEFORE the export.
    /// CRDT import is monotone — it never drops ops — so a live doc that
    /// never saw a tombstone another writer persisted (e.g. a transient
    /// delete-path write while this window was constructed outside the
    /// registry) can no longer overwrite `d:w:` with a snapshot missing it.
    ///
    /// Subsumed-row prune (ONE-1151): the `u:w:{key}:*` rows the merge
    /// imported are deleted in the SAME transaction as the `d:w:` snapshot
    /// write — every pruned op is provably inside the snapshot (merged
    /// before export), and a crash can never observe pruned rows without
    /// the snapshot that covers them. Rows persisted after the merge keep
    /// their higher `{seq:08x}` keys and survive; `m:u_seq:w:{key}` is
    /// never reset, so future sequence numbers cannot collide with rows
    /// that escaped the prune.
    ///
    /// Freshness (ONE-1151): `svf:w:{key}` is written LAST, after the prune,
    /// from the post-prune `u:w:` set — so when a post-merge row survives,
    /// the flag reads STALE (`[0]`) and the fast-reconnect reader full-opens
    /// the doc rather than shipping an `sv:w:` VV that omits the survivor's
    /// ops. It is never assumed fresh just because a snapshot was persisted.
    pub fn persist_state(&self, vault: &Vault) -> Result<Vec<u8>> {
        let subsumed_update_keys = merge_persisted_state_into_doc(vault, &self.doc, &self.key)?;

        // Export full snapshot for persistence
        let state = export_snapshot(&self.doc)?;
        let vv = doc_version_vector(&self.doc);

        vault.with_write_txn(|wtxn| {
            persist_window_doc_in_txn(vault, wtxn, &self.key, &state, &vv)?;
            prune_subsumed_window_updates_in_txn(vault, wtxn, &self.key, &subsumed_update_keys)?;
            // svf LAST: freshness is computed against the POST-PRUNE u:w:
            // set, so a surviving post-merge row forces stale (ONE-1151).
            write_window_svf_in_txn(vault, wtxn, &self.key)
        })?;

        Ok(state)
    }
}

/// `svf:*` byte meaning "the persisted `sv:*` reflects the FULL durable
/// window state" — so the fast-reconnect reader may ship `sv:w:` without
/// replaying `u:w:` rows. Mirrors the literal pinned in the ON-DISK bulk
/// arm (`SyncClient`, `client.rs`).
const SVF_FRESH: u8 = 1;

/// Writes the pinned window-doc persistence pair — `d:w:{key}` snapshot and
/// `sv:w:{key}` state vector — inside the caller's transaction (ARCH-0023b
/// sync_state key layout).
///
/// The `svf:w:{key}` freshness byte is deliberately NOT written here: it
/// must be computed from the FINAL on-disk `u:w:{key}:` set, AFTER every
/// prune / scrub / delete the caller performs in the same txn. Each caller
/// therefore writes it LAST via [`write_window_svf_in_txn`] — otherwise a
/// snapshot persist that leaves a surviving `u:w:` row on top of `sv:w:`
/// would lie "fresh" and the fast-reconnect reader would omit that row's
/// ops from the VV (ONE-1151 svf-freshness fix).
pub(crate) fn persist_window_doc_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &WindowKey,
    state: &[u8],
    vv: &[u8],
) -> Result<()> {
    let doc_key = format!("d:w:{key}");
    vault.store.sync_state.put(wtxn, &doc_key, state)?;

    let sv_key = format!("sv:w:{key}");
    vault.store.sync_state.put(wtxn, &sv_key, vv)?;
    Ok(())
}

/// Writes `svf:w:{key}` from the FINAL on-disk `u:w:{key}:` set in the
/// caller's transaction: `[SVF_FRESH]` iff zero pending update rows remain,
/// else `[0u8]` (stale). Mirrors the predicate the ON-DISK bulk arm pins in
/// `client.rs` (`svf = if has_pending { 0 } else { SVF_FRESH }`), probing
/// the same `u:w:{key}:` prefix with `prefix_iter`.
///
/// MUST be the LAST sync_state write in every persist txn — after every
/// `u:w:` prune / scrub / delete — so freshness is never computed against a
/// stale view of the update set. `svf:w:` fresh is a promise that `sv:w:`
/// reflects the full durable state; a surviving `u:w:` row breaks that
/// promise, and the flag must read stale so the fast-reconnect reader
/// full-opens the doc instead of shipping a VV that omits the survivor.
pub(crate) fn write_window_svf_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &WindowKey,
) -> Result<()> {
    let pending_prefix = format!("u:w:{key}:");
    let has_pending = {
        let mut iter = vault.store.sync_state.prefix_iter(wtxn, &pending_prefix)?;
        iter.next().transpose()?.is_some()
    };
    let svf = if has_pending { 0u8 } else { SVF_FRESH };
    let svf_key = format!("svf:w:{key}");
    vault.store.sync_state.put(wtxn, &svf_key, &[svf])?;
    Ok(())
}

/// Deletes `u:w:{key}:*` update rows subsumed by a just-persisted
/// `d:w:{key}` snapshot, inside the SAME transaction as the snapshot write
/// (ONE-1151) — subsume-then-prune is atomic, so a crash can never leave
/// pruned rows without the snapshot that covers them.
///
/// `subsumed_update_keys` MUST be the keys returned by
/// [`merge_persisted_state_into_doc`] for the SAME doc the persisted
/// snapshot was exported from: those rows were import-merged into the doc
/// BEFORE the export, so the snapshot provably contains their ops. Rows
/// persisted after the merge's read transaction carry higher `{seq:08x}`
/// keys, are absent from the list, and survive — their ops may not be in
/// the snapshot (e.g. a transient delete-path doc persisting in parallel).
/// `m:u_seq:w:{key}` is deliberately NOT touched: the high-water mark
/// stays monotonic so post-prune sequence numbers can never collide with
/// surviving rows.
///
/// Surgically scoped (fail closed): a key outside this window's own
/// `u:w:{key}:` family is a typed error and nothing is deleted — the
/// prune must not be able to touch `q:`/`d:`/`h:`/`dt:` rows or another
/// window's updates.
pub(crate) fn prune_subsumed_window_updates_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &WindowKey,
    subsumed_update_keys: &[String],
) -> Result<()> {
    let prefix = format!("u:w:{key}:");
    for update_key in subsumed_update_keys {
        if !update_key.starts_with(&prefix) {
            return Err(Error::SyncProtocolError(format!(
                "u:w: prune scoped to {prefix}* refused foreign key {update_key}"
            )));
        }
    }
    for update_key in subsumed_update_keys {
        vault.store.sync_state.delete(wtxn, update_key)?;
    }
    Ok(())
}

/// Import-merges the persisted sync_state record for `key` — the
/// `d:w:{key}` snapshot plus every pending `u:w:{key}:*` update — into
/// `doc`, returning the `u:` row KEYS that were merged.
///
/// This is the ONE-1135 anti-clobber primitive: every exporter that writes
/// a full snapshot over `d:w:` merges the on-disk record first, so a doc
/// that has not seen ops a parallel writer persisted (a tombstone above
/// all) converges with them instead of overwriting them. Ops the doc
/// already has are VV-dominated no-ops on import.
///
/// Imports run AFTER the read transaction drops: an import into an
/// OBSERVED doc fires Observer B, which opens its own write transactions.
pub(crate) fn merge_persisted_state_into_doc(
    vault: &Vault,
    doc: &LoroDoc,
    key: &WindowKey,
) -> Result<Vec<String>> {
    let mut update_keys = Vec::new();
    let mut blobs: Vec<Vec<u8>> = Vec::new();
    {
        let rtxn = vault.store.env.read_txn()?;
        let doc_key = format!("d:w:{key}");
        if let Some(state) = vault.store.sync_state.get(&rtxn, &doc_key)? {
            blobs.push(state.to_vec());
        }
        let prefix = format!("u:w:{key}:");
        for entry in vault.store.sync_state.prefix_iter(&rtxn, &prefix)? {
            let (k, v) = entry?;
            update_keys.push(k.to_string());
            blobs.push(v.to_vec());
        }
    }
    for blob in &blobs {
        import_doc(doc, blob)?;
    }
    Ok(update_keys)
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
///
/// `pub` like its sibling startup steps ([`load_window_from_state`],
/// [`replay_pending_tombstones`], [`replay_pending_mirrors`],
/// [`reverse_rematerialize`], [`forward_rematerialize`]): the integration
/// harness' fresh-open path replays through this EXACT fn (ONE-1152) —
/// re-implementing the replay out-of-crate is precisely the
/// production-divergence class that ticket closes, and `#[cfg(test)]`
/// helpers are invisible to integration-test crates.
pub fn apply_pending_window_updates(vault: &Vault, doc: &LoroDoc, key: &WindowKey) -> Result<u32> {
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

/// A tombstone-commit delta authorized to be queued as DELETE-BEARING.
///
/// The `d:{seq:8BE}` sidecar marker exempts its `q:` row from every
/// unconfirmed clear and from the carrier-15 scrub — protections built for
/// tombstone deltas, not arbitrary payloads. The private field plus the
/// single constructor ([`export_tombstone_commit_delta`]) are the
/// type-system pin that delete-bearing = a real tombstone-commit delta:
/// nothing outside the tombstone-commit path can mark bytes delete-bearing
/// (ONE-1135 review item 14).
pub(crate) struct DeleteBearingUpdate(Vec<u8>);

impl DeleteBearingUpdate {
    /// The delta bytes stored in the `q:` row.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Test-only escape hatch so queue unit tests can exercise the `d:`
    /// row machinery with synthetic bytes. NOT part of the public API and
    /// compiled out of every non-test build.
    #[cfg(test)]
    pub(crate) fn for_test(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Exports the tombstone commit's delta as the [`DeleteBearingUpdate`]
/// queued for transmission — the ONLY constructor of that type.
///
/// Call IMMEDIATELY after [`apply_tombstone_to_window_doc`] + commit;
/// `vv_before` must be the doc's oplog version vector captured before the
/// tombstone was applied. Returns `None` when the commit was a no-op
/// (e.g. a blocked downgrade of an existing hard tombstone) — there is
/// nothing to queue.
pub(crate) fn export_tombstone_commit_delta(
    doc: &LoroDoc,
    vv_before: &loro::VersionVector,
) -> Result<Option<DeleteBearingUpdate>> {
    if doc.oplog_vv() == *vv_before {
        return Ok(None);
    }
    Ok(Some(DeleteBearingUpdate(export_updates_from(
        doc, vv_before,
    )?)))
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
///
/// ONE-1135 (delete-propagation transport, crash-recovery leg of the
/// delete path):
/// - The persisted state is import-MERGED into the doc first (clobber
///   guard) — the snapshot exported below can then never lose on-disk ops.
/// - The replay commit's delta is queued as a DELETE-BEARING `q:` row so
///   the recovered delete is delivered on next connect and survives the
///   optimistic clear until VV-confirmed.
/// - Any HARD marker triggers the carrier-15 scrub for this window
///   (ARCH-0038 #15): pre-existing `q:` rows dropped, merged `u:` rows
///   dropped post-snapshot, `fr:w:{key}` full-resync marker set.
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

    // Clobber guard + scrub inventory: merge the on-disk record into the
    // doc so the full snapshot below subsumes it, and remember which `u:`
    // rows it covered (only those may be scrubbed).
    let merged_update_keys = merge_persisted_state_into_doc(vault, doc, window_key)?;
    let any_hard = markers
        .iter()
        .any(|(_, _, value)| decode_tombstone_value(value).is_hard());

    let vv_before = doc.oplog_vv();
    for (_, id, value) in &markers {
        apply_tombstone_to_window_doc(doc, id, value)?;
    }
    // Bridge origin: local LMDB already reflects the delete (the marker was
    // written in the purge/scrub txn itself), so Observer B must not re-run
    // the hard purge against a soft shell.
    doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));

    // The replay commit's delta — tombstone values + key-delete ops, opaque
    // ids only — is the delete-bearing update queued for transmission.
    let delete_update = export_tombstone_commit_delta(doc, &vv_before)?;

    // Persist BEFORE clearing the markers — the marker may only be cleared
    // after CRDT commit + snapshot persistence succeed.
    let snapshot = export_snapshot(doc)?;
    let vv = doc_version_vector(doc);
    vault.with_write_txn(|wtxn| {
        persist_window_doc_in_txn(vault, wtxn, window_key, &snapshot, &vv)?;
        if any_hard {
            crate::sync::queue::scrub_window_updates_in_txn(vault, wtxn, window_key.as_str())?;
            for update_key in &merged_update_keys {
                vault.store.sync_state.delete(wtxn, update_key)?;
            }
            let fr_key = format!("fr:w:{window_key}");
            vault.store.sync_state.put(wtxn, &fr_key, &[1_u8])?;
        }
        if let Some(update) = &delete_update {
            crate::sync::queue::push_delete_bearing_in_txn(
                vault,
                wtxn,
                window_key.as_str(),
                update,
            )?;
        }
        for (marker_key, _, _) in &markers {
            vault.store.sync_state.delete(wtxn, marker_key)?;
        }
        // svf LAST (ONE-1151): the hard branch scrubbed the merged u:w:
        // rows above; the soft branch kept them. Either way freshness is
        // computed against the FINAL u:w: set — a surviving row forces
        // stale so the fast-reconnect reader never trusts a partial sv:w:.
        write_window_svf_in_txn(vault, wtxn, window_key)
    })?;

    Ok(u32::try_from(markers.len()).unwrap_or(u32::MAX))
}

/// Rebuilds a window Doc from pending update rows (`u:w:{key}:*`) alone,
/// for windows with NO persisted snapshot (`d:w:` row absent).
///
/// Used by the rm: drain path: a flagged window whose snapshot was never
/// persisted may still carry its tombstones in Observer A's durable update
/// rows — without this rebuild a hard-deleted entity would stay live
/// indefinitely behind the missing `d:w:` row. Fail closed: an empty
/// rebuild yields a doc with zero tombstones, and `forward_rematerialize`
/// keeps the rm: marker for such a doc.
pub fn rebuild_window_from_updates(
    vault: &Vault,
    user_id: &str,
    key: &WindowKey,
) -> Result<LoroDoc> {
    let doc = create_window_doc(user_id, key);
    let rtxn = vault.store.env.read_txn()?;
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
///
/// ONE-1124 silent-skip hygiene: every REMOTE-origin op rejected by a write
/// gate persists a quarantine record (`x:` family) — never a bare skip;
/// the engine's own LMDB read errors propagate as typed errors (fail
/// closed, never quarantine-and-continue); and a tombstone-purge failure
/// flags `rm:w:{window}:{entity_hex}` for durable retry (each marker
/// cleared only when that entity's own purge succeeds).
///
/// ONE-1147: Observer B's entity/edge batch swallow sites flag the same
/// entity-scoped markers on whole-txn failure. This pass discharges such a
/// marker ONLY when it performs the actual healing write for that entity
/// (entity body put, or an edge write whose SOURCE is the marked entity).
/// Byte-parity alone never discharges: a failed GDPR purge also leaves
/// byte-identical state, and a parity-clear would vacuously drop a pending
/// hard-delete retry (fail closed).
///
/// ONE-1157/1158: the entity/edge passes visit EVERY map key: non-Binary
/// values quarantine as protocol violations (ONE-1157, Observer-B parity),
/// and a non-canonical (case-shifted) entities-map alias key quarantines
/// instead of materializing (ONE-1158).
pub fn forward_rematerialize(
    vault: &Vault,
    doc: &LoroDoc,
    materializer: &Materializer,
    window_key: &WindowKey,
) -> Result<u32> {
    let _guard = materializer.lock();
    let entities_map = doc.get_map("entities");
    let edges_map = doc.get_map("edges");
    let tombstones_map = doc.get_map("tombstones");

    // Entity-scoped retry markers pending for this window, loaded up front:
    // the entity/edge passes discharge a marker only via an actual healing
    // write (ONE-1147); the tombstone pass only via that entity's own
    // replay success (ONE-1124). Malformed marker rows never match a
    // canonical `to_hex()` and so are never discharged here (fail closed).
    let marked: HashSet<String> = quarantine::pending_remat_entities(vault, window_key.as_str())?
        .into_iter()
        .collect();
    let mut healed: Vec<EntityId> = Vec::new();

    let mut count = 0u32;

    // Entities
    {
        let rtxn = vault.store.env.read_txn()?;
        let mut materialized_blobs = HashMap::<EntityId, Vec<u8>>::new();
        let mut entity_error = None;
        map_for_each_value_bytes(&entities_map, |key, blob| {
            if entity_error.is_some() {
                return;
            }

            // ONE-1157: non-Binary value where an entity blob belongs — an
            // undecodable remote op, quarantined exactly like Observer B's
            // non-Binary arm (empty payload: a non-Binary value carries no
            // bytes), never an invisible skip.
            let Some(blob) = blob else {
                if let Err(err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Entities,
                    key,
                    &Error::InvalidKey,
                    &[],
                ) {
                    entity_error = Some(err);
                }
                return;
            };

            let id = match EntityId::from_hex(key) {
                Ok(id) => id,
                Err(_) => {
                    if let Err(err) = quarantine::quarantine_rejected_op(
                        vault,
                        window_key.as_str(),
                        QuarantineContainer::Entities,
                        key,
                        &Error::InvalidKey,
                        blob,
                    ) {
                        entity_error = Some(err);
                    }
                    return;
                }
            };

            // ONE-1158 (Observer-B parity): a non-canonical (case-shifted)
            // hex alias key is a protocol violation — no engine version
            // ever emits one (`to_hex()` is lowercase). Quarantine instead
            // of materializing: an alias key never enters LMDB
            // materialization (fail closed at the door).
            if key != id.to_hex() {
                if let Err(err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Entities,
                    key,
                    &Error::InvalidKey,
                    blob,
                ) {
                    entity_error = Some(err);
                }
                return;
            }

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

            // Track whether a local record exists for this id: byte-identical
            // → idempotent skip (return); present-but-different falls through
            // with `locally_present = true` so the REDACTION_AUDIT
            // immutability gate below can quarantine the divergence.
            let locally_present = if let Some(latest) = materialized_blobs.get(&id) {
                if latest.as_slice() == blob {
                    return;
                }
                true
            } else {
                let lmdb_blob = match vault.get_raw_in(&rtxn, &id) {
                    Ok(v) => v,
                    Err(err) => {
                        entity_error = Some(err);
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
                lmdb_blob.is_some()
            };

            let header = match EntityMetadataHeader::parse(blob) {
                Some(h) => h,
                None => {
                    if let Err(err) = quarantine::quarantine_rejected_op(
                        vault,
                        window_key.as_str(),
                        QuarantineContainer::Entities,
                        key,
                        &Error::CorruptedIndex("entity metadata"),
                        blob,
                    ) {
                        entity_error = Some(err);
                    }
                    return;
                }
            };
            let data = if blob.len() > ENTITY_METADATA_HEADER_LEN {
                &blob[ENTITY_METADATA_HEADER_LEN..]
            } else {
                &[]
            };
            // ONE-1134: REDACTION_AUDIT (type 120) replay door #2. Receipts
            // are immutable audit records (contracts.ts
            // `redactionAuditReceipt`; ARCH-0023b audit/guardrail class:
            // quarantine divergence, never silent LWW):
            // * a blob failing the pinned receipt-body validation is
            //   quarantined, never written;
            // * id present locally with divergent bytes (byte-identical
            //   already returned above) → quarantine the remote payload and
            //   KEEP the local bytes;
            // * id absent → accept-new (falls through to `put_replicated`).
            if header.entity_type == crate::types::ENTITY_TYPE_REDACTION_AUDIT {
                if let Err(err) = crate::deletion::validate_redaction_receipt_body(data) {
                    if let Err(q_err) = quarantine::quarantine_rejected_op(
                        vault,
                        window_key.as_str(),
                        QuarantineContainer::Entities,
                        key,
                        &err,
                        blob,
                    ) {
                        entity_error = Some(q_err);
                    }
                    return;
                }
                if locally_present {
                    if let Err(q_err) = quarantine::quarantine_rejected_op(
                        vault,
                        window_key.as_str(),
                        QuarantineContainer::Entities,
                        key,
                        &Error::RedactionReceiptDivergence { id },
                        blob,
                    ) {
                        entity_error = Some(q_err);
                    }
                    return;
                }
            }
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
                    // ONE-1147: an ACTUAL healing write discharges this
                    // entity's needs-remat marker (set by a failed
                    // Observer-B batch). Byte-identical skips above never
                    // reach here — parity alone must not discharge.
                    if marked.contains(&id.to_hex()) {
                        healed.push(id);
                    }
                }
                Err(err) => {
                    if quarantine::remote_rejection_reason(&err).is_some() {
                        if let Err(q_err) = quarantine::quarantine_rejected_op(
                            vault,
                            window_key.as_str(),
                            QuarantineContainer::Entities,
                            key,
                            &err,
                            blob,
                        ) {
                            entity_error = Some(q_err);
                        }
                    } else {
                        // LOCAL failure — fail closed.
                        entity_error = Some(err);
                    }
                }
            }
        });
        if let Some(err) = entity_error {
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
        map_for_each_value_bytes(&edges_map, |key, buf| {
            if edge_error.is_some() {
                return;
            }
            // ONE-1157 (edge-pass parity, same gap as the entity pass):
            // non-Binary value where an edge value belongs — quarantined
            // like Observer B's non-Binary edge arm, never an invisible
            // skip.
            let Some(buf) = buf else {
                if let Err(err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Edges,
                    key,
                    &Error::InvalidKey,
                    &[],
                ) {
                    edge_error = Some(err);
                }
                return;
            };
            let Some((src, kind, tgt)) = bridge::parse_edge_key(key) else {
                if let Err(err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Edges,
                    key,
                    &Error::InvalidKey,
                    buf,
                ) {
                    edge_error = Some(err);
                }
                return;
            };

            // Decode BEFORE the tombstone/endpoint gates (mirrors Observer
            // B's ordering in bridge.rs): a malformed value is a remote
            // rejection regardless of endpoint state, and decode has no side
            // effects. Checking endpoints first would silently defer a
            // valid-key malformed edge whose endpoint is absent — no x: row.
            let decoded = match decode_edge_value_for_kind(kind, buf) {
                Ok(decoded) => decoded,
                Err(err) => {
                    if let Err(q_err) = quarantine::quarantine_rejected_op(
                        vault,
                        window_key.as_str(),
                        QuarantineContainer::Edges,
                        key,
                        &err,
                        buf,
                    ) {
                        edge_error = Some(q_err);
                    }
                    return;
                }
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
                // Deferral, not a rejection: cross-window endpoints
                // arrive later; the edge stays in the CRDT and
                // re-materializes when its endpoints do.
                tracing::debug!(
                    edge = %key,
                    "forward remat: edge deferred — endpoint absent"
                );
                return;
            }

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
                Ok(()) => {
                    count += 1;
                    // ONE-1147: a healing edge write discharges the SOURCE
                    // entity's needs-remat marker (Observer B's edge batch
                    // swallow site marks lost upserts by source id).
                    if marked.contains(&src.to_hex()) {
                        healed.push(src);
                    }
                }
                Err(err) => {
                    if quarantine::remote_rejection_reason(&err).is_some() {
                        if let Err(q_err) = quarantine::quarantine_rejected_op(
                            vault,
                            window_key.as_str(),
                            QuarantineContainer::Edges,
                            key,
                            &err,
                            buf,
                        ) {
                            edge_error = Some(q_err);
                        }
                    } else {
                        // LOCAL failure — fail closed.
                        edge_error = Some(err);
                    }
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
    //
    // Retry state is ENTITY-scoped (ONE-1124): `rm:w:{window}:{entity_hex}`
    // is written for the specific entity whose replay failed, and cleared
    // ONLY when that entity's own replay succeeds — an unrelated
    // tombstone's success must never discharge another entity's retry.
    // (`marked` is the up-front snapshot loaded before the entity pass.)
    let mut purge_failures: Vec<EntityId> = Vec::new();
    let mut cleared: Vec<EntityId> = Vec::new();
    let mut tombstone_error: Option<Error> = None;
    map_for_each_tombstone_value(&tombstones_map, |key, value| {
        if tombstone_error.is_some() {
            return;
        }
        let id = match EntityId::from_hex(key) {
            Ok(id) => id,
            Err(_) => {
                if let Err(err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Tombstones,
                    key,
                    &Error::InvalidKey,
                    value,
                ) {
                    tombstone_error = Some(err);
                }
                return;
            }
        };

        match quarantine::apply_replayed_tombstone_for_sync(vault, &id, value) {
            Ok(outcome) => {
                if outcome.changed_local_state() {
                    count += 1;
                }
                // The goal state for THIS tombstone's reason holds (purge
                // done, already absent, or soft shell kept) — the entity's
                // own retry marker (if flagged) is discharged.
                if marked.contains(&id.to_hex()) {
                    cleared.push(id);
                }
            }
            Err(err) => {
                // Replay failure — the tombstoned content may still be
                // live. Flag THIS entity for durable retry; the pass keeps
                // going so one failure cannot starve other tombstones.
                purge_failures.push(id);
                tracing::error!(
                    entity = %id.to_hex(),
                    error = %err,
                    "forward remat: tombstone replay FAILED — hard-deleted content may still be live (GDPR SLA breach signal)"
                );
            }
        }
    });

    if !purge_failures.is_empty() || !cleared.is_empty() || !healed.is_empty() {
        vault.with_write_txn(|wtxn| {
            // Clear BEFORE set so set wins: an id that both succeeded and
            // failed in one pass (case-shifted tombstone aliases with
            // divergent reasons) must KEEP its marker — losing it would
            // silently drop a pending hard purge (fail closed). The
            // ONE-1147 `healed` discharges (entity/edge healing writes,
            // structurally disjoint from tombstoned ids — both passes are
            // tombstone-gated) clear under the same ordering.
            for id in healed.iter().chain(cleared.iter()) {
                quarantine::clear_remat_marker_in_txn(vault, wtxn, window_key.as_str(), id)?;
            }
            for id in &purge_failures {
                quarantine::set_remat_marker_in_txn(vault, wtxn, window_key.as_str(), id)?;
            }
            Ok(())
        })?;
    }
    if let Some(err) = tombstone_error {
        return Err(err);
    }
    if quarantine::pending_remat_windows(vault)?
        .iter()
        .any(|window| window == window_key.as_str())
    {
        // Markers survive the pass when a purge failed above, when a
        // flagged entity's tombstone is missing from the loaded doc (stale
        // window state), or when a marker row no longer parses. Clearing
        // any of them here would vacuously discharge a GDPR retry — keep
        // them (fail closed) and keep ERROR-grade visibility.
        tracing::error!(
            window = %window_key,
            "forward remat: rm: markers still pending after tombstone pass — hard-deleted content may be live (GDPR SLA breach signal)"
        );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::VaultConfig;

    fn test_vault() -> (tempfile::TempDir, Arc<Vault>) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
        (dir, vault)
    }

    /// Pinned 25-byte entity envelope: type u8 + occurred_start/end u64 BE +
    /// learned_at u64 BE + body (`occurred == learned` so CRDT-vs-LMDB
    /// byte-equality is exact).
    fn make_entity_blob(entity_type: u8, learned_at: u64, data: &[u8]) -> Vec<u8> {
        let mut blob = Vec::with_capacity(25 + data.len());
        blob.push(entity_type);
        blob.extend_from_slice(&learned_at.to_be_bytes());
        blob.extend_from_slice(&learned_at.to_be_bytes());
        blob.extend_from_slice(&learned_at.to_be_bytes());
        blob.extend_from_slice(data);
        blob
    }

    fn commit_entity(window: &LoadedWindow, learned_at: u64, data: &[u8]) -> EntityId {
        let id = EntityId::now();
        map_insert_bytes(
            &window.doc.get_map("entities"),
            &id.to_hex(),
            &make_entity_blob(1, learned_at, data),
        )
        .unwrap();
        window.doc.commit();
        id
    }

    /// ONE-1151 prune: `persist_state` deletes exactly the `u:w:{key}:*`
    /// rows its snapshot subsumed — in the same transaction as the `d:w:`
    /// write — while `m:u_seq:w:{key}` keeps its high-water mark
    /// (ARCH-0023b: monotonic, missing=0) and every other row family
    /// survives byte-identical: the neighbor window's `u:w:` rows, a
    /// prefix-adjacent `u:w:` key (exact `u:w:{key}:` scope, not a sloppy
    /// substring match), the `dt:` local hard-delete marker (sync_state),
    /// and the `q:`/`d:`/`h:` sync_queue families a delete-bearing path
    /// owns. The window must then reopen from `d:w:` ALONE.
    #[test]
    fn persist_state_prunes_subsumed_rows_and_spares_other_families() {
        let (_dir, vault) = test_vault();
        let materializer = Arc::new(Materializer::new());
        let key = WindowKey::new("2026-03");
        let t = key.start_timestamp().unwrap() + 60;

        let window = LoadedWindow::new("local", key.clone(), &vault, &materializer);
        let id_a = commit_entity(&window, t, b"prune-a");
        let id_b = commit_entity(&window, t, b"prune-b");

        // Observer A persisted the contract rows (ARCH-0023b key table).
        assert!(
            vault
                .sync_state_get("u:w:2026-03:00000001")
                .unwrap()
                .is_some()
        );
        assert!(
            vault
                .sync_state_get("u:w:2026-03:00000002")
                .unwrap()
                .is_some()
        );
        assert_eq!(
            vault
                .sync_state_get("m:u_seq:w:2026-03")
                .unwrap()
                .as_deref(),
            Some(2u32.to_le_bytes().as_slice())
        );

        // Sentinels the prune must NOT touch. sync_state families:
        vault
            .sync_state_put("u:w:2026-02:00000001", b"neighbor-window-update")
            .unwrap();
        vault
            .sync_state_put("u:w:2026-030:00000001", b"prefix-adjacent-update")
            .unwrap();
        let dt_key = format!("dt:{}", EntityId::now().to_hex());
        vault.sync_state_put(&dt_key, &[2u8; 26]).unwrap();
        // sync_queue families (`q:{seq:8BE}` update row, `d:{seq:8BE}`
        // delete-bearing sidecar, `h:{seq:8BE}` hard-erase sweep job):
        let q_key = [b'q', b':', 0, 0, 0, 0, 0, 0, 0, 1];
        let d_key = [b'd', b':', 0, 0, 0, 0, 0, 0, 0, 1];
        let h_key = [b'h', b':', 0, 0, 0, 0, 0, 0, 0, 1];
        {
            let mut wtxn = vault.store.env.write_txn().unwrap();
            vault
                .store
                .sync_queue
                .put(&mut wtxn, &q_key, &[1u8])
                .unwrap();
            vault
                .store
                .sync_queue
                .put(&mut wtxn, &d_key, &[1u8])
                .unwrap();
            vault
                .store
                .sync_queue
                .put(&mut wtxn, &h_key, &[7u8])
                .unwrap();
            wtxn.commit().unwrap();
        }

        window.persist_state(&vault).unwrap();

        // Subsumed rows pruned; the high-water mark is NOT reset.
        assert!(
            vault
                .sync_state_get("u:w:2026-03:00000001")
                .unwrap()
                .is_none(),
            "subsumed u:w: row must be pruned after the snapshot persist"
        );
        assert!(
            vault
                .sync_state_get("u:w:2026-03:00000002")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            vault
                .sync_state_get("m:u_seq:w:2026-03")
                .unwrap()
                .as_deref(),
            Some(2u32.to_le_bytes().as_slice()),
            "m:u_seq:w: must stay monotonic — never reset by the prune"
        );
        assert!(vault.sync_state_get("d:w:2026-03").unwrap().is_some());
        // Positive control for the ONE-1151 svf recompute: with every u:w:
        // row subsumed and pruned, the post-prune probe finds zero rows, so
        // freshness is written FRESH ([1]) — proving the fix is not a blanket
        // svf=0 (see persist_state_marks_svf_stale_when_a_post_merge_uw_row_survives
        // for the surviving-row counterpart).
        assert_eq!(
            vault.sync_state_get("svf:w:2026-03").unwrap().as_deref(),
            Some([1u8].as_slice()),
            "all rows subsumed → svf recomputes FRESH"
        );

        // Every sentinel survives byte-identical.
        assert_eq!(
            vault
                .sync_state_get("u:w:2026-02:00000001")
                .unwrap()
                .as_deref(),
            Some(b"neighbor-window-update".as_slice()),
            "the neighbor window's u:w: rows are out of scope"
        );
        assert_eq!(
            vault
                .sync_state_get("u:w:2026-030:00000001")
                .unwrap()
                .as_deref(),
            Some(b"prefix-adjacent-update".as_slice()),
            "prune scope is exactly `u:w:{{key}}:` — never a substring match"
        );
        assert_eq!(
            vault.sync_state_get(&dt_key).unwrap().as_deref(),
            Some([2u8; 26].as_slice()),
            "dt: local hard-delete markers are out of scope (delete safety)"
        );
        {
            let rtxn = vault.store.env.read_txn().unwrap();
            assert_eq!(
                vault.store.sync_queue.get(&rtxn, &q_key).unwrap(),
                Some([1u8].as_slice()),
                "q: update rows are out of scope"
            );
            assert_eq!(
                vault.store.sync_queue.get(&rtxn, &d_key).unwrap(),
                Some([1u8].as_slice()),
                "d: delete-bearing sidecars are out of scope (delete safety)"
            );
            assert_eq!(
                vault.store.sync_queue.get(&rtxn, &h_key).unwrap(),
                Some([7u8].as_slice()),
                "h: hard-erase sweep rows are out of scope (delete safety)"
            );
        }

        // The window reopens from d:w: ALONE (no u:w: rows left to replay).
        drop(window);
        assert_eq!(
            vault
                .sync_state_keys_with_prefix("u:w:2026-03:")
                .unwrap()
                .len(),
            0
        );
        let reloaded = load_window_from_state(&vault, "local", &key).unwrap();
        let entities = reloaded.get_map("entities");
        assert_eq!(
            map_get_bytes(&entities, &id_a.to_hex()).as_deref(),
            Some(make_entity_blob(1, t, b"prune-a").as_slice()),
            "pruned ops must reload from the d:w: snapshot"
        );
        assert!(map_get_bytes(&entities, &id_b.to_hex()).is_some());
    }

    /// ONE-1151 concurrency seam: a `u:w:` row persisted AFTER the merge
    /// captured its subsumption inventory (a transient delete-path doc
    /// persisting in parallel — its ops are in neither the merged set nor
    /// the exported snapshot) gets a higher seq, is absent from the merged
    /// key list, and MUST survive the prune; recovery still replays it.
    #[test]
    fn prune_spares_updates_persisted_after_the_merge() {
        let (_dir, vault) = test_vault();
        let materializer = Arc::new(Materializer::new());
        let key = WindowKey::new("2026-03");
        let t = key.start_timestamp().unwrap() + 60;

        let window = LoadedWindow::new("local", key.clone(), &vault, &materializer);
        commit_entity(&window, t, b"merged-op");

        // Snapshot-persist sequence as persist_state runs it, with a
        // concurrent writer landing BETWEEN the merge and the write txn.
        let merged = merge_persisted_state_into_doc(&vault, &window.doc, &key).unwrap();
        assert_eq!(merged, vec!["u:w:2026-03:00000001".to_string()]);

        let transient = create_window_doc("transient", &key);
        let late_id = EntityId::now();
        map_insert_bytes(
            &transient.get_map("entities"),
            &late_id.to_hex(),
            &make_entity_blob(1, t, b"late-op"),
        )
        .unwrap();
        transient.commit();
        let late_bytes = export_updates_from(&transient, &loro::VersionVector::default()).unwrap();
        bridge::persist_window_update(&vault, "2026-03", &late_bytes).unwrap();

        let state = export_snapshot(&window.doc).unwrap();
        let vv = doc_version_vector(&window.doc);
        vault
            .with_write_txn(|wtxn| {
                persist_window_doc_in_txn(&vault, wtxn, &key, &state, &vv)?;
                prune_subsumed_window_updates_in_txn(&vault, wtxn, &key, &merged)
            })
            .unwrap();

        assert!(
            vault
                .sync_state_get("u:w:2026-03:00000001")
                .unwrap()
                .is_none(),
            "the merged row is subsumed and pruned"
        );
        assert_eq!(
            vault
                .sync_state_get("u:w:2026-03:00000002")
                .unwrap()
                .as_deref(),
            Some(late_bytes.as_slice()),
            "a row persisted after the merge is NOT in the snapshot and must survive"
        );

        // Recovery = d:w: + surviving u:w: replay — the late op is intact.
        let recovered = load_window_from_state(&vault, "local", &key).unwrap();
        assert!(
            map_get_bytes(&recovered.get_map("entities"), &late_id.to_hex()).is_some(),
            "recovery must replay the surviving post-merge row"
        );
    }

    /// ONE-1151 svf-freshness fix: the prune_spares scenario driven through
    /// the production `persist_state` path. A post-merge `u:w:` row lands
    /// DURING the merge import (a one-shot subscription standing in for the
    /// transient delete-path writer that persists in parallel), so it is
    /// absent from the prune's subsumed-key inventory and survives. Because a
    /// pending `u:w:` row then sits on top of `sv:w:`, `svf:w:` MUST be
    /// written STALE (`[0]`) — a plausible-wrong impl that keeps the old
    /// unconditional `svf=1` fails on the literal `[0]`.
    #[test]
    fn persist_state_marks_svf_stale_when_a_post_merge_uw_row_survives() {
        use loro::ContainerTrait;
        use std::sync::atomic::{AtomicBool, Ordering};

        let (_dir, vault) = test_vault();
        let materializer = Arc::new(Materializer::new());
        let key = WindowKey::new("2026-03");
        let t = key.start_timestamp().unwrap() + 60;

        let window = LoadedWindow::new("local", key.clone(), &vault, &materializer);

        // Pre-seed `u:w:2026-03:00000001` with an op the LIVE doc does NOT
        // hold, so `persist_state`'s merge import produces a diff (and fires
        // the injection below). This row IS in the merge inventory → pruned.
        let seed = create_window_doc("seed", &key);
        let seed_id = EntityId::now();
        map_insert_bytes(
            &seed.get_map("entities"),
            &seed_id.to_hex(),
            &make_entity_blob(1, t, b"seed-op"),
        )
        .unwrap();
        seed.commit();
        let seed_bytes = export_updates_from(&seed, &loro::VersionVector::default()).unwrap();
        bridge::persist_window_update(&vault, "2026-03", &seed_bytes).unwrap();

        // The survivor op (transient parallel writer): not in the merge
        // inventory, not in the exported snapshot.
        let late = create_window_doc("late", &key);
        let late_id = EntityId::now();
        map_insert_bytes(
            &late.get_map("entities"),
            &late_id.to_hex(),
            &make_entity_blob(1, t, b"late-op"),
        )
        .unwrap();
        late.commit();
        let late_bytes = export_updates_from(&late, &loro::VersionVector::default()).unwrap();

        // Inject the survivor row DURING the merge import (after the prune's
        // inventory was captured, before the write txn) — exactly the seam
        // prune_spares models manually, now exercised through persist_state.
        let injected = Arc::new(AtomicBool::new(false));
        let cb_vault = Arc::clone(&vault);
        let cb_bytes = late_bytes;
        let cb_flag = Arc::clone(&injected);
        let entities_cid = window.doc.get_map("entities").id();
        let _inj = window.doc.subscribe(
            &entities_cid,
            Arc::new(move |_event| {
                if cb_flag.swap(true, Ordering::SeqCst) {
                    return;
                }
                bridge::persist_window_update(&cb_vault, "2026-03", &cb_bytes)
                    .expect("inject post-merge survivor row");
            }),
        );

        window.persist_state(&vault).unwrap();
        assert!(injected.load(Ordering::SeqCst), "injection must have fired");

        // The merged row is pruned …
        assert!(
            vault
                .sync_state_get("u:w:2026-03:00000001")
                .unwrap()
                .is_none(),
            "the merged row is subsumed and pruned"
        );
        // … the post-merge row survives …
        assert!(
            vault
                .sync_state_get("u:w:2026-03:00000002")
                .unwrap()
                .is_some(),
            "a row persisted during the merge import escapes the prune"
        );
        // … the high-water mark stays monotonic …
        assert_eq!(
            vault
                .sync_state_get("m:u_seq:w:2026-03")
                .unwrap()
                .as_deref(),
            Some(2u32.to_le_bytes().as_slice()),
            "m:u_seq:w: must stay monotonic"
        );
        // … and svf is STALE: the fast-reconnect reader must NOT trust sv:w:.
        assert_eq!(
            vault.sync_state_get("svf:w:2026-03").unwrap().as_deref(),
            Some([0u8].as_slice()),
            "a surviving post-merge u:w: row forces svf STALE ([0])"
        );
    }

    /// ONE-1151 scope extension: the soft-only `pt:` replay branch keeps the
    /// merged `u:w:` rows (only the hard branch scrubs them), so after a soft
    /// replay a pending row still sits on top of `sv:w:` — `svf:w:` MUST be
    /// written STALE. A wrong impl that writes `svf=1` in the soft branch
    /// fails. (Delete-safety-adjacent.)
    #[test]
    fn replay_pending_tombstones_soft_keeps_svf_stale_when_merged_uw_survives() {
        let (_dir, vault) = test_vault();
        let materializer = Arc::new(Materializer::new());
        let key = WindowKey::new("2026-03");
        let t = key.start_timestamp().unwrap() + 60;

        // A live window with one committed entity → Observer A persists a
        // `u:w:` row the SOFT branch must NOT scrub.
        let window = LoadedWindow::new("local", key.clone(), &vault, &materializer);
        let _id = commit_entity(&window, t, b"keep-me");
        assert!(
            vault
                .sync_state_get("u:w:2026-03:00000001")
                .unwrap()
                .is_some()
        );

        // A SOFT pending-tombstone marker (user_delete, wire byte 1 = soft).
        let victim = EntityId::now();
        let mut soft = vec![1_u8]; // user_delete (soft)
        soft.extend_from_slice(&t.to_le_bytes());
        soft.extend_from_slice(&[0x11; 16]);
        let marker_key = format!("pt:2026-03:{}", victim.to_hex());
        vault.sync_state_put(&marker_key, &soft).unwrap();

        let replayed = replay_pending_tombstones(&vault, &window.doc, &key).unwrap();
        assert_eq!(replayed, 1);

        // The merged u:w: row survives the soft branch …
        assert!(
            vault
                .sync_state_get("u:w:2026-03:00000001")
                .unwrap()
                .is_some(),
            "soft replay must not scrub surviving u:w: rows"
        );
        // … so svf is STALE.
        assert_eq!(
            vault.sync_state_get("svf:w:2026-03").unwrap().as_deref(),
            Some([0u8].as_slice()),
            "a surviving u:w: row after a soft replay forces svf STALE"
        );
        // fr:w: full-resync is a HARD-only concern — untouched by soft replay.
        assert!(vault.sync_state_get("fr:w:2026-03").unwrap().is_none());
    }

    /// Fail-closed scope guard: a key outside the window's own
    /// `u:w:{key}:` family is a TYPED error and the transaction deletes
    /// nothing — not even the in-scope keys validated alongside it.
    #[test]
    fn prune_refuses_keys_outside_the_window_family() {
        let (_dir, vault) = test_vault();
        let key = WindowKey::new("2026-03");
        vault
            .sync_state_put("u:w:2026-03:00000001", b"in-scope")
            .unwrap();
        vault
            .sync_state_put("u:w:2026-02:00000001", b"foreign")
            .unwrap();

        let keys = vec![
            "u:w:2026-03:00000001".to_string(),
            "u:w:2026-02:00000001".to_string(),
        ];
        let err = vault
            .with_write_txn(|wtxn| prune_subsumed_window_updates_in_txn(&vault, wtxn, &key, &keys))
            .expect_err("a foreign key must fail the prune closed");
        assert!(
            matches!(err, Error::SyncProtocolError(_)),
            "typed error, got: {err:?}"
        );
        assert_eq!(
            vault
                .sync_state_get("u:w:2026-03:00000001")
                .unwrap()
                .as_deref(),
            Some(b"in-scope".as_slice()),
            "validate-before-delete: the aborted txn must delete nothing"
        );
        assert_eq!(
            vault
                .sync_state_get("u:w:2026-02:00000001")
                .unwrap()
                .as_deref(),
            Some(b"foreign".as_slice())
        );
    }

    /// The single constructor of [`DeleteBearingUpdate`] (ONE-1135 review
    /// item 14): a no-op tombstone commit exports nothing (no q:/d: rows
    /// queued); a real tombstone commit exports a non-empty delta.
    #[test]
    fn export_tombstone_commit_delta_none_on_noop_some_on_commit() {
        let doc = create_window_doc("local", &WindowKey::from_timestamp(1_750_000_000_000));
        let vv_before = doc.oplog_vv();
        assert!(
            export_tombstone_commit_delta(&doc, &vv_before)
                .unwrap()
                .is_none(),
            "unchanged doc must export no delete-bearing update"
        );

        let id = EntityId::now();
        apply_tombstone_to_window_doc(&doc, &id, &[1, 2, 3]).unwrap();
        doc.commit();
        let delta = export_tombstone_commit_delta(&doc, &vv_before)
            .unwrap()
            .expect("tombstone commit must export a delete-bearing update");
        assert!(!delta.as_bytes().is_empty());
    }
}
