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
    map_contains_binary, map_contains_key, map_delete, map_for_each_bytes,
    map_for_each_tombstone_value, map_for_each_value_bytes, map_get_bytes, map_insert_bytes,
    tombstone_map_contains_id, tombstone_values_for_id,
};
use super::quarantine::{self, QuarantineContainer};
use super::queue::scrub_receiver_outbox_on_remote_hard_delete_in_txn;
use super::quota;
use super::schema::create_window_doc;
use super::types::WindowKey;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EdgeValueFields, EntityMetadataHeader};
use crate::companion::{
    CompanionExportClassification, ENTITY_TYPE_COMPANION_REGISTER, decode_companion_record_body,
};
use crate::deletion::{PENDING_TOMBSTONE_PREFIX, decode_tombstone_value};
use crate::edge::decode_edge_value_for_kind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncProtocolPruneScope, SyncProtocolValidation};
use crate::registry::{ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_POLICY_MANIFEST};
use crate::store::Store;
use loro::{CommitOptions, ExportMode, LoroDoc, LoroMap, Subscription, VersionVector};

const HISTORY_FREE_WINDOW_PREFIX: &str = "hfs:w:";

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

        // A fence may be added after this doc acquired the entity (or one of
        // its incident edges). Persistence is itself an outbound carrier:
        // the snapshot is later used for VV/delta sync, so scrub immediately
        // before computing either the snapshot or its state vector.
        let scrubbed = scrub_off_record_fenced_carriers(vault, &self.key, &self.doc)?;
        let history_free = scrubbed || history_free_window_required(vault, &self.key)?;

        // Once a fenced carrier has existed in this window, a normal Loro
        // snapshot would retain its pre-delete op bytes. Persist a shallow
        // snapshot at the latest frontier instead: identical live state and
        // VV, but no historical body carrier.
        let state = if history_free {
            export_history_free_window_snapshot(&self.doc)?
        } else {
            export_snapshot(&self.doc)?
        };
        let vv = doc_version_vector(&self.doc);

        vault.with_write_txn(|wtxn| {
            persist_window_doc_in_txn(vault, wtxn, &self.key, &state, &vv)?;
            if history_free {
                vault.store.sync_state.put(
                    wtxn,
                    &format!("{HISTORY_FREE_WINDOW_PREFIX}{}", self.key),
                    &[1u8],
                )?;
            }
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
            return Err(Error::sync_protocol(SyncProtocolValidation::ScopedPrune {
                scope: SyncProtocolPruneScope::WindowUpdateRows,
                prefix,
                key: update_key.clone(),
            }));
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
    let doc = doc_from_snapshot(&state)?;
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
        import_doc(doc, &v)?;
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
    let snapshot = export_scrubbed_window_snapshot(vault, window_key, doc)?;
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
        import_doc(&doc, &v)?;
    }
    Ok(doc)
}

/// Captures the fenced subset of `ids` under one LMDB read snapshot.
///
/// Window packing calls this for an entity's edge targets so fence checks do
/// not open one read transaction per edge on large graphs.
fn off_record_fenced_ids(
    vault: &Vault,
    ids: impl IntoIterator<Item = EntityId>,
) -> Result<HashSet<EntityId>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut fenced = HashSet::new();
    for id in ids {
        if crate::off_record::off_record_fence_active(&vault.store, &rtxn, &id)? {
            fenced.insert(id);
        }
    }
    Ok(fenced)
}

/// Removes every currently fenced off-record carrier from a window doc and
/// returns whether the window must use history-free persistence/transport.
///
/// This is the export-boundary backstop for a fence that was established
/// after a body or incident edge had already entered the CRDT. Candidate ids
/// come from both entity keys and edge endpoints, so an edge to a fenced
/// cross-window target is scrubbed even when that target has no body in this
/// window. A single LMDB read snapshot decides the entire candidate set.
pub fn scrub_off_record_fenced_carriers(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
) -> Result<bool> {
    let entities_map = doc.get_map("entities");
    let edges_map = doc.get_map("edges");
    let mut candidates = HashSet::new();

    map_for_each_value_bytes(&entities_map, |key, _| {
        if let Ok(id) = EntityId::from_hex(key) {
            candidates.insert(id);
        }
    });
    map_for_each_value_bytes(&edges_map, |key, _| {
        if let Some((source, _, target)) = bridge::parse_edge_key(key) {
            candidates.insert(source);
            candidates.insert(target);
        }
    });

    let fenced = off_record_fenced_ids(vault, candidates)?;
    let fences_present = {
        let rtxn = vault.store.env.read_txn()?;
        crate::off_record::off_record_fences_present(&vault.store, &rtxn)?
    };
    let mut removed = false;
    for id in &fenced {
        removed |= scrub_fenced_entity_crdt_carriers(&entities_map, &edges_map, id)?;
    }
    if removed {
        // Bridge origin prevents Observer B from trying to materialize this
        // local privacy scrub back into LMDB; Observer A still durably queues
        // and broadcasts the deletion update to retire any older carrier.
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    if removed || fences_present {
        // Deleting a live value does not erase its prior set operation from
        // ordinary Loro history. An inbound set-then-delete can also carry a
        // fenced body without leaving a live value for the scan above. Pin
        // every window boundary while any fence exists so neither shape can
        // later take a raw delta/snapshot path.
        require_history_free_window(vault, key)?;
    }
    Ok(removed || fences_present)
}

/// Whether this window has ever carried bytes for a currently fenced turn.
/// The marker is durable because a scrubbed live doc still retains the old
/// set operation in its ordinary Loro history until shallow-compacted.
pub fn history_free_window_required(vault: &Vault, key: &WindowKey) -> Result<bool> {
    Ok(vault
        .sync_state_get(&format!("{HISTORY_FREE_WINDOW_PREFIX}{key}"))?
        .is_some())
}

/// Durably pins this window to history-free snapshot transport/persistence.
pub fn require_history_free_window(vault: &Vault, key: &WindowKey) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .sync_state
            .put(wtxn, &format!("{HISTORY_FREE_WINDOW_PREFIX}{key}"), &[1u8])?;
        Ok(())
    })
}

/// Exports a full-window response without carrying pre-scrub operation bytes.
/// The peer VV is still decoded first so malformed-VV requests never become a
/// full-export fallback.
pub fn export_window_updates_since(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
    remote_vv: &[u8],
) -> Result<Vec<u8>> {
    VersionVector::decode(remote_vv).map_err(|source| Error::CrdtDecodeError {
        context: "decode version vector",
        source,
    })?;
    let scrubbed = scrub_off_record_fenced_carriers(vault, key, doc)?;
    if scrubbed || history_free_window_required(vault, key)? || doc.is_shallow() {
        export_history_free_window_snapshot(doc)
    } else {
        super::loro_support::export_updates_since(doc, remote_vv)
    }
}

pub(crate) fn export_history_free_window_snapshot(doc: &LoroDoc) -> Result<Vec<u8>> {
    doc.commit();
    let frontiers = doc.oplog_frontiers();
    doc.export(ExportMode::shallow_snapshot(&frontiers))
        .map_err(|e| {
            Error::sync_engine(
                crate::error::SyncEngineContext::LoroExportShallowSnapshot,
                e,
            )
        })
}

/// Scrubs the live state and chooses ordinary versus shallow snapshot bytes
/// using the durable per-window history-free pin.
pub(crate) fn export_scrubbed_window_snapshot(
    vault: &Vault,
    key: &WindowKey,
    doc: &LoroDoc,
) -> Result<Vec<u8>> {
    let scrubbed = scrub_off_record_fenced_carriers(vault, key, doc)?;
    if scrubbed || history_free_window_required(vault, key)? || doc.is_shallow() {
        export_history_free_window_snapshot(doc)
    } else {
        export_snapshot(doc)
    }
}

/// Replays pending-mirror markers (pm:*) for crash recovery.
///
/// Fenced off-record entities remain pending until promotion. The marker is
/// intentionally not cleared while the fence is live: promotion lifts only
/// that turn's fence, then this normal replay path releases that turn to sync.
pub fn replay_pending_mirrors(vault: &Vault, doc: &LoroDoc, window_key: &WindowKey) -> Result<u32> {
    scrub_off_record_fenced_carriers(vault, window_key, doc)?;

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

        // OFRC-2i defer-sync: a fenced turn (including its incident edges)
        // is device-local until explicit promotion. Keep the pending marker
        // so the promoted turn can flow through this ordinary path later.
        if vault.is_turn_off_record_fenced(id)? {
            continue;
        }

        if skip_companion_register_sync_mirror(&raw)? {
            let mut wrote_doc = false;
            if map_contains_binary(&entities_map, &hex_id) {
                map_delete(&entities_map, &hex_id)?;
                wrote_doc = true;
            }
            if delete_edges_touching_entities(&edges_map, &HashSet::from([*id]))? {
                wrote_doc = true;
            }
            if wrote_doc {
                doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
            }
            vault.with_write_txn(|wtxn| {
                vault.store.sync_state.delete(wtxn, marker_key)?;
                Ok(())
            })?;
            continue;
        }

        // Type-classify the local carrier BEFORE granting the CRDT
        // tombstone delete authority. Engine-authored protected rows keep
        // their carrier and quarantine the hostile tombstone; ordinary rows
        // retain the value-agnostic, entity-canonical delete-wins gate.
        let protected_tombstone =
            quarantine_outbound_protected_tombstones(vault, window_key, &tombstones_map, id, &raw)?;
        if !protected_tombstone && tombstone_map_contains_id(&tombstones_map, id) {
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
            let fenced_targets =
                off_record_fenced_ids(vault, edges_out.iter().map(|edge| edge.target))?;
            for edge in &edges_out {
                let edge_key = format_edge_key(id, edge.kind, &edge.target);
                // A cross-window source may already carry an edge to a
                // newly fenced target. Defer must remove that carrier, not
                // merely skip its next backfill.
                if fenced_targets.contains(&edge.target) {
                    if map_contains_key(&edges_map, &edge_key) {
                        map_delete(&edges_map, &edge_key)?;
                        wrote_edges = true;
                    }
                    continue;
                }
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
                map_insert_bytes(&edges_map, edge_key.as_str(), &edge_val)?;
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

        // Mirror to CRDT under bridge origin. Finalized type-120 receipts
        // are LMDB-local accountability rows; undecodable type-120 bytes
        // fail closed using the same gate as reverse remat.
        if reverse_remat_skip_redaction_receipt_mirror(&raw) {
            vault.with_write_txn(|wtxn| {
                vault.store.sync_state.delete(wtxn, marker_key)?;
                Ok(())
            })?;
            continue;
        }
        map_insert_bytes(&entities_map, hex_id.as_str(), raw.as_slice())?;

        let edges_out = vault.edges_out(id)?;
        let fenced_targets =
            off_record_fenced_ids(vault, edges_out.iter().map(|edge| edge.target))?;
        for edge in &edges_out {
            let edge_key = format_edge_key(id, edge.kind, &edge.target);
            if fenced_targets.contains(&edge.target) {
                if map_contains_key(&edges_map, &edge_key) {
                    map_delete(&edges_map, &edge_key)?;
                }
                continue;
            }
            // Same tombstoned-target gate as the byte-equal path above:
            // the full mirror must not re-insert edges to deleted targets.
            if tombstone_map_contains_id(&tombstones_map, &edge.target) {
                continue;
            }
            let edge_val = encode_edge_value_for_crdt(
                edge.kind,
                edge.weight,
                edge.created_at,
                edge.vad,
                edge.provenance,
            )?;
            map_insert_bytes(&edges_map, edge_key.as_str(), &edge_val)?;
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
fn push_terminal_quarantine_marker(
    terminal_quarantines: &mut Vec<EntityId>,
    container: QuarantineContainer,
    crdt_key: &str,
) {
    if let Some(id) = quarantine::remat_marker_entity_for_quarantine(container, crdt_key) {
        terminal_quarantines.push(id);
    }
}

#[expect(clippy::too_many_lines)]
pub fn forward_rematerialize(
    vault: &Vault,
    doc: &LoroDoc,
    materializer: &Materializer,
    window_key: &WindowKey,
) -> Result<u32> {
    let _guard = materializer.lock();
    let lease_vault_id = materializer.lease_vault_id();
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
    let mut terminal_quarantines: Vec<EntityId> = Vec::new();

    let mut count = 0u32;
    let mut fenced_rejections = HashSet::<EntityId>::new();

    // Entities
    {
        let rtxn = vault.store.env.read_txn()?;
        let mut materialized_blobs = HashMap::<EntityId, Vec<u8>>::new();
        let mut entity_error = None;
        let mut local_only_companion_entity_keys = Vec::<String>::new();
        let mut local_only_companion_entity_ids = HashSet::<EntityId>::new();
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
                } else {
                    push_terminal_quarantine_marker(
                        &mut terminal_quarantines,
                        QuarantineContainer::Entities,
                        key,
                    );
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
                } else {
                    terminal_quarantines.push(id);
                }
                return;
            }

            // Decode the envelope before deletion gates so a concurrent
            // protected engine record (notably type-76) cannot be hidden by
            // a hostile tombstone or a pre-fix `dt:` poison marker.
            let header = match EntityMetadataHeader::parse(blob) {
                Some(header) => header,
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
                    } else {
                        terminal_quarantines.push(id);
                    }
                    return;
                }
            };
            let delete_protected =
                crate::registry::is_delete_protected_engine_record(header.entity_type);

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
            if !delete_protected && tombstone_map_contains_id(&tombstones_map, &id) {
                return;
            }
            let locally_hard_deleted = !delete_protected
                && match vault.local_hard_delete_marker_exists_in_txn(&rtxn, &id) {
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

            // Track the local record for most ids: byte-identical →
            // idempotent skip (return). Two kinds make this decision later
            // inside their own replay door instead: type-120 receipts
            // (inside the same write txn as their lease verification and
            // replicated put, so a stale long-lived `rtxn` cannot hide a
            // mid-flight finalized/divergent receipt) and ARCH-0055
            // type-76 events (whose door preserves immutable divergence and
            // seq-clock checks on byte-identical replay while short-circuiting
            // before the full-family reconciliation DoS surface).
            let byte_compare_in_door = matches!(
                header.entity_type,
                crate::registry::ENTITY_TYPE_REDACTION_AUDIT
                    | crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT
            );
            if !byte_compare_in_door {
                if let Some(latest) = materialized_blobs.get(&id) {
                    if latest.as_slice() == blob {
                        return;
                    }
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
                    // SoftErase shell guard: `user_delete` truncates the
                    // local record to the 25 B header shell and writes NO
                    // CRDT record (contracts.ts deleteReasons user_delete:
                    // "Tombstone revision (empty content); keep the message
                    // shell" — cross-device propagation is deferred to
                    // ONE-1090), so the CRDT mirror still carries the
                    // pre-delete body. Replaying that body over the shell
                    // would resurrect deleted content — delete wins.
                    // Interim guard until reason-aware tombstones land in
                    // M4-06.
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
            }

            let data = if blob.len() > ENTITY_METADATA_HEADER_LEN {
                &blob[ENTITY_METADATA_HEADER_LEN..]
            } else {
                &[]
            };
            if header.entity_type == ENTITY_TYPE_COMPANION_REGISTER {
                match decode_companion_record_body(data) {
                    Ok(record)
                        if record.export_classification
                            == CompanionExportClassification::LocalOnly =>
                    {
                        local_only_companion_entity_keys.push(key.to_owned());
                        local_only_companion_entity_ids.insert(id);
                        return;
                    }
                    Ok(_) | Err(_) => {
                        if let Err(err) = vault.ensure_companion_register_kind() {
                            entity_error = Some(err);
                            return;
                        }
                    }
                }
            }
            // ONE-1134 + ONE-1140: REDACTION_AUDIT (type 120) replay door
            // #2. Receipts are immutable audit records (contracts.ts
            // `redactionAuditReceipt`; ARCH-0023b audit/guardrail class:
            // quarantine divergence, never silent LWW), pinned door order:
            // * a blob failing the pinned receipt-body validation (incl.
            //   the ONE-1140 v2 att_ verification grammar) is quarantined,
            //   never written;
            // * id present locally with byte-identical/stale-echo bytes →
            //   skip inside the write txn; any other divergence →
            //   quarantine the remote payload and KEEP the local bytes
            //   (before any crypto — accepted local bytes always win);
            // * id absent (NEW receipt) → the ONE-1140 origin predicate:
            //   Ed25519 transcript verification + `ls:` lease-binding read
            //   (OD-6/OD-7). Remote-classified rejections quarantine; a
            //   LOCAL failure (storage, corrupt ls: mirror row) fails
            //   closed. This pass is also the OD-10 lazy re-admission path:
            //   a previously quarantined receipt re-runs the door here
            //   after the lease mirror catches up.
            if header.entity_type == crate::registry::ENTITY_TYPE_REDACTION_AUDIT
                && let Err(err) = crate::deletion::validate_redaction_receipt_body(data)
            {
                if let Err(q_err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Entities,
                    key,
                    &err,
                    blob,
                ) {
                    entity_error = Some(q_err);
                } else {
                    terminal_quarantines.push(id);
                }
                return;
            }
            // Replicated put: the CRDT mirror is unfiltered, so the
            // maintenance band (REDACTION_AUDIT = 120) and reserved-predicate
            // `edge.provenance` truth-Claims reach here on the way back into
            // LMDB. Routing through the public gate would silently drop them
            // on cross-node sync / replay; `put_replicated` admits both
            // engine-authored bands while still running full structural
            // validation (unknown type bytes, ungrammatical predicates, and
            // malformed CLAIM bodies all still fail typed).
            let result = if header.entity_type == crate::registry::ENTITY_TYPE_REDACTION_AUDIT {
                #[cfg(any(test, feature = "test-hooks"))]
                if let Err(err) = test_hooks::run_receipt_revocation_race(vault) {
                    entity_error = Some(err);
                    return;
                }
                vault.with_write_txn(|wtxn| {
                    if let Some(local) = vault.store.entities.get(&*wtxn, id.as_bytes())? {
                        if *local == *blob {
                            return Ok(false);
                        }
                        // ONE-1087 designed exception: the sweep's receipt
                        // finalization (`sweep_complete_at` None→Some) is
                        // LOCAL-LMDB-only, so the CRDT mirror replays the
                        // PRE-finalization bytes every boot. That one
                        // monotone shape is the own node's stale echo:
                        // idempotent skip, never an x: row. All other
                        // divergence quarantines.
                        if crate::deletion::redaction_receipt_is_stale_finalization_echo(
                            &local, blob,
                        ) {
                            tracing::debug!(
                                entity = %key,
                                "forward remat: stale pre-finalization receipt echo — keeping finalized local"
                            );
                            return Ok(false);
                        }
                        quarantine::quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key.as_str(),
                            QuarantineContainer::Entities,
                            key,
                            &Error::RedactionReceiptDivergence { id },
                            blob,
                        )?;
                        terminal_quarantines.push(id);
                        return Ok(false);
                    }
                    let pubkey = crate::sync::lease::verify_new_receipt_origin_for_vault_in_txn(
                        vault,
                        wtxn,
                        lease_vault_id,
                        &id,
                        blob,
                    )?;
                    let _quota_debit = quota::try_accept_maintenance_ingest_peer_in_txn(
                        vault,
                        wtxn,
                        quota::peer_key_from_redaction_pubkey(&pubkey),
                        crate::unix_seconds_now(),
                    )?;
                    vault
                        .batch_in()
                        .put_replicated(
                            &id,
                            header.entity_type,
                            crate::temporal::TimeRange {
                                start: header.occurred_start,
                                end: header.occurred_end,
                            },
                            header.learned_at,
                            data,
                        )
                        .apply(wtxn)?;
                    Ok(true)
                })
            } else if header.entity_type == ENTITY_TYPE_AUTHORITY_LOG {
                vault.with_write_txn(|wtxn| {
                    if let Some(local) = vault.store.entities.get(&*wtxn, id.as_bytes())?
                        && *local == *blob
                    {
                        return Ok(false);
                    }
                    let validation =
                        crate::batch::validate_replicated_authority_log_for_local_vault(
                            &vault.store,
                            wtxn,
                            data,
                        )?;
                    let peer_key = if validation.signer_known {
                        quota::peer_key_from_authority_key(&validation.signer_key)
                    } else {
                        quota::peer_key_from_unknown_authority_signer(validation.local_vault_id)
                    };
                    let _quota_debit = quota::try_accept_maintenance_ingest_peer_in_txn(
                        vault,
                        wtxn,
                        peer_key,
                        crate::unix_seconds_now(),
                    )?;
                    vault
                        .batch_in()
                        .put_replicated(
                            &id,
                            header.entity_type,
                            crate::temporal::TimeRange {
                                start: header.occurred_start,
                                end: header.occurred_end,
                            },
                            header.learned_at,
                            data,
                        )
                        .apply(wtxn)?;
                    Ok(true)
                })
            } else if header.entity_type == crate::registry::ENTITY_TYPE_IDENTITY_TOPOLOGY_EVENT {
                // ARCH-0055: type-76 ledger events route through the SAME
                // fail-closed single-writer ingest door as Observer B —
                // never the generic LWW arm below, which would silently
                // overwrite an accepted local event with divergent remote
                // bytes and skip validation, the per-stream quota, the
                // seq-clock join, and shell-edge reconciliation. A
                // divergent or malformed remote row classifies as a remote
                // rejection (quarantine-and-continue) at the match below.
                vault.with_write_txn(|wtxn| {
                    bridge::ingest_replicated_identity_topology_event_in_txn(
                        vault,
                        wtxn,
                        &id,
                        &header,
                        blob,
                        data,
                        lease_vault_id,
                    )
                })
            } else {
                vault.with_write_txn(|wtxn| {
                    vault
                        .batch_in()
                        .put_replicated(
                            &id,
                            header.entity_type,
                            crate::temporal::TimeRange {
                                start: header.occurred_start,
                                end: header.occurred_end,
                            },
                            header.learned_at,
                            data,
                        )
                        .apply(wtxn)?;
                    Ok(true)
                })
            };
            match result {
                Ok(true) => {
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
                Ok(false) => {}
                Err(err) if quarantine::remote_rejection_reason(&err).is_some() => {
                    let retryable_quota =
                        matches!(err, Error::MaintenanceIngestQuotaExceeded { .. });
                    if let Err(q_err) = quarantine::quarantine_rejected_op(
                        vault,
                        window_key.as_str(),
                        QuarantineContainer::Entities,
                        key,
                        &err,
                        blob,
                    ) {
                        entity_error = Some(q_err);
                    } else if !retryable_quota {
                        terminal_quarantines.push(id);
                    }
                    if matches!(err, Error::OffRecordFencedTurnWriteRejected { .. }) {
                        fenced_rejections.insert(id);
                    }
                }
                Err(err) => {
                    // LOCAL failure — fail closed.
                    entity_error = Some(err);
                }
            }
        });
        if let Some(err) = entity_error {
            return Err(err);
        }
        if !local_only_companion_entity_keys.is_empty() {
            let mut wrote_doc = false;
            for key in &local_only_companion_entity_keys {
                map_delete(&entities_map, key)?;
                wrote_doc = true;
            }
            if delete_edges_touching_entities(&edges_map, &local_only_companion_entity_ids)? {
                wrote_doc = true;
            }
            if wrote_doc {
                doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
            }
        }
    }

    // Quarantine is the durable evidence for the rejected remote write; it
    // is not a scrub. Wait until the entity pass's read transaction is gone,
    // then remove the rejected body and all incident edges through the shared
    // scrub boundary so the same carrier cannot be exported again.
    if !fenced_rejections.is_empty() {
        scrub_off_record_fenced_carriers(vault, window_key, doc)?;
    }

    // Edges (endpoint + tombstone filtering, stored-value byte-compare).
    // ARCH-0023b step 5 byte-compares edges too ("write any that differ"):
    // an exists-skip would let a CRDT edge carrying confirmation_status =
    // retracted (value[24] == 3) lose to a stale local Active stamp, and the
    // PPR retracted gate would keep propagating withdrawn provenance.
    {
        enum EdgeRematOutcome {
            Written,
            Unchanged,
            Deferred,
            Quarantined,
        }

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
                } else {
                    push_terminal_quarantine_marker(
                        &mut terminal_quarantines,
                        QuarantineContainer::Edges,
                        key,
                    );
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
                    } else {
                        terminal_quarantines.push(src);
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

            // The reserved-kind mandate, endpoint readiness, stored-byte
            // comparison, and paired write share ONE LMDB write txn. A
            // separate read check followed by `batch().commit()` would let
            // an intervening undo revoke the mandate before the edge write.
            let result = vault.with_write_txn(|wtxn| {
                if let Err(reserved) = crate::edge::validate_public_edge_kind(kind) {
                    let mandated_at = vault
                        .identity_topology_mandated_shell_edge_in_txn(&*wtxn, &src, kind, &tgt)?;
                    let door_echo = mandated_at.is_some_and(|at| {
                        decoded.created_at == at && kind.default_weight() == Some(decoded.weight)
                    });
                    if !door_echo {
                        quarantine::quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key.as_str(),
                            QuarantineContainer::Edges,
                            key,
                            &reserved,
                            buf,
                        )?;
                        return Ok(EdgeRematOutcome::Quarantined);
                    }
                }

                let src_exists = vault.store.entities.get(&*wtxn, src.as_bytes())?.is_some();
                let tgt_exists = vault.store.entities.get(&*wtxn, tgt.as_bytes())?.is_some();
                if !src_exists || !tgt_exists {
                    return Ok(EdgeRematOutcome::Deferred);
                }

                // ONE-1645 replay door for the FacetOf type table. The batch
                // arm this write lands on (`BatchOp::EdgeWithCreatedAt`) is
                // deliberately UNGATED — a hard abort there would wedge sync
                // permanently (H2) — so the table is enforced HERE, at the
                // remat chokepoint, as a quarantine-and-continue rejection.
                //
                // Without it a federation peer could replay an off-table
                // stamp (e.g. PERSON -> FACET) that no local public writer
                // can write, and the grant-backed selector treats ANY
                // `FacetOf` source as a facet seed
                // (`selector::facet_scope_by_source`, no source-type check) —
                // an authorization-boundary bypass via replay.
                //
                // Ordered AFTER the endpoint-existence check on purpose: a
                // cross-window endpoint that has not arrived yet is a
                // DEFERRAL, not a rejection, and the type table reads
                // endpoint types from the entity rows this check just proved
                // present. Reversing the order would burn a legitimate
                // out-of-order replay as a permanent quarantine.
                //
                // The match is GUARDED (ONE-1124 fail-closed split): only a
                // remote-classifiable error may quarantine. The table also
                // surfaces LOCAL faults — `CorruptedIndex("entity header")`
                // on a stored row it cannot parse, and heed read errors on
                // the type lookups themselves — and those must ABORT the
                // drain. Quarantining one would be doubly wrong: it swallows
                // our own storage defect behind a continue, and the `x:` row
                // it writes is PERMANENT false evidence accusing the peer of
                // a forgery it never sent.
                match crate::batch::validate_facet_of_edge(&vault.store, &*wtxn, src, kind, tgt) {
                    Ok(()) => {}
                    Err(off_table) if quarantine::remote_rejection_reason(&off_table).is_some() => {
                        quarantine::quarantine_rejected_op_in_txn(
                            vault,
                            wtxn,
                            window_key.as_str(),
                            QuarantineContainer::Edges,
                            key,
                            &off_table,
                            buf,
                        )?;
                        return Ok(EdgeRematOutcome::Quarantined);
                    }
                    Err(local) => return Err(local),
                }

                let out_key = Store::encode_edge_key(&src, kind, &tgt);
                let in_key = Store::encode_edge_key(&tgt, kind, &src);
                let out_matches = vault
                    .store
                    .edges_out
                    .get(&*wtxn, &out_key)?
                    .is_some_and(|value| value == buf);
                let in_matches = vault
                    .store
                    .edges_in
                    .get(&*wtxn, &in_key)?
                    .is_some_and(|value| value == buf);
                if out_matches && in_matches {
                    return Ok(EdgeRematOutcome::Unchanged);
                }

                vault
                    .batch_in()
                    .edge_with_value_fields(
                        &src,
                        kind,
                        &tgt,
                        EdgeValueFields::from_decoded(decoded),
                    )
                    .apply(wtxn)?;
                Ok(EdgeRematOutcome::Written)
            });
            match result {
                Ok(EdgeRematOutcome::Written) => {
                    count += 1;
                    // ONE-1147: a healing edge write discharges the SOURCE
                    // entity's needs-remat marker (Observer B's edge batch
                    // swallow site marks lost upserts by source id).
                    if marked.contains(&src.to_hex()) {
                        healed.push(src);
                    }
                }
                Ok(EdgeRematOutcome::Unchanged) => {}
                Ok(EdgeRematOutcome::Deferred) => {
                    // Deferral, not a rejection: cross-window endpoints
                    // arrive later; the edge stays in the CRDT and
                    // re-materializes when its endpoints do.
                    tracing::debug!(
                        edge = %key,
                        "forward remat: edge deferred — endpoint absent"
                    );
                }
                Ok(EdgeRematOutcome::Quarantined) => {
                    // The reserved-kind rejection and its durable evidence
                    // committed in the edge txn above. Keep iterating: one
                    // forged row must not starve the other N-1 edge heals.
                    terminal_quarantines.push(src);
                }
                Err(err) if quarantine::remote_rejection_reason(&err).is_some() => {
                    if let Err(q_err) = quarantine::quarantine_rejected_op(
                        vault,
                        window_key.as_str(),
                        QuarantineContainer::Edges,
                        key,
                        &err,
                        buf,
                    ) {
                        edge_error = Some(q_err);
                    } else {
                        terminal_quarantines.push(src);
                    }
                }
                Err(err) => {
                    // LOCAL failure — fail closed.
                    edge_error = Some(err);
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
    let mut receiver_scrub_candidates: Vec<EntityId> = Vec::new();
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

        // The entity pass may have rejected or not yet materialized a
        // concurrent protected record. Its CRDT envelope is still enough
        // to deny delete authority: quarantine the tombstone before the
        // headerless replay path can mint a permanent `dt:` marker.
        if matches!(vault.read_entity_header(&id), Ok(None))
            && let Some(entity_blob) = map_get_bytes(&entities_map, &id.to_hex())
            && let Some(header) = bridge::admitted_concurrent_delete_protected_header(&entity_blob)
        {
            let rejection = Error::MaintenanceKindNotWritable(header.entity_type);
            if let Err(quarantine_err) = quarantine::quarantine_rejected_op(
                vault,
                window_key.as_str(),
                QuarantineContainer::Tombstones,
                key,
                &rejection,
                value,
            ) {
                tombstone_error = Some(quarantine_err);
            } else {
                terminal_quarantines.push(id);
            }
            return;
        }

        let hard_tombstone = decode_tombstone_value(value).is_hard();
        match quarantine::apply_replayed_tombstone_for_sync(vault, &id, value) {
            Ok(outcome) => {
                if outcome.changed_local_state() {
                    count += 1;
                }
                if hard_tombstone {
                    receiver_scrub_candidates.push(id);
                }
                // The goal state for THIS tombstone's reason holds (purge
                // done, already absent, or soft shell kept) — the entity's
                // own retry marker (if flagged) is discharged.
                if marked.contains(&id.to_hex()) {
                    cleared.push(id);
                }
            }
            Err(err) if quarantine::remote_rejection_reason(&err).is_some() => {
                if let Err(quarantine_err) = quarantine::quarantine_rejected_op(
                    vault,
                    window_key.as_str(),
                    QuarantineContainer::Tombstones,
                    key,
                    &err,
                    value,
                ) {
                    tombstone_error = Some(quarantine_err);
                } else {
                    terminal_quarantines.push(id);
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

    if !purge_failures.is_empty()
        || !cleared.is_empty()
        || !healed.is_empty()
        || !terminal_quarantines.is_empty()
        || !receiver_scrub_candidates.is_empty()
    {
        let marker_result = vault.with_write_txn(|wtxn| {
            // Clear BEFORE set so set wins: an id that both succeeded and
            // failed in one pass (case-shifted tombstone aliases with
            // divergent reasons) must KEEP its marker — losing it would
            // silently drop a pending hard purge (fail closed). The
            // ONE-1147 `healed` discharges (entity/edge healing writes,
            // structurally disjoint from tombstoned ids — both passes are
            // tombstone-gated). ONE-1167 terminal quarantine may discharge
            // only replay/quarantine-origin markers whose provenance sidecar
            // already proves they are not delete-safety retries; legacy or
            // purge-failure markers stay pending until their own tombstone
            // goal state holds.
            let mut success_seen = HashSet::new();
            // Delete-safety invariant: the `cleared` side has this entity's
            // own tombstone goal state above, while the `healed` side is
            // safe only because tombstone-gating keeps entity/edge healing
            // disjoint from unproven delete-safety `rm:` markers. A
            // tombstoned id cannot reach `healed`; if a refactor weakens
            // that gate or reorders this bookkeeping, the debug assert below
            // catches the healed-clear regression before an unproven purge
            // retry can be silently discharged.
            #[cfg(debug_assertions)]
            for id in &healed {
                let has_unproven_marker = quarantine::unproven_remat_marker_exists_in_txn(
                    vault,
                    wtxn,
                    window_key.as_str(),
                    id,
                )
                .unwrap_or_else(|err| {
                    panic!("delete-safety invariant: failed to read rm: marker state: {err}")
                });
                debug_assert!(
                    !has_unproven_marker,
                    "delete-safety invariant: healed ids must be disjoint from unproven rm: markers"
                );
            }
            for id in healed.iter().chain(cleared.iter()) {
                if !success_seen.insert(*id) {
                    continue;
                }
                quarantine::clear_remat_marker_in_txn(vault, wtxn, window_key.as_str(), id)?;
            }
            let mut terminal_seen = HashSet::new();
            for id in &terminal_quarantines {
                if !terminal_seen.insert(*id) {
                    continue;
                }
                let cleared = quarantine::clear_replay_remat_marker_in_txn(
                    vault,
                    wtxn,
                    window_key.as_str(),
                    id,
                )?;
                if !cleared {
                    tracing::debug!(
                        entity = %id.to_hex(),
                        window = %window_key,
                        "forward remat: terminal quarantine left unproven rm: marker pending"
                    );
                }
            }
            // Delete-safety invariant: `purge_failures` MUST be applied LAST,
            // after healed/cleared clears and terminal-quarantine clears.
            // Tombstone/delete-safety dominance requires a failed purge to win
            // over every clear in this txn: a terminal quarantine may remove
            // replay provenance for non-delete markers, but a simultaneous
            // purge failure must restore the unproven `rm:` retry so the
            // delete-safety provenance is not silently removed.
            for id in &purge_failures {
                quarantine::set_remat_marker_in_txn(vault, wtxn, window_key.as_str(), id)?;
            }
            if !receiver_scrub_candidates.is_empty() {
                scrub_receiver_outbox_on_remote_hard_delete_in_txn(
                    vault,
                    wtxn,
                    window_key.as_str(),
                )?;
            }
            Ok(())
        });
        match marker_result {
            Err(err) if receiver_scrub_candidates.is_empty() => return Err(err),
            Err(err) => {
                tracing::error!(
                    window = %window_key,
                    purge_failures = purge_failures.len(),
                    receiver_scrub_candidates = receiver_scrub_candidates.len(),
                    error = %err,
                    "forward remat: receiver outbox scrub/bookkeeping txn FAILED after hard tombstone replay; flagging entity-scoped rm: markers for durable retry"
                );
                vault.with_write_txn(|wtxn| {
                    for id in purge_failures
                        .iter()
                        .chain(receiver_scrub_candidates.iter())
                    {
                        quarantine::set_remat_marker_in_txn(vault, wtxn, window_key.as_str(), id)?;
                    }
                    Ok(())
                })?;
            }
            Ok(()) => {}
        }
    }
    if let Some(err) = tombstone_error {
        return Err(err);
    }
    if quarantine::pending_remat_windows(vault)?
        .iter()
        .any(|window| window == window_key.as_str())
    {
        // Markers survive the pass when a purge failed above, when a
        // flagged entity has neither a healing write nor a proven non-delete
        // terminal x: row in the loaded doc (stale/cross-window state), or
        // when a marker row no longer parses. Clearing any of them here
        // would vacuously discharge a GDPR retry — keep them (fail closed)
        // and keep ERROR-grade visibility.
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
/// window's `learned_at` range and mirror every syncable, non-fenced entity
/// missing from CRDT. Edge backfill runs for every non-tombstoned, non-fenced
/// in-range entity; edges to fenced targets stay device-local too. Differing
/// edge values are left alone: this pass inserts missing records only.
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
    let entities_in_range_set: HashSet<EntityId> = entities_in_range.iter().copied().collect();
    let mut protected_tombstones = HashSet::new();
    let mut entity_tombstones = Vec::new();

    // Type-classify entity-keyed tombstones BEFORE any CRDT edge-key scan.
    // A hostile tombstone naming a locally available protected engine row
    // cannot be sent through the edge-key parser (its grammar is just the
    // entity hex), and cannot suppress the carrier before reverse recovery
    // sees its type. Ordinary and out-of-window rows are untouched here and
    // retain the existing delete-wins handling in the main loop below.
    map_for_each_tombstone_value(&tombstones_map, |key, tombstone| {
        if let Ok(id) = EntityId::from_hex(key)
            && entities_in_range_set.contains(&id)
        {
            entity_tombstones.push((id, key.to_owned(), tombstone.to_vec()));
        }
    });
    for (id, key, tombstone) in entity_tombstones {
        if vault.is_turn_off_record_fenced(&id)? {
            continue;
        }
        let Some(raw) = vault.get_raw(&id)? else {
            continue;
        };
        if reverse_remat_skip_policy_manifest_mirror(&raw) {
            continue;
        }
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            continue;
        };
        if !crate::registry::is_delete_protected_engine_record(header.entity_type) {
            continue;
        }

        let rejection = Error::MaintenanceKindNotWritable(header.entity_type);
        quarantine::quarantine_rejected_op(
            vault,
            window_key.as_str(),
            QuarantineContainer::Tombstones,
            &key,
            &rejection,
            &tombstone,
        )?;
        protected_tombstones.insert(id);
        let hex_id = id.to_hex();
        if !map_contains_binary(&entities_map, &hex_id) {
            map_insert_bytes(&entities_map, &hex_id, &raw)?;
            wrote_any = true;
            count += 1;
        }
    }

    // The protected-tombstone prepass above intentionally precedes this
    // privacy scrub because the scrub discovers fenced candidates by parsing
    // CRDT edge keys. Protected entity tombstones have already been
    // classified and restored before that different key grammar is touched.
    scrub_off_record_fenced_carriers(vault, window_key, doc)?;

    for id in &entities_in_range {
        let hex_id = id.to_hex();

        // OFRC-2i defer-sync: check the fence before reading or packing the
        // payload. It also scrubs a carrier that landed before the fence was
        // observed, so a live off-record turn cannot remain in a window
        // through reverse rematerialization.
        if vault.is_turn_off_record_fenced(id)? {
            continue;
        }

        let Some(raw) = vault.get_raw(id)? else {
            continue;
        };

        if reverse_remat_skip_policy_manifest_mirror(&raw) {
            continue;
        }

        // Read and type-classify the local row BEFORE granting the CRDT
        // tombstone delete authority. A hostile tombstone cannot suppress a
        // protected engine record from outbound recovery; quarantine it and
        // restore the carrier. Ordinary rows retain delete-wins semantics,
        // including non-binary values and case-shifted aliases.
        let protected_tombstone = protected_tombstones.contains(id);
        if !protected_tombstone && tombstone_map_contains_id(&tombstones_map, id) {
            continue;
        }

        if skip_companion_register_sync_mirror(&raw)? {
            let mut removed = false;
            if map_contains_binary(&entities_map, &hex_id) {
                map_delete(&entities_map, &hex_id)?;
                removed = true;
            }
            if delete_edges_touching_entities(&edges_map, &HashSet::from([*id]))? {
                removed = true;
            }
            wrote_any |= removed;
            continue;
        }

        if !map_contains_binary(&entities_map, &hex_id)
            && !reverse_remat_skip_redaction_receipt_mirror(&raw)
        {
            map_insert_bytes(&entities_map, hex_id.as_str(), raw.as_slice())?;
            wrote_any = true;
            count += 1;
        }

        let edges_out = vault.edges_out(id)?;
        let fenced_targets =
            off_record_fenced_ids(vault, edges_out.iter().map(|edge| edge.target))?;
        for edge in &edges_out {
            let edge_key = format_edge_key(id, edge.kind, &edge.target);
            // The target can live in another window, so its own entity scrub
            // cannot reach this source-window carrier. Delete it here when
            // the source is packed again.
            if fenced_targets.contains(&edge.target) {
                if map_contains_key(&edges_map, &edge_key) {
                    map_delete(&edges_map, &edge_key)?;
                    wrote_any = true;
                }
                continue;
            }
            // Never backfill an edge whose TARGET is tombstoned — matching
            // forward remat's both-endpoint filter (the source is gated
            // above). A surviving local S→E row from the tombstone-commit/
            // purge-txn crash window must not re-enter the replicated edges
            // map. Plain containment = skip on this branch; reason-aware
            // (skip iff HARD) once tombstone v2 lands in M4-06.
            if tombstone_map_contains_id(&tombstones_map, &edge.target) {
                continue;
            }
            if local_entity_is_unsyncable_companion(vault, &edge.target)? {
                continue;
            }
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
            map_insert_bytes(&edges_map, edge_key.as_str(), &edge_val)?;
            wrote_any = true;
        }
    }

    // Commit all bridge writes with origin tag
    if wrote_any {
        doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    Ok(count)
}

fn skip_companion_register_sync_mirror(raw: &[u8]) -> Result<bool> {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Ok(false);
    };
    if header.entity_type != ENTITY_TYPE_COMPANION_REGISTER {
        return Ok(false);
    }
    decode_companion_record_body(&raw[ENTITY_METADATA_HEADER_LEN..])
        .map(|record| record.export_classification == CompanionExportClassification::LocalOnly)
}

/// Quarantines every CRDT tombstone aliasing a locally available,
/// delete-protected engine record. Returns `true` only when tombstone
/// authority was denied, allowing the caller to preserve or restore the
/// entity carrier through the ordinary outbound mirror path.
fn quarantine_outbound_protected_tombstones(
    vault: &Vault,
    window_key: &WindowKey,
    tombstones_map: &LoroMap,
    id: &EntityId,
    raw: &[u8],
) -> Result<bool> {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Ok(false);
    };
    if !crate::registry::is_delete_protected_engine_record(header.entity_type) {
        return Ok(false);
    }

    let tombstones = tombstone_values_for_id(tombstones_map, id);
    if tombstones.is_empty() {
        return Ok(false);
    }

    let rejection = Error::MaintenanceKindNotWritable(header.entity_type);
    for tombstone in &tombstones {
        quarantine::quarantine_rejected_op(
            vault,
            window_key.as_str(),
            QuarantineContainer::Tombstones,
            &id.to_hex(),
            &rejection,
            tombstone,
        )?;
    }
    Ok(true)
}

fn local_entity_is_unsyncable_companion(vault: &Vault, id: &EntityId) -> Result<bool> {
    let Some(raw) = vault.get_raw(id)? else {
        return Ok(false);
    };
    skip_companion_register_sync_mirror(&raw)
}

/// Removes a fenced entity's already-present CRDT body and every incident
/// edge. Fencing must hold even when the carrier arrived before the local
/// fence check; merely skipping a later mirror would leave the old carrier
/// sync-visible indefinitely.
fn scrub_fenced_entity_crdt_carriers(
    entities_map: &LoroMap,
    edges_map: &LoroMap,
    id: &EntityId,
) -> Result<bool> {
    let mut removed = false;
    let mut entity_keys = Vec::new();
    map_for_each_value_bytes(entities_map, |key, _| {
        if EntityId::from_hex(key).ok().as_ref() == Some(id) {
            entity_keys.push(key.to_owned());
        }
    });
    for key in &entity_keys {
        map_delete(entities_map, key)?;
        removed = true;
    }
    if delete_edges_touching_entities(edges_map, &HashSet::from([*id]))? {
        removed = true;
    }
    Ok(removed)
}

fn delete_edges_touching_entities(edges_map: &LoroMap, ids: &HashSet<EntityId>) -> Result<bool> {
    if ids.is_empty() {
        return Ok(false);
    }

    let mut edge_keys = Vec::new();
    map_for_each_value_bytes(edges_map, |key, _| {
        if let Some((src, _, tgt)) = bridge::parse_edge_key(key)
            && (ids.contains(&src) || ids.contains(&tgt))
        {
            edge_keys.push(key.to_owned());
        }
    });
    for key in &edge_keys {
        map_delete(edges_map, key)?;
    }
    Ok(!edge_keys.is_empty())
}

fn reverse_remat_skip_policy_manifest_mirror(raw: &[u8]) -> bool {
    EntityMetadataHeader::parse(raw)
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_POLICY_MANIFEST)
}

/// REDACTION_AUDIT finalization is local-LMDB-only. Reverse remat is the
/// outgoing replay door, so it must not copy finalized receipt bytes into the
/// CRDT mirror. Undecodable type-120 bodies also stay local: fail closed
/// rather than replicate raw accountability bytes whose shape is unknown.
fn reverse_remat_skip_redaction_receipt_mirror(raw: &[u8]) -> bool {
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return raw.first().copied() == Some(crate::registry::ENTITY_TYPE_REDACTION_AUDIT);
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_REDACTION_AUDIT {
        return false;
    }
    let body = if raw.len() > ENTITY_METADATA_HEADER_LEN {
        &raw[ENTITY_METADATA_HEADER_LEN..]
    } else {
        &[]
    };
    match crate::deletion::decode_redaction_audit_receipt(body) {
        Ok(receipt) => receipt.sweep_complete_at.is_some(),
        Err(_) => true,
    }
}

/// Test-only hook for the REDACTION_AUDIT rematerialization race pin. The
/// armed writes land just before the same-txn recheck+verify+put path starts,
/// so production code must observe mid-flight lease revocation or local
/// divergent receipt bytes before admitting the remote receipt.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub mod test_hooks {
    use std::cell::RefCell;

    use crate::entity_id::EntityId;
    use crate::{Error, Result, Vault};

    thread_local! {
        static RECEIPT_REVOCATION: RefCell<Option<(String, Vec<u8>)>> = const { RefCell::new(None) };
        static RECEIPT_LOCAL_WRITE: RefCell<Option<(EntityId, Vec<u8>)>> = const { RefCell::new(None) };
    }

    pub fn arm_receipt_revocation_race(lease_key: String, revoked_row: Vec<u8>) {
        RECEIPT_REVOCATION.with(|slot| {
            *slot.borrow_mut() = Some((lease_key, revoked_row));
        });
    }

    pub fn arm_receipt_local_write_race(id: EntityId, local_blob: Vec<u8>) {
        RECEIPT_LOCAL_WRITE.with(|slot| {
            *slot.borrow_mut() = Some((id, local_blob));
        });
    }

    pub(crate) fn run_receipt_revocation_race(vault: &Vault) -> Result<()> {
        let armed = RECEIPT_REVOCATION.with(|slot| slot.borrow_mut().take());
        if let Some((lease_key, revoked_row)) = armed {
            if revoked_row.is_empty() {
                return Err(Error::InvariantViolation("empty revoked lease test row"));
            }
            vault.sync_state_put(&lease_key, &revoked_row)?;
        }
        let armed = RECEIPT_LOCAL_WRITE.with(|slot| slot.borrow_mut().take());
        if let Some((id, local_blob)) = armed {
            if local_blob.is_empty() {
                return Err(Error::InvariantViolation("empty local receipt test row"));
            }
            vault.with_write_txn(|wtxn| {
                vault.store.entities.put(wtxn, id.as_bytes(), &local_blob)?;
                Ok(())
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
