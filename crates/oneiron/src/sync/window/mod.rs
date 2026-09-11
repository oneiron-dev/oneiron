//! Window lifecycle management for the CRDT sync layer.
//!
//! Windows partition entities by `learned_at` month. Each window has an
//! independent CRDT Doc (Loro). Only 2 windows are loaded by default
//! (current + previous month); older windows are ON-DISK in sync_state.

use std::sync::Arc;

use super::bridge::{self, Materializer, ObserverAState, OutboundSink};
use super::diagnostic_ingest;
use super::loro_support::{
    self, doc_from_snapshot, doc_version_vector, export_snapshot, import_doc,
};
use super::quarantine;
use super::queue;
use super::quota;
use super::schema::{self, create_window_doc};
use super::types::{self, WindowKey};
use crate::Vault;
use crate::error::{Error, Result, SyncProtocolPruneScope, SyncProtocolValidation};
use loro::{LoroDoc, Subscription};

mod egress;
mod forward;
mod reverse;
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub mod test_hooks;
mod tombstones;

pub(crate) use self::egress::export_history_free_window_snapshot;
pub(in crate::sync) use self::egress::export_scrubbed_window_snapshot;
use self::egress::window_packing_excludes_entity;
pub use self::egress::{
    export_window_updates_since, history_free_window_required, replay_pending_mirrors,
    require_history_free_window,
};
pub use self::forward::forward_rematerialize;
pub use self::reverse::reverse_rematerialize;
pub(crate) use self::tombstones::{DeleteBearingUpdate, export_tombstone_commit_delta};
pub use self::tombstones::{
    apply_tombstone_to_window_doc, rebuild_window_from_updates, replay_pending_tombstones,
};

pub(super) const HISTORY_FREE_WINDOW_PREFIX: &str = "hfs:w:";

/// Reserved prefix for Loro commit MESSAGES written by the edit-distance
/// proposal-artifact substrate (ED-00, ONE-1756).
///
/// Two pieces of Loro commit metadata exist and only one of them is durable:
/// `CommitOptions::origin` is local event metadata (the [`BRIDGE_ORIGIN`]
/// live-event filter above is its only consumer, and it does NOT survive
/// snapshot/reopen), while `CommitOptions::commit_msg` is persisted in the
/// `Change` record and replicates. Proposal-artifact writes therefore stamp
/// their actor into the commit MESSAGE, under this prefix so a message written
/// by any other layer can never be mistaken for one.
///
/// Declared here beside the origin convention so a sync-layer author sees both
/// reservations in one place; the grammar and its parser live in
/// [`crate::edit_distance::proposal_text`].
pub(crate) const PROPOSAL_TEXT_COMMIT_MSG_PREFIX: &str = "oneiron.edit_distance.v1";

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

        let history_free = history_free_window_required(vault, &self.key)?;

        // Once a sealed carrier has existed in this window, a normal Loro
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
fn prune_subsumed_window_updates_in_txn(
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
        .ok_or_else(|| {
            Error::Sync(SyncError::WindowNotFound {
                window_key: key.as_str().to_string(),
            })
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

#[cfg(test)]
mod tests;

// The flat window.rs module used to provide these names to the sibling test
// module through `use super::*`: its own private crate/std import header, and
// every window-internal item the tests name bare. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::reverse::*;
#[cfg(test)]
use super::bridge::{encode_edge_value_for_crdt, format_edge_key};
#[cfg(test)]
use super::loro_support::{
    export_updates_from, map_contains_binary, map_delete, map_for_each_bytes, map_get_bytes,
    map_insert_bytes, tombstone_map_contains_id,
};
#[cfg(test)]
use super::quarantine::QuarantineContainer;
#[cfg(test)]
use crate::batch::ENTITY_METADATA_HEADER_LEN;
#[cfg(test)]
use crate::companion::ENTITY_TYPE_COMPANION_REGISTER;
#[cfg(test)]
use crate::entity_id::EntityId;
use crate::error::SyncError;
#[cfg(test)]
use crate::registry::{ENTITY_TYPE_AUTHORITY_LOG, ENTITY_TYPE_SECRET_CUSTODY};
#[cfg(test)]
use crate::store::Store;
#[cfg(test)]
use loro::{LoroMap, VersionVector};
