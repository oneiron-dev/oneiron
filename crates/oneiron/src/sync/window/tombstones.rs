//! Tombstone apply/export/replay plus window rebuild from updates.

use super::bridge::{self, BRIDGE_ORIGIN};
use super::egress::export_scrubbed_window_snapshot;
use super::loro_support::{
    TombstoneIndex, doc_version_vector, export_updates_from, import_doc, map_delete,
    map_for_each_bytes, map_get_bytes, map_insert_bytes,
};
use super::schema::create_window_doc;
use super::types::WindowKey;
use super::{
    load_window_from_state, merge_persisted_state_into_doc, persist_window_doc_in_txn,
    prune_subsumed_window_updates_in_txn, write_window_svf_in_txn,
};

use crate::Vault;
use crate::deletion::decode_tombstone_value;
use crate::entity_id::EntityId;
use crate::error::{Error, Result, SyncError};
use crate::ports::{WindowAddress, WindowDeletionRows};
use crate::sync::window_rows::{PENDING_TOMBSTONE, WINDOW_FULL_RESYNC_MARKER};
use loro::{CommitOptions, LoroDoc};

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
    let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
    apply_tombstone_to_indexed_window_doc(doc, &tombstones, id, raw_value)
}

/// The entity carriers `ids` hold in `doc`, read before a local path removes
/// them, so [`mark_removed_carriers_first`] can mark the task of an authority
/// fact among them that this vault never admitted: removing its carrier
/// before ingest saw it would otherwise read as a fact never made.
pub(crate) fn entity_carriers(doc: &LoroDoc, ids: &[EntityId]) -> Vec<(EntityId, Vec<u8>)> {
    let entities = doc.get_map("entities");
    ids.iter()
        .filter_map(|id| map_get_bytes(&entities, &id.to_hex()).map(|carrier| (*id, carrier)))
        .collect()
}

/// Each local path that removes the window carrier of an id deleted here.
/// Every one marks through [`mark_removed_carriers_first`], naming itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CarrierRemoval {
    /// The boot replay of `pt:` markers.
    PendingTombstoneReplay,
    /// The `ra:` drain, live and transient.
    ReassertDrain,
    /// The egress scrub of a carrier whose tombstone a peer withdrew.
    WithdrawnDeleteScrub,
    /// The egress scrub of the carriers at an id whose stored row is a CLAIM
    /// held back from sync, such as a soft-deleted CLAIM's shell.
    LocalClaimScrub,
    /// The local delete's tombstone publication, live and transient.
    LocalPublication,
    /// The sweep's compaction of a hard-erased id's residue.
    HardEraseSweep,
    /// A canonical window capture, which leaves a deleted id's carrier out
    /// of the artifact or keeps only its shell.
    CanonicalCapture,
}

impl CarrierRemoval {
    /// Every path, for the check that each marks before it removes.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 7] = [
        Self::PendingTombstoneReplay,
        Self::ReassertDrain,
        Self::WithdrawnDeleteScrub,
        Self::LocalClaimScrub,
        Self::LocalPublication,
        Self::HardEraseSweep,
        Self::CanonicalCapture,
    ];
}

/// [`crate::task_authority::mark_removed_carriers`], committed before `path`
/// touches the document. The id is deleted here, so the fact can never be
/// admitted: a removal that fails after the mark leaves the task reading as a
/// refusal, never as a fact never made, and no observer or later persist can
/// make the removal durable without its mark.
pub(crate) fn mark_removed_carriers_first(
    vault: &Vault,
    #[cfg_attr(
        not(test),
        expect(unused_variables, reason = "names the path to a test seam")
    )]
    path: CarrierRemoval,
    carriers: &[(EntityId, Vec<u8>)],
) -> Result<()> {
    crate::task_authority::mark_removed_carriers(vault, carriers)?;
    // A peer's record of a removed carrier leaves with it.
    crate::sync::ingest::forget_peer_rows(vault, carriers)?;
    #[cfg(test)]
    fail_after_carrier_mark(path)?;
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FAIL_AFTER_CARRIER_MARK: std::cell::Cell<Option<CarrierRemoval>> =
        const { std::cell::Cell::new(None) };
}

/// Arms a one-shot failure of `path` right after its carrier marks commit,
/// before it touches the document.
#[cfg(test)]
pub(crate) fn arm_fail_after_carrier_mark(path: CarrierRemoval) {
    FAIL_AFTER_CARRIER_MARK.with(|armed| armed.set(Some(path)));
}

/// Disarms [`arm_fail_after_carrier_mark`]: whether it was still armed,
/// that is, whether its path never reached its mark.
#[cfg(test)]
pub(crate) fn disarm_fail_after_carrier_mark() -> bool {
    FAIL_AFTER_CARRIER_MARK.with(|armed| armed.take().is_some())
}

#[cfg(test)]
fn fail_after_carrier_mark(path: CarrierRemoval) -> Result<()> {
    if FAIL_AFTER_CARRIER_MARK.with(|armed| armed.get() == Some(path)) {
        FAIL_AFTER_CARRIER_MARK.with(|armed| armed.set(None));
        return Err(crate::error::Error::InvariantViolation(
            "test failure after a carrier mark",
        ));
    }
    Ok(())
}

/// [`apply_tombstone_to_window_doc`] for a replay of many tombstones into one doc: `tombstones`
/// indexes the doc's map once for the whole replay (H15), built after the replay's last import.
pub(in crate::sync) fn apply_tombstone_to_indexed_window_doc(
    doc: &LoroDoc,
    tombstones: &TombstoneIndex,
    id: &EntityId,
    raw_value: &[u8],
) -> Result<()> {
    let incoming = decode_tombstone_value(raw_value);
    let hex_id = id.to_hex();

    // Tombstone-aware read across EVERY hex-casing alias of the id: a
    // PRESENT non-Binary value reads as the empty slice, which decodes HARD
    // (fail closed) — a garbage tombstone must block a soft downgrade
    // exactly like a hard binary one, and a crafted UPPERCASE-key hard
    // tombstone must block it exactly like the canonical lowercase one.
    let existing_hard = tombstones
        .values_for(id)
        .iter()
        .any(|existing| decode_tombstone_value(existing).is_hard());
    let downgrade_blocked = existing_hard && !incoming.is_hard();
    if !downgrade_blocked {
        map_insert_bytes(tombstones.map(), &hex_id, raw_value)?;
    }

    crate::sync::note::deleted(doc, id)?;

    let entities = doc.get_map("entities");
    if entities.get(&hex_id).is_some() {
        map_delete(&entities, &hex_id)?;
    }
    // The deleted row's birth leaves with its carrier.
    crate::sync::row_birth::remove_birth_carrier(doc, id)?;

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
/// A sync-enabled boot calls this BEFORE [`replay_pending_mirrors`](crate::sync::window::replay_pending_mirrors) (so a
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
    let markers = pending_tombstone_markers(vault, window_key)?;
    if markers.is_empty() {
        return Ok(0);
    }

    // Clobber guard + scrub inventory: merge the on-disk record into the
    // doc so the full snapshot below subsumes it, and remember which `u:`
    // rows it covered (only those may be scrubbed).
    let merged_update_keys = merge_persisted_state_into_doc(vault, doc, window_key)?;
    replay_tombstone_markers(vault, doc, window_key, &markers, &merged_update_keys, false)
}

/// [`replay_pending_tombstones`] now rather than at the window's next load,
/// for a door whose own transaction staged `pt:` markers it could not
/// publish there: an erase stages its world's pad tombstones in each pad's
/// window (FIX 343). It takes `Vault::write_crdt_tombstone`'s two paths: the
/// live doc under the materializer lock when the window is open here, else
/// a transient load, whose persist also keeps the delta as a `u:` row so an
/// open racing it still loads the tombstones.
pub(crate) fn publish_pending_tombstones(vault: &Vault, window_key: &WindowKey) -> Result<u32> {
    let markers = pending_tombstone_markers(vault, window_key)?;
    if markers.is_empty() {
        return Ok(0);
    }
    if let Some((window, materializer, _manager)) = vault.live_window(window_key) {
        // Merged outside the materializer lock: an import into an observed
        // doc fires Observer B, which takes the lock itself. The commit runs
        // under it, and Observer A persists and routes the delta as usual.
        let merged_update_keys = merge_persisted_state_into_doc(vault, &window.doc, window_key)?;
        let _guard = materializer.lock();
        return replay_tombstone_markers(
            vault,
            &window.doc,
            window_key,
            &markers,
            &merged_update_keys,
            false,
        );
    }
    let doc = match load_window_from_state(vault, "local", window_key) {
        Ok(doc) => doc,
        Err(Error::Sync(SyncError::WindowNotFound { .. })) => {
            create_window_doc("local", window_key)
        }
        Err(err) => return Err(err),
    };
    let merged_update_keys = merge_persisted_state_into_doc(vault, &doc, window_key)?;
    replay_tombstone_markers(vault, &doc, window_key, &markers, &merged_update_keys, true)
}

/// The `pt:` markers staged in `window_key`. A malformed marker key is left
/// in place and logged: a deletion intent is never silently dropped.
fn pending_tombstone_markers(
    vault: &Vault,
    window_key: &WindowKey,
) -> Result<Vec<(crate::sync::window_rows::WindowEntityHexKey, Vec<u8>)>> {
    let mut markers: Vec<(crate::sync::window_rows::WindowEntityHexKey, Vec<u8>)> = Vec::new();
    let rtxn = vault.store.env.read_txn()?;
    for entry in vault
        .store
        .port_pending_tombstones_in_window(&rtxn, WindowAddress::new(window_key.as_str()))?
    {
        match entry {
            Ok(row) => markers.push((
                crate::sync::window_rows::WindowEntityHexKey {
                    window: row.window_label,
                    id: row.id,
                },
                row.raw,
            )),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "pt replay: malformed pending-tombstone marker left in place"
                );
            }
        }
    }
    Ok(markers)
}

/// Replays `markers` into `doc`, whose persisted state `merged_update_keys`
/// was merged in, and persists the result ([`replay_pending_tombstones`]).
/// `keep_update` also stores the delta as a `u:` row, for a doc no Observer
/// A watches.
fn replay_tombstone_markers(
    vault: &Vault,
    doc: &LoroDoc,
    window_key: &WindowKey,
    markers: &[(crate::sync::window_rows::WindowEntityHexKey, Vec<u8>)],
    merged_update_keys: &[String],
    keep_update: bool,
) -> Result<u32> {
    let any_hard = markers
        .iter()
        .any(|(_, value)| decode_tombstone_value(value).is_hard());

    let vv_before = doc.oplog_vv();
    let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
    let ids: Vec<EntityId> = markers.iter().map(|(key, _)| key.id).collect();
    mark_removed_carriers_first(
        vault,
        CarrierRemoval::PendingTombstoneReplay,
        &entity_carriers(doc, &ids),
    )?;
    for (key, value) in markers {
        apply_tombstone_to_indexed_window_doc(doc, &tombstones, &key.id, value)?;
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
    vault.with_write_txn_grouped(|wtxn| {
        persist_window_doc_in_txn(vault, wtxn, window_key, &snapshot, &vv)?;
        if any_hard {
            crate::sync::queue::scrub_window_updates_in_txn(vault, wtxn, window_key.as_str())?;
            prune_subsumed_window_updates_in_txn(vault, wtxn, window_key, merged_update_keys)?;
            WINDOW_FULL_RESYNC_MARKER.put(
                &vault.store,
                wtxn,
                &window_key.as_str().to_owned(),
                &[1u8],
            )?;
        }
        if let Some(update) = &delete_update {
            if keep_update {
                crate::sync::bridge::persist_window_update_in_txn(
                    vault,
                    wtxn,
                    window_key.as_str(),
                    update.as_bytes(),
                )?;
            }
            crate::sync::queue::push_delete_bearing_in_txn(
                vault,
                wtxn,
                window_key.as_str(),
                update,
            )?;
        }
        for (key, value) in markers {
            // A pending tombstone is also a crash-replay path for an owned
            // topology deletion. Release only this exact request, and only
            // after snapshot/export persistence in the same transaction.
            // The helper retains Published hard intents without a matching
            // completed dt: purge witness, so a replay cannot unblock a
            // topology write while the hard delete remains unfinished.
            let tombstone = decode_tombstone_value(value);
            if let Some(request_id) = tombstone.request_id {
                crate::deletion::topology_delete_intent::complete_replayed_topology_delete_in_txn(
                    &vault.store,
                    wtxn,
                    &key.id,
                    &request_id,
                    tombstone.is_hard(),
                )?;
            }
            PENDING_TOMBSTONE.delete(&vault.store, wtxn, key)?;
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
    let address = WindowAddress::new(key.as_str());
    for entry in vault
        .store
        .port_window_updates(&rtxn, address, |_, v| import_doc(&doc, v))?
    {
        entry??;
    }
    Ok(doc)
}
