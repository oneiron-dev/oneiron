//! Tombstone apply/export/replay plus window rebuild from updates.

use super::bridge::{self, BRIDGE_ORIGIN};
use super::egress::export_scrubbed_window_snapshot;
use super::loro_support::{
    doc_version_vector, export_updates_from, import_doc, map_delete, map_for_each_bytes,
    map_insert_bytes, tombstone_values_for_id,
};
use super::schema::create_window_doc;
use super::types::WindowKey;
use super::{merge_persisted_state_into_doc, persist_window_doc_in_txn, write_window_svf_in_txn};

use crate::Vault;
use crate::deletion::{PENDING_TOMBSTONE_PREFIX, decode_tombstone_value};
use crate::entity_id::EntityId;
use crate::error::Result;
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
