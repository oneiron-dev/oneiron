//! ra: tombstone reassert markers, enqueue/pending/drain.

use std::sync::Arc;

use crate::Vault;
use crate::error::SyncError;
use crate::error::{Error, Result};
use crate::sync::types::{WindowKey, parse_window_key_str};

// ─── ra: tombstone re-assertion markers (ONE-1156c) ──────────────────────────

/// Prefix for queued tombstone re-assertion markers in `sync_state`
/// (ONE-1156(c), WAVE-C design OD-11). Full key grammar, mirroring `rm:w:`:
/// `ra:w:{window}:{entity_hex}` → exactly the 25 B tombstone value
/// `[reason:1][deleted_at:8 LE][request_id:16]` to re-assert — byte-identical
/// to the `dt:` local hard-delete row (LE in the opaque value, per the dt:
/// convention). `window` is `YYYY-MM`; `entity_hex` is the 32-char lowercase
/// entity id.
///
/// Producers are Observer B tombstone callbacks observing doc-side delete
/// residue for a locally hard-deleted id: a tombstone REMOVAL delta, or a
/// soft value merged over the local hard truth (M4 handoff §8c.1). LMDB is
/// already safe (`dt:` gate + never-downgrade in the replay primitive), but
/// the window doc would keep propagating the residue. The re-entrancy bar —
/// no doc writes inside observer callbacks — means the re-assertion cannot
/// run at the producer; the durable marker defers it to a safe commit point
/// ([`drain_reassert_markers`]).
///
/// HARD-only by design (OD-11): without a `dt:` row there is no faithful
/// local value to re-assert, and a reconstructed soft value could HARD-purge
/// a user-kept shell at peers (decode mismatch) — soft-removal residue stays
/// quarantine-only (pinned residual R4).
const REASSERT_MARKER_PREFIX: &str = "ra:w:";

/// Formats the `ra:w:{window}:{entity_hex}` re-assertion marker key.
#[must_use]
pub(super) fn reassert_marker_key(window_key: &str, id: &crate::entity_id::EntityId) -> String {
    format!("{REASSERT_MARKER_PREFIX}{window_key}:{}", id.to_hex())
}

/// Enqueues the tombstone re-assertion marker for `id` IF the permanent
/// `dt:{entity_hex}` local hard-delete marker exists: reads the `dt:` row
/// and writes `ra:w:{window}:{entity_hex}` with the row's EXACT bytes — the
/// value the drain re-asserts verbatim. Returns whether a marker was written
/// (`false` = no `dt:` row, nothing faithful to re-assert — OD-11 HARD-only).
/// Idempotent: same key, same dt:-derived value.
///
/// Caller supplies the write transaction (batch parent or a thin one-txn
/// delegate). Soft-over-hard staging folds into `apply_tombstone_batch`'s
/// single top-level write txn so materialize never opens a per-item
/// committing helper for staged work (ONE-521).
pub(in crate::sync) fn enqueue_tombstone_reassert_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<bool> {
    let dt_key = crate::deletion::local_hard_delete_key(id);
    let Some(dt_value) = vault.store.sync_state.get(wtxn, &dt_key)? else {
        return Ok(false);
    };
    let dt_value = dt_value.to_vec();
    vault
        .store
        .sync_state
        .put(wtxn, &reassert_marker_key(window_key, id), &dt_value)?;
    Ok(true)
}

/// Enqueues the tombstone re-assertion marker in its own write transaction.
/// Thin one-txn delegate over [`enqueue_tombstone_reassert_marker_in_txn`]
/// (same pattern as [`set_remat_marker`] / [`set_remat_marker_in_txn`]).
/// Used by pre-batch door paths (e.g. tombstone REMOVAL deltas) that are
/// not part of staged batch materialization.
pub(in crate::sync) fn enqueue_tombstone_reassert_marker(
    vault: &Vault,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<bool> {
    vault.with_write_txn(|wtxn| {
        enqueue_tombstone_reassert_marker_in_txn(vault, wtxn, window_key, id)
    })
}

/// Lists DISTINCT windows with pending `ra:` re-assertion markers.
///
/// Fail closed like [`pending_remat_windows`]: a row under `ra:w:` missing
/// the entity segment (or otherwise unparsable) is still surfaced — its
/// whole remainder is reported as the pending window. A re-assertion intent
/// is never dropped by a read.
pub fn pending_reassert_windows(vault: &Vault) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut windows = std::collections::BTreeSet::new();
    let iter = vault
        .store
        .sync_state
        .prefix_iter(&rtxn, REASSERT_MARKER_PREFIX)?;
    for entry in iter {
        let (key, _) = entry?;
        let rest = &key[REASSERT_MARKER_PREFIX.len()..];
        let window = match rest.split_once(':') {
            Some((window, _entity_hex)) => window,
            None => rest,
        };
        windows.insert(window.to_string());
    }
    Ok(windows.into_iter().collect())
}

/// One parsed `ra:` marker: (full `sync_state` key, entity id, value bytes).
type ReassertMarker = (String, crate::entity_id::EntityId, Vec<u8>);

/// The `ra:` markers for one window: `(marker_key, parsed_id, value)` for
/// every row whose entity segment parses, plus the count of malformed rows.
/// Malformed rows are NEVER returned for application and never deleted —
/// they keep the window `still_pending` (fail closed) and stay
/// doctor-visible via [`pending_reassert_windows`].
fn pending_reassert_markers(
    vault: &Vault,
    window_key: &str,
) -> Result<(Vec<ReassertMarker>, usize)> {
    let rtxn = vault.store.env.read_txn()?;
    let prefix = format!("{REASSERT_MARKER_PREFIX}{window_key}:");
    let mut markers = Vec::new();
    let mut malformed = 0usize;
    let iter = vault.store.sync_state.prefix_iter(&rtxn, &prefix)?;
    for entry in iter {
        let (key, value) = entry?;
        let hex = &key[prefix.len()..];
        match crate::entity_id::EntityId::from_hex(hex) {
            Ok(id) => markers.push((key.to_string(), id, value.to_vec())),
            Err(_) => {
                tracing::error!(
                    marker = %key,
                    "ra drain: malformed re-assertion marker entity segment — marker kept (fail closed)"
                );
                malformed += 1;
            }
        }
    }
    Ok((markers, malformed))
}

/// Outcome of a [`drain_reassert_markers`] pass — same shape as
/// [`RematDrainReport`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReassertDrainReport {
    /// Windows whose `ra:` markers ALL re-asserted + cleared.
    pub drained: Vec<String>,
    /// Windows with at least one marker still set after the pass — the
    /// re-assertion keeps failing or a marker row does not parse (fail
    /// closed). ERROR-grade: doc-side delete residue keeps propagating.
    pub still_pending: Vec<String>,
}

/// Drains `ra:` tombstone re-assertion markers (ONE-1156(c), OD-11): per
/// flagged window, re-asserts each marker's exact tombstone value into the
/// window doc at a SAFE COMMIT POINT — handler/maintenance context, never
/// inside an observer callback (the §8c.1 re-entrancy bar the producers
/// respect).
///
/// Mirrors the `Vault::write_crdt_tombstone` dual path — live registry doc
/// (commit through the SHARED doc under the materializer lock) vs transient
/// load (`load_window_from_state`, with the rm:-drain
/// `rebuild_window_from_updates` fallback) — minus `pt:` bookkeeping and
/// minus the carrier-15 scrub: the LMDB purge already ran in the origin
/// txn; this is doc-side repair only (no `fr:` marker, no `q:` scrub).
///
/// Call sites: maintenance/doctor surfaces (alongside
/// [`drain_remat_markers`]) and inline in the bulk-transfer door
/// (`SyncClient::handle_bulk_transfer_done`), scoped to that window.
pub fn drain_reassert_markers(
    vault: &Arc<Vault>,
    user_id: &str,
    manager: &Arc<crate::sync::manager::WindowManager>,
) -> Result<ReassertDrainReport> {
    let mut report = ReassertDrainReport::default();
    for window in pending_reassert_windows(vault)? {
        if parse_window_key_str(&window).is_none() {
            tracing::error!(
                window = %window,
                "ra drain: malformed marker window key — cannot re-assert, marker kept"
            );
            report.still_pending.push(window);
            continue;
        }
        let window_key = WindowKey::new(window.clone());
        if drain_reassert_markers_for_window(vault, user_id, manager, &window_key)? {
            report.drained.push(window);
        } else {
            tracing::error!(
                window = %window,
                "ra drain: re-assertion markers still pending — doc-side delete residue keeps propagating"
            );
            report.still_pending.push(window);
        }
    }
    Ok(report)
}

/// Per-window `ra:` drain (see [`drain_reassert_markers`]). Returns `true`
/// when no marker remains for the window (every parsed marker re-asserted
/// and cleared; vacuously true when none were pending), `false` when a
/// malformed marker row was kept (fail closed).
///
/// The success transaction is atomic: the re-asserted window-doc snapshot
/// triple (`d:`/`sv:`/`svf:`), the delete-bearing queue row (`q:` +
/// `d:{seq:8BE}` sidecar — the re-asserted tombstone must propagate and
/// survive optimistic clears), and the `ra:` row deletions commit together.
/// Markers are deleted ONLY in this transaction; a failure anywhere leaves
/// them set for retry. Idempotent on double-drain: the second pass finds no
/// markers (and a re-applied hard value is downgrade-blocked/no-op at every
/// consumer — never-downgrade).
pub(in crate::sync) fn drain_reassert_markers_for_window(
    vault: &Arc<Vault>,
    user_id: &str,
    manager: &Arc<crate::sync::manager::WindowManager>,
    window_key: &WindowKey,
) -> Result<bool> {
    use crate::sync::bridge::BRIDGE_ORIGIN;
    use crate::sync::loro_support::doc_version_vector;
    use crate::sync::window::{
        apply_tombstone_to_window_doc, export_scrubbed_window_snapshot,
        export_tombstone_commit_delta, load_window_from_state, merge_persisted_state_into_doc,
        persist_window_doc_in_txn, rebuild_window_from_updates,
    };
    use loro::CommitOptions;

    let (markers, malformed) = pending_reassert_markers(vault, window_key.as_str())?;
    if markers.is_empty() {
        return Ok(malformed == 0);
    }

    // Live vs transient doc routing — `write_crdt_tombstone`'s dual path.
    let live = manager.window(window_key);
    let (delete_update, snapshot, vv) = match &live {
        Some(window) => {
            // Clobber guard OUTSIDE the materializer lock: importing into
            // an observed doc fires Observer B, which takes the
            // (non-reentrant) lock itself. The commit + exports then run
            // UNDER the lock so a concurrent remote re-put cannot read the
            // tombstones map between this commit and the persist below
            // (mirrors `Vault::write_crdt_tombstone`; lock order
            // materializer → LMDB txn matches every other holder, and the
            // registry lock is NOT held here).
            merge_persisted_state_into_doc(vault, &window.doc, window_key)?;
            let _guard = manager.materializer().lock();
            let vv_before = window.doc.oplog_vv();
            for (_, id, value) in &markers {
                apply_tombstone_to_window_doc(&window.doc, id, value)?;
            }
            // BRIDGE_ORIGIN: Observer B must skip this commit — LMDB
            // already holds the delete truth (`dt:` + the origin purge
            // txn); Observer A still persists/broadcasts as usual.
            window
                .doc
                .commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
            let delete_update = export_tombstone_commit_delta(&window.doc, &vv_before)?;
            (
                delete_update,
                export_scrubbed_window_snapshot(vault, window_key, &window.doc)?,
                doc_version_vector(&window.doc),
            )
        }
        None => {
            // Transient: the loaded doc IS the merge of `d:w:` + pending
            // `u:w:` rows; no observers are attached, so no lock is needed.
            let doc = match load_window_from_state(vault, user_id, window_key) {
                Ok(doc) => doc,
                Err(Error::Sync(SyncError::WindowNotFound { .. })) => {
                    // Same fallback as the rm: drain: a flagged window
                    // without a persisted snapshot can still carry its
                    // tombstones in Observer A's durable update rows.
                    rebuild_window_from_updates(vault, user_id, window_key)?
                }
                Err(err) => return Err(err),
            };
            let vv_before = doc.oplog_vv();
            for (_, id, value) in &markers {
                apply_tombstone_to_window_doc(&doc, id, value)?;
            }
            doc.commit_with(CommitOptions::new().origin(BRIDGE_ORIGIN));
            let delete_update = export_tombstone_commit_delta(&doc, &vv_before)?;
            (
                delete_update,
                export_scrubbed_window_snapshot(vault, window_key, &doc)?,
                doc_version_vector(&doc),
            )
        }
    };

    // ONE transaction: snapshot triple + delete-bearing queue row + marker
    // deletions. An empty delta (every apply was downgrade-blocked / no-op)
    // skips the queue push — nothing new to propagate.
    vault.with_write_txn(|wtxn| {
        persist_window_doc_in_txn(vault, wtxn, window_key, &snapshot, &vv)?;
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
        Ok(())
    })?;

    Ok(malformed == 0)
}

// ─── Test failure injection ──────────────────────────────────────────────────

// Test-only purge failure injection for the rm: round-trip tests. Counts
// down per purge attempt on the current thread (Loro observer callbacks
// fire synchronously on the committing thread).
#[cfg(test)]
thread_local! {
    pub(in crate::sync) static INJECT_PURGE_FAILURES: std::cell::Cell<u32> =
        const { std::cell::Cell::new(0) };
    /// Purge attempts to let THROUGH before [`INJECT_PURGE_FAILURES`] starts
    /// counting down. A batch applies N tombstones under one transaction
    /// (ONE-521), so targeting a specific item — the middle one — needs a
    /// skip count, not just a failure count.
    pub(in crate::sync) static INJECT_PURGE_FAILURES_SKIP: std::cell::Cell<u32> =
        const { std::cell::Cell::new(0) };
}

/// Consumes one purge attempt against the test-only injection hooks,
/// returning the injected error when this attempt is the one to fail.
#[cfg(test)]
fn maybe_inject_purge_failure() -> Result<()> {
    let skipped = INJECT_PURGE_FAILURES_SKIP.with(|cell| {
        let remaining = cell.get();
        if remaining > 0 {
            cell.set(remaining - 1);
            true
        } else {
            false
        }
    });
    if skipped {
        return Ok(());
    }
    let inject = INJECT_PURGE_FAILURES.with(|cell| {
        let remaining = cell.get();
        if remaining > 0 {
            cell.set(remaining - 1);
            true
        } else {
            false
        }
    });
    if inject {
        return Err(Error::Io(std::io::Error::other(
            "injected purge failure (test hook)",
        )));
    }
    Ok(())
}

/// Applies a replayed tombstone on behalf of the sync tombstone paths —
/// the reason-aware primitive ([`Vault::apply_replayed_tombstone`],
/// ONE-1133) is the ONLY effect path, never a bare purge. In test builds a
/// thread-local injection hook can force failures to exercise the rm:
/// marker round-trip.
///
/// This is the ONE-TRANSACTION entry point, for callers that own no write
/// transaction of their own (forward rematerialization's tombstone pass).
/// The batched Observer B path uses
/// [`apply_replayed_tombstone_for_sync_in_txn`] instead.
pub(crate) fn apply_replayed_tombstone_for_sync(
    vault: &Vault,
    id: &crate::entity_id::EntityId,
    raw_value: &[u8],
) -> Result<crate::deletion::ReplayedTombstoneOutcome> {
    #[cfg(test)]
    maybe_inject_purge_failure()?;
    vault.apply_replayed_tombstone_for_sync(id, raw_value)
}

/// [`apply_replayed_tombstone_for_sync`] against a caller-owned transaction
/// (ONE-521): same reason-aware primitive, same test injection, no commit of
/// its own. The caller decides the durability boundary — Observer B's
/// tombstone batch runs each item in a nested savepoint under ONE top-level
/// transaction, so an item's failure rolls back only that item.
pub(in crate::sync) fn apply_replayed_tombstone_for_sync_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &crate::entity_id::EntityId,
    raw_value: &[u8],
) -> Result<crate::deletion::ReplayedTombstoneOutcome> {
    #[cfg(test)]
    maybe_inject_purge_failure()?;
    vault.apply_replayed_tombstone_in_txn(wtxn, id, raw_value)
}
