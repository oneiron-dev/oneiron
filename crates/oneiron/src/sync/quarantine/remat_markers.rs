//! rm: marker keys, setters/clears, pending scans plus drain.

use std::sync::Arc;

use crate::Vault;
use crate::error::{Error, Result};
use crate::sync::bridge::Materializer;
use crate::sync::types::{WindowKey, parse_window_key_str};

/// Prefix for needs-rematerialization markers in `sync_state`. Full key
/// grammar (ONE-1124 fix wave 2, entity-scoped):
/// `rm:w:{window}:{entity_hex}` → `1 byte (marker)`, where `window` is
/// `YYYY-MM` and `entity_hex` is the 32-char lowercase entity id.
const REMAT_MARKER_PREFIX: &str = "rm:w:";

/// Sidecar provenance for `rm:w:` markers created by replay/quarantine
/// surfaces, not by delete-safety purge failures. Absence means unknown and
/// therefore fail-closed as delete-safety for terminal quarantine clearing.
const REPLAY_REMAT_MARKER_PROVENANCE_PREFIX: &str = "rmp:w:";

// ─── rm: needs-rematerialization markers ─────────────────────────────────────

/// Formats the entity-scoped needs-rematerialization marker key:
/// `rm:w:{window}:{entity_hex}` (32-char lowercase hex). Entity-scoped so
/// an unrelated entity's successful purge can never discharge another
/// entity's GDPR purge retry.
#[must_use]
pub(super) fn remat_marker_key(window_key: &str, id: &crate::entity_id::EntityId) -> String {
    format!("{REMAT_MARKER_PREFIX}{window_key}:{}", id.to_hex())
}

pub(super) fn replay_remat_marker_provenance_key(
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> String {
    format!(
        "{REPLAY_REMAT_MARKER_PROVENANCE_PREFIX}{window_key}:{}",
        id.to_hex()
    )
}

/// Sets `rm:w:{window}:{entity_hex}` (1-byte marker) in `sync_state` inside
/// an existing write transaction. Written when THAT entity's CRDT-tombstone
/// purge (or the read backing it) against the local active store fails.
/// Deletes any replay provenance sidecar so a later terminal `x:` row cannot
/// discharge delete-safety work without the entity's own tombstone success.
pub(in crate::sync) fn set_remat_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<()> {
    let marker_key = remat_marker_key(window_key, id);
    let provenance_key = replay_remat_marker_provenance_key(window_key, id);
    vault.store.sync_state.put(wtxn, &marker_key, &[1u8])?;
    vault.store.sync_state.delete(wtxn, &provenance_key)?;
    Ok(())
}

/// Sets `rm:w:{window}:{entity_hex}` in its own write transaction.
#[cfg_attr(not(test), allow(dead_code))] // batch path writes markers in-txn (ONE-521)
pub(super) fn set_remat_marker(
    vault: &Vault,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<()> {
    vault.with_write_txn(|wtxn| set_remat_marker_in_txn(vault, wtxn, window_key, id))
}

/// Sets a replay/quarantine-origin `rm:w:{window}:{entity_hex}` marker plus
/// provenance sidecar. If an unproven marker already exists, preserve that
/// stronger delete-safety/unknown provenance and do not add the sidecar.
pub(in crate::sync) fn set_replay_remat_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<()> {
    let marker_key = remat_marker_key(window_key, id);
    let provenance_key = replay_remat_marker_provenance_key(window_key, id);
    let marker_present = vault.store.sync_state.get(wtxn, &marker_key)?.is_some();
    let replay_provenance_present = vault.store.sync_state.get(wtxn, &provenance_key)?.is_some();

    vault.store.sync_state.put(wtxn, &marker_key, &[1u8])?;
    if !marker_present || replay_provenance_present {
        vault.store.sync_state.put(wtxn, &provenance_key, &[1u8])?;
    }
    Ok(())
}

/// Sets a replay/quarantine-origin `rm:w:{window}:{entity_hex}` marker in
/// its own write transaction.
pub(in crate::sync) fn set_replay_remat_marker(
    vault: &Vault,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<()> {
    vault.with_write_txn(|wtxn| set_replay_remat_marker_in_txn(vault, wtxn, window_key, id))
}

/// Clears `rm:w:{window}:{entity_hex}` inside an existing write
/// transaction. Only called when THAT entity's purge succeeded (or the
/// entity is verifiably absent — the purge goal state), or when forward
/// remat performed the actual healing write for that entity (ONE-1147).
pub(in crate::sync) fn clear_remat_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<()> {
    let marker_key = remat_marker_key(window_key, id);
    let provenance_key = replay_remat_marker_provenance_key(window_key, id);
    vault.store.sync_state.delete(wtxn, &marker_key)?;
    vault.store.sync_state.delete(wtxn, &provenance_key)?;
    Ok(())
}

/// True when an `rm:` marker is present without replay/quarantine
/// provenance. Terminal quarantine must treat this as delete-safety/unknown
/// provenance and leave it pending until the entity's tombstone goal holds.
pub(in crate::sync) fn unproven_remat_marker_exists_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<bool> {
    let marker_key = remat_marker_key(window_key, id);
    let provenance_key = replay_remat_marker_provenance_key(window_key, id);
    Ok(vault.store.sync_state.get(wtxn, &marker_key)?.is_some()
        && vault.store.sync_state.get(wtxn, &provenance_key)?.is_none())
}

/// Clears a marker only when its sidecar proves replay/quarantine origin.
/// Unproven markers survive terminal quarantine because they may represent
/// delete-safety work from a failed tombstone purge.
pub(in crate::sync) fn clear_replay_remat_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<bool> {
    let provenance_key = replay_remat_marker_provenance_key(window_key, id);
    if vault.store.sync_state.get(wtxn, &provenance_key)?.is_none() {
        return Ok(false);
    }
    let marker_key = remat_marker_key(window_key, id);
    vault.store.sync_state.delete(wtxn, &marker_key)?;
    vault.store.sync_state.delete(wtxn, &provenance_key)?;
    Ok(true)
}

/// Lists DISTINCT windows currently flagged needs-rematerialization.
///
/// Fail closed: a row under `rm:` that is missing the entity segment (or
/// otherwise does not parse) is still surfaced — its whole remainder is
/// reported as the pending window. A needs-remat row is never dropped by a
/// read.
pub fn pending_remat_windows(vault: &Vault) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut windows = std::collections::BTreeSet::new();
    let iter = vault
        .store
        .sync_state
        .prefix_iter(&rtxn, REMAT_MARKER_PREFIX)?;
    for entry in iter {
        let (key, _) = entry?;
        let rest = &key[REMAT_MARKER_PREFIX.len()..];
        let window = match rest.split_once(':') {
            Some((window, _entity_hex)) => window,
            None => rest,
        };
        windows.insert(window.to_string());
    }
    Ok(windows.into_iter().collect())
}

/// Entity-hex segments of the `rm:w:{window}:{entity_hex}` markers for one
/// window. Rows whose entity segment is malformed are returned verbatim
/// (fail closed — never dropped); they can never be cleared by an
/// entity-scoped purge success and stay doctor-visible.
pub(crate) fn pending_remat_entities(vault: &Vault, window_key: &str) -> Result<Vec<String>> {
    let rtxn = vault.store.env.read_txn()?;
    let prefix = format!("{REMAT_MARKER_PREFIX}{window_key}:");
    let mut entities = Vec::new();
    let iter = vault.store.sync_state.prefix_iter(&rtxn, &prefix)?;
    for entry in iter {
        let (key, _) = entry?;
        entities.push(key[prefix.len()..].to_string());
    }
    Ok(entities)
}

/// Outcome of a [`drain_remat_markers`] pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RematDrainReport {
    /// Windows whose markers ALL cleared (every flagged entity's purge
    /// succeeded).
    pub drained: Vec<String>,
    /// Windows with at least one marker still set after the pass — a purge
    /// keeps failing, the flagged entity's tombstone is missing from the
    /// loaded doc, or a marker row does not parse (fail closed).
    /// ERROR-grade: hard-deleted content may still be live locally.
    pub still_pending: Vec<String>,
}

/// Drains `rm:` markers by re-running `forward_rematerialize` for each
/// flagged window. Each entity-scoped marker is cleared (inside
/// `forward_rematerialize`) only when that entity's own purge succeeds —
/// or, for ONE-1147 batch-failure markers, when its actual healing write
/// lands; a window with any surviving marker stays flagged and is reported
/// in `still_pending`.
pub fn drain_remat_markers(
    vault: &Arc<Vault>,
    user_id: &str,
    materializer: &Arc<Materializer>,
) -> Result<RematDrainReport> {
    let mut report = RematDrainReport::default();
    for window in pending_remat_windows(vault)? {
        if parse_window_key_str(&window).is_none() {
            tracing::error!(
                window = %window,
                "rm drain: malformed marker window key — cannot rematerialize, marker kept"
            );
            report.still_pending.push(window);
            continue;
        }
        let window_key = WindowKey::new(window.clone());
        let doc = match crate::sync::window::load_window_from_state(vault, user_id, &window_key) {
            Ok(doc) => doc,
            Err(Error::WindowNotFound { .. }) => {
                // No persisted snapshot (d:w: absent) — rebuild from
                // Observer A's durable update rows (u:w:) so the tombstone
                // whose purge failed can still be drained; otherwise a
                // hard-deleted entity stays live indefinitely behind the
                // missing snapshot. Fail closed: an empty rebuild carries
                // zero tombstones and `forward_rematerialize` keeps the
                // marker for such a doc.
                tracing::warn!(
                    window = %window,
                    "rm drain: no persisted doc for flagged window — rebuilding from pending update rows"
                );
                crate::sync::window::rebuild_window_from_updates(vault, user_id, &window_key)?
            }
            Err(err) => return Err(err),
        };
        crate::sync::window::forward_rematerialize(vault, &doc, materializer, &window_key)?;
        let still_flagged = pending_remat_windows(vault)?.contains(&window);
        if still_flagged {
            tracing::error!(
                window = %window,
                "rm drain: tombstone purge still failing — hard-deleted content may be live (GDPR SLA breach signal)"
            );
            report.still_pending.push(window);
        } else {
            report.drained.push(window);
        }
    }
    Ok(report)
}
