//! rm: marker keys, setters/clears, pending scans plus drain.

use std::sync::Arc;

use crate::Vault;
use crate::error::{Error, Result, SyncError};
use crate::sync::bridge::Materializer;
use crate::sync::types::{WindowKey, parse_window_key_str};
use crate::sync::window_rows::{
    REMAT_DEPENDENCY_HOLD_START, REMAT_MARKER, REPLAY_REMAT_MARKER_PROVENANCE, WindowEntityHexKey,
};

fn window_entity_key(window_key: &str, id: &crate::entity_id::EntityId) -> WindowEntityHexKey {
    WindowEntityHexKey {
        window: window_key.to_owned(),
        id: *id,
    }
}

/// Prefix for needs-rematerialization markers in `sync_state`. Full key
/// grammar (ONE-1124 fix wave 2, entity-scoped):
/// `rm:w:{window}:{entity_hex}` → `1 byte (marker)`, where `window` is
/// `YYYY-MM` and `entity_hex` is the 32-char lowercase entity id.
const REMAT_MARKER_PREFIX: &str = "rm:w:";

/// Sidecar provenance for `rm:w:` markers created by replay/quarantine
/// surfaces, not by delete-safety purge failures. Absence means unknown and
/// therefore fail-closed as delete-safety for terminal quarantine clearing.
///
/// Production reads/writes go through the typed
/// [`REPLAY_REMAT_MARKER_PROVENANCE`] table; this raw prefix stays only for
/// [`replay_remat_marker_provenance_key`]'s test-only raw-byte seam.
#[cfg(test)]
const REPLAY_REMAT_MARKER_PROVENANCE_PREFIX: &str = "rmp:w:";

// ─── rm: needs-rematerialization markers ─────────────────────────────────────

/// Formats the entity-scoped needs-rematerialization marker key:
/// `rm:w:{window}:{entity_hex}` (32-char lowercase hex). Entity-scoped so
/// an unrelated entity's successful purge can never discharge another
/// entity's GDPR purge retry.
///
/// Production reads and writes go through the typed `REMAT_MARKER` table;
/// this raw string builder stays only for this module's own tests, which
/// address the row directly through raw `sync_state` access.
#[cfg(test)]
#[must_use]
pub(super) fn remat_marker_key(window_key: &str, id: &crate::entity_id::EntityId) -> String {
    format!("{REMAT_MARKER_PREFIX}{window_key}:{}", id.to_hex())
}

/// See [`remat_marker_key`]: production goes through
/// [`REPLAY_REMAT_MARKER_PROVENANCE`], this stays for this module's tests.
#[cfg(test)]
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
    let key = window_entity_key(window_key, id);
    REMAT_MARKER.put(&vault.store, wtxn, &key, &[1u8])?;
    REPLAY_REMAT_MARKER_PROVENANCE.delete(&vault.store, wtxn, &key)?;
    Ok(())
}

/// Sets `rm:w:{window}:{entity_hex}` in its own write transaction.
#[cfg_attr(not(test), allow(dead_code))] // batch path writes markers in-txn (ONE-521)
pub(super) fn set_remat_marker(
    vault: &Vault,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| set_remat_marker_in_txn(vault, wtxn, window_key, id))
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
    let key = window_entity_key(window_key, id);
    let marker_present = REMAT_MARKER.contains(&vault.store, wtxn, &key)?;
    let replay_provenance_present =
        REPLAY_REMAT_MARKER_PROVENANCE.contains(&vault.store, wtxn, &key)?;

    REMAT_MARKER.put(&vault.store, wtxn, &key, &[1u8])?;
    if !marker_present || replay_provenance_present {
        REPLAY_REMAT_MARKER_PROVENANCE.put(&vault.store, wtxn, &key, &[1u8])?;
    }
    Ok(())
}

/// Sets a replay marker and, only if no marker stood, starts the hold for a parent project
/// or the message a project was born from that this replica does not hold yet.
/// An existing marker keeps its start; if it has no start (such as an older binary's
/// marker or a batch-rollback replay marker), the hold reads as a breach.
pub(in crate::sync) fn set_project_dependency_hold_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::entity_id::EntityId,
    mutation_recorded_at: u64,
) -> Result<()> {
    let key = window_entity_key(window_key, id);
    let marker_present = REMAT_MARKER.contains(&vault.store, wtxn, &key)?;
    set_replay_remat_marker_in_txn(vault, wtxn, window_key, id)?;
    if !marker_present {
        REMAT_DEPENDENCY_HOLD_START.put(
            &vault.store,
            wtxn,
            &key,
            &mutation_recorded_at.to_le_bytes(),
        )?;
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
    vault.with_write_txn_grouped(|wtxn| set_replay_remat_marker_in_txn(vault, wtxn, window_key, id))
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
    let key = window_entity_key(window_key, id);
    REMAT_MARKER.delete(&vault.store, wtxn, &key)?;
    REPLAY_REMAT_MARKER_PROVENANCE.delete(&vault.store, wtxn, &key)?;
    REMAT_DEPENDENCY_HOLD_START.delete(&vault.store, wtxn, &key)?;
    Ok(())
}

/// True when an `rm:` marker is present without replay/quarantine
/// provenance. Terminal quarantine must treat this as delete-safety/unknown
/// provenance and leave it pending until the entity's tombstone goal holds.
pub(crate) fn unproven_remat_marker_exists_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<bool> {
    let key = window_entity_key(window_key, id);
    Ok(REMAT_MARKER.contains(&vault.store, wtxn, &key)?
        && !REPLAY_REMAT_MARKER_PROVENANCE.contains(&vault.store, wtxn, &key)?)
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
    let key = window_entity_key(window_key, id);
    if !REPLAY_REMAT_MARKER_PROVENANCE.contains(&vault.store, wtxn, &key)? {
        return Ok(false);
    }
    REMAT_MARKER.delete(&vault.store, wtxn, &key)?;
    REPLAY_REMAT_MARKER_PROVENANCE.delete(&vault.store, wtxn, &key)?;
    REMAT_DEPENDENCY_HOLD_START.delete(&vault.store, wtxn, &key)?;
    Ok(true)
}

/// [`clear_replay_remat_marker_in_txn`] for an edge wait that settled (its
/// edge written, ignored or quarantined), except that a marker carrying an
/// entity's dependency hold start stays, start and all: the edge and the
/// entity share the marker, and only the entity's own settlement (its healing
/// write, a terminal refusal or its tombstone's purge) discharges the hold and
/// its clock (review round 2 of #10565).
pub(in crate::sync) fn clear_edge_wait_remat_marker_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    window_key: &str,
    id: &crate::entity_id::EntityId,
) -> Result<bool> {
    let key = window_entity_key(window_key, id);
    if REMAT_DEPENDENCY_HOLD_START.contains(&vault.store, wtxn, &key)? {
        return Ok(false);
    }
    clear_replay_remat_marker_in_txn(vault, wtxn, window_key, id)
}

/// Lists DISTINCT windows currently flagged needs-rematerialization.
///
/// Fail closed: a row under `rm:` that is missing the entity segment (or
/// otherwise does not parse) is still surfaced — its whole remainder is
/// reported as the pending window. A needs-remat row is never dropped by a
/// read.
///
/// Deliberately RAW `sync_state` access (not `REMAT_MARKER`): the typed
/// door's key decode either succeeds or turns the whole scan into an `Err`,
/// and this reader's contract is the opposite — a key that fails to parse is
/// still surfaced (as its own best-effort "window"), never dropped and never
/// aborting the read of every OTHER window's markers.
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
///
/// Deliberately RAW `sync_state` access — see [`pending_remat_windows`].
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

/// How one window's surviving `rm:` markers read after a forward pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WindowMarkerClass {
    /// No marker row at all survives for the window.
    NonePending,
    /// Every survivor is a proven replay marker for an id the caller still
    /// waits on, with a hold start inside the allowed age.
    AllMatch,
    /// Any other survivor, including a missing, malformed, or expired hold start.
    Unclassified,
}

/// Classifies one window's surviving `rm:` markers in one read
/// transaction: `NonePending` when no row survives, `AllMatch` when every
/// row is a canonical replay marker with exact provenance whose id the caller
/// still waits on. A present id that still owes an edge wait sourced at it,
/// a missing or malformed hold start, a start in the future,
/// or an age over `sync.remat.dependency_hold_max_secs` is a breach
/// (`Unclassified`), as is any other survivor that does not match.
/// Raw marker iteration lets malformed rows classify as breaches, not read errors.
/// The age is measured against the vault's committed clock floor (or this
/// store's clock if later), the same floor the hold start was stamped from,
/// so a clock that steps back never reads a fresh hold as one in the future.
pub(crate) fn classify_window_markers(
    vault: &Vault,
    window_key: &str,
    matches: impl Fn(crate::entity_id::EntityId) -> bool,
) -> Result<WindowMarkerClass> {
    let rtxn = vault.store.env.read_txn()?;
    let now = crate::ports::job_recorded_at_in_txn(&vault.store, &rtxn)?;
    let exact = format!("{REMAT_MARKER_PREFIX}{window_key}");
    if vault.store.sync_state.get(&rtxn, &exact)?.is_some() {
        return Ok(WindowMarkerClass::Unclassified);
    }
    let prefix = format!("{REMAT_MARKER_PREFIX}{window_key}:");
    let mut any = false;
    let mut max_hold_secs = None;
    for entry in vault.store.sync_state.prefix_iter(&rtxn, &prefix)? {
        let (key, value) = entry?;
        any = true;
        let suffix = &key[prefix.len()..];
        let matched = crate::entity_id::EntityId::from_hex(suffix)
            .ok()
            .filter(|id| id.to_hex() == suffix);
        let Some(id) = matched else {
            return Ok(WindowMarkerClass::Unclassified);
        };
        if &*value != [1u8].as_slice() {
            return Ok(WindowMarkerClass::Unclassified);
        }
        let entity_key = window_entity_key(window_key, &id);
        let sidecar = REPLAY_REMAT_MARKER_PROVENANCE.get_bytes(&vault.store, &rtxn, &entity_key)?;
        if sidecar.as_deref() != Some([1u8].as_slice()) {
            return Ok(WindowMarkerClass::Unclassified);
        }
        if !matches(id) {
            return Ok(WindowMarkerClass::Unclassified);
        }
        // An id this replica already holds (an older revision) that still owes
        // an edge wait sourced at it waits on more than its own missing
        // dependency: that wait vetoes the hold (review round 2 of #10565).
        // While the id itself is absent, every edge sourced at it waits on it
        // first; a wait that outlasts its landing vetoes from then on.
        if crate::ports::EntityStoreRead::port_entity_present(&vault.store, &rtxn, &id)?
            && crate::sync::bridge::has_pending_source_in_txn(vault, &rtxn, window_key, &id)?
        {
            return Ok(WindowMarkerClass::Unclassified);
        }
        let Some(age) = REMAT_DEPENDENCY_HOLD_START
            .get_lenient(&vault.store, &rtxn, &entity_key)?
            .and_then(|bytes| now.checked_sub(u64::from_le_bytes(bytes)))
        else {
            return Ok(WindowMarkerClass::Unclassified);
        };
        let max = match max_hold_secs {
            Some(max) => max,
            None => {
                let max = crate::deletion::setting_keys::REMAT_DEPENDENCY_HOLD_MAX_SECS
                    .read_in_txn(vault, &rtxn, &[], None)?
                    .value;
                max_hold_secs = Some(max);
                max
            }
        };
        if age > max {
            return Ok(WindowMarkerClass::Unclassified);
        }
    }
    if any {
        Ok(WindowMarkerClass::AllMatch)
    } else {
        Ok(WindowMarkerClass::NonePending)
    }
}

/// Outcome of a [`drain_remat_markers`] pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RematDrainReport {
    /// Windows whose markers ALL cleared (every flagged entity's purge
    /// succeeded).
    pub drained: Vec<String>,
    /// Windows still flagged after the pass whose every surviving marker is a
    /// bounded project-dependency hold (the forward pass logged its WARN):
    /// WARN-grade, tried again by the next drain; past
    /// `sync.remat.dependency_hold_max_secs` such a window moves to `still_pending`.
    pub held: Vec<String>,
    /// Windows still flagged after the pass that do not qualify as held.
    /// A purge may keep failing, the flagged entity's tombstone may be missing
    /// from the loaded doc, or a marker row may not parse (fail closed).
    /// ERROR-grade: hard-deleted content may still be live locally.
    pub still_pending: Vec<String>,
}

/// Drains `rm:` markers by re-running `forward_rematerialize` for each
/// flagged window. Each entity-scoped marker is cleared (inside
/// `forward_rematerialize`) only when that entity's own purge succeeds —
/// or, for ONE-1147 batch-failure markers, when its actual healing write
/// lands. A window with any surviving marker stays flagged. Windows with only
/// bounded project-dependency holds after a clean pass are reported in `held`;
/// other flagged windows are reported in `still_pending`.
pub fn drain_remat_markers(
    vault: &Arc<Vault>,
    user_id: &str,
    materializer: &Arc<Materializer>,
) -> Result<RematDrainReport> {
    drain_remat_windows(vault, user_id, materializer, pending_remat_windows(vault)?)
}

/// [`drain_remat_markers`] for `window` alone, when it is flagged: the rows
/// it holds back on a local dependency are tried again once that dependency
/// may have cleared (OF-370: a move here ended under the setup window).
pub(in crate::sync) fn drain_remat_markers_of(
    vault: &Arc<Vault>,
    user_id: &str,
    materializer: &Arc<Materializer>,
    window: &WindowKey,
) -> Result<RematDrainReport> {
    let flagged = pending_remat_windows(vault)?
        .into_iter()
        .filter(|flagged| flagged == window.as_str())
        .collect();
    drain_remat_windows(vault, user_id, materializer, flagged)
}

fn drain_remat_windows(
    vault: &Arc<Vault>,
    user_id: &str,
    materializer: &Arc<Materializer>,
    windows: Vec<String>,
) -> Result<RematDrainReport> {
    let mut report = RematDrainReport::default();
    for window in windows {
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
            Err(Error::Sync(SyncError::WindowNotFound { .. })) => {
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
        let (_, verdict) = crate::sync::window::forward_rematerialize_classified(
            vault,
            &doc,
            materializer,
            &window_key,
        )?;
        // One read after the pass decides (review round 1 of #10565): a
        // replay that settles the window between two reads can never turn a
        // drained window into a breach.
        match classify_window_markers(vault, &window, |_| true)? {
            WindowMarkerClass::NonePending => report.drained.push(window),
            WindowMarkerClass::AllMatch if verdict == Some(WindowMarkerClass::AllMatch) => {
                report.held.push(window);
            }
            WindowMarkerClass::AllMatch | WindowMarkerClass::Unclassified => {
                tracing::error!(
                    window = %window,
                    "rm drain: tombstone purge still failing — hard-deleted content may be live (GDPR SLA breach signal)"
                );
                report.still_pending.push(window);
            }
        }
    }
    Ok(report)
}
