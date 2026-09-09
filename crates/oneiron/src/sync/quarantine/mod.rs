//! Quarantine sink (`x:` family) + needs-rematerialization (`rm:`) retry
//! markers — no silent drops on the sync replay surface (ONE-1124).
//!
//! ARCH-0023b stream-class split: REMOTE divergent/malformed state is
//! "QUARANTINED … never silent LWW". Every remote-origin op rejected by a
//! write gate during Observer B materialization or forward
//! re-materialization persists a [`QuarantineRecord`] under
//! `x:{seq:8BE}` in `sync_queue` (db #25) — never a bare log line.
//!
//! The record is GDPR-inert by construction: it carries an `xxh3_64` HASH of
//! the rejected bytes plus metadata, never the bytes themselves. The CRDT
//! map key is attacker-controlled content too, so the record stores
//! `xxh3_64(key)` + byte length — never the key string (and never a prefix:
//! a prefix is still content). The `x:` family therefore does NOT become a
//! byte carrier and does NOT join the ARCH-0038 historical-carrier sweep
//! scope (OWNER-DECISION, see ONE-1124).
//!
//! LOCAL corruption (the engine's own LMDB read errors) is the opposite
//! stream class: a fail-closed typed error, NEVER quarantine-and-continue.
//! `remote_rejection_reason` is the classifier the replay sites use.
//!
//! The `rm:w:{window}:{entity_hex}` marker (ARCH-0023b sync_state
//! needs-rematerialization flag, ENTITY-scoped) is produced when a
//! CRDT-tombstone purge of that specific entity against the local active
//! store fails — a purge failure left hard-deleted content live, which is a
//! GDPR SLA breach signal until drained — when an Observer-B entity/edge
//! materialization batch carrying that entity's op fails as a whole txn
//! (lost create/update writes = silent LMDB↔CRDT divergence), and when an
//! entity/edge replay op is quarantined with no healing write (ONE-1167).
//! A row rejected TERMINALLY — refused by a door that never lets it into any
//! document, so no replay can ever heal it — takes no marker at all; see
//! `TerminalRejectionBatch`.
//! Replay/quarantine-origin markers also carry a sidecar provenance row so
//! terminal `x:` quarantine can discharge only non-delete retry work. An
//! unproven `rm:` row is delete-safety/unknown and must survive terminal
//! entity/edge quarantine. The marker is cleared ONLY by that entity's own
//! success — its purge for tombstoned ids, the actual healing write (entity
//! body / edge from that source) in forward remat, or terminal quarantine
//! when replay provenance already proves the marker is non-delete; never
//! byte-parity alone, and never an unrelated entity's success.
//! [`drain_remat_markers`] re-runs `forward_rematerialize` for each flagged
//! window. A row under `rm:` that does not parse is fail-closed: it is
//! treated as needs-remat and never dropped.

mod keys_classifier;
mod reassert_drain;
mod remat_markers;
mod retention_reports;
mod writes_batch;

#[cfg(test)]
mod tests;

pub use self::keys_classifier::{
    MAX_QUARANTINE_ROWS, MAX_QUARANTINE_ROWS_PER_PASS, QUARANTINE_MAX_AGE_SECS,
    QuarantineContainer, QuarantineRecord,
};
pub use self::reassert_drain::{
    ReassertDrainReport, drain_reassert_markers, pending_reassert_windows,
};
pub use self::remat_markers::{RematDrainReport, drain_remat_markers, pending_remat_windows};
pub use self::retention_reports::{SyncQuarantineReport, quarantined_records, sync_doctor};

pub(in crate::sync) use self::keys_classifier::reason_code_for;
pub(crate) use self::keys_classifier::{crdt_key_metadata, payload_hash, remote_rejection_reason};
pub(crate) use self::reassert_drain::apply_replayed_tombstone_for_sync;
pub(in crate::sync) use self::reassert_drain::{
    apply_replayed_tombstone_for_sync_in_txn, drain_reassert_markers_for_window,
    enqueue_tombstone_reassert_marker, enqueue_tombstone_reassert_marker_in_txn,
};
pub(crate) use self::remat_markers::pending_remat_entities;
pub(in crate::sync) use self::remat_markers::{
    clear_remat_marker_in_txn, clear_replay_remat_marker_in_txn, set_remat_marker_in_txn,
    set_replay_remat_marker, set_replay_remat_marker_in_txn, unproven_remat_marker_exists_in_txn,
};
// QUARANTINE_PREFIX, QUARANTINE_BATCH_DROPS_KEY and reassert_marker_key keep
// their definitions in the children but take no seam re-export: nothing
// outside this module names those paths, and an unreferenced `pub(crate)`
// re-export would trip `unused_imports` under the workspace `-D warnings`.
pub(crate) use self::retention_reports::expire_stale_rows;
pub(in crate::sync) use self::writes_batch::{
    TerminalRejectionBatch, quarantine_rejected_op, quarantine_rejected_op_in_txn, record_in_txn,
    remat_marker_entity_for_quarantine,
};

#[cfg(test)]
pub(in crate::sync) use self::reassert_drain::{INJECT_PURGE_FAILURES, INJECT_PURGE_FAILURES_SKIP};
// Test-only paths (named from `*_tests.rs` / `tests.rs` suites, never from
// shipped code): same `gate/mod.rs` precedent — gate them `cfg(test)` so the
// plain-lib build sees no unreferenced re-export.
#[cfg(test)]
use self::keys_classifier::decode_quarantine_seq;
#[cfg(test)]
pub(in crate::sync) use self::keys_classifier::{
    LAST_QUARANTINE_SEQ_KEY, QUARANTINE_EVICTIONS_KEY, encode_quarantine_key,
};
#[cfg(test)]
use self::remat_markers::{remat_marker_key, set_remat_marker};

// The pre-existing `tests.rs` sibling resolves names through `use super::*`:
// its own import header plus every quarantine-internal item the tests name
// bare, plus the old flat module's private import header (`xxh3_64`, `Error`,
// `WindowKey`) which `super::*` used to surface. The seam re-imports the
// private ones here so `tests.rs` resolves exactly as it did before the
// split.
#[cfg(test)]
use self::{
    remat_markers::replay_remat_marker_provenance_key, retention_reports::enforce_retention_in_txn,
};
#[cfg(test)]
use crate::error::Error;
#[cfg(test)]
use crate::sync::types::WindowKey;
#[cfg(test)]
use xxhash_rust::xxh3::xxh3_64;
