//! ARCH-0038 historical-carrier sweep executor — ONE-1087 / ONE-1091
//! phase 1 (manual trigger via [`crate::maintain::MaintenanceBuilder`]).
//!
//! The hard-delete path erases the ACTIVE carriers in the delete
//! transaction itself and queues a durable `h:{seq:8BE}` obligation row for
//! the HISTORICAL carriers — the persisted Loro op-history that still
//! embeds the erased payload bytes (`d:w:{key}` full snapshots above all,
//! plus the `u:w:{key}:{seq:08x}` incremental rows). This module is the
//! consumer of those rows.
//!
//! # Mechanism (OWNER-DECISION, ONE-1087 design)
//!
//! Each persisted window doc is rebuilt through a **Loro shallow snapshot
//! at its own latest frontiers** (`ExportMode::shallow_snapshot`): the live
//! state survives byte-exactly, the op history before the frontier — the
//! dominant residual byte carrier — is dropped, and, critically, the doc
//! IDENTITY and version vector are preserved. The rejected alternative (a
//! fresh doc rebuilt from live state) shares zero history with every peer
//! replica, so the first post-sweep delta exchange would re-import the
//! ENTIRE pre-sweep history — erased payload included — and silently undo
//! the sweep. With the shallow snapshot, peer echoes of pre-sweep ops are
//! VV-dominated no-ops and the dropped history can never be re-imported.
//!
//! Wire/SLA implication (pinned): a swept window can no longer SERVE
//! deltas to peers behind the shallow start (the ops are gone), so the
//! sweep re-asserts the `fr:w:{key}` full-resync marker (ONE-1135) in the
//! same transaction that replaces the snapshot — peers heal through a full
//! window resync, never through a partial delta.
//!
//! # Scope (pinned)
//!
//! * Sweep targets: `d:w:` snapshots + the `u:w:` rows each rebuilt
//!   snapshot subsumes, plus §8c.2 live-map residue (see below). Receipts,
//!   `dt:` markers and tombstones are PERMANENT — never swept. Orphan
//!   `d:{seq}` markers are inert fail-closed blockers — GC is not phase 1.
//!   General `u:w:` pruning on snapshot persist is ONE-1151 (separate).
//! * ALL persisted windows are compacted, not just tombstone-bearing ones:
//!   discovery would have to load every window doc anyway, and compacting
//!   everything is strictly safer (it also clears crafted cross-window
//!   history residue) at the same read cost.
//! * §8c.2 cross-node live-map residue: a concurrent re-put can win LWW
//!   over the tombstone commit's entities-key delete, leaving the erased
//!   payload LIVE in the map (gated from LMDB by the `dt:` marker, but
//!   still a carrier). Before each shallow export the executor removes
//!   every entities/edges map key referencing an erased id. The erased-id
//!   authority is the union of the permanent `dt:` marker set and the
//!   pending jobs' scopes — which also covers §8c.3 (receiver nodes that
//!   never materialized the entity: `dt:` exists, NO `h:` row and NO
//!   receipt; their obligation is carrier-scrub only, and the compaction
//!   pass handles it without a job).
//!
//! # Crash safety / completion gate (pinned)
//!
//! Per-window compaction commits in its own transaction (snapshot replace +
//! subsumed-row prune + `fr:w:` marker are atomic per window). Receipt
//! finalization + `h:` row deletion happen LAST, in one transaction per
//! job — a crash anywhere before that leaves the obligation row in place,
//! and the re-run is idempotent (shallow-of-shallow is a no-op rebuild).
//! The completion gate is fail-closed and GLOBAL: a job is finalized only
//! in a run where EVERY persisted window compacted successfully and none
//! was deferred — id→window attribution cannot be trusted when any window
//! is unreadable (a corrupt window might carry anything).
//!
//! * OPEN (registry-live) windows are DEFERRED, never compacted in place: a
//!   live doc holds the full history in memory, and its next
//!   `persist_state` full-snapshot export would rewrite the history over
//!   the shallow `d:w:` row — resurrecting the carrier.
//! * RACED windows are DEFERRED (anti-clobber): if a `u:w:` row is
//!   added/removed (full set-equality check) or the `d:w:` snapshot is
//!   replaced between the read phase and the compaction write txn, the
//!   write txn is ABORTED uncommitted — never overwriting a newer carrier —
//!   and the run defers. A quiesced re-run compacts cleanly.
//! * Builds WITHOUT the `sync` feature fail closed: if any CRDT carrier
//!   rows exist (`d:w:`/`u:w:`/`q:`), every job is deferred loudly (the
//!   executor cannot parse Loro docs without the feature). A vault that
//!   never ran sync has no historical CRDT carriers, so its jobs finalize.
//! * Undecodable `h:` rows are KEPT and reported loudly — an erasure
//!   obligation is never deleted unexecuted, never "quarantined away".
//! * A job whose `scope.entity_ids` carries an unparsable hex is KEPT
//!   BYTE-IDENTICAL and reported (never compacted-and-finalized) — wrong
//!   id→window attribution must never delete an obligation row.
//! * An undecodable REDACTION_AUDIT receipt body encountered during a job's
//!   finalize txn ABORTS that txn (typed `CorruptedIndex` — the `h:` row is
//!   kept, all-or-nothing) and routes ONE job to retry; the audit pass
//!   counts unreadable receipts in `obligations_undecodable` (a SIBLING of
//!   `obligations_missing`, never folded in).
//!
//! # Receipt finalization (pinned)
//!
//! `sweep_complete_at` None→Some on the OWN node's receipt is the single
//! sanctioned mutation of the otherwise-immutable REDACTION_AUDIT record.
//! It is LOCAL-LMDB-ONLY: the CRDT mirror keeps the pre-finalization bytes
//! (replicated receipt copies are informational; GDPR Art. 5(2)
//! accountability lives on the node that erased). The replay doors get the
//! matching narrow exception — see
//! [`crate::deletion::redaction_receipt_is_stale_finalization_echo`].
//! The rewritten body is re-validated against the pinned field set before
//! the put, and the 25 B entity envelope is preserved byte-exactly.
//!
//! # Audit path (ONE-1091)
//!
//! After processing, every receipt with `sweep_queued_at` set and
//! `sweep_complete_at` still nil must be covered by a pending `h:` row
//! whose scope contains the receipt's scope — a dropped obligation (e.g. a
//! manually deleted row) is surfaced as `sweep_obligations_missing` plus a
//! `tracing::error`, never silent. `SyncQueue::clear_all` re-bootstrap
//! already preserves `h:` rows byte-identically (ONE-1091 residual).

mod compact;
mod finalize;
mod run;

pub(crate) use self::run::run_hard_erase_sweep;

#[cfg(test)]
mod tests;

// The flat sweep.rs module used to provide these names to the sibling test
// module through `use super::*`: every sweep-internal item the tests name
// bare (via the child glob below — the tests only name `run` items in code),
// and sweep's own private crate/std import header. After the directory split
// the seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(all(feature = "sync", test))]
use self::run::*;
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::deletion::{
    HARD_ERASE_SWEEP_PREFIX, decode_redaction_audit_receipt, validate_redaction_receipt_body,
};
#[cfg(all(feature = "sync", test))]
use crate::deletion::{decode_hard_erase_sweep_job, encode_hard_erase_sweep_job_value};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(all(feature = "sync", test))]
use crate::error::Error;
#[cfg(test)]
use crate::registry::ENTITY_TYPE_REDACTION_AUDIT;
