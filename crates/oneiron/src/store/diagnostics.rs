//! The content-free counters one open vault owns.
//!
//! Engine state belongs to a vault or to a thread, never to the process, and a
//! counter is no exception: the three diagnostic families here used to be
//! process-global atomic arrays, so two vaults open in one process shared one
//! number. That is what flaked #922 — a sibling test in the same
//! `cargo test --lib` binary moved the BM25 counter another test was asserting
//! a delta on, and the assertion had to be loosened to "it moved at all".
//!
//! Each family keeps its counter struct next to the code that records into it
//! ([`crate::bm25`] for index integrity, [`crate::gate`] for decision
//! outcomes, [`crate::attempt_queue`] for lease cleanup); this type is only
//! the per-vault composition that [`super::StoreCore`] holds and hands out.
//! A host that packs several vaults into one process reads per-tenant numbers
//! through `vault.diagnostics()` with no further change.

use crate::attempt_queue::{AttemptQueueCleanupMetrics, AttemptQueueCleanupMetricsSnapshot};
use crate::bm25::{Bm25Diagnostics, Bm25DiagnosticsSnapshot};
use crate::gate::GateMetrics;

/// The diagnostic counters of one open vault.
///
/// Every field is interior-mutable and recorded into through a shared
/// reference, so the store handle hands out `&Diagnostics` and never needs a
/// lock of its own.
#[derive(Default)]
pub struct Diagnostics {
    /// BM25 index-integrity classes (malformed postings, missing scored-doc
    /// metadata, self-healed deindex repairs).
    pub(crate) bm25: Bm25Diagnostics,
    /// Gate outcome x reason-class co-occurrences. No public reader: the gate
    /// snapshot type is gate-internal, so in-crate callers read the field.
    pub(crate) gate: GateMetrics,
    /// Attempt-queue lease-cleanup runs, stale requeues and retry reasons.
    pub(crate) attempt_queue: AttemptQueueCleanupMetrics,
}

impl Diagnostics {
    /// This vault's BM25 index-integrity counters.
    ///
    /// Replaces the deleted process-wide `bm25_diagnostics_snapshot()`: the
    /// numbers are this vault's own, so a second vault open in the same process
    /// cannot move them.
    #[must_use]
    pub fn bm25_snapshot(&self) -> Bm25DiagnosticsSnapshot {
        self.bm25.snapshot()
    }

    /// This vault's attempt-queue lease-cleanup counters.
    ///
    /// Replaces the deleted process-wide
    /// `attempt_queue_cleanup_metrics_snapshot()`.
    #[must_use]
    pub fn attempt_queue_cleanup_snapshot(&self) -> AttemptQueueCleanupMetricsSnapshot {
        self.attempt_queue.snapshot()
    }
}
