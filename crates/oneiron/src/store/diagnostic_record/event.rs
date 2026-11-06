//! Core half of `store::diagnostic_record::event`: its store-layer items live in `oneiron_store::diagnostic_record::event` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::diagnostic_record::event::*;

use crate::entity_id::EntityId;
use crate::error::{Error, RecordError};
use rmpv::Value;

/// One observed input fact a detector may consult.
///
/// The sole element type of the working set, so its shape and ordering are what
/// "same ordered input yields identical events" MEANS. `payload_digest` is a
/// digest of the canonical source bytes and never the bytes themselves: the
/// working set is an index into evidence, not a second copy of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticObservation {
    /// The entity/receipt/row the fact came from.
    pub source_ref: EntityId,
    /// Closed per-detector vocabulary token, e.g. `"receipt"`, `"retr_run"`.
    pub kind: &'static str,
    /// Digest of the canonical source bytes.
    pub payload_digest: [u8; 32],
    /// When the fact was observed (unix seconds).
    pub observed_at: u64,
}

impl DiagnosticObservation {
    /// The PINNED ordering key: `(observed_at, source_ref, payload_digest)`.
    pub(crate) fn order_key(&self) -> (u64, EntityId, [u8; 32]) {
        (self.observed_at, self.source_ref, self.payload_digest)
    }
}

/// A bounded, scoped, pinned-order slice of observations.
///
/// The caller builds it from a scoped read; this layer never widens it.
#[derive(Debug, Clone, Copy)]
pub struct DiagnosticWorkingSet<'a> {
    /// Opaque label for the scope the caller read under.
    pub scope_ref: &'a str,
    /// Observations in strictly ascending
    /// `(observed_at, source_ref, payload_digest)` order.
    pub observations: &'a [DiagnosticObservation],
}

/// A pure, deterministic detector over a working set.
///
/// `detect` MUST be a function of the ordered working set alone: no clock, no
/// randomness, no ambient reads, no re-sorting of `input.observations`. It
/// returns drafts and nothing else — it CANNOT repair, propose, authorize or
/// mutate anything, because it is handed no vault and no transaction.
pub trait DeterministicDetector: Send + Sync {
    /// Stable identity, folded into every derived event id.
    fn detector_id(&self) -> &'static str;
    /// Draft events for this working set. Each draft's `detector_id` must
    /// equal this detector's identity; the runner rejects a mismatch.
    fn detect(&self, input: &DiagnosticWorkingSet<'_>) -> Vec<DiagnosticEvent>;
}
