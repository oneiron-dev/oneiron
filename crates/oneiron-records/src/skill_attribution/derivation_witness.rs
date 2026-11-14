//! Moved from `crates/oneiron/src/skill_attribution/derivation_witness.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// What wrote a witnessed edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessProducer {
    /// A batch applied under the run's envelope.
    Write,
    /// A code revision's lifecycle link, written directly.
    RevisionLink,
    /// An off-record op the run journaled, replayed by an authorized
    /// promotion.
    Promotion,
    /// A scope summary the run asked for, minted or reused by this Dreamer
    /// attempt; `None` once that attempt's run is erased.
    Summary(Option<AttemptId>),
    /// A tested queue revision sealed from this run's admitted proposal.
    QueueSeal,
}

impl WitnessProducer {
    /// Whether this producer lands a run's edge after the run's own write:
    /// its token held as it was captured, so the edge stays the run's once
    /// the lease has ended.
    const fn lands_late(self) -> bool {
        matches!(self, Self::Promotion | Self::Summary(_) | Self::QueueSeal)
    }
}
