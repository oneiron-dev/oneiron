//! Moved from `crates/oneiron/src/ports/dependent_walk.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::Bound;

/// OF-520 question a source's walk raised once it withdrew more dependents
/// than the threshold. It is evidence for the host, never a refusal: the walk
/// went on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependentWalkCheck {
    /// The source whose dependents were walked.
    pub document: String,
    /// The door that walked them ([`DependentWalkProgress::door`]).
    pub door: String,
    /// The threshold in force at the crossing.
    pub threshold: u64,
    /// Dependents withdrawn when the walk crossed it.
    pub walked: u64,
    /// Unix seconds of the crossing.
    pub raised_at: u64,
}

impl DependentWalkCheck {
    /// Machine-readable check discriminator; presentation text belongs to hosts.
    pub const KIND: &'static str = "dependent_walk_size";
}
