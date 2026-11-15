//! Moved from `crates/oneiron/src/critic/review/questions.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::critic::review::*;
use crate::critic::*;
use serde::Deserialize;
use serde::Serialize;

/// Generated text beside one finding. Every part is optional: a note read
/// from JSON names only the parts it has.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReviewNote {
    pub evidence_refs: Vec<String>,
    pub suggested_edit: Option<String>,
    pub prediction: Option<CriticPrediction>,
    /// The concrete flaw the finding names, if any: its review refuses one
    /// that names no place in the target as the review's state shows it
    /// ([`flaw_fits_review_state`]).
    pub flaw: Option<FlawIdentity>,
}
