//! Moved from `crates/oneiron/src/critic/review.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::critic::review::dissent::CriticPrediction;
pub use crate::critic::review::dissent::ReviewDissent;
pub use crate::critic::review::doors::CriticOutcomeRecord;
pub use crate::critic::review::questions::ReviewNote;
use crate::critic::*;
pub use oneiron_verb_wire::critic::review::doors::CriticFindingsRequest;
pub use oneiron_verb_wire::critic::review::doors::CriticOutcomeAnchor;
pub use oneiron_verb_wire::critic::review::doors::CriticOutcomeSubmit;
pub use oneiron_verb_wire::critic::review::submit::CriticBinding;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewArtifactKind {
    Document,
    Design,
    ClaimWrite,
}
pub mod dissent;
pub mod doors;
pub mod questions;
