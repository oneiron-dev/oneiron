//! Moved from `crates/oneiron/src/self_heal/distillation.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::self_heal::distillation::ReviewedFinding;
use serde::Deserialize;
use serde::Serialize;

/// One family's registered T2: the exact reviewed corpus the host's pass asks
/// with, and the closed-form T1 that retired it, if one reproduces every label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintedRegistration {
    pub family: String,
    /// Hash of the seed's wording and the corpus. A new label or a reworded
    /// seed is a new revision, registered afresh.
    pub revision: [u8; 32],
    #[serde(with = "super::receipt_serde::ids")]
    pub positive_events: Vec<EntityId>,
    #[serde(with = "super::receipt_serde::ids")]
    pub negative_events: Vec<EntityId>,
    pub registered_at: u64,
    /// The T1 detector that reproduces this revision's labels. A graduated
    /// T2 no longer runs.
    pub graduated_to: Option<String>,
}
