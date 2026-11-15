//! Moved from `crates/oneiron/src/authority/checkpoint_policy_choice.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::*;

/// The vault's checkpoint root policy as the owner's surface shows it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckpointPolicyView {
    /// Whether this operator permits owner checkpoint root selection here.
    pub selection_available: bool,
    /// The revision to present back as `seen`: the digest of the live
    /// choices, zero when none.
    pub revision: [u8; 32],
    /// The policy in force; `None` when the roster cannot fix it.
    pub policy: Option<CheckpointRootPolicy>,
    /// Why the roster cannot fix the policy in force, when it cannot.
    pub refusal: Option<String>,
    /// The owner's choice in force; `None` while the hosting posture fixes
    /// the policy.
    pub selected: Option<CheckpointPolicyHead>,
    /// Every live choice.
    pub heads: Vec<CheckpointPolicyHead>,
    /// The live choices in conflict, empty when none: the choice in force
    /// stays the last one they agreed on until a choice that saw them all
    /// supersedes them.
    pub conflict: Vec<CheckpointPolicyHead>,
}
