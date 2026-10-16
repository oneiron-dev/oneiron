//! The receipts of the pack lens lifecycle (OF-250): a proposal, and the
//! owner's selection or clearing of a lens slot.
//!
//! These project the lens records the proposal and slot doors already wrote
//! (`crate::lens`); they keep no store of their own. The proposal record is
//! the proposal's receipt, and the slot record is the owner's decision.

use serde::{Deserialize, Serialize};

/// Where a lens proposal stands. A proposal is always born `proposed`: no
/// caller's write ceiling lands a lens active, only the owner's selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensApproval {
    Proposed,
}

/// `vault.lenses.propose`'s answer: the frozen revision the vault now holds,
/// what it is bound to, and that it waits for the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LensProposalReceipt {
    pub lens_ref: String,
    pub pack_name: String,
    pub skill_id: String,
    pub pack_content_hash: String,
    /// BLAKE3 of the frozen tree's canonical JSON; the owner's selection
    /// names it, so it selects exactly the revision it was shown.
    pub compiled_hash: String,
    pub approval: LensApproval,
    pub proposed_by: String,
    pub proposed_at: u64,
}

/// The owner's decision on one pack lens slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LensSlotDecision {
    Activated,
    Deactivated,
}

/// `vault.lenses.activate` and `vault.lenses.deactivate`'s answer: the slot,
/// the revision selected or cleared, the one it replaced, and the owner's
/// decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LensActivationReceipt {
    pub decision: LensSlotDecision,
    pub pack_name: String,
    pub skill_id: String,
    /// The lens selected (`activated`) or cleared (`deactivated`).
    pub lens_ref: String,
    pub compiled_hash: String,
    /// On activation, the lens the slot held before it, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_ref: Option<String>,
    /// The owner whose proof the decision revalidated in its writer.
    pub decided_by: String,
    /// This decision's own id.
    pub decision_ref: String,
    /// The owner authentication the decision was made under.
    pub authenticated_under: String,
    pub decided_at: u64,
}
