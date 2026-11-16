//! Moved from `crates/oneiron/src/self_heal/healer_host.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::self_heal::repair::RepairProposal;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalState {
    Proposed,
    Denied,
    Released { release_ref: String },
    Reversed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealerProposalRecord {
    pub proposal: RepairProposal,
    pub state: ProposalState,
    pub run_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalBurstCheck {
    #[serde(with = "super::receipt_serde::id")]
    pub actor: EntityId,
    pub count: u64,
    /// Run that crossed the threshold, not the scope of the actor-wide burst.
    /// Use `Vault::reverse_healer_burst` to reverse the flagged actor's submissions.
    pub run_ref: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HealerRunReceipt {
    pub run_ref: String,
    #[serde(with = "super::receipt_serde::id")]
    pub actor: EntityId,
    #[serde(with = "super::receipt_serde::ids")]
    pub proposals: Vec<EntityId>,
    pub reversed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchPullRequest {
    #[serde(with = "super::receipt_serde::id")]
    pub proposal_id: EntityId,
    pub target_ref: String,
    pub patch_ref: String,
    pub schema: bool,
    pub release_ref: String,
    #[serde(with = "super::receipt_serde::id")]
    pub approved_by: EntityId,
}
