//! Moved from `crates/oneiron/src/repo_mutation/proposal/settlement.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_contracts::claim::ClaimApprovalStatus;
use oneiron_contracts::claim::ClaimLifecycleStatus;
use oneiron_contracts::claim::ClaimSource;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::repo_proposal_record::RepoProposalOperation;
use oneiron_store::repo_proposal_record::RepoProposalStatus;
use oneiron_store::write_envelope::claim_body::ClaimBody;
use oneiron_store::write_envelope::claim_body::ClaimSubject;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepoProposalDecision {
    Approve,
    Reject,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RepoProposalSettlement {
    pub receipt: EntityId,
    /// The owner who settled it; `None` once that actor was erased (FIX
    /// 5220). The decision stays.
    pub actor: Option<EntityId>,
    pub decision: RepoProposalDecision,
    pub settled_at: u64,
}
