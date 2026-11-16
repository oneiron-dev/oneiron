//! Moved from `crates/oneiron/src/gate/proposal_observation.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::proposal_observation_record::ProposalPolicySource;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalSubmissionCheck {
    pub actor: String,
    pub count: u64,
    pub threshold: u64,
    pub policy_source: ProposalPolicySource,
    /// Engine-derived proposal identity that first crossed the threshold.
    pub proposal_ref: String,
}

impl ProposalSubmissionCheck {
    pub const KIND: &'static str = "proposal_submission_burst";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalSubmissionReceipt {
    pub actor: String,
    pub proposal_ref: String,
    pub count: u64,
    pub policy_source: ProposalPolicySource,
}
