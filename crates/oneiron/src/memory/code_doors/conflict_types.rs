//! Code conflict and proposal-settlement request and view records.
//! `CodeConflictRecordRequest` is the first of its records.
//! These are local definitions; `memory::code_doors` re-exports them.

use crate::EntityId;
use crate::critic::{CritiqueSeverity, CritiqueVerdict};
use crate::learning::LearningCell;
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::memory::code_doors::conflict_types::{
    CodeConflictHistory, CodeConflictRecordRequest, CodeConflictResolutionView, CodeConflictView,
    CodeConflictViewRequest, CodeProposalReplacementView, CodeProposalResolveRequest,
    CodeProposalResolveRereviewRequest, CodeProposalSettleRequest, CodeProposalSettlementRequest,
    CodeProposalSettlementView,
};

/// An owner's own immutable opinion for a lens, not a contract-check receipt.
/// The door binds candidate, critic identity, class and timestamp itself.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeProposalReviewRequest {
    pub proposal: EntityId,
    pub artifact_id: String,
    pub run_id: String,
    pub attempt: EntityId,
    pub lens_id: String,
    pub domain: String,
    pub model_id: String,
    pub model_revision: Option<String>,
    pub calibration: LearningCell,
    pub verdict: CritiqueVerdict,
    pub severity: CritiqueSeverity,
    pub hard_check_passed: Option<bool>,
    pub evidence: Vec<EntityId>,
    pub suggested_edit: Option<String>,
}
