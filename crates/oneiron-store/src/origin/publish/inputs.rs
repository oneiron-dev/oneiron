//! The inputs of the exact publish verbs (FIX 6866), and the one answer
//! that is not a request: a review page.

use serde::{Deserialize, Serialize};

use oneiron_contracts::entity_id::EntityId;

/// Names one request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginPublishIdRequest {
    pub repo: String,
    pub request_id: EntityId,
    pub code_repo: Option<EntityId>,
}

/// Approves one request's reviewed tuple.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginPublishApproveRequest {
    pub repo: String,
    pub request_id: EntityId,
    /// The review digest the approver read; another refuses.
    pub review_digest: String,
    pub code_repo: Option<EntityId>,
}

/// Reads one page of a request's review.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OriginPublishReviewRequest {
    pub repo: String,
    pub request_id: EntityId,
    /// From 0.
    pub page: u64,
    pub code_repo: Option<EntityId>,
}
