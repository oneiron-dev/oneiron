//! Moved from `crates/oneiron/src/verbs/grants.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::access_grant::request::AccessRequestStatus;
pub use crate::memory::people_verbs::GrantRequestedScope;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// An answer to an access request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrantAnswer {
    Approve,
    Deny,
}

/// `self.grants.answer`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrantAnswerRequest {
    pub request: EntityId,
    pub answer: GrantAnswer,
}

/// `self.grants.answer`'s answer.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GrantAnswered {
    pub request: EntityId,
    pub principal_ref: EntityId,
    pub capability: String,
    pub scope: GrantRequestedScope,
    pub status: AccessRequestStatus,
    /// The person or agent the request asks, when it asks one.
    pub addressed_to: Option<EntityId>,
    /// Approval creates exactly this grant at the request's id; denial
    /// creates none, and so does an approval that delegates none of it,
    /// which leaves the request pending.
    pub grant_ref: Option<EntityId>,
    /// The request that keeps the whole requested grant for the owner, when
    /// the answerer's credential delegated only part of it.
    pub excess_request: Option<EntityId>,
    pub decided_by: Option<EntityId>,
    pub decided_at: Option<u64>,
}
