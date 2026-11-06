//! `self.grants.answer` (FIX 1379): the general answer to an access request,
//! by the vault's owner or by the person or agent the request asks.
//! `vault.companions.access_requests.answer` stays the owner's companion-only
//! door.

use serde::{Deserialize, Serialize};

use crate::access_grant::{AccessRequestResponder, AccessRequestStatus};
use crate::memory::{MemoryError, MemoryResult};
use crate::{EntityId, Vault};

pub use crate::memory::GrantRequestedScope;
pub(crate) use crate::memory::grant_requested_scope;

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

/// Answers `input` as `responder`, revalidated in the answering write
/// ([`Vault::respond_addressed_access_request`]).
pub fn answer_grant_request_as(
    vault: &Vault,
    responder: AccessRequestResponder<'_>,
    input: GrantAnswerRequest,
) -> MemoryResult<GrantAnswered> {
    let crate::access_grant::AddressedAnswer {
        request: answered,
        excess,
    } = vault.respond_addressed_access_request(
        responder,
        input.request,
        matches!(input.answer, GrantAnswer::Approve),
        crate::unix_seconds_now(),
    )?;
    let scope = grant_requested_scope(&answered.grant.scope)
        .ok_or_else(|| MemoryError::bad_request("request is not an access request"))?;
    Ok(GrantAnswered {
        request: answered.id,
        principal_ref: answered.grant.principal_ref,
        capability: answered.grant.capability.as_str().to_owned(),
        scope,
        status: answered.status,
        addressed_to: answered.addressed_to,
        grant_ref: (answered.status == AccessRequestStatus::Approved).then_some(answered.id),
        excess_request: excess.map(|excess| excess.id),
        decided_by: answered.decided_by,
        decided_at: answered.decided_at,
    })
}
