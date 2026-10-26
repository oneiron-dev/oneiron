//! `self.grants.answer` (FIX 1379): the general answer to an access request,
//! by the vault's owner or by the person or agent the request asks.
//! `vault.companions.access_requests.answer` stays the owner's companion-only
//! door.

use serde::{Deserialize, Serialize};

use crate::access_grant::{AccessGrantScope, AccessRequestResponder, AccessRequestStatus};
use crate::memory::{MemoryError, MemoryResult};
use crate::{EntityId, Vault};

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

/// What an answered request asked for.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantRequestedScope {
    Messages {
        space_ref: EntityId,
    },
    Summaries {
        space_ref: EntityId,
    },
    RelationshipClaims {
        space_ref: EntityId,
    },
    CompanionProfile {
        person_ref: EntityId,
        facet_ref: Option<EntityId>,
    },
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
    /// Approval creates exactly this grant at the request's id; denial creates none.
    pub grant_ref: Option<EntityId>,
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
    let answered = vault.respond_addressed_access_request(
        responder,
        input.request,
        matches!(input.answer, GrantAnswer::Approve),
        crate::unix_seconds_now(),
    )?;
    let scope = match answered.grant.scope {
        AccessGrantScope::Messages { space_ref } => GrantRequestedScope::Messages { space_ref },
        AccessGrantScope::Summaries { space_ref } => GrantRequestedScope::Summaries { space_ref },
        AccessGrantScope::RelationshipClaims { space_ref } => {
            GrantRequestedScope::RelationshipClaims { space_ref }
        }
        AccessGrantScope::CompanionProfile {
            person_ref,
            facet_ref,
        } => GrantRequestedScope::CompanionProfile {
            person_ref,
            facet_ref,
        },
        _ => return Err(MemoryError::bad_request("request is not an access request")),
    };
    Ok(GrantAnswered {
        request: answered.id,
        principal_ref: answered.grant.principal_ref,
        capability: answered.grant.capability.as_str().to_owned(),
        scope,
        status: answered.status,
        addressed_to: answered.addressed_to,
        grant_ref: (answered.status == AccessRequestStatus::Approved).then_some(answered.id),
        decided_by: answered.decided_by,
        decided_at: answered.decided_at,
    })
}
