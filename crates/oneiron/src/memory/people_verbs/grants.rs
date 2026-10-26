//! `self.grants.ask` (FIX 1379): an access request addressed to the person
//! asked, for the requested resource's read and nothing wider.

use super::{GrantAskReceipt, GrantAskRequest, GrantAskScope, hex_ref, unix_ms};
use crate::access_grant::{AccessGrant, AccessGrantScope, AccessGrantStatus};
use crate::federation::Scope;
use crate::memory::{Memory, MemoryResult};

/// Policy hook (CALLS "OF-1379 ask authority", open): the authority an ask
/// requests is the read of the resource it names, never the whole vault.
fn requested_authority_scope() -> Scope {
    crate::federation::scope_codec::read_preset()
}

impl Memory<'_> {
    /// `self.grants.ask`: asks a person or an agent for access, on behalf of
    /// the caller. The request names the one asked, who may answer it beside
    /// the owner; it grants nothing until one of them approves it.
    pub fn grants_ask(&self, input: &GrantAskRequest) -> MemoryResult<GrantAskReceipt> {
        super::super::verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        let people = self.people_roster()?;
        let asked = Self::person_by_handle(&people, &input.pr)?;
        let scope = match &input.scope {
            GrantAskScope::Messages { space_ref } => AccessGrantScope::Messages {
                space_ref: hex_ref("space_ref", space_ref)?,
            },
            GrantAskScope::Summaries { space_ref } => AccessGrantScope::Summaries {
                space_ref: hex_ref("space_ref", space_ref)?,
            },
            GrantAskScope::RelationshipClaims { space_ref } => {
                AccessGrantScope::RelationshipClaims {
                    space_ref: hex_ref("space_ref", space_ref)?,
                }
            }
            GrantAskScope::CompanionProfile { facet_ref } => AccessGrantScope::CompanionProfile {
                person_ref: asked.person,
                facet_ref: facet_ref
                    .as_deref()
                    .map(|facet| hex_ref("facet_ref", facet))
                    .transpose()?,
            },
        };
        let request = self.vault.new_entity_id()?;
        self.vault.request_access_to(
            request,
            AccessGrant {
                authority_scope: requested_authority_scope(),
                principal_ref: self.actor,
                capability: scope.required_capability(),
                scope,
                status: AccessGrantStatus::Active,
                created_at: unix_ms() / 1_000,
                revoked_at: None,
                expires_at: None,
                companion_bounds: None,
            },
            Some(asked.person),
        )?;
        Ok(GrantAskReceipt {
            request: request.to_hex(),
            asked: asked.handle.clone(),
            status: "pending".to_owned(),
        })
    }
}
