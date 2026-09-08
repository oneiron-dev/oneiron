//! Companion scope-resolution authorization for context-pack assembly.

use super::super::{auth_bound_principal_ref, core_engine_error};
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;

pub(crate) fn companion_scope_resolution_authorized(
    vault: &oneiron::Vault,
    auth: &CoreAuth,
    person_ref: Option<oneiron::EntityId>,
    persona_ref: Option<oneiron::EntityId>,
) -> Result<bool, ApiError> {
    if auth.has_scope(CoreScope::CompanionRegisterRead) || auth.has_scope(CoreScope::Auth) {
        return Ok(true);
    }
    let (Some(person_ref), Some(persona_ref)) = (person_ref, persona_ref) else {
        return Ok(false);
    };
    let Some(principal_ref) = auth_bound_principal_ref(auth)? else {
        return Ok(false);
    };
    vault
        .companion_profile_access_grant(&principal_ref, &person_ref, &persona_ref)
        .map(|grant| grant.is_some())
        .map_err(|error| {
            tracing::error!(
                error = %error,
                principal_ref = %principal_ref.to_hex(),
                person_ref = %person_ref.to_hex(),
                persona_ref = %persona_ref.to_hex(),
                "companion profile grant lookup failed"
            );
            core_engine_error("companion profile grant lookup failed", error)
        })
}
