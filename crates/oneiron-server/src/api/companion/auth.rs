//! Companion authorization helpers.

use super::super::parse_entity_id_param;
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;

pub(crate) fn require_companion_profile_read(auth: &CoreAuth) -> Result<(), ApiError> {
    if auth.has_scope(CoreScope::CompanionProfileRead) || auth.has_scope(CoreScope::Read) {
        Ok(())
    } else {
        Err(ApiError::forbidden_scope(
            CoreScope::CompanionProfileRead.as_str(),
        ))
    }
}

pub(crate) fn require_companion_access_grant_write(auth: &CoreAuth) -> Result<(), ApiError> {
    if auth.has_scope(CoreScope::CompanionAccessGrantWrite) || auth.has_scope(CoreScope::Auth) {
        Ok(())
    } else {
        Err(ApiError::forbidden_scope(
            CoreScope::CompanionAccessGrantWrite.as_str(),
        ))
    }
}

pub(crate) fn require_companion_access_grant_write_for_principal(
    auth: &CoreAuth,
    principal_ref: &oneiron::EntityId,
) -> Result<(), ApiError> {
    require_companion_access_grant_write(auth)?;
    if auth.has_scope(CoreScope::Auth) {
        return Ok(());
    }
    match auth_bound_principal_ref(auth)? {
        Some(bound) if bound == *principal_ref => Ok(()),
        _ => Err(ApiError::forbidden_scope(CoreScope::Auth.as_str())),
    }
}

pub(crate) fn auth_bound_principal_ref(
    auth: &CoreAuth,
) -> Result<Option<oneiron::EntityId>, ApiError> {
    auth.principal_ref()
        .map(|principal_ref| parse_entity_id_param(principal_ref, "principal_ref"))
        .transpose()
}

pub(crate) fn companion_profile_principal_ref(
    auth: &CoreAuth,
    requested: Option<oneiron::EntityId>,
) -> Result<oneiron::EntityId, ApiError> {
    let bound = auth_bound_principal_ref(auth)?;

    match (requested, bound) {
        (Some(requested), Some(bound)) if requested == bound => Ok(requested),
        (Some(requested), _) => {
            auth.require(CoreScope::Auth)?;
            Ok(requested)
        }
        (None, Some(bound)) => Ok(bound),
        (None, None) => Err(ApiError::bad_request(
            "principal_ref is required unless bearer auth binds principal_ref",
            Some("principal_ref"),
        )),
    }
}
