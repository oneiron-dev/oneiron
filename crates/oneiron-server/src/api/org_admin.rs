//! Owner-only setup and the Console's closed organization action list.
use crate::{
    auth::{CoreAuth, CoreScope},
    error::{ApiError, EnvelopedApiError},
    server::SyncServer,
};
use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use oneiron::{
    EntityId,
    federation::{OrgAdminError, OrgAdminPolicy},
};
use std::collections::BTreeSet;
use std::sync::Arc;

fn id(value: &str) -> Result<EntityId, ApiError> {
    EntityId::from_hex(value)
        .map_err(|_| ApiError::bad_request("invalid organization or actor reference", Some("ref")))
}
fn policy_error(error: OrgAdminError) -> ApiError {
    match error {
        OrgAdminError::AlreadyConfigured => {
            ApiError::invalid_state(Some("organization already configured"))
        }
        OrgAdminError::Denied => ApiError::forbidden_scope("org:named-power"),
        OrgAdminError::Engine(error) => {
            super::core_engine_error("organization administration failed", error)
        }
    }
}

pub(super) async fn configure(
    State(server): State<Arc<SyncServer>>,
    Path(org): Path<String>,
    headers: HeaderMap,
    Json(policy): Json<OrgAdminPolicy>,
) -> Result<Json<serde_json::Value>, EnvelopedApiError> {
    super::check_api_auth(&headers, &server)?;
    if policy.org_ref() != id(&org)? {
        return Err(ApiError::bad_request("setup organization mismatch", Some("org_ref")).into());
    }
    server
        .vault()
        .configure_org_admin(&policy)
        .map_err(policy_error)?;
    Ok(Json(serde_json::json!({"configured":true})))
}

pub(super) async fn powers(
    State(server): State<Arc<SyncServer>>,
    Path(org): Path<String>,
    auth: CoreAuth,
) -> Result<Json<serde_json::Value>, EnvelopedApiError> {
    let org = id(&org)?;
    if !auth.is_owner_grade() && auth.org_ref() != Some(org.to_hex().as_str()) {
        return Err(ApiError::forbidden_scope("org:named-power").into());
    }
    let admin = id(auth.require_registered_principal()?)?;
    let policy = server.vault().org_admin_policy(org).map_err(policy_error)?;
    let powers: BTreeSet<_> = policy
        .visible_powers(admin)
        .into_iter()
        .filter(|power| auth.has_scope(CoreScope::OrgAdmin(*power)))
        .map(oneiron::federation::OrgAdminPower::as_str)
        .collect();
    Ok(Json(serde_json::json!({"powers":powers})))
}
