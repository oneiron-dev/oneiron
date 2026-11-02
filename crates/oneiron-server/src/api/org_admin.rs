//! Owner-only setup and the Console's closed organization action list.
use crate::{
    auth::{CoreAuth, CoreScope},
    error::{ApiError, ApiErrorEnvelope, EnvelopedApiError},
    server::SyncServer,
};
use axum::{
    Json,
    extract::{Path, State},
    http::request::Parts,
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

/// Fix one organization's admin policy, once.
#[utoipa::path(
    post,
    path = "/v1/core/org-admin/{org}/policy",
    params(("org" = String, Path, description = "Hex organization id.")),
    request_body(content = Object, description = "`OrgAdminPolicy`: `org_ref` (32 hex), `admin_refs` (32 hex each) and `powers` (`org:...` names).", content_type = "application/json"),
    responses(
        (status = 200, description = "The organization is configured.", body = Object, content_type = "application/json"),
        (status = 400, description = "Malformed organization id, or the policy names another organization.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 403, description = "Not an owner act, or the organization administration power is denied.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 409, description = "The key's first request never settled an outcome (`idempotent_outcome_unknown`, FIX 9527): its effect may have landed, so it is not run again; read the resource's state, or send a new `Idempotency-Key` to act again. A retry whose first request counted committed writes gets `idempotent_reply_not_kept` instead (FIX 10379): those writes landed, and the reply was not kept.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "Organization setup failed, or it is already configured.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(super) async fn configure(
    State(server): State<Arc<SyncServer>>,
    Path(org): Path<String>,
    parts: Parts,
    Json(policy): Json<OrgAdminPolicy>,
) -> Result<Json<serde_json::Value>, EnvelopedApiError> {
    super::scoped_auth::check_request_owner_act(&parts, &server)?;
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
