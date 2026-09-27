//! Bounded, authorization-checked companion list projections.

use super::auth::{companion_profile_principal_ref, require_companion_profile_read};
use super::errors::companion_engine_error;
use crate::api::{parse_entity_id_param, query_params, unix_seconds_now};
use crate::auth::{CoreAuth, CoreScope};
use crate::error::{ApiErrorEnvelope, EnvelopedApiError};
use crate::server::SyncServer;
use axum::extract::{Query, State, rejection::QueryRejection};
use axum::response::Json;
use oneiron::ErrorKind;
use oneiron::access_grant::AccessGrantScope;
use oneiron::registry::ENTITY_TYPE_ACCESS_GRANT;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};
use utoipa::{IntoParams, ToSchema};

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub(crate) struct PersonaListQuery {
    person_ref: String,
    principal_ref: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct PersonaListRow {
    persona_ref: String,
    person_ref: String,
    /// Persisted PsychProfile compact tier; no generation on list reads.
    #[serde(rename = "personalityCompact", default)]
    personality_compact: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct PersonasListResponse {
    items: Vec<PersonaListRow>,
}

/// List only personas for which the caller has a live, exact profile grant.
#[utoipa::path(get, path = "/v1/companion/personas", params(PersonaListQuery),
    responses((status = 200, body = PersonasListResponse),
              (status = 400, body = ApiErrorEnvelope),
              (status = 403, body = ApiErrorEnvelope)))]
pub(crate) async fn list_personas(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<PersonaListQuery>, QueryRejection>,
) -> Result<Json<PersonasListResponse>, EnvelopedApiError> {
    require_companion_profile_read(&auth)?;
    // A stored profile grant cannot widen this request's credential caveats.
    auth.require_unrestricted_record_scope()?;
    let req = query_params(query)?;
    let principal = companion_profile_principal_ref(
        &auth,
        req.principal_ref
            .as_deref()
            .map(|s| parse_entity_id_param(s, "principal_ref"))
            .transpose()?,
    )?;
    let person = parse_entity_id_param(&req.person_ref, "person_ref")?;
    let mut cursor = None;
    let mut seen = BTreeSet::new();
    let mut items = Vec::new();
    loop {
        let ids = server
            .vault
            .entities_by_type_page(ENTITY_TYPE_ACCESS_GRANT, cursor.as_ref(), 256)
            .map_err(|e| companion_engine_error("persona grant list failed", e))?;
        if ids.is_empty() {
            break;
        }
        for id in &ids {
            let Some(grant) = server
                .vault
                .get_access_grant(id)
                .map_err(|e| companion_engine_error("persona grant read failed", e))?
            else {
                continue;
            };
            let Some((grant_person, persona)) = grant.scope.companion_profile_refs() else {
                continue;
            };
            if grant_person != person
                || !grant.allows_companion_profile_read(
                    &principal,
                    &person,
                    &persona,
                    unix_seconds_now(),
                )
                || !seen.insert(persona)
            {
                continue;
            }
            let profile = match server.vault.get_psych_profile(&persona) {
                Ok(profile) => profile,
                Err(error) if error.kind() == ErrorKind::InvalidEntityType => None,
                Err(error) => {
                    return Err(companion_engine_error("persona profile read failed", error));
                }
            };
            items.push(PersonaListRow {
                persona_ref: persona.to_hex(),
                person_ref: person.to_hex(),
                personality_compact: profile.map(|p| p.compact),
            });
        }
        cursor = ids.last().copied();
        if ids.len() < 256 {
            break;
        }
    }
    Ok(Json(PersonasListResponse { items }))
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct AccessRequestListRow {
    id: String,
    principal_ref: String,
    capability: String,
    /// Exact scope description from the persisted requested grant, not a read of protected content.
    #[serde(rename = "grantContentPreview", default)]
    grant_content_preview: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct AccessRequestsListResponse {
    items: Vec<AccessRequestListRow>,
    /// Null when the pending set is exhausted; otherwise the last returned request id.
    #[serde(rename = "nextCursor", default)]
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub(crate) struct AccessRequestListQuery {
    /// Page size, clamped to 1..=100.
    #[serde(default = "default_request_limit")]
    limit: usize,
    /// Exclusive request-id cursor from a prior page.
    after: Option<String>,
}

fn default_request_limit() -> usize {
    100
}

/// Owner/control-plane view of pending requests only. A pending grant never authorizes a content read.
#[utoipa::path(get, path = "/v1/companion/personas/access-requests", params(AccessRequestListQuery),
    responses((status = 200, body = AccessRequestsListResponse),
              (status = 403, body = ApiErrorEnvelope)))]
pub(crate) async fn list_access_requests(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<AccessRequestListQuery>, QueryRejection>,
) -> Result<Json<AccessRequestsListResponse>, EnvelopedApiError> {
    auth.require(CoreScope::Auth)?;
    let req = query_params(query)?;
    let after = req
        .after
        .as_deref()
        .map(|id| parse_entity_id_param(id, "after"))
        .transpose()?;
    let (requests, next) = server
        .vault
        .pending_access_requests_page(after.as_ref(), req.limit.clamp(1, 100))
        .map_err(|e| companion_engine_error("access request list failed", e))?;
    Ok(Json(AccessRequestsListResponse {
        next_cursor: next.map(|id| id.to_hex()),
        items: requests
            .into_iter()
            .map(|request| AccessRequestListRow {
                id: request.id.to_hex(),
                principal_ref: request.grant.principal_ref.to_hex(),
                capability: request.grant.capability.as_str().to_owned(),
                grant_content_preview: grant_content_preview(&request.grant.scope),
            })
            .collect(),
    }))
}

fn grant_content_preview(scope: &AccessGrantScope) -> Option<String> {
    match scope {
        AccessGrantScope::Messages { space_ref } => {
            Some(format!("messages in space {}", space_ref.to_hex()))
        }
        AccessGrantScope::Summaries { space_ref } => {
            Some(format!("summaries in space {}", space_ref.to_hex()))
        }
        AccessGrantScope::RelationshipClaims { space_ref } => Some(format!(
            "relationshipClaims in space {}",
            space_ref.to_hex()
        )),
        AccessGrantScope::CompanionProfile { .. } => {
            scope.companion_profile_refs().map(|(person, persona)| {
                format!(
                    "companion_profile for person {} persona {}",
                    person.to_hex(),
                    persona.to_hex()
                )
            })
        }
        _ => None,
    }
}
