//! Bounded, authorization-checked companion list projections.

use super::auth::{companion_profile_principal_ref, require_companion_profile_read};
use super::errors::companion_engine_error;
use crate::api::{parse_entity_id_param, query_params};
use crate::auth::{CoreAuth, CoreScope};
use crate::error::{ApiErrorEnvelope, EnvelopedApiError};
use crate::server::SyncServer;
use axum::extract::{Query, State, rejection::QueryRejection};
use axum::response::Json;
use oneiron::access_grant::AccessGrantScope;
use oneiron::companion::CompanionProfileAdmission;
use oneiron::psych_profile::{PsychProfileKey, PsychProfileState, psych_profile_entity_id};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{IntoParams, ToSchema};

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
#[into_params(parameter_in = Query)]
pub(crate) struct ProfileListQuery {
    /// PERSON whose granted companion profiles are listed.
    person_ref: String,
    principal_ref: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct ProfileListRow {
    /// PERSON the profile describes.
    person_ref: String,
    /// FACET the grant is bounded to; null is a person-wide grant, listed at
    /// the PERSON's unfaceted profile.
    facet_ref: Option<String>,
    /// PSYCH_PROFILE id derived from PERSON x FACET, with no WORLD.
    profile_ref: String,
    /// Persisted PsychProfile compact tier; no generation on list reads.
    /// Null as well when the owner's recipient choice keeps the profile from
    /// where this read goes (FIX 8141).
    #[serde(rename = "personalityCompact", default)]
    personality_compact: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct ProfilesListResponse {
    items: Vec<ProfileListRow>,
}

/// List only the PERSON's profiles the caller holds a live profile grant for.
#[utoipa::path(get, path = "/v1/companion/profiles", params(ProfileListQuery),
    responses((status = 200, body = ProfilesListResponse),
              (status = 400, body = ApiErrorEnvelope),
              (status = 403, body = ApiErrorEnvelope)))]
pub(crate) async fn list_profiles(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<ProfileListQuery>, QueryRejection>,
) -> Result<Json<ProfilesListResponse>, EnvelopedApiError> {
    require_companion_profile_read(&auth)?;
    let req = query_params(query)?;
    let principal = companion_profile_principal_ref(
        &auth,
        req.principal_ref
            .as_deref()
            .map(|s| parse_entity_id_param(s, "principal_ref"))
            .transpose()?,
    )?;
    let person = parse_entity_id_param(&req.person_ref, "person_ref")?;
    let facets = server
        .vault
        .authorized_companion_profile_facets(&principal, &person)
        .map_err(|e| companion_engine_error("profile grant list failed", e))?;
    let destination = auth.destination();
    // The caller's own read lane judges each profile's world and sources
    // (FIX 11174); one that cannot be built leaves the listing as it was.
    let reader = crate::api::scoped_read_for_core_auth(&server.vault, &auth).ok();
    let mut items = Vec::with_capacity(facets.len());
    for facet in facets {
        let key = PsychProfileKey {
            person,
            facet,
            world: None,
        };
        let profile_ref = psych_profile_entity_id(&key);
        // The compact tier is read through the profile read's own admission:
        // a profile kept from this destination lists with no tier.
        let admission = server
            .vault
            .companion_profile_snapshot_admitted(
                &principal,
                &key,
                &destination,
                reader.as_ref(),
                None,
            )
            .map_err(|error| companion_engine_error("profile read failed", error))?;
        let compact = match admission {
            CompanionProfileAdmission::Admitted {
                state: PsychProfileState::Fresh(profile) | PsychProfileState::Stale { profile, .. },
                ..
            } => Some(profile.compact),
            _ => None,
        };
        items.push(ProfileListRow {
            person_ref: person.to_hex(),
            facet_ref: facet.map(|facet| facet.to_hex()),
            profile_ref: profile_ref.to_hex(),
            personality_compact: compact,
        });
    }
    Ok(Json(ProfilesListResponse { items }))
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub(crate) struct AccessRequestListRow {
    id: String,
    principal_ref: String,
    capability: String,
    /// Exact scope description from the persisted requested grant, not a read of protected content.
    #[serde(rename = "grantContentPreview", default)]
    grant_content_preview: Option<String>,
    /// The person or agent the request asks (FIX 1379), when it asks one.
    #[serde(default)]
    addressed_to: Option<String>,
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
#[utoipa::path(get, path = "/v1/companion/profiles/access-requests", params(AccessRequestListQuery),
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
                addressed_to: request.addressed_to.map(|id| id.to_hex()),
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
        AccessGrantScope::CompanionProfile {
            person_ref,
            facet_ref: None,
        } => Some(format!(
            "companion_profile for person {}",
            person_ref.to_hex()
        )),
        AccessGrantScope::CompanionProfile {
            person_ref,
            facet_ref: Some(facet_ref),
        } => Some(format!(
            "companion_profile for person {} facet {}",
            person_ref.to_hex(),
            facet_ref.to_hex()
        )),
        _ => None,
    }
}
