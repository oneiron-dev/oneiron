//! CA-07 campaign HTTP routes.
//!
//! Every handler does the same four things and nothing else: check the scope,
//! bind the facade to the AUTHENTICATED principal, build a
//! [`oneiron::campaign::surface::SurfaceCall`], and serialize the reply the
//! engine returned. Campaign semantics — validation, ownership, the version
//! CAS, the archive transition, cohort paging — all live in
//! `oneiron::campaign::surface`, which the MCP gateway dialect reaches through
//! the same door. This file defines no Campaign, SavedQuery, filter-AST,
//! verdict, or claim type, so the two transports cannot drift.
//!
//! The auth helpers below are shared with [`super::saved_query`]: one spelling
//! of "who is the principal" for both resources.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::auth::{CoreAuth, CoreScope};
use crate::error::{ApiError, ApiErrorDetails};
use crate::server::SyncServer;
use oneiron::campaign::surface::{
    SELF_CAMPAIGN_ARCHIVE, SELF_CAMPAIGN_CREATE, SELF_CAMPAIGN_MEMBERS, SELF_CAMPAIGN_READ,
    SELF_CAMPAIGN_UPDATE, SurfaceCall, invoke_campaign_surface,
};

/// The campaign resource router.
pub(crate) fn campaign_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/campaigns", post(create_campaign))
        .route(
            "/campaigns/{campaign_ref}",
            get(read_campaign).patch(update_campaign),
        )
        .route("/campaigns/{campaign_ref}/archive", post(archive_campaign))
        .route("/campaigns/{campaign_ref}/members", get(campaign_members))
}

/// `POST /campaigns` → `self.campaign.create`.
pub(crate) async fn create_campaign(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    dispatch(&auth, &server, CoreScope::Write, SELF_CAMPAIGN_CREATE, body)
}

/// `GET /campaigns/{campaign_ref}` → `self.campaign.read`.
pub(crate) async fn read_campaign(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(campaign_ref): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let body = with_path_ref(Value::Null, "campaign_ref", &campaign_ref)?;
    dispatch(&auth, &server, CoreScope::Read, SELF_CAMPAIGN_READ, body)
}

/// `PATCH /campaigns/{campaign_ref}` → `self.campaign.update`.
pub(crate) async fn update_campaign(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(campaign_ref): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let body = with_path_ref(body, "campaign_ref", &campaign_ref)?;
    dispatch(&auth, &server, CoreScope::Write, SELF_CAMPAIGN_UPDATE, body)
}

/// `POST /campaigns/{campaign_ref}/archive` → `self.campaign.archive`.
pub(crate) async fn archive_campaign(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(campaign_ref): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let body = with_path_ref(body, "campaign_ref", &campaign_ref)?;
    dispatch(
        &auth,
        &server,
        CoreScope::Write,
        SELF_CAMPAIGN_ARCHIVE,
        body,
    )
}

/// `GET /campaigns/{campaign_ref}/members` → `self.campaign.members`.
pub(crate) async fn campaign_members(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(campaign_ref): Path<String>,
    page: Result<Query<MembershipPageQuery>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let body = with_path_ref(membership_body(page)?, "campaign_ref", &campaign_ref)?;
    dispatch(&auth, &server, CoreScope::Read, SELF_CAMPAIGN_MEMBERS, body)
}

/// Cursor controls shared by both `members` routes.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct MembershipPageQuery {
    /// Opaque cursor from a prior page's `next_cursor`.
    pub(crate) cursor: Option<String>,
    /// Requested page size; the engine clamps it.
    pub(crate) limit: Option<u32>,
    /// Optional membership-epoch ceiling for a bitemporal read.
    pub(crate) at_epoch: Option<u64>,
}

/// Turns the query string into the surface body the engine parses.
pub(crate) fn membership_body(
    page: Result<Query<MembershipPageQuery>, QueryRejection>,
) -> Result<Value, ApiError> {
    let page = super::query_params(page)?;
    let mut body = Map::new();
    if let Some(cursor) = page.cursor {
        body.insert("cursor".to_owned(), Value::String(cursor));
    }
    if let Some(limit) = page.limit {
        body.insert("limit".to_owned(), Value::from(limit));
    }
    if let Some(at_epoch) = page.at_epoch {
        body.insert("at_epoch".to_owned(), Value::from(at_epoch));
    }
    Ok(Value::Object(body))
}

/// Stamps the resource id from the PATH into the surface body.
///
/// Overwrites rather than merges: the URL names the resource, so a body key
/// disagreeing with it is not a second opinion worth honoring. `null` and an
/// absent body are accepted as an empty object, which is what a GET sends.
pub(crate) fn with_path_ref(body: Value, field: &str, value: &str) -> Result<Value, ApiError> {
    let mut object = match body {
        Value::Null => Map::new(),
        Value::Object(object) => object,
        _ => {
            return Err(ApiError::bad_request(
                "request body must be a JSON object",
                None,
            ));
        }
    };
    object.insert(field.to_owned(), Value::String(value.to_owned()));
    Ok(Value::Object(object))
}

/// Runs one surface verb under the caller's credential.
///
/// The single place either router touches the engine. The reply is serialized
/// whole — verb name included — so an HTTP response and an in-process
/// `invoke_campaign_surface` result are the same document.
pub(crate) fn dispatch(
    auth: &CoreAuth,
    server: &SyncServer,
    scope: CoreScope,
    verb: &str,
    body: Value,
) -> Result<Json<Value>, ApiError> {
    auth.require(scope)?;
    let actor = surface_actor(auth)?;
    let facade = server.vault.memory(actor, oneiron::EdgeActorClass::Human);
    let reply = invoke_campaign_surface(
        &facade,
        SurfaceCall {
            verb: verb.to_owned(),
            body,
        },
    )
    .map_err(surface_error)?;
    serde_json::to_value(&reply)
        .map(Json)
        .map_err(|_| ApiError::internal_server_error("campaign surface reply could not be encoded"))
}

/// The actor every campaign and saved-query write is owned by.
///
/// Read from the CREDENTIAL and from nowhere else. The surface's create and
/// update request types carry no owner field, so there is no payload key a
/// caller could set — but the choice of which principal to bind is made here,
/// and binding anything a request body supplied would hand one caller another
/// caller's records.
///
/// An un-narrowed root secret carries no principal entity. It is refused rather
/// than defaulted to some ambient owner: "the trust root" is not a person, and
/// records owned by a rotating secret would be unreachable after rotation.
///
/// The class is `Human` because `principal_ref` is the third-party PERSON
/// binding (OF-365 ILD-1). The engine, not this file, decides whether the
/// asserted class holds — `verify_actor_binding` rejects a principal whose
/// stored entity type does not admit it, and that check is the authority.
pub(crate) fn surface_actor(auth: &CoreAuth) -> Result<oneiron::EntityId, ApiError> {
    let principal_ref = auth.principal_ref().ok_or_else(|| {
        ApiError::new(
            "campaign and saved-query records are owned by an authenticated principal",
            ApiErrorDetails::Forbidden {
                required_scope: None,
            },
            ["Present a bearer token carrying principal_ref=<32-hex person id>."],
        )
    })?;
    super::parse_entity_id_param(principal_ref, "principal_ref")
}

/// Maps an engine facade failure onto the existing API error contract.
///
/// One mapping for both transports' shared engine, so `NOT_FOUND` from the HTTP
/// route and `NOT_FOUND` from the MCP gateway describe the same outcome. The
/// facade's own code is the discriminator; nothing here re-inspects the message.
pub(crate) fn surface_error(error: oneiron::MemoryError) -> ApiError {
    match error.code.as_str() {
        oneiron::MEMORY_CODE_NOT_FOUND => ApiError::not_found("campaign_surface", None),
        oneiron::MEMORY_CODE_FORBIDDEN => ApiError::new(
            error.message,
            ApiErrorDetails::Forbidden {
                required_scope: None,
            },
            error.suggestions,
        ),
        oneiron::MEMORY_CODE_INVALID_STATE => ApiError::new(
            error.message,
            ApiErrorDetails::InvalidState {
                state: Some("campaign_surface_conflict".to_owned()),
            },
            error.suggestions,
        ),
        oneiron::MEMORY_CODE_INTERNAL => {
            tracing::error!(error = %error.message, "campaign surface failed");
            ApiError::internal_server_error("campaign surface failed")
        }
        _ => ApiError::new(
            error.message,
            ApiErrorDetails::BadRequest { field: None },
            error.suggestions,
        ),
    }
}
