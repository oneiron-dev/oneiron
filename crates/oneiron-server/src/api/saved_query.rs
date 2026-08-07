//! CA-07 saved-query HTTP routes.
//!
//! The campaign router's twin, and deliberately its mirror image: same scope
//! checks, same principal binding, same `dispatch` into
//! `oneiron::campaign::surface`. Filter-AST parsing, matcher validation, the
//! definition-version CAS, the archive transition, and cause preservation are
//! CA-02's, reached through the engine surface — none of it is reimplemented
//! here, and this file defines no SavedQuery type of its own.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use serde_json::Value;

use super::campaign::{MembershipPageQuery, dispatch, membership_body, with_path_ref};
use crate::auth::{CoreAuth, CoreScope};
use crate::error::ApiError;
use crate::server::SyncServer;
use oneiron::campaign::surface::{
    SELF_SAVED_QUERY_ARCHIVE, SELF_SAVED_QUERY_CREATE, SELF_SAVED_QUERY_MEMBERS,
    SELF_SAVED_QUERY_READ, SELF_SAVED_QUERY_UPDATE,
};

/// The saved-query resource router.
pub(crate) fn saved_query_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/saved-queries", post(create_saved_query))
        .route(
            "/saved-queries/{query_ref}",
            get(read_saved_query).patch(update_saved_query),
        )
        .route(
            "/saved-queries/{query_ref}/archive",
            post(archive_saved_query),
        )
        .route(
            "/saved-queries/{query_ref}/members",
            get(saved_query_members),
        )
}

/// `POST /saved-queries` → `self.saved_query.create`.
pub(crate) async fn create_saved_query(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    dispatch(
        &auth,
        &server,
        CoreScope::Write,
        SELF_SAVED_QUERY_CREATE,
        body,
    )
}

/// `GET /saved-queries/{query_ref}` → `self.saved_query.read`.
pub(crate) async fn read_saved_query(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(query_ref): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let body = with_path_ref(Value::Null, "query_ref", &query_ref)?;
    dispatch(&auth, &server, CoreScope::Read, SELF_SAVED_QUERY_READ, body)
}

/// `PATCH /saved-queries/{query_ref}` → `self.saved_query.update`.
pub(crate) async fn update_saved_query(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(query_ref): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let body = with_path_ref(body, "query_ref", &query_ref)?;
    dispatch(
        &auth,
        &server,
        CoreScope::Write,
        SELF_SAVED_QUERY_UPDATE,
        body,
    )
}

/// `POST /saved-queries/{query_ref}/archive` → `self.saved_query.archive`.
pub(crate) async fn archive_saved_query(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(query_ref): Path<String>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, ApiError> {
    let body = with_path_ref(body, "query_ref", &query_ref)?;
    dispatch(
        &auth,
        &server,
        CoreScope::Write,
        SELF_SAVED_QUERY_ARCHIVE,
        body,
    )
}

/// `GET /saved-queries/{query_ref}/members` → `self.saved_query.members`.
pub(crate) async fn saved_query_members(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(query_ref): Path<String>,
    page: Result<Query<MembershipPageQuery>, QueryRejection>,
) -> Result<Json<Value>, ApiError> {
    let body = with_path_ref(membership_body(page)?, "query_ref", &query_ref)?;
    dispatch(
        &auth,
        &server,
        CoreScope::Read,
        SELF_SAVED_QUERY_MEMBERS,
        body,
    )
}
