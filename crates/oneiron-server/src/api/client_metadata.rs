//! Public CIMD documents derived only from the configured OAuth resource origin.
use crate::mcp::oauth_client::{ClientApplication, client_metadata};
use crate::server::SyncServer;
use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

pub(super) async fn native(State(server): State<Arc<SyncServer>>) -> Response {
    document(&server, ClientApplication::Native)
}
pub(super) async fn web(State(server): State<Arc<SyncServer>>) -> Response {
    document(&server, ClientApplication::Web)
}
fn document(server: &SyncServer, app: ClientApplication) -> Response {
    let Some(base) = server.config.oauth_resource_indicator.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match client_metadata(base, app) {
        Ok(value) => (
            [(header::CACHE_CONTROL, "public, max-age=300")],
            Json(value),
        )
            .into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
