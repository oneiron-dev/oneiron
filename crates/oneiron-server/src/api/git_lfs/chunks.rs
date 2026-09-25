//! Grant-scoped binary have/want endpoint over the standing bearer identity.

use super::gate::{LfsAccess, authorize};
use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use std::sync::Arc;

pub(super) async fn exchange(
    State(server): State<Arc<SyncServer>>,
    Path(_repo): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, EnvelopedApiError> {
    let auth = authorize(&headers, &server, LfsAccess::Read)?;
    let principal = auth.require_registered_principal()?;
    let principal = oneiron::EntityId::from_hex(principal)
        .map_err(|_| ApiError::forbidden_scope("registered chunk principal"))?;
    let vault = Arc::clone(&server.vault);
    let scope = crate::handler::selector_grant_scope();
    let bytes = tokio::task::spawn_blocking(move || {
        oneiron::sync::chunks::serve_chunk_request(&vault, principal, scope, &body)
    })
    .await
    .map_err(|_| ApiError::internal_server_error("lfs chunk worker failed"))?
    // Do not reveal absent object vs denied selector vs hash membership.
    .map_err(|_| ApiError::forbidden_scope("lfs chunk selector"))?;
    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "application/vnd.oneiron.chunks",
        )],
        bytes,
    )
        .into_response())
}
