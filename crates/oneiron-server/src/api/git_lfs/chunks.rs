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
    let (object, bytes) = tokio::task::spawn_blocking(move || {
        let object = oneiron::sync::chunks::chunk_request_object(&body)?;
        oneiron::sync::chunks::serve_chunk_request(&vault, principal, scope, &body)
            .map(|bytes| (object, bytes))
    })
    .await
    .map_err(|_| ApiError::internal_server_error("lfs chunk worker failed"))?
    // Do not reveal absent object vs denied selector vs hash membership.
    .map_err(|_| ApiError::forbidden_scope("lfs chunk selector"))?;
    #[cfg(test)]
    release_hook::run(&server);
    // A device-only flag may land while the worker builds the reply: the
    // object is judged again as its bytes are released.
    if oneiron::sync::chunks::lfs_object_withheld(&server.vault, object).unwrap_or(true) {
        return Err(ApiError::forbidden_scope("lfs chunk selector").into());
    }
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

/// A device-only flag committed after the worker built its reply and before
/// the handler releases it.
#[cfg(test)]
pub(super) mod release_hook {
    use std::cell::Cell;

    thread_local! {
        // Per thread: the handler resumes on the test's own current-thread
        // runtime.
        static FLAG: Cell<Option<oneiron::EntityId>> = const { Cell::new(None) };
    }

    pub(in crate::api::git_lfs) fn arm(world: oneiron::EntityId) {
        FLAG.set(Some(world));
    }

    pub(super) fn run(server: &crate::server::SyncServer) {
        if let Some(world) = FLAG.take() {
            server
                .vault
                .set_world_device_only(world, true)
                .expect("device-only flag");
        }
    }
}
