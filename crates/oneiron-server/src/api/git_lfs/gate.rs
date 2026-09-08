//! LFS authentication gate and principal checks.

use super::LFS_MAX_OBJECT_BYTES;
use super::{lfs_batch, lfs_download, lfs_upload, lfs_verify};
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::server::SyncServer;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::HeaderMap;
use axum::routing::get;
use axum::routing::post;
use std::sync::Arc;

/// Builds the git-LFS routes. Merged into the ONE-1908 git router.
pub(crate) fn lfs_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/git/{repo}/info/lfs/objects/batch", post(lfs_batch))
        .route(
            "/git/{repo}/info/lfs/objects/{oid}",
            get(lfs_download)
                .put(lfs_upload)
                .post(lfs_upload)
                .layer(DefaultBodyLimit::max(LFS_MAX_OBJECT_BYTES)),
        )
        .route(
            "/git/{repo}/info/lfs/objects/{oid}/verify",
            post(lfs_verify),
        )
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// What one LFS request needs to be allowed to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LfsAccess {
    /// Reads bytes this vault already holds.
    Read,
    /// Makes bytes durable, or probes an upload flow.
    Write,
}

/// Authenticates and authorizes one LFS request.
///
/// Split from the handlers so the gate is testable as itself, exactly as the
/// smart-HTTP gate is: the scope check and the registered-principal demand are
/// one function with no transport around them.
pub(super) fn authorize(
    headers: &HeaderMap,
    server: &SyncServer,
    access: LfsAccess,
) -> Result<CoreAuth, ApiError> {
    let auth = CoreAuth::from_headers(headers, &server.config, server.vault().as_ref())?;
    auth.require(CoreScope::Read)?;
    if access == LfsAccess::Write {
        require_lfs_write(&auth)?;
    }
    Ok(auth)
}

/// The write half of the gate, over an already-authenticated actor.
///
/// A hatch-only identity and a bare trust-root secret both arrive here with
/// every scope and no `principal_ref`. Neither is a registered actor, so
/// neither may write — on 127.0.0.1 exactly as much as anywhere else.
pub(super) fn require_lfs_write(auth: &CoreAuth) -> Result<(), ApiError> {
    auth.require(CoreScope::Write)?;
    auth.require_registered_principal()?;
    Ok(())
}
