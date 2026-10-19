//! LFS authentication gate and principal checks.

use super::{lfs_batch, lfs_download, lfs_upload, lfs_verify};
use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::server::SyncServer;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::HeaderMap;
use axum::http::request::Parts;
use axum::routing::get;
use axum::routing::post;
use std::sync::Arc;

/// Builds the git-LFS routes. Merged into the ONE-1908 git router.
pub(crate) fn lfs_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route(
            "/git/{repo}/info/lfs/chunks",
            // The handler reads its body, within a frame, at its turn.
            post(super::chunks::exchange),
        )
        .route("/git/{repo}/info/lfs/objects/batch", post(lfs_batch))
        .route(
            "/git/{repo}/info/lfs/objects/{oid}",
            get(lfs_download)
                .put(lfs_upload)
                .post(lfs_upload)
                .layer(DefaultBodyLimit::disable()),
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
    admit(auth, access)
}

/// [`authorize`] for the request `parts` name. On a managed vault whose
/// supervisor attested the owner on this request, the caller is that owner
/// ([`CoreAuth::for_attested_request`]): the person himself while the vault
/// records him as its live owner, his registered principal and every owner
/// scope, judged by the same checks a bearer is. Every other request is
/// judged by its headers, as before. Either way the caller carries the
/// machine the binding door already proved for this request, if any
/// ([`crate::auth::proved_peer`], FIX 4937): its objects are released as that
/// machine may read them, and a request with no proof stays a destination
/// nobody proved.
pub(super) fn authorize_request(
    parts: &Parts,
    server: &SyncServer,
    access: LfsAccess,
) -> Result<CoreAuth, ApiError> {
    match CoreAuth::for_attested_request(
        &parts.headers,
        &parts.extensions,
        crate::auth::request_path(parts),
        server,
    ) {
        Some(attested) => admit(attested?, access),
        None => authorize(&parts.headers, server, access)
            .map(|auth| auth.toward(crate::auth::proved_peer(&parts.headers, &parts.extensions))),
    }
}

/// The gate past authentication: `Read`, an unrestricted record scope and,
/// for `Write`, the write half.
fn admit(auth: CoreAuth, access: LfsAccess) -> Result<CoreAuth, ApiError> {
    auth.require(CoreScope::Read)?;
    auth.require_unrestricted_record_scope()?;
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
