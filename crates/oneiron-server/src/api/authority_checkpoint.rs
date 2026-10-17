//! OF-469: a kept authority checkpoint image and its attestations, for a
//! paired device to adopt.
//!
//! `GET /v1/core/authority/checkpoints/{id}` answers the image this vault
//! keeps at `id` (64 lower-case hex) and the attestations stored for it under
//! the image's own root policy. The device fetches the image the pin its
//! pairing returned names and verifies it against that pin; nothing here is
//! trusted for having been served. Any verified credential that reads may
//! fetch; an id this vault keeps no image at answers `NOT_FOUND`.
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::response::Json;
use oneiron::authority::AuthorityCheckpointBundle;

use crate::auth::{CoreAuth, CoreScope};
use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;

pub(super) async fn bundle(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(id): Path<String>,
) -> Result<Json<AuthorityCheckpointBundle>, EnvelopedApiError> {
    auth.require(CoreScope::Read)?;
    let image = crate::auth::parse_slip_id(&id)
        .map_err(|_| ApiError::bad_request("the checkpoint id is not 64 lower-case hex", None))?;
    let vault = Arc::clone(server.vault());
    let bundle = tokio::task::spawn_blocking(move || vault.authority_checkpoint_bundle(&image))
        .await
        .map_err(|_| ApiError::internal_server_error("the checkpoint read stopped"))?
        .map_err(|error| super::core_engine_error("authority checkpoint bundle", error))?;
    bundle
        .map(Json)
        .ok_or_else(|| ApiError::not_found("authority checkpoint", Some(&id)).into())
}
