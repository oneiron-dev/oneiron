//! `/v1/owner/workspace/finish`: the owner finishes a stored workspace and
//! its house mind takes the root project's lead (ARCH-0067, FIX 700/911),
//! behind the same owner door as every other owner route. The house is the
//! one the workspace's stored preset names, never one the caller names.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::post;
use serde::Deserialize;

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::house;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/workspace/finish", post(finish))
}

/// `POST /v1/owner/workspace/finish`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishWorkspace {
    /// The stored workspace whose house leads the root.
    workspace_ref: String,
}

/// `POST /v1/owner/workspace/finish` with `{"workspace_ref": "<ref>"}`: a
/// repeat leaves the root as the first finish signed it.
async fn finish(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<FinishWorkspace>, JsonRejection>,
) -> OwnerReply<()> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    blocking(move || house::finish_workspace(&server, &owner, &request.workspace_ref)).await?;
    Ok(Json(()))
}
