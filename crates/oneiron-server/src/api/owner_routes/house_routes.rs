//! `/v1/owner/workspace/finish`: the owner finishes a stored workspace and
//! its house mind takes the root project's lead (ARCH-0067, FIX 700/911),
//! behind the same owner door as every other owner route. The house is the
//! one the workspace's stored preset names, never one the caller names.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use serde::Deserialize;

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::house;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: "/workspace/finish",
            summary: "\"<ref>\"}: a repeat leaves the root as the first finish signed it.",
            row: None,
            shape: Some(RestShape::json(
                finish_workspace_body_schema,
                workspace_finished_schema,
            )),
        },
        post(finish),
    )]
}

/// `POST /v1/owner/workspace/finish`.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct FinishWorkspace {
    /// The stored workspace whose house leads the root.
    workspace_ref: String,
}

/// The OpenAPI schema of `POST /v1/owner/workspace/finish`'s body
/// (FIX 11611): [`FinishWorkspace`].
pub(crate) fn finish_workspace_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<FinishWorkspace>()
}

/// The OpenAPI schema of `POST /v1/owner/workspace/finish`'s answer
/// (FIX 11611): unit, answered as JSON null.
pub(crate) fn workspace_finished_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<()>()
}

/// `POST /v1/owner/workspace/finish` with `{"workspace_ref": "<ref>"}`: a
/// repeat leaves the root as the first finish signed it.
async fn finish(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<FinishWorkspace>,
) -> OwnerReply<()> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    blocking(move || house::finish_workspace(&server, &owner, &request.workspace_ref)).await?;
    Ok(Json(()))
}
