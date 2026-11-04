//! `POST /v1/owner/packs/preview` (FIX 5493): the owner's look at a pack
//! folder before `POST /v1/owner/packs`, as `vault.packs.preview` answers it.
//! It names the world a travelling agent would land in when that world's
//! current setting does not cover this machine ("please double-check"),
//! stages and writes nothing, and never stops the put that follows.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use oneiron::EntityId;
use oneiron::skill_hub::pack_catalog::PackImportPreview;
use oneiron::task_verb::sdk::{PackFileInput, decode_pack_files};
use serde::Deserialize;

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::OwnerError;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: "/packs/preview",
            summary: "What installing a pack folder would land, and each world it would land in that this machine's setting does not cover; stages and writes nothing (FIX 5493).",
            row: None,
            shape: Some(RestShape::json(
                preview_pack_body_schema,
                pack_import_preview_schema,
            )),
        },
        post(preview),
    )]
}

/// The folder `POST /v1/owner/packs` would take, and the world the owner
/// would pick for an agent held for its world.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct PreviewPack {
    /// An absolute folder on this host.
    #[serde(default)]
    path: Option<PathBuf>,
    /// The folder's files, when the caller sends them instead.
    #[serde(default)]
    files: Option<Vec<PackFileInput>>,
    /// The picked live local world, as 32 hex.
    #[serde(default)]
    world: Option<String>,
}

/// The OpenAPI schema of `POST /v1/owner/packs/preview`'s body (FIX 11611):
/// [`PreviewPack`].
pub(crate) fn preview_pack_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PreviewPack>()
}

/// The OpenAPI schema of `POST /v1/owner/packs/preview`'s answer (FIX 11611):
/// [`PackImportPreview`].
pub(crate) fn pack_import_preview_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PackImportPreview>()
}

/// `POST /v1/owner/packs/preview`: what installing the folder would land,
/// and each world it would land in that this machine's setting does not
/// cover.
async fn preview(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<PreviewPack>,
) -> OwnerReply<PackImportPreview> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let preview = blocking(move || {
        let files = match (request.path, request.files) {
            (Some(path), None) => super::pack_routes::read_folder(&path)?,
            (None, Some(files)) => {
                decode_pack_files(files).map_err(|error| OwnerError::Invalid(error.to_string()))?
            }
            _ => {
                return Err(OwnerError::Invalid(
                    "send exactly one of path or files".to_owned(),
                ));
            }
        };
        let world = request
            .world
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()
            .map_err(|_| OwnerError::Invalid("world is not an entity id".to_owned()))?;
        Ok(server.vault().preview_pack_import(&owner, files, world)?)
    })
    .await?;
    Ok(Json(preview))
}
