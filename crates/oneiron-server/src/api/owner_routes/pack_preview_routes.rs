//! `POST /v1/owner/packs/preview` (FIX 5493): the owner's look at a pack
//! folder before `POST /v1/owner/packs`, as `vault.packs.preview` answers it.
//! It names the world a travelling agent would land in when that world's
//! current setting does not cover this machine ("please double-check"),
//! stages and writes nothing, and never stops the put that follows.

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::post;
use oneiron::EntityId;
use oneiron::skill_hub::pack_catalog::PackImportPreview;
use oneiron::task_verb::sdk::{PackFileInput, decode_pack_files};
use serde::Deserialize;

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::OwnerError;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/packs/preview", post(preview))
}

/// The folder `POST /v1/owner/packs` would take, and the world the owner
/// would pick for an agent held for its world.
#[derive(Debug, Deserialize)]
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

/// `POST /v1/owner/packs/preview`: what installing the folder would land,
/// and each world it would land in that this machine's setting does not
/// cover.
async fn preview(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<PreviewPack>, JsonRejection>,
) -> OwnerReply<PackImportPreview> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
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
