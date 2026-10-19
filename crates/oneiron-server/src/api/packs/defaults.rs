//! Explicit default restores and on-demand imports from the pinned library.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::post;
use oneiron::skill_hub::{HubImportReceipt, default_skill_hub_id};
use oneiron::{EntityId, TimeRange, Vault};
use serde::Deserialize;

use crate::auth::CoreAuth;
use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;

use super::super::error_map::core_engine_error;
use super::super::owner_routes::owner;
use super::super::{json_payload, unix_seconds_now};

type Reply<T> = Result<Json<T>, EnvelopedApiError>;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/packs/defaults/restore", post(restore_defaults))
        .route("/packs/defaults/import", post(import_hub_skill))
        .route("/packs/defaults/restore-skill", post(restore_hub_skill))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HubSkillRequest {
    subtree: String,
}

async fn restore_defaults(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> Reply<Vec<HubImportReceipt>> {
    let owner = owner(&auth, &server)?;
    let receipts = blocking(move || {
        let vault = server.vault();
        let at = unix_seconds_now();
        let restored =
            vault.restore_default_skills(&owner, TimeRange { start: at, end: at }, at)?;
        restored
            .into_iter()
            .map(|entity| {
                vault
                    .current_hub_import_receipts(&entity)?
                    .into_iter()
                    .next()
                    .ok_or(oneiron::Error::InvariantViolation(
                        "restored default skill has no source receipt",
                    ))
            })
            .collect()
    })
    .await?;
    Ok(Json(receipts))
}

async fn import_hub_skill(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<HubSkillRequest>, JsonRejection>,
) -> Reply<HubImportReceipt> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let receipt = blocking(move || {
        let vault = server.vault();
        owner.revalidate(vault)?;
        let at = unix_seconds_now();
        let entity = vault.import_default_hub_skill(
            &request.subtree,
            TimeRange { start: at, end: at },
            at,
        )?;
        hub_skill_receipt(vault, &entity, &request.subtree)
    })
    .await?;
    Ok(Json(receipt))
}

async fn restore_hub_skill(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<HubSkillRequest>, JsonRejection>,
) -> Reply<HubImportReceipt> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let receipt = blocking(move || {
        let vault = server.vault();
        let at = unix_seconds_now();
        let entity = vault.restore_default_hub_skill(
            &owner,
            &request.subtree,
            TimeRange { start: at, end: at },
            at,
        )?;
        hub_skill_receipt(vault, &entity, &request.subtree)
    })
    .await?;
    Ok(Json(receipt))
}

fn hub_skill_receipt(
    vault: &Vault,
    entity: &EntityId,
    subtree: &str,
) -> oneiron::Result<HubImportReceipt> {
    let hub = default_skill_hub_id()?.to_hex();
    vault
        .current_hub_import_receipts(entity)?
        .into_iter()
        .find(|receipt| {
            receipt.hub_id == hub
                && receipt.ref_string == subtree
                && receipt.pin_type == "commit"
                && receipt.pin_value.is_some()
        })
        .ok_or(oneiron::Error::InvariantViolation(
            "default hub skill has no pinned source receipt",
        ))
}

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> oneiron::Result<T> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| ApiError::internal_server_error("default skill task failed"))?
        .map_err(|error| core_engine_error("default skill operation failed", error))
}
