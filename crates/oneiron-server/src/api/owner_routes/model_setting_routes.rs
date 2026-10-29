//! `/v1/owner/settings/models`: the owner's model settings. Today that is
//! the Responses `store` switch (OF-602): off, nothing is kept at the
//! provider and a reconnected socket sends the whole conversation; on, the
//! provider keeps each response and a reconnected socket resumes the chain.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::response::Json;
use axum::routing::get;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/settings/models", get(read).post(put))
}

/// The owner's model settings.
#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ModelSettings {
    /// Whether a provider keeps each Responses turn (`store`).
    responses_store: bool,
}

/// The OpenAPI schema of `POST /v1/owner/settings/models`'s body and answer (FIX
/// 11103): [`ModelSettings`].
pub(crate) fn model_settings_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ModelSettings>()
}

/// `GET /v1/owner/settings/models`.
async fn read(auth: CoreAuth, State(server): State<Arc<SyncServer>>) -> OwnerReply<ModelSettings> {
    owner(&auth, &server)?;
    let settings = blocking(move || -> OwnerResult<ModelSettings> {
        Ok(ModelSettings {
            responses_store: server.vault().responses_store()?,
        })
    })
    .await?;
    Ok(Json(settings))
}

/// `POST /v1/owner/settings/models`: sets the switch; the next Responses
/// turn reads it.
async fn put(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ModelSettings>,
) -> OwnerReply<ModelSettings> {
    let owner = owner(&auth, &server)?;
    let settings = payload.read(&server).await?;
    let settings = blocking(move || -> OwnerResult<ModelSettings> {
        server
            .vault()
            .set_responses_store(&owner, settings.responses_store)?;
        // Only this server's providers read it (FIX 9516), once its vault
        // kept it.
        server
            .ai
            .models()
            .responses_context()
            .set_store(settings.responses_store);
        Ok(settings)
    })
    .await?;
    Ok(Json(settings))
}
