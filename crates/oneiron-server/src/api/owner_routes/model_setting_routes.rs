//! `/v1/owner/settings/models`: the owner's model settings. Today that is
//! the Responses `store` switch (OF-602): off, nothing is kept at the
//! provider and a reconnected socket sends the whole conversation; on, the
//! provider keeps each response and a reconnected socket resumes the chain.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::get;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/settings/models", get(read).post(put))
}

/// The owner's model settings.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ModelSettings {
    /// Whether a provider keeps each Responses turn (`store`).
    responses_store: bool,
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
    payload: Result<Json<ModelSettings>, JsonRejection>,
) -> OwnerReply<ModelSettings> {
    let owner = owner(&auth, &server)?;
    let settings = json_payload(payload)?;
    let settings = blocking(move || -> OwnerResult<ModelSettings> {
        server
            .vault()
            .set_responses_store(&owner, settings.responses_store)?;
        Ok(settings)
    })
    .await?;
    crate::models::set_responses_store(settings.responses_store);
    Ok(Json(settings))
}
