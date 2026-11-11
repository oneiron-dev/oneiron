//! `/v1/owner/settings/models`: the owner's model settings and first-run setup.
//! The Responses `store` switch (OF-602): off, nothing is kept at the provider
//! and a reconnected socket sends the whole conversation; on, the provider
//! keeps each response and a reconnected socket resumes the chain. `/setup`
//! configures the model slots on the vault this server already opened.

use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::task_verb::sdk::ModelResponsesStoreSettings as ModelSettings;

use super::{CHANGED, OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::commands::{ModelSetupAnswers, ModelSetupOutcome, setup_models_on_open_vault};
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/settings/models",
                summary: "The owner's Responses store setting.",
                row: None,
                shape: None,
            },
            get(read),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/settings/models",
                summary: "Sets the switch; the next Responses turn reads it.",
                row: None,
                shape: Some(RestShape::json(
                    model_settings_schema,
                    model_settings_schema,
                )),
            },
            post(put),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/settings/models/setup",
                summary: "Configures first-run models on the vault this server already opened.",
                row: None,
                shape: Some(
                    RestShape::json(model_setup_answers_schema, model_setup_outcome_schema)
                        .refusing(&[CHANGED]),
                ),
            },
            post(setup),
        ),
    ]
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
        server.apply_responses_store(&owner, settings.responses_store)?;
        Ok(settings)
    })
    .await?;
    Ok(Json(settings))
}

/// The model answers accepted by first-run setup.
pub(crate) fn model_setup_answers_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ModelSetupAnswers>()
}

/// The configuration and model slots first-run setup installed.
pub(crate) fn model_setup_outcome_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ModelSetupOutcome>()
}

/// `POST /v1/owner/settings/models/setup` on the already-open vault.
async fn setup(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ModelSetupAnswers>,
) -> OwnerReply<ModelSetupOutcome> {
    let owner = owner(&auth, &server)?;
    let answers = payload.read(&server).await?;
    let outcome = blocking(move || setup_models_on_open_vault(&server, &owner, answers)).await?;
    Ok(Json(outcome))
}
