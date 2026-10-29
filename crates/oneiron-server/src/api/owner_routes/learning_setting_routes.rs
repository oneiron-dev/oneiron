//! `/v1/owner/settings/learning`: the owner reads the learned-setting
//! catalog and its own rows, and lays or clears a seed or a pin over a knob
//! or a spawn choice at the vault, a project's goal, a project or a task
//! type (`oneiron::learning_setting_doors`). The engine keeps the catalog
//! bounds and the seed and pin rules. Each route runs its
//! `vault.settings.learning*` row's verb hooks once around the call, as the
//! owner in person (FIX 9479).

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::learning_setting_doors::{
    self as doors, LearningSettingClear, LearningSettingPut, LearningSettingsRequest,
    LearningSettingsView,
};
use serde_json::Value;

use super::{OwnerReply, blocking, hooked_owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerResult, hooked_row};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/settings/learning", get(list).post(put))
        .route("/settings/learning/clear", post(clear))
}

/// The OpenAPI schema of `POST /v1/owner/settings/learning`'s body (FIX 11611):
/// [`LearningSettingPut`].
pub(crate) fn put_learning_setting_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<LearningSettingPut>()
}

/// The OpenAPI schema of `POST /v1/owner/settings/learning/clear`'s body (FIX 11611):
/// [`LearningSettingClear`].
pub(crate) fn clear_learning_setting_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<LearningSettingClear>()
}

/// The OpenAPI schema of the two learning writes' answer (FIX 11611): [`LearningSettingsView`].
pub(crate) fn learning_settings_view_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<LearningSettingsView>()
}

/// `GET /v1/owner/settings/learning[?key=<key>]`: the catalog, each knob
/// with the value the vault reads now, and the owner's rows.
async fn list(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<LearningSettingsRequest>, QueryRejection>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = query_params(query)?;
    let view = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.settings.learning",
            request,
            |request: LearningSettingsRequest| -> OwnerResult<LearningSettingsView> {
                Ok(doors::learning_settings_as_owner(vault, &owner, &request)?)
            },
        )
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/settings/learning`: lays one seed or pin, replacing the
/// row of the same key, mode and scope.
async fn put(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LearningSettingPut>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let view = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.settings.learning.put",
            request,
            |request: LearningSettingPut| -> OwnerResult<LearningSettingsView> {
                Ok(doors::put_learning_setting_as_owner(
                    vault, &owner, request,
                )?)
            },
        )
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/settings/learning/clear`: clears one row; an absent row
/// clears too.
async fn clear(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LearningSettingClear>,
) -> OwnerReply<Value> {
    let (owner, actor) = hooked_owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let view = blocking(move || {
        let vault = server.vault();
        hooked_row(
            vault,
            actor,
            "vault.settings.learning.clear",
            request,
            |request: LearningSettingClear| -> OwnerResult<LearningSettingsView> {
                Ok(doors::clear_learning_setting_as_owner(
                    vault, &owner, request,
                )?)
            },
        )
    })
    .await?;
    Ok(Json(view))
}
