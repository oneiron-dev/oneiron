//! `/v1/owner/settings/learning`: the owner reads the learned-setting
//! catalog and its own rows, and lays or clears a seed or a pin at the vault,
//! a project or a task type (`oneiron::learning_setting_doors`). The engine
//! keeps the catalog bounds and the seed and pin rules.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::learning_setting_doors::{
    LearningSettingClear, LearningSettingPut, LearningSettingsRequest, LearningSettingsView,
};

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::OwnerResult;
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/settings/learning", get(list).post(put))
        .route("/settings/learning/clear", post(clear))
}

/// `GET /v1/owner/settings/learning[?key=<key>]`: the catalog, each knob
/// with the value the vault reads now, and the owner's rows.
async fn list(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<LearningSettingsRequest>, QueryRejection>,
) -> OwnerReply<LearningSettingsView> {
    let owner = owner(&auth, &server)?;
    let request = query_params(query)?;
    let view = blocking(move || -> OwnerResult<LearningSettingsView> {
        Ok(oneiron::learning_setting_doors::learning_settings_as_owner(
            server.vault(),
            &owner,
            &request,
        )?)
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/settings/learning`: lays one seed or pin, replacing the
/// row of the same key, mode and scope.
async fn put(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<LearningSettingPut>, JsonRejection>,
) -> OwnerReply<LearningSettingsView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let view = blocking(move || -> OwnerResult<LearningSettingsView> {
        Ok(
            oneiron::learning_setting_doors::put_learning_setting_as_owner(
                server.vault(),
                &owner,
                request,
            )?,
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
    payload: Result<Json<LearningSettingClear>, JsonRejection>,
) -> OwnerReply<LearningSettingsView> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let view = blocking(move || -> OwnerResult<LearningSettingsView> {
        Ok(
            oneiron::learning_setting_doors::clear_learning_setting_as_owner(
                server.vault(),
                &owner,
                request,
            )?,
        )
    })
    .await?;
    Ok(Json(view))
}
