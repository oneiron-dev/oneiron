//! `POST /v1/core/linear/push`: a caller's own push of one TASK to Linear
//! now (FIX 8788, FIX 9382). The caller holds core write and reads the TASK;
//! the push goes as a scheduled pass sends it (`crate::linear_host`), under
//! the same admission for the scheduler and the TASK revision's verified
//! writer, and waits up to the caller's `wait_ms` for a full Rate window.
//! Zero answers at once; a push that still waits answers `waiting`, and its
//! TASK stays dirty for a later pass or push. Nothing here refuses for a
//! count or a size.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use oneiron::registry::ENTITY_TYPE_TASK;
use oneiron::{LinearMirrorStatus, LinearSyncError};
use serde::{Deserialize, Serialize};

use super::{
    core_engine_error, json_payload, parse_entity_id_param, require_entity_type,
    scoped_read_for_core_auth,
};
use crate::auth::{CoreAuth, CoreScope};
use crate::error::{ApiError, EnvelopedApiError};
use crate::linear_host::LinearPushError;
use crate::server::SyncServer;

/// A caller's push of one TASK.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinearPushRequest {
    /// The TASK, in hex.
    task_ref: String,
    /// How long the push may wait for a full Rate window, in milliseconds;
    /// zero, the default, answers at once.
    #[serde(default)]
    wait_ms: u64,
}

/// What a caller's push did.
#[derive(Debug, Serialize)]
pub(crate) struct LinearPushReply {
    task_ref: String,
    /// `linked`, `applied`, `noop` or `conflict` for a push that ran;
    /// `nothing_owed` when the TASK owes the mirror nothing or its push is
    /// held; `waiting` when it waits its turn.
    status: &'static str,
    /// The mirrored issue's identifier, for a push that ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    issue: Option<String>,
    /// Why the push waits, when it waits.
    #[serde(skip_serializing_if = "Option::is_none")]
    waiting: Option<String>,
}

/// Pushes the caller's TASK now, on a blocking thread.
pub(crate) async fn core_linear_push(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<LinearPushRequest>, JsonRejection>,
) -> Result<Json<LinearPushReply>, EnvelopedApiError> {
    auth.require(CoreScope::Write)?;
    let request = json_payload(payload)?;
    let task = parse_entity_id_param(&request.task_ref, "task_ref")?;
    require_entity_type(&server, &task, ENTITY_TYPE_TASK, "task")?;
    let readable = scoped_read_for_core_auth(&server.vault, &auth)?
        .is_entity_readable(&task)
        .map_err(|error| core_engine_error("TASK read failed", error))?;
    if !readable {
        return Err(ApiError::not_found("task", Some(&task.to_hex())).into());
    }
    let wait = Duration::from_millis(request.wait_ms);
    let body_line = crate::linear_host::push_body_line(&server);
    let pushing = Arc::clone(&server);
    let pushed = tokio::task::spawn_blocking(move || {
        crate::linear_host::push_task_now(&pushing, task, wait, &body_line)
    })
    .await
    .map_err(|_| ApiError::internal_server_error("Linear push did not finish"))?;
    let reply = |status, issue, waiting| LinearPushReply {
        task_ref: task.to_hex(),
        status,
        issue,
        waiting,
    };
    match pushed {
        Ok(Some(receipt)) => {
            let status = match receipt.status {
                LinearMirrorStatus::Linked => "linked",
                LinearMirrorStatus::Applied => "applied",
                LinearMirrorStatus::Noop => "noop",
                LinearMirrorStatus::Conflict => "conflict",
            };
            Ok(Json(reply(status, Some(receipt.issue.identifier), None)))
        }
        Ok(None) => Ok(Json(reply("nothing_owed", None, None))),
        Err(LinearPushError::Sync(LinearSyncError::Waiting(waiting))) => {
            Ok(Json(reply("waiting", None, Some(waiting.to_string()))))
        }
        Err(LinearPushError::Unavailable(why)) => {
            Err(ApiError::invalid_state(Some(why.as_str())).into())
        }
        // The door's own refusal text names no provider body or credential.
        Err(LinearPushError::Sync(LinearSyncError::Transport(why))) => {
            Err(ApiError::invalid_state(Some(why.as_str())).into())
        }
        Err(LinearPushError::Sync(LinearSyncError::AuthorizationDenied)) => {
            Err(ApiError::invalid_state(Some("linear_effect_not_admitted")).into())
        }
        Err(LinearPushError::Sync(LinearSyncError::RemoteChanged)) => {
            Err(ApiError::invalid_state(Some("linear_remote_changed")).into())
        }
        Err(LinearPushError::Sync(error)) => {
            tracing::warn!(%error, "Linear push failed");
            Err(ApiError::internal_server_error("Linear push failed").into())
        }
    }
}
