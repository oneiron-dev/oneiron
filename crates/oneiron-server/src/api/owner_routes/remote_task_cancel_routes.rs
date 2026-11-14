//! `/v1/owner/connectors/remote-tasks/{intent}/cancel`: the owner asks a
//! background MCP task to stop (L8-29; canon agent-runtime-v1
//! `#mcp-tasks-outbound`). A connector took the call as a remote task, so
//! its send is Deferred and the served poller reads the task's status. The
//! owner's ask marks the task's poll row, and the poller's next pass sends
//! the connector one `tasks/cancel`, which undoes nothing already done; the
//! send stays Deferred until a poll reads the task's end (`cancelled`, or
//! `completed` when the work finished first). The stop is sent once: a
//! second ask answers where the first stands. The intent is the call's
//! 64-hex intent id. The engine checks the owner's proof again in its
//! transaction. An owner act: no agent grant reaches it.

use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::response::Json;
use axum::routing::post;
use oneiron::outbound_intent_ledger::RemoteTaskCancelAsk;
use serde::Serialize;
use serde_json::Value;

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

/// The refusal state of a call whose connector never took it as a remote
/// task, or whose task already ended.
const NOT_DEFERRED: &str = "remote_task_not_deferred";
/// The refusal state of a remote task the host does not poll: its send's
/// credential cannot be presented again, so nothing can carry the stop.
const UNPOLLABLE: &str = "remote_task_unpollable";

pub(super) fn owner_table() -> OwnerTable {
    vec![(
        OwnerRoute {
            method: "post",
            path: "/connectors/remote-tasks/{intent}/cancel",
            summary: "The owner asks a background MCP task to stop (L8-29): the poller's next pass sends its connector one `tasks/cancel`, which undoes nothing already done, and the call stays deferred until a poll reads the task's end. `intent` is the call's 64-hex intent id. Answers where the stop stands (`requested`, `sending`, `sent` or `uncertain`); a second ask sends nothing more.",
            row: None,
            shape: Some(RestShape::no_body(cancel_asked_schema).refusing(&[
                ("404", "No call has this intent."),
                (
                    "409",
                    "The call is not a deferred remote task (`remote_task_not_deferred`), or its task keeps no poll because its credential cannot be presented again (`remote_task_unpollable`).",
                ),
            ])),
        },
        post(cancel),
    )]
}

/// Where the owner's stop of a remote task stands after the ask.
#[derive(Serialize, schemars::JsonSchema)]
struct CancelAsked {
    /// `requested`: the poller sends `tasks/cancel` on its next pass;
    /// `sending`, `sent` or `uncertain`: an earlier ask's stop, claimed,
    /// taken by the connector, or of unknown outcome. Never sent again.
    phase: &'static str,
}

/// The OpenAPI schema of `POST /v1/owner/connectors/remote-tasks/{intent}/cancel`'s
/// answer: [`CancelAsked`].
pub(crate) fn cancel_asked_schema() -> Value {
    oneiron_contracts::code_run::vault_read::request_schema::<CancelAsked>()
}

/// The intent id a path names: 64 lower-case hex, the 32-byte intent.
fn intent_id(value: &str) -> OwnerResult<[u8; 32]> {
    blake3::Hash::from_hex(value)
        .ok()
        .filter(|hash| hash.to_hex().as_str() == value)
        .map(|hash| *hash.as_bytes())
        .ok_or_else(|| OwnerError::Invalid("intent must be a 64-hex intent id".into()))
}

/// `POST /v1/owner/connectors/remote-tasks/{intent}/cancel`: the owner's
/// stop of the call's remote task.
async fn cancel(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(intent): UrlPath<String>,
) -> OwnerReply<CancelAsked> {
    let owner = owner(&auth, &server)?;
    let path = intent.clone();
    let asked = blocking(move || -> OwnerResult<RemoteTaskCancelAsk> {
        let id = intent_id(&intent)?;
        Ok(server.vault().request_remote_task_cancel(&owner, &id)?)
    })
    .await?;
    match asked {
        RemoteTaskCancelAsk::Marked(phase) => Ok(Json(CancelAsked {
            phase: phase.as_str(),
        })),
        RemoteTaskCancelAsk::Unknown => Err(ApiError::not_found("remote task", Some(&path)).into()),
        RemoteTaskCancelAsk::NotDeferred => Err(ApiError::invalid_state(Some(NOT_DEFERRED)).into()),
        RemoteTaskCancelAsk::Unpollable => Err(ApiError::invalid_state(Some(UNPOLLABLE)).into()),
    }
}
