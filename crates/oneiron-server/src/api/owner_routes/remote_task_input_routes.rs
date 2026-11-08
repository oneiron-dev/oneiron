//! `/v1/owner/connectors/remote-tasks/{intent}/input`: a background MCP
//! task's form question, parked for the vault owner (FIX 16029, L13). A
//! remote task in `input_required` asked a form question while nobody was
//! at its call; the served poller parked it in the ledger with an owner Ask
//! on the decision-ask queue. The owner reads the question here (the
//! connector's message and the form it asks for) and submits the values for
//! the round read; the poller sends them when the connector asks that same
//! question again. Decline and Cancel are the Ask's own options
//! (`/v1/owner/decisions/asks/answer`). The intent is the call's 64-hex
//! intent id. The engine checks the owner's proof again in each transaction.

use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::outbound_intent_ledger::RemoteTaskInputView;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/connectors/remote-tasks/{intent}/input",
                summary: "The form question a background MCP task parked for the owner (FIX 16029): the connector, the tool, the connector's message, the requested schema and its field names, the question's phase and round (`generation`) and its owner ask. `intent` is the call's 64-hex intent id. Not found when no question is parked.",
                row: None,
                shape: None,
            },
            get(question),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/connectors/remote-tasks/{intent}/input",
                summary: "The owner's values for a background MCP task's parked form question (FIX 16029): `generation`, the round read, and `content`, one value per field of its requested schema. They are checked against that schema and sealed, the question is ready to send, and its owner ask is answered; the poller sends them when the connector asks the same question again.",
                row: None,
                shape: Some(RestShape::json(
                    submit_input_body_schema,
                    input_submitted_schema,
                )),
            },
            post(submit),
        ),
    ]
}

/// The owner's values for one round of a parked question.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct SubmitInput {
    /// The question's round, as the owner read it: a question that changed
    /// since is refused.
    generation: u32,
    /// One value per field of the question's requested schema.
    content: Map<String, Value>,
}

/// The round the values answer, now ready to send.
#[derive(Serialize, schemars::JsonSchema)]
struct InputSubmitted {
    generation: u32,
    /// `ready`: the poller sends the values when the connector asks again.
    phase: &'static str,
}

/// The OpenAPI schema of `POST /v1/owner/connectors/remote-tasks/{intent}/input`'s
/// body: [`SubmitInput`].
pub(crate) fn submit_input_body_schema() -> Value {
    oneiron_contracts::code_run::vault_read::request_schema::<SubmitInput>()
}

/// The OpenAPI schema of `POST /v1/owner/connectors/remote-tasks/{intent}/input`'s
/// answer: [`InputSubmitted`].
pub(crate) fn input_submitted_schema() -> Value {
    oneiron_contracts::code_run::vault_read::request_schema::<InputSubmitted>()
}

/// The intent id a path names: 64 lower-case hex, the 32-byte intent.
fn intent_id(value: &str) -> OwnerResult<[u8; 32]> {
    blake3::Hash::from_hex(value)
        .ok()
        .filter(|hash| hash.to_hex().as_str() == value)
        .map(|hash| *hash.as_bytes())
        .ok_or_else(|| OwnerError::Invalid("intent must be a 64-hex intent id".into()))
}

/// `GET /v1/owner/connectors/remote-tasks/{intent}/input`: the parked
/// question, opened for the owner.
async fn question(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(intent): UrlPath<String>,
) -> OwnerReply<RemoteTaskInputView> {
    let owner = owner(&auth, &server)?;
    let view = blocking(move || -> OwnerResult<RemoteTaskInputView> {
        let id = intent_id(&intent)?;
        server
            .vault()
            .remote_task_input_question(&owner, &id)?
            .ok_or(OwnerError::NotFound("remote task input", intent))
    })
    .await?;
    Ok(Json(view))
}

/// `POST /v1/owner/connectors/remote-tasks/{intent}/input`: the owner's
/// values for the round read.
async fn submit(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    UrlPath(intent): UrlPath<String>,
    payload: OwnerJsonBody<SubmitInput>,
) -> OwnerReply<InputSubmitted> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let submitted = blocking(move || -> OwnerResult<InputSubmitted> {
        let id = intent_id(&intent)?;
        server.vault().submit_remote_task_input(
            &owner,
            &id,
            request.generation,
            request.content,
        )?;
        Ok(InputSubmitted {
            generation: request.generation,
            phase: "ready",
        })
    })
    .await?;
    Ok(Json(submitted))
}
