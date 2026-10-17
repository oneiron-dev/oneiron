//! OF-516: a role holder's door to the ladder's person asks (Q3 by role). A
//! person or bound agent holding the role an ask is at now, its principal as
//! a standing question's responsible actor or a board the ask climbed to,
//! lists those asks and answers them, as the owner does at
//! `/v1/owner/decisions/asks`. The role check, made again when the answer
//! lands, is the authorization.
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::WriteActor;
use oneiron::llm::decision::{DecisionAnswer, DecisionAsk};
use oneiron::memory::{MEMORY_CODE_INTERNAL, MEMORY_CODE_NOT_FOUND};
use serde::Deserialize;

use super::{FacadeApiError, facade_actor, facade_input, facade_json};
use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;

pub(crate) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/v1/core/decisions/asks", get(asks))
        .route("/v1/core/decisions/asks/answer", post(answer))
}

/// The same answer the owner's door takes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerAsk {
    seq: u64,
    answer: DecisionAnswer,
}

/// `GET /v1/core/decisions/asks`: the open asks at a role the credential's
/// principal holds now, oldest first.
async fn asks(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<Vec<DecisionAsk>>, FacadeApiError> {
    auth.require(CoreScope::Read)?;
    let (actor, _) = facade_actor(&auth)?;
    let vault = Arc::clone(&server.vault);
    let asks = tokio::task::spawn_blocking(move || vault.decision_asks_held_by(actor))
        .await
        .map_err(|_| internal())?
        .map_err(engine)?;
    Ok(Json(asks))
}

/// `POST /v1/core/decisions/asks/answer`: a role holder's answer to one ask,
/// checked against the role's live holders when it lands. The same answer
/// again returns the ask as it stands.
async fn answer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<DecisionAsk>, FacadeApiError> {
    auth.require(CoreScope::Write)?;
    auth.require_unrestricted_record_scope()?;
    let (actor, class) = facade_actor(&auth)?;
    let request: AnswerAsk = facade_input(facade_json(payload)?)?;
    let ask = tokio::task::spawn_blocking(move || {
        let asks = server.decision_host().asks();
        if asks.get(request.seq)?.is_none() {
            return Ok(None);
        }
        asks.answer_as(&WriteActor::new(actor, class), request.seq, request.answer)
            .map(Some)
    })
    .await
    .map_err(|_| internal())?
    .map_err(engine)?
    .ok_or_else(|| {
        FacadeApiError::new(
            StatusCode::NOT_FOUND,
            MEMORY_CODE_NOT_FOUND,
            "no such decision ask",
            ["List the asks at your role with GET /v1/core/decisions/asks."],
        )
    })?;
    Ok(Json(ask))
}

fn engine(error: oneiron::Error) -> FacadeApiError {
    crate::api::error_map::core_engine_error("decision ask answer", error).into()
}

fn internal() -> FacadeApiError {
    FacadeApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        MEMORY_CODE_INTERNAL,
        "the answer did not finish",
        ["Read the ask again before answering."],
    )
}
