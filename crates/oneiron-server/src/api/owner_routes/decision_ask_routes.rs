//! `/v1/owner/decisions/asks`: the typed decisions the host's ladder asked
//! the vault owner (ARCH-0076, its last rung). The owner pages the asks and
//! answers each with one answer its question's contract accepts. The answer
//! is kept beside the ask and reaches every waiter on it; an answer that
//! changed the ladder's own is kept for the Coach.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::llm::decision::{DecisionAnswer, DecisionAsk};
use serde::Deserialize;

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

/// Asks one page holds unless the owner asks for fewer.
const PAGE: usize = 50;
const PAGE_MAX: usize = 500;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/decisions/asks", get(list))
        .route("/decisions/asks/answer", post(answer))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AskPage {
    /// The last arrival number read; the page starts after it.
    #[serde(default)]
    after: Option<u64>,
    #[serde(default)]
    limit: Option<usize>,
    /// Only the asks still waiting for an answer.
    #[serde(default)]
    open: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnswerAsk {
    seq: u64,
    answer: DecisionAnswer,
}

/// `GET /v1/owner/decisions/asks?after=<seq>&limit=<n>&open=<bool>`: the
/// asks after `after`, oldest first.
async fn list(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<AskPage>, QueryRejection>,
) -> OwnerReply<Vec<DecisionAsk>> {
    owner(&auth, &server)?;
    let page = query_params(query)?;
    let asks = blocking(move || -> OwnerResult<Vec<DecisionAsk>> {
        let limit = page.limit.unwrap_or(PAGE).clamp(1, PAGE_MAX);
        Ok(server
            .decision_host()
            .asks()
            .page(page.after, limit, page.open.unwrap_or(false))?)
    })
    .await?;
    Ok(Json(asks))
}

/// `POST /v1/owner/decisions/asks/answer`: the owner's answer to one ask.
/// The same answer again returns the ask as it stands.
async fn answer(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<AnswerAsk>, JsonRejection>,
) -> OwnerReply<DecisionAsk> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let ask = blocking(move || -> OwnerResult<DecisionAsk> {
        let asks = server.decision_host().asks();
        if asks.get(request.seq)?.is_none() {
            return Err(OwnerError::NotFound(
                "decision ask",
                request.seq.to_string(),
            ));
        }
        asks.answer(&owner, request.seq, request.answer)
            .map_err(|error| OwnerError::Invalid(error.to_string()))
    })
    .await?;
    Ok(Json(ask))
}
