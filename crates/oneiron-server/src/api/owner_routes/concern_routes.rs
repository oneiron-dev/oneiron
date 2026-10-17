//! `/v1/owner/inbox/concern`: the owner reads one of the Coach's agent-health
//! cards (OF-568) with its run-tree diagram, and settles it: confirmed,
//! dismissed or unresolved. A settled card leaves "Waiting on you" until its
//! evidence grows. The outcome never moves `learning.reliability`.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::dreamer_runner::maintenance::agent_health::{
    AgentHealthCardView, AgentHealthOutcome, ConcernCardSummary,
};
use serde::Deserialize;

use super::{OwnerReply, blocking, owner};
use crate::api::{json_payload, query_params};
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/inbox/concern", get(card))
        .route("/inbox/concern/outcome", post(set_outcome))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConcernCard {
    /// The card's `health:` handle, the row's `payload_ref`.
    card: String,
}

/// `GET /v1/owner/inbox/concern?card=<health:…>`: one card, with the run its
/// attempt is in and that attempt's node marked.
async fn card(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<ConcernCard>, QueryRejection>,
) -> OwnerReply<AgentHealthCardView> {
    owner(&auth, &server)?;
    let request = query_params(query)?;
    let view = blocking(move || -> OwnerResult<AgentHealthCardView> {
        server
            .vault()
            .agent_health_card_view(&request.card)?
            .ok_or(OwnerError::NotFound("concern_card", request.card))
    })
    .await?;
    Ok(Json(view))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConcernOutcome {
    /// The card's `health:` handle, the row's `payload_ref`.
    card: String,
    /// `confirmed`, `dismissed` or `unresolved`.
    outcome: String,
}

/// `POST /v1/owner/inbox/concern/outcome`: sets one card's outcome.
async fn set_outcome(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ConcernOutcome>, JsonRejection>,
) -> OwnerReply<ConcernCardSummary> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let card = blocking(move || -> OwnerResult<ConcernCardSummary> {
        let outcome = AgentHealthOutcome::from_wire(&request.outcome).ok_or_else(|| {
            OwnerError::Invalid("outcome is confirmed, dismissed or unresolved".to_owned())
        })?;
        match server
            .vault()
            .set_agent_health_outcome(&owner, &request.card, outcome)
        {
            Ok(card) => Ok(ConcernCardSummary::of(&card)),
            Err(error) if error.kind() == oneiron::ErrorKind::EntityNotFound => {
                Err(OwnerError::NotFound("concern_card", request.card))
            }
            Err(error) => Err(error.into()),
        }
    })
    .await?;
    Ok(Json(card))
}
