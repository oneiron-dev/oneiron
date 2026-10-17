//! `/v1/owner/inbox/concern/outcome`: the owner settles one of the Coach's
//! agent-health cards (OF-568): confirmed, dismissed or unresolved. A settled
//! card leaves "Waiting on you" until its evidence grows. The outcome never
//! moves `learning.reliability`.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::response::Json;
use axum::routing::post;
use oneiron::dreamer_runner::maintenance::agent_health::AgentHealthOutcome;
use serde::{Deserialize, Serialize};

use super::{OwnerReply, blocking, owner};
use crate::api::json_payload;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/inbox/concern/outcome", post(set_outcome))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConcernOutcome {
    /// The card's `health:` handle, the row's `payload_ref`.
    card: String,
    /// `confirmed`, `dismissed` or `unresolved`.
    outcome: String,
}

#[derive(Debug, Serialize)]
struct ConcernCard {
    card: String,
    agent: String,
    signal: &'static str,
    tone: &'static str,
    outcome: &'static str,
    evidence: usize,
}

/// `POST /v1/owner/inbox/concern/outcome`: sets one card's outcome.
async fn set_outcome(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ConcernOutcome>, JsonRejection>,
) -> OwnerReply<ConcernCard> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let card = blocking(move || -> OwnerResult<ConcernCard> {
        let outcome = AgentHealthOutcome::from_wire(&request.outcome).ok_or_else(|| {
            OwnerError::Invalid("outcome is confirmed, dismissed or unresolved".to_owned())
        })?;
        match server
            .vault()
            .set_agent_health_outcome(&owner, &request.card, outcome)
        {
            Ok(card) => Ok(ConcernCard {
                card: card.card_ref(),
                agent: card.subject.to_hex(),
                signal: card.signal.as_str(),
                tone: card.tone.as_str(),
                outcome: card.outcome.as_str(),
                evidence: card.evidence.len(),
            }),
            Err(error) if error.kind() == oneiron::ErrorKind::EntityNotFound => {
                Err(OwnerError::NotFound("concern_card", request.card))
            }
            Err(error) => Err(error.into()),
        }
    })
    .await?;
    Ok(Json(card))
}
