//! `/v1/owner/inbox/concern`: the owner reads one of the Coach's agent-health
//! cards (OF-568) with its run-tree diagram, and settles it: confirmed,
//! dismissed or unresolved. A settled card leaves "Waiting on you" until its
//! evidence grows. The outcome never moves `learning.reliability`. The owner
//! may also take the card's `ask_coach` move: the Coach's proposal lands on
//! the card. Only the owner applies a `skill_edit` proposal, as an approval of
//! one exact edit that the held-out gate then rules on.

use std::sync::Arc;

use axum::Router;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{Query, State};
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::EdgeActorClass;
use oneiron::dreamer_runner::maintenance::agent_health::{
    AgentHealthCardView, AgentHealthMove, AgentHealthOutcome, ConcernApplyOutcome,
    ConcernApplyRequest, ConcernCardSummary, ConcernMove, ConcernMoveLink, ConcernMoveOutcome,
    ConcernMoveRequest,
};
use oneiron::memory::MemoryError;
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
        .route("/inbox/concern/move", post(take_move))
        .route("/inbox/concern/apply", post(apply_edit))
        .route(
            "/inbox/concern/apply-prompt-inject",
            post(apply_prompt_inject),
        )
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

fn move_error(error: MemoryError) -> OwnerError {
    match error.code.as_str() {
        oneiron::memory::MEMORY_CODE_BAD_REQUEST => OwnerError::Invalid(error.message),
        oneiron::memory::MEMORY_CODE_INVALID_STATE => OwnerError::Changed(error.message),
        _ => OwnerError::Refused(error.message),
    }
}

/// `POST /v1/owner/inbox/concern/move`: takes one of the card's moves, with
/// `self.inbox.concern.move`'s input. `ask_coach` asks the Coach; asking
/// again on the same evidence returns the standing ask. A `note` goes to the
/// card's agent as the owner's own message, and a `steer` to its TASK's live
/// run as the owner's steer; a resend with the same key returns the first
/// receipt.
async fn take_move(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ConcernMoveRequest>, JsonRejection>,
) -> OwnerReply<ConcernMoveOutcome> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let locality = auth.locality();
    let host = Arc::clone(&server);
    let outcome = blocking(move || -> OwnerResult<ConcernMoveOutcome> {
        let vault = server.vault();
        if !matches!(request.r#move, ConcernMove::AskCoach) {
            return vault
                .apply_concern_move(&owner, locality, &request)
                .map_err(move_error);
        }
        let Some(card) = vault.agent_health_card(&request.card)? else {
            return Err(OwnerError::NotFound("concern_card", request.card));
        };
        if !card.moves.contains(&AgentHealthMove::AskCoach) {
            return Err(OwnerError::Invalid(
                "this concern card proposes no ask_coach move".to_owned(),
            ));
        }
        match vault.ask_coach_on_agent_health_card(&owner, &request.card) {
            Ok(outcome) => Ok(outcome),
            Err(error) if error.kind() == oneiron::ErrorKind::EntityNotFound => {
                Err(OwnerError::NotFound("concern_card", request.card))
            }
            Err(error) => Err(error.into()),
        }
    })
    .await?;
    // A note landed a turn: its producer wakes after the commit, as the
    // message path's does.
    if let ConcernMoveOutcome::Applied { receipt, .. } = &outcome
        && matches!(receipt.link, ConcernMoveLink::Note { .. })
    {
        host.ai
            .turn_landed_by(host.vault(), receipt.actor, EdgeActorClass::Human);
    }
    Ok(Json(outcome))
}

/// `POST /v1/owner/inbox/concern/apply`: applies the Coach's `skill_edit` on
/// one card as the owner approves it: the ask they read, the skill and
/// version the edit replaces, and the whole replacement instructions. The
/// edit lands as a gated candidate, and only the held-out gate's acceptance
/// admits it; applying the same approval again returns the same candidate.
async fn apply_edit(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<ConcernApplyRequest>, JsonRejection>,
) -> OwnerReply<ConcernApplyOutcome> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let outcome = blocking(move || -> OwnerResult<ConcernApplyOutcome> {
        match server
            .vault()
            .apply_coach_skill_edit_on_agent_health_card(&owner, &request)
        {
            Ok(outcome) => Ok(outcome),
            Err(error) if error.kind() == oneiron::ErrorKind::EntityNotFound => {
                Err(OwnerError::NotFound("concern_card", request.card))
            }
            Err(error) => Err(error.into()),
        }
    })
    .await?;
    Ok(Json(outcome))
}

/// `POST /v1/owner/inbox/concern/apply-prompt-inject`: applies the Coach's
/// `prompt_inject` on one card as the owner approves it: the ask they read,
/// the prompt (the Coach's proposal, or the owner's own edit of it), and
/// optionally the checkpoint the failed run continues from. The failed
/// attempt goes on as a new attempt from that checkpoint with the approved
/// prompt; applying the same approval again returns the same successor. A
/// refusal names its `continuation_*` code.
async fn apply_prompt_inject(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<oneiron::agent_dispatch::ConcernPromptInjectRequest>, JsonRejection>,
) -> OwnerReply<oneiron::agent_dispatch::ConcernPromptInjectOutcome> {
    let owner = owner(&auth, &server)?;
    let request = json_payload(payload)?;
    let outcome = blocking(
        move || -> OwnerResult<oneiron::agent_dispatch::ConcernPromptInjectOutcome> {
            match server
                .vault()
                .apply_coach_prompt_inject_on_agent_health_card(&owner, &request)
            {
                Ok(outcome) => Ok(outcome),
                Err(error) if error.kind() == oneiron::ErrorKind::EntityNotFound => {
                    Err(OwnerError::NotFound("concern_card", request.card))
                }
                // The door's refusals, a `continuation_*` code included, reach
                // the owner as exactly their text.
                Err(oneiron::Error::InvalidConfig(why)) => Err(OwnerError::Refused(why)),
                Err(error) => Err(error.into()),
            }
        },
    )
    .await?;
    Ok(Json(outcome))
}
