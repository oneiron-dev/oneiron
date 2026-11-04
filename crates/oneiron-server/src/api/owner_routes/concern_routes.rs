//! `/v1/owner/inbox/concern`: the owner reads one of the Coach's agent-health
//! cards (OF-568) with its run-tree diagram, and settles it: confirmed,
//! dismissed or unresolved. A settled card leaves "Waiting on you" until its
//! evidence grows. The outcome never moves `learning.reliability`. The owner
//! may also take the card's `ask_coach` move: the Coach's proposal lands on
//! the card. Only the owner applies a `skill_edit` proposal, as an approval of
//! one exact edit that the held-out gate then rules on.

use std::sync::Arc;

use axum::extract::rejection::QueryRejection;
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

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::query_params;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn owner_table() -> OwnerTable {
    vec![
        (
            OwnerRoute {
                method: "get",
                path: "/inbox/concern",
                summary: "One card, with the run its attempt is in and that attempt's node marked.",
                row: None,
                shape: None,
            },
            get(card),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/inbox/concern/outcome",
                summary: "Sets one card's outcome.",
                row: None,
                shape: Some(RestShape::json(
                    concern_outcome_body_schema,
                    concern_card_summary_schema,
                )),
            },
            post(set_outcome),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/inbox/concern/move",
                summary: "Takes one of the card's moves.",
                row: None,
                shape: Some(RestShape::json(
                    concern_move_body_schema,
                    concern_move_outcome_schema,
                )),
            },
            post(take_move),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/inbox/concern/apply",
                summary: "Applies the Coach's skill edit on one card as the owner approves it.",
                row: None,
                shape: Some(RestShape::json(
                    concern_apply_body_schema,
                    concern_apply_outcome_schema,
                )),
            },
            post(apply_edit),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/inbox/concern/apply-prompt-inject",
                summary: "Applies the Coach's prompt injection on one card as the owner approves or edits it: the failed attempt goes on as a new one, from its pre-fail checkpoint.",
                row: None,
                shape: Some(RestShape::json(
                    concern_prompt_inject_body_schema,
                    concern_prompt_inject_outcome_schema,
                )),
            },
            post(apply_prompt_inject),
        ),
    ]
}

/// The OpenAPI schema of `POST /v1/owner/inbox/concern/outcome`'s body
/// (FIX 11611): [`ConcernOutcome`].
pub(crate) fn concern_outcome_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ConcernOutcome>()
}

/// The OpenAPI schema of `POST /v1/owner/inbox/concern/outcome`'s answer
/// (FIX 11611): [`ConcernCardSummary`].
pub(crate) fn concern_card_summary_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ConcernCardSummary>()
}

/// The OpenAPI schema of `POST /v1/owner/inbox/concern/move`'s body
/// (FIX 11611): [`ConcernMoveRequest`].
pub(crate) fn concern_move_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ConcernMoveRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/inbox/concern/move`'s answer
/// (FIX 11611): [`ConcernMoveOutcome`].
pub(crate) fn concern_move_outcome_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ConcernMoveOutcome>()
}

/// The OpenAPI schema of `POST /v1/owner/inbox/concern/apply`'s body
/// (FIX 11611): [`ConcernApplyRequest`].
pub(crate) fn concern_apply_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ConcernApplyRequest>()
}

/// The OpenAPI schema of `POST /v1/owner/inbox/concern/apply`'s answer
/// (FIX 11611): [`ConcernApplyOutcome`].
pub(crate) fn concern_apply_outcome_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ConcernApplyOutcome>()
}

/// The OpenAPI schema of `POST /v1/owner/inbox/concern/apply-prompt-inject`'s
/// body (FIX 11611): the approved prompt continuation.
pub(crate) fn concern_prompt_inject_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<
        oneiron::agent_dispatch::ConcernPromptInjectRequest,
    >()
}

/// The OpenAPI schema of `POST /v1/owner/inbox/concern/apply-prompt-inject`'s
/// answer (FIX 11611): the continuation the approval made.
pub(crate) fn concern_prompt_inject_outcome_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<
        oneiron::agent_dispatch::ConcernPromptInjectOutcome,
    >()
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

#[derive(Debug, Deserialize, schemars::JsonSchema)]
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
    payload: OwnerJsonBody<ConcernOutcome>,
) -> OwnerReply<ConcernCardSummary> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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
    payload: OwnerJsonBody<ConcernMoveRequest>,
) -> OwnerReply<ConcernMoveOutcome> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let locality = auth.locality();
    let host = Arc::clone(&server);
    let outcome = blocking(move || -> OwnerResult<ConcernMoveOutcome> {
        let vault = server.vault();
        if !matches!(request.r#move, ConcernMove::AskCoach) {
            return match vault.apply_concern_move(&owner, locality, &request) {
                // Only a card that is gone is not found, as on every other
                // concern route (FIX 8537); a target the move could not
                // reach keeps its own words.
                Err(error)
                    if error.code == oneiron::memory::MEMORY_CODE_NOT_FOUND
                        && vault.agent_health_card(&request.card)?.is_none() =>
                {
                    Err(OwnerError::NotFound("concern_card", request.card.clone()))
                }
                moved => moved.map_err(move_error),
            };
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
    payload: OwnerJsonBody<ConcernApplyRequest>,
) -> OwnerReply<ConcernApplyOutcome> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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
    payload: OwnerJsonBody<oneiron::agent_dispatch::ConcernPromptInjectRequest>,
) -> OwnerReply<oneiron::agent_dispatch::ConcernPromptInjectOutcome> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
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
