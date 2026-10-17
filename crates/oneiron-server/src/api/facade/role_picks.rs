//! OF-495: role holders' tradeoff picks (ROLES-EVERYWHERE). A person or an
//! agent, owner or not, holding a responsible role a skill tradeoff ask has
//! climbed to lists the asks it may answer and picks, as the owner does at
//! `/v1/owner/skills/judge`. The role check is the authorization; the pick is learned as that role's preference
//! like a person's and, for a project-bound goal, proposed for the project's
//! goal record, which only its interview revises.
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{get, post};
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_INTERNAL};
use oneiron::skill_optimize::{
    SkillTradeoffAsk, TradeoffChoice, settle_skill_tradeoff_ask_as, skill_tradeoff_asks_for,
};
use oneiron::{EdgeActorClass, EntityId, WriteActor};
use serde::{Deserialize, Serialize};

use super::{FacadeApiError, facade_actor, facade_input, facade_json};
use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;

pub(crate) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/v1/core/skills/tradeoff-asks", get(asks))
        .route("/v1/core/skills/tradeoff-asks/pick", post(pick))
}

/// The same pick the owner's door takes.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pick {
    /// The open optimizer proposal the ask is about, as 32 hex.
    proposal: String,
    /// The digest of the exact question the pick answers.
    question_digest: String,
    choice: TradeoffChoice,
}

#[derive(Serialize)]
struct Settled {
    proposal: String,
    accepted: bool,
    goal_revision: String,
}

/// `GET /v1/core/skills/tradeoff-asks`: the asks that have climbed to a role
/// the credential's principal holds.
async fn asks(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<Vec<SkillTradeoffAsk>>, FacadeApiError> {
    auth.require(CoreScope::Read)?;
    let (actor, _) = facade_actor(&auth)?;
    let vault = Arc::clone(&server.vault);
    let asks = tokio::task::spawn_blocking(move || skill_tradeoff_asks_for(&vault, &actor))
        .await
        .map_err(|_| internal())?
        .map_err(engine)?;
    Ok(Json(asks))
}

/// `POST /v1/core/skills/tradeoff-asks/pick`: a person or agent role
/// holder's A/B pick, as the credential's principal: a board member who is
/// not a vault owner picks here.
async fn pick(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: Result<Json<serde_json::Value>, JsonRejection>,
) -> Result<Json<Settled>, FacadeApiError> {
    auth.require(CoreScope::Write)?;
    auth.require_unrestricted_record_scope()?;
    let (actor, class) = facade_actor(&auth)?;
    if !matches!(class, EdgeActorClass::Human | EdgeActorClass::Agent) {
        return Err(FacadeApiError::forbidden(
            "this door takes a person's or an agent's pick",
            ["Pick as the person or agent that holds the ask's role."],
        ));
    }
    let request: Pick = facade_input(facade_json(payload)?)?;
    let proposal = EntityId::from_hex(&request.proposal).map_err(|_| {
        FacadeApiError::new(
            StatusCode::BAD_REQUEST,
            MEMORY_CODE_BAD_REQUEST,
            "proposal is not a 32-hex entity id",
            ["Name the proposal the ask is about."],
        )
    })?;
    let vault = Arc::clone(&server.vault);
    let verdict = tokio::task::spawn_blocking(move || {
        settle_skill_tradeoff_ask_as(
            &vault,
            &WriteActor::new(actor, class),
            &proposal,
            &request.question_digest,
            request.choice,
            unix_seconds(),
        )
    })
    .await
    .map_err(|_| internal())?
    .map_err(engine)?;
    Ok(Json(Settled {
        proposal: proposal.to_hex(),
        accepted: verdict.accepted,
        goal_revision: verdict.goal_revision,
    }))
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn engine(error: oneiron::Error) -> FacadeApiError {
    crate::api::error_map::core_engine_error("skill tradeoff pick", error).into()
}

fn internal() -> FacadeApiError {
    FacadeApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        MEMORY_CODE_INTERNAL,
        "the pick did not finish",
        ["Read the ask again before picking."],
    )
}
