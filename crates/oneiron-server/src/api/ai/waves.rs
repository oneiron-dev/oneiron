//! Owner-authenticated admission and durable status for live wave planning.
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, EnqueueOutcome};
use oneiron::wave_orchestration::WAVE_PLAN_ATTEMPT_KIND;
use oneiron::{EdgeActorClass, EntityId};
use serde::Deserialize;
use serde_json::{Value, json};

use super::refusal;
use crate::ai_host::waves::PlanningContext;
use crate::auth::{CoreAuth, CoreScope};
use crate::server::SyncServer;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WaveRequest {
    epic_task_ref: String,
    planner_ref: String,
    objective: String,
    constraints: Value,
}

/// The epic a wave planning attempt plans: the `epic` its payload names.
fn wave_epic(attempt: &oneiron::attempt_queue::AttemptRecord) -> Option<EntityId> {
    let payload: Value = serde_json::from_slice(&attempt.payload).ok()?;
    EntityId::from_hex(payload.get("epic")?.as_str()?).ok()
}

pub(super) async fn enqueue(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Json(request): Json<WaveRequest>,
) -> Response {
    if let Err(error) = auth
        .require(CoreScope::Read)
        .and_then(|()| auth.require(CoreScope::Write))
    {
        return error.into_response();
    }
    // Restriction wave 11: the owner takes today's path; an agent the
    // owner lets plan enqueues as itself below; anyone else is refused
    // as before.
    let agent = if auth.is_owner_grade() {
        None
    } else {
        super::agent_caller(&auth)
    };
    if !auth.is_owner_grade() && agent.is_none() {
        return refusal(
            StatusCode::FORBIDDEN,
            "owner_required",
            "wave planning requires the owner",
        );
    }
    // The key first, so a closed key answers exactly today's refusal.
    if let Some(agent) = agent {
        match server.vault().agent_may_plan_waves(agent) {
            Ok(true) => {}
            Ok(false) => {
                return refusal(
                    StatusCode::FORBIDDEN,
                    "owner_required",
                    "wave planning requires the owner",
                );
            }
            Err(_) => {
                return refusal(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "wave_not_queued",
                    "wave planning could not be queued",
                );
            }
        }
    }
    // FIX 2222: an owner act; a hosted operator's root is refused, typed.
    if let Err(error) = crate::api::host_action::require_host_owner_act(&server, &auth) {
        return error.into_response();
    }
    if server.ai.status().workflows.state == crate::ai_host::WorkState::Idle {
        return refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "planner_unavailable",
            "the model workflow worker is not running",
        );
    }
    let (Ok(epic), Ok(planner)) = (
        EntityId::from_hex(&request.epic_task_ref),
        EntityId::from_hex(&request.planner_ref),
    ) else {
        return refusal(
            StatusCode::BAD_REQUEST,
            "invalid_ref",
            "epic_task_ref and planner_ref must be entity ids",
        );
    };
    if request.objective.trim().is_empty() {
        return refusal(
            StatusCode::BAD_REQUEST,
            "empty_objective",
            "a wave requires an objective",
        );
    }
    for id in [epic, planner] {
        if !auth.can_read_entity(server.vault(), &id).unwrap_or(false) {
            return refusal(
                StatusCode::FORBIDDEN,
                "not_readable",
                "the epic and planner must be readable by this credential",
            );
        }
    }
    if server.vault().get_entity_type(&epic).ok().flatten()
        != Some(oneiron::registry::ENTITY_TYPE_TASK)
        || AgentDispatcher::new(server.vault())
            .dispatchable_definition(&AgentDispatchTarget::Custom(planner))
            .is_err()
    {
        return refusal(
            StatusCode::BAD_REQUEST,
            "invalid_wave",
            "the epic must be a TASK and the planner must be dispatchable",
        );
    }
    // The owner a self-hosted root or the dev mode acts as (FIX 2222); the
    // owner-act admission above already refused a hosted operator's root.
    let actor = match auth.principal_ref() {
        Some(reference) => {
            EntityId::from_hex(reference).map_err(oneiron::memory::MemoryError::from)
        }
        None => match crate::api::host_action::host_action_of(server.vault(), &auth) {
            Some(action) => action
                .map(|action| action.actor().entity_ref())
                .map_err(oneiron::memory::MemoryError::from),
            None => Err(oneiron::Error::EntityNotFound.into()),
        },
    };
    let Ok(actor) = actor else {
        return refusal(
            StatusCode::FORBIDDEN,
            "principal_required",
            "a wave requires a bound principal",
        );
    };
    let class = match auth.actor_class() {
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        _ => EdgeActorClass::Human,
    };
    let context = PlanningContext {
        actor_ref: actor.to_hex(),
        actor_class: class as u8,
        planner_ref: planner.to_hex(),
        input: request.constraints,
    };
    let Ok(constraints) = serde_json::to_value(context) else {
        return refusal(
            StatusCode::BAD_REQUEST,
            "invalid_constraints",
            "wave constraints could not be encoded",
        );
    };
    if !auth.credential_is_live(server.vault()) {
        return refusal(
            StatusCode::UNAUTHORIZED,
            "credential_revoked",
            "the admission credential is no longer live",
        );
    }
    // The agent enqueues as itself; its key is read again inside
    // the write, and a key that closed since the read above refuses.
    let outcome = match agent {
        Some(agent) => {
            match server.vault().enqueue_wave_plan_as_agent(
                agent,
                epic,
                &request.objective,
                constraints,
                super::super::unix_seconds_now(),
            ) {
                Err(oneiron::Error::Refused(message))
                    if message.contains("ai.waves.agent_may_plan") =>
                {
                    return refusal(
                        StatusCode::FORBIDDEN,
                        "owner_required",
                        "wave planning requires the owner",
                    );
                }
                outcome => outcome,
            }
        }
        None => server.vault().enqueue_wave_plan(
            epic,
            &request.objective,
            constraints,
            super::super::unix_seconds_now(),
        ),
    };
    match outcome {
        Ok(EnqueueOutcome::Enqueued(attempt) | EnqueueOutcome::Existing(attempt)) => (
            StatusCode::ACCEPTED,
            Json(json!({
                "attempt_ref": crate::ai_host::waves::attempt_ref(attempt.id),
                "state": attempt.state.as_str(),
            })),
        )
            .into_response(),
        Ok(_) | Err(_) => refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "wave_not_queued",
            "wave planning could not be queued",
        ),
    }
}

pub(super) async fn status(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    Path(reference): Path<String>,
) -> Response {
    if let Err(error) = auth.require(CoreScope::Read) {
        return error.into_response();
    }
    // Restriction wave 11: the owner takes today's path; an agent the
    // owner lets plan reads a wave whose epic it can read; anyone else
    // is refused as before.
    let agent = if auth.is_owner_grade() {
        None
    } else {
        super::agent_caller(&auth)
    };
    if !auth.is_owner_grade() && agent.is_none() {
        return refusal(
            StatusCode::FORBIDDEN,
            "owner_required",
            "wave status requires the owner",
        );
    }
    // The key first, so a closed key answers exactly today's refusal.
    if let Some(agent) = agent {
        match server.vault().agent_may_plan_waves(agent) {
            Ok(true) => {}
            Ok(false) => {
                return refusal(
                    StatusCode::FORBIDDEN,
                    "owner_required",
                    "wave status requires the owner",
                );
            }
            Err(_) => {
                return refusal(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "wave_unreadable",
                    "wave status could not be read",
                );
            }
        }
    }
    // FIX 2222: an owner act; a hosted operator's root is refused, typed.
    if let Err(error) = crate::api::host_action::require_host_owner_act(&server, &auth) {
        return error.into_response();
    }
    // A managed vault's attested owner reads while he is its live owner.
    if let Err(error) = crate::api::scoped_auth::require_live_managed_owner(&server, &auth) {
        return error.into_response();
    }
    let id = EntityId::from_hex(&reference).and_then(|id| AttemptId::from_bytes(id.as_bytes()));
    let Ok(id) = id else {
        return refusal(
            StatusCode::BAD_REQUEST,
            "invalid_ref",
            "attempt_ref must be an entity id",
        );
    };
    match AttemptQueue::new(server.vault()).get(id) {
        Ok(Some(attempt)) if attempt.kind == WAVE_PLAN_ATTEMPT_KIND => {
            // The agent reads a wave whose epic it can read.
            if let Some(agent) = agent {
                let readable = wave_epic(&attempt)
                    .and_then(|epic| auth.can_read_entity(server.vault(), &epic).ok())
                    .unwrap_or(false);
                if !readable {
                    return refusal(
                        StatusCode::FORBIDDEN,
                        "owner_required",
                        "wave status requires the owner",
                    );
                }
            }
            match crate::ai_host::waves::status(server.vault(), &attempt) {
                Ok(status) => Json(status).into_response(),
                Err(_) => refusal(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "wave_unreadable",
                    "wave status could not be read",
                ),
            }
        }
        Ok(_) => refusal(
            StatusCode::NOT_FOUND,
            "wave_not_found",
            "no wave plan has this attempt ref",
        ),
        Err(_) => refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "wave_unreadable",
            "wave status could not be read",
        ),
    }
}
