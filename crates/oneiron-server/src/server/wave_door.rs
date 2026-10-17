//! The wave door (OF-427, ARCH-0068 RC5): `tasks.wave` cuts an epic TASK into
//! a wave of TASKs through a planner agent, queued as one planning attempt
//! the model workflow worker runs. Who asks is the host's: the planning
//! context it hands the planner names the asker and the planner the host
//! checked, never request text. A pumped run's wave is its own, bound to its
//! live lease (its host door); a credential's has no lease, so it is root and
//! the owner's, as `POST /v1/ai/waves` is.
use oneiron::attempt_queue::EnqueueOutcome;
use oneiron::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL, MEMORY_CODE_MODEL_UNAVAILABLE, MemoryError,
    MemoryResult,
};
use oneiron::task_verb::sdk::{TaskWaveReceipt, TaskWaveRequest};
use oneiron::{EntityId, WriteActor};
use serde_json::Value;

use super::SyncServer;
use crate::ai_host::waves::PlanningContext;

const VERB: &str = "tasks.wave";

/// Checks one wave request for `asker` and states the planning constraints
/// the planner reads: the epic must be a TASK and the planner a dispatchable
/// definition, both readable to the asker, and the model workflow worker
/// must be running to plan it.
pub(crate) fn wave_plan(
    server: &SyncServer,
    asker: WriteActor,
    readable: impl Fn(&EntityId) -> oneiron::Result<bool>,
    input: &TaskWaveRequest,
) -> MemoryResult<(EntityId, Value)> {
    if server.ai.status().workflows.state == crate::ai_host::WorkState::Idle {
        return Err(MemoryError::new(
            MEMORY_CODE_MODEL_UNAVAILABLE,
            format!("{VERB}: the model workflow worker is not running"),
            &["Start the host's model workflows, then ask again."],
        ));
    }
    let (Ok(epic), Ok(planner)) = (
        EntityId::from_hex(&input.epic_task_ref),
        EntityId::from_hex(&input.planner_ref),
    ) else {
        return Err(MemoryError::bad_request(
            "epic_task_ref and planner_ref are entity ids",
        ));
    };
    if input.objective.trim().is_empty() {
        return Err(MemoryError::bad_request("a wave states its objective"));
    }
    for id in [epic, planner] {
        if !readable(&id)? {
            return Err(MemoryError::new(
                MEMORY_CODE_FORBIDDEN,
                format!("{VERB}: the epic and the planner are read by the asker"),
                &["Name an epic and a planner you can read."],
            ));
        }
    }
    let vault = server.vault();
    if vault.get_entity_type(&epic)? != Some(oneiron::registry::ENTITY_TYPE_TASK)
        || oneiron::agent_dispatch::AgentDispatcher::new(vault)
            .dispatchable_definition(&oneiron::agent_dispatch::AgentDispatchTarget::Custom(
                planner,
            ))
            .is_err()
    {
        return Err(MemoryError::bad_request(
            "the epic is a TASK and the planner a dispatchable agent definition",
        ));
    }
    let context = PlanningContext {
        actor_ref: asker.entity_ref().to_hex(),
        actor_class: asker.actor_class() as u8,
        planner_ref: planner.to_hex(),
        input: input.constraints.clone(),
    };
    let constraints = serde_json::to_value(context).map_err(|_| {
        MemoryError::new(
            MEMORY_CODE_INTERNAL,
            format!("{VERB}: the planning context did not encode"),
            &["Report this wave-door failure."],
        )
    })?;
    Ok((epic, constraints))
}

/// The planning attempt one enqueue answered with.
pub(crate) fn wave_receipt(outcome: EnqueueOutcome) -> MemoryResult<TaskWaveReceipt> {
    let (EnqueueOutcome::Enqueued(attempt) | EnqueueOutcome::Existing(attempt)) = outcome else {
        return Err(MemoryError::new(
            MEMORY_CODE_INTERNAL,
            format!("{VERB}: the wave's planning was not queued"),
            &["Report this wave-door failure."],
        ));
    };
    Ok(TaskWaveReceipt {
        attempt_ref: crate::ai_host::waves::attempt_ref(attempt.id),
        state: attempt.state.as_str().to_owned(),
    })
}
