//! A continued run's config, seat and carried exposure (FIX 3694): the
//! leased successor that carries the owner's approved prompt continuation
//! runs on its fork of the failed predecessor's run.

use super::super::{
    AgentModel, AttemptRecord, EngineExecutorConfig, EngineRunError, EntityId, McpCodeModeProvider,
    ModelSeat, SeatKind, SeatTask, TaskExposure, TaskTypeRef, Vault, fork_executor_run,
    run_continuation, task_run_seat, text,
};
use oneiron::llm::seat::SeatLearningContext;

/// The exposure a source run's [`TaskExposure::append`] left at the end of
/// a continued run's forked task (FIX 3694): the separator and `body`.
/// `None` when the task does not end with them, as when the skill changed
/// since the source ran.
pub(super) fn appended_exposure(
    task: &str,
    separator: &str,
    body: &str,
    skill: EntityId,
    revision: String,
) -> Option<TaskExposure> {
    let start = task.len().checked_sub(separator.len() + body.len())?;
    let tail = task.get(start..)?;
    (tail.strip_prefix(separator)? == body).then(|| TaskExposure {
        skill,
        revision,
        content_hash: *blake3::hash(tail.as_bytes()).as_bytes(),
        start,
        end: task.len(),
    })
}

/// The config a leased successor runs under when it carries the owner's
/// approved prompt continuation (FIX 3694): its fork of the failed
/// predecessor's run, seeded from the cut, or re-opened on a later entry.
/// `None` for any other run. A fork that refuses fails the run under the
/// refusal's code.
pub(super) fn continued_config(
    vault: &Vault,
    attempt: &AttemptRecord,
    template: &EngineExecutorConfig,
) -> Result<Option<EngineExecutorConfig>, EngineRunError> {
    if run_continuation(vault, attempt.id).map_err(text)?.is_none() {
        return Ok(None);
    }
    fork_executor_run(vault, attempt, template)
        .map(|prepared| Some(prepared.config))
        .map_err(|refusal| EngineRunError::Binding(refusal.to_string()))
}

/// The seat a continued run is born on (FIX 3694): one of its own, under its
/// own run's receipt, bound to the model, locality and effort its source ran
/// on, so the fork's config marker holds on every entry. That model must
/// still be on the agent's list (`listed`, FIX 4472). It is stamped with
/// the successor's own dispatch stamp (`type_ref`, DOOR-111 S5), and picked
/// in the dispatched `agent`'s voice (FIX 4543).
#[allow(clippy::too_many_arguments)]
pub(super) fn continued_seat(
    vault: &Vault,
    provider: &dyn McpCodeModeProvider,
    agent: EntityId,
    config: &EngineExecutorConfig,
    type_ref: &TaskTypeRef,
    listed: Vec<AgentModel>,
    worlds: Vec<EntityId>,
    learning: Option<SeatLearningContext>,
) -> Result<Option<ModelSeat>, String> {
    // The birth's worlds are the dispatch row's branch world, threaded by the
    // caller (FIX 11918, Engine 00:54); empty inherits. No federation slip here.
    task_run_seat(
        vault,
        provider,
        agent,
        config.run_id,
        type_ref,
        worlds,
        learning,
        |facet| SeatTask {
            kind: SeatKind::Attempt,
            warm_scope: format!("agent-run:{}", config.run_id.to_hex()),
            task: config.task.clone(),
            purpose: oneiron::CallPurpose::Other {
                name: oneiron::engine_executor::ENGINE_EXECUTOR_PURPOSE_NAME.into(),
            },
            facet: facet.to_owned(),
            required: Vec::new(),
            min_context_tokens: 1,
            locality: config.model_locality,
            override_model: Some(config.model.clone()),
            override_effort: config.seat_effort,
            listed,
            worlds: Vec::new(),
            served: None,
            learning: None,
        },
    )
}
