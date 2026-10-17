//! Live, model-backed wave planning on the server's durable workflow pump.
//! Instructions come from a stored agent definition. The model returns data;
//! the host owns the epic, plan identity, lease, validation and TASK writes.

use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher};
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptResultRef, ClaimAttempt, ClaimOutcome,
    FailAttempt, SetAttemptResult,
};
use oneiron::compaction::output::{OutputRef, restore_output, store_output};
use oneiron::retrieval_depth::RetrievalDeadline;
use oneiron::wave_orchestration::{
    PlannedTask, VaultWaveTaskPort, WAVE_PLAN_ATTEMPT_KIND, WAVE_PLAN_SCHEMA_VERSION,
    WaveApplyOutcome, WaveOrchestrator, WavePlan, WavePlanRequest, WavePlanner,
};
use oneiron::{
    ContentPart, EdgeActorClass, EntityId, Error, LlmMessage, LlmMessageRole, ResponseFormat,
    Vault, WaveResult, WriteActor,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::status::{StatusCell, WorkState};
use super::step::{ModelStep, StepRunner};
use crate::decision_host::{DecisionHost, WAVE_FANOUT_BUDGET};

const LEASE_OWNER: &str = "oneiron-server-waves";

/// Host-authored metadata around the caller's opaque planning constraints.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlanningContext {
    pub(crate) actor_ref: String,
    pub(crate) actor_class: u8,
    pub(crate) planner_ref: String,
    pub(crate) input: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanningJob {
    epic: String,
    objective: String,
    constraints: PlanningContext,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanOutput {
    tasks: Vec<TaskOutput>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskOutput {
    local_key: String,
    label: String,
    spec: Value,
    assignee_ref: Option<String>,
    blocked_by: Vec<String>,
}

fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.to_owned())
}

pub(crate) fn attempt_ref(id: AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn plan_ref(attempt: &AttemptRecord) -> String {
    format!("wave:{}", attempt_ref(attempt.id))
}

impl PlanOutput {
    fn into_plan(self, epic: EntityId, attempt: &AttemptRecord) -> oneiron::Result<WavePlan> {
        let tasks = self
            .tasks
            .into_iter()
            .map(|task| {
                Ok(PlannedTask {
                    local_key: task.local_key,
                    label: task.label,
                    spec: task.spec,
                    assignee_ref: task
                        .assignee_ref
                        .as_deref()
                        .map(EntityId::from_hex)
                        .transpose()?,
                    blocked_by: task.blocked_by,
                })
            })
            .collect::<oneiron::Result<Vec<_>>>()?;
        Ok(WavePlan {
            schema_version: WAVE_PLAN_SCHEMA_VERSION,
            plan_ref: plan_ref(attempt),
            epic_task_ref: epic,
            tasks,
        })
    }
}

fn output_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false, "required": ["tasks"],
        "properties": {"tasks": {
            "type": "array", "minItems": 1,
            "items": {"type": "object", "additionalProperties": false,
                "required": ["local_key", "label", "spec", "assignee_ref", "blocked_by"],
                "properties": {
                    "local_key": {"type": "string", "minLength": 1},
                    "label": {"type": "string", "minLength": 1},
                    "spec": {},
                    "assignee_ref": {"type": ["string", "null"]},
                    "blocked_by": {"type": "array", "items": {"type": "string"}}
                }
            }
        }}
    })
}

struct ModelWavePlanner<'a> {
    vault: &'a Vault,
    runtime: &'a tokio::runtime::Runtime,
    runner: &'a StepRunner,
    attempt: &'a AttemptRecord,
    context: &'a PlanningContext,
    actor: WriteActor,
}

impl WavePlanner for ModelWavePlanner<'_> {
    fn cut_plan(&self, request: WavePlanRequest) -> WaveResult<WavePlan> {
        let bytes = if let Some(reference) = &self.attempt.result_ref {
            // A crash after capture never pays for a second plan or changes its cut.
            restore_output(self.vault, OutputRef::from_handle(reference.as_str())?)?
        } else {
            let planner = EntityId::from_hex(&self.context.planner_ref)?;
            let definition = AgentDispatcher::new(self.vault)
                .dispatchable_definition(&AgentDispatchTarget::Custom(planner))?;
            let instructions = definition
                .instructions
                .as_ref()
                .filter(|text| !text.trim().is_empty())
                .unwrap_or(&definition.desc);
            let messages = vec![
                LlmMessage {
                    role: LlmMessageRole::System,
                    content: vec![ContentPart::Text {
                        text: instructions.clone(),
                    }],
                },
                LlmMessage {
                    role: LlmMessageRole::User,
                    content: vec![ContentPart::Text {
                        text: json!({
                            "epic_task_ref": request.epic_task_ref.to_hex(),
                            "planner_attempt_ref": attempt_ref(request.planner_attempt_ref),
                            "objective": request.objective,
                            "constraints": request.constraints,
                        })
                        .to_string(),
                    }],
                },
            ];
            let bytes = self
                .runner
                .generate(
                    self.runtime,
                    self.vault,
                    ModelStep {
                        definition: &definition,
                        attempt: self.attempt,
                        actor: self.actor,
                        purpose: WAVE_PLAN_ATTEMPT_KIND,
                        messages,
                        response_format: ResponseFormat::Json {
                            schema: output_schema(),
                        },
                    },
                )
                .map_err(|fault| fault.error)?;
            let output = store_output(self.vault, &bytes)?;
            AttemptQueue::new(self.vault).set_result(SetAttemptResult {
                id: self.attempt.id,
                lease_owner: LEASE_OWNER.to_owned(),
                attempt_count: self.attempt.attempt_count,
                result_ref: AttemptResultRef::new(output.handle())?,
                now: super::unix_now(),
            })?;
            bytes
        };
        let output: PlanOutput = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("wave planner returned invalid task data"))?;
        Ok(output.into_plan(request.epic_task_ref, self.attempt)?)
    }
}

/// Consume one queued PLAN task. The ordinary TASK router runs its children.
/// Under the vault's `auto` fan-out mode the cut's launch is ruled on through
/// `decisions`, the host's ladder, once the host installed it.
pub(super) fn run_once(
    runtime: &tokio::runtime::Runtime,
    vault: &Vault,
    runner: &StepRunner,
    status: &StatusCell,
    decisions: Option<&DecisionHost>,
) -> oneiron::Result<bool> {
    let queue = AttemptQueue::new(vault);
    let ClaimOutcome::Claimed(attempt) = queue.claim_kind(
        WAVE_PLAN_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: LEASE_OWNER.to_owned(),
            now: super::unix_now(),
        },
    )?
    else {
        return Ok(false);
    };
    status.update(|status| {
        status.workflows.state = WorkState::Working;
        status.workflows.started += 1;
    });
    let result = (|| -> WaveResult<_> {
        let job: PlanningJob = serde_json::from_slice(&attempt.payload)
            .map_err(|_| invalid("invalid served wave planning job"))?;
        let actor = EntityId::from_hex(&job.constraints.actor_ref)?;
        let class = EdgeActorClass::try_from_u8(job.constraints.actor_class)
            .ok_or_else(|| invalid("invalid wave planning actor class"))?;
        let epic = EntityId::from_hex(&job.epic)?;
        let planner = ModelWavePlanner {
            vault,
            runtime,
            runner,
            attempt: &attempt,
            context: &job.constraints,
            actor: WriteActor::new(actor, class),
        };
        let plan = planner.cut_plan(WavePlanRequest {
            epic_task_ref: epic,
            planner_attempt_ref: attempt.id,
            objective: job.objective,
            constraints: job.constraints.input.clone(),
            now: super::unix_now(),
        })?;
        // Under the vault's fan-out approval mode (FIX 939): `auto` asks the
        // host's ladder for the requesting actor, on a clock that starts
        // here. Before the host installs its ladder, an ask no standing row
        // answers holds the cut for the owner.
        let deadline = RetrievalDeadline::after(WAVE_FANOUT_BUDGET);
        let fanout = decisions.map(|host| host.wave_fanout_decisions(actor, &deadline));
        vault.apply_wave_plan_attempt_gated(
            actor,
            class,
            &attempt,
            plan,
            fanout.as_ref(),
            super::unix_now(),
        )
    })();
    runner.forget(attempt.id);
    status.update(|status| {
        status.workflows.state = WorkState::Waiting;
        match &result {
            Ok(WaveApplyOutcome::Applied(_)) => status.workflows.completed += 1,
            // A held cut parked its attempt in the same transaction: neither
            // done nor failed, and never replanned. The owner's approval
            // launches that exact cut and completes the attempt.
            Ok(WaveApplyOutcome::Paused(_)) => {}
            Err(_) => {
                status.workflows.failed += 1;
                status.workflows.last_error = Some("wave_plan_failed".to_owned());
            }
        }
    });
    if matches!(result, Ok(WaveApplyOutcome::Paused(_))) {
        tracing::info!(attempt = ?attempt.id, "wave cut held for fan-out approval");
    }
    if result.is_err() {
        // Keep provider output by reference and expose a stable failure reason.
        // The run-tree retry door can requeue a failed plan explicitly.
        queue.fail(FailAttempt {
            id: attempt.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: attempt.attempt_count,
            reason: "wave_plan_failed".to_owned(),
            now: super::unix_now(),
        })?;
        tracing::warn!(attempt = ?attempt.id, reason = "wave_plan_failed", "wave plan did not land");
    }
    Ok(true)
}

pub(crate) fn status(vault: &Vault, attempt: &AttemptRecord) -> oneiron::Result<Value> {
    let job: PlanningJob = serde_json::from_slice(&attempt.payload)
        .map_err(|_| invalid("invalid served wave planning job"))?;
    let mut body = json!({
        "attempt_ref": attempt_ref(attempt.id),
        "epic_task_ref": job.epic, "state": attempt.state.as_str(),
        "result_ref": attempt.result_ref.as_ref().map(|reference| reference.as_str()),
        "last_error": attempt.last_error,
    });
    if attempt.state == oneiron::attempt_queue::AttemptState::Completed {
        let reference = attempt
            .result_ref
            .as_ref()
            .ok_or_else(|| invalid("completed wave plan has no output"))?;
        let bytes = restore_output(vault, OutputRef::from_handle(reference.as_str())?)?;
        let output: PlanOutput =
            serde_json::from_slice(&bytes).map_err(|_| invalid("invalid saved wave output"))?;
        let plan = output.into_plan(EntityId::from_hex(&job.epic)?, attempt)?;
        let plan = WaveOrchestrator::<VaultWaveTaskPort<'_>>::validate(plan)
            .map_err(|_| invalid("invalid saved wave plan"))?;
        let tasks = vault
            .wave_plan_task_refs(&plan)?
            .ok_or_else(|| invalid("completed wave plan has no TASK rows"))?;
        body["plan_ref"] = json!(plan.plan_ref());
        body["task_refs"] = json!(
            tasks
                .into_iter()
                .map(|(key, id)| (key, id.to_hex()))
                .collect::<std::collections::BTreeMap<_, _>>()
        );
    }
    Ok(body)
}
