//! Typed batched child admission and input-order observations over the wave
//! launch gate. The existing wave port mints and routes every child under the
//! host-bound creator; this door owns no scheduler or spend accounting.
use serde::{Deserialize, Serialize};

use super::create_origin::task_create_origin_in_txn;
use super::fanout_launch::{LaunchPayload, WaveLaunchGate, wave_launch_ref};
use super::sdk::{FanoutLaunchRequest, FanoutLaunchView};
use super::{TaskTerminalDisposition, VaultWaveTaskPort};
use crate::agent_dispatch::{AgentDispatcher, SpendRead, SpendScope, SpendState};
use crate::attempt_queue::{AttemptQueue, AttemptState};
use crate::claim::ClaimReadStatus;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::wave_orchestration::{
    PlannedTask, WAVE_PLAN_SCHEMA_VERSION, WaveOrchestrator, WavePlan,
};

/// One child. No child maximum is copied from the parent: the route reserves
/// its calibrated hold from the one existing parent spend tree.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FanoutChildInput {
    pub agent_ref: EntityId,
    pub label: String,
    pub prompt: String,
}

/// The caller supplies work and a retry key, never an actor, attempt or lease.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FanoutBatchInput {
    pub intent_key: String,
    pub children: Vec<FanoutChildInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FanoutSlotState {
    Held,
    Pending,
    Completed,
    Error,
}

/// The TASK's real terminal result, not an ask answer or an inferred success.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanoutSlotTerminal {
    pub disposition: TaskTerminalDisposition,
    pub result_ref: Option<EntityId>,
    pub finished_at: u64,
}

/// One recorded spend scope. A closed scope's unused balance is the hold the
/// existing settlement released, not a synthetic provider-cost receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanoutLeaseView {
    pub lease: SpendScope,
    pub spend: SpendRead,
    pub released_units: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanoutSlotAttempt {
    pub attempt_ref: String,
    pub state: AttemptState,
    pub last_error: Option<String>,
    pub result_ref: Option<String>,
    pub budget_hold: bool,
    pub lease: Option<FanoutLeaseView>,
}

/// A slot never moves when siblings finish or fail. Attempts retain their
/// own errors and budget holds; a read never cancels or settles any child.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanoutChildSlot {
    pub index: usize,
    pub input: FanoutChildInput,
    pub task_ref: Option<EntityId>,
    pub state: FanoutSlotState,
    pub terminal: Option<FanoutSlotTerminal>,
    pub attempts: Vec<FanoutSlotAttempt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanoutSharedAccounting {
    /// Includes spend and reservations from all work on this parent, not
    /// only this batch. It is never a sum of copied per-child limits.
    pub parent: Option<FanoutLeaseView>,
    pub hard_cap: Option<FanoutLeaseView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanoutBatchView {
    pub launch: FanoutLaunchView,
    pub parent_task_ref: EntityId,
    pub slots: Vec<FanoutChildSlot>,
    pub accounting: FanoutSharedAccounting,
}

fn wave_error(error: crate::linear_sync::LinearSyncError) -> MemoryError {
    match error {
        crate::linear_sync::LinearSyncError::Store(error) => error.into(),
        error => MemoryError::bad_request(error.to_string()),
    }
}

impl Memory<'_> {
    /// Admit the typed work through the existing wave gate. The sealed live
    /// binding supplies the parent TASK and creator; no unbound root path.
    pub fn spawn_fanout_batch(
        &self,
        input: FanoutBatchInput,
        decisions: Option<&crate::fanout_auto::FanoutDecisions<'_>>,
    ) -> MemoryResult<FanoutBatchView> {
        if input.intent_key.trim().is_empty() || input.intent_key.len() > 256 {
            return Err(MemoryError::bad_request("a batch intent_key is 1..=256 nonblank bytes"));
        }
        let binding = self.task_host().ok_or_else(|| {
            MemoryError::bad_request("a batch requires its caller's acquired live-run lease")
        })?;
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let (origin, epic) = {
            let txn = self.vault().store.env.read_txn().map_err(crate::Error::from)?;
            let origin = task_create_origin_in_txn(self, &txn, Some(binding))?
                .ok_or_else(|| MemoryError::bad_request("a batch requires its creator"))?;
            let parent = AttemptQueue::new(self.vault())
                .get_in_txn(&txn, binding.parent())?
                .ok_or_else(|| MemoryError::bad_request("the batch parent is missing"))?;
            let epic = parent.task_ref.as_deref()
                .ok_or_else(|| MemoryError::bad_request("the batch parent has no TASK"))?;
            let epic = EntityId::from_hex(epic)?;
            if !lane.is_entity_readable_in(&txn, &epic)? {
                return Err(MemoryError::not_found("the parent TASK is not readable"));
            }
            for child in &input.children {
                if child.prompt.trim().is_empty() || child.label.trim().is_empty() {
                    return Err(MemoryError::bad_request("each child states its label and prompt"));
                }
                if !lane.is_entity_readable_in(&txn, &child.agent_ref)? {
                    return Err(MemoryError::not_found("the child agent is not readable"));
                }
                if self.vault().get_entity_type_in_txn(&txn, &child.agent_ref)?
                    != Some(crate::registry::ENTITY_TYPE_AGENT_DEF)
                {
                    return Err(MemoryError::bad_request("each child names an AGENT_DEF"));
                }
            }
            (origin, epic)
        };
        // Fixed-width ordinal keys keep the wave's canonical order exactly
        // equal to input order, including widths above ten. No count cap.
        let plan = WavePlan {
            schema_version: WAVE_PLAN_SCHEMA_VERSION,
            plan_ref: format!("fanout.batch:{}:{}", bytes_to_hex_lower(binding.parent().as_bytes()), input.intent_key),
            epic_task_ref: epic,
            tasks: input.children.into_iter().enumerate().map(|(index, child)| PlannedTask {
                local_key: format!("{index:020}"),
                label: child.label,
                spec: serde_json::json!({"prompt": child.prompt}),
                assignee_ref: Some(child.agent_ref),
                blocked_by: Vec::new(),
            }).collect(),
        };
        let plan = WaveOrchestrator::<VaultWaveTaskPort<'_>>::validate(plan).map_err(wave_error)?;
        let launch_ref = wave_launch_ref(self.actor(), plan.plan_ref())?;
        let gate = WaveLaunchGate::decide(self.vault(), self.actor(), &plan, Some(&origin), decisions)?;
        let port = VaultWaveTaskPort::for_fanout(self.vault(), self.actor(), self.actor_class(), origin, gate);
        WaveOrchestrator::new(port).apply_gated(plan, crate::unix_seconds_now()).map_err(wave_error)?;
        self.fanout_batch_slots(FanoutLaunchRequest { launch_ref })?
            .ok_or_else(|| MemoryError::not_found("the admitted batch is not readable"))
    }

    /// The frozen launch, input-order child slots and shared lease facts in
    /// one read snapshot. Admission's own actor/owner gate remains decisive.
    pub fn fanout_batch_slots(
        &self,
        input: FanoutLaunchRequest,
    ) -> MemoryResult<Option<FanoutBatchView>> {
        let lane = self.read_lane(ClaimReadStatus::Recorded)?;
        let txn = self.vault().store.env.read_txn().map_err(crate::Error::from)?;
        let Some(launch) = self.readable_task_fanout_in(&txn, input.launch_ref)? else {
            return Ok(None);
        };
        let LaunchPayload::Wave { cut, creator_origin } = &launch.payload else {
            return Ok(None);
        };
        if !cut.plan_ref.starts_with("fanout.batch:") {
            return Ok(None);
        }
        if !lane.is_entity_readable_in(&txn, &cut.epic_task_ref)? {
            return Ok(None);
        }
        let dispatcher = AgentDispatcher::new(self.vault());
        let parent = creator_origin.as_ref().and_then(|origin| origin.parent_attempt())
            .map(|attempt| dispatcher.attempt_spend_scope_in_txn(&txn, attempt))
            .transpose()?.flatten()
            .map(|lease| lease_view(&dispatcher, &txn, lease)).transpose()?;
        let hard_cap = parent.as_ref()
            .map(|parent| dispatcher.scope_with_root_in_txn(&txn, &parent.spend.cap_scope))
            .transpose()?.flatten()
            .map(|(lease, _)| lease_view(&dispatcher, &txn, lease)).transpose()?;
        let mut tasks = cut.tasks.iter().collect::<Vec<_>>();
        tasks.sort_by(|left, right| left.local_key.cmp(&right.local_key));
        let mut slots = Vec::with_capacity(tasks.len());
        for (index, child) in tasks.into_iter().enumerate() {
            let agent_ref = child.assignee_ref.ok_or_else(|| MemoryError::bad_request("batch child has no agent"))?;
            if !lane.is_entity_readable_in(&txn, &agent_ref)? {
                return Ok(None);
            }
            let task_ref = launch.task_refs.get(index).copied();
            let mut attempts = Vec::new();
            let mut terminal = None;
            if let Some(task) = task_ref {
                if !lane.is_entity_readable_in(&txn, &task)? {
                    return Ok(None);
                }
                let body = super::wire_decode::task_verb_body_in(self.vault(), &txn, task)?
                    .ok_or_else(|| MemoryError::not_found("batch child TASK is missing"))?;
                terminal = body.terminal().map(|record| FanoutSlotTerminal {
                    disposition: record.disposition,
                    result_ref: record.result_ref,
                    finished_at: record.finished_at,
                });
                for attempt in AttemptQueue::new(self.vault()).list_task_in_txn(&txn, &task.to_hex())? {
                    let lease = dispatcher.attempt_spend_scope_in_txn(&txn, attempt.id)?
                        .map(|lease| lease_view(&dispatcher, &txn, lease)).transpose()?;
                    attempts.push(FanoutSlotAttempt {
                        attempt_ref: bytes_to_hex_lower(attempt.id.as_bytes()),
                        state: attempt.state,
                        last_error: attempt.last_error.clone(),
                        result_ref: attempt.result_ref.as_ref().map(|reference| reference.as_str().to_owned()),
                        budget_hold: attempt.budget_hold(),
                        lease,
                    });
                }
            }
            let state = match terminal.as_ref().map(|record| record.disposition) {
                Some(TaskTerminalDisposition::Completed) => FanoutSlotState::Completed,
                Some(_) => FanoutSlotState::Error,
                None if task_ref.is_none() => FanoutSlotState::Held,
                None if attempts.last().is_some_and(|attempt| matches!(attempt.state,
                    AttemptState::Failed | AttemptState::Cancelled | AttemptState::Abandoned)) => FanoutSlotState::Error,
                None => FanoutSlotState::Pending,
            };
            slots.push(FanoutChildSlot {
                index,
                input: FanoutChildInput {
                    agent_ref,
                    label: child.label.clone(),
                    prompt: child.spec.get("prompt").and_then(serde_json::Value::as_str)
                        .ok_or_else(|| MemoryError::bad_request("batch child has no prompt"))?.to_owned(),
                },
                task_ref,
                state,
                terminal,
                attempts,
            });
        }
        let view = FanoutBatchView {
            launch: launch.receipt().into(),
            parent_task_ref: cut.epic_task_ref,
            slots,
            accounting: FanoutSharedAccounting { parent, hard_cap },
        };
        self.produced_from(fanout_batch_rows(&view));
        Ok(Some(view))
    }
}

fn lease_view(
    dispatcher: &AgentDispatcher<'_>,
    txn: &heed::RoTxn<'_>,
    lease: SpendScope,
) -> MemoryResult<FanoutLeaseView> {
    let spend = dispatcher.spend_read_at_in_txn(txn, &lease.scope)?;
    let released_units = (lease.state == SpendState::Closed && lease.parent.is_some()).then(|| lease.local_available());
    Ok(FanoutLeaseView { lease, spend, released_units })
}

/// The records the batch observation names, for each transport's release
/// check. Spend scopes and attempts are side-table facts, not record rows.
pub fn fanout_batch_rows(view: &FanoutBatchView) -> Vec<EntityId> {
    let mut rows = vec![view.parent_task_ref];
    for slot in &view.slots {
        rows.push(slot.input.agent_ref);
        rows.extend(slot.task_ref);
        rows.extend(slot.terminal.as_ref().and_then(|terminal| terminal.result_ref));
        rows.extend(slot.attempts.iter().filter_map(|attempt| {
            attempt.result_ref.as_deref().and_then(|reference| EntityId::from_hex(reference).ok())
        }));
    }
    rows.sort_unstable();
    rows.dedup();
    rows
}
