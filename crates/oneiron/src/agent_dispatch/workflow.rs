//! Atomic saved-workflow admission. Later steps are data, not queued work.

use super::widen::PreparedParentContext;
use super::widen_record::{invalid, json};
use super::workflow_record::{
    DEDUPE, RECORD, WORKFLOW_ATTEMPT_TYPE, WorkflowIntent, WorkflowRecord, WorkflowTaskBinding,
    dedupe_key_hash,
};
use super::{
    AgentDispatchInput, AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher,
    AgentSpawnContext, DispatchAgent,
};
use crate::attempt_queue::{AttemptInterventionKind, AttemptQueue, InterveneAttempt};
use crate::context_projection::normalize_context_spec;
use crate::dreamer_runner::{EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome};
use crate::error::Result;

mod member_context;
mod model_context;
mod workflow_task;

/// `input` and `spawn` as their admitted `intent` reads them (FIX 2314):
/// each field the intent carries from them takes the handles the wall
/// placed, so the leaves, frozen steps and wrapper are derived from what
/// the record stores, never from a secret it masked.
fn as_admitted(
    mut input: DispatchAgent,
    mut spawn: AgentSpawnContext,
    intent: &WorkflowIntent,
) -> (DispatchAgent, AgentSpawnContext) {
    input.run_id.clone_from(&intent.run_id);
    spawn.context_spec.clone_from(&intent.context_spec);
    spawn.type_ref.clone_from(&intent.type_ref);
    spawn.objectives.clone_from(&intent.objectives);
    (input, spawn)
}

impl AgentDispatcher<'_> {
    pub(super) fn dispatch_workflow(
        &self,
        input: DispatchAgent,
        spawn: AgentSpawnContext,
    ) -> Result<AgentDispatchOutcome> {
        // OF-541: a plan seats one AGENT_DEF; a saved workflow's leaves are
        // its own composition, so a planned spawn names an agent.
        if spawn.plan.is_some() {
            return Err(invalid("a spawn plan seats an agent, not a workflow"));
        }
        let spawn = AgentSpawnContext {
            context_spec: spawn.context_spec.map(normalize_context_spec),
            ..spawn
        };
        if let Some(key) = input.dedupe_key.as_deref() {
            let txn = self.vault.store.env.read_txn()?;
            let first = DEDUPE.get(&self.vault.store, &txn, &dedupe_key_hash(key))?;
            if let Some(id) = first {
                let row = AttemptQueue::new(self.vault)
                    .get_in_txn(&txn, id)?
                    .ok_or_else(|| invalid("workflow dedupe root is missing"))?;
                let record = self.read_workflow(&txn, &row)?;
                let (_, expected) = self.workflow_intent(&txn, &input, &spawn)?;
                drop(txn);
                // A first run whose record the wall masked answers the same
                // request, read as the wall stores it (FIX 2314).
                if record.intent != expected
                    && record.intent != self.admitted_workflow_intent(expected)?
                {
                    return Err(invalid("workflow dedupe key names a different intent"));
                }
                return Ok(AgentDispatchOutcome::WorkflowExisting(Box::new(
                    self.workflow_status_from(row, &record)?,
                )));
            }
        }
        // A wrapper is inert and cannot stand in for an actual authority parent.
        if let Some(parent) = input.parent_attempt {
            self.parent_dispatch_input(parent)?
                .ok_or_else(|| invalid("workflow requires an actual agent parent"))?;
            self.child_depth_remaining(parent)?;
        }
        let txn = self.vault.store.env.read_txn()?;
        self.project_depth_limit_in_txn(&txn, input.parent_attempt, spawn.project_ref)?;
        drop(txn);
        if let Some(outcome) = self.propose_context_widen(&input, &spawn)? {
            return Ok(outcome);
        }
        let mut txn = self.vault.store.env.write_txn()?;
        let outcome = self.dispatch_workflow_in_txn(&mut txn, input, spawn, None)?;
        txn.commit()?;
        self.vault.store.notify_attempt_observers();
        Ok(outcome)
    }

    fn workflow_intent(
        &self,
        txn: &heed::RoTxn<'_>,
        input: &DispatchAgent,
        spawn: &AgentSpawnContext,
    ) -> Result<(
        crate::agent_def::workflow::WorkflowDefinition,
        WorkflowIntent,
    )> {
        let AgentDispatchTarget::Workflow(id) = input.target else {
            return Err(invalid("workflow dispatch requires a workflow target"));
        };
        let definition = self.workflow_definition_in_txn(txn, id)?;
        let intent = WorkflowIntent {
            workflow_ref: id.to_hex(),
            definition: crate::agent_def::workflow::encode_workflow(&definition)?,
            parent: input.parent_attempt,
            run_id: input.run_id.clone(),
            context_spec: spawn.context_spec.clone(),
            context_from: spawn
                .context_from
                .iter()
                .map(crate::EntityId::to_hex)
                .collect(),
            depth_remaining: spawn.depth_remaining,
            project_ref: spawn.project_ref.map(|id| id.to_hex()),
            type_ref: spawn.type_ref.clone(),
            budget: spawn.budget,
            spend: spawn.spend.as_ref().map(|spend| spend.scope.clone()),
            room: spawn.room,
            objectives: spawn.objectives.clone(),
            comm: spawn.comm,
            task: None,
        };
        Ok((definition, intent))
    }

    /// The approval caller carries a private, already-validated parent projection.
    /// No persisted override is read before its transaction has committed. Both
    /// paths still check declared and resolved narrowing for EVERY real leaf.
    pub(super) fn dispatch_workflow_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: DispatchAgent,
        spawn: AgentSpawnContext,
        approved_parent: Option<&PreparedParentContext>,
    ) -> Result<AgentDispatchOutcome> {
        self.dispatch_workflow_bound_in_txn(txn, input, spawn, approved_parent, None)
    }

    /// [`Self::dispatch_workflow_in_txn`] for a run bound to the TASK it
    /// realizes (FIX 4391): the binding joins the intent, and the wrapper
    /// alone carries the backlink. `None` admits exactly as before.
    fn dispatch_workflow_bound_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: DispatchAgent,
        spawn: AgentSpawnContext,
        approved_parent: Option<&PreparedParentContext>,
        task: Option<&WorkflowTaskBinding>,
    ) -> Result<AgentDispatchOutcome> {
        let (definition, mut intent) = self.workflow_intent(txn, &input, &spawn)?;
        // FIX 9180: every leaf seats one agent, noted before any check below.
        for step in &definition.steps {
            self.observe_seat(*step);
        }
        intent.task = task.cloned();
        // FIX 2314: the request as the side-row wall stores it, before any
        // compare, frozen step, wrapper payload or status is derived from
        // it, so its record masks a secret rather than refusing it.
        let raw = intent.clone();
        let intent = self.admitted_workflow_intent_in(txn, intent)?;
        let (input, spawn) = as_admitted(input, spawn, &intent);
        if let Some(parent) = input.parent_attempt {
            let parent_input = self
                .parent_dispatch_input_in_txn(txn, parent)?
                .ok_or_else(|| invalid("workflow requires an actual agent parent"))?;
            super::attenuation::child_depth_from(Some(parent_input))?;
        }
        // Validate all leaves while the writer serializes revocation. Resolution
        // opens read snapshots, so finish it before any fork or queue mutation.
        for step in &definition.steps {
            let live =
                self.dispatchable_definition_in_txn(txn, &AgentDispatchTarget::Custom(*step))?;
            match approved_parent {
                Some(parent) => {
                    parent.resolve_child(self, &input, &spawn, live.scope.to_world_scope())?;
                }
                None => {
                    self.resolve_dispatch_context(
                        input.parent_attempt,
                        spawn.context_spec.as_ref(),
                        &spawn.context_from,
                        input.run_id.as_deref(),
                        live.scope.to_world_scope(),
                    )?;
                }
            }
        }
        if let Some(key) = input.dedupe_key.as_deref()
            && let Some(root) = DEDUPE.get(&self.vault.store, txn, &dedupe_key_hash(key))?
        {
            let row = AttemptQueue::new(self.vault)
                .get_in_write_txn(txn, root)?
                .ok_or_else(|| invalid("workflow dedupe root is missing"))?;
            let record = self.read_workflow(txn, &row)?;
            if record.intent != intent && record.intent != raw {
                return Err(invalid("workflow dedupe key names a different intent"));
            }
            return Ok(AgentDispatchOutcome::WorkflowExisting(Box::new(
                self.workflow_status_from(row, &record)?,
            )));
        }
        // OF-532: the whole workflow is one launch: one agent per leaf. Its
        // budget carves (or its expected spend holds) for the wrapper; each
        // leaf holds its own share under the wrapper's scope at its release.
        let launch = self.admit_launch_in_txn(
            txn,
            input.parent_attempt,
            spawn.spend.as_ref(),
            spawn.budget,
            &input.target,
            spawn.plan.as_ref().map(|plan| &plan.plan.model),
            input.now,
        )?;
        let leaf_spawn = AgentSpawnContext {
            budget: None,
            spend: None,
            ..spawn.clone()
        };
        let mut steps = Vec::with_capacity(definition.steps.len());
        let mut first = None;
        for id in &definition.steps {
            let frozen = self.prepare_dispatch_in_txn(
                txn,
                DispatchAgent {
                    target: AgentDispatchTarget::Custom(*id),
                    ..input.clone()
                },
                leaf_spawn.clone(),
            )?;
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, &super::encode_agent_dispatch_input(&frozen)?)
                .map_err(|_| invalid("workflow step does not encode"))?;
            steps.push(bytes);
            if first.is_none() {
                first = Some(frozen);
            }
        }
        // Every step is snapshotted; a long composition asks through the
        // workflow-steps row (Rule 5).
        self.vault.measure_workflow_steps(&definition);
        let EnqueueDreamerAttemptOutcome::Enqueued(root) =
            self.runner.enqueue_with_task_ref_in_txn(
                txn,
                EnqueueDreamerAttempt {
                    attempt_type: WORKFLOW_ATTEMPT_TYPE.to_owned(),
                    input: rmpv::Value::Binary(json(&intent)?),
                    parent_attempt: input.parent_attempt,
                    dedupe_key: None,
                    run_id: input.run_id.clone(),
                    now: input.now,
                },
                task.map(|binding| binding.task_ref.clone()),
            )?
        else {
            return Err(invalid("new workflow unexpectedly deduped"));
        };
        // No worker should execute an inert wrapper. The pump settles it only
        // after all real leaves have durable results.
        let root = AttemptQueue::new(self.vault)
            .intervene_in_txn(
                txn,
                InterveneAttempt {
                    id: root.attempt.id,
                    kind: AttemptInterventionKind::Pause,
                    actor: "runtime".to_owned(),
                    note: None,
                    now: input.now,
                },
            )?
            .record;
        // The wrapper is not an agent: its settlement calibrates nothing.
        launch.reserve_in_txn(self, txn, root.id, None, input.now)?;
        // FIX 6637: each frozen step as the side-row wall keeps it, before the
        // record is saved and before its first leaf is enqueued, so the first
        // leaf runs the input the record froze. A step the wall leaves keeps
        // its bytes, and its leaf the input prepared for it.
        let mut first = first.ok_or_else(|| invalid("workflow has no first step"))?;
        for (ordinal, step) in steps.iter_mut().enumerate() {
            if let Some((masked, frozen)) = self.admitted_workflow_step_in(txn, &root.id, step)? {
                *step = masked;
                if ordinal == 0 {
                    first = frozen;
                }
            }
        }
        let mut record = WorkflowRecord {
            version: 1,
            root: root.id,
            intent,
            steps,
            active: root.id,
            results: Vec::new(),
            launch: Some(launch.statement),
            task_settled: None,
        };
        record.active = self.enqueue_prepared_workflow_step(txn, &record, first, 0, input.now)?;
        RECORD.admit(self.vault, txn, &root.id, &mut record)?;
        RECORD.put(self.vault, txn, &root.id, &record)?;
        if let Some(key) = input.dedupe_key.as_deref() {
            DEDUPE.put(&self.vault.store, txn, &dedupe_key_hash(key), &root.id)?;
        }
        let status = self.workflow_status_from(root, &record)?;
        Ok(AgentDispatchOutcome::WorkflowDispatched(Box::new(status)))
    }

    pub(super) fn workflow_definition_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        id: crate::EntityId,
    ) -> Result<crate::agent_def::workflow::WorkflowDefinition> {
        match crate::vault::live_entity_row_in_txn(&self.vault.store, txn, &id)? {
            crate::vault::LiveEntityRow::Live { entity_type, body }
                if entity_type == crate::registry::ENTITY_TYPE_WORKFLOW =>
            {
                crate::agent_def::workflow::decode_workflow(&body)
            }
            _ => Err(invalid("saved workflow is missing or inactive")),
        }
    }

    pub(super) fn enqueue_workflow_step(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &WorkflowRecord,
        ordinal: usize,
        now: u64,
    ) -> Result<crate::attempt_queue::AttemptId> {
        let bytes = record
            .steps
            .get(ordinal)
            .ok_or_else(|| invalid("workflow step is missing"))?;
        let value = rmpv::decode::read_value(&mut std::io::Cursor::new(bytes))
            .map_err(|_| invalid("workflow step is malformed"))?;
        let mut frozen = super::decode_agent_dispatch_input(&value)?;
        let live = self.dispatchable_definition_in_txn(txn, &frozen.target)?;
        // Composition stays frozen, authority does not. Recheck a narrower or
        // revoked parent at every release, even after a host restart.
        frozen.definition.ceiling = live.ceiling;
        let (_, ceiling) =
            self.project_depth_limit_in_txn(txn, record.intent.parent, frozen.project_ref)?;
        // Only an explicit slice is stored (FIX 9560).
        frozen.depth_remaining = super::dispatch::stored_depth(frozen.depth_remaining, ceiling);
        if let Some(parent) = record.intent.parent {
            let (target, definition) = self.attenuate_child_target(
                txn,
                parent,
                frozen.target.agent_definition_ref()?,
                frozen.definition,
                record.intent.run_id.as_deref(),
                now,
            )?;
            frozen.target = target.target;
            frozen.definition = definition;
        }
        // FIX 1380: a released leaf re-resolves its reach against the real
        // parent, never the inert wrapper it is queued under.
        frozen.comm = self.resolve_comm_in_txn(
            txn,
            record.intent.comm,
            record.intent.parent,
            &frozen.target,
            &frozen.definition,
            frozen.project_ref,
        )?;
        self.resolve_dispatch_context(
            record.intent.parent,
            frozen.context_spec.as_ref(),
            &frozen.context_from,
            record.intent.run_id.as_deref(),
            live.scope.to_world_scope(),
        )?;
        self.enqueue_prepared_workflow_step(txn, record, frozen, ordinal, now)
    }

    /// Only initial admission and the checked release path above call this.
    /// Context has been resolved already; re-reading here would miss an atomic
    /// approval's uncommitted SliceOverride (and newly attenuated fork rows).
    fn enqueue_prepared_workflow_step(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &WorkflowRecord,
        mut frozen: AgentDispatchInput,
        ordinal: usize,
        now: u64,
    ) -> Result<crate::attempt_queue::AttemptId> {
        // OF-532: each leaf is a launch under the wrapper's scope, stated and
        // reserved at its release. Calibration keys on the requested leaf.
        let requested = *crate::agent_def::workflow::decode_workflow(&record.intent.definition)?
            .steps
            .get(ordinal)
            .ok_or_else(|| invalid("workflow step is missing"))?;
        let model = frozen.plan.as_ref().map(|plan| &plan.plan.model);
        let launch = self.admit_leaf_in_txn(txn, record.root, requested, ordinal, model, now)?;
        frozen.launch = Some(launch.statement.clone());
        // OF-531: a room-bound leaf re-proves its join at every release.
        frozen.join = self.require_room_join_in_txn(
            txn,
            frozen.room.as_ref(),
            requested,
            launch.statement.parent_scope.as_ref(),
        )?;
        let EnqueueDreamerAttemptOutcome::Enqueued(status) =
            self.runner.enqueue_with_task_ref_in_txn(
                txn,
                EnqueueDreamerAttempt {
                    attempt_type: super::AGENT_DISPATCH_ATTEMPT_TYPE.to_owned(),
                    input: super::encode_agent_dispatch_input(&frozen)?,
                    parent_attempt: Some(record.root),
                    dedupe_key: None,
                    run_id: record.intent.run_id.clone(),
                    now,
                },
                None,
            )?
        else {
            return Err(invalid("new workflow step unexpectedly deduped"));
        };
        launch.reserve_in_txn(self, txn, status.attempt.id, Some(requested), now)?;
        let index: Vec<_> = frozen
            .definition
            .skills
            .iter()
            .map(|skill| (&skill.skill_id, &skill.min_version))
            .collect();
        let bytes = serde_json::to_vec(&index)
            .map_err(|_| invalid("workflow skill index does not encode"))?;
        AttemptQueue::new(self.vault).append_manifest_entry_in_txn(
            txn,
            status.attempt.id,
            crate::attempt_queue::ManifestEntry::new(
                crate::attempt_queue::ManifestKind::SkillIndex,
                frozen.target.agent_definition_ref()?.to_hex(),
                blake3::hash(&bytes).to_hex().as_str(),
                now,
            ),
        )?;
        Ok(status.attempt.id)
    }
}
