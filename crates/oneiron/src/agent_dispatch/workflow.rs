//! Atomic saved-workflow admission. Later steps are data, not queued work.

use super::widen::PreparedParentContext;
use super::widen_record::{invalid, json};
use super::workflow_record::{
    DEDUPE, RECORD, WORKFLOW_ATTEMPT_TYPE, WorkflowIntent, WorkflowRecord, dedupe_key_hash,
};
use super::{
    AgentDispatchInput, AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher,
    AgentSpawnContext, DispatchAgent,
};
use crate::attempt_queue::{AttemptInterventionKind, AttemptQueue, InterveneAttempt};
use crate::context_projection::normalize_context_spec;
use crate::dreamer_runner::{EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome};
use crate::error::Result;

impl AgentDispatcher<'_> {
    pub(super) fn dispatch_workflow(
        &self,
        input: DispatchAgent,
        spawn: AgentSpawnContext,
    ) -> Result<AgentDispatchOutcome> {
        let spawn = AgentSpawnContext {
            context_spec: spawn.context_spec.map(normalize_context_spec),
            ..spawn
        };
        // A wrapper is inert and cannot stand in for an actual authority parent.
        if let Some(parent) = input.parent_attempt {
            self.parent_dispatch_input(parent)?
                .ok_or_else(|| invalid("workflow requires an actual agent parent"))?;
            self.child_depth_remaining(parent)?;
        }
        if let Some(outcome) = self.propose_context_widen(&input, &spawn)? {
            return Ok(outcome);
        }
        let mut txn = self.vault.store.env.write_txn()?;
        let outcome = self.dispatch_workflow_in_txn(&mut txn, input, spawn, None)?;
        txn.commit()?;
        Ok(outcome)
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
        let AgentDispatchTarget::Workflow(id) = input.target else {
            return Err(invalid("workflow dispatch requires a workflow target"));
        };
        let definition = self.workflow_definition_in_txn(txn, id)?;
        if let Some(parent) = input.parent_attempt {
            let parent_input = self
                .parent_dispatch_input_in_txn(txn, parent)?
                .ok_or_else(|| invalid("workflow requires an actual agent parent"))?;
            super::attenuation::child_depth_from(Some(parent_input))?;
        }
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
        };
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
            if record.intent != intent {
                return Err(invalid("workflow dedupe key names a different intent"));
            }
            return Ok(AgentDispatchOutcome::WorkflowExisting(Box::new(
                self.workflow_status_from(row, &record)?,
            )));
        }
        let mut steps = Vec::with_capacity(definition.steps.len());
        let mut first = None;
        for id in &definition.steps {
            let frozen = self.prepare_dispatch_in_txn(
                txn,
                DispatchAgent {
                    target: AgentDispatchTarget::Custom(*id),
                    ..input.clone()
                },
                spawn.clone(),
            )?;
            let mut bytes = Vec::new();
            rmpv::encode::write_value(&mut bytes, &super::encode_agent_dispatch_input(&frozen)?)
                .map_err(|_| invalid("workflow step does not encode"))?;
            steps.push(bytes);
            if first.is_none() {
                first = Some(frozen);
            }
        }
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
                None,
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
        let mut record = WorkflowRecord {
            version: 1,
            root: root.id,
            intent,
            steps,
            active: root.id,
            results: Vec::new(),
        };
        record.active = self.enqueue_prepared_workflow_step(
            txn,
            &record,
            first.ok_or_else(|| invalid("workflow has no first step"))?,
            input.now,
        )?;
        RECORD.put(&self.vault.store, txn, &root.id, &record)?;
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
        if let Some(parent) = record.intent.parent {
            let parent_input = self
                .parent_dispatch_input_in_txn(txn, parent)?
                .ok_or_else(|| invalid("workflow live parent is missing"))?;
            let bound = super::attenuation::child_depth_from(Some(parent_input))?;
            frozen.depth_remaining = Some(frozen.depth_remaining.unwrap_or(bound).min(bound));
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
        self.resolve_dispatch_context(
            record.intent.parent,
            frozen.context_spec.as_ref(),
            &frozen.context_from,
            record.intent.run_id.as_deref(),
            live.scope.to_world_scope(),
        )?;
        self.enqueue_prepared_workflow_step(txn, record, frozen, now)
    }

    /// Only initial admission and the checked release path above call this.
    /// Context has been resolved already; re-reading here would miss an atomic
    /// approval's uncommitted SliceOverride (and newly attenuated fork rows).
    fn enqueue_prepared_workflow_step(
        &self,
        txn: &mut heed::RwTxn<'_>,
        record: &WorkflowRecord,
        frozen: AgentDispatchInput,
        now: u64,
    ) -> Result<crate::attempt_queue::AttemptId> {
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
