//! A saved workflow that realizes a TASK (FIX 4391), on the dispatch side:
//! the bound admission, the wrapper facts the TASK's fence reads, and the
//! settlement an ended run owes its TASK.
//!
//! Only the wrapper carries the TASK backlink; its leaves stay TASK-less.
//! The binding is part of the stored intent, so the same intent key naming
//! another TASK, or none, is another intent. An owner's bound run is a root;
//! an agent's has the try its lease holds as its real parent (FIX 5316). A
//! TASK-less run never reaches any of this. The TASK's own gate, take, fence
//! and settlement are the task highway's
//! (`task_verb::highway_runner::workflow_try`).

use crate::agent_dispatch::widen_record::invalid;
use crate::agent_dispatch::workflow_record::{
    DEDUPE, RECORD, WORKFLOW_ATTEMPT_TYPE, WorkflowTaskBinding, dedupe_key_hash, is_wrapper,
};
use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::context_projection::normalize_context_spec;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::task_verb::highway_runner::workflow_try::{self, WorkflowRunEnd};
use crate::task_verb::{RunnerDoneAnswer, RunnerDoneQuestion};
use crate::write_envelope::WriteActor;

impl AgentDispatcher<'_> {
    /// Whether a queue row's type is an inert workflow wrapper's, for a read
    /// surface that folds one.
    pub(crate) fn is_workflow_attempt_type(attempt_type: &str) -> bool {
        attempt_type == WORKFLOW_ATTEMPT_TYPE
    }

    /// The checks a TASK-bound run takes before its writer: no spawn plan,
    /// its parent, its descriptor normalized once, and the project depth.
    /// An owner's run is a root. An agent's has `leased`, the try its lease
    /// holds, as its real parent, under the checks every workflow with a
    /// parent takes (FIX 5316).
    pub(crate) fn prepare_bound_workflow(
        &self,
        input: &DispatchAgent,
        spawn: AgentSpawnContext,
        leased: Option<AttemptId>,
    ) -> Result<AgentSpawnContext> {
        if !matches!(input.target, AgentDispatchTarget::Workflow(_)) {
            return Err(invalid("workflow dispatch requires a workflow target"));
        }
        if spawn.plan.is_some() {
            return Err(invalid("a spawn plan seats an agent, not a workflow"));
        }
        match (input.parent_attempt, leased) {
            (None, None) => {}
            // A wrapper is inert: the owner's run that realizes a TASK has
            // no parent.
            (Some(_), None) => {
                return Err(invalid("a workflow that realizes a TASK is a root run"));
            }
            (Some(parent), Some(leased)) if parent == leased => {
                self.parent_dispatch_input(parent)?
                    .ok_or_else(|| invalid("workflow requires an actual agent parent"))?;
                self.child_depth_remaining(parent)?;
            }
            (_, Some(_)) => {
                return Err(invalid(
                    "an agent's bound workflow has the try its lease holds as its parent",
                ));
            }
        }
        let spawn = AgentSpawnContext {
            context_spec: spawn.context_spec.map(normalize_context_spec),
            ..spawn
        };
        let txn = self.vault.store.env.read_txn()?;
        self.project_depth_limit_in_txn(&txn, input.parent_attempt, spawn.project_ref)?;
        Ok(spawn)
    }

    /// The run an identical bound request already started, read before its
    /// TASK is: the same workflow, intent key, request and binding. The same
    /// key with another TASK, no TASK or another request is refused with
    /// `refusal`, given the key and the run it names.
    pub(crate) fn bound_workflow_existing_in(
        &self,
        txn: &heed::RoTxn<'_>,
        input: &DispatchAgent,
        spawn: &AgentSpawnContext,
        task: EntityId,
        bound_by: WriteActor,
        refusal: impl Fn(&str, AttemptId) -> Error,
    ) -> Result<Option<AgentDispatchOutcome>> {
        let Some(key) = input.dedupe_key.as_deref() else {
            return Ok(None);
        };
        let Some(root) = DEDUPE.get(&self.vault.store, txn, &dedupe_key_hash(key))? else {
            return Ok(None);
        };
        let row = AttemptQueue::new(self.vault)
            .get_in_txn(txn, root)?
            .ok_or_else(|| invalid("workflow dedupe root is missing"))?;
        let record = self.read_workflow(txn, &row)?;
        let (_, mut expected) = self.workflow_intent(txn, input, spawn)?;
        expected.task = Some(WorkflowTaskBinding::new(task, bound_by));
        if record.intent != expected {
            return Err(refusal(key, root));
        }
        Ok(Some(AgentDispatchOutcome::WorkflowExisting(Box::new(
            self.workflow_status_from(row, &record)?,
        ))))
    }

    /// Admits a TASK-bound run in the caller's writer, after its TASK's
    /// gate: the ordinary saved-workflow admission with the binding in its
    /// intent and the backlink on its wrapper alone.
    pub(crate) fn dispatch_bound_workflow_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: DispatchAgent,
        spawn: AgentSpawnContext,
        task: EntityId,
        bound_by: WriteActor,
    ) -> Result<AgentDispatchOutcome> {
        let binding = WorkflowTaskBinding::new(task, bound_by);
        self.dispatch_workflow_bound_in_txn(txn, input, spawn, None, Some(&binding))
    }

    /// The TASK a registered wrapper realizes and the actor who bound it,
    /// under its class, in `txn`. `None` for any other row and for a
    /// TASK-less run.
    pub(crate) fn workflow_task_source_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        row: &AttemptRecord,
    ) -> Result<Option<(EntityId, WriteActor)>> {
        if !is_wrapper(row) || RECORD.get(&self.vault.store, txn, &row.id)?.is_none() {
            return Ok(None);
        }
        let record = self.read_workflow(txn, row)?;
        record
            .intent
            .task
            .as_ref()
            .map(WorkflowTaskBinding::ids)
            .transpose()
    }

    /// Ended runs that realize a TASK and have not settled it, in creation
    /// order: what a host's pass settles (FIX 4391). Every row is read,
    /// however many; one whose record fails to read is logged and passed
    /// over, and the next pass reads it again.
    ///
    /// # Errors
    ///
    /// The queue's and storage errors.
    pub fn unsettled_workflow_tasks(&self) -> Result<Vec<AttemptId>> {
        let rows = AttemptQueue::new(self.vault).list()?;
        let txn = self.vault.store.env.read_txn()?;
        let mut roots = Vec::new();
        for row in rows {
            if row.task_ref.is_none() || !row.state.is_terminal() || !is_wrapper(&row) {
                continue;
            }
            match RECORD.get(&self.vault.store, &txn, &row.id) {
                Ok(Some(record))
                    if record.intent.task.is_some() && record.task_settled.is_none() =>
                {
                    roots.push(row.id);
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(kind = ?error.kind(), root = ?row.id, "an ended workflow's record did not read");
                }
            }
        }
        Ok(roots)
    }

    /// The "Done means met?" an ended run's TASK settlement asks, for a host
    /// that judges it outside any writer (FIX 4391). The run's report NOTE
    /// lands first, so the judge reads the result it judges. `None` when no
    /// question is owed: the run did not complete, its TASK is no longer its
    /// to settle, or the TASK has no brief.
    ///
    /// # Errors
    ///
    /// A wrapper whose record does not match it; the report NOTE's write
    /// refusals; storage errors.
    pub fn workflow_done_question(&self, root: AttemptId) -> Result<Option<RunnerDoneQuestion>> {
        match self.workflow_end(root)? {
            Some(end) => workflow_try::done_question(self.vault, &end),
            None => Ok(None),
        }
    }

    /// Settles the TASK an ended run realizes, in a writer of its own
    /// (FIX 4391): Completed through the TASK's done-means, with `judged` as
    /// the answer a host gave outside the writer; Failed, Cancelled or
    /// Abandoned as the run ended. `false` when nothing moved: the run is
    /// live, TASK-less or settled, or its TASK moved on.
    ///
    /// # Errors
    ///
    /// The fence's and the TASK writer's refusals; storage errors. Nothing
    /// is marked then, so a later pass tries again.
    pub fn settle_workflow_task(
        &self,
        root: AttemptId,
        judged: Option<RunnerDoneAnswer>,
        now: u64,
    ) -> Result<bool> {
        match self.workflow_end(root)? {
            Some(end) => workflow_try::settle(self.vault, &end, judged, now),
            None => Ok(false),
        }
    }

    /// Marks an ended run's TASK settlement run, in the settling writer, so
    /// no later pass runs it again.
    pub(crate) fn mark_workflow_task_settled_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        root: AttemptId,
        ended: &str,
    ) -> Result<()> {
        let mut record = RECORD
            .get(&self.vault.store, txn, &root)?
            .ok_or_else(|| invalid("workflow wrapper has no registered admission"))?;
        if record.intent.task.is_none() {
            return Err(invalid("a TASK-less workflow settles no TASK"));
        }
        record.task_settled = Some(ended.to_owned());
        RECORD.put(&self.vault.store, txn, &root, &record)
    }

    /// What a bound wrapper's terminal commit runs next: its TASK settles in
    /// a writer of its own, and nothing here changes the transition it
    /// follows. An error is logged, and the host's pass settles it later. A
    /// completed run whose done-means asks a question waits for a pass that
    /// judges it.
    pub(crate) fn settle_bound_task_after_commit(&self, root: AttemptId, now: u64) {
        let settled = self
            .workflow_done_question(root)
            .and_then(|question| match question {
                Some(_) => Ok(false),
                None => self.settle_workflow_task(root, None, now),
            });
        if let Err(error) = settled {
            tracing::warn!(kind = ?error.kind(), ?root, "a workflow's TASK did not settle; the host's pass tries again");
        }
    }

    /// One ended run's TASK binding and durable results while its settlement
    /// is owed: `None` for a live, TASK-less or settled run.
    fn workflow_end(&self, root: AttemptId) -> Result<Option<WorkflowRunEnd>> {
        let txn = self.vault.store.env.read_txn()?;
        let Some(wrapper) = AttemptQueue::new(self.vault).get_in_txn(&txn, root)? else {
            return Ok(None);
        };
        if !wrapper.state.is_terminal() || !is_wrapper(&wrapper) {
            return Ok(None);
        }
        let record = self.read_workflow(&txn, &wrapper)?;
        let Some(binding) = record
            .intent
            .task
            .as_ref()
            .filter(|_| record.task_settled.is_none())
        else {
            return Ok(None);
        };
        let (task, bound_by) = binding.ids()?;
        Ok(Some(WorkflowRunEnd {
            workflow: EntityId::from_hex(&record.intent.workflow_ref)?,
            steps: record.steps.len(),
            results: record.results.clone(),
            task,
            bound_by,
            wrapper,
        }))
    }
}
