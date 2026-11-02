//! A saved workflow that realizes a TASK (FIX 4391), on the dispatch side:
//! the bound admission, the wrapper facts the TASK's fence reads, and the
//! settlement an ended run owes its TASK.
//!
//! Only the wrapper carries the TASK backlink; its leaves stay TASK-less.
//! The binding is part of the stored intent, so the same intent key naming
//! another TASK, or none, is another intent. An owner's or a member's bound
//! run is a root; an agent's has the try its lease holds as its real parent
//! (FIX 5316). A member's run requires a payer, which its steps find through
//! their wrapper, as they find the member whose own lane their context is
//! read on (FIX 5416). An agent's run whose declared context widens its
//! parent's slice files the board a widen proposal that keeps the binding,
//! and takes its TASK only in the writer that approves it (FIX 5350). A
//! TASK-less run never reaches any of this. The TASK's own gate, take, fence
//! and settlement are the task highway's
//! (`task_verb::highway_runner::workflow_try`).

use crate::agent_dispatch::widen::PreparedParentContext;
use crate::agent_dispatch::widen_record::invalid;
use crate::agent_dispatch::workflow_record::{
    DEDUPE, RECORD, WORKFLOW_ATTEMPT_TYPE, WorkflowTaskBinding, dedupe_key_hash, is_wrapper,
    wrapper_rows_in_txn,
};
use crate::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext, DispatchAgent,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::context_projection::{normalize_context_spec, validate_spec_narrows};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::memory::MemoryError;
use crate::task_verb::highway_runner::workflow_try::{self, WorkflowRunEnd, WorkflowTaskBind};
use crate::task_verb::{RunnerDoneAnswer, RunnerDoneQuestion};

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
    /// `refusal`, given the key and the run it names. A first run whose
    /// record the side-row wall masked answers the same request, read as
    /// the wall stores it in `txn` (FIX 2314), which a caller outside its
    /// own writer opens and commits nothing in.
    pub(crate) fn bound_workflow_existing_in(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: &DispatchAgent,
        spawn: &AgentSpawnContext,
        bind: &WorkflowTaskBind,
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
        // The slip a member presented is settlement metadata, no part of the
        // request (FIX 5419): a retry on another slip answers the first run.
        let mut binding = WorkflowTaskBinding::new(bind);
        binding.slip = record.intent.task.as_ref().and_then(|first| first.slip);
        expected.task = Some(binding);
        if record.intent != expected
            && record.intent != self.admitted_workflow_intent_in(txn, expected)?
        {
            return Err(refusal(key, root));
        }
        Ok(Some(AgentDispatchOutcome::WorkflowExisting(Box::new(
            self.workflow_status_from(row, &record)?,
        ))))
    }

    /// Admits a TASK-bound run in the caller's writer, after its TASK's
    /// gate: the ordinary saved-workflow admission with the binding in its
    /// intent and the backlink on its wrapper alone. An agent's run whose
    /// declared context widens its parent's slice, which that admission
    /// refuses, files a widen proposal keeping the binding in this writer
    /// instead (FIX 5350): no run is queued and no TASK is taken until the
    /// board above approves it.
    pub(crate) fn dispatch_bound_workflow_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: DispatchAgent,
        spawn: AgentSpawnContext,
        bind: &WorkflowTaskBind,
    ) -> Result<AgentDispatchOutcome> {
        let binding = WorkflowTaskBinding::new(bind);
        if self.bound_context_widens(txn, &input, &spawn)
            && let Some(proposed) =
                self.propose_context_widen_in_txn(txn, &input, &spawn, Some(&binding))?
        {
            return Ok(proposed);
        }
        self.dispatch_workflow_bound_in_txn(txn, input, spawn, None, Some(&binding))
    }

    /// Whether a bound run's declared context widens its leased parent's
    /// slice: the one case its admission refuses (`validate_spec_narrows`).
    /// A root run, or a parent whose slice does not read, is left to that
    /// admission, which answers as it always did.
    fn bound_context_widens(
        &self,
        txn: &heed::RwTxn<'_>,
        input: &DispatchAgent,
        spawn: &AgentSpawnContext,
    ) -> bool {
        let (Some(parent), Some(spec)) = (input.parent_attempt, spawn.context_spec.as_ref()) else {
            return false;
        };
        let parent_spec = self
            .parent_dispatch_input_in_txn(txn, parent)
            .and_then(|parent_input| {
                parent_input
                    .map(|parent_input| {
                        self.effective_context_spec_in_txn(txn, parent, &parent_input)
                    })
                    .transpose()
            });
        let Ok(Some(parent_spec)) = parent_spec else {
            return false;
        };
        validate_spec_narrows(&parent_spec, spec).is_err()
    }

    /// Lands an agent's bound run whose widen the board above approved
    /// (FIX 5350), in the approving writer: the bind gate again, the run
    /// under the approved slice with the binding on its wrapper, then the
    /// wrapper's take of its TASK. A refusal of either lands nothing.
    pub(in crate::agent_dispatch) fn approve_bound_workflow_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        input: DispatchAgent,
        spawn: AgentSpawnContext,
        approved: &PreparedParentContext,
        binding: &WorkflowTaskBinding,
    ) -> Result<AgentDispatchOutcome> {
        let bind = binding.bind()?;
        workflow_try::admit_in_txn(self.vault, txn, bind.bound_by, bind.task)
            .map_err(bound_refusal)?;
        let outcome =
            self.dispatch_workflow_bound_in_txn(txn, input, spawn, Some(approved), Some(binding))?;
        if let AgentDispatchOutcome::WorkflowDispatched(status) = &outcome {
            workflow_try::take_in_txn(self.vault, txn, bind.bound_by, &status.attempt, bind.task)
                .map_err(bound_refusal)?;
        }
        Ok(outcome)
    }

    /// The TASK a registered wrapper realizes and the actor who bound it,
    /// under its class, in `txn`. `None` for any other row and for a
    /// TASK-less run.
    pub(crate) fn workflow_task_source_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        row: &AttemptRecord,
    ) -> Result<Option<WorkflowTaskBind>> {
        if !is_wrapper(row) || RECORD.get(&self.vault.store, txn, &row.id)?.is_none() {
            return Ok(None);
        }
        let record = self.read_workflow(txn, row)?;
        record
            .intent
            .task
            .as_ref()
            .map(WorkflowTaskBinding::bind)
            .transpose()
    }

    /// Whether `attempt`'s model calls must read a payer because it is a
    /// step of a member's bound run (FIX 5316): its parent is a registered
    /// wrapper whose TASK binding requires one. The wrapper alone keeps the
    /// fact, so a step's retries find it too. `false` for any other attempt,
    /// a missing one included.
    ///
    /// # Errors
    ///
    /// A wrapper whose record does not match it; storage errors.
    pub fn workflow_payer_required(&self, attempt: AttemptId) -> Result<bool> {
        let queue = AttemptQueue::new(self.vault);
        let txn = self.vault.store.env.read_txn()?;
        let Some(parent) = queue
            .get_in_txn(&txn, attempt)?
            .and_then(|row| decode_dreamer_attempt_payload(&row.payload).ok())
            .and_then(|payload| payload.parent_attempt)
        else {
            return Ok(false);
        };
        let Some(wrapper) = queue.get_in_txn(&txn, parent)? else {
            return Ok(false);
        };
        if !is_wrapper(&wrapper) || RECORD.get(&self.vault.store, &txn, &wrapper.id)?.is_none() {
            return Ok(false);
        }
        Ok(self
            .read_workflow(&txn, &wrapper)?
            .intent
            .task
            .is_some_and(|binding| binding.payer_required))
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
        let txn = self.vault.store.env.read_txn()?;
        let rows = wrapper_rows_in_txn(self.vault, &txn)?;
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
    /// live, TASK-less or settled, or its TASK moved on, or the TASK or its
    /// fence was lost for good, which marks the run settled with that typed
    /// reason so no pass retries it (FIX 5291).
    ///
    /// # Errors
    ///
    /// The fence's and the TASK writer's transient refusals; storage errors.
    /// Nothing is marked then, so a later pass tries again.
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
        // FIX 2314: through the vault's custody door, as admission wrote it.
        RECORD.put(self.vault, txn, &root, &record)
    }

    /// Marks an ended run's TASK settlement run in a writer of its own when
    /// its TASK or fence was lost for good (FIX 5291): `ended` with the typed
    /// `reason` beside it, nothing on the TASK moved, so no later pass runs
    /// it again. A run some pass marked since keeps its mark.
    pub(crate) fn mark_workflow_task_lost(
        &self,
        root: AttemptId,
        ended: &str,
        reason: &str,
    ) -> Result<()> {
        let mut txn = self.vault.store.env.write_txn()?;
        let settled = RECORD
            .get(&self.vault.store, &txn, &root)?
            .and_then(|record| record.task_settled);
        if settled.is_none() {
            self.mark_workflow_task_settled_in(&mut txn, root, &format!("{ended}:{reason}"))?;
        }
        txn.commit()?;
        tracing::info!(
            ?root,
            reason,
            "a workflow's TASK settlement was lost for good; it settles moving nothing"
        );
        Ok(())
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
        let bind = binding.bind()?;
        Ok(Some(WorkflowRunEnd {
            workflow: EntityId::from_hex(&record.intent.workflow_ref)?,
            steps: record.steps.len(),
            results: record.results.clone(),
            task: bind.task,
            bound_by: bind.bound_by,
            settles_on_bind: bind.settles_on_bind(),
            wrapper,
        }))
    }
}

/// A bound run's gate or take refusal, as the approving writer's error: the
/// approval lands nothing.
fn bound_refusal(error: MemoryError) -> Error {
    Error::Refused(format!(
        "this widen's TASK binding no longer holds: {}",
        error.message
    ))
}
