//! `self.workflows.dispatch_bound` (FIX 5316): a leased agent run binds one
//! run of a saved workflow to a TASK it owns, as itself. The run must hold
//! its live lease: the try it holds is the bound run's real parent, whose
//! run, project, scope, context and depth bounds every step inherits and
//! whose lease tree the run spends under. The TASK, the workflow and each
//! step's definition are read first on the read lane the run's door
//! admitted the call with, never the owner's, and the lease is read again
//! after them. The bind gate, the take and the TASK's settlement are the
//! owner's own, run as the agent under its own class.

use crate::claim::{ClaimReadStatus, PointRead, ScopedReadActorKey};
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    AGENT_VERB_SESSION_BOUND, AgentVerbAnswer, SelfDeniedResult, SelfDispatchOutcome, SelfEffect,
    SelfFailedResult,
};
use crate::error::{ArtifactError, Error, Result};
use crate::task_verb::HostBinding;
use crate::task_verb::sdk::{
    WorkflowBoundDispatchRequest, WorkflowRunView, dispatch_workflow_bound_as,
};
use crate::{EntityId, Vault};

use super::HostSelfDispatcher;

/// What a run with no live lease on its own agent try reads.
const NEEDS_LEASE: &str = "self.workflows.dispatch_bound needs a live leased run; bind from an \
                           agent run that still holds its try's lease";
/// What a run whose door admitted the call with no read lane reads.
const NEEDS_LANE: &str = "self.workflows.dispatch_bound reads its TASK and workflow on its run's \
                          read lane; call it through a host door that binds your credential's \
                          read key";
/// What a run reads when its lane does not read a ref the binding needs.
const UNREADABLE: &str = "self.workflows.dispatch_bound reads its TASK, its workflow and each \
                          step's definition on its run's read lane, and one is not readable \
                          there; bind only a TASK and a workflow your Grant reads";

impl HostSelfDispatcher<'_> {
    /// The run's binding of a saved workflow's run to a TASK, answered with
    /// the run's view and the rows it served. A refusal is a failure the
    /// script reads, named by what would admit it. A run bound to a session
    /// is refused: the binding writes the canonical vault.
    pub(super) fn dispatch_workflow_bound(
        &self,
        call: WorkflowBoundDispatchRequest,
        read_as: Option<ScopedReadActorKey>,
    ) -> Result<SelfDispatchOutcome> {
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Ok(SelfDispatchOutcome::Denied(SelfDeniedResult {
                effect: SelfEffect::WorkflowDispatch,
                outcome: AGENT_VERB_SESSION_BOUND.to_owned(),
                reason_codes: Vec::new(),
            }));
        };
        if self.live_lease()?.is_none() {
            return Ok(refused(NEEDS_LEASE));
        }
        let Some(reader) = read_as else {
            return Ok(refused(NEEDS_LANE));
        };
        if !lane_reads(vault, &reader, &[call.task_ref, call.workflow_ref])? {
            return Ok(refused(UNREADABLE));
        }
        let steps = match vault.get_workflow(&call.workflow_ref) {
            Ok(Some(definition)) => definition.steps,
            Ok(None) => return Ok(refused(UNREADABLE)),
            Err(error) => return Ok(refused(&error.to_string())),
        };
        if !lane_reads(vault, &reader, &steps)? {
            return Ok(refused(UNREADABLE));
        }
        // A lease lost while the refs were read binds nothing; the binder
        // reads it once more in its writer.
        let Some(lease) = self.live_lease()? else {
            return Ok(refused(NEEDS_LEASE));
        };
        let task = call.task_ref;
        let view = match dispatch_workflow_bound_as(vault, self.actor, &lease, &reader, call) {
            Ok(view) => view,
            Err(error) => return Ok(refused(&error.message)),
        };
        let output = serde_json::to_value(&view)
            .map_err(|_| Error::InvariantViolation("workflow run answer encode"))?;
        Ok(SelfDispatchOutcome::AgentVerb(AgentVerbAnswer {
            output,
            rows: Some(run_rows(&view, task)),
            observations: Vec::new(),
        }))
    }

    /// The live lease of the agent try this run is, read now; `None` for a
    /// run no leased agent try binds, or whose lease no longer holds.
    fn live_lease(&self) -> Result<Option<HostBinding>> {
        if self.agent_lease.is_none() {
            return Ok(None);
        }
        match self.task_host_binding() {
            Ok(binding) => Ok(binding),
            Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(_))) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// A refusal the script reads.
fn refused(message: &str) -> SelfDispatchOutcome {
    SelfDispatchOutcome::Failed(SelfFailedResult {
        effect: SelfEffect::WorkflowDispatch,
        error: message.to_owned(),
    })
}

/// Whether `reader`'s lane reads every one of `refs`, bodies included, in
/// one snapshot. Every ref is read, however many.
fn lane_reads(vault: &Vault, reader: &ScopedReadActorKey, refs: &[EntityId]) -> Result<bool> {
    let points: Vec<_> = refs.iter().copied().map(PointRead::id).collect();
    let checked = vault
        .scoped_read(reader.clone())
        .with_claim_status(ClaimReadStatus::Recorded)
        .read(&points, None)?;
    Ok(checked
        .value
        .iter()
        .all(|row| row.as_ref().is_some_and(|row| row.body.is_some())))
}

/// The rows the answer serves: the TASK, the workflow, every attempt the
/// run started and every definition its steps captured.
fn run_rows(view: &WorkflowRunView, task: EntityId) -> Vec<EntityId> {
    let mut rows = vec![
        task,
        view.workflow_ref,
        view.root_attempt_ref,
        view.active_attempt_ref,
    ];
    for step in &view.steps {
        rows.extend([step.requested_agent_ref, step.agent_def_ref]);
    }
    for result in &view.results {
        rows.extend([result.dispatched_agent_ref, result.attempt_ref]);
    }
    rows.sort_unstable();
    rows.dedup();
    rows
}
