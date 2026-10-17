//! A runner's "Done means met?", answered before it settles (OF-533).
//!
//! A runner reports Done inside the write that settles its try, where no
//! model may run, so the report alone always asks up on a TASK with a brief.
//! A runner instead reads the question first, has the host's decisions
//! answer it on its own thread, and carries the answer into the completion.
//! The answer binds the TASK, result, brief version and principal it judged;
//! a report that finds any of them changed asks up as before.

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::decision::Reversibility;

use super::brief::StoredBrief;
use super::decision_port::{PortAnswer, TaskDecisions, TaskQuestion, ask};
use super::highway_report::done_question_inputs;
use super::highway_runner::{runner_refusal, runner_task_in};
use super::terminal_state::TaskExecutionState;
use super::wire_decode::task_verb_body_in;

/// What one runner Done is judged over, read outside any write.
#[derive(Debug, Clone)]
pub struct RunnerDoneQuestion {
    judged: Judged,
    evidence: Vec<EntityId>,
    state: serde_json::Value,
    reversibility: Reversibility,
}

/// The answer to a [`RunnerDoneQuestion`], for the completion that reports
/// its Done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerDoneAnswer {
    judged: Judged,
    answer: PortAnswer,
}

/// The report an answer was given for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Judged {
    task_ref: EntityId,
    result_ref: EntityId,
    brief_rev: u32,
    brief_digest: [u8; 32],
    principal: EntityId,
}

impl RunnerDoneQuestion {
    /// Asks the question through `decisions`; an abstention or a refused
    /// call answers "ask up".
    #[must_use]
    pub fn decide(&self, decisions: &TaskDecisions<'_>) -> RunnerDoneAnswer {
        RunnerDoneAnswer {
            judged: self.judged,
            answer: ask(
                Some(decisions),
                TaskQuestion::DoneMet,
                self.judged.principal,
                &self.evidence,
                &self.state,
                self.reversibility,
            ),
        }
    }
}

impl RunnerDoneAnswer {
    /// The answer, when it was given for exactly this report.
    pub(super) fn for_report(
        &self,
        task_ref: EntityId,
        result_ref: EntityId,
        brief: &StoredBrief,
        principal: EntityId,
    ) -> Option<PortAnswer> {
        let judged = Judged {
            task_ref,
            result_ref,
            brief_rev: brief.rev,
            brief_digest: brief.digest,
            principal,
        };
        (judged == self.judged).then_some(self.answer)
    }
}

/// The question a leased try's Done would ask, read before its runner
/// completes it. `None` when its Done asks none: no TASK the runner may
/// move, no durable result entity on the row, no brief (Done is met), or an
/// ask that already holds the TASK.
pub fn runner_done_question(
    vault: &Vault,
    attempt: AttemptId,
) -> Result<Option<RunnerDoneQuestion>> {
    let txn = vault.store.env.read_txn()?;
    let Some(record) = AttemptQueue::new(vault).get_in_txn(&txn, attempt)? else {
        return Ok(None);
    };
    if !record.state.is_running() {
        return Ok(None);
    }
    let Some(task_ref) = runner_task_in(vault, &txn, &record).map_err(runner_refusal)? else {
        return Ok(None);
    };
    let Some(result_ref) = record
        .result_ref
        .as_ref()
        .and_then(|result| EntityId::from_hex(result.as_str()).ok())
    else {
        return Ok(None);
    };
    if vault.get_entity_type_in_txn(&txn, &result_ref)?.is_none() {
        return Ok(None);
    }
    let Some(body) = task_verb_body_in(vault, &txn, task_ref)? else {
        return Ok(None);
    };
    if matches!(&body.state, Some(TaskExecutionState::Blocked { on, .. }) if !on.is_empty()) {
        return Ok(None);
    }
    let Some(brief) = body.brief else {
        return Ok(None);
    };
    // The principal the report asks for; a TASK with no authority row asks
    // up in the report.
    let Some(authority) = vault.task_authority_state_in(&txn, task_ref)? else {
        return Ok(None);
    };
    let (evidence, state) = done_question_inputs(task_ref, result_ref, &brief);
    Ok(Some(RunnerDoneQuestion {
        judged: Judged {
            task_ref,
            result_ref,
            brief_rev: brief.rev,
            brief_digest: brief.digest,
            principal: authority.owner_ref,
        },
        evidence,
        state,
        reversibility: brief.brief.escalation.reversibility,
    }))
}
