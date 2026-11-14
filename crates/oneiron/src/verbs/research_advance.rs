//! `vault.research.advance` (LEARNING-09; ruling LEARN-ROOT-09 = B): the
//! owner, or an agent whose live owner Grant names it and lists this verb,
//! runs the host pass for one campaign bound with an execution spec now,
//! rather than at the next Coach tick, and reads where its work stands.
//!
//! The pass is the Coach host's own, for this one root: each owed or live
//! continuation steps until a run is still going, it holds, or it ends. It
//! adds no authority. The agents it dispatches are the ones the bind named,
//! every step reserves on the RSI lines first, and a budget hold stays a hold
//! until the owner tops up the line and resumes. The answer names no sealed
//! case: a released confirmation shows only that it was released.

use serde::{Deserialize, Serialize};

use super::research_root::admit_owner_or_granted_in_txn;
use crate::attempt_queue::AttemptId;
use crate::autoreason_campaign::research::{
    self, ForkKind, ResearchBudgetRead, ResearchContinuation, ResearchContinuationState,
    ResearchReservationLine, ResearchRunning, ResearchSplit, ResearchTask, ResearchWork,
};
use crate::entity_id::EntityId;
use crate::memory::{Memory, MemoryResult};

/// The verb a Grant lists to name a host pass: the row's own name.
const ADVANCE_VERB: &str = "vault.research.advance";

/// `vault.research.advance`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchAdvanceWire {
    /// The campaign's root attempt.
    pub root: EntityId,
}

/// One task of a continuation; ids travel as hex.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResearchTaskView {
    /// Score `node`'s candidate on a split.
    Measure {
        node: EntityId,
        split: ResearchSplit,
    },
    /// Run the experimenter under `parent` for one child candidate.
    Experiment { parent: EntityId, kind: ForkKind },
    /// Decide promotion of `candidate` against the incumbent.
    Basis { candidate: EntityId },
    /// Serve the sealed cohort and run the referee on `candidate`.
    Confirm { candidate: EntityId },
}

/// The task in flight.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchRunningView {
    pub task: ResearchTaskView,
    /// The token reservation the task's run spends.
    pub reservation: EntityId,
    /// A confirmation's exposure reservation on the exploration line.
    pub exposure: Option<EntityId>,
    /// The dispatched run, once there is one.
    pub run: Option<EntityId>,
    /// Whether the sealed cohort was released for this task. Its cases go to
    /// the referee alone.
    pub released: bool,
}

/// One continuation: what is left to run, what is running, and why it waits.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchContinuationView {
    pub work: ResearchWork,
    /// The tasks still to run; the front runs next.
    pub pending: Vec<ResearchTaskView>,
    pub running: Option<ResearchRunningView>,
    pub state: ResearchContinuationState,
    /// The line whose refusal holds the front task, while it is held for
    /// budget.
    pub held_line: Option<ResearchReservationLine>,
    /// Every run this continuation dispatched, in order.
    pub runs: Vec<EntityId>,
    pub updated_at: u64,
}

/// `vault.research.advance`'s answer: the campaign's continuations after the
/// pass, and its lease read.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResearchAdvanceView {
    pub root: EntityId,
    pub continuations: Vec<ResearchContinuationView>,
    pub budget: ResearchBudgetRead,
}

/// `vault.research.advance` on the caller's handle.
///
/// # Errors
///
/// FORBIDDEN for a caller that is neither the vault owner nor an agent with
/// a live owner Grant listing the verb; an unbound root, or a campaign bound
/// without an execution spec; every refusal a pass meets that is not one
/// continuation's own; storage errors; another pass advancing one of the
/// campaign's continuations at the same time.
pub fn research_advance(
    memory: &Memory<'_>,
    input: ResearchAdvanceWire,
) -> MemoryResult<ResearchAdvanceView> {
    let root = AttemptId::from_bytes(input.root.as_bytes())?;
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    admit_owner_or_granted_in_txn(memory, &txn, ADVANCE_VERB)?;
    drop(txn);
    let continuations = research::advance_research_campaign(vault, root, vault.now_recorded_at())?
        .into_iter()
        .map(continuation_view)
        .collect::<MemoryResult<_>>()?;
    Ok(ResearchAdvanceView {
        root: input.root,
        continuations,
        budget: research::research_budget(vault, root)?,
    })
}

fn hex_id(attempt: AttemptId) -> MemoryResult<EntityId> {
    Ok(EntityId::from_bytes(*attempt.as_bytes())?)
}

fn task_view(task: ResearchTask) -> MemoryResult<ResearchTaskView> {
    Ok(match task {
        ResearchTask::Measure { node, split } => ResearchTaskView::Measure {
            node: hex_id(node)?,
            split,
        },
        ResearchTask::Experiment { parent, kind } => ResearchTaskView::Experiment {
            parent: hex_id(parent)?,
            kind,
        },
        ResearchTask::Basis { candidate } => ResearchTaskView::Basis {
            candidate: hex_id(candidate)?,
        },
        ResearchTask::Confirm { candidate } => ResearchTaskView::Confirm {
            candidate: hex_id(candidate)?,
        },
    })
}

fn running_view(running: ResearchRunning) -> MemoryResult<ResearchRunningView> {
    Ok(ResearchRunningView {
        task: task_view(running.task)?,
        reservation: running.reservation,
        exposure: running.exposure,
        run: running.run.map(hex_id).transpose()?,
        released: running.release.is_some(),
    })
}

fn continuation_view(row: ResearchContinuation) -> MemoryResult<ResearchContinuationView> {
    Ok(ResearchContinuationView {
        work: row.work,
        pending: row
            .pending
            .into_iter()
            .map(task_view)
            .collect::<MemoryResult<_>>()?,
        running: row.running.map(running_view).transpose()?,
        state: row.state,
        held_line: row.held_line,
        runs: row
            .runs
            .into_iter()
            .map(hex_id)
            .collect::<MemoryResult<_>>()?,
        updated_at: row.updated_at,
    })
}
