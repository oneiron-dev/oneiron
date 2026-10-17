//! The agent run pump's view (OF-533): every agent-def dispatch no other
//! host runs. A run's spawned children, and the top-level dispatches of an
//! agent that is no settled resident, run here. A saved workflow's leaves
//! are its pump's; a resident's inbox wakes and TASKs are the resident
//! pump's.

use super::resident::{resident_run_id, resident_run_input};
use super::workflow_record::is_wrapper;
use super::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchInput, AgentDispatchStatus, AgentDispatchTarget,
    AgentDispatcher, decode_agent_dispatch_input,
};
use crate::EntityId;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
};
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::error::Result;

/// How far up a run tree its Q&A thread is looked for.
const MAX_TREE_DEPTH: usize = 64;

/// A claimed agent run: its leased attempt and input, and the MESSAGE thread
/// its failure's Q&A goes to.
#[derive(Debug, Clone)]
pub struct AgentRun {
    pub status: AgentDispatchStatus,
    pub qa_thread_ref: EntityId,
}

/// An agent-def dispatch row this pump may run.
struct AgentRunRow {
    agent: EntityId,
    input: AgentDispatchInput,
    /// A top-level dispatch for a TASK, which is a resident's when its agent
    /// is one.
    task_root: bool,
}

impl AgentDispatcher<'_> {
    /// The agent run pump's view: each ready agent run, oldest first, with
    /// the agent it runs as. A TASK of one of `residents` is the resident
    /// pump's. It reads only; the claim checks the row again.
    pub fn ready_agent_runs(
        &self,
        residents: &[EntityId],
        now: u64,
    ) -> Result<Vec<(AttemptId, EntityId)>> {
        let queue = AttemptQueue::new(self.vault);
        let rows = queue.list_kind_bounded(
            DREAMER_RUNNER_ATTEMPT_KIND,
            crate::receipt::MAX_RECEIPT_QUERY_SCAN,
        )?;
        let txn = self.vault.store.env.read_txn()?;
        let mut ready = Vec::new();
        for row in rows {
            if !matches!(row.state, AttemptState::Queued | AttemptState::Scheduled)
                || row
                    .scheduled_at
                    .or(row.backoff_until)
                    .is_some_and(|at| at > now)
            {
                continue;
            }
            // A row this view cannot decode is no agent run; its own worker
            // reports it.
            let Ok(Some(run)) = agent_run_row(&queue, &txn, &row) else {
                continue;
            };
            if !(run.task_root && residents.contains(&run.agent)) {
                ready.push((row.id, run.agent));
            }
        }
        Ok(ready)
    }

    /// Claims one agent run by id, as the resident pump claims its runs.
    /// `None` when the row is no longer a ready run of this pump's, or
    /// another worker holds it.
    pub fn claim_agent_run(
        &self,
        id: AttemptId,
        lease_owner: &str,
        now: u64,
    ) -> Result<Option<AgentRun>> {
        let queue = AttemptQueue::new(self.vault);
        let mut txn = self.vault.store.env.write_txn()?;
        let Some(row) = queue.get_in_write_txn(&txn, id)? else {
            return Ok(None);
        };
        if !matches!(row.state, AttemptState::Queued | AttemptState::Scheduled) {
            return Ok(None);
        }
        let Some(run) = agent_run_row(&queue, &txn, &row)? else {
            return Ok(None);
        };
        if run.task_root
            && self
                .vault
                .resident_binding_for_effect_in_txn(&txn, run.agent)?
                .is_some()
        {
            return Ok(None);
        }
        self.dispatchable_definition_in_txn(&txn, &run.input.target)?;
        let qa_thread_ref = self.run_thread_in(&queue, &txn, &row)?;
        let ClaimOutcome::Claimed(attempt) = crate::ports::JobQueue::port_job_claim_id(
            self.vault,
            &mut txn,
            id,
            ClaimAttempt {
                lease_owner: lease_owner.to_owned(),
                now,
            },
        )?
        else {
            return Ok(None);
        };
        // OF-220: the TASK this try realizes is taken on the task highway.
        crate::task_verb::highway_runner::accept_leased_task_in_txn(
            self.vault, &mut txn, &attempt,
        )?;
        txn.commit()?;
        self.vault.store.notify_attempt_observers();
        Ok(Some(AgentRun {
            status: AgentDispatchStatus {
                attempt,
                input: run.input,
            },
            qa_thread_ref,
        }))
    }

    /// Where a run's failure asks: its tree's resident home when a settled
    /// resident's run spawned it, else its TASK, else its tree's root.
    fn run_thread_in(
        &self,
        queue: &AttemptQueue<'_>,
        txn: &heed::RoTxn<'_>,
        row: &AttemptRecord,
    ) -> Result<EntityId> {
        let mut root = row.clone();
        for _ in 0..MAX_TREE_DEPTH {
            let parent = decode_dreamer_attempt_payload(&root.payload)?.parent_attempt;
            let Some(parent) = parent.and_then(|id| queue.get_in_txn(txn, id).transpose()) else {
                break;
            };
            root = parent?;
        }
        if let Ok(Some((agent, _))) = resident_run_input(&root)
            && let Some((_, resident)) = self.vault.resident_binding_for_effect_in_txn(txn, agent)?
        {
            return Ok(resident.home_message_ref);
        }
        if let Some(task) = row
            .task_ref
            .as_deref()
            .and_then(|hex| EntityId::from_hex(hex).ok())
        {
            return Ok(task);
        }
        EntityId::from_bytes(*root.id.as_bytes())
    }
}

/// The row as an agent run of this pump, or `None` when it is another
/// host's: no agent dispatch, a saved workflow's leaf, a child whose parent
/// is gone, or a resident's inbox wake.
fn agent_run_row(
    queue: &AttemptQueue<'_>,
    txn: &heed::RoTxn<'_>,
    row: &AttemptRecord,
) -> Result<Option<AgentRunRow>> {
    if row.kind != DREAMER_RUNNER_ATTEMPT_KIND {
        return Ok(None);
    }
    let payload = decode_dreamer_attempt_payload(&row.payload)?;
    if payload.attempt_type != AGENT_DISPATCH_ATTEMPT_TYPE {
        return Ok(None);
    }
    let input = decode_agent_dispatch_input(&payload.input)?;
    let AgentDispatchTarget::Custom(agent) = &input.target else {
        return Ok(None);
    };
    let agent = *agent;
    let task_root = match payload.parent_attempt {
        Some(parent) => match queue.get_in_txn(txn, parent)? {
            Some(parent) if !is_wrapper(&parent) => false,
            _ => return Ok(None),
        },
        None if row.run_id.as_deref() == Some(resident_run_id(agent).as_str()) => {
            return Ok(None);
        }
        None => row.task_ref.is_some(),
    };
    Ok(Some(AgentRunRow {
        agent,
        input,
        task_root,
    }))
}
