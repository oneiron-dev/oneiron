//! The agent run pump's view (OF-533): every agent-def dispatch no other
//! host runs. A run's spawned children, and the top-level dispatches of an
//! agent that is no settled resident, run here. A saved workflow's leaves
//! are its pump's; a resident's inbox wakes and TASKs are the resident
//! pump's, which take no executor lease yet (FIX 4747 slice 6).
//!
//! The claim takes the run's executor lease on its run TASK in its write
//! (FIX 4747, `super::run_task`): a run another machine holds or settled,
//! or whose run TASK stands but does not read, ends here unrun, and a
//! closing process claims nothing. A spawned child has no run TASK of its
//! own: its claim takes no lease and runs it under a fence on its root's
//! (REVIEW-6638).

use super::resident::{resident_run_id, resident_run_input};
use super::run_task::{
    AGENT_RUN_EXECUTOR_MOVED, AgentRunFence, AgentRunLeaseTake, agent_run_moved_in,
    agent_run_unrun_cause_in, take_agent_run_lease_in_txn,
};
use super::workflow_record::is_wrapper;
use super::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchInput, AgentDispatchStatus, AgentDispatchTarget,
    AgentDispatcher, decode_agent_dispatch_input,
};
use crate::EntityId;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome, FailAttempt,
};
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::error::Result;

/// How far up a run tree its Q&A thread is looked for.
const MAX_TREE_DEPTH: usize = 64;

/// A claimed agent run: its leased attempt and input, the MESSAGE thread
/// its failure's Q&A goes to, and the fence its claim took on its run TASK
/// (FIX 4747); `None` for a run with no run TASK, which runs as before.
#[derive(Debug, Clone)]
pub struct AgentRun {
    pub status: AgentDispatchStatus,
    pub qa_thread_ref: EntityId,
    pub fence: Option<AgentRunFence>,
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
        let txn = self.vault.store.env.read_txn()?;
        let rows = queue.ready_rows_in_txn(&txn)?;
        let mut ready = Vec::new();
        for row in rows {
            if row.kind != DREAMER_RUNNER_ATTEMPT_KIND
                || !matches!(row.state, AttemptState::Queued | AttemptState::Scheduled)
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
        // FIX 11592: a requester whose authority was withdrawn ends the try
        // unrun, on the TASK runner's turn; this pump claims nothing.
        if self.requester_withdrawn_in_txn(&txn, &run.input).is_some() {
            drop(txn);
            self.end_withdrawn(id, lease_owner, now)?;
            return Ok(None);
        }
        let qa_thread_ref = self.run_thread_in(&queue, &txn, &row)?;
        // FIX 4747: the run's executor lease, taken in this write; a spawned
        // child's claim only fences it on its root's (REVIEW-6638). A run
        // another machine holds or settled, or whose run TASK does not read,
        // ends unrun, with no fence and no change to its run TASK; a closing
        // process claims nothing and the row stays queued.
        let fence = match take_agent_run_lease_in_txn(self.vault, &mut txn, &row, now)? {
            AgentRunLeaseTake::NoRunTask => None,
            AgentRunLeaseTake::Taken(fence) => Some(fence),
            AgentRunLeaseTake::Closing => return Ok(None),
            AgentRunLeaseTake::HeldElsewhere
            | AgentRunLeaseTake::Settled
            | AgentRunLeaseTake::Unreadable => {
                drop(txn);
                self.end_unrun_agent_run(id, lease_owner, now)?;
                return Ok(None);
            }
        };
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
        // The run's step commits and effects meet this fence while it is on
        // this host (`run_task::fence_agent_run_step_in_txn`).
        if let Some(fence) = fence {
            self.vault.register_agent_run_fence(attempt.id, fence);
        }
        self.vault.store.notify_attempt_observers();
        Ok(Some(AgentRun {
            status: AgentDispatchStatus {
                attempt,
                input: run.input,
            },
            qa_thread_ref,
            fence,
        }))
    }

    /// Ends the queued try `id`, whose run another machine holds or
    /// settled, or whose run TASK does not read, unrun, as `lease_owner`
    /// (FIX 4747): in a writer of its own the run TASK is judged again, then
    /// the try is claimed and fails for good with the typed cause, its step
    /// receipts go and its spend lease settles, as [`Self::end_withdrawn`]
    /// ends a try. Neither its run TASK nor the TASK it realizes changes:
    /// the run is not this machine's to run. A try another worker took
    /// first, or whose run is this machine's again, is left as it is.
    fn end_unrun_agent_run(&self, id: AttemptId, lease_owner: &str, now: u64) -> Result<()> {
        let ended = self.vault.with_write_txn_grouped(|txn| {
            let Some(row) = AttemptQueue::new(self.vault).get_in_write_txn(&*txn, id)? else {
                return Ok(None);
            };
            if !matches!(row.state, AttemptState::Queued | AttemptState::Scheduled) {
                return Ok(None);
            }
            let Some(cause) = agent_run_unrun_cause_in(self.vault, txn, &row)? else {
                return Ok(None);
            };
            let ClaimOutcome::Claimed(attempt) = crate::ports::JobQueue::port_job_claim_id(
                self.vault,
                txn,
                id,
                ClaimAttempt {
                    lease_owner: lease_owner.to_owned(),
                    now,
                },
            )?
            else {
                return Ok(None);
            };
            self.end_leased_unrun_in_txn(txn, &attempt, lease_owner, cause, now)?;
            Ok(Some((attempt, cause)))
        })?;
        if let Some((attempt, cause)) = ended {
            tracing::info!(
                attempt = %crate::entity_id::bytes_to_hex_lower(attempt.id.as_bytes()),
                cause,
                "an agent run's queued try ended unrun: its run is not this machine's to run"
            );
            self.notify_ended(&attempt);
        }
        Ok(())
    }

    /// Stands the claimed run `attempt` down at its settlement when its
    /// run TASK no longer names the holding `fence` took (FIX 4747): in one
    /// writer the fence is read again, and the try fails for good with
    /// `agent_run_executor_moved` under `lease_owner`, its step receipts go
    /// and its spend lease settles, with no change to its run TASK or the
    /// TASK it realizes. `false` while the fence holds, so the settlement
    /// goes on; `true` once the run stood down, or another worker took its
    /// lease meanwhile.
    ///
    /// # Errors
    /// Storage errors.
    pub fn stand_down_moved_agent_run(
        &self,
        fence: &AgentRunFence,
        attempt: &AttemptRecord,
        lease_owner: &str,
        now: u64,
    ) -> Result<bool> {
        let moved = {
            let rtxn = self.vault.store.env.read_txn()?;
            agent_run_moved_in(self.vault, &rtxn, fence)?
        };
        if !moved {
            return Ok(false);
        }
        let ended = self.vault.with_write_txn_grouped(|txn| {
            if !agent_run_moved_in(self.vault, &*txn, fence)? {
                return Ok(None);
            }
            if !AttemptQueue::new(self.vault).holds_lease_in_txn(
                &*txn,
                attempt.id,
                lease_owner,
                attempt.attempt_count,
            )? {
                return Ok(Some(None));
            }
            self.end_leased_unrun_in_txn(txn, attempt, lease_owner, AGENT_RUN_EXECUTOR_MOVED, now)?;
            Ok(Some(Some(attempt.clone())))
        })?;
        match ended {
            None => Ok(false),
            Some(ended) => {
                if let Some(attempt) = ended {
                    self.notify_ended(&attempt);
                }
                Ok(true)
            }
        }
    }

    /// Drops the fence `attempt`'s claim took, once its run left this host
    /// (FIX 4747): its settlement returned, or it parked.
    pub fn forget_agent_run_fence(&self, attempt: AttemptId) {
        self.vault.forget_agent_run_fence(attempt);
    }

    /// Fails the leased try `attempt` for good with `cause` and nothing run,
    /// in the caller's write: its step receipts go and its spend lease
    /// settles. The TASK it realizes is not reported: its run is another
    /// machine's.
    fn end_leased_unrun_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: &AttemptRecord,
        lease_owner: &str,
        cause: &str,
        now: u64,
    ) -> Result<()> {
        let _failed = crate::ports::JobQueue::port_job_fail(
            self.vault,
            txn,
            FailAttempt {
                id: attempt.id,
                lease_owner: lease_owner.to_owned(),
                attempt_count: attempt.attempt_count,
                reason: cause.to_owned(),
                now,
            },
        )?;
        crate::dreamer_runner::DreamerRunnerStore::new(self.vault)
            .cleanup_step_receipts_in_txn(txn, attempt.id)?;
        self.settle_child_in_txn(txn, &attempt.id, now)?;
        Ok(())
    }

    /// Tells the attempt observers and the TASK board a try ended.
    fn notify_ended(&self, attempt: &AttemptRecord) {
        self.vault.store.notify_attempt_observers();
        self.vault.store.notify_task_updates(
            attempt
                .task_ref
                .as_deref()
                .and_then(|task| EntityId::from_hex(task).ok()),
        );
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
            && let Some((_, resident)) =
                self.vault.resident_binding_for_effect_in_txn(txn, agent)?
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

impl AgentDispatcher<'_> {
    /// Whether attempt `id` is a run the native agent pump would take at
    /// `now` (FIX 4929): queued or scheduled, resting on no schedule or
    /// backoff past `now`, and an agent run of this pump's by
    /// [`Self::ready_agent_runs`]'s rule, so no saved workflow's leaf and no
    /// orphaned child. A status read asks it; it decides and changes nothing.
    pub fn is_ready_native_run(&self, id: AttemptId, now: u64) -> Result<bool> {
        let queue = AttemptQueue::new(self.vault);
        let txn = self.vault.store.env.read_txn()?;
        let Some(row) = queue.get_in_txn(&txn, id)? else {
            return Ok(false);
        };
        if !matches!(row.state, AttemptState::Queued | AttemptState::Scheduled)
            || row
                .scheduled_at
                .or(row.backoff_until)
                .is_some_and(|at| at > now)
        {
            return Ok(false);
        }
        Ok(agent_run_row(&queue, &txn, &row)?.is_some())
    }
}

/// Whether the agent run pump is the one that claims `row` (FIX 4747): an
/// agent-def dispatch row it reads, other than a resident agent's TASK-root
/// run, which the resident pump runs. Only such a run takes the executor
/// lease at its claim, so only its dispatch mints a run TASK, and only when
/// it is a root: a spawned child runs under its root's (REVIEW-6638).
pub(super) fn agent_pump_claims_in(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    row: &AttemptRecord,
) -> Result<bool> {
    let queue = AttemptQueue::new(vault);
    let Some(run) = agent_run_row(&queue, txn, row)? else {
        return Ok(false);
    };
    Ok(!(run.task_root
        && vault
            .resident_binding_for_effect_in_txn(txn, run.agent)?
            .is_some()))
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
