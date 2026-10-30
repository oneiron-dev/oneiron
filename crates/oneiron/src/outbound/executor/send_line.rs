//! The connector-send executor's claim order (FIX 12157). One drain takes
//! the sends ready at its `now` in the fair line's order
//! ([`super::super::fair_line`]): round-robin across the writers whose sends
//! wait, oldest first within one writer. The sends a full count-bound window
//! paced all come back at the instant it opens, so they share that window by
//! writer rather than by arrival. A drain with nothing ready reads once and
//! writes nothing.

use std::collections::{HashSet, VecDeque};

use super::super::connector_task::ConnectorSendAttemptPayload;
use super::super::fair_line::fair_line_order;
use super::CONNECTOR_TASK_EXECUTOR_LEASE_OWNER;
use crate::Vault;
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, admission_order,
};
use crate::entity_id::EntityId;
use crate::error::Error;

/// Whose turn a ready send takes: its TASK's sending actor, or the row alone
/// for a send whose TASK does not read, which the executor then fails.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum SendWriter {
    Actor(EntityId),
    Row(AttemptId),
}

/// One drain's line of ready connector sends.
#[derive(Default)]
pub(super) struct ConnectorSendLine {
    /// The ready sends the last plan put in line, in the fair line's order.
    planned: VecDeque<AttemptId>,
    /// Every send this drain took from the line, claimed or not: a later
    /// plan passes over it, so a drain ends.
    taken: HashSet<AttemptId>,
}

impl ConnectorSendLine {
    /// Claims the next ready send in the line's order; `None` once no send
    /// is ready at `now`. A planned send another claim took, or one no longer
    /// claimable, is passed over; when the plan runs out, the line is planned
    /// again from the sends ready now.
    ///
    /// # Errors
    /// Storage errors.
    pub(super) fn claim_next(
        &mut self,
        vault: &Vault,
        queue: &AttemptQueue<'_>,
        now: u64,
    ) -> Result<Option<AttemptRecord>, Error> {
        loop {
            let Some(id) = self.planned.pop_front() else {
                self.plan(vault, queue, now)?;
                if self.planned.is_empty() {
                    return Ok(None);
                }
                continue;
            };
            self.taken.insert(id);
            if let ClaimOutcome::Claimed(attempt) = claim_planned(vault, queue, id, now)? {
                // Only a real claim is broadcast, so an empty line never
                // wakes the worker that just found it empty.
                vault.store.notify_attempt_observers();
                return Ok(Some(attempt));
            }
        }
    }

    /// Puts every connector send ready at `now` that this drain has not
    /// taken in the fair line's order, each send's writer read from its TASK
    /// in one snapshot.
    fn plan(&mut self, vault: &Vault, queue: &AttemptQueue<'_>, now: u64) -> Result<(), Error> {
        let rtxn = vault.store.env.read_txn()?;
        let cutoff = now.min(crate::ports::job_recorded_at_in_txn(&vault.store, &rtxn)?);
        let mut ready: Vec<_> = queue
            .ready_rows_in_txn(&rtxn)?
            .into_iter()
            .filter(|row| {
                row.kind == crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND
                    && row.accepts_worker(CONNECTOR_TASK_EXECUTOR_LEASE_OWNER)
                    && !self.taken.contains(&row.id)
            })
            .filter_map(|row| {
                admission_order(&row)
                    .filter(|(ready_at, _)| *ready_at <= cutoff)
                    .map(|order| (order, row))
            })
            .collect();
        ready.sort_by_key(|(order, _)| *order);
        let writers = ready
            .into_iter()
            .map(|(_, row)| (send_writer(vault, &rtxn, &row), row.id));
        self.planned = VecDeque::from(fair_line_order(writers));
        Ok(())
    }
}

/// Whose turn `row` takes, read from its TASK in the plan's snapshot.
fn send_writer(vault: &Vault, rtxn: &heed::RoTxn<'_>, row: &AttemptRecord) -> SendWriter {
    serde_json::from_slice::<ConnectorSendAttemptPayload>(&row.payload)
        .ok()
        .and_then(|payload| EntityId::from_hex(&payload.task_ref).ok())
        .and_then(|task_ref| vault.connector_send_task_in(rtxn, &task_ref).ok().flatten())
        .map_or(SendWriter::Row(row.id), |task| {
            SendWriter::Actor(task.actor_ref)
        })
}

/// Claims the planned send `id` while it is still ready; a send another
/// claim took since the plan, or one settled since, comes back empty.
fn claim_planned(
    vault: &Vault,
    queue: &AttemptQueue<'_>,
    id: AttemptId,
    now: u64,
) -> Result<ClaimOutcome, Error> {
    vault.with_write_txn_grouped(|wtxn| {
        let ready = queue
            .get_in_write_txn(wtxn, id)?
            .as_ref()
            .and_then(admission_order)
            .is_some();
        if !ready {
            return Ok(ClaimOutcome::Empty);
        }
        queue.claim_id_in_txn(
            wtxn,
            id,
            ClaimAttempt {
                lease_owner: CONNECTOR_TASK_EXECUTOR_LEASE_OWNER.to_owned(),
                now,
            },
        )
    })
}
