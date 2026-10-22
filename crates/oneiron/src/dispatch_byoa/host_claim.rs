//! A run host's own claim of a CLI attempt (FIX 4552): a host that runs the
//! official CLIs on the person's own runtime reads the queued CLI-sandbox
//! attempts it can run, and claims one by id through the queue's existing
//! lease (the claim by id the agent run pump takes). A row another runner
//! already leased is no longer ready, so its lease stands and nothing runs
//! twice. A seat attempt that names another machine is left for that
//! machine's runner. This reads and claims only:
//! [`ByoaDispatcher::execute_cli`] and
//! [`ByoaDispatcher::capture_terminal_exhaust`] run and settle the claim
//! under the fence it returns.

use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
};
use crate::error::Error;

use super::connector::{BYOA_ATTEMPT_KIND, ByoaConnectorSpec, CliSandboxSpec};
use super::dispatcher::{ByoEndpointBackendFactory, ByoaDispatcher, ByoaExecutionFence};
use super::error::ByoaResult;
use super::exhaust::{ByoaEgressPort, decode_byoa_record};
use super::work_binding::{RunnerWorkBindingId, head_hop, seat_index};

impl<B, E> ByoaDispatcher<'_, B, E>
where
    B: ByoEndpointBackendFactory,
    E: ByoaEgressPort,
{
    /// The queued CLI-sandbox attempts ready by `now` that this host runs,
    /// oldest first: each one's connector `serves` admits, under a placement
    /// this runtime admits, and whose official seat names no machine or names
    /// one of `machines`, this host's machine labels: its machine id and any
    /// alias its operator declared (FIX 4552, FIX 9420). It reads only; the
    /// claim checks each row again against the same labels.
    ///
    /// # Errors
    /// The queue could not be read.
    pub fn ready_host_cli_attempts(
        &self,
        now: u64,
        machines: &[String],
        serves: impl Fn(&CliSandboxSpec) -> bool,
    ) -> ByoaResult<Vec<AttemptId>> {
        let rows = AttemptQueue::new(self.vault())
            .list_kind_bounded(BYOA_ATTEMPT_KIND, crate::receipt::MAX_RECEIPT_QUERY_SCAN)?;
        Ok(rows
            .into_iter()
            .filter(|row| self.host_runs(row, now, machines, &serves))
            .map(|row| row.id)
            .collect())
    }

    /// Claims attempt `id` for this host as `lease_owner`, by id, in one
    /// writer: the fence its run and its capture go under. `None` when the
    /// row is no longer a ready CLI attempt this host, on one of `machines`,
    /// runs, or another runner holds it.
    ///
    /// # Errors
    /// The queue could not be read or written.
    pub fn claim_host_cli_attempt(
        &self,
        id: AttemptId,
        lease_owner: &str,
        now: u64,
        machines: &[String],
        serves: impl Fn(&CliSandboxSpec) -> bool,
    ) -> ByoaResult<Option<ByoaExecutionFence>> {
        let vault = self.vault();
        let queue = AttemptQueue::new(vault);
        let mut txn = vault.store.env.write_txn().map_err(Error::from)?;
        let Some(row) = queue.get_in_write_txn(&txn, id)? else {
            return Ok(None);
        };
        if !self.host_runs(&row, now, machines, &serves) {
            return Ok(None);
        }
        let claim = ClaimAttempt {
            lease_owner: lease_owner.to_owned(),
            now,
        };
        let ClaimOutcome::Claimed(attempt) =
            crate::ports::JobQueue::port_job_claim_id(vault, &mut txn, id, claim)?
        else {
            return Ok(None);
        };
        txn.commit().map_err(Error::from)?;
        vault.store.notify_attempt_observers();
        Ok(Some(ByoaExecutionFence {
            attempt_id: attempt.id,
            lease_owner: lease_owner.to_owned(),
            attempt_count: attempt.attempt_count,
        }))
    }

    /// The seat a bound runner work's attempt `id` runs on (OF-137, FIX
    /// 9320): the seat its work's durable head hop names, when that hop is
    /// this attempt. `None` for an attempt that carries no bound work, or
    /// whose work's head has moved past it; the host then captures it as a
    /// plain attempt.
    ///
    /// # Errors
    /// The queue or the work's record could not be read or decoded.
    pub fn host_attempt_seat(&self, id: AttemptId) -> ByoaResult<Option<usize>> {
        let vault = self.vault();
        let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
        let Some(row) = AttemptQueue::new(vault).get_in_txn(&rtxn, id)? else {
            return Ok(None);
        };
        let Some(work) = decode_byoa_record(&row)?.work else {
            return Ok(None);
        };
        let binding = RunnerWorkBindingId::from_bytes(work.binding)?;
        Ok(head_hop(vault, &rtxn, binding)?
            .filter(|hop| hop.attempt == *id.as_bytes())
            .map(|hop| seat_index(hop.seat)))
    }

    /// Whether `row` is a ready CLI attempt this host, on one of `machines`,
    /// runs by `now`.
    fn host_runs(
        &self,
        row: &AttemptRecord,
        now: u64,
        machines: &[String],
        serves: &impl Fn(&CliSandboxSpec) -> bool,
    ) -> bool {
        matches!(row.state, AttemptState::Queued | AttemptState::Scheduled)
            && row
                .scheduled_at
                .or(row.backoff_until)
                .is_none_or(|at| at <= now)
            && decode_byoa_record(row).is_ok_and(|payload| {
                let ByoaConnectorSpec::CliSandbox(spec) = &payload.connector else {
                    return false;
                };
                serves(spec)
                    && payload
                        .official_seat
                        .is_none_or(|seat| seat.runs_on(machines))
                    && self.check_payload_placement(&payload).is_ok()
            })
    }
}
