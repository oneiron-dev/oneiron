//! The wake observation's seams in the pass (DOOR-144): its header and end,
//! the attempt generations it admits, and the ended passes' Checkpoint parks
//! its root resumes before it prepares. None of them fails or holds the pass.

use super::*;
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::dreamer_wake::observation;

impl DreamerWakeDriver<'_> {
    /// Opens this pass's observation once its hooks allowed it, before any
    /// work. Its deadline carries the wake to every worker's clone.
    pub(super) fn start_wake_observation(&mut self, input: &RunWakePass) {
        let wake =
            observation::start_wake_observation(self.vault, &self.deadline, input, &self.budget_id);
        self.deadline.bind_wake(wake);
    }

    /// Closes it once every worker settled, errors included, and drops the
    /// pass's live hold. A pass that parked wakes the deadline lane, which
    /// arms the Checkpoint parks of a pass that ended.
    pub(super) fn finish_wake_observation(
        &mut self,
        report: std::result::Result<&WakePassReport, &crate::Error>,
    ) {
        let stop = report.ok().map(|report| report.stop);
        let fallback = report
            .ok()
            .and_then(|report| report.claim_authoring_fallback.clone());
        observation::finish_wake_observation(self.vault, &self.deadline, stop, fallback);
        self.deadline.bind_wake(None);
        if report.is_ok_and(|report| report.parked > 0) {
            self.vault.store.notify_proactivity_changes();
        }
    }

    /// Records the generation queue admission just leased, before dispatch.
    pub(super) fn observe_admitted(&self, admitted: &DreamerAdmittedAttempt) {
        if let Some(wake) = self.deadline.wake_ref() {
            observation::observe_attempt(
                self.vault,
                wake,
                &admitted.status.attempt,
                self.deadline.elapsed_ms(),
            );
        }
    }

    /// Resumes the Checkpoint parks ended passes cut, as the same tries.
    pub(super) fn resume_checkpoints(&self, input: &RunWakePass) {
        if let Some(wake) = self.deadline.wake_ref() {
            let later = observation::LaterWake {
                wake,
                local_node_id: input.local_node_id,
                worker: &input.lease_owner,
                now: input.now,
            };
            observation::resume_checkpoints_for_wake(self.vault, &later);
        }
    }

    /// The pass past its hooks: begin, freeze its preparation, run it.
    pub(super) async fn run_begun_wake_pass<E: DreamerAttemptExecutor + ?Sized>(
        &mut self,
        input: RunWakePass,
        exec: &mut E,
        cancel: &WakeCancellation,
    ) -> Result<WakePassReport> {
        self.begin_wake(&input)?;
        let prepared = crate::dreamer_consolidation::PreparedWake::capture_for_pass(
            self.vault,
            input.scope,
            input.host_scope.as_ref(),
            &self.deadline,
            cancel,
        )?;
        self.run_prepared_wake_pass(input, exec, cancel, &prepared)
            .await
    }
}
