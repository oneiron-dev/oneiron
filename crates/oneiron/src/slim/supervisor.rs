//! The supervisor's view of SLIM (FIX 5186): a content-free observation of
//! the live outbound wait a shed would park on, and a shed guarded by that
//! observation.
//!
//! Journal selection stays the eligibility authority. The live waits add
//! only how long the selected step has waited, on a monotonic clock, and an
//! opaque process-local id that names that one wait. The status read takes
//! the same transition lock and runs the same selection and admission as a
//! shed, and changes nothing. The guarded shed runs the same fixed-order
//! drop transaction as every other shed. Neither holds a policy number.

use super::{ShedAdmission, ShedCause, ShedOutcome, SlimState, VaultResidency};
use crate::Vault;
use crate::error::Result;

/// The one live outbound wait a shed would admit right now: an opaque,
/// process-local id and how long it has waited, in whole seconds. No
/// payload, prompt, credential or step identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EligibleWait {
    pub wait_id: u64,
    pub waited_secs: u64,
}

/// One atomic observation of residency and the eligible live wait.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SupervisorSlimStatus {
    pub residency: VaultResidency,
    /// `None` only when the journal read and no live wait is eligible.
    pub eligible_wait: Option<EligibleWait>,
}

/// What a shed guarded by a wait observation did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SupervisorShedOutcome {
    /// The shed transaction's own outcome, as an unguarded shed reports it.
    Shed(ShedOutcome),
    /// The admitted step has no live wait under the observed id: the wait
    /// ended or another took its place. Nothing was dropped.
    WaitObservationChanged,
}

impl Vault {
    /// Residency, and the live wait on the step a shed would admit now. A
    /// step that is selected but not live (a `Pending` effect between sends)
    /// has no eligible wait.
    ///
    /// Reads under the transition lock, with the selection and admission a
    /// shed runs. It changes no residency, drops nothing, writes no journal
    /// row and resumes nothing, so a status read never ends a SLIM episode.
    ///
    /// # Errors
    ///
    /// A journal that does not read is an error, never "no eligible wait".
    pub fn supervisor_slim_status(&self) -> Result<SupervisorSlimStatus> {
        let state = self.slim.lock_state();
        let residency = match &*state {
            SlimState::Full => VaultResidency::Full,
            SlimState::Slim(_) => VaultResidency::Slim,
        };
        let eligible_wait = match self.admit_shed(&state)? {
            ShedAdmission::Admitted { step, .. } => {
                self.slim.live_wait_on(&step).map(|wait| EligibleWait {
                    wait_id: wait.wait_id,
                    waited_secs: wait.started.elapsed().as_secs(),
                })
            }
            ShedAdmission::Decided(_) => None,
        };
        Ok(SupervisorSlimStatus {
            residency,
            eligible_wait,
        })
    }

    /// [`Self::shed_rebuildable_heap`] for a supervisor holding an
    /// [`EligibleWait`] observation. Under the same transition lock, after
    /// the same admission, the admitted step's one live wait must still carry
    /// `wait_id`; otherwise it refuses with
    /// [`SupervisorShedOutcome::WaitObservationChanged`] before any drop, so
    /// stale evidence never sheds a step that replaced the observed one. An
    /// admission that decides on its own (a canonical blocker, or a SLIM
    /// vault whose step completed) answers as it does unguarded.
    ///
    /// # Errors
    ///
    /// As [`Self::shed_rebuildable_heap`].
    pub fn shed_rebuildable_heap_for_wait(
        &self,
        cause: ShedCause,
        waited_secs: u64,
        now_ms: u64,
        wait_id: u64,
    ) -> Result<SupervisorShedOutcome> {
        super::require_positive_wait(waited_secs)?;

        let mut state = self.slim.lock_state();
        let (step, admitted_residue) = match self.admit_shed(&state)? {
            ShedAdmission::Decided(outcome) => return Ok(SupervisorShedOutcome::Shed(outcome)),
            ShedAdmission::Admitted {
                step,
                admitted_residue,
            } => (step, admitted_residue),
        };
        if self.slim.live_wait_on(&step).map(|wait| wait.wait_id) != Some(wait_id) {
            return Ok(SupervisorShedOutcome::WaitObservationChanged);
        }
        self.drop_rebuildable_heap(
            &mut state,
            step,
            admitted_residue,
            cause,
            waited_secs,
            now_ms,
        )
        .map(SupervisorShedOutcome::Shed)
    }
}
