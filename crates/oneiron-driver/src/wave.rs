//! Host-side consumption of a queued planning attempt and live TASK dispatch.
//!
//! The planner is injected by the agent host. This module supplies no plan DSL,
//! polling timer, or authority of its own: the queue leases the attempt, and
//! the vault validates/lands its cut under that lease.

use oneiron::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};
use oneiron::wave_orchestration::{
    VaultWaveTaskPort, WAVE_PLAN_ATTEMPT_KIND, WaveApplyOutcome, WaveOrchestrator, WavePlanRequest,
    WavePlanner,
};
use oneiron::{EdgeActorClass, EntityId, LinearSyncError, Vault, WaveResult};

use crate::supervisor::PassExecutorFactory;

/// A host-owned agent-side planner, over the production vault and queue ports.
pub struct WaveHost<'v, P> {
    vault: &'v Vault,
    planner: P,
    actor: EntityId,
    actor_class: EdgeActorClass,
}

impl<'v, P: WavePlanner> WaveHost<'v, P> {
    /// Bind an agent-side planner to an authenticated actor. The host supplies
    /// its own lease owner for each pass, not an identity from the queued body.
    pub const fn new(
        vault: &'v Vault,
        planner: P,
        actor: EntityId,
        actor_class: EdgeActorClass,
    ) -> Self {
        Self {
            vault,
            planner,
            actor,
            actor_class,
        }
    }

    /// Claim and execute one `wave.plan` attempt, or return `None` when idle.
    /// The cut goes through the vault's fan-out approval door with
    /// `factory`'s host decision loan (FIX 8599), so the owner's MANUAL/AUTO
    /// launch choice rules it: an `Applied` cut has landed its TASKs, and a
    /// `Paused` one is frozen whole with its planning attempt parked, each
    /// durably in the door's own transaction before this returns. Only an
    /// applied cut has anything to dispatch; a held one stays owed until the
    /// owner's ruling launches it on the existing resume path. An error
    /// leaves the lease for the ordinary retry/cleanup path; in particular,
    /// a failed apply never marks the attempt completed.
    pub fn run_plan_once<F: PassExecutorFactory>(
        &self,
        factory: &F,
        lease_owner: &str,
        now: u64,
    ) -> WaveResult<Option<WaveApplyOutcome>> {
        let queue = AttemptQueue::new(self.vault);
        let ClaimOutcome::Claimed(attempt) = queue.claim_kind(
            WAVE_PLAN_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: lease_owner.to_owned(),
                now,
            },
        )?
        else {
            return Ok(None);
        };
        let payload: serde_json::Value =
            serde_json::from_slice(&attempt.payload).map_err(|_| invalid_plan_request())?;
        let epic = payload
            .get("epic")
            .and_then(serde_json::Value::as_str)
            .and_then(|raw| EntityId::from_hex(raw).ok())
            .ok_or_else(invalid_plan_request)?;
        let objective = payload
            .get("objective")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid_plan_request)?;
        let constraints = payload
            .get("constraints")
            .cloned()
            .ok_or_else(invalid_plan_request)?;
        let plan = self.planner.cut_plan(WavePlanRequest {
            epic_task_ref: epic,
            planner_attempt_ref: attempt.id,
            objective: objective.to_owned(),
            constraints,
            now,
        })?;
        // The host's ruling runs on its own clock, from here: the planner's
        // cut above never spends it.
        let outcome = factory.wave_fanout_decisions(self.actor, |decisions| {
            self.vault.apply_wave_plan_attempt_gated(
                self.actor,
                self.actor_class,
                &attempt,
                plan,
                decisions,
                now,
            )
        })?;
        Ok(Some(outcome))
    }

    /// Read the current ready subset immediately before a host dispatches
    /// those TASKs. The atomic attempt-claim door repeats this dependency
    /// check, so a blocker changing after this preview cannot bypass it.
    pub fn ready_to_dispatch(&self, candidates: &[EntityId]) -> WaveResult<Vec<EntityId>> {
        WaveOrchestrator::new(VaultWaveTaskPort::new(
            self.vault,
            self.actor,
            self.actor_class,
        ))
        .ready_set(candidates)
    }
}

fn invalid_plan_request() -> LinearSyncError {
    oneiron::Error::InvalidConfig("invalid queued wave plan request".to_owned()).into()
}

#[cfg(test)]
mod tests;
