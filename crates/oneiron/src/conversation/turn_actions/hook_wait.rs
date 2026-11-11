//! A turn action whose `host.turn.generate` hook asked first waits for the
//! answer (FIX 1765). Its attempt is held under the queue's hook pause and
//! keeps its id, and it is resumed once the ask no longer waits. The worker
//! then claims the same attempt again. Its hook call derives from the
//! attempt's id ([`turn_action_hook_parent`]), so the boundary finds the
//! saved call and its answer, and the boundary alone decides whether the
//! reply runs.

use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptResumePoint, AttemptState, HoldAttemptForHook,
};
use crate::runtime_hooks::InvocationId;
use crate::runtime_hooks::verb::VerbHookWaitStatus;
use crate::skill_hub::pack_catalog::HookActorClass;
use crate::{EntityId, Result, Vault};

use super::{TURN_ACTION_ATTEMPT_KIND, TurnActionAttempt};

/// The host verb whose pre chain a turn action's reply crosses.
const HOST_TURN_GENERATE: &str = "host.turn.generate";
/// A held action's resume point names the claim it was held at.
const HOOK_WAIT_MARKER: &str = "turn-action:host-hook:";
/// A held action's resume reference: the hook call that asked, then its ask.
const HOOK_ASK_REF: &str = "hook-ask:";

/// The invocation a turn action's host hook call derives from: one per
/// attempt, the same on every claim of it.
#[must_use]
pub fn turn_action_hook_parent(attempt: &AttemptRecord) -> InvocationId {
    InvocationId::of_run_step(attempt.id.as_bytes(), 0)
}

/// Whether `attempt`, claimed again, was resumed from its host hook's wait at
/// the claim just before this one, rather than cut off when a process stopped
/// under it.
#[must_use]
pub fn turn_action_resumed_from_hook(attempt: &AttemptRecord) -> bool {
    attempt.attempt_count > 1
        && attempt
            .cancel_state
            .resume_point
            .as_ref()
            .is_some_and(|point| point.marker == held_marker(attempt.attempt_count - 1))
}

impl Vault {
    /// Holds `leased`, a turn action claimed by `lease_owner`, on its host
    /// hook's open ask: `invocation` is the hook call that asked, `ask` its
    /// ask. The attempt stays unsettled and keeps its id; nothing fails.
    pub fn hold_turn_action_for_hook(
        &self,
        leased: &AttemptRecord,
        lease_owner: &str,
        invocation: InvocationId,
        ask: EntityId,
        now: u64,
    ) -> Result<()> {
        let mut resume_point = AttemptResumePoint::new(held_marker(leased.attempt_count), now);
        resume_point.artifact_ref = Some(format!(
            "{HOOK_ASK_REF}{}:{}",
            invocation.to_hex(),
            ask.to_hex()
        ));
        let mut txn = self.store.env.write_txn()?;
        AttemptQueue::new(self).hold_for_hook_in_txn(
            &mut txn,
            HoldAttemptForHook {
                id: leased.id,
                lease_owner: lease_owner.to_owned(),
                attempt_count: leased.attempt_count,
                invocation: invocation.0,
                resume_point,
                now,
            },
        )?;
        txn.commit()?;
        self.store.notify_attempt_observers();
        Ok(())
    }

    /// Every turn action held on its host hook now, for a worker starting
    /// after a stop. Each waits until [`Self::resume_turn_action_hook`]
    /// resumes it.
    pub fn held_turn_action_hooks(&self) -> Result<Vec<AttemptId>> {
        Ok(AttemptQueue::new(self)
            .list_kind_bounded(TURN_ACTION_ATTEMPT_KIND, usize::MAX)?
            .into_iter()
            .filter(|attempt| held_wait(attempt).is_some())
            .map(|attempt| attempt.id)
            .collect())
    }

    /// Resumes held turn action `id` once its host hook's ask no longer
    /// waits (answered, declined, expired, or its saved call gone) and hooks
    /// run ([`Self::verb_hooks_running`]): with hooks off the boundary keeps
    /// an answered call parked, so the action waits for them rather than
    /// holding again on every pass. The worker's next claim crosses the hook
    /// boundary again, which alone decides. Whether it still waits.
    pub fn resume_turn_action_hook(&self, id: AttemptId, now: u64) -> Result<bool> {
        let queue = AttemptQueue::new(self);
        let Some(held) = queue.get(id)? else {
            return Ok(false);
        };
        let Some((invocation, ask)) = held_wait(&held) else {
            return Ok(false);
        };
        let (actor, _) = TurnActionAttempt::decode(&held)?.requester()?;
        let status = self.verb_hook_wait_status(
            invocation,
            HOST_TURN_GENERATE,
            actor,
            HookActorClass::System,
            ask,
        )?;
        if status == VerbHookWaitStatus::Waiting || !self.verb_hooks_running()? {
            return Ok(true);
        }
        let mut txn = self.store.env.write_txn()?;
        if queue.resume_hook_in_txn(&mut txn, id, invocation.0, held.attempt_count, now)? {
            txn.commit()?;
            self.store.notify_attempt_observers();
        }
        Ok(false)
    }
}

fn held_marker(claim: u32) -> String {
    format!("{HOOK_WAIT_MARKER}{claim}")
}

/// The hook call and ask `attempt` waits on, while it is held on them.
fn held_wait(attempt: &AttemptRecord) -> Option<(InvocationId, EntityId)> {
    if attempt.kind != TURN_ACTION_ATTEMPT_KIND || attempt.state != AttemptState::Paused {
        return None;
    }
    let point = attempt.cancel_state.resume_point.as_ref()?;
    if point.marker != held_marker(attempt.attempt_count) {
        return None;
    }
    let (invocation, ask) = point
        .artifact_ref
        .as_deref()?
        .strip_prefix(HOOK_ASK_REF)?
        .split_once(':')?;
    let invocation = InvocationId::parse_hex(invocation)?;
    let ask = EntityId::from_hex(ask).ok()?;
    attempt
        .hook_wait_for(invocation.0)
        .then_some((invocation, ask))
}
