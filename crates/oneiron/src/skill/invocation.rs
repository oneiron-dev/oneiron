//! The callable skill invocations running in this vault (FIX 600), each
//! with the token that stops it, so an owner's suspension reaches the ones
//! already running. In memory only: no table, and nothing outlives the
//! vault handle.
//!
//! An invocation registers before its final load, so a suspension either
//! finds it or committed before that load, which then refuses the skill. It
//! stays registered through its return checks, and it leaves the set as it
//! finishes, under the same lock a suspension signals under: a cancel that
//! landed first fails it, and one that comes after it left reaches nothing.
//! No lock is held while a guest or a host callback runs.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::engine_executor::StepCancellation;
use crate::entity_id::EntityId;
use crate::error::Result;

/// One live invocation: the skill asked for, the run whose bridge call ran
/// it and that call's position, and the registration it belongs to, so a
/// guard removes only its own entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct InvocationKey {
    skill: EntityId,
    run_id: EntityId,
    seq: u64,
    registration: u64,
}

#[derive(Debug, Default)]
struct Live {
    next_registration: u64,
    running: BTreeMap<InvocationKey, StepCancellation>,
}

/// This vault's live callable skill invocations.
#[derive(Debug, Default)]
pub(crate) struct SkillInvocations {
    live: Mutex<Live>,
}

impl SkillInvocations {
    fn lock(&self) -> MutexGuard<'_, Live> {
        // The set is whole after any step of it, so a poisoned lock still
        // holds a usable one.
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers one invocation of `skill`, called by `run_id` at bridge
    /// position `seq`, under a child of `parent`, the caller's step token.
    pub(crate) fn register(
        &self,
        skill: EntityId,
        run_id: EntityId,
        seq: u64,
        parent: &StepCancellation,
    ) -> InvocationGuard<'_> {
        let cancel = parent.child();
        let mut live = self.lock();
        let registration = live.next_registration;
        live.next_registration = registration.wrapping_add(1);
        let key = InvocationKey {
            skill,
            run_id,
            seq,
            registration,
        };
        live.running.insert(key, cancel.clone());
        InvocationGuard {
            invocations: self,
            key,
            cancel,
        }
    }

    /// Cancels every live invocation of `skill` in this vault, across runs,
    /// attempts and versions, and answers how many it signalled. It returns
    /// once they are signalled, not once their guests have stopped.
    pub(crate) fn cancel_skill(&self, skill: &EntityId) -> usize {
        let live = self.lock();
        let mut signalled = 0;
        for (key, cancel) in &live.running {
            if key.skill == *skill {
                cancel.cancel();
                signalled += 1;
            }
        }
        signalled
    }
}

/// One registered invocation. Dropping it removes its entry, whatever the
/// invocation ended with.
pub(crate) struct InvocationGuard<'v> {
    invocations: &'v SkillInvocations,
    key: InvocationKey,
    cancel: StepCancellation,
}

impl InvocationGuard<'_> {
    /// The invocation's own token: a child of its caller's.
    pub(crate) fn token(&self) -> &StepCancellation {
        &self.cancel
    }

    /// Leaves the live set as the invocation finishes, so it may be
    /// credited as a success.
    ///
    /// # Errors
    ///
    /// [`crate::error::CodeError::CodeStepCancelled`] when a cancel landed
    /// first; the entry is removed all the same.
    pub(crate) fn finish(self) -> Result<()> {
        let mut live = self.invocations.lock();
        live.running.remove(&self.key);
        self.cancel.check()
    }
}

impl Drop for InvocationGuard<'_> {
    fn drop(&mut self) {
        self.invocations.lock().running.remove(&self.key);
    }
}
