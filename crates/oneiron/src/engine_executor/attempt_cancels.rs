//! The step loops leased attempts are running in this vault (FIX 600), each
//! under its attempt's root token, so a hard queue control that already
//! committed stops the step that is running: a force cancel, or a lease the
//! attempt lost to a redirect or to its landing's expiry. In memory only:
//! no table, and nothing outlives the vault handle.
//!
//! The signal follows the commit and never authorizes anything; the queue
//! already terminalized or fenced the attempt. Soft controls (a cancel
//! request on a leased attempt, a run-tree cancel) do not reach it.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::cancel::StepCancellation;
use super::driver::EngineNativeExecutor;
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::code_run::ExecutorStorage;

/// One registered loop: the attempt, its lease generation and the
/// registration, so a guard removes only its own entry.
type RootKey = ([u8; 16], u32, u64);

#[derive(Debug, Default)]
struct Live {
    next_registration: u64,
    running: BTreeMap<RootKey, StepCancellation>,
}

/// This vault's running attempt step loops.
#[derive(Debug, Default)]
pub(crate) struct AttemptCancels {
    live: Mutex<Live>,
}

impl AttemptCancels {
    fn lock(&self) -> MutexGuard<'_, Live> {
        // The map is whole after any step of it, so a poisoned lock still
        // holds a usable one.
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers a step loop of `attempt` under lease `generation`, with a
    /// root token of its own.
    pub(crate) fn register(&self, attempt: AttemptId, generation: u32) -> AttemptRoot<'_> {
        let root = StepCancellation::new();
        let mut live = self.lock();
        let registration = live.next_registration;
        live.next_registration = registration.wrapping_add(1);
        let key = (*attempt.as_bytes(), generation, registration);
        live.running.insert(key, root.clone());
        AttemptRoot {
            registered: Some((self, key)),
            root,
        }
    }

    /// Cancels the root of every loop `attempt` runs under lease
    /// `generation`, and answers how many it signalled. It returns once they
    /// are signalled, not once their steps have stopped.
    pub(crate) fn cancel(&self, attempt: AttemptId, generation: u32) -> usize {
        let live = self.lock();
        let mut signalled = 0;
        for ((id, held, _), root) in &live.running {
            if id == attempt.as_bytes() && *held == generation {
                root.cancel();
                signalled += 1;
            }
        }
        signalled
    }
}

/// A step loop's root token. A registered one leaves the vault's map when
/// dropped, however the loop ended.
pub(crate) struct AttemptRoot<'v> {
    registered: Option<(&'v AttemptCancels, RootKey)>,
    root: StepCancellation,
}

impl AttemptRoot<'_> {
    /// The root of a loop no attempt lease binds: nothing cancels it.
    pub(crate) const fn unbound() -> Self {
        Self {
            registered: None,
            root: StepCancellation::never(),
        }
    }

    /// The loop's root: every step it runs, and every skill those steps
    /// call, descends from it.
    pub(crate) fn token(&self) -> &StepCancellation {
        &self.root
    }
}

impl Drop for AttemptRoot<'_> {
    fn drop(&mut self) {
        if let Some((cancels, key)) = &self.registered {
            cancels.lock().running.remove(key);
        }
    }
}

/// Stops the step a loop of `attempt` under lease `generation` is running,
/// after a hard queue control committed (FIX 600). A store-only queue handle
/// holds no vault and signals nothing.
pub(crate) fn stop_attempt_step(vault: Option<&Vault>, attempt: AttemptId, generation: u32) {
    if let Some(vault) = vault {
        vault.attempt_cancels.cancel(attempt, generation);
    }
}

impl<'a> EngineNativeExecutor<'a> {
    /// The root of this run's step loop: registered under the leased attempt
    /// and lease generation the run serves, so a hard queue control that
    /// committed for them stops its running step; a root nothing cancels for
    /// a run no attempt lease binds.
    pub(super) fn attempt_root(&self) -> AttemptRoot<'a> {
        match (&self.storage, self.gated_write.replay_capture()) {
            (ExecutorStorage::Canonical(vault), Some((attempt, generation, _))) => {
                let vault: &'a Vault = *vault;
                vault.attempt_cancels.register(attempt, generation)
            }
            _ => AttemptRoot::unbound(),
        }
    }
}
