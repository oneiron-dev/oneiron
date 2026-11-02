//! The runtime's own witness of what a leased attempt is doing in this vault
//! now (OF-568 L5): whether a tool call or a model call of it is open, and
//! when it last streamed an output frame or finished a tool call. Agent
//! health reads it before it calls an attempt silent.
//!
//! Each entry is keyed by the exact lease a run was bound to (the attempt,
//! its lease generation and its lease owner) and lasts while a run holds a
//! binding on it. In memory only: no table, no restore row, nothing outlives
//! the vault handle, and a restart drops it. Its absence is not evidence of
//! anything.
//!
//! Every stamp is the vault's clock in real Unix seconds, never a run's
//! frozen bridge clock. Nothing here fails a run: a poisoned registry is
//! recovered with one warning, and no lock is held past one counter update
//! or one snapshot's read.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use super::{ExecutorStorage, HostSelfDispatcher};
use crate::attempt_queue::AttemptId;
use crate::ports::StoreClock;

/// One leased try, exactly as its sealed lease names it: the attempt, its
/// lease generation and its lease owner.
type ActivityKey = (AttemptId, u32, String);

/// One lease's entry: the runs bound to it now, and what they witnessed.
#[derive(Debug, Default)]
struct Entry {
    bindings: u32,
    seen: AttemptActivity,
}

type Live = HashMap<ActivityKey, Entry>;

/// What this vault's runtime witnessed of one leased try while a run of it
/// was bound here (OF-568 L5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AttemptActivity {
    /// Its last accepted non-empty output frame, in Unix seconds.
    pub(crate) last_stream_at: Option<u64>,
    /// Its last finished tool call, whatever came of it, in Unix seconds.
    pub(crate) last_call_finished_at: Option<u64>,
    /// Its tool calls open now, each nested one counted on its own.
    pub(crate) running_tools: u32,
    /// Its model calls open now.
    pub(crate) generating: u32,
}

impl AttemptActivity {
    /// Whether a tool call or a model call of it is open now.
    pub(crate) const fn running(self) -> bool {
        self.running_tools > 0 || self.generating > 0
    }

    /// Two entries of one try (two owners at one generation) as one.
    fn merge(self, other: Self) -> Self {
        Self {
            last_stream_at: self.last_stream_at.max(other.last_stream_at),
            last_call_finished_at: self.last_call_finished_at.max(other.last_call_finished_at),
            running_tools: self.running_tools.saturating_add(other.running_tools),
            generating: self.generating.saturating_add(other.generating),
        }
    }
}

/// This vault's attempt activity witness: one entry per lease a run is
/// bound to now.
#[derive(Debug, Default)]
pub(crate) struct AttemptActivityRuntime {
    live: Arc<Mutex<Live>>,
}

impl AttemptActivityRuntime {
    /// Binds a run to `key`'s entry, making it when it is the first, with
    /// `clock` as its stamps' clock. `None` when the entry did not take it.
    fn register(&self, clock: &StoreClock, key: ActivityKey) -> Option<AttemptActivityBinding> {
        let witness = Arc::new(Witness {
            live: Arc::clone(&self.live),
            key,
            clock: clock.clone(),
        });
        // Built only once the entry took it: its drop closes a binding.
        if !witness.bind() {
            return None;
        }
        Some(AttemptActivityBinding { witness })
    }

    /// What the runtime witnesses now of `attempt` at lease `generation`.
    /// `None` when no run of it is bound here. It waits for a writer holding
    /// the registry (FIX 8522): every hold is one short update, and a busy
    /// registry read as none would let a busy attempt read as quiet.
    pub(crate) fn snapshot(&self, attempt: AttemptId, generation: u32) -> Option<AttemptActivity> {
        lock_live(&self.live)
            .iter()
            .filter(|((held, at, _), _)| *held == attempt && *at == generation)
            .map(|(_, entry)| entry.seen)
            .reduce(AttemptActivity::merge)
    }
}

/// One lease's place in the registry, shared by a binding and its scopes.
#[derive(Debug)]
struct Witness {
    live: Arc<Mutex<Live>>,
    key: ActivityKey,
    clock: StoreClock,
}

impl Witness {
    fn lock(&self) -> MutexGuard<'_, Live> {
        lock_live(&self.live)
    }

    /// The vault's clock now, in Unix seconds, without moving its floor.
    fn now(&self) -> u64 {
        self.clock.peek_recorded_at()
    }

    /// Opens one binding on the entry, making it when it is the first.
    fn bind(&self) -> bool {
        let mut live = self.lock();
        let entry = live.entry(self.key.clone()).or_default();
        entry.bindings = entry.bindings.saturating_add(1);
        true
    }

    /// Closes one binding; the entry ends with its last.
    fn unbind(&self) {
        let mut live = self.lock();
        let ended = live.get_mut(&self.key).is_some_and(|entry| {
            entry.bindings = entry.bindings.saturating_sub(1);
            entry.bindings == 0
        });
        if ended {
            live.remove(&self.key);
        }
    }

    /// Applies `change` to the entry while one is bound; whether it did.
    fn touch(&self, change: impl FnOnce(&mut AttemptActivity)) -> bool {
        let mut live = self.lock();
        let Some(entry) = live.get_mut(&self.key) else {
            return false;
        };
        change(&mut entry.seen);
        true
    }
}

/// What a scope holds open: a tool call or a model call.
#[derive(Debug, Clone, Copy)]
enum Scope {
    Tool,
    Generation,
}

/// One run's binding on its lease's entry (OF-568 L5), held as long as the
/// run's dispatcher. The entry ends when its last binding drops.
#[derive(Debug)]
pub(crate) struct AttemptActivityBinding {
    witness: Arc<Witness>,
}

impl AttemptActivityBinding {
    /// Opens a scope of `scope`'s kind; `None` when the registry did not
    /// take it.
    fn open(&self, scope: Scope) -> Option<ActivityGuard> {
        let opened = self.witness.touch(|seen| match scope {
            Scope::Tool => seen.running_tools = seen.running_tools.saturating_add(1),
            Scope::Generation => seen.generating = seen.generating.saturating_add(1),
        });
        opened.then(|| ActivityGuard {
            witness: Arc::clone(&self.witness),
            scope,
        })
    }

    /// Stamps a streamed output frame now.
    fn streamed(&self) {
        let now = self.witness.now();
        self.witness
            .touch(|seen| seen.last_stream_at = seen.last_stream_at.max(Some(now)));
    }
}

impl Drop for AttemptActivityBinding {
    fn drop(&mut self) {
        self.witness.unbind();
    }
}

/// One open tool call or model call of a bound lease. Dropping it closes
/// only its own scope, on every path out of the call, unwinding included; a
/// tool scope stamps its call finished as it closes.
#[derive(Debug)]
pub(crate) struct ActivityGuard {
    witness: Arc<Witness>,
    scope: Scope,
}

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        let scope = self.scope;
        let finished = matches!(scope, Scope::Tool).then(|| self.witness.now());
        self.witness.touch(|seen| match scope {
            Scope::Tool => {
                seen.running_tools = seen.running_tools.saturating_sub(1);
                seen.last_call_finished_at = seen.last_call_finished_at.max(finished);
            }
            Scope::Generation => seen.generating = seen.generating.saturating_sub(1),
        });
    }
}

// A binding and a scope cross awaits, so both stay `Send`; neither holds a
// lock guard, only the shared map it locks for one update at a time.
const _: () = {
    const fn send<T: Send>() {}
    send::<ActivityGuard>();
    send::<AttemptActivityBinding>();
};

impl HostSelfDispatcher<'_> {
    /// Binds this run to its vault's witness under the lease it was just
    /// bound to (OF-568 L5), for as long as the dispatcher lives. A run with
    /// no lease or no canonical vault, or one the registry did not take,
    /// stays unwitnessed: nothing here fails it.
    pub(super) fn witness_attempt_activity(&mut self) {
        let (ExecutorStorage::Canonical(vault), Some(lease)) = (&self.storage, &self.agent_lease)
        else {
            return;
        };
        let key = (lease.attempt, lease.generation, lease.owner.clone());
        self.activity = vault.attempt_activity.register(&vault.store.clock, key);
    }

    /// Holds one call of this run open as a running tool until the guard
    /// drops; `None` for an unwitnessed run.
    pub(crate) fn activity_tool(&self) -> Option<ActivityGuard> {
        self.activity.as_ref()?.open(Scope::Tool)
    }

    /// Holds one model call of this run open until the guard drops; `None`
    /// for an unwitnessed run.
    pub(crate) fn activity_generating(&self) -> Option<ActivityGuard> {
        self.activity.as_ref()?.open(Scope::Generation)
    }

    /// Stamps an output frame the run's host accepted, when it holds bytes.
    pub(crate) fn activity_streamed(&self, frame: &[u8]) {
        if let Some(activity) = self.activity.as_ref().filter(|_| !frame.is_empty()) {
            activity.streamed();
        }
    }
}

/// The registry, waited for. A poisoned one is recovered (FIX 8523): its
/// entries are counters and stamps, each written whole, so a panic inside one
/// update loses at most that update. It warns once, clears the poison and
/// goes on witnessing, so later writes neither warn nor drop.
fn lock_live(live: &Mutex<Live>) -> MutexGuard<'_, Live> {
    live.lock().unwrap_or_else(|poisoned| {
        tracing::warn!("attempt activity witness recovered from a poisoned lock");
        live.clear_poison();
        poisoned.into_inner()
    })
}
