//! One turn-wake worker per vault (FIX 14873). Each landed turn used to
//! start its own blocking wake task, so a burst of witnesses ran as many
//! sieve and turn-wake reads at once, each going stale under the others'
//! commits and reading again in its writer. Now a landed turn joins its
//! vault's pending round: the worker runs rounds one after another, and a
//! round takes every turn that landed before it started. Every distinct
//! cadence subject still wakes (the vault's grain once, each agent on its
//! own dial with its turns' signals together), the turn wake reads every
//! unread turn's ordinal in its window as before, and the sieve reads up
//! to one bounded pass per landed turn, as each turn's own wake read one,
//! stopping once it has read everything. A caller that waits for its wake
//! is answered when the round that took its turn ends.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oneiron::dreamer_wake::{AgentWakeSignals, WakeTurnSubject};
use oneiron::{EntityId, Vault};
use tokio::sync::oneshot;

/// The landed turns no round has taken yet, per vault.
#[derive(Default)]
pub(super) struct TurnWakes {
    /// Keyed by the vault's address: an entry lives only while its worker
    /// runs, and that worker holds the vault.
    pending: Mutex<HashMap<usize, Pending>>,
}

/// One vault's turns waiting for the next round.
#[derive(Default)]
struct Pending {
    /// A turn landed on the vault's grain.
    vault: bool,
    /// Each agent a turn landed for, its turns' signals together.
    agents: Vec<(EntityId, AgentWakeSignals)>,
    /// How many turns landed.
    landed: usize,
    /// The callers waiting for this round to end.
    waiters: Vec<oneshot::Sender<()>>,
}

/// What one round takes: the turns pending when it started.
pub(super) struct TurnWakeRound {
    pub(super) subjects: Vec<WakeTurnSubject>,
    /// One bounded sieve pass per landed turn at most.
    pub(super) sieve_passes: usize,
    waiters: Vec<oneshot::Sender<()>>,
}

impl TurnWakeRound {
    /// Answers every caller waiting for this round.
    pub(super) fn finish(self) {
        for waiter in self.waiters {
            let _ = waiter.send(());
        }
    }
}

fn key(vault: &Arc<Vault>) -> usize {
    Arc::as_ptr(vault).addr()
}

impl TurnWakes {
    /// Adds `subject`'s landed turn to `vault`'s next round. True when no
    /// worker runs for the vault: the caller starts one.
    pub(super) fn offer(
        &self,
        vault: &Arc<Vault>,
        subject: WakeTurnSubject,
        waiter: Option<oneshot::Sender<()>>,
    ) -> bool {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let start = !pending.contains_key(&key(vault));
        let entry = pending.entry(key(vault)).or_default();
        match subject {
            WakeTurnSubject::Vault => entry.vault = true,
            WakeTurnSubject::Agent { id, signals } => {
                match entry.agents.iter_mut().find(|(agent, _)| *agent == id) {
                    Some((_, held)) => *held = either(*held, signals),
                    None => entry.agents.push((id, signals)),
                }
            }
        }
        entry.landed = entry.landed.saturating_add(1);
        entry.waiters.extend(waiter);
        start
    }

    /// The next round for `vault`: every turn pending now. `None` when none
    /// is, and the worker stops; a turn that lands after starts the next.
    pub(super) fn take(&self, vault: &Arc<Vault>) -> Option<TurnWakeRound> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = pending.get_mut(&key(vault))?;
        if entry.landed == 0 {
            pending.remove(&key(vault));
            return None;
        }
        let taken = std::mem::take(entry);
        let subjects = taken
            .vault
            .then_some(WakeTurnSubject::Vault)
            .into_iter()
            .chain(
                taken
                    .agents
                    .into_iter()
                    .map(|(id, signals)| WakeTurnSubject::Agent { id, signals }),
            )
            .collect();
        Some(TurnWakeRound {
            subjects,
            sieve_passes: taken.landed,
            waiters: taken.waiters,
        })
    }
}

/// The signals of two landed turns for one agent: each signal any of them
/// carried.
fn either(held: AgentWakeSignals, landed: AgentWakeSignals) -> AgentWakeSignals {
    let AgentWakeSignals {
        surprise,
        agency,
        event,
    } = landed;
    AgentWakeSignals {
        surprise: held.surprise || surprise,
        agency: held.agency || agency,
        event: held.event || event,
    }
}
