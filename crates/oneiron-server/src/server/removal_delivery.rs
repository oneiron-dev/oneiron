//! The host's side of removal-archive delivery (FIX 3215, 3396): the wakes
//! that end a removed holder's held delivery session, and the reconciliation
//! at the host's start. An execute or re-execute of an export-first removal
//! wakes the sessions its recipient holds, so a device holding one asks again
//! at once, with a fresh proof, and is sent the archive. Nothing here holds
//! an archive byte or a slip: a wake says only that the person's archives may
//! have moved. A person with no session held is woken by nobody; its device's
//! next session finds what is owed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use oneiron::EntityId;
use oneiron::task_verb::sdk::{ActAnswer, SharedActExecuted};
use tokio::sync::Notify;

/// The wakes of every held delivery session on this host.
pub(crate) struct RemovalDeliveries {
    wakes: Mutex<Wakes>,
    woken: Notify,
}

#[derive(Default)]
struct Wakes {
    /// The latest wake's number, counted from the host's start.
    latest: u64,
    /// Each woken person's latest wake.
    by_person: HashMap<EntityId, u64>,
}

impl RemovalDeliveries {
    /// The registry, and the reconciliation at the host's start, run on its
    /// runtime's blocking pool when it has one (FIX 3396): it drops ledger
    /// rows whose archive is gone and logs how many deliveries still wait
    /// for their holder's ack. Each goes again at its holder's next session.
    pub(crate) fn start(vault: &Arc<oneiron::Vault>) -> Self {
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let vault = Arc::clone(vault);
            runtime.spawn_blocking(move || match vault.reconcile_removal_deliveries() {
                Ok(0) => {}
                Ok(owed) => tracing::info!(
                    owed,
                    "removal archive deliveries wait for their holders' acknowledgement"
                ),
                Err(error) => tracing::warn!(%error, "removal archive delivery reconciliation"),
            });
        }
        Self {
            wakes: Mutex::default(),
            woken: Notify::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Wakes> {
        self.wakes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The latest wake's number: a session takes it before it reads what is
    /// owed, so a wake while it reads is never missed.
    pub(crate) fn mark(&self) -> u64 {
        self.lock().latest
    }

    /// Wakes every session `person` holds.
    pub(crate) fn wake(&self, person: EntityId) {
        let mut wakes = self.lock();
        wakes.latest += 1;
        let latest = wakes.latest;
        wakes.by_person.insert(person, latest);
        drop(wakes);
        self.woken.notify_waiters();
    }

    /// One wake for what `vault.shared.execute` ran: the recipient of the
    /// archive an export-first removal, or its re-run, delivered.
    pub(crate) fn wake_after<E>(&self, ran: &Result<ActAnswer<SharedActExecuted>, E>) {
        if let Ok(ActAnswer::Done(SharedActExecuted {
            delivery: Some(delivery),
            ..
        })) = ran
            && let Ok(person) = EntityId::from_hex(&delivery.recipient)
        {
            self.wake(person);
        }
    }

    /// Holds `person`'s session until a wake for them after `since`, or
    /// until `hold` passes: `true` when woken.
    pub(crate) async fn hold(&self, person: EntityId, since: u64, hold: Duration) -> bool {
        let until = tokio::time::Instant::now() + hold;
        loop {
            // Made before the check, so a wake between the two still counts.
            let woken = self.woken.notified();
            if self
                .lock()
                .by_person
                .get(&person)
                .is_some_and(|wake| *wake > since)
            {
                return true;
            }
            if tokio::time::timeout_at(until, woken).await.is_err() {
                return false;
            }
        }
    }
}
