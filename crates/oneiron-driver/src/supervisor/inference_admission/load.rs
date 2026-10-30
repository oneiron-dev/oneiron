//! Pre-launch grants and their class inheritance.

use super::*;

impl DeviceAdmission {
    /// Takes a transient load reservation before launch. A load inherits the
    /// highest class of its worker's waiters; warmup with no waiter is
    /// Background. `None` means another load goes first or room is unknown.
    #[must_use]
    pub fn acquire_load(
        self: &Arc<Self>,
        worker_id: &str,
        declared: &DeclaredEnvelope,
        class: ResourceClass,
    ) -> Option<LoadGrant> {
        let holder = load_holder(worker_id);
        let envelope = WorkEnvelope {
            kv_increment_mib: declared.weights_mib,
            workspace_mib: declared.load_transient_mib,
        };
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let wanted = wanted_load_class(&state, worker_id);
        let mut announce = false;
        let sequence = match state.load_waiters.get(worker_id) {
            Some(waiter) => {
                announce = waiter.class != wanted;
                waiter.sequence
            }
            None => {
                announce = true;
                let sequence = state.next_load;
                state.next_load = state.next_load.saturating_add(1);
                sequence
            }
        };
        state.load_waiters.insert(
            worker_id.to_owned(),
            LoadWaiter {
                class: wanted,
                sequence,
            },
        );
        if next_load(&state).as_deref() != Some(worker_id) {
            drop(state);
            if announce {
                self.changed.notify_waiters();
            }
            return None;
        }
        let outcome = self.ledger.try_reserve(&holder, &envelope, class);
        if outcome == TryReserveOutcome::NoRoom {
            drop(state);
            if announce {
                self.changed.notify_waiters();
            }
            return None;
        }
        state.load_waiters.remove(worker_id);
        drop(state);
        self.changed.notify_waiters();
        Some(LoadGrant {
            admission: Arc::clone(self),
            worker_id: worker_id.to_owned(),
            holder,
            released: false,
        })
    }

    /// Promotes a load to its steady row and frees the transient hold.
    pub fn loaded(&self, worker_id: &str, declared: DeclaredEnvelope, class: ResourceClass) {
        self.ledger
            .mark_loaded(worker_id, declared, class, &load_holder(worker_id));
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .load_waiters
            .remove(worker_id);
        self.changed.notify_waiters();
    }

    /// Drops a transient load grant and wakes the next waiting load.
    pub(super) fn release_load(&self, worker_id: &str, holder: &str) {
        self.ledger.release_hold(holder);
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .load_waiters
            .remove(worker_id);
        self.changed.notify_waiters();
    }
}

fn wanted_load_class(state: &AdmissionState, worker_id: &str) -> WorkClass {
    let now = Instant::now();
    if state.tickets.values().any(|ticket| {
        ticket.request.worker_id == worker_id
            && ticket.request.class == WorkClass::Foreground
            && ticket_live(ticket, now)
    }) {
        WorkClass::Foreground
    } else {
        WorkClass::Background
    }
}

fn next_load(state: &AdmissionState) -> Option<String> {
    state
        .load_waiters
        .iter()
        .filter(|(_, waiter)| waiter.class == WorkClass::Foreground)
        .min_by_key(|(_, waiter)| waiter.sequence)
        .or_else(|| {
            state
                .load_waiters
                .iter()
                .filter(|(_, waiter)| waiter.class == WorkClass::Background)
                .min_by_key(|(_, waiter)| waiter.sequence)
        })
        .map(|(worker, _)| worker.clone())
}
