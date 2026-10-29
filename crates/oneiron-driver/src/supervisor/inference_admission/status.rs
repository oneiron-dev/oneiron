//! Admission status and host-observed pause state.

use super::*;

impl DeviceAdmission {
    /// Whether a worker has no host queue, active grant, pause, or transfer
    /// ticket and its executor row is idle.
    #[must_use]
    pub fn worker_idle(&self, worker_id: &str) -> bool {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.executors.get(worker_id).is_some_and(|row| row.idle)
            && !state
                .tickets
                .values()
                .any(|ticket| ticket.request.worker_id == worker_id)
            && !self.ledger.has_hold(&load_holder(worker_id))
    }

    /// Marks host-observed pause state. Paused work keeps its bytes.
    pub fn set_paused(&self, ticket: TicketId, paused: bool) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if paused && is_granted(&state, ticket) {
            state.paused.insert(ticket);
        } else if !paused {
            state.paused.remove(&ticket);
        }
        state.revision = state.revision.saturating_add(1);
        drop(state);
        self.changed.notify_waiters();
    }

    /// A copy of host and ledger state, never a device/worker probe.
    #[must_use]
    pub fn snapshot(&self) -> AdmissionSnapshot {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        let queued_foreground = state
            .tickets
            .iter()
            .filter(|(id, ticket)| {
                !is_granted(&state, **id)
                    && ticket_live(ticket, now)
                    && ticket.request.class == WorkClass::Foreground
            })
            .count() as u64;
        let queued_background = state
            .tickets
            .iter()
            .filter(|(id, ticket)| {
                !is_granted(&state, **id)
                    && ticket_live(ticket, now)
                    && ticket.request.class == WorkClass::Background
            })
            .count() as u64;
        let mut workers = BTreeMap::new();
        for (id, ticket) in &state.tickets {
            let worker = workers
                .entry(ticket.request.worker_id.clone())
                .or_insert_with(WorkerQueueStatus::default);
            if is_granted(&state, *id) {
                worker.active += 1;
                if state.paused.contains(id) {
                    worker.paused += 1;
                }
            } else if ticket_live(ticket, now) {
                worker.queued += 1;
            }
        }
        AdmissionSnapshot {
            device: self.device.clone(),
            capacity_mib: self.ledger.capacity(),
            queued_foreground,
            queued_background,
            active_grants: state.grants.len() as u64,
            paused: state.paused.len() as u64,
            ledger: self.ledger.snapshot(),
            pressure: state.pressure.clone(),
            executors: state.executors.values().cloned().collect(),
            workers,
        }
    }
}
