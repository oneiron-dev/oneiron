//! Ticket waits and cancellation for the parent device queue.

use super::*;

impl WorkTicket {
    /// Waits until this is the next runnable ticket, its deadline passes, or
    /// it is cancelled. No execution grant is held during this wait.
    pub async fn wait_runnable(&self) -> Result<(), AdmissionStop> {
        loop {
            let changed = self.admission.changed();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(stop) = self.admission.ticket_stop(self.ticket) {
                self.admission.cancel(self.ticket);
                return Err(stop);
            }
            if self
                .admission
                .choose_next()
                .is_some_and(|next| next.ticket == self.ticket)
            {
                return Ok(());
            }
            if let Some(deadline) = self.admission.ticket_deadline(self.ticket) {
                let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
                tokio::pin!(sleep);
                tokio::select! {
                    () = changed.as_mut() => {},
                    () = &mut sleep => {
                        self.admission.cancel(self.ticket);
                        return Err(AdmissionStop::Deadline);
                    }
                }
            } else {
                changed.await;
            }
        }
    }

    /// Tries to take this ticket's execution grant. `Ok(None)` means wait.
    pub fn execution_grant(&self) -> Result<Option<DeviceGrant>, AdmissionStop> {
        self.admission.grant(self)
    }

    /// Waits for the selected ticket's execution grant without polling or
    /// holding it while a dependency or capacity blocks it.
    pub async fn wait_execution_grant(&self) -> Result<DeviceGrant, AdmissionStop> {
        loop {
            let changed = self.admission.changed();
            tokio::pin!(changed);
            changed.as_mut().enable();
            match self.execution_grant() {
                Ok(Some(grant)) => return Ok(grant),
                Err(stop) => {
                    self.admission.cancel(self.ticket);
                    return Err(stop);
                }
                Ok(None) => {}
            }
            if let Some(deadline) = self.admission.ticket_deadline(self.ticket) {
                let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
                tokio::pin!(sleep);
                tokio::select! {
                    () = changed.as_mut() => {},
                    () = &mut sleep => {
                        self.admission.cancel(self.ticket);
                        return Err(AdmissionStop::Deadline);
                    }
                }
            } else {
                changed.await;
            }
        }
    }

    /// Resolves this ticket against current capacity and idle workers.
    pub fn resolve_pressure(&self) -> PressureDecision {
        self.admission.resolve_pressure(self)
    }

    /// One pressure pass without victims this caller already tried.
    pub fn resolve_pressure_excluding(&self, tried: &BTreeSet<String>) -> PressureDecision {
        self.admission.resolve_pressure_excluding(self, tried)
    }

    /// Admission changes, armed by the caller before its final state check.
    pub fn pressure_change(&self) -> tokio::sync::futures::Notified<'_> {
        self.admission.changed()
    }

    /// This ticket's caller deadline, if it has one.
    pub fn deadline(&self) -> Option<Instant> {
        self.admission.ticket_deadline(self.ticket)
    }

    /// Cancels this ticket and any children still inheriting from it.
    pub fn cancel(&self) {
        self.request.cancel.store(true, Ordering::Release);
        self.admission.cancel(self.ticket);
    }
}
