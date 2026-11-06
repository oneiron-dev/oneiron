//! Fact-only session ownership rows (FIX10370): which vault sessions hold bytes
//! on a device's worker, as the coordinator observed them. Never a capacity
//! reservation: these rows feed no total, no room check, no class budget and
//! no admission decision ([`DeviceLedger`](super::DeviceLedger) owns those).
//!
//! One row per live-or-releasing session, keyed by a unique token drawn
//! from the ledger's existing grant counter. Its identity is the actual
//! native one (worker id, incarnation epoch, vault, session target); its
//! report is the last [`SessionResidency`](oneiron::llm::SessionResidency)
//! the coordinator observed for it, `None` while none was observed. Export
//! and import answers do not update it. A report's `unique_bytes`,
//! when measured, mixes that session's device pages with its host recurrent
//! snapshots; it is never KV-only and never device-only, and an unmeasured
//! report carries `None`, never zero.
use std::sync::Arc;

use oneiron::llm::{SessionResidency, SessionTarget, VaultRef};

use super::inference_device::DeviceLedger;

/// One session's ownership fact on one device: where it lives and what the
/// coordinator last observed it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAllocation {
    /// The worker that holds the session.
    pub worker_id: String,
    /// The incarnation epoch that holds it.
    pub epoch: String,
    /// The vault whose conversation the session keeps.
    pub vault: VaultRef,
    /// The session: its binding and its handle on the incarnation.
    pub target: SessionTarget,
    /// The last residency the coordinator observed for it; `None` while
    /// none was observed.
    pub report: Option<SessionResidency>,
}

/// The one owner of a [`SessionAllocation`] row: non-clone, drop-removes.
/// Dropping it removes only its own token; a stale drop can never take
/// another session's row or another incarnation's.
pub struct SessionAllocationOwner {
    ledger: Arc<DeviceLedger>,
    token: u64,
}

impl SessionAllocationOwner {
    /// Records `allocation` on `ledger` and owns its row from now until
    /// dropped.
    #[must_use]
    pub fn new(ledger: &Arc<DeviceLedger>, allocation: SessionAllocation) -> Self {
        let token = ledger.insert_session_allocation(allocation);
        Self {
            ledger: Arc::clone(ledger),
            token,
        }
    }

    /// Replaces this row's report with `report`: `Some` from an actual
    /// worker answer (even when that answer measured nothing), `None`
    /// while no report was observed. Only this token's row changes.
    pub fn observe(&self, report: Option<SessionResidency>) {
        self.ledger.observe_session_allocation(self.token, report);
    }
}

impl Drop for SessionAllocationOwner {
    /// The row goes with its owner: only this token is removed. The sole
    /// release path; there is no explicit release.
    fn drop(&mut self) {
        self.ledger.remove_session_allocation(self.token);
    }
}
