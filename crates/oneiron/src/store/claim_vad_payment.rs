//! Per-handle claim VAD payment wake state and attached-worker lifetime.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::entity_id::EntityId;

/// The wake cell one vault handle owns. In memory only.
#[derive(Debug, Default)]
pub(crate) struct ClaimVadPayment {
    pub(crate) wake: tokio::sync::Notify,
    /// The claims the door handed over, in the order it handed them.
    pub(crate) handed: Mutex<Vec<EntityId>>,
    /// How many attached workers wait on the wake now.
    pub(crate) workers: Arc<AtomicUsize>,
}

/// A host's claim VAD payment worker, attached to one vault until this is
/// dropped ([`crate::Vault::attach_claim_vad_payment_worker`]).
#[derive(Debug)]
#[must_use = "dropping it detaches the worker"]
pub struct ClaimVadPaymentWorker {
    pub(crate) workers: Arc<AtomicUsize>,
}

impl Drop for ClaimVadPaymentWorker {
    fn drop(&mut self) {
        self.workers.fetch_sub(1, Ordering::AcqRel);
    }
}
