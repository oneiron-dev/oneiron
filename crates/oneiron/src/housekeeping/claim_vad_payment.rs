//! The claim VAD payment worker's wake (FIX 11702, Engine 10-31 04:1x).
//!
//! A write through the vault's write door owes the VAD consolidation of each
//! Dreamer claim it approved, and the debt row commits with the approval
//! (FIX 9598). A host that drives this wake pays those debts off the write's
//! reply path: it attaches a worker ([`Vault::attach_claim_vad_payment_worker`]),
//! waits on [`Vault::claim_vad_payment_wake`], and runs
//! [`Vault::pay_handed_claim_vads`] on each wake, one run at a time. The door
//! then hands its approved claims over, wakes the worker and answers at once;
//! it wakes the worker on every write, so a debt an earlier commit left is
//! paid after a later one (FIX 11923). With no worker attached (an embedded
//! SDK, the CLI), the door pays on the calling thread before it answers, as
//! before.
//!
//! The handed claims are a hint: the debt row is the debt. A wake that comes
//! while a run is going is kept, and starts the next run when it ends; wakes
//! that come together coalesce into one run. A worker that stops leaves every
//! debt in place for the next write through the door or the housekeeping
//! pass's `ClaimVadDebt` sweep. Nothing here can fail, so no write fails for
//! a wake.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The wake cell one vault handle owns. In memory only.
#[derive(Debug, Default)]
pub(crate) struct ClaimVadPayment {
    wake: tokio::sync::Notify,
    /// The claims the door handed over, in the order it handed them.
    handed: Mutex<Vec<EntityId>>,
    /// How many attached workers wait on the wake now.
    workers: Arc<AtomicUsize>,
}

/// A host's claim VAD payment worker, attached to one vault until this is
/// dropped ([`Vault::attach_claim_vad_payment_worker`]).
#[derive(Debug)]
#[must_use = "dropping it detaches the worker"]
pub struct ClaimVadPaymentWorker {
    workers: Arc<AtomicUsize>,
}

impl Drop for ClaimVadPaymentWorker {
    fn drop(&mut self) {
        self.workers.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Vault {
    /// What an attached worker waits on: a run of
    /// [`Self::pay_handed_claim_vads`] starts when it fires.
    pub fn claim_vad_payment_wake(&self) -> &tokio::sync::Notify {
        &self.claim_vad_payment.wake
    }

    /// Attaches a worker that waits on [`Self::claim_vad_payment_wake`] and
    /// runs [`Self::pay_handed_claim_vads`] on each wake, until the returned
    /// value is dropped. While one is attached, the write door answers
    /// before the claim VAD consolidations its write owes.
    pub fn attach_claim_vad_payment_worker(&self) -> ClaimVadPaymentWorker {
        let workers = Arc::clone(&self.claim_vad_payment.workers);
        workers.fetch_add(1, Ordering::AcqRel);
        ClaimVadPaymentWorker { workers }
    }

    /// Whether a worker is attached, so the door hands its debts over.
    pub(crate) fn claim_vad_payment_worker_attached(&self) -> bool {
        self.claim_vad_payment.workers.load(Ordering::Acquire) > 0
    }

    /// Hands the claims a committed write approved to the worker, and wakes
    /// it. `approved` may be empty: the wake alone pays older debts.
    pub(crate) fn hand_claim_vads_for_payment(&self, approved: Vec<EntityId>) {
        if !approved.is_empty() {
            self.claim_vad_payment
                .handed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend(approved);
        }
        self.wake_claim_vad_payment();
    }

    /// Wakes the worker with nothing handed: older debts only.
    pub(crate) fn wake_claim_vad_payment(&self) {
        self.claim_vad_payment.wake.notify_one();
    }

    /// One worker run (FIX 11702): pays each claim the door handed over that
    /// is still owed, in the order it was handed, then up to the door's
    /// bound of older debts, as the door paid both after its commit before.
    /// A consolidation that fails keeps its debt for the housekeeping sweep
    /// and warns; a run in which a handed claim failed leaves the older
    /// debts for the next wake, as the door's own failure did.
    ///
    /// # Errors
    ///
    /// Storage errors reading or clearing the debt rows. The debts stay.
    pub fn pay_handed_claim_vads(&self) -> Result<()> {
        let handed = std::mem::take(
            &mut *self
                .claim_vad_payment
                .handed
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
        let owed = {
            let txn = self.store.env.read_txn()?;
            let mut seen = BTreeSet::new();
            let mut owed = Vec::with_capacity(handed.len());
            for id in handed {
                if seen.insert(id)
                    && crate::store::claim_vad_owed_in_txn(&self.store, &txn, &id)?
                {
                    owed.push(id);
                }
            }
            owed
        };
        let mut failed = false;
        if !owed.is_empty() {
            let now = self.store.clock.now_recorded_at();
            for id in owed {
                if let Err(error) = self.consolidate_claim_vad_now(&id, now) {
                    tracing::warn!(
                        claim = %id.to_hex(),
                        error = %error,
                        "a handed claim VAD consolidation failed; the debt stays for a later pass"
                    );
                    failed = true;
                }
            }
        }
        if failed {
            return Ok(());
        }
        self.drain_owed_claim_vads_after_commit()
    }
}
