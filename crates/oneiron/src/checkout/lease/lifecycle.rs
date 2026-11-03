//! Lease state machine: claim, renew, reclaim, settle, and teardown plus fence guards.

use super::codec::LEASE;
use super::types::{
    CheckoutClaimRequest, CheckoutError, CheckoutFactMutation, CheckoutFactSink, CheckoutId,
    CheckoutLeaseAct, CheckoutLeaseFence, CheckoutLeaseGrant, CheckoutLiveness,
    CheckoutLivenessPulse, CheckoutRepoOps, CheckoutResult, CheckoutSettlementDisposition,
    CheckoutSettlementReceipt, CheckoutSettlementRequest, CheckoutTeardownOutcome,
    PushedHeadReceipt,
};

use crate::Vault;
use crate::error::Error;

pub struct CheckoutLeaseService<'a, F, L> {
    vault: &'a Vault,
    facts: F,
    liveness: L,
}
impl<'a, F, L> CheckoutLeaseService<'a, F, L> {
    pub fn new(vault: &'a Vault, facts: F, liveness: L) -> Self {
        Self {
            vault,
            facts,
            liveness,
        }
    }
    pub fn into_parts(self) -> (F, L) {
        (self.facts, self.liveness)
    }
}
impl<F: CheckoutFactSink, L: CheckoutLiveness> CheckoutLeaseService<'_, F, L> {
    pub fn claim(&mut self, r: CheckoutClaimRequest) -> CheckoutResult<CheckoutLeaseGrant> {
        CheckoutId::from_bytes(*r.checkout_id.as_bytes())?;
        if r.holder_ref.is_empty() {
            return Err(CheckoutError::Invalid("checkout holder empty"));
        }
        let (vault, facts) = (self.vault, &mut self.facts);
        // The TASK fact is applied inside the lease's write: a fact the sink
        // refuses rolls the claim back, so no lease commits without it (FIX
        // 8653). The host's sink runs there, so the write is a group of its own.
        let a = vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            let a = super::transactions::claim_in_txn(vault, t, r.clone())?;
            facts.apply_checkout_fact(CheckoutFactMutation::Claimed {
                task_ref: a.task_ref,
                assignee_ref: a.holder_ref.clone(),
                started_at: r.now,
                epoch: a.epoch,
            })?;
            Ok(a)
        })?;
        self.liveness.publish(CheckoutLivenessPulse {
            checkout_id: a.checkout_id,
            epoch: a.epoch,
            holder_ref: a.holder_ref.clone(),
            observed_at: r.now,
        })?;
        Ok(grant(&a))
    }
    pub fn renew(
        &mut self,
        f: CheckoutLeaseFence,
        ttl: u64,
        now: u64,
    ) -> CheckoutResult<CheckoutLeaseGrant> {
        let a = self
            .vault
            .try_with_write_txn_grouped::<_, _, CheckoutError>(|t| {
                super::transactions::renew_in_txn(self.vault, t, &f, ttl, now)
            })?;
        self.liveness.publish(CheckoutLivenessPulse {
            checkout_id: a.checkout_id,
            epoch: a.epoch,
            holder_ref: a.holder_ref.clone(),
            observed_at: now,
        })?;
        Ok(grant(&a))
    }
    pub fn reclaim_idempotent(
        &mut self,
        id: CheckoutId,
        new: String,
        now: u64,
    ) -> CheckoutResult<CheckoutLeaseGrant> {
        if new.is_empty() {
            return Err(CheckoutError::Invalid("checkout holder empty"));
        }
        let (vault, facts) = (self.vault, &mut self.facts);
        // A new epoch's TASK fact commits with it, as a claim's does (FIX 8653).
        let a = vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            let a =
                super::transactions::reclaim_in_txn(vault, t, id, new.clone(), now, None, false)?;
            if a.1 {
                facts.apply_checkout_fact(CheckoutFactMutation::Reclaimed {
                    task_ref: a.0.task_ref,
                    assignee_ref: a.0.holder_ref.clone(),
                    epoch: a.0.epoch,
                })?;
            }
            Ok(a)
        })?;
        if a.1 {
            self.liveness.publish(CheckoutLivenessPulse {
                checkout_id: a.0.checkout_id,
                epoch: a.0.epoch,
                holder_ref: a.0.holder_ref.clone(),
                observed_at: now,
            })?;
        }
        Ok(grant(&a.0))
    }
    pub fn get(&self, id: CheckoutId) -> CheckoutResult<Option<CheckoutLeaseAct>> {
        let t = self.vault.store.env.read_txn().map_err(Error::from)?;
        Ok(LEASE.get(&self.vault.store, &t, &id)?)
    }
    pub fn settle(
        &mut self,
        r: CheckoutSettlementRequest,
    ) -> CheckoutResult<CheckoutSettlementReceipt> {
        if r.observed_ref.is_empty() || r.result_ref.is_empty() {
            return Err(CheckoutError::Invalid("settlement references empty"));
        }
        let (vault, facts) = (self.vault, &mut self.facts);
        // The settlement acknowledges only with its TASK fact applied in the
        // same write: a refused fact rolls the settlement back, so a retry
        // settles and applies it again instead of replaying past it (FIX 8653).
        let receipt = vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            let (a, receipt, new) = super::transactions::settle_in_txn(vault, t, &r)?;
            if new {
                facts.apply_checkout_fact(
                    if receipt.disposition == CheckoutSettlementDisposition::Release {
                        CheckoutFactMutation::Released {
                            task_ref: a.task_ref,
                            epoch: a.epoch,
                        }
                    } else {
                        CheckoutFactMutation::Settled {
                            task_ref: a.task_ref,
                            epoch: a.epoch,
                            result_ref: r.result_ref.clone(),
                        }
                    },
                )?;
            }
            Ok(receipt)
        })?;
        Ok(receipt)
    }
    /// Tears a checkout down, collecting its working tree only when every
    /// fail-closed condition holds and retaining it otherwise.
    ///
    /// Teardown is restartable under the **same fence**: it accepts every lease
    /// state, so a retain for a transient cause (receipt not pushed yet, a
    /// foreign worker still alive, a dirty tree) can be re-driven to collection
    /// once the cause clears. Only the fenced holder at the fenced epoch may
    /// drive it — `fenced_in_txn` rejects every stale or foreign fence before
    /// any port call or state change.
    ///
    /// State pins:
    /// - `Retained` records a retain decision; a retry re-runs
    ///   inspect -> reason -> collect from scratch.
    /// - `Settling` means "collection authorised under this fence": it is
    ///   written only after a full inspection passed, immediately before the
    ///   irreversible `ops.collect`. A retry *resumes* to completion once the
    ///   tree is gone, and inspects a tree still present again before
    ///   removing it (FIX 8654); `CheckoutRepoOps::collect` is required to be
    ///   idempotent.
    /// - Liveness/repo port errors surface before any state transition, so a
    ///   failing port can never strand the lease in `Settling`.
    /// - `Released` is applied before the lease row is deleted, so the FACT is
    ///   never lost behind the delete.
    pub fn teardown<R: CheckoutRepoOps>(
        &mut self,
        f: CheckoutLeaseFence,
        receipt: Option<&PushedHeadReceipt>,
        ops: &R,
        now: u64,
    ) -> CheckoutResult<CheckoutTeardownOutcome> {
        let vault = self.vault;
        let facts = &mut self.facts;
        super::teardown::teardown_through(&f, ops, &mut self.liveness, |step, live| {
            if matches!(step, super::teardown::TeardownStep::Finish) {
                let t = vault.store.env.read_txn().map_err(Error::from)?;
                let act = super::codec::load_act_in_txn(vault, &t, f.checkout_id)?
                    .ok_or(CheckoutError::Invalid("checkout missing"))?;
                drop(t);
                facts.apply_checkout_fact(CheckoutFactMutation::Released {
                    task_ref: act.task_ref,
                    epoch: act.epoch,
                })?;
            }
            vault.try_with_write_txn_grouped::<_, _, CheckoutError>(|t| match step {
                super::teardown::TeardownStep::Prepare => {
                    super::teardown::prepare_teardown_in_txn(vault, t, &f, receipt, ops, live, now)
                }
                super::teardown::TeardownStep::Finish => {
                    super::transactions::finish_teardown_in_txn(vault, t, &f, now)
                        .map(|act| (act, None))
                }
            })
        })
    }
}
fn grant(a: &CheckoutLeaseAct) -> CheckoutLeaseGrant {
    CheckoutLeaseGrant {
        checkout_id: a.checkout_id,
        epoch: a.epoch,
        holder_ref: a.holder_ref.clone(),
        lease_expires_at: a.lease_expires_at,
    }
}
