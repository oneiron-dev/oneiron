//! Lease state machine: claim, renew, reclaim, settle, and teardown plus fence guards.

use super::codec::{load_act_in_txn, load_tombstone_in_txn, store_act_in_txn};
use super::types::{
    CheckoutClaimRequest, CheckoutError, CheckoutFactMutation, CheckoutFactSink, CheckoutId,
    CheckoutLeaseAct, CheckoutLeaseFence, CheckoutLeaseGrant, CheckoutLeaseState, CheckoutLiveness,
    CheckoutLivenessPulse, CheckoutRepoOps, CheckoutResult, CheckoutRetainReason,
    CheckoutSettlementDisposition, CheckoutSettlementReceipt, CheckoutSettlementRequest,
    CheckoutTeardownOutcome, PushedHeadReceipt, TeardownReceiptMatch,
};
use super::{
    checkout_result_identity, decode_act, decode_receipt, encode_receipt, encode_tombstone,
    lease_key, settlement_key, tombstone_key,
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
        let a = self.vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            if load_act_in_txn(self.vault, t, r.checkout_id)?.is_some() {
                return Err(CheckoutError::StaleEpoch {
                    held: 1,
                    presented: 0,
                });
            }
            // Epochs are monotone per checkout_id *across* lifecycles: a fresh id
            // has no tombstone and starts at 1, while a re-claimed id resumes
            // above every epoch its earlier lifecycles ever held, so an old fence
            // can never match a new lifecycle.
            let epoch = load_tombstone_in_txn(self.vault, t, r.checkout_id)?
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(CheckoutError::Invalid("lease epoch overflow"))?;
            let expires = r
                .ttl_secs
                .map(|ttl| {
                    r.now
                        .checked_add(ttl)
                        .ok_or(CheckoutError::Invalid("lease expiry overflow"))
                })
                .transpose()?;
            let a = CheckoutLeaseAct {
                checkout_id: r.checkout_id,
                task_ref: r.task_ref,
                repo_ref: r.repo_ref.clone(),
                holder_ref: r.holder_ref.clone(),
                epoch,
                task_class: r.task_class,
                state: CheckoutLeaseState::Active,
                claimed_at: r.now,
                lease_expires_at: expires,
                updated_at: r.now,
            };
            store_act_in_txn(self.vault, t, &a)?;
            Ok(a)
        })?;
        self.facts
            .apply_checkout_fact(CheckoutFactMutation::Claimed {
                task_ref: a.task_ref,
                assignee_ref: a.holder_ref.clone(),
                started_at: r.now,
                epoch: a.epoch,
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
        let a = self.vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            let mut a = fenced_in_txn(self.vault, t, &f)?;
            require_not_regressed(&a, now)?;
            require_active(&a)?;
            a.lease_expires_at = Some(
                now.checked_add(ttl)
                    .ok_or(CheckoutError::Invalid("lease expiry overflow"))?,
            );
            a.updated_at = now;
            store_act_in_txn(self.vault, t, &a)?;
            Ok(a)
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
        let a = self.vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            let mut a = load_act_in_txn(self.vault, t, id)?
                .ok_or(CheckoutError::Invalid("checkout missing"))?;
            require_not_regressed(&a, now)?;
            require_active(&a)?;
            if a.holder_ref == new {
                return Ok((a, false));
            }
            let expiry = a
                .lease_expires_at
                .ok_or(CheckoutError::Invalid("ttl reclaim requires ttl"))?;
            if !a.task_class.allows_ttl_reclaim() || now < expiry {
                return Err(CheckoutError::StaleEpoch {
                    held: a.epoch,
                    presented: a.epoch,
                });
            }
            let ttl = expiry
                .checked_sub(a.updated_at)
                .ok_or(CheckoutError::Invalid("invalid lease ttl"))?;
            a.epoch = a
                .epoch
                .checked_add(1)
                .ok_or(CheckoutError::Invalid("lease epoch overflow"))?;
            a.holder_ref = new.clone();
            a.updated_at = now;
            a.lease_expires_at = Some(
                now.checked_add(ttl)
                    .ok_or(CheckoutError::Invalid("lease expiry overflow"))?,
            );
            store_act_in_txn(self.vault, t, &a)?;
            Ok((a, true))
        })?;
        if a.1 {
            self.facts
                .apply_checkout_fact(CheckoutFactMutation::Reclaimed {
                    task_ref: a.0.task_ref,
                    assignee_ref: a.0.holder_ref.clone(),
                    epoch: a.0.epoch,
                })?;
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
        match self.vault.store.vault_meta.get(&t, &lease_key(id))? {
            Some(raw) => Ok(Some(decode_act(&raw)?)),
            None => Ok(None),
        }
    }
    pub fn settle(
        &mut self,
        r: CheckoutSettlementRequest,
    ) -> CheckoutResult<CheckoutSettlementReceipt> {
        if r.observed_ref.is_empty() || r.result_ref.is_empty() {
            return Err(CheckoutError::Invalid("settlement references empty"));
        }
        let (a, receipt, new) = self.vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            let mut a = fenced_in_txn(self.vault, t, &r.fence)?;
            require_not_regressed(&a, r.now)?;
            let identity =
                checkout_result_identity(a.checkout_id, a.epoch, &r.observed_ref, &r.result_ref);
            let key = settlement_key(a.checkout_id, a.epoch, identity);
            if let Some(raw) = self.vault.store.vault_meta.get(&*t, &key)? {
                let old = decode_receipt(&raw)?;
                if old.checkout_id == a.checkout_id
                    && old.epoch == a.epoch
                    && old.result_identity == identity
                    && old.disposition == r.disposition
                    && old.observed_ref == r.observed_ref
                    && old.result_ref == r.result_ref
                {
                    return Ok((a, old, false));
                }
                return Err(CheckoutError::SettlementAlreadyWon);
            }
            require_settleable(&a)?;
            let receipt = CheckoutSettlementReceipt {
                receipt_id: *blake3::hash(&[identity.as_slice(), &r.now.to_le_bytes()].concat())
                    .as_bytes(),
                checkout_id: a.checkout_id,
                epoch: a.epoch,
                result_identity: identity,
                disposition: r.disposition,
                observed_ref: r.observed_ref.clone(),
                result_ref: r.result_ref.clone(),
                settled_at: r.now,
            };
            self.vault
                .store
                .vault_meta
                .put(t, &key, &encode_receipt(&receipt)?)?;
            a.state = CheckoutLeaseState::Settled;
            a.updated_at = r.now;
            store_act_in_txn(self.vault, t, &a)?;
            Ok((a, receipt, true))
        })?;
        if new {
            let fact = if receipt.disposition == CheckoutSettlementDisposition::Release {
                CheckoutFactMutation::Released {
                    task_ref: a.task_ref,
                    epoch: a.epoch,
                }
            } else {
                CheckoutFactMutation::Settled {
                    task_ref: a.task_ref,
                    epoch: a.epoch,
                    result_ref: r.result_ref,
                }
            };
            self.facts.apply_checkout_fact(fact)?;
        }
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
    ///   irreversible `ops.collect`. A retry therefore *resumes* to completion
    ///   instead of re-inspecting an already collected tree, and
    ///   `CheckoutRepoOps::collect` is required to be idempotent.
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
        let mut a = self.vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            let current = fenced_in_txn(self.vault, t, &f)?;
            require_not_regressed(&current, now)?;
            Ok(current)
        })?;
        if a.state != CheckoutLeaseState::Settling {
            if let Some(reason) = self.teardown_reason(&a, receipt, ops)? {
                self.retain(&f, now)?;
                return Ok(retained(&a, reason));
            }
            self.vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
                let mut current = fenced_in_txn(self.vault, t, &f)?;
                current.state = CheckoutLeaseState::Settling;
                current.updated_at = now;
                store_act_in_txn(self.vault, t, &current)
            })?;
            a.state = CheckoutLeaseState::Settling;
            a.updated_at = now;
        }
        ops.collect(&a)?;
        self.facts
            .apply_checkout_fact(CheckoutFactMutation::Released {
                task_ref: a.task_ref,
                epoch: a.epoch,
            })?;
        self.liveness.clear(a.checkout_id, a.epoch)?;
        self.vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            let current = fenced_in_txn(self.vault, t, &f)?;
            require_settling(&current)?;
            // Same txn as the delete: the epoch this row held is tombstoned
            // before the namespace is freed, so no crash window can free the id
            // without recording the epoch it just retired. Monotone-only.
            let prior = load_tombstone_in_txn(self.vault, t, current.checkout_id)?.unwrap_or(0);
            self.vault.store.vault_meta.put(
                t,
                &tombstone_key(current.checkout_id),
                &encode_tombstone(prior.max(current.epoch))?,
            )?;
            self.vault
                .store
                .vault_meta
                .delete(t, &lease_key(current.checkout_id))?;
            Ok(())
        })?;
        Ok(CheckoutTeardownOutcome::Collected {
            checkout_id: a.checkout_id,
            epoch: a.epoch,
        })
    }
    /// Decides whether the fenced checkout must be retained, without touching
    /// durable state: every port error returns before any transition.
    fn teardown_reason<R: CheckoutRepoOps>(
        &self,
        a: &CheckoutLeaseAct,
        receipt: Option<&PushedHeadReceipt>,
        ops: &R,
    ) -> CheckoutResult<Option<CheckoutRetainReason>> {
        let Some(r) = receipt else {
            return Ok(Some(CheckoutRetainReason::MissingPushedHeadReceipt));
        };
        if r.checkout_id != a.checkout_id || r.epoch != a.epoch {
            return Ok(Some(CheckoutRetainReason::ReceiptMismatch));
        }
        let i = ops.inspect_teardown(a, r)?;
        let pulse = self.liveness.current(a.checkout_id)?;
        let head_matches = match &i.observed_head {
            Some(h) => h.to_string() == r.pushed_head,
            None => false,
        };
        let reason = if foreign_occupant(a, i.occupant.as_deref(), pulse.as_ref()) {
            Some(CheckoutRetainReason::LiveOccupant)
        } else if i.dirty || i.receipt_match == TeardownReceiptMatch::Uncertain {
            Some(CheckoutRetainReason::DirtyOrUncertain)
        } else if i.receipt_match != TeardownReceiptMatch::Match || !head_matches {
            Some(CheckoutRetainReason::ReceiptMismatch)
        } else {
            None
        };
        Ok(reason)
    }
    /// Records a retain decision under the same fence. It accepts any state a
    /// restartable teardown can observe, so a retained lease stays retryable.
    fn retain(&self, f: &CheckoutLeaseFence, now: u64) -> CheckoutResult<()> {
        self.vault.try_with_write_txn::<_, _, CheckoutError>(|t| {
            let mut current = fenced_in_txn(self.vault, t, f)?;
            current.state = CheckoutLeaseState::Retained;
            current.updated_at = now;
            store_act_in_txn(self.vault, t, &current)
        })
    }
}
/// Only a *foreign* occupant blocks collection. The fenced holder's own
/// worktree occupancy and its own liveness pulse for the fenced epoch are its
/// own custody, not a live third party — `claim`/`renew` publish that pulse
/// themselves. Any pulse for a different checkout, epoch or holder is foreign
/// (fail-closed).
fn foreign_occupant(
    a: &CheckoutLeaseAct,
    occupant: Option<&str>,
    pulse: Option<&CheckoutLivenessPulse>,
) -> bool {
    let foreign_worktree = occupant.is_some_and(|o| o != a.holder_ref.as_str());
    let foreign_pulse = pulse.is_some_and(|p| !is_own_pulse(a, p));
    foreign_worktree || foreign_pulse
}
fn is_own_pulse(a: &CheckoutLeaseAct, p: &CheckoutLivenessPulse) -> bool {
    p.checkout_id == a.checkout_id && p.epoch == a.epoch && p.holder_ref == a.holder_ref
}
fn require_not_regressed(a: &CheckoutLeaseAct, now: u64) -> CheckoutResult<()> {
    if now < a.updated_at {
        Err(CheckoutError::Invalid("checkout time regressed"))
    } else {
        Ok(())
    }
}
fn require_settleable(a: &CheckoutLeaseAct) -> CheckoutResult<()> {
    if matches!(
        a.state,
        CheckoutLeaseState::Active | CheckoutLeaseState::Settled | CheckoutLeaseState::Retained
    ) {
        Ok(())
    } else {
        Err(CheckoutError::StaleEpoch {
            held: a.epoch,
            presented: a.epoch,
        })
    }
}
fn require_settling(a: &CheckoutLeaseAct) -> CheckoutResult<()> {
    if a.state == CheckoutLeaseState::Settling {
        Ok(())
    } else {
        Err(CheckoutError::StaleEpoch {
            held: a.epoch,
            presented: a.epoch,
        })
    }
}
fn require_active(a: &CheckoutLeaseAct) -> CheckoutResult<()> {
    if a.state == CheckoutLeaseState::Active {
        Ok(())
    } else {
        Err(CheckoutError::StaleEpoch {
            held: a.epoch,
            presented: a.epoch,
        })
    }
}
fn fenced_in_txn(
    vault: &Vault,
    t: &mut heed::RwTxn<'_>,
    f: &CheckoutLeaseFence,
) -> CheckoutResult<CheckoutLeaseAct> {
    let a = load_act_in_txn(vault, t, f.checkout_id)?
        .ok_or(CheckoutError::Invalid("checkout missing"))?;
    if a.epoch != f.epoch || a.holder_ref != f.holder_ref {
        Err(CheckoutError::StaleEpoch {
            held: a.epoch,
            presented: f.epoch,
        })
    } else {
        Ok(a)
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
fn retained(a: &CheckoutLeaseAct, reason: CheckoutRetainReason) -> CheckoutTeardownOutcome {
    CheckoutTeardownOutcome::Retained {
        checkout_id: a.checkout_id,
        epoch: a.epoch,
        reason,
    }
}
