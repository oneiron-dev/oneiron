//! Transaction-composable reservation settlement shared by completion and deferral.
use super::*;
use crate::model_step_context::StepReceipt;

impl DreamerRunnerStore<'_> {
    pub(crate) fn settle_budget_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: SettleDreamerBudget,
    ) -> Result<DreamerBudgetSettlementOutcome> {
        validate_budget_id(&input.budget_id)?;
        let reservation_key = BudgetReservationKey {
            budget_id: input.budget_id.clone(),
            attempt_id: input.child_attempt,
        };
        let Some(reservation) = read_budget_reservation_in_txn(
            self.vault,
            wtxn,
            &input.budget_id,
            input.child_attempt,
        )?
        else {
            return Ok(DreamerBudgetSettlementOutcome::NoReservation);
        };

        let Some(mut budget) = BUDGET.get(&self.vault.store, &*wtxn, &input.budget_id)? else {
            return Err(invalid_dreamer_runner(
                "dreamer budget reservation missing counter",
            ));
        };
        if budget.budget_id != input.budget_id {
            return Err(invalid_dreamer_runner("dreamer budget key/body mismatch"));
        }

        let settlement = super::spend::settle_budget_for_child(
            &mut budget,
            reservation,
            input.actual_units,
            input.now,
        )?;
        put_budget_record_in_txn(self.vault, wtxn, &settlement.budget)?;
        BUDGET_RESERVATION.delete(&self.vault.store, wtxn, &reservation_key)?;
        // The charge and the owed rows commit together: a crash before this
        // leaves the spend to the wake-start reconcile (FIX 11450).
        crate::dreamer_wake::owed::delete_attempt_owed_calls_in_txn(
            self.vault,
            wtxn,
            input.child_attempt,
        )?;
        // A free-time item's real spend, what its reservation owed among
        // it, lands on its cycle's spend scope in the commit that settles
        // this reservation, once (FIX 4453).
        crate::dreamer_runner::charge_free_time_item_in_txn(
            self.vault,
            wtxn,
            input.child_attempt,
            settlement.actual_units,
        )?;

        Ok(DreamerBudgetSettlementOutcome::Settled(settlement))
    }

    /// Was this exact terminal step charged at an earlier wake checkpoint?
    /// A memoized response is paid on replay only if it has no such receipt.
    pub(crate) fn checkpoint_step_charged(&self, receipt: StepReceipt) -> Result<bool> {
        let rtxn = self.vault.store.env.read_txn()?;
        self.step_charge_marked_in_txn(&rtxn, receipt)
    }

    /// Forgets the paid receipt of `attempt_id`'s terminal step `step_hash`
    /// in the caller's writer, so the call its forgotten memo asks again is
    /// charged its own usage (FIX 2851). A step with no receipt is left as it
    /// is.
    pub(crate) fn forget_step_charge_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        attempt_id: AttemptId,
        step_hash: &[u8; 32],
    ) -> Result<()> {
        let mut prefix = attempt_id.as_bytes().to_vec();
        prefix.extend_from_slice(step_hash);
        BUDGET_STEP_CHARGE.delete_from(&self.vault.store, wtxn, &prefix)?;
        Ok(())
    }

    /// Whether this exact terminal step already reads charged, in the
    /// caller's snapshot: the crash-owed reconcile charges no step twice
    /// (FIX 11450).
    pub(crate) fn step_charge_marked_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        receipt: StepReceipt,
    ) -> Result<bool> {
        Ok(BUDGET_STEP_CHARGE.get(
            &self.vault.store,
            txn,
            &(receipt.attempt_id, receipt.step_hash, receipt.claim_id),
        )? == Some(receipt.claim_id))
    }

    /// Retire paid-step receipts, the pinned listing and the narrowed hold
    /// when their attempt can no longer replay.
    pub(crate) fn cleanup_step_receipts_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        attempt_id: AttemptId,
    ) -> Result<()> {
        BUDGET_STEP_CHARGE.delete_from(&self.vault.store, wtxn, attempt_id.as_bytes())?;
        crate::dreamer_consolidation::unpin_neighbourhood_in_txn(self.vault, wtxn, attempt_id)?;
        crate::dreamer_consolidation::delete_running_buckets_in_txn(self.vault, wtxn, attempt_id)
    }

    /// Settle real usage and pin the paid receipts of `step_bindings` in one
    /// writer, so a memo the same try replays later is not paid twice
    /// (FIX 6100). Receipts land only beside a settled reservation, so no
    /// step reads paid before its charge commits; a step already pinned is
    /// refused, as a checkpoint's double charge always was.
    pub(in crate::dreamer_runner) fn settle_budget_and_step_receipts_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: SettleDreamerBudget,
        step_bindings: &[StepReceipt],
    ) -> Result<DreamerBudgetSettlementOutcome> {
        let settled = self.settle_budget_in_txn(wtxn, input)?;
        if matches!(settled, DreamerBudgetSettlementOutcome::Settled(_)) {
            for binding in step_bindings {
                if self.step_charge_marked_in_txn(wtxn, *binding)? {
                    return Err(invalid_dreamer_runner("checkpoint step charged twice"));
                }
                BUDGET_STEP_CHARGE.put(
                    &self.vault.store,
                    wtxn,
                    &(binding.attempt_id, binding.step_hash, binding.claim_id),
                    &binding.claim_id,
                )?;
            }
        }
        Ok(settled)
    }

    /// [`Self::settle_budget_and_step_receipts_in_txn`] in its own writer:
    /// a failed or plainly parked try settles what it charged and pins the
    /// terminal steps that charge paid for (FIX 6100). A step already pinned
    /// keeps its receipt and is not pinned twice, so the charge itself is
    /// never refused for it (FIX 8728).
    pub(crate) fn settle_budget_with_step_receipts(
        &self,
        input: SettleDreamerBudget,
        step_bindings: &[StepReceipt],
    ) -> Result<DreamerBudgetSettlementOutcome> {
        self.settle_budget_with_native_meter(input, step_bindings, None)
    }

    /// The actual registered meter's selected native intervals, committed
    /// beside the existing aggregate charge. They do not pay a NET invoice.
    pub(crate) fn settle_budget_with_native_meter(
        &self,
        input: SettleDreamerBudget,
        step_bindings: &[StepReceipt],
        native: Option<&NativeMeterSnapshot>,
    ) -> Result<DreamerBudgetSettlementOutcome> {
        self.vault.with_write_txn_grouped(|wtxn| {
            let mut unpinned = Vec::with_capacity(step_bindings.len());
            for binding in step_bindings {
                if !unpinned.contains(binding) && !self.step_charge_marked_in_txn(wtxn, *binding)? {
                    unpinned.push(*binding);
                }
            }
            let settled =
                self.settle_budget_and_step_receipts_in_txn(wtxn, input.clone(), &unpinned)?;
            if let DreamerBudgetSettlementOutcome::Settled(ref actual) = settled
                && let Some(native) = native
            {
                super::native_call::record_native_gross_settlement_in_txn(
                    self.vault,
                    wtxn,
                    &input,
                    actual.actual_units,
                    native,
                );
            }
            Ok(settled)
        })
    }

    /// Settle real usage, pin charged step identities, and park atomically.
    /// A failure at any door rolls back all three writes. The park is fenced
    /// on `lease` (FIX 6057): a try resumed or claimed again since that lease
    /// ran it keeps its spend settled and is not parked.
    pub(crate) fn settle_checkpoint_budget(
        &self,
        input: SettleDreamerBudget,
        step_bindings: &[StepReceipt],
        park: ParkDreamerAttempt,
        lease: crate::dreamer_runner::DreamerTryLease<'_>,
    ) -> Result<DreamerBudgetSettlementOutcome> {
        if park.attempt_id != input.child_attempt {
            return Err(invalid_dreamer_runner(
                "checkpoint park target differs from settlement",
            ));
        }
        let settled = self.vault.with_write_txn_grouped(|wtxn| {
            let settled =
                self.settle_budget_and_step_receipts_in_txn(wtxn, input, step_bindings)?;
            if !matches!(settled, DreamerBudgetSettlementOutcome::Settled(_)) {
                return Err(invalid_dreamer_runner(
                    "checkpoint has no budget reservation",
                ));
            }
            // A trapped child already parked under the step layer's owner.
            // Settle completed siblings without stealing that park.
            if !self.is_parked_in_txn(wtxn, park.attempt_id)? {
                self.park_if_current_lease_in_txn(wtxn, park, lease)?;
            }
            Ok(settled)
        })?;
        self.vault.store.notify_attempt_observers();
        Ok(settled)
    }
}
