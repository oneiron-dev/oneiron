//! Transaction-composable reservation settlement shared by completion and deferral.
use super::*;

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
    pub(crate) fn checkpoint_step_charged(
        &self,
        attempt_id: AttemptId,
        step_hash: &[u8; 32],
    ) -> Result<bool> {
        let rtxn = self.vault.store.env.read_txn()?;
        self.step_charge_marked_in_txn(&rtxn, attempt_id, step_hash)
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
        BUDGET_STEP_CHARGE.delete(&self.vault.store, wtxn, &(attempt_id, *step_hash))?;
        Ok(())
    }

    /// Whether this exact terminal step already reads charged, in the
    /// caller's snapshot: the crash-owed reconcile charges no step twice
    /// (FIX 11450).
    pub(crate) fn step_charge_marked_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt_id: AttemptId,
        step_hash: &[u8; 32],
    ) -> Result<bool> {
        let Some(paid) =
            BUDGET_STEP_CHARGE.get(&self.vault.store, txn, &(attempt_id, *step_hash))?
        else {
            return Ok(false);
        };
        Ok(Self::terminal_claim_in(self.vault, txn, attempt_id, step_hash)? == Some(paid))
    }

    /// The terminal claim the step's memo replays now. A receipt counts only
    /// while it names that claim: a re-ask after the memo's claim was erased
    /// or deindexed answers with a new claim, so its paid usage is tallied
    /// once and pinned again (FIX 7489).
    fn terminal_claim_in(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        attempt_id: AttemptId,
        step_hash: &[u8; 32],
    ) -> Result<Option<EntityId>> {
        crate::llm::model_step::step_terminal_claim_in_txn(vault, txn, attempt_id, step_hash)
    }

    /// Retire paid-step receipts, and the listing its extraction pinned,
    /// when their attempt can no longer replay.
    pub(crate) fn cleanup_step_receipts_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        attempt_id: AttemptId,
    ) -> Result<()> {
        BUDGET_STEP_CHARGE.delete_from(&self.vault.store, wtxn, attempt_id.as_bytes())?;
        crate::dreamer_consolidation::unpin_neighbourhood_in_txn(self.vault, wtxn, attempt_id)
    }

    /// Settle real usage and pin the paid receipts of `step_hashes` in one
    /// writer, so a memo the same try replays later is not paid twice
    /// (FIX 6100). Receipts land only beside a settled reservation, so no
    /// step reads paid before its charge commits; a step already pinned is
    /// refused, as a checkpoint's double charge always was.
    pub(in crate::dreamer_runner) fn settle_budget_and_step_receipts_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: SettleDreamerBudget,
        step_hashes: &[[u8; 32]],
    ) -> Result<DreamerBudgetSettlementOutcome> {
        let child = input.child_attempt;
        let settled = self.settle_budget_in_txn(wtxn, input)?;
        if matches!(settled, DreamerBudgetSettlementOutcome::Settled(_)) {
            for hash in step_hashes {
                if self.step_charge_marked_in_txn(wtxn, child, hash)? {
                    return Err(invalid_dreamer_runner("checkpoint step charged twice"));
                }
                // A step with no memo has nothing a replay could reuse.
                let Some(paid) = Self::terminal_claim_in(self.vault, wtxn, child, hash)? else {
                    continue;
                };
                BUDGET_STEP_CHARGE.put(&self.vault.store, wtxn, &(child, *hash), &paid)?;
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
        step_hashes: &[[u8; 32]],
    ) -> Result<DreamerBudgetSettlementOutcome> {
        self.vault.with_write_txn_grouped(|wtxn| {
            let child = input.child_attempt;
            let mut unpinned = Vec::with_capacity(step_hashes.len());
            for hash in step_hashes {
                if !unpinned.contains(hash) && !self.step_charge_marked_in_txn(wtxn, child, hash)? {
                    unpinned.push(*hash);
                }
            }
            self.settle_budget_and_step_receipts_in_txn(wtxn, input, &unpinned)
        })
    }

    /// Settle real usage, pin charged step identities, and park atomically.
    /// A failure at any door rolls back all three writes. The park is fenced
    /// on `lease` (FIX 6057): a try resumed or claimed again since that lease
    /// ran it keeps its spend settled and is not parked.
    pub(crate) fn settle_checkpoint_budget(
        &self,
        input: SettleDreamerBudget,
        step_hashes: &[[u8; 32]],
        park: ParkDreamerAttempt,
        lease: crate::dreamer_runner::DreamerTryLease<'_>,
    ) -> Result<DreamerBudgetSettlementOutcome> {
        if park.attempt_id != input.child_attempt {
            return Err(invalid_dreamer_runner(
                "checkpoint park target differs from settlement",
            ));
        }
        let settled = self.vault.with_write_txn_grouped(|wtxn| {
            let settled = self.settle_budget_and_step_receipts_in_txn(wtxn, input, step_hashes)?;
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
