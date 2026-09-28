//! Transaction-composable reservation settlement shared by completion and deferral.
use super::*;

impl DreamerRunnerStore<'_> {
    pub(in crate::dreamer_runner) fn settle_budget_in_txn(
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

        let settlement =
            settle_budget_for_child(&mut budget, reservation, input.actual_units, input.now)?;
        put_budget_record_in_txn(self.vault, wtxn, &settlement.budget)?;
        BUDGET_RESERVATION.delete(&self.vault.store, wtxn, &reservation_key)?;

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
        match BUDGET_STEP_CHARGE.get(&self.vault.store, &rtxn, &(attempt_id, *step_hash))? {
            None => Ok(false),
            Some([1]) => Ok(true),
            Some(_) => Err(invalid_dreamer_runner(
                "invalid checkpoint step charge receipt",
            )),
        }
    }

    /// Retire paid-step receipts when their attempt can no longer replay.
    pub(crate) fn cleanup_step_receipts_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        attempt_id: AttemptId,
    ) -> Result<()> {
        BUDGET_STEP_CHARGE.delete_from(&self.vault.store, wtxn, attempt_id.as_bytes())?;
        Ok(())
    }

    /// Settle real usage, pin charged step identities, and park atomically.
    /// A failure at any door rolls back all three writes.
    pub(crate) fn settle_checkpoint_budget(
        &self,
        input: SettleDreamerBudget,
        step_hashes: &[[u8; 32]],
        park: ParkDreamerAttempt,
    ) -> Result<DreamerBudgetSettlementOutcome> {
        if park.attempt_id != input.child_attempt {
            return Err(invalid_dreamer_runner(
                "checkpoint park target differs from settlement",
            ));
        }
        let settled = self.vault.with_write_txn(|wtxn| {
            let settled = self.settle_budget_in_txn(wtxn, input.clone())?;
            if !matches!(settled, DreamerBudgetSettlementOutcome::Settled(_)) {
                return Err(invalid_dreamer_runner(
                    "checkpoint has no budget reservation",
                ));
            }
            for hash in step_hashes {
                let key = (input.child_attempt, *hash);
                if BUDGET_STEP_CHARGE.contains(&self.vault.store, wtxn, &key)? {
                    return Err(invalid_dreamer_runner("checkpoint step charged twice"));
                }
                BUDGET_STEP_CHARGE.put(&self.vault.store, wtxn, &key, &[1])?;
            }
            self.park_attempt_in_txn(wtxn, park)?;
            Ok(settled)
        })?;
        self.vault.store.notify_attempt_observers();
        Ok(settled)
    }
}
