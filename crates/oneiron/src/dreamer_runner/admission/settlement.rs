//! Transaction-composable reservation settlement shared by completion and deferral.
use super::*;

impl DreamerRunnerStore<'_> {
    pub(in crate::dreamer_runner) fn settle_budget_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        input: SettleDreamerBudget,
    ) -> Result<DreamerBudgetSettlementOutcome> {
        validate_budget_id(&input.budget_id)?;
        let reservation_key = budget_reservation_key(&input.budget_id, input.child_attempt)?;
        let Some(reservation) = read_budget_reservation_in_txn(
            self.vault,
            wtxn,
            &input.budget_id,
            input.child_attempt,
        )?
        else {
            return Ok(DreamerBudgetSettlementOutcome::NoReservation);
        };

        let budget_key = budget_key(&input.budget_id)?;
        let Some(raw_budget) = self.vault.store.vault_meta.get(wtxn, &budget_key)? else {
            return Err(invalid_dreamer_runner(
                "dreamer budget reservation missing counter",
            ));
        };
        let mut budget = decode_budget_record(&raw_budget)?;
        if budget.budget_id != input.budget_id {
            return Err(invalid_dreamer_runner("dreamer budget key/body mismatch"));
        }

        let settlement =
            settle_budget_for_child(&mut budget, reservation, input.actual_units, input.now)?;
        put_budget_record_in_txn(self.vault, wtxn, &settlement.budget)?;
        self.vault.store.vault_meta.delete(wtxn, &reservation_key)?;

        Ok(DreamerBudgetSettlementOutcome::Settled(settlement))
    }

    /// Was this exact terminal step charged at an earlier wake checkpoint?
    /// A memoized response is paid on replay only if it has no such receipt.
    pub(crate) fn checkpoint_step_charged(
        &self,
        attempt_id: AttemptId,
        step_hash: &[u8; 32],
    ) -> Result<bool> {
        let key = budget_step_charge_key(attempt_id, step_hash);
        let rtxn = self.vault.store.env.read_txn()?;
        match self.vault.store.vault_meta.get(&rtxn, &key)?.as_deref() {
            None => Ok(false),
            Some([1]) => Ok(true),
            Some(_) => Err(invalid_dreamer_runner(
                "invalid checkpoint step charge receipt",
            )),
        }
    }

    /// Retire paid-step receipts when their attempt can no longer replay.
    pub(in crate::dreamer_runner) fn cleanup_step_receipts_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        attempt_id: AttemptId,
    ) -> Result<()> {
        let prefix = budget_step_charge_prefix(attempt_id);
        let keys: Vec<Vec<u8>> = self
            .vault
            .store
            .vault_meta
            .prefix_iter(&*wtxn, &prefix)?
            .map(|row| row.map(|(key, _)| key.to_vec()))
            .collect::<std::result::Result<_, _>>()?;
        for key in keys {
            self.vault.store.vault_meta.delete(wtxn, &key)?;
        }
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
                let key = budget_step_charge_key(input.child_attempt, hash);
                if self.vault.store.vault_meta.get(wtxn, &key)?.is_some() {
                    return Err(invalid_dreamer_runner("checkpoint step charged twice"));
                }
                self.vault.store.vault_meta.put(wtxn, &key, &[1])?;
            }
            self.park_attempt_in_txn(wtxn, park)?;
            Ok(settled)
        })?;
        self.vault.store.notify_attempt_observers();
        Ok(settled)
    }
}
