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
        budget_id: &str,
        attempt_id: AttemptId,
        step_hash: &[u8; 32],
    ) -> Result<bool> {
        let key = budget_step_charge_key(budget_id, attempt_id, step_hash)?;
        let rtxn = self.vault.store.env.read_txn()?;
        match self.vault.store.vault_meta.get(&rtxn, &key)?.as_deref() {
            None => Ok(false),
            Some([1]) => Ok(true),
            Some(_) => Err(invalid_dreamer_runner(
                "invalid checkpoint step charge receipt",
            )),
        }
    }

    /// Settle real usage and pin the charged step identities in ONE transaction.
    /// An absent reservation cannot mint receipts for usage the ledger did not pay.
    pub(crate) fn settle_checkpoint_budget(
        &self,
        input: SettleDreamerBudget,
        step_hashes: &[[u8; 32]],
    ) -> Result<DreamerBudgetSettlementOutcome> {
        self.vault.with_write_txn(|wtxn| {
            let settled = self.settle_budget_in_txn(wtxn, input.clone())?;
            if !matches!(settled, DreamerBudgetSettlementOutcome::Settled(_)) {
                return Err(invalid_dreamer_runner(
                    "checkpoint has no budget reservation",
                ));
            }
            for hash in step_hashes {
                let key = budget_step_charge_key(&input.budget_id, input.child_attempt, hash)?;
                if self.vault.store.vault_meta.get(wtxn, &key)?.is_some() {
                    return Err(invalid_dreamer_runner("checkpoint step charged twice"));
                }
                self.vault.store.vault_meta.put(wtxn, &key, &[1])?;
            }
            Ok(settled)
        })
    }
}
