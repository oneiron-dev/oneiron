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
}
