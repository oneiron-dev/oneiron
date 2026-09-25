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
}
