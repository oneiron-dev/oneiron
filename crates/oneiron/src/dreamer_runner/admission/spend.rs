//! What a wake-budget counter charges once spend is incurred: a settlement
//! never refuses it (FIX 8702), so spend beyond what is left is carried as
//! the counter's overdraft, and owner policy governs only later admission (a
//! counter with nothing left admits nothing until its owner refills it).
//! Measured spend a settlement could not charge, and a stopped child's call
//! that settles late, stay owed until charged (FIX 8728, 9015).

use super::*;

impl DreamerBudgetRecord {
    /// What settled as spent on this counter: its total less what remains
    /// and what is reserved, plus its overdraft (FIX 8702). `None` for a row
    /// whose counters exceed its total, which the runner never writes.
    #[must_use]
    pub fn spent_units(&self) -> Option<u64> {
        self.total_units
            .checked_sub(self.remaining_units)?
            .checked_sub(self.reserved_units)?
            .checked_add(self.overdraft_units)
    }
}

impl DreamerRunnerStore<'_> {
    /// Marks `calls` admitted calls on `budget_id` whose terminal usage is
    /// still owed (FIX 9015): a stopped child's calls in flight. Each is
    /// charged by [`Self::charge_late_usage`] when it settles; one that
    /// never settles stays owed on the line. A line with no counter row
    /// marks nothing.
    ///
    /// # Errors
    ///
    /// Storage errors; a counter row naming another budget.
    pub fn owe_late_calls(&self, budget_id: &str, calls: u64) -> Result<()> {
        validate_budget_id(budget_id)?;
        if calls == 0 {
            return Ok(());
        }
        let now = self.vault.now_recorded_at();
        self.vault.with_write_txn(|wtxn| {
            let Some(mut budget) = BUDGET.get(&self.vault.store, &*wtxn, &budget_id.to_owned())?
            else {
                return Ok(());
            };
            if budget.budget_id != budget_id {
                return Err(invalid_dreamer_runner("dreamer budget key/body mismatch"));
            }
            budget.owed_calls = budget
                .owed_calls
                .checked_add(calls)
                .ok_or(Error::ArithmeticOverflow("dreamer budget owed calls"))?;
            budget.updated_at = budget.updated_at.max(now);
            put_budget_record_in_txn(self.vault, wtxn, &budget)
        })
    }

    /// Charges one owed call's terminal usage, `units`, to `child_attempt`
    /// on `budget_id` (FIX 9015), clearing the line's owed call: onto the
    /// child's reservation while one is held, so its settlement charges it
    /// with the rest; else onto the line itself, past what remains if need
    /// be (FIX 8702). A call that failed settles with 0 units.
    ///
    /// # Errors
    ///
    /// Storage errors; a line with no counter row.
    pub fn charge_late_usage(
        &self,
        budget_id: &str,
        child_attempt: AttemptId,
        units: u64,
    ) -> Result<()> {
        validate_budget_id(budget_id)?;
        let now = self.vault.now_recorded_at();
        self.vault.with_write_txn(|wtxn| {
            let mut budget = self.owing_budget_in_txn(wtxn, budget_id)?;
            budget.owed_calls = budget.owed_calls.saturating_sub(1);
            self.owe_usage_in_txn(wtxn, &mut budget, child_attempt, units, now)
        })
    }

    /// Keeps a measured charge whose settlement failed owed on its child's
    /// reservation (FIX 8728), never refunded: the reservation's next
    /// settlement or abort charges it.
    pub(crate) fn owe_unsettled_charge(&self, input: &SettleDreamerBudget) -> Result<()> {
        validate_budget_id(&input.budget_id)?;
        self.vault.with_write_txn(|wtxn| {
            let mut budget = self.owing_budget_in_txn(wtxn, &input.budget_id)?;
            self.owe_usage_in_txn(
                wtxn,
                &mut budget,
                input.child_attempt,
                input.actual_units,
                input.now,
            )
        })
    }

    /// The counter row owed spend lands on.
    fn owing_budget_in_txn(
        &self,
        wtxn: &heed::RwTxn<'_>,
        budget_id: &str,
    ) -> Result<DreamerBudgetRecord> {
        let Some(budget) = BUDGET.get(&self.vault.store, wtxn, &budget_id.to_owned())? else {
            return Err(invalid_dreamer_runner(
                "dreamer owed spend names no budget counter",
            ));
        };
        if budget.budget_id != budget_id {
            return Err(invalid_dreamer_runner("dreamer budget key/body mismatch"));
        }
        Ok(budget)
    }

    /// `units` owed by `child_attempt`, on its reservation when one is held,
    /// else charged to `budget` at once; `budget` is written either way.
    fn owe_usage_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        budget: &mut DreamerBudgetRecord,
        child_attempt: AttemptId,
        units: u64,
        now: u64,
    ) -> Result<()> {
        if let Some(mut reservation) =
            read_budget_reservation_in_txn(self.vault, wtxn, &budget.budget_id, child_attempt)?
        {
            reservation.owed_units = reservation
                .owed_units
                .checked_add(units)
                .ok_or(Error::ArithmeticOverflow("dreamer budget owed units"))?;
            reservation.updated_at = reservation.updated_at.max(now);
            validate_budget_reservation(&reservation)?;
            let key = BudgetReservationKey {
                budget_id: reservation.budget_id.clone(),
                attempt_id: reservation.attempt_id,
            };
            BUDGET_RESERVATION.put(&self.vault.store, wtxn, &key, &reservation)?;
        } else {
            let free = budget.remaining_units;
            charge_beyond_free(budget, free, units)?;
            crate::dreamer_runner::charge_free_time_item_in_txn(
                self.vault,
                wtxn,
                child_attempt,
                units,
            )?;
        }
        budget.updated_at = budget.updated_at.max(now);
        validate_budget_record(budget)?;
        put_budget_record_in_txn(self.vault, wtxn, budget)
    }
}

/// Settles `reservation` on `budget` with `actual_units` and what the
/// reservation already owed: the unspent rest is refunded, and spend past
/// the reservation is charged even beyond what remains (FIX 8702).
pub(super) fn settle_budget_for_child(
    budget: &mut DreamerBudgetRecord,
    reservation: DreamerBudgetReservation,
    actual_units: u64,
    now: u64,
) -> Result<DreamerBudgetSettlement> {
    validate_budget_reservation(&reservation)?;
    if reservation.budget_id != budget.budget_id {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation targets a different counter",
        ));
    }
    if reservation.reserved_units > budget.reserved_units {
        return Err(invalid_dreamer_runner(
            "dreamer budget reservation exceeds reserved units",
        ));
    }

    let actual_units = actual_units
        .checked_add(reservation.owed_units)
        .ok_or(Error::ArithmeticOverflow("dreamer budget owed units"))?;
    let refunded_units = reservation.reserved_units.saturating_sub(actual_units);
    let over_reserved_units = actual_units.saturating_sub(reservation.reserved_units);
    let free_after_refund = budget
        .remaining_units
        .checked_add(refunded_units)
        .ok_or(Error::ArithmeticOverflow("dreamer budget refund units"))?;

    budget.reserved_units -= reservation.reserved_units;
    charge_beyond_free(budget, free_after_refund, over_reserved_units)?;
    budget.updated_at = now;
    validate_budget_record(budget)?;

    Ok(DreamerBudgetSettlement {
        budget: budget.clone(),
        reservation,
        actual_units,
        refunded_units,
        over_reserved_units,
    })
}

/// Charges `units` against `free` units on `budget`: free units first pay
/// the overdraft and the new spend, and what they cannot pay is carried as
/// the overdraft (FIX 8702), so nothing incurred is ever refused.
fn charge_beyond_free(budget: &mut DreamerBudgetRecord, free: u64, units: u64) -> Result<()> {
    let owed = budget
        .overdraft_units
        .checked_add(units)
        .ok_or(Error::ArithmeticOverflow("dreamer budget overdraft units"))?;
    let paid = free.min(owed);
    budget.remaining_units = free - paid;
    budget.overdraft_units = owed - paid;
    Ok(())
}
