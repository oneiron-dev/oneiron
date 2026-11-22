//! The owner's presses on a run-budget ask: his choice with the overdraft
//! cap he names, or the dollars he adds, answered and applied in one write.

use super::answers::add_funds_in_txn;
use super::forecast::forecast_add_funds_in_txn;
use super::*;

impl Vault {
    /// The owner's press on a run-budget ask (Engine ruling RUNBUDGET-OVERDRAFT):
    /// his `choice`, and for `overdraft` the cap he names (the default when
    /// `None`), answered and applied in one write, his proof revalidated in it.
    /// `continue_on_local` resumes the run on the local model the ask offered.
    /// The family's ask about a Dreamer try parked at its budget trap takes
    /// the same press (`budget_trap_ask`). Any other ask passes unchanged, for
    /// the generic answer door. The same answer again is a no-op.
    ///
    /// # Errors
    ///
    /// The owner refusal; an ask that is withdrawn, answered another way, or
    /// does not offer `choice`; a zero cap; storage errors.
    pub fn press_run_budget_ask(
        &self,
        owner: &AuthenticatedOwner,
        seq: u64,
        choice: RunBudgetChoice,
        cap_units: Option<u64>,
    ) -> Result<()> {
        if choice == RunBudgetChoice::AddFunds {
            return Err(add_funds_needs_amount());
        }
        let Some(asked) = self.decision_ask(seq)? else {
            return Ok(());
        };
        if super::super::is_budget_trap_ask(&asked) {
            return super::super::budget_trap_ask::press_budget_trap_ask(
                self, owner, seq, choice, cap_units,
            );
        }
        if asked_run(&asked).is_none() {
            return Ok(());
        }
        let resumed = self.with_write_txn_grouped(|txn| {
            let by = owner.revalidate_in_txn(self, txn)?;
            let ask = self
                .decision_ask_in_txn(txn, seq)?
                .ok_or_else(|| invalid("no such decision ask"))?;
            let root = asked_run(&ask).ok_or_else(|| invalid("not a run-budget ask"))?;
            let answer = DecisionAnswer::Choice(choice.token().to_owned());
            if !self.answer_owner_queue_ask_in_txn(txn, RUN_BUDGET_ASK_QUEUE, seq, by, answer)? {
                return Ok(None);
            }
            let resumed = match choice {
                RunBudgetChoice::StayParked => false,
                RunBudgetChoice::Overdraft => approve_overdraft_in_txn(
                    self,
                    txn,
                    root,
                    by,
                    seq,
                    cap_units.unwrap_or(RUN_BUDGET_DEFAULT_OVERDRAFT_UNITS),
                    self.store.clock.now_recorded_at(),
                )?,
                RunBudgetChoice::ContinueOnLocal => continue_on_local_in_txn(
                    self,
                    txn,
                    root,
                    by,
                    seq,
                    self.store.clock.now_recorded_at(),
                )?,
                RunBudgetChoice::AddFunds => return Err(add_funds_needs_amount()),
            };
            Ok(Some(resumed))
        })?;
        if let Some(resumed) = resumed {
            self.signal_decision_answer(seq);
            if resumed {
                self.store.notify_attempt_observers();
            }
        }
        Ok(())
    }

    /// The owner's `add_funds` press on a run-budget ask (owner ruling
    /// RUN-BUDGET-SPENT = B): the dollars he names, `amount_usd_micros`,
    /// answered and applied in one write, his proof revalidated in it. They
    /// buy whole units at the vault's USD quote, rounded down, and raise the
    /// held run's root scope for good; the run resumes, and each of its
    /// meters takes the units once. The family's ask about a Dreamer try
    /// parked at its budget trap takes the same press. Any other ask passes
    /// unchanged, for the generic answer door. The same answer again is a
    /// no-op.
    ///
    /// # Errors
    ///
    /// The owner refusal; an ask that is withdrawn, answered another way, or
    /// does not offer `add_funds`; a zero amount, or one that buys no whole
    /// unit; no USD price; storage errors.
    pub fn press_run_budget_add_funds(
        &self,
        owner: &AuthenticatedOwner,
        seq: u64,
        amount_usd_micros: u64,
    ) -> Result<()> {
        let Some(asked) = self.decision_ask(seq)? else {
            return Ok(());
        };
        if super::super::is_budget_trap_ask(&asked) {
            return super::super::budget_trap_ask::press_budget_trap_add_funds(
                self,
                owner,
                seq,
                amount_usd_micros,
            );
        }
        if let Some(root) = asked_forecast(&asked) {
            let added = self.with_write_txn_grouped(|txn| {
                let by = owner.revalidate_in_txn(self, txn)?;
                let answer = DecisionAnswer::Choice(RunBudgetChoice::AddFunds.token().to_owned());
                if !self.answer_owner_queue_ask_in_txn(
                    txn,
                    RUN_BUDGET_FORECAST_QUEUE,
                    seq,
                    by,
                    answer,
                )? {
                    return Ok(None);
                }
                forecast_add_funds_in_txn(self, txn, root, by, seq, amount_usd_micros).map(Some)
            })?;
            if let Some(added) = added {
                self.signal_decision_answer(seq);
                if added {
                    self.store.notify_attempt_observers();
                }
            }
            return Ok(());
        }
        if asked_run(&asked).is_none() {
            return Ok(());
        }
        let resumed = self.with_write_txn_grouped(|txn| {
            let by = owner.revalidate_in_txn(self, txn)?;
            let ask = self
                .decision_ask_in_txn(txn, seq)?
                .ok_or_else(|| invalid("no such decision ask"))?;
            let root = asked_run(&ask).ok_or_else(|| invalid("not a run-budget ask"))?;
            let answer = DecisionAnswer::Choice(RunBudgetChoice::AddFunds.token().to_owned());
            if !self.answer_owner_queue_ask_in_txn(txn, RUN_BUDGET_ASK_QUEUE, seq, by, answer)? {
                return Ok(None);
            }
            add_funds_in_txn(
                self,
                txn,
                root,
                by,
                seq,
                amount_usd_micros,
                self.store.clock.now_recorded_at(),
            )
            .map(Some)
        })?;
        if let Some(resumed) = resumed {
            self.signal_decision_answer(seq);
            if resumed {
                self.store.notify_attempt_observers();
            }
        }
        Ok(())
    }
}
