//! The read side of run-budget asks: what the owner granted a run (its
//! overdraft, local route and added dollars), and the open asks
//! `GET /v1/ai/status` lists.

use super::*;

impl AgentDispatcher<'_> {
    /// The overdraft the owner approved for the run `attempt` belongs to (the
    /// root or any attempt of its run), or the units his added dollars bought
    /// it, while the run has not been held again: each of its meters takes
    /// its cap once. `None` with none approved.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn run_overdraft(&self, attempt: AttemptId) -> Result<Option<RunOverdraft>> {
        let txn = self.vault.store.env.read_txn()?;
        for key in self.run_keys_in_txn(&txn, attempt)? {
            if let Some(overdraft) = OVERDRAFT.get(&self.vault.store, &txn, &key)? {
                return Ok(Some(overdraft));
            }
        }
        Ok(None)
    }

    /// The free local chat model the owner chose to continue the run
    /// `attempt` belongs to on (the root or any attempt of its run), while the
    /// run has not been held again: each of its calls runs on that model
    /// alone, on its free route. `None` with none chosen.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn run_local_route(&self, attempt: AttemptId) -> Result<Option<ModelId>> {
        let txn = self.vault.store.env.read_txn()?;
        for key in self.run_keys_in_txn(&txn, attempt)? {
            if let Some(route) = LOCAL_ROUTE.get(&self.vault.store, &txn, &key)? {
                return Ok(route.chosen.is_some().then_some(route.model));
            }
        }
        Ok(None)
    }

    /// Every amount the owner added to the run `attempt` belongs to (the root
    /// or any attempt of its run), oldest first. Empty with none added.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn run_funds(&self, attempt: AttemptId) -> Result<Vec<RunFundsEntry>> {
        let txn = self.vault.store.env.read_txn()?;
        for key in self.run_keys_in_txn(&txn, attempt)? {
            if let Some(funds) = FUNDS.get(&self.vault.store, &txn, &key)? {
                return Ok(funds.entries);
            }
        }
        Ok(Vec::new())
    }

    /// The attempts a row keyed by the root of `attempt`'s run may sit under:
    /// `attempt` itself, then every attempt of its run.
    fn run_keys_in_txn(&self, txn: &heed::RoTxn<'_>, attempt: AttemptId) -> Result<Vec<AttemptId>> {
        let mut keys = vec![attempt];
        let queue = AttemptQueue::new(self.vault);
        let run = queue
            .get_in_txn(txn, attempt)?
            .and_then(|record| record.run_id);
        if let Some(run) = run {
            keys.extend(
                queue
                    .list_run_in_txn(txn, &run)?
                    .into_iter()
                    .map(|row| row.id),
            );
        }
        Ok(keys)
    }
}

/// Every open run-budget ask, oldest first: what `GET /v1/ai/status` shows.
///
/// # Errors
///
/// Storage errors.
pub fn run_budget_questions(vault: &Vault) -> Result<Vec<RunBudgetQuestion>> {
    let txn = vault.store.env.read_txn()?;
    let mut questions = Vec::new();
    for ask in vault.open_queue_asks_in_txn(&txn, RUN_BUDGET_ASK_QUEUE)? {
        let Some(run) = asked_run(&ask) else {
            continue;
        };
        let AnswerContract::Choice { options } = &ask.question.contract else {
            continue;
        };
        let choices: Vec<RunBudgetChoice> = options
            .iter()
            .filter_map(|token| RunBudgetChoice::of_token(token))
            .collect();
        let local_model = if choices.contains(&RunBudgetChoice::ContinueOnLocal) {
            LOCAL_ROUTE
                .get(&vault.store, &txn, &run)?
                .map(|route| route.model)
        } else {
            None
        };
        let add_funds_price = if choices.contains(&RunBudgetChoice::AddFunds) {
            run_funds_price_in_txn(vault, &txn, run)?
        } else {
            None
        };
        questions.push(RunBudgetQuestion {
            seq: ask.seq,
            run: crate::entity_id::bytes_to_hex_lower(run.as_bytes()),
            asked_at: ask.asked_at,
            choices,
            default_overdraft_units: RUN_BUDGET_DEFAULT_OVERDRAFT_UNITS,
            local_model,
            add_funds_price,
            projected_units: None,
            available_units: None,
        });
    }
    for ask in vault.open_queue_asks_in_txn(&txn, RUN_BUDGET_FORECAST_QUEUE)? {
        let Some(run) = asked_forecast(&ask) else {
            continue;
        };
        let Some(forecast) = FORECAST.get(&vault.store, &txn, &run)? else {
            continue;
        };
        let AnswerContract::Choice { options } = &ask.question.contract else {
            continue;
        };
        questions.push(RunBudgetQuestion {
            seq: ask.seq,
            run: crate::entity_id::bytes_to_hex_lower(run.as_bytes()),
            asked_at: ask.asked_at,
            choices: options
                .iter()
                .filter_map(|token| RunBudgetChoice::of_token(token))
                .collect(),
            default_overdraft_units: RUN_BUDGET_DEFAULT_OVERDRAFT_UNITS,
            local_model: None,
            add_funds_price: funds_price_in_txn(vault, &txn, &forecast.unit),
            projected_units: Some(forecast.expected_units),
            available_units: Some(forecast.available_units),
        });
    }
    questions.sort_by_key(|question| question.seq);
    Ok(questions)
}
