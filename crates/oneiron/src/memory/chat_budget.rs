//! Composition on the owner's budget (FIX 9951): when the owner has set a
//! budget for chat, the composer runs on a lease taken from it and settled
//! with what the composer reports it spent. With no budget set, the composer
//! runs exactly as before, on the caller's own lease if any.

use super::*;

use crate::llm::{BudgetGuard, BudgetLease};

impl Memory<'_> {
    /// Runs `composer` once for `request`. With `budget` set, the call holds
    /// a lease admitted from it for its whole run: settled with the tokens the
    /// composer reports, or released untouched when it fails. Without one,
    /// the composer gets `lease` as before. Light chat never reaches here, so
    /// it stays lease-free.
    ///
    /// # Errors
    /// `BUDGET_SPENT` when the owner's budget cannot admit the call; the
    /// composer's own error otherwise.
    pub(super) fn compose_on_budget(
        &self,
        composer: &dyn ChatComposer,
        request: &ChatComposeRequest<'_>,
        lease: Option<&BudgetLease>,
        budget: Option<&BudgetGuard>,
    ) -> MemoryResult<ComposedChatAnswer> {
        let Some(budget) = budget else {
            return composer.compose(request, lease);
        };
        let admitted = budget.admit().map_err(|denied| {
            MemoryError::new(
                MEMORY_CODE_BUDGET_SPENT,
                format!("the owner's chat budget refused the composition: {denied}"),
                &["Raise the chat budget, or ask at light depth for an extractive answer."],
            )
        })?;
        let composed = composer.compose(request, Some(&admitted.lease));
        match &composed {
            Ok(answer) => {
                // The spend is the composer's own report; settling never
                // takes back an answer the composer already gave.
                let _ = budget.settle_usage(&admitted.lease, u64::from(answer.tokens_used));
            }
            Err(_) => {
                let _ = budget.abort(&admitted.lease);
            }
        }
        composed
    }
}
