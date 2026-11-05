//! The vault a configured decision reader serves, bound once the AI host builds its
//! runtime over that vault: where a third-party rung's catalog price is read (FIX 11408),
//! and the chat-reply line its tokenizer's JSON replies are read whole on (FIX 11412). A
//! reader no host bound prices nothing and reads on no line, as before.

use std::sync::{Arc, OnceLock, Weak};

use oneiron::llm::LlmUsage;
use oneiron::llm::registry::catalog_usage_cost;
use oneiron::{ModelId, Vault};

use super::DecisionReadDoor;
use crate::models::ModelHostBudgets;

/// The served vault, shared by a door and the reader it was bound with.
pub(super) type HostSlot = Arc<OnceLock<ReaderHost>>;

/// The vault a reader's reads serve and that vault's model byte budgets.
pub(super) struct ReaderHost {
    vault: Weak<Vault>,
    pub(super) budgets: ModelHostBudgets,
}

impl DecisionReadDoor {
    /// Binds `vault`, whose model byte budgets are `budgets`, as the vault this door's
    /// configured reader serves. The first binding holds; a door a host built over its own
    /// reader binds nothing that reader reads.
    pub(crate) fn bind_host(&self, vault: &Arc<Vault>, budgets: &ModelHostBudgets) {
        let _ = self.host.set(ReaderHost {
            vault: Arc::downgrade(vault),
            budgets: budgets.clone(),
        });
    }
}

impl ReaderHost {
    /// The catalog-priced token cost per thousand logical readings of one question,
    /// including its retries. Missing prices or currency stay unknown (FIX 11778).
    pub(super) fn cost_per_thousand(&self, model: &ModelId, usage: &LlmUsage) -> Option<f64> {
        let vault = self.vault.upgrade()?;
        let row = vault.model_registry_row(model).ok().flatten()?;
        let cost = row.catalog.cost.as_ref()?;
        cost.currency.as_ref()?;
        let per_thousand = catalog_usage_cost(cost, usage).ok()? * 1_000.0;
        per_thousand.is_finite().then_some(per_thousand)
    }
}
