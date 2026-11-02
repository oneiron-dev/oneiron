//! The vault a configured decision reader serves, bound once the AI host builds its
//! runtime over that vault: where a third-party rung's catalog price is read (FIX 11408),
//! and the chat-reply line its tokenizer's JSON replies are read whole on (FIX 11412). A
//! reader no host bound prices nothing and reads on no line, as before.

use std::sync::{Arc, OnceLock, Weak};

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
    /// What `model` costs per thousand units it reads, from its registry row's input price
    /// per million, as a durable generated read prices its model (FIX 11305); none when the
    /// vault is gone, the row names no price, or the price names no currency (FIX 11778:
    /// unknown never prices).
    pub(super) fn cost_per_thousand(&self, model: &ModelId) -> Option<f64> {
        let vault = self.vault.upgrade()?;
        let row = vault.model_registry_row(model).ok().flatten()?;
        let cost = row.catalog.cost.as_ref()?;
        if cost.currency.is_none() {
            return None;
        }
        let per_million: f64 = cost.input_per_million.parse().ok()?;
        (per_million.is_finite() && per_million >= 0.0).then(|| per_million / 1_000.0)
    }
}
