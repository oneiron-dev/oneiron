//! The vault's model byte budgets a ladder's chat replies are read on
//! (FIX 10626), kept beside its offers' rests, which every ladder of one
//! runtime shares.

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};

use oneiron::Vault;

use super::super::ModelHostBudgets;

impl super::OfferCooldowns {
    /// [`Self::in_vault`], its ladders' chat replies read on `budgets`, the
    /// vault's own.
    #[must_use]
    pub(crate) fn in_vault_with(vault: Arc<Vault>, budgets: ModelHostBudgets) -> Arc<Self> {
        Arc::new(Self {
            vault: Some(vault),
            fallbacks: RwLock::default(),
            health: Mutex::default(),
            probes: AtomicU64::new(0),
            health_changed: tokio::sync::watch::Sender::new(0),
            recovered: tokio::sync::watch::Sender::new(0),
            warmth: super::super::ladder::cache_warmth::CacheWarmth::default(),
            budgets,
            #[cfg(test)]
            waits_move: None,
        })
    }

    /// The budgets its ladders' chat replies are read on.
    pub(in crate::models) fn reply_budgets(&self) -> &ModelHostBudgets {
        &self.budgets
    }
}
