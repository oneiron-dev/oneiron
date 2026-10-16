//! The engine's `[limits]` rows and their question port, defined in
//! `oneiron-contracts`. One port is held per open vault, on its shared store
//! core, so every handle on the vault asks through it.

pub(crate) use oneiron_contracts::limit_ask::LimitWatch;
pub use oneiron_contracts::limit_ask::{EngineLimit, EngineLimits, LimitAsk};

use std::sync::Arc;

use crate::Vault;

impl Vault {
    /// Installs where this vault's engine `[limits]` rows ask when they are
    /// crossed (OF-520), in place of any port before it. A crossing still
    /// serves its work; with no port installed, it asks nobody.
    pub fn set_limit_ask(&self, ask: Arc<dyn LimitAsk>) {
        self.store.limit_watch.install(ask);
    }

    /// This vault's engine rows.
    pub(crate) fn limit_watch(&self) -> &LimitWatch {
        &self.store.limit_watch
    }
}
