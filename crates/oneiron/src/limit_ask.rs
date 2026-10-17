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

    /// Work a host serves on this vault measured `measured` against `row`:
    /// past what the row is set to, the installed port is asked, and the
    /// bound is returned so the host can name the crossing. It never refuses;
    /// the host serves the work either way.
    pub fn measure_limit(&self, row: EngineLimit, measured: u64) -> Option<u64> {
        let watch = self.limit_watch();
        let bound = watch.bound(row);
        (measured > bound).then(|| {
            watch.crossed(row, bound, measured);
            bound
        })
    }

    /// This vault's engine rows.
    pub(crate) fn limit_watch(&self) -> &LimitWatch {
        &self.store.limit_watch
    }
}
