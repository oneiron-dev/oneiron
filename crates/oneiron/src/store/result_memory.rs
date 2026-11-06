//! Core half of `store::result_memory`: its store-layer items live in `oneiron_store::result_memory` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::result_memory::*;

use crate::limit_ask::{EngineLimit, LimitWatch};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

impl crate::Vault {
    /// Installs the process's result-memory pool on this vault, in place of
    /// the one it opened with. A run already open keeps the pool it drew on.
    pub fn set_result_memory(&self, pool: Arc<ResultMemoryPool>) {
        *self
            .store
            .result_memory
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = pool;
    }

    /// Opens one run's share of the installed pool.
    pub(crate) fn result_share(&self) -> ResultShare {
        let pool = Arc::clone(
            &self
                .store
                .result_memory
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        pool.share(
            self.limit_watch()
                .bound(EngineLimit::CodeResultSessionMemoryBytes),
        )
    }
}
