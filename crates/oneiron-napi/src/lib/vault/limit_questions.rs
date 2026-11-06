//! One raw vault's engine `[limits]` questions, kept for the host that opened it.
//!
//! The collector is installed on a vault `NapiVault::new` opened itself, outside the
//! SDK registry, and served back through the host getter. It keeps the last crossing
//! per actual `EngineLimit` identity: the row's key plus the two counts the question
//! carried. No actor, query, value, credential, or timestamp is kept. Storage is
//! bounded by the row enum itself, not by a count cap.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use napi_derive::napi;
use oneiron::Vault;
use oneiron::limit_ask::{EngineLimit, LimitAsk};

/// What one kept crossing is: the two counts the question carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LastCrossing {
    bound: u64,
    measured: u64,
}

/// Where one raw vault's engine rows ask (FIX 75).
///
/// `crossed` records under a short mutex and returns: no storage, no notified work,
/// no await, and no vault handle (so no reference cycle), as the `LimitAsk` contract
/// requires -- a question may arrive inside a write transaction.
#[derive(Debug, Default)]
pub(crate) struct NativeLimitCollector {
    last: Mutex<BTreeMap<EngineLimit, LastCrossing>>,
}

impl NativeLimitCollector {
    /// Installs a fresh collector on `vault` and returns the host's handle to it.
    pub(crate) fn install_on(vault: &Vault) -> Arc<Self> {
        let collector = Arc::new(Self::default());
        vault.set_limit_ask(collector.clone());
        collector
    }

    /// The kept crossings in row order, for the host getter.
    pub(crate) fn snapshot(&self) -> Vec<NativeLimitQuestion> {
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(row, crossing)| NativeLimitQuestion {
                row: row.key().to_owned(),
                bound: crossing.bound,
                measured: crossing.measured,
            })
            .collect()
    }
}

impl LimitAsk for NativeLimitCollector {
    fn crossed(&self, row: EngineLimit, bound: u64, measured: u64) {
        self.last
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(row, LastCrossing { bound, measured });
    }
    // `crossed_for_owner` keeps the default: the owner is not recorded.
}

/// One kept engine-row crossing, served to the host that opened the vault.
#[napi(object, object_from_js = false)]
pub struct NativeLimitQuestion {
    /// The `[limits]` row key that asked (for example `limits.embedding_dimensions`).
    pub row: String,
    /// What the row stood at for the work, exact.
    pub bound: u64,
    /// What the work measured, exact.
    pub measured: u64,
}
