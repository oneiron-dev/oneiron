//! Native SDK host snapshots of the shared vault's engine-limit crossings.

use std::collections::BTreeMap;
use std::sync::{Mutex, Once};

use oneiron::Vault;
use oneiron::limit_ask::{EngineLimit, LimitAsk};

/// The latest crossing for one engine limit in an internally opened vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeLimitQuestion {
    /// The engine's configuration key for this limit.
    pub row: &'static str,
    /// The configured boundary that was crossed.
    pub bound: u64,
    /// The value measured at that crossing.
    pub measured: u64,
}

pub(crate) struct NativeLimitQuestions {
    crossings: Mutex<BTreeMap<EngineLimit, (u64, u64)>>,
    width_measured: Once,
}

impl Default for NativeLimitQuestions {
    fn default() -> Self {
        Self {
            crossings: Mutex::new(BTreeMap::new()),
            width_measured: Once::new(),
        }
    }
}

impl NativeLimitQuestions {
    pub(crate) fn measure_open(&self, vault: &Vault) {
        self.width_measured.call_once(|| {
            if let Ok(width) = u64::try_from(vault.embedding_dimensions()) {
                vault.measure_limit(EngineLimit::EmbeddingDimensions, width);
            }
        });
    }

    pub(crate) fn snapshot(&self) -> Vec<NativeLimitQuestion> {
        let crossings = self
            .crossings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crossings
            .iter()
            .map(|(row, (bound, measured))| NativeLimitQuestion {
                row: row.key(),
                bound: *bound,
                measured: *measured,
            })
            .collect()
    }
}

impl LimitAsk for NativeLimitQuestions {
    fn crossed(&self, row: EngineLimit, bound: u64, measured: u64) {
        self.crossings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(row, (bound, measured));
    }
}
