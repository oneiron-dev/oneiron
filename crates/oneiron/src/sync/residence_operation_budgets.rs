//! Resolved holder-side residence operation budgets.
//!
//! Budgets come from the live vault policy manifest. Trusted vault and holder
//! rows only narrow shipped defaults; a holder row is capped by its vault row.
//! Malformed loaded policy returns `None` so callers cannot silently fall back
//! to unbounded operation defaults.

use crate::error::Result;
use crate::gate::ResidenceOperationBudgetLimits;
use crate::vault::Vault;

/// Absolute memory ceiling for a per-connection residence index cache.
///
/// The shipped manifest default is half this value. This hard ceiling remains
/// in place even if the shipped default changes in a future release.
pub const MAX_RESIDENCE_INDEX_CACHE_BYTES: usize = 32 * 1024 * 1024;

/// Effective residence operation caps resolved from the live vault manifest.
///
/// All fields are positive. Manifest values are bounded and resolve
/// component-wise against the shipped defaults, with holder limits never
/// widening the vault-level caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResidenceOperationBudgets {
    /// Timeout for one residence RPC, in milliseconds.
    pub rpc_timeout_ms: u64,
    /// Maximum number of entries requested in one index page.
    pub index_page_limit: usize,
    /// Maximum number of index pages requested per operation.
    pub max_index_pages: usize,
    /// Number of current residence windows indexed on first join.
    pub current_window_count: usize,
    /// Maximum title characters retained in index metadata.
    pub title_max_chars: usize,
    /// Maximum search results returned by one operation.
    pub search_limit: usize,
    /// Timeout while waiting for a residence acknowledgement, in milliseconds.
    pub ack_timeout_ms: u64,
    /// Maximum bytes held by the residence index cache.
    pub index_cache_bytes: usize,
}

impl ResidenceOperationBudgets {
    /// Converts the gate resolver's fail-closed-safe effective limits.
    fn from_resolved(limits: ResidenceOperationBudgetLimits) -> Self {
        Self {
            rpc_timeout_ms: limits.rpc_timeout_ms,
            index_page_limit: limits.index_page_limit,
            max_index_pages: limits.max_index_pages,
            current_window_count: limits.current_window_count,
            title_max_chars: limits.title_max_chars,
            search_limit: limits.search_limit,
            ack_timeout_ms: limits.ack_timeout_ms,
            index_cache_bytes: limits
                .index_cache_bytes
                .min(MAX_RESIDENCE_INDEX_CACHE_BYTES),
        }
    }
}

impl Default for ResidenceOperationBudgets {
    fn default() -> Self {
        Self::from_resolved(ResidenceOperationBudgetLimits::default())
    }
}

impl Vault {
    /// Resolves the live holder-side residence limits from trusted manifests.
    ///
    /// A missing row uses the shipped defaults. Trusted `vault` and `holder`
    /// maps compose by minimum, and the holder map cannot widen the vault map.
    /// A malformed loaded manifest returns `Ok(None)`; callers must refuse the
    /// operation instead of substituting defaults. Storage errors are returned.
    pub fn residence_operation_budgets(&self) -> Result<Option<ResidenceOperationBudgets>> {
        let txn = self.store.env.read_txn()?;
        let policy = crate::gate::resolve_policy_manifest(&self.store, &txn)?;
        Ok(policy
            .residence_operation_budgets()
            .map(ResidenceOperationBudgets::from_resolved))
    }
}
