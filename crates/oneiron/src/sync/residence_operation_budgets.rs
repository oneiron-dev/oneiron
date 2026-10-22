//! Resolved holder-side residence operation budgets.
//!
//! Budgets come from the live vault policy manifest. A trusted vault row
//! replaces the shipped defaults it names; a holder row only narrows its vault
//! row (FIX 8783). The counts are work slices, never admission ceilings.
//! Malformed loaded policy returns `None` so callers cannot silently fall back
//! to unbounded operation defaults.

use crate::error::Result;
use crate::gate::ResidenceOperationBudgetLimits;
use crate::vault::Vault;

/// Effective residence operation caps resolved from the live vault manifest.
///
/// All fields are positive. Manifest values resolve field by field against
/// the shipped defaults, with holder values never widening the vault's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResidenceOperationBudgets {
    /// Timeout for one residence RPC, in milliseconds.
    pub rpc_timeout_ms: u64,
    /// Entries requested in one index page: a work slice.
    pub index_page_limit: usize,
    /// Index pages one operation reads before it yields: a work slice.
    pub max_index_pages: usize,
    /// Number of current residence windows indexed on first join.
    pub current_window_count: usize,
    /// Maximum title characters retained in index metadata.
    pub title_max_chars: usize,
    /// Maximum query input bytes accepted by home search.
    pub search_query_max_bytes: usize,
    /// Search results one page carries: a work slice.
    pub search_limit: usize,
    /// Candidate overfetch factor for explicitly partial offline search.
    pub offline_candidate_multiplier: usize,
    /// Timeout while waiting for a residence acknowledgement, in milliseconds.
    pub ack_timeout_ms: u64,
    /// Index cache bytes past which the home asks its retained-memory row.
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
            search_query_max_bytes: limits.search_query_max_bytes,
            search_limit: limits.search_limit,
            offline_candidate_multiplier: limits.offline_candidate_multiplier,
            ack_timeout_ms: limits.ack_timeout_ms,
            index_cache_bytes: limits.index_cache_bytes,
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
    /// A missing row uses the shipped defaults. A trusted `vault` map replaces
    /// the defaults it names, and a `holder` map cannot widen the vault map.
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
