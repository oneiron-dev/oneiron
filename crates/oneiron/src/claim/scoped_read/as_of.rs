//! Bitemporal ledger reads under the same authority and admission as lexical reads.
use super::*;

impl ScopedRead<'_> {
    /// Claims valid at `valid_at`, known by `learned_at`. Historical lookup does
    /// not bypass consent, current disclosure authority, or closed-claim admission.
    pub fn search_claims_as_of(
        &self,
        valid_at: u64,
        learned_at: u64,
        limit: usize,
    ) -> Result<Vec<ScoredEntity>> {
        let (filter, policy) = self.resolve_retrieval_filter(None)?;
        if filter.deny_all || limit == 0 {
            return Ok(Vec::new());
        }
        let fetch = self
            .vault
            .scoped_read_search_candidate_limit(limit, false, false)?;
        let results = self
            .vault
            .query()
            .authority_filter(filter.clone())
            .search_temporal_bitemporal(valid_at, valid_at, 0, learned_at, 1, fetch)
            .temporal_adaptive(false)
            .filter_types(&[ENTITY_TYPE_CLAIM])
            .filter_occurred_range(valid_at, valid_at)
            .filter_learned_range(0, learned_at)
            .limit(fetch)
            .run()?;
        self.filter_search_results(results, limit, &filter, &policy)
    }
}
