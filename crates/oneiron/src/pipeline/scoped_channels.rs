use heed::RoTxn;

use crate::corpus::CorpusScope;
use crate::error::{Error, Result};

use super::builder::PipelineBuilder;
use super::channels::{
    execute_temporal, scoped_entity_channel_limit, scoped_vector_channel_limit,
    truncate_widened_channel_results_to_scope,
};
use super::filters::import_claim_gate_decisions_for_scores;
use super::types::{
    ClaimStatusGateCache, EntityMetadataCache, FacetMode, PipelineFilterConfig, RelMode,
    ScoredEntity, TemporalSearchConfig, WorldScope,
};

impl PipelineBuilder<'_> {
    pub(super) fn scoped_vector_results(
        &self,
        rtxn: &RoTxn<'_>,
        query: &[f32],
        requested: usize,
        filters: PipelineFilterConfig<'_>,
        metadata_cache: &mut EntityMetadataCache,
        claim_gate: &mut ClaimStatusGateCache,
    ) -> Result<Vec<ScoredEntity>> {
        // EMB-2: full and fast-dimension prefix queries keep the same validation.
        if query.len() != self.vault.config.dimensions
            && self.vault.config.fast_dims.map(usize::from) != Some(query.len())
        {
            return Err(Error::DimensionMismatch {
                expected: self.vault.config.dimensions,
                got: query.len(),
            });
        }
        if let Some(error) = Error::invalid_vector_component(query) {
            return Err(error);
        }
        let codebase_scope_active = self.has_codebase_scope_filter();
        let corpus_scope_active = filters.corpus_scope != &CorpusScope::All;
        // Fetch the indexed population, not a fixed overfetch factor: arbitrarily
        // many excluded top hits must not hide an eligible lower hit.
        let channel_limit = scoped_vector_channel_limit(
            &self.vault.store,
            rtxn,
            requested,
            codebase_scope_active || corpus_scope_active,
        )?;
        let mut scores = crate::hnsw::hnsw_search(
            &self.vault.store,
            &self.vault.config,
            rtxn,
            query,
            channel_limit,
            self.skip_vector_rescore,
        )?;
        self.truncate_corpus_channel(
            &mut scores,
            rtxn,
            requested,
            filters,
            metadata_cache,
            claim_gate,
        )?;
        Ok(scores)
    }

    pub(super) fn scoped_temporal_results(
        &self,
        rtxn: &RoTxn<'_>,
        config: &TemporalSearchConfig,
        now: u64,
        filters: PipelineFilterConfig<'_>,
        metadata_cache: &mut EntityMetadataCache,
        claim_gate: &mut ClaimStatusGateCache,
    ) -> Result<Vec<ScoredEntity>> {
        let mut scoped_config = config.clone();
        scoped_config.limit = scoped_entity_channel_limit(
            &self.vault.store,
            rtxn,
            config.limit,
            self.has_codebase_scope_filter() || filters.corpus_scope != &CorpusScope::All,
        )?;
        // Widen before the temporal collector's scan caps and score truncation.
        let mut scores =
            execute_temporal(&self.vault.store, rtxn, &scoped_config, now, metadata_cache)?;
        self.truncate_corpus_channel(
            &mut scores,
            rtxn,
            config.limit,
            filters,
            metadata_cache,
            claim_gate,
        )?;
        Ok(scores)
    }

    fn truncate_corpus_channel(
        &self,
        scores: &mut Vec<ScoredEntity>,
        rtxn: &RoTxn<'_>,
        requested: usize,
        filters: PipelineFilterConfig<'_>,
        metadata_cache: &mut EntityMetadataCache,
        claim_gate: &mut ClaimStatusGateCache,
    ) -> Result<()> {
        if filters.corpus_scope == &CorpusScope::All || requested == 0 {
            return Ok(());
        }
        // Codebase retrieval already carries the widened list into fusion. Keep
        // that convention when both scopes are selected; only remove ineligible
        // rows. Corpus-only retrieval restores the caller's channel bound.
        let retained_limit = if self.has_codebase_scope_filter() {
            scores.len()
        } else {
            requested
        };
        // As with text prefix probes, rejected probe rows must not inflate pack
        // suppression stats. Import only the candidates that enter fusion.
        let mut probe_gate = ClaimStatusGateCache::default();
        // Reuse known decisions from earlier channels in this read transaction,
        // including suppressed claims, without importing probe-only decisions.
        for scored in scores.iter() {
            if let Some(decision) = claim_gate.decisions.get(&scored.id) {
                probe_gate.decisions.insert(scored.id, decision.clone());
            }
        }
        truncate_widened_channel_results_to_scope(
            scores,
            &self.vault.store,
            rtxn,
            retained_limit,
            filters,
            metadata_cache,
            &mut probe_gate,
        )?;
        import_claim_gate_decisions_for_scores(claim_gate, &mut probe_gate, scores);
        Ok(())
    }

    pub(super) fn has_codebase_scope_filter(&self) -> bool {
        self.repo_ref_filter.is_some() || self.project_id_filter.is_some()
    }

    pub(super) fn has_strict_text_scope_filter(&self) -> bool {
        self.type_filter.is_some()
            || self.since_filter.is_some()
            || self.occurred_range.is_some()
            || self.learned_range.is_some()
            || matches!(self.facet_filter, Some((_, FacetMode::Strict)))
            || matches!(self.relationship_filter, Some((_, RelMode::Filter)))
            || self.world_scope != WorldScope::All
            || self.corpus_scope != CorpusScope::All
    }
}
