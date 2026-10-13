use heed::RoTxn;

use crate::corpus::CorpusScope;
use crate::error::{Error, Result};

use super::builder::PipelineBuilder;
use super::capabilities::CapabilityLane;
use super::channels::{
    execute_temporal, scoped_vector_channel_limit, truncate_widened_channel_results_to_scope,
};
use super::filters::import_claim_gate_decisions_for_scores;
use super::temporal_bound::{
    ReadableRows, execute_temporal_for_reader, scoped_temporal_channel_limit,
};
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
            codebase_scope_active
                || corpus_scope_active
                || filters.candidate_filter.is_some()
                || self.memory_category,
        )?;
        let mut scores = self.vault.scoped_vector_search_quality_in_txn(
            rtxn,
            query,
            channel_limit,
            self.skip_vector_rescore,
            claim_gate.private_note_ids.as_deref(),
        )?;
        self.truncate_corpus_channel(
            &mut scores,
            rtxn,
            requested,
            filters,
            false,
            (metadata_cache, claim_gate),
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
        scoped_config.widened = Some(scoped_temporal_channel_limit(
            &self.vault.store,
            rtxn,
            config.limit,
            self.has_codebase_scope_filter()
                || self.has_strict_text_scope_filter()
                || filters.corpus_scope != &CorpusScope::All
                || filters.candidate_filter.is_some()
                || self.memory_category,
        )?);
        // Widen the collector's window, scan caps and score truncation, not
        // the request sigma settles on.
        let Some(predicate) = filters.candidate_filter else {
            let mut scores = execute_temporal(
                &self.vault.store,
                rtxn,
                &scoped_config,
                now,
                metadata_cache,
                filters.deadline,
            )?;
            self.truncate_corpus_channel(
                &mut scores,
                rtxn,
                config.limit,
                filters,
                self.has_strict_text_scope_filter(),
                (metadata_cache, claim_gate),
            )?;
            return Ok(scores);
        };
        // Only rows the call's predicate admits count toward the rounds and
        // take places in the bound, and the walk below takes the bound's cut
        // as it reaches each row. The memory lane's kinds join the same
        // predicate, so no row past the cut is read for them.
        let reader = ReadableRows::new(predicate, filters.deadline);
        let (mut scores, cut) = execute_temporal_for_reader(
            &self.vault.store,
            rtxn,
            &scoped_config,
            now,
            metadata_cache,
            filters.deadline,
            &reader,
        )?;
        let memory = self.memory_category;
        let kept =
            |store: &crate::store::Store, txn: &RoTxn<'_>, id: &crate::EntityId| -> Result<bool> {
                Ok(cut.keeps(store, txn, id)?
                    && (!memory || CapabilityLane::Memory.admits(store, txn, id)?))
            };
        let filters = PipelineFilterConfig {
            candidate_filter: Some(&kept),
            ..filters
        };
        self.truncate_to_scope(
            &mut scores,
            rtxn,
            config.limit,
            filters,
            self.has_strict_text_scope_filter(),
            (metadata_cache, claim_gate),
        )?;
        Ok(scores)
    }

    fn truncate_corpus_channel(
        &self,
        scores: &mut Vec<ScoredEntity>,
        rtxn: &RoTxn<'_>,
        requested: usize,
        filters: PipelineFilterConfig<'_>,
        strict_scope: bool,
        caches: (&mut EntityMetadataCache, &mut ClaimStatusGateCache),
    ) -> Result<()> {
        if self.memory_category {
            super::capabilities::retain_memory_candidates(scores, &self.vault.store, rtxn)?;
        }
        self.truncate_to_scope(scores, rtxn, requested, filters, strict_scope, caches)
    }

    fn truncate_to_scope(
        &self,
        scores: &mut Vec<ScoredEntity>,
        rtxn: &RoTxn<'_>,
        requested: usize,
        filters: PipelineFilterConfig<'_>,
        strict_scope: bool,
        caches: (&mut EntityMetadataCache, &mut ClaimStatusGateCache),
    ) -> Result<()> {
        let (metadata_cache, claim_gate) = caches;
        if (!strict_scope
            && filters.corpus_scope == &CorpusScope::All
            && filters.candidate_filter.is_none())
            || requested == 0
        {
            if self.memory_category && !self.has_codebase_scope_filter() {
                scores.truncate(requested);
            }
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
        let mut probe_gate = claim_gate.fresh(filters.authority_filter.include_stale);
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
        self.authority_filter.is_some()
            || self.type_filter.is_some()
            || self.since_filter.is_some()
            || self.occurred_range.is_some()
            || self.learned_range.is_some()
            || matches!(self.facet_filter, Some((_, FacetMode::Strict)))
            || matches!(self.relationship_filter, Some((_, RelMode::Filter)))
            || self.world_scope != WorldScope::All
            || self.corpus_scope != CorpusScope::All
    }
}
