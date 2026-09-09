//! The text channel: the D19 claim-gate widening probe, the scoped BM25 search, and the HyDE-retry extra queries.

use super::admit::{AdmitSignal, ChannelAccumulator};
use crate::bm25::Bm25Config;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::pipeline::builder::PipelineBuilder;
use crate::pipeline::channels::{
    scoped_text_channel_limit, truncate_widened_channel_results_to_scope,
};
use crate::pipeline::execution::types::HydeAttemptOverrides;
use crate::pipeline::filters::{
    claim_status_gate_allows, import_claim_gate_decisions_for_scores,
    pipeline_candidate_matches_filters_and_gate,
};
use crate::pipeline::types::{
    ClaimStatusGateCache, EntityMetadataCache, PER_SCAN_CAP_FACTOR, PipelineFilterConfig,
};
use crate::query_expansion::{HydeExpansion, retry_channel_limit};
use crate::retrieval_quality::RetrievalDiagnostics;
use crate::store::RetrievalSignal;
use heed::RoTxn;

/// What the text channel reads, plus the widening probe's gate cache it
/// consumes.
pub(super) struct TextChannelInputs<'a> {
    pub(super) bm25_config: &'a Bm25Config,
    pub(super) hyde_expansion: Option<&'a HydeExpansion>,
    pub(super) overrides: &'a HydeAttemptOverrides<'a>,
    pub(super) recency: Option<u64>,
    pub(super) filter_config: PipelineFilterConfig<'a>,
    pub(super) authority_filter: &'a crate::gate::ResolvedRetrievalFilter,
    pub(super) text_scope_widening_active: bool,
    /// The D19 widening probe's gate cache, moved in and reused as the
    /// exact-posting probe gate.
    pub(super) claim_gate_widening_probe: ClaimStatusGateCache,
}

impl PipelineBuilder<'_> {
    /// Whether D19 claim-gate rejections widen the text channel: the final
    /// query token has an exact posting the gate rejects, or a prefix
    /// expansion with both in-scope and gate-rejected postings.
    pub(super) fn claim_gate_text_widening_probe(
        &self,
        rtxn: &RoTxn<'_>,
        bm25_config: &Bm25Config,
        hyde_expansion: Option<&HydeExpansion>,
        filter_config: PipelineFilterConfig<'_>,
        metadata_cache: &mut EntityMetadataCache,
        claim_gate_widening_probe: &mut ClaimStatusGateCache,
    ) -> Result<bool> {
        let claim_gate_text_widening_active = if let Some((query, limit)) = &self.text_search
            && *limit > 0
            && self.candidate_filter.is_none()
        {
            let text_query = hyde_expansion.as_ref().map_or(query.as_str(), |expansion| {
                expansion.grounded_query.as_str()
            });
            let exact_posting_fails_claim_gate = {
                let mut exact_posting_fails_claim_gate = |id: &EntityId| {
                    claim_status_gate_allows(
                        &self.vault.store,
                        rtxn,
                        id,
                        metadata_cache,
                        claim_gate_widening_probe,
                    )
                    .map(|allowed| !allowed)
                };
                crate::bm25::final_token_exact_posting_matches(
                    &self.vault.store,
                    rtxn,
                    &self.vault.analyzer,
                    bm25_config,
                    text_query,
                    &mut exact_posting_fails_claim_gate,
                )?
            };
            if exact_posting_fails_claim_gate {
                true
            } else {
                let mut classify_prefix_posting = |id: &EntityId| {
                    let rejected_by_gate = !claim_status_gate_allows(
                        &self.vault.store,
                        rtxn,
                        id,
                        metadata_cache,
                        claim_gate_widening_probe,
                    )?;
                    let matches_scope = !rejected_by_gate
                        && pipeline_candidate_matches_filters_and_gate(
                            &self.vault.store,
                            rtxn,
                            id,
                            filter_config,
                            metadata_cache,
                            claim_gate_widening_probe,
                        )?;
                    Ok(crate::bm25::PrefixExpansionPostingDecision {
                        matches_scope,
                        rejected_by_gate,
                    })
                };
                crate::bm25::final_token_prefix_expansion_has_scoped_and_rejected_postings(
                    &self.vault.store,
                    rtxn,
                    &self.vault.analyzer,
                    bm25_config,
                    text_query,
                    &mut classify_prefix_posting,
                )?
            }
        } else {
            false
        };
        Ok(claim_gate_text_widening_active)
    }

    /// Runs the text channel and its HyDE-retry extra queries, admitting
    /// each into `acc`. Returns the index the primary text list took in the
    /// ranked lists, `None` when no text search is configured.
    pub(super) fn run_text_channel(
        &self,
        rtxn: &RoTxn<'_>,
        inputs: TextChannelInputs<'_>,
        acc: &mut ChannelAccumulator,
        diagnostics: &mut RetrievalDiagnostics,
        metadata_cache: &mut EntityMetadataCache,
        claim_gate: &mut ClaimStatusGateCache,
    ) -> Result<Option<usize>> {
        let mut text_channel_index = None;
        if let Some((query, limit)) = &self.text_search {
            let scoped_text_limit = scoped_text_channel_limit(
                &self.vault.store,
                rtxn,
                if inputs.overrides.widen_channel_limits {
                    retry_channel_limit(*limit)
                } else {
                    *limit
                },
                inputs.text_scope_widening_active,
            )?;
            let text_channel_limit = if inputs.recency.is_some() {
                scoped_text_limit.max(limit.saturating_mul(PER_SCAN_CAP_FACTOR))
            } else {
                scoped_text_limit
            };
            let mut prefix_probe_claim_gate = inputs.claim_gate_widening_probe;
            let mut exact_posting_matches_scope = |id: &EntityId| {
                pipeline_candidate_matches_filters_and_gate(
                    &self.vault.store,
                    rtxn,
                    id,
                    inputs.filter_config,
                    metadata_cache,
                    &mut prefix_probe_claim_gate,
                )
            };
            let text_query = inputs
                .hyde_expansion
                .as_ref()
                .map_or(query.as_str(), |expansion| {
                    expansion.grounded_query.as_str()
                });
            let search = if self.candidate_filter.is_some() {
                crate::bm25::search_text_filtered_with_recency
            } else {
                crate::bm25::search_text_scoped_with_recency
            };
            let mut text_results = search(
                &self.vault.store,
                rtxn,
                &self.vault.analyzer,
                inputs.bm25_config,
                text_query,
                if self.candidate_filter.is_some() {
                    *limit
                } else {
                    text_channel_limit
                },
                crate::bm25::Bm25SearchOptions {
                    recency: None,
                    exact_posting_matches_scope: &mut exact_posting_matches_scope,
                },
            )?;
            diagnostics.succeeded.push(RetrievalSignal::Text);
            if self.candidate_filter.is_none()
                && text_channel_limit > *limit
                && inputs.text_scope_widening_active
            {
                let scoped_result_limit = if inputs.recency.is_some() {
                    limit.saturating_mul(PER_SCAN_CAP_FACTOR)
                } else {
                    *limit
                };
                truncate_widened_channel_results_to_scope(
                    &mut text_results,
                    &self.vault.store,
                    rtxn,
                    scoped_result_limit,
                    inputs.filter_config,
                    metadata_cache,
                    &mut prefix_probe_claim_gate,
                )?;
            }
            import_claim_gate_decisions_for_scores(
                claim_gate,
                &mut prefix_probe_claim_gate,
                &text_results,
            );
            text_channel_index = Some(acc.admit_channel(
                RetrievalSignal::Text,
                text_results,
                &self.vault.store,
                rtxn,
                inputs.filter_config,
                metadata_cache,
            )?);
            for query in inputs.overrides.extra_text_queries {
                let retry_scoped_text_limit = scoped_text_channel_limit(
                    &self.vault.store,
                    rtxn,
                    retry_channel_limit(*limit),
                    inputs.text_scope_widening_active,
                )?;
                let retry_text_channel_limit = if inputs.recency.is_some() {
                    retry_scoped_text_limit.max(limit.saturating_mul(PER_SCAN_CAP_FACTOR))
                } else {
                    retry_scoped_text_limit
                };
                let mut retry_prefix_probe_claim_gate = ClaimStatusGateCache {
                    include_stale: inputs.authority_filter.include_stale,
                    ..ClaimStatusGateCache::default()
                };
                let mut retry_exact_posting_matches_scope = |id: &EntityId| {
                    pipeline_candidate_matches_filters_and_gate(
                        &self.vault.store,
                        rtxn,
                        id,
                        inputs.filter_config,
                        metadata_cache,
                        &mut retry_prefix_probe_claim_gate,
                    )
                };
                let mut results = crate::bm25::search_text_scoped_with_recency(
                    &self.vault.store,
                    rtxn,
                    &self.vault.analyzer,
                    inputs.bm25_config,
                    query,
                    retry_text_channel_limit,
                    crate::bm25::Bm25SearchOptions {
                        recency: None,
                        exact_posting_matches_scope: &mut retry_exact_posting_matches_scope,
                    },
                )?;
                if retry_text_channel_limit > *limit && inputs.text_scope_widening_active {
                    let scoped_result_limit = if inputs.recency.is_some() {
                        limit.saturating_mul(PER_SCAN_CAP_FACTOR)
                    } else {
                        *limit
                    };
                    truncate_widened_channel_results_to_scope(
                        &mut results,
                        &self.vault.store,
                        rtxn,
                        scoped_result_limit,
                        inputs.filter_config,
                        metadata_cache,
                        &mut retry_prefix_probe_claim_gate,
                    )?;
                }
                import_claim_gate_decisions_for_scores(
                    claim_gate,
                    &mut retry_prefix_probe_claim_gate,
                    &results,
                );
                acc.admit_channel(
                    AdmitSignal {
                        components: RetrievalSignal::Text,
                        trace: RetrievalSignal::HydeRetry,
                    },
                    results,
                    &self.vault.store,
                    rtxn,
                    inputs.filter_config,
                    metadata_cache,
                )?;
            }
        }
        Ok(text_channel_index)
    }
}
