//! The text channel: the D19 claim-gate widening probe, the scoped BM25 search, and the HyDE-retry extra queries.

use super::admit::{AdmitSignal, ChannelAccumulator};
use super::turn_fold;
use crate::bm25::Bm25Config;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::pipeline::builder::PipelineBuilder;
use crate::pipeline::channels::{fusion_fetch_limit, truncate_widened_channel_results_to_scope};
use crate::pipeline::execution::types::HydeAttemptOverrides;
use crate::pipeline::filters::{
    claim_status_gate_allows, import_claim_gate_decisions_for_scores,
    pipeline_candidate_matches_filters_and_gate,
};
use crate::pipeline::types::{
    ClaimStatusGateCache, EntityMetadataCache, PER_SCAN_CAP_FACTOR, PipelineFilterConfig,
    ScoredEntity, TurnFold,
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
    pub(super) private_note_ids: Option<&'a crate::claim::ScopedDiaryCandidates>,
    /// The D19 widening probe's gate cache, moved in and reused as the
    /// exact-posting probe gate.
    pub(super) claim_gate_widening_probe: ClaimStatusGateCache,
}

impl TextChannelInputs<'_> {
    /// Whether a scan scores only the postings the run's scope admits: a
    /// caller's candidate filter, or any scope that once widened the fetch to
    /// the whole index. An excluded posting then takes no place in the bound.
    fn filters_every_posting(&self, run: &PipelineBuilder<'_>) -> bool {
        run.candidate_filter.is_some() || self.text_scope_widening_active
    }

    /// The metadata cache a scan's scope check fills. A scan that checks
    /// every posting reads in a cache of its own, so the run's cache holds
    /// no corpus-sized memo and counts no posting the scan passed.
    fn scan_metadata<'c>(
        &self,
        run: &PipelineBuilder<'_>,
        metadata_cache: &'c mut EntityMetadataCache,
        scan_metadata: &'c mut EntityMetadataCache,
    ) -> &'c mut EntityMetadataCache {
        if self.filters_every_posting(run) && run.candidate_filter.is_none() {
            scan_metadata
        } else {
            metadata_cache
        }
    }
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
            && !self.deadline_reached()
            && *limit > 0
            && self.candidate_filter.is_none()
        {
            let text_query = hyde_expansion.as_ref().map_or(query.as_str(), |expansion| {
                expansion.grounded_query.as_str()
            });
            // A posting a device-local world keeps is no posting of this
            // run: it neither fails the gate nor matches the scope.
            let exact_posting_fails_claim_gate = {
                let mut exact_posting_fails_claim_gate = |id: &EntityId| {
                    if claim_gate_widening_probe.keeps_device_local(&self.read, rtxn, id)? {
                        return Ok(false);
                    }
                    claim_status_gate_allows(
                        &self.read,
                        rtxn,
                        id,
                        metadata_cache,
                        claim_gate_widening_probe,
                    )
                    .map(|allowed| !allowed)
                };
                crate::bm25::final_token_exact_posting_matches(
                    &self.read,
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
                    if claim_gate_widening_probe.keeps_device_local(&self.read, rtxn, id)? {
                        return Ok(crate::bm25::PrefixExpansionPostingDecision {
                            matches_scope: false,
                            rejected_by_gate: false,
                        });
                    }
                    let rejected_by_gate = !claim_status_gate_allows(
                        &self.read,
                        rtxn,
                        id,
                        metadata_cache,
                        claim_gate_widening_probe,
                    )?;
                    let matches_scope = !rejected_by_gate
                        && pipeline_candidate_matches_filters_and_gate(
                            &self.read,
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
                    &self.read,
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

    /// Runs the text channel, the next of `stages_left` deadline stages, and
    /// its HyDE-retry extra queries, admitting each into `acc`. Returns the
    /// index the primary text list took in the ranked lists, `None` when no
    /// text search is configured or the deadline cut it.
    #[expect(
        clippy::too_many_arguments,
        reason = "the stage count rides beside the channel's existing inputs"
    )]
    pub(super) fn run_text_channel(
        &self,
        rtxn: &RoTxn<'_>,
        stages_left: usize,
        mut inputs: TextChannelInputs<'_>,
        acc: &mut ChannelAccumulator,
        diagnostics: &mut RetrievalDiagnostics,
        metadata_cache: &mut EntityMetadataCache,
        claim_gate: &mut ClaimStatusGateCache,
    ) -> Result<Option<usize>> {
        let mut text_channel_index = None;
        let prefix_probe_claim_gate = std::mem::take(&mut inputs.claim_gate_widening_probe);
        let text_search = self
            .text_search
            .as_ref()
            .map(|(query, limit)| (query.as_str(), fusion_fetch_limit(*limit)));
        if let Some((query, limit)) = &text_search
            && let Some(text_results) =
                self.run_stage(RetrievalSignal::Text, stages_left, || {
                    self.text_stage(
                        rtxn,
                        (query, *limit),
                        &inputs,
                        prefix_probe_claim_gate,
                        (metadata_cache, claim_gate),
                    )
                })?
        {
            diagnostics.succeeded.push(RetrievalSignal::Text);
            text_channel_index = Some(acc.admit_channel(
                RetrievalSignal::Text,
                text_results,
                &self.read,
                rtxn,
                inputs.filter_config,
                metadata_cache,
            )?);
            for query in inputs.overrides.extra_text_queries {
                if self.deadline_reached() {
                    break;
                }
                let retry_scoped_text_limit = self.text_channel_limit(retry_channel_limit(*limit));
                let retry_text_channel_limit = if inputs.recency.is_some() {
                    self.text_channel_limit(
                        retry_scoped_text_limit.max(limit.saturating_mul(PER_SCAN_CAP_FACTOR)),
                    )
                } else {
                    retry_scoped_text_limit
                };
                let filter_all = inputs.filters_every_posting(self);
                let mut retry_prefix_probe_claim_gate =
                    claim_gate.fresh(inputs.authority_filter.include_stale);
                let mut scan_metadata = EntityMetadataCache::default();
                let retry_metadata = inputs.scan_metadata(self, metadata_cache, &mut scan_metadata);
                let mut retry_exact_posting_matches_scope = |id: &EntityId| {
                    pipeline_candidate_matches_filters_and_gate(
                        &self.read,
                        rtxn,
                        id,
                        inputs.filter_config,
                        retry_metadata,
                        &mut retry_prefix_probe_claim_gate,
                    )
                };
                let candidate_limit = if self.candidate_filter.is_some() {
                    retry_scoped_text_limit
                } else {
                    retry_text_channel_limit
                };
                let mut results = if self.memory_category {
                    self.search_text_candidates(
                        rtxn,
                        inputs.bm25_config,
                        (query, candidate_limit, filter_all),
                        crate::bm25::Bm25SearchOptions {
                            recency: None,
                            exact_posting_matches_scope: &mut retry_exact_posting_matches_scope,
                            private_note_ids: inputs.private_note_ids,
                        },
                    )?
                } else {
                    self.vault.text_scoped_in_txn(
                        &self.read,
                        rtxn,
                        crate::ports::TextQuery {
                            query,
                            limit: candidate_limit,
                            rank: inputs.bm25_config,
                            filter_all,
                            matches_scope: &mut retry_exact_posting_matches_scope,
                            private_note_ids: inputs.private_note_ids,
                        },
                    )?
                };
                if retry_text_channel_limit > *limit && inputs.text_scope_widening_active {
                    let scoped_result_limit = if inputs.recency.is_some() {
                        limit.saturating_mul(PER_SCAN_CAP_FACTOR)
                    } else {
                        *limit
                    };
                    self.truncate_widened_text_results(
                        &mut results,
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
                    &self.read,
                    rtxn,
                    inputs.filter_config,
                    metadata_cache,
                )?;
            }
        }
        Ok(text_channel_index)
    }
    /// The text stage itself: the scoped BM25 read, read on while folded
    /// turns are short, then cut to the run's own scope. Every candidate its
    /// scope gate reads is a deadline checkpoint.
    fn text_stage(
        &self,
        rtxn: &RoTxn<'_>,
        (query, limit): (&str, usize),
        inputs: &TextChannelInputs<'_>,
        mut prefix_probe_claim_gate: ClaimStatusGateCache,
        (metadata_cache, claim_gate): (&mut EntityMetadataCache, &mut ClaimStatusGateCache),
    ) -> Result<Vec<ScoredEntity>> {
        let scoped_text_limit = self.text_channel_limit(if inputs.overrides.widen_channel_limits {
            retry_channel_limit(limit)
        } else {
            limit
        });
        let text_channel_limit = if inputs.recency.is_some() {
            self.text_channel_limit(
                scoped_text_limit.max(limit.saturating_mul(PER_SCAN_CAP_FACTOR)),
            )
        } else {
            scoped_text_limit
        };
        let filter_all = inputs.filters_every_posting(self);
        // The bound below admits turns as the fold does, in caches of its
        // own: the scan closure holds the run's.
        let mut fold_claim_gate =
            prefix_probe_claim_gate.fresh(inputs.filter_config.authority_filter.include_stale);
        let mut scan_metadata = EntityMetadataCache::default();
        let stage_metadata = inputs.scan_metadata(self, metadata_cache, &mut scan_metadata);
        let mut exact_posting_matches_scope = |id: &EntityId| {
            pipeline_candidate_matches_filters_and_gate(
                &self.read,
                rtxn,
                id,
                inputs.filter_config,
                stage_metadata,
                &mut prefix_probe_claim_gate,
            )
        };
        let text_query = inputs
            .hyde_expansion
            .as_ref()
            .map_or(query, |expansion| expansion.grounded_query.as_str());
        let candidate_limit = if self.candidate_filter.is_some() {
            self.text_channel_limit(limit)
        } else {
            text_channel_limit
        };
        // A run that folds each MESSAGE into its TURN returns turns, so the
        // bound counts turns: several messages of one turn would otherwise
        // fill it and keep later conversations out. Such a run reads on,
        // up to `PER_SCAN_CAP_FACTOR` times the bound, until its rows hold
        // that many turns or the matches run out.
        let fold_cap = self.text_channel_limit(candidate_limit.saturating_mul(PER_SCAN_CAP_FACTOR));
        let mut fold_metadata = EntityMetadataCache::default();
        let mut fetch_limit = candidate_limit;
        let mut text_results = loop {
            let mut rows = if self.memory_category {
                self.search_text_candidates(
                    rtxn,
                    inputs.bm25_config,
                    (text_query, fetch_limit, filter_all),
                    crate::bm25::Bm25SearchOptions {
                        recency: None,
                        exact_posting_matches_scope: &mut exact_posting_matches_scope,
                        private_note_ids: inputs.private_note_ids,
                    },
                )?
            } else {
                self.vault.text_scoped_in_txn(
                    &self.read,
                    rtxn,
                    crate::ports::TextQuery {
                        query: text_query,
                        limit: fetch_limit,
                        rank: inputs.bm25_config,
                        filter_all,
                        matches_scope: &mut exact_posting_matches_scope,
                        private_note_ids: inputs.private_note_ids,
                    },
                )?
            };
            let exhausted = rows.len() < fetch_limit;
            if self.turn_fold == TurnFold::Off || (exhausted && fetch_limit == candidate_limit) {
                break rows;
            }
            if let Some(held) = turn_fold::rows_holding_distinct_turns(
                &rows,
                candidate_limit,
                self.turn_fold,
                &self.read,
                rtxn,
                inputs.filter_config,
                &mut fold_metadata,
                &mut fold_claim_gate,
            )? {
                rows.truncate(held);
                break rows;
            }
            if exhausted || fetch_limit >= fold_cap || self.deadline_reached() {
                break rows;
            }
            fetch_limit = fetch_limit.saturating_mul(2).min(fold_cap);
        };
        if self.candidate_filter.is_none()
            && text_channel_limit > limit
            && inputs.text_scope_widening_active
        {
            let scoped_result_limit = if inputs.recency.is_some() {
                limit.saturating_mul(PER_SCAN_CAP_FACTOR)
            } else {
                limit
            };
            self.truncate_widened_text_results(
                &mut text_results,
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
        Ok(text_results)
    }
    /// Keeps the rows of a widened text read that the run's own scope
    /// admits, up to `requested` results. A run that folds each MESSAGE into
    /// its TURN counts results as the fold leaves them, as the unwidened
    /// bound does ([`turn_fold::rows_holding_distinct_turns`]): several
    /// messages of one turn are one result, so they cannot crowd the next
    /// turn out. Like the unwidened read, it looks no further than
    /// `PER_SCAN_CAP_FACTOR` times the bound.
    fn truncate_widened_text_results(
        &self,
        rows: &mut Vec<ScoredEntity>,
        rtxn: &RoTxn<'_>,
        requested: usize,
        filter_config: PipelineFilterConfig<'_>,
        metadata_cache: &mut EntityMetadataCache,
        claim_gate: &mut ClaimStatusGateCache,
    ) -> Result<()> {
        let kept = if self.turn_fold == TurnFold::Off {
            requested
        } else {
            requested.saturating_mul(PER_SCAN_CAP_FACTOR)
        };
        truncate_widened_channel_results_to_scope(
            rows,
            &self.read,
            rtxn,
            kept,
            filter_config,
            metadata_cache,
            claim_gate,
        )?;
        if self.turn_fold != TurnFold::Off
            && let Some(held) = turn_fold::rows_holding_distinct_turns(
                rows,
                requested,
                self.turn_fold,
                &self.read,
                rtxn,
                filter_config,
                metadata_cache,
                claim_gate,
            )?
        {
            rows.truncate(held);
        }
        Ok(())
    }

    /// The memory lane's text read: every posting through the lane's kinds
    /// and, when `filter_all`, through the run's whole scope as well.
    fn search_text_candidates<F>(
        &self,
        rtxn: &RoTxn<'_>,
        config: &Bm25Config,
        (query, limit, filter_all): (&str, usize, bool),
        options: crate::bm25::Bm25SearchOptions<'_, F>,
    ) -> Result<Vec<crate::pipeline::ScoredEntity>>
    where
        F: FnMut(&EntityId) -> Result<bool>,
    {
        let in_category = |id: &EntityId| {
            super::super::super::capabilities::CapabilityLane::Memory.admits(&self.read, rtxn, id)
        };
        let mut matches_scope = |id: &EntityId| {
            if self.memory_category && !in_category(id)? {
                return Ok(false);
            }
            (options.exact_posting_matches_scope)(id)
        };
        let scope = crate::bm25::Bm25SearchOptions {
            recency: options.recency,
            exact_posting_matches_scope: &mut matches_scope,
            private_note_ids: options.private_note_ids,
        };
        if filter_all {
            crate::bm25::search_text_filtered_with_recency(
                &self.read,
                rtxn,
                &self.vault.analyzer,
                config,
                query,
                limit,
                scope,
            )
        } else if self.memory_category {
            // Category admission consumes no claim body. D19 decisions made by
            // prefix/widening probes remain reusable by fusion and projection.
            let mut category = |id: &EntityId| {
                super::super::super::capabilities::CapabilityLane::Memory
                    .admits(&self.read, rtxn, id)
            };
            crate::bm25::search_text_category_with_recency(
                &self.read,
                rtxn,
                &self.vault.analyzer,
                config,
                query,
                limit,
                crate::bm25::Bm25CategorySearchOptions {
                    scope,
                    category: &mut category,
                },
            )
        } else {
            crate::bm25::search_text_scoped_with_recency(
                &self.read,
                rtxn,
                &self.vault.analyzer,
                config,
                query,
                limit,
                scope,
            )
        }
    }
}
