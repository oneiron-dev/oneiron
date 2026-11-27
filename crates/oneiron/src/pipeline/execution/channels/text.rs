//! The text channel: the D19 claim-gate widening probe, the scoped BM25 search, and the HyDE-retry extra queries.

use super::admit::{AdmitSignal, ChannelAccumulator};
use super::turn_fold;
use crate::bm25::{Bm25Config, HiddenRowTest};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::pipeline::builder::PipelineBuilder;
use crate::pipeline::channels::fusion_fetch_limit;
use crate::pipeline::execution::types::HydeAttemptOverrides;
use crate::pipeline::filters::{
    allowed_set_withholds_row, claim_status_gate_allows, clamp_hides_row,
    clamp_hides_row_or_word_sources, import_claim_gate_decisions_for_scores,
    pipeline_candidate_matches_filters_and_gate,
};
use crate::pipeline::types::{
    ClaimStatusGateCache, EntityMetadataCache, PER_SCAN_CAP_FACTOR, PipelineFilterConfig,
    ScoredEntity, TurnFold, WorldAuthoritySet,
};
use crate::query_expansion::{HydeExpansion, retry_channel_limit};
use crate::retrieval_quality::RetrievalDiagnostics;
use crate::store::RetrievalSignal;
use heed::RoTxn;

mod truncation;

/// How many rows the text channel fetches for a barred direct-match push: the window's whole
/// bound, not the fusion floor. The bar drops under-bar hits after the fold, so a push that
/// fetched only the floor's 80 rows would never see a passing claim ranked below 80
/// under-bar hits (REVIEW-10566/10567 round 2). Pull and no-bar recalls keep the floor; past
/// this bound the window still hides a passing claim.
const BARRED_PUSH_TEXT_WINDOW: usize = crate::memory::caps::MAX_SEARCH_LIMIT;

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
    /// The owner's ALLOWED-SET of an ActiveSet turn
    /// ([`crate::store::world_authority::ResolvedWorldAuthority::allowed_set`]),
    /// resolved once for the run; `None` under every other world scope.
    pub(super) world_allowed_set: Option<&'a WorldAuthoritySet>,
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
            // run: it neither fails the gate nor matches the scope. Nor is
            // one a clamped pack's audience could not read whatever its
            // status: the probe's rejections join the run's gate, so such a
            // dead claim would count as suppressed.
            let exact_posting_fails_claim_gate = {
                let mut exact_posting_fails_claim_gate = |id: &EntityId| {
                    if claim_gate_widening_probe.keeps_device_local(&self.read, rtxn, id)?
                        || clamp_hides_row(
                            &self.read,
                            rtxn,
                            id,
                            filter_config.disclosure,
                            metadata_cache,
                        )?
                    {
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
                    if claim_gate_widening_probe.keeps_device_local(&self.read, rtxn, id)?
                        || clamp_hides_row(
                            &self.read,
                            rtxn,
                            id,
                            filter_config.disclosure,
                            metadata_cache,
                        )?
                    {
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

    /// The own-row test of the run's BM25 statistics
    /// ([`crate::bm25::Bm25SearchOptions::hidden_row`]): a row the reader
    /// may not read whatever its status counts in none. That is a row a
    /// clamped pack's audience may not read (`filter_config.disclosure`), or
    /// one a world keeps from the reader (FIX
    /// WORLD-SCOPE-BM25-DF-COUNTS-HIDDEN-POSTINGS): a device-local world
    /// off this device (`filter_config.device_local`), a world outside the
    /// owner's ALLOWED-SET of an ActiveSet turn (`world_allowed_set`), or a
    /// world the run's scoped reader may not read
    /// ([`crate::claim::ScopedReadActorKey::world_withheld_rows_in`]: its
    /// verified credential's worlds and its holder's standing agent Grants).
    /// A run scored for a scoped read ([`Self::statistics_read`]) asks that
    /// read instead, which also hides every other row it refuses and counts
    /// nowhere ([`crate::claim::ScopedRead::withheld_row_test_in`]; FIX
    /// SCOPED-BM25-DF-COUNTS-NON-WORLD-REFUSED-POSTINGS).
    /// What the run only selects still counts: its types, corpus or
    /// category, a named world or world set, the worlds a turn chose inside
    /// its ALLOWED-SET, the worlds a read asked for (save, under a scoped
    /// read, a row with no count whatever its worlds, such as a NOTE, that
    /// those worlds leave out). `None` when nothing keeps a row from the
    /// reader.
    ///
    /// Each row it judges is a deadline checkpoint, as at the scope's
    /// admission: a term's document frequency asks it of every posting. It
    /// answers each row once across the stage's reads (the turn fold's
    /// longer reads ask again of the same postings).
    pub(super) fn hidden_row_test<'t>(
        &'t self,
        rtxn: &'t RoTxn<'_>,
        (filter_config, world_allowed_set): (
            PipelineFilterConfig<'t>,
            Option<&'t WorldAuthoritySet>,
        ),
        metadata: &'t mut EntityMetadataCache,
    ) -> Result<Option<HiddenRowTest<'t>>> {
        let clamp = filter_config.disclosure;
        let device_local = filter_config
            .device_local
            .filter(|flagged| !flagged.is_empty());
        let mut scoped = match self.statistics_read {
            Some(read) => Some(read.withheld_row_test_in(rtxn)?),
            None => None,
        };
        let reader = match (&scoped, self.statistics_reader_key()) {
            (None, Some(key)) => key.world_withheld_rows_in(self.vault, rtxn)?,
            _ => None,
        };
        if clamp.is_none()
            && device_local.is_none()
            && world_allowed_set.is_none()
            && reader.is_none()
            && scoped.is_none()
        {
            return Ok(None);
        }
        let mut answers = std::collections::HashMap::<EntityId, bool>::new();
        Ok(Some(Box::new(move |id: &EntityId| {
            if let Some(&hidden) = answers.get(id) {
                return Ok(hidden);
            }
            if let Some(deadline) = self.deadline {
                deadline.checkpoint()?;
            }
            let hidden = clamp_hides_row(&self.read, rtxn, id, clamp, metadata)?
                || match device_local {
                    Some(flagged) => {
                        crate::settings::device_local_keeps_among(&self.read, rtxn, flagged, id)?
                    }
                    None => false,
                }
                || match world_allowed_set {
                    Some(allowed) => allowed_set_withholds_row(&self.read, rtxn, id, allowed)?,
                    None => false,
                }
                || match &reader {
                    Some(withheld) => withheld.withholds_in(&self.read, rtxn, id)?,
                    None => false,
                }
                || match scoped.as_mut() {
                    Some(withheld) => withheld(id)?,
                    None => false,
                };
            answers.insert(*id, hidden);
            Ok(hidden)
        })))
    }

    /// Whether this run is a push the owner's bar judges by direct match
    /// (RECALL-CARRIER-THRESHOLD): a barred `start` or `carrier` on a vault with no embedder
    /// (or under an explicit direct-match row). Only such a run reads the text window whole
    /// ([`BARRED_PUSH_TEXT_WINDOW`]); pull and no-bar recalls never set the claims-only flag.
    fn barred_direct_match_push(&self) -> bool {
        self.recall_bar_claims_only
            && self
                .recall_bar
                .as_ref()
                .is_some_and(crate::memory::recall::bar::BarJudge::is_direct_match)
    }

    /// Runs the text channel, the next of `stages_left` deadline stages, and
    /// its HyDE-retry extra queries, admitting each into `acc`. Returns the
    /// index the primary text list took in the ranked lists, `None` when no
    /// text search is configured or the deadline cut it, and whether that
    /// primary scan exhausted its admitted matches without a window cut.
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
    ) -> Result<(Option<usize>, bool)> {
        let mut text_channel_index = None;
        let mut text_exhausted = false;
        let prefix_probe_claim_gate = std::mem::take(&mut inputs.claim_gate_widening_probe);
        let text_search = self
            .text_search
            .as_ref()
            .map(|(query, limit)| (query.as_str(), fusion_fetch_limit(*limit)));
        if let Some((query, limit)) = &text_search
            && let Some((text_results, exhausted, withheld)) =
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
            text_exhausted = exhausted;
            acc.clamped_at_fetch.extend(withheld);
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
                // A subquery asks the retry's bound, as the main query's
                // read does, and a strict scope's cut keeps it (REVIEW-10311).
                let retry_requested = retry_channel_limit(*limit);
                let retry_scoped_text_limit = self.text_channel_limit(retry_requested);
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
                let retry_withheld_gate = claim_gate.fresh(inputs.authority_filter.include_stale);
                let mut scan_metadata = EntityMetadataCache::default();
                let retry_metadata = inputs.scan_metadata(self, metadata_cache, &mut scan_metadata);
                let retry_filters = self.bounded_result_filters(inputs.filter_config);
                let mut retry_hidden_metadata = EntityMetadataCache::default();
                let mut retry_hidden_row = self.hidden_row_test(
                    rtxn,
                    (inputs.filter_config, inputs.world_allowed_set),
                    &mut retry_hidden_metadata,
                )?;
                let mut retry_exact_posting_matches_scope = |id: &EntityId| {
                    pipeline_candidate_matches_filters_and_gate(
                        &self.read,
                        rtxn,
                        id,
                        retry_filters,
                        retry_metadata,
                        &mut retry_prefix_probe_claim_gate,
                    )
                };
                let mut candidate_limit = if self.candidate_filter.is_some() {
                    retry_scoped_text_limit
                } else {
                    retry_text_channel_limit
                };
                if self.barred_direct_match_push() {
                    candidate_limit =
                        candidate_limit.max(self.text_channel_limit(BARRED_PUSH_TEXT_WINDOW));
                }
                let mut results = if self.memory_category {
                    self.search_text_candidates(
                        rtxn,
                        inputs.bm25_config,
                        (query, candidate_limit, filter_all),
                        crate::bm25::Bm25SearchOptions {
                            recency: None,
                            exact_posting_matches_scope: &mut retry_exact_posting_matches_scope,
                            private_note_ids: inputs.private_note_ids,
                            hidden_row: retry_hidden_row
                                .as_deref_mut()
                                .map(|hidden| hidden as &mut dyn FnMut(&EntityId) -> Result<bool>),
                        },
                        (
                            (inputs.filter_config, &retry_withheld_gate),
                            &mut acc.clamped_at_fetch,
                        ),
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
                            // FIX 9096 PART (blind P1 REVIEW-4502.md): the port
                            // BM25 must not pre-boost with the fixed
                            // table_default 0.35; the pipeline blends recency
                            // post-fusion on the non-port path instead.
                            recency: None,
                            hidden_row: retry_hidden_row
                                .as_deref_mut()
                                .map(|hidden| hidden as &mut dyn FnMut(&EntityId) -> Result<bool>),
                        },
                    )?
                };
                if retry_text_channel_limit > retry_requested && inputs.text_scope_widening_active {
                    let scoped_result_limit = if inputs.recency.is_some() {
                        retry_requested.max(limit.saturating_mul(PER_SCAN_CAP_FACTOR))
                    } else {
                        retry_requested
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
        Ok((
            text_channel_index,
            text_exhausted && inputs.overrides.extra_text_queries.is_empty(),
        ))
    }
    /// The text stage itself: the scoped BM25 read, read on while folded
    /// turns are short, then cut to the run's own scope. Every candidate its
    /// scope gate reads is a deadline checkpoint. Also returns the rows a
    /// clamped pack's read kept out of its window
    /// ([`Self::search_text_candidates`]).
    fn text_stage(
        &self,
        rtxn: &RoTxn<'_>,
        (query, limit): (&str, usize),
        inputs: &TextChannelInputs<'_>,
        mut prefix_probe_claim_gate: ClaimStatusGateCache,
        (metadata_cache, claim_gate): (&mut EntityMetadataCache, &mut ClaimStatusGateCache),
    ) -> Result<(Vec<ScoredEntity>, bool, Vec<EntityId>)> {
        // A HyDE retry asks for more rows than the first attempt; a strict
        // scope's cut below keeps that bound too (REVIEW-10311 round 1).
        let requested = if inputs.overrides.widen_channel_limits {
            retry_channel_limit(limit)
        } else {
            limit
        };
        let scoped_text_limit = self.text_channel_limit(requested);
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
        let withheld_gate =
            prefix_probe_claim_gate.fresh(inputs.filter_config.authority_filter.include_stale);
        let mut scan_metadata = EntityMetadataCache::default();
        let stage_metadata = inputs.scan_metadata(self, metadata_cache, &mut scan_metadata);
        let result_filters = self.bounded_result_filters(inputs.filter_config);
        let mut hidden_metadata = EntityMetadataCache::default();
        let mut hidden_row = self.hidden_row_test(
            rtxn,
            (inputs.filter_config, inputs.world_allowed_set),
            &mut hidden_metadata,
        )?;
        let mut exact_posting_matches_scope = |id: &EntityId| {
            pipeline_candidate_matches_filters_and_gate(
                &self.read,
                rtxn,
                id,
                result_filters,
                stage_metadata,
                &mut prefix_probe_claim_gate,
            )
        };
        let text_query = inputs
            .hyde_expansion
            .as_ref()
            .map_or(query, |expansion| expansion.grounded_query.as_str());
        let mut candidate_limit = if self.candidate_filter.is_some() {
            self.text_channel_limit(limit)
        } else {
            text_channel_limit
        };
        if self.barred_direct_match_push() {
            candidate_limit = candidate_limit.max(self.text_channel_limit(BARRED_PUSH_TEXT_WINDOW));
        }
        // A run that folds each MESSAGE into its TURN returns turns, so the
        // bound counts turns: several messages of one turn would otherwise
        // fill it and keep later conversations out. Such a run reads on,
        // up to `PER_SCAN_CAP_FACTOR` times the bound, until its rows hold
        // that many turns or the matches run out.
        let fold_cap = self.text_channel_limit(candidate_limit.saturating_mul(PER_SCAN_CAP_FACTOR));
        let mut fold_metadata = EntityMetadataCache::default();
        let mut fetch_limit = candidate_limit;
        // The rows the last read kept out of its window: a longer read for
        // folded turns places them anew.
        let mut withheld = Vec::new();
        let (mut text_results, mut text_exhausted) = loop {
            withheld.clear();
            let mut rows = if self.memory_category {
                self.search_text_candidates(
                    rtxn,
                    inputs.bm25_config,
                    (text_query, fetch_limit, filter_all),
                    crate::bm25::Bm25SearchOptions {
                        recency: None,
                        exact_posting_matches_scope: &mut exact_posting_matches_scope,
                        private_note_ids: inputs.private_note_ids,
                        hidden_row: hidden_row
                            .as_deref_mut()
                            .map(|hidden| hidden as &mut dyn FnMut(&EntityId) -> Result<bool>),
                    },
                    ((inputs.filter_config, &withheld_gate), &mut withheld),
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
                        // FIX 9096 PART (blind P1 REVIEW-4502.md): the port
                        // BM25 must not pre-boost with the fixed
                        // table_default 0.35; the pipeline blends recency
                        // post-fusion on the non-port path instead.
                        recency: None,
                        hidden_row: hidden_row
                            .as_deref_mut()
                            .map(|hidden| hidden as &mut dyn FnMut(&EntityId) -> Result<bool>),
                    },
                )?
            };
            let exhausted = rows.len() < fetch_limit;
            if self.turn_fold == TurnFold::Off || (exhausted && fetch_limit == candidate_limit) {
                break (rows, exhausted);
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
                break (rows, false);
            }
            if exhausted || fetch_limit >= fold_cap || self.deadline_reached() {
                break (rows, exhausted && !self.deadline_reached());
            }
            fetch_limit = fetch_limit.saturating_mul(2).min(fold_cap);
        };
        if self.candidate_filter.is_none()
            && text_channel_limit > requested
            && inputs.text_scope_widening_active
        {
            let scoped_result_limit = if inputs.recency.is_some() {
                requested.max(limit.saturating_mul(PER_SCAN_CAP_FACTOR))
            } else {
                requested
            };
            let before_truncate = text_results.len();
            self.truncate_widened_text_results(
                &mut text_results,
                rtxn,
                scoped_result_limit,
                inputs.filter_config,
                metadata_cache,
                &mut prefix_probe_claim_gate,
            )?;
            text_exhausted &= text_results.len() == before_truncate;
        }
        import_claim_gate_decisions_for_scores(
            claim_gate,
            &mut prefix_probe_claim_gate,
            &text_results,
        );
        Ok((text_results, text_exhausted, withheld))
    }

    /// The memory lane's text read: every posting through the lane's kinds
    /// and, when `filter_all`, through the run's whole scope as well, which
    /// asks a clamp first. Under a clamp, a row the audience could not read
    /// whatever its status takes no place in the read's `limit`; such rows
    /// come back in `withheld` while they fall inside the read's first
    /// `limit` places, as the clamped read ranks them (see the read). Through
    /// the whole scope a place is a row the scope admits, so a hidden row
    /// takes one, and counts, only when it meets every other check of the
    /// call ([`Self::clamp_withheld_row_counts`], in caches of its own, as
    /// `gate` is). The lane-only read gives every lane row a place, so the
    /// two reads can count different hidden rows, and a narrowed read still
    /// counts them (REVIEW-10311 rounds 1 and 2).
    fn search_text_candidates<F>(
        &self,
        rtxn: &RoTxn<'_>,
        config: &Bm25Config,
        (query, limit, filter_all): (&str, usize, bool),
        options: crate::bm25::Bm25SearchOptions<'_, F>,
        ((filters, gate), withheld): (
            (PipelineFilterConfig<'_>, &ClaimStatusGateCache),
            &mut Vec<EntityId>,
        ),
    ) -> Result<Vec<crate::pipeline::ScoredEntity>>
    where
        F: FnMut(&EntityId) -> Result<bool>,
    {
        let clamp = filters.disclosure;
        let in_category = |id: &EntityId| {
            super::super::super::capabilities::CapabilityLane::Memory.admits(&self.read, rtxn, id)
        };
        // The scope's test, asked by the read's prefix expansion and, in a
        // clamped pack's scan through the whole scope, by the lane's read.
        let in_scope = std::cell::RefCell::new(options.exact_posting_matches_scope);
        let mut matches_scope = |id: &EntityId| {
            if self.memory_category && !in_category(id)? {
                return Ok(false);
            }
            (*in_scope.borrow_mut())(id)
        };
        let scope = crate::bm25::Bm25SearchOptions {
            recency: options.recency,
            exact_posting_matches_scope: &mut matches_scope,
            private_note_ids: options.private_note_ids,
            hidden_row: options
                .hidden_row
                .map(|hidden| hidden as &mut dyn FnMut(&EntityId) -> Result<bool>),
        };
        if filter_all && !(self.memory_category && clamp.is_some()) {
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
            // Hidden rows that outrank a readable one would fill the window
            // and leave it only before the blend, cutting the readable row
            // out of the run (REVIEW-9980 round 1), so the clamp asks first:
            // of the row, and of the rows its words came from
            // (PACK-PRESELECT-CLAMP-ROW-ONLY-DISPLACES-READABLE-HIT).
            // Read best first, the pack counts a hidden row as withheld while
            // it falls among the first `limit` places the read judges; which
            // rows take a place is said at the test below. The read scores
            // with the audience's document frequencies, so those places
            // follow that ranking, not the unclamped one: a hidden row's own
            // words weigh more there than they would without the clamp. With
            // a port walk pending the read judges every posting in index
            // order, so there the places follow that order, not rank. Each
            // judged row under a clamp is a deadline checkpoint, as at the
            // scope's admission: a read past many hidden rows stops there.
            let mut clamp_metadata = EntityMetadataCache::default();
            let mut places = 0_usize;
            let mut category = |id: &EntityId| {
                if !super::super::super::capabilities::CapabilityLane::Memory
                    .admits(&self.read, rtxn, id)?
                {
                    return Ok(false);
                }
                if let Some(deadline) = self.deadline
                    && clamp.is_some()
                {
                    deadline.checkpoint()?;
                }
                let hidden = clamp_hides_row_or_word_sources(
                    self.vault,
                    &self.read,
                    rtxn,
                    id,
                    clamp,
                    &mut clamp_metadata,
                )?;
                // Through the whole scope, a place is a row the scope
                // admits: a hidden row takes one when it meets every other
                // check of the call.
                if filter_all {
                    if !hidden {
                        let admitted = (*in_scope.borrow_mut())(id)?;
                        places = places.saturating_add(usize::from(admitted));
                        return Ok(admitted);
                    }
                    if places < limit && self.clamp_withheld_row_counts(rtxn, id, filters, gate)? {
                        withheld.push(*id);
                        places = places.saturating_add(1);
                    }
                    return Ok(false);
                }
                if hidden && places < limit {
                    withheld.push(*id);
                }
                places = places.saturating_add(1);
                Ok(!hidden)
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
