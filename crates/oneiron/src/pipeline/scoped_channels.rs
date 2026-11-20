use std::cell::RefCell;

use heed::RoTxn;

use crate::corpus::CorpusScope;
use crate::error::{Error, Result};

use super::builder::PipelineBuilder;
use super::capabilities::CapabilityLane;
use super::channels::{
    execute_phonetic, execute_temporal, scoped_vector_channel_limit,
    truncate_widened_channel_results_to_scope,
};
use super::filters::{
    claim_status_gate_allows, import_claim_gate_decisions_for_scores, made_by_admits,
    pipeline_candidate_matches_filters_and_gate,
};
use super::temporal_bound::{
    ReadableRows, execute_temporal_for_reader, scoped_temporal_channel_limit,
};
use super::types::{
    ClaimStatusGateCache, EntityMetadataCache, FacetMode, PipelineFilterConfig, RelMode,
    ScoredEntity, SnapshotCandidateFilter, TemporalSearchConfig, WorldScope,
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
        let filters = self.bounded_result_filters(filters);
        let narrowed = self.has_codebase_scope_filter()
            || self.has_strict_text_scope_filter()
            || filters.corpus_scope != &CorpusScope::All
            || filters.candidate_filter.is_some()
            || filters.device_local.is_some()
            || self.memory_category;
        // A narrowed run's scope decides inside the walk, so however many
        // excluded rows rank above an eligible one, none takes its place; the
        // walk is one bounded window, and a short page is the answer. Its
        // caches are its own: a row the walk passes leaves no decision behind.
        let memory = self.memory_category;
        let probe = std::cell::RefCell::new((
            EntityMetadataCache::default(),
            claim_gate.fresh(filters.authority_filter.include_stale),
        ));
        let admits = |txn: &RoTxn<'_>, id: &crate::EntityId| -> Result<bool> {
            let (metadata, gate) = &mut *probe.borrow_mut();
            Ok(pipeline_candidate_matches_filters_and_gate(
                &self.read, txn, id, filters, metadata, gate,
            )? && (!memory || CapabilityLane::Memory.admits(&self.read, txn, id)?))
        };
        let admission: Option<&crate::hnsw::Admission<'_>> = narrowed.then_some(&admits);
        let mut scores = self.vault.scoped_vector_search_quality_in_txn(
            &self.read,
            rtxn,
            query,
            scoped_vector_channel_limit(requested, narrowed, self.result_limit()),
            self.skip_vector_rescore,
            (claim_gate.private_note_ids.as_deref(), admission),
        )?;
        self.truncate_corpus_channel(
            &mut scores,
            rtxn,
            requested,
            filters,
            false,
            (metadata_cache, claim_gate),
        )?;
        scores.truncate(requested);
        Ok(scores)
    }

    /// The phonetic channel under the call's scope. The sound match keeps
    /// the nearest few of its rows, so the call's predicate decides inside
    /// that cut ([`Self::phonetic_candidate_admits`]). Exact codes have no
    /// cut: the call's scope asks their hits once entity-type authority has
    /// narrowed the list ([`Self::retain_phonetic_hits_in_scope`]). The
    /// probe's caches are its own, as the vector walk's: a row the cut asks
    /// about leaves no decision behind.
    pub(super) fn scoped_phonetic_results(
        &self,
        rtxn: &RoTxn<'_>,
        codes: &[String],
        filters: PipelineFilterConfig<'_>,
        claim_gate: &ClaimStatusGateCache,
    ) -> Result<Vec<ScoredEntity>> {
        let mut metadata = EntityMetadataCache::default();
        let mut gate = claim_gate.fresh(filters.authority_filter.include_stale);
        let mut admits = |id: &crate::EntityId| {
            self.phonetic_candidate_admits(rtxn, id, filters, &mut metadata, &mut gate)
        };
        execute_phonetic(
            &self.read,
            rtxn,
            codes,
            &self.params,
            self.deadline,
            &mut admits,
        )
    }

    /// Whether a phonetic list that keeps only the nearest few of its rows
    /// admits `id` to them: the call's filters and gate, its memory lane,
    /// and its made_by predicate, which the post-blend filter applies after
    /// the cut. A row it refuses sets no nearest distance and takes no place
    /// under the cap (review #8107, both rounds). An unborn claim's class is
    /// its admitted body's source; under a candidate filter the gate judged
    /// the row in a cache of its own, so the body is read into `gate` here.
    pub(super) fn phonetic_candidate_admits(
        &self,
        rtxn: &RoTxn<'_>,
        id: &crate::EntityId,
        filters: PipelineFilterConfig<'_>,
        metadata: &mut EntityMetadataCache,
        gate: &mut ClaimStatusGateCache,
    ) -> Result<bool> {
        let scoped = pipeline_candidate_matches_filters_and_gate(
            &self.read, rtxn, id, filters, metadata, gate,
        )? && (!self.memory_category
            || CapabilityLane::Memory.admits(&self.read, rtxn, id)?);
        if !scoped {
            return Ok(false);
        }
        self.made_by_slice_admits(rtxn, id, metadata, gate)
    }

    /// Whether the call's `made_by` slice admits `id`. An unborn claim's
    /// class is its admitted body's source, read into `gate` when `gate` has
    /// not judged the row yet.
    pub(super) fn made_by_slice_admits(
        &self,
        rtxn: &RoTxn<'_>,
        id: &crate::EntityId,
        metadata: &mut EntityMetadataCache,
        gate: &mut ClaimStatusGateCache,
    ) -> Result<bool> {
        made_by_admits(&self.read, rtxn, id, self.made_by, || {
            if !gate.decisions.contains_key(id) {
                claim_status_gate_allows(&self.read, rtxn, id, metadata, gate)?;
            }
            Ok(gate
                .decisions
                .get(id)
                .and_then(Option::as_ref)
                .and_then(|body| body.made_by_class()))
        })
    }

    /// Keeps the rows of a result list no admission sliced (a PPR walk's,
    /// whose narrowed visibility asks the rest of the call's scope) that the
    /// call's `made_by` slice admits, before the list joins a blend. A row the
    /// slice drops takes no rank in the fusion, counts as no candidate and
    /// seeds no implicit expansion (REVIEW-9842). A walk's transit and an
    /// explicit seed stay as the run's shared scope has them. The run's
    /// claim gate judges each row first, as the D19 gate judges every row of
    /// these lists anyway (memoized), so its suppressions count as before;
    /// the slice's own refusal adds none, and an unborn claim's class is
    /// read from the body that gate admitted. A search list takes it only
    /// once the memory lane and entity-type authority have narrowed it, so
    /// the gate judges no row the D19 gate never would (round 2).
    pub(super) fn retain_made_by_slice(
        &self,
        rtxn: &RoTxn<'_>,
        results: &mut Vec<ScoredEntity>,
        metadata: &mut EntityMetadataCache,
        claim_gate: &mut ClaimStatusGateCache,
    ) -> Result<()> {
        if self.made_by == crate::provenance::made_by::MadeByPredicate::All {
            return Ok(());
        }
        let mut kept = Vec::with_capacity(results.len());
        for scored in std::mem::take(results) {
            claim_status_gate_allows(&self.read, rtxn, &scored.id, metadata, claim_gate)?;
            if self.made_by_slice_admits(rtxn, &scored.id, metadata, claim_gate)? {
                kept.push(scored);
            }
        }
        *results = kept;
        Ok(())
    }

    /// Keeps the rows of the phonetic code rung's list that the call's scope
    /// admits, before the list joins a blend. Its exact-code hits have no
    /// cut, so no admission asked them, and a hit outside the call's type,
    /// time, world, corpus, relationship or candidate filter counted as a
    /// candidate in scope, took a fusion rank and could seed an implicit
    /// expansion (PHONETIC-EXACT-HITS-UNSCOPED-BEFORE-BLEND). Each row is
    /// asked as a bounded channel's admission asks it, made_by slice
    /// included, in the run's caches: the D19 gate judges a row the scope
    /// admits as far as the gate, as it judges every row of the blend, so
    /// its suppression counts as before, and the bookkeeping of every later
    /// check is the post-blend filters' own. A row the candidate filter
    /// refuses is judged by nothing after it: this step adds no gate
    /// decision, no `read_suppressed` entry and no count for it. A claim
    /// that only a check after the gate refuses is judged by the gate first
    /// and its suppression counts, as at main's post-blend gate. The list
    /// takes this only once the memory lane and entity-type authority have
    /// narrowed it, so the gate judges no row of a kind the reader may not
    /// retrieve (REVIEW-9842 round 2). No deadline cuts it: admission always
    /// runs.
    ///
    /// A clamped pack's disclosure clamp is asked apart (REVIEW-9911 round
    /// 2). A row the audience could not read whatever its status is judged
    /// in caches of its own, so the run records no gate decision and no
    /// `read_suppressed` entry (an archived row, a claim the caller's scalar
    /// ceiling refuses) for it, and neither the run's counts nor its empty
    /// reason change with it. A
    /// row the clamp refuses takes no rank in the blend, as at a bounded
    /// channel's fetch; one that meets every other check of the scope, the
    /// gate included, is returned, and the pack counts it among the rows its
    /// clamp withheld (`PipelineOutput::disclosure_clamped`), as main's
    /// preselection counted it. The clamp's test here reads the row alone;
    /// the preselection before the cuts asks a summary's sources too.
    pub(super) fn retain_phonetic_hits_in_scope(
        &self,
        rtxn: &RoTxn<'_>,
        results: &mut Vec<ScoredEntity>,
        filters: PipelineFilterConfig<'_>,
        metadata: &mut EntityMetadataCache,
        claim_gate: &mut ClaimStatusGateCache,
    ) -> Result<Vec<crate::EntityId>> {
        let admission = filters.candidate_filter;
        let clamp = filters.disclosure;
        // The candidate filter is asked here, so the predicate judges the
        // rows it admits in the run's caches, not in caches of its own; the
        // clamp is asked after it, so a row it refuses is counted, not lost.
        let filters = PipelineFilterConfig {
            candidate_filter: None,
            deadline: None,
            disclosure: None,
            ..self.bounded_result_filters(filters)
        };
        let mut kept = Vec::with_capacity(results.len());
        let mut clamped = Vec::new();
        for scored in std::mem::take(results) {
            if let Some(admits) = admission
                && !admits(&self.read, rtxn, &scored.id)?
            {
                continue;
            }
            let Some(clamp) = clamp else {
                if pipeline_candidate_matches_filters_and_gate(
                    &self.read, rtxn, &scored.id, filters, metadata, claim_gate,
                )? {
                    kept.push(scored);
                }
                continue;
            };
            let Some(entity_type) = metadata
                .get(&self.read, rtxn, &scored.id)?
                .map(|meta| meta.entity_type)
            else {
                continue;
            };
            if !clamp.admits_row_ignoring_status(&self.read, rtxn, &scored.id, entity_type)? {
                let mut own_metadata = EntityMetadataCache::default();
                let mut own_gate = claim_gate.fresh(filters.authority_filter.include_stale);
                if pipeline_candidate_matches_filters_and_gate(
                    &self.read,
                    rtxn,
                    &scored.id,
                    filters,
                    &mut own_metadata,
                    &mut own_gate,
                )? {
                    clamped.push(scored.id);
                }
                continue;
            }
            if !pipeline_candidate_matches_filters_and_gate(
                &self.read, rtxn, &scored.id, filters, metadata, claim_gate,
            )? {
                continue;
            }
            if crate::context_pack::retained_copies::clamp_prefilter_admits(
                clamp,
                &self.read,
                rtxn,
                &scored.id,
                entity_type,
                claim_gate
                    .decisions
                    .get(&scored.id)
                    .and_then(Option::as_ref),
            )? {
                kept.push(scored);
            } else {
                clamped.push(scored.id);
            }
        }
        *results = kept;
        Ok(clamped)
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
        let filters = self.bounded_result_filters(filters);
        let mut scoped_config = config.clone();
        scoped_config.widened = Some(scoped_temporal_channel_limit(
            &self.read,
            rtxn,
            config.limit,
            self.has_codebase_scope_filter()
                || self.has_strict_text_scope_filter()
                || filters.corpus_scope != &CorpusScope::All
                || filters.candidate_filter.is_some()
                || self.memory_category,
            &self.params,
        )?);
        // A made_by slice joins the reader's predicate, after the call's own:
        // only rows it admits count toward the rounds' stops and take places
        // in the window's bound, so rows it drops cannot fill the window
        // ahead of the rows it keeps (REVIEW-9842). The window's scans ask
        // that reader too, so neither can they fill a scan's cap or the
        // spanner buffer (round 2).
        let slice_caches = RefCell::new((
            EntityMetadataCache::default(),
            claim_gate.fresh(filters.authority_filter.include_stale),
        ));
        let in_slice = |store: &crate::store::StoreRead<'_>,
                        txn: &RoTxn<'_>,
                        id: &crate::EntityId|
         -> Result<bool> {
            if let Some(scope) = filters.candidate_filter
                && !scope(store, txn, id)?
            {
                return Ok(false);
            }
            let (metadata, gate) = &mut *slice_caches.borrow_mut();
            self.made_by_slice_admits(txn, id, metadata, gate)
        };
        let predicate: Option<&SnapshotCandidateFilter<'_>> =
            if self.made_by == crate::provenance::made_by::MadeByPredicate::All {
                filters.candidate_filter
            } else {
                Some(&in_slice)
            };
        // Widen the collector's window, scan caps and score truncation, not
        // the request sigma settles on.
        let Some(predicate) = predicate else {
            let mut scores = execute_temporal(
                &self.read,
                rtxn,
                &scoped_config,
                &self.params,
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
        let reader = if self.made_by == crate::provenance::made_by::MadeByPredicate::All {
            ReadableRows::new(predicate, filters.deadline)
        } else {
            ReadableRows::new_asked_by_scans(predicate, filters.deadline)
        };
        let (mut scores, cut) = execute_temporal_for_reader(
            &self.read,
            rtxn,
            &scoped_config,
            &self.params,
            now,
            metadata_cache,
            filters.deadline,
            &reader,
        )?;
        let memory = self.memory_category;
        let kept = |store: &crate::store::StoreRead<'_>,
                    txn: &RoTxn<'_>,
                    id: &crate::EntityId|
         -> Result<bool> {
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

    /// `filters` for a bounded result channel's own admission and cut
    /// (vector and HyDE vector, text, temporal, typed media): the call's
    /// `made_by` slice joins the scope, so a row it drops takes no place in
    /// the fetch. A slice counts as a strict scope
    /// ([`Self::has_strict_text_scope_filter`]), so these channels widen their
    /// window and cut it to the slice. The run's shared config keeps every
    /// slice for the reads that judge rows other than results.
    pub(super) fn bounded_result_filters<'f>(
        &self,
        filters: PipelineFilterConfig<'f>,
    ) -> PipelineFilterConfig<'f> {
        PipelineFilterConfig {
            made_by: self.made_by,
            ..filters
        }
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
            super::capabilities::retain_memory_candidates(scores, &self.read, rtxn)?;
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
            &self.read,
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
            || self.made_by != crate::provenance::made_by::MadeByPredicate::All
    }
}
