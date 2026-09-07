use heed::RoTxn;

use crate::claim::{ClaimBody, claim_corpus_id};
use crate::context_pack::EmptyReason;
use crate::corpus::CorpusScope;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

use super::builder::PipelineBuilder;
use super::filters::claim_status_gate_allows;
use super::types::{ClaimStatusGateCache, EntityMetadataCache, PipelineFilterConfig, ScoredEntity};

/// Canonical audience selection for one retrieval attempt. Construction rejects
/// empty AnyOf before any candidate scan; every door borrows the same selection.
pub(super) struct CorpusFilter(CorpusScope);

impl CorpusFilter {
    pub(super) fn new(scope: &CorpusScope) -> Result<Self> {
        Ok(Self(scope.clone().canonicalize()?))
    }

    pub(super) fn config<'a>(
        &'a self,
        builder: &'a PipelineBuilder<'_>,
        occurred_range: Option<(u64, u64)>,
    ) -> PipelineFilterConfig<'a> {
        PipelineFilterConfig {
            candidate_filter: builder.candidate_filter,
            type_filter: builder.type_filter.as_deref(),
            since_filter: builder.since_filter,
            occurred_range,
            learned_range: builder.learned_range,
            repo_ref_filter: builder.repo_ref_filter.as_ref(),
            project_id_filter: builder.project_id_filter.as_deref(),
            facet_filter: builder.facet_filter,
            relationship_filter: builder.relationship_filter,
            world_scope: builder.world_scope,
            corpus_scope: &self.0,
        }
    }

    pub(super) fn apply(
        &self,
        scores: &mut Vec<ScoredEntity>,
        store: &Store,
        rtxn: &RoTxn<'_>,
        metadata_cache: &mut EntityMetadataCache,
        gate: &mut ClaimStatusGateCache,
        empty_reason: Option<EmptyReason>,
    ) -> Result<Option<EmptyReason>> {
        let before = scores.len();
        apply_corpus_filter(scores, store, rtxn, &self.0, metadata_cache, gate)?;
        Ok(if before > 0 && scores.is_empty() {
            Some(EmptyReason::FilterMatchedNone)
        } else {
            empty_reason
        })
    }
}

/// All is a strict no-op, including no corpus projection from a decoded body.
pub(super) fn claim_matches_corpus(scope: &CorpusScope, body: &ClaimBody) -> Result<bool> {
    if matches!(scope, CorpusScope::All) {
        return Ok(true);
    }
    Ok(scope.matches(claim_corpus_id(body)?))
}

/// Post-fusion audience removal, before result truncation. Selected corpora
/// retain matching and unscoped claims; non-claims pass untouched. The D19
/// cache supplies decoded bodies, as it does on the candidate/probe path.
pub(super) fn apply_corpus_filter(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    scope: &CorpusScope,
    metadata_cache: &mut EntityMetadataCache,
    gate: &mut ClaimStatusGateCache,
) -> Result<()> {
    if matches!(scope, CorpusScope::All) {
        return Ok(());
    }
    let scope = scope.clone().canonicalize()?;
    let mut kept = Vec::with_capacity(scores.len());
    for scored in scores.iter().copied() {
        if pipeline_candidate_matches_corpus_filter(
            store,
            rtxn,
            &scored.id,
            &scope,
            metadata_cache,
            gate,
        )? {
            kept.push(scored);
        }
    }
    *scores = kept;
    Ok(())
}

/// Candidate twin. The caller supplies canonical scope. Gate on cache miss so
/// a suppressed or undecodable CLAIM cannot be mistaken for an unscoped row.
/// Production candidate and post-fusion callers have already gated these ids;
/// this call then only reuses the decision, with no body lookup or decode.
pub(super) fn pipeline_candidate_matches_corpus_filter(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    scope: &CorpusScope,
    metadata_cache: &mut EntityMetadataCache,
    gate: &mut ClaimStatusGateCache,
) -> Result<bool> {
    if matches!(scope, CorpusScope::All) {
        return Ok(true);
    }
    if !claim_status_gate_allows(store, rtxn, id, metadata_cache, gate)? {
        return Ok(false);
    }
    match gate.decisions.get(id) {
        Some(Some(body)) => claim_matches_corpus(scope, body),
        Some(None) => Ok(false),
        None => Ok(true), // Non-claims never enter the D19 cache.
    }
}
