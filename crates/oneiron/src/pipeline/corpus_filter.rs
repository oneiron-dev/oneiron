use heed::RoTxn;

use crate::claim::ClaimBody;
use crate::context_pack::EmptyReason;
use crate::corpus::CorpusScope;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::StoreRead;

use super::builder::PipelineBuilder;
use super::filters::claim_status_gate_allows;
use super::types::{
    CandidateFilter, ClaimStatusGateCache, EntityMetadataCache, PipelineFilterConfig, ScoredEntity,
    SnapshotCandidateFilter,
};

/// The candidate admission of one retrieval snapshot (FIX 11648): the run's
/// candidate filter, then what its gate admits under the state it holds for
/// the snapshot's transaction. Made beside that transaction
/// ([`PipelineBuilder::snapshot_admission`]) and dropped before it, so what
/// the gate holds never serves another one.
pub(super) enum SnapshotAdmission<'t> {
    Filter(Option<&'t CandidateFilter<'t>>),
    Gated(Box<SnapshotCandidateFilter<'t>>),
}

impl SnapshotAdmission<'_> {
    fn filter(&self) -> Option<&SnapshotCandidateFilter<'_>> {
        match self {
            Self::Filter(Some(filter)) => Some(*filter),
            Self::Filter(None) => None,
            Self::Gated(gated) => Some(&**gated),
        }
    }
}

impl PipelineBuilder<'_> {
    /// This run's candidate admission for the snapshot read in `txn`.
    pub(super) fn snapshot_admission<'t>(&'t self, txn: &'t RoTxn<'t>) -> SnapshotAdmission<'t> {
        let filter = self.candidate_filter;
        let Some(gate) = self.candidate_gate else {
            return SnapshotAdmission::Filter(filter);
        };
        let gated = gate.in_txn(txn);
        SnapshotAdmission::Gated(Box::new(
            move |store: &StoreRead<'_>, rtxn: &RoTxn<'_>, id: &EntityId| {
                if let Some(filter) = filter
                    && !filter(store, rtxn, id)?
                {
                    return Ok(false);
                }
                gated(store, rtxn, id)
            },
        ))
    }
}

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
        admission: &'a SnapshotAdmission<'_>,
        occurred_range: Option<(u64, u64)>,
        authority_filter: &'a crate::gate::ResolvedRetrievalFilter,
    ) -> PipelineFilterConfig<'a> {
        PipelineFilterConfig {
            authority_filter,
            candidate_filter: admission.filter(),
            type_filter: builder.type_filter.as_deref(),
            criticality: builder.criticality,
            since_filter: builder.since_filter,
            occurred_range,
            learned_range: builder.learned_range,
            repo_ref_filter: builder.repo_ref_filter.as_ref(),
            project_id_filter: builder.project_id_filter.as_deref(),
            facet_filter: builder.facet_filter,
            relationship_filter: builder.relationship_filter,
            world_scope: &builder.world_scope,
            world_active_set: None,
            stale_worlds: None,
            corpus_scope: &self.0,
            device_local: None,
            deadline: builder.deadline,
            disclosure: builder.disclosure_preselect.as_ref(),
        }
    }

    pub(super) fn apply(
        &self,
        scores: &mut Vec<ScoredEntity>,
        store: &StoreRead<'_>,
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

/// Corpus selection reads the required project-axis stamp, not the opaque scope map.
pub(super) fn claim_matches_corpus(scope: &CorpusScope, body: &ClaimBody) -> bool {
    scope.matches(body.scope_project)
}

/// Post-fusion project-axis removal, before result truncation. Selected
/// projects retain only their own claims; non-claims pass untouched. The D19
/// cache supplies decoded bodies, as it does on the candidate/probe path.
pub(super) fn apply_corpus_filter(
    scores: &mut Vec<ScoredEntity>,
    store: &StoreRead<'_>,
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
    store: &StoreRead<'_>,
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
        Some(Some(body)) => Ok(claim_matches_corpus(scope, body)),
        Some(None) => Ok(false),
        None => Ok(true), // Non-claims never enter the D19 cache.
    }
}
