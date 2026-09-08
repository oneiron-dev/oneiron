//! Attempt plumbing for the retrieval transaction: attempt overrides, the transaction output, and the pending-vector collector.

use super::super::types::{ClaimStatusGateCache, PendingVectorEmbedding, ScoredEntity};
use crate::context_pack::EmptyReason;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::retrieval_quality::RetrievalDiagnostics;
use crate::store::{RetrievalScoreComponent, RetrievalTrace, Store};
use heed::RoTxn;
use std::collections::HashMap;

/// Detailed pipeline output for the context-pack path.
///
/// `claim_bodies` carries every claim body decoded (once) by the D19 gate
/// that PASSED it; `claims_suppressed` counts the unique type-0 records the
/// gate excluded (status-failed or undecodable). Bodies were decoded under
/// the pipeline's read transaction; the context pack hydrates under a fresh
/// transaction, so reusing them keeps projection consistent with the gate
/// decision (the same seam the score/hydration split already has).
pub(super) struct HydeAttemptOverrides<'a> {
    pub(super) widen_channel_limits: bool,
    pub(super) extra_text_queries: &'a [String],
    pub(super) skip_ret01_abstain: bool,
}

pub(super) struct RetrievalTxnOutput {
    pub(super) diagnostics: RetrievalDiagnostics,
    pub(super) scores: Vec<ScoredEntity>,
    pub(super) pending_vectors: Vec<PendingVectorEmbedding>,
    pub(super) claim_gate: ClaimStatusGateCache,
    pub(super) deferred_ppr_cache_writes: Vec<crate::ppr::DeferredPprCacheWrite>,
    pub(super) cosine_ghosts_dampened: usize,
    pub(super) total_in_scope: usize,
    pub(super) empty_reason: Option<EmptyReason>,
    pub(super) signal_components: HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    pub(super) blend_components: HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    /// The applied read-side multiplier per candidate, from the run's
    /// single decay-applying blend. Empty when no blend ran.
    pub(super) access_factors: HashMap<EntityId, f32>,
    pub(super) rerank_merged_components: Option<HashMap<EntityId, Vec<RetrievalScoreComponent>>>,
    pub(super) retrieval_trace: Option<RetrievalTrace>,
    pub(super) ppr_expand_executed: bool,
    pub(super) early_empty_no_telemetry: bool,
}

pub(super) fn pending_vectors_for_scores(
    store: &Store,
    rtxn: &RoTxn<'_>,
    scores: &[ScoredEntity],
) -> Result<Vec<PendingVectorEmbedding>> {
    let mut pending = Vec::new();
    for scored in scores {
        if let Some(token) = store.pending_embedding_token(rtxn, &scored.id)? {
            pending.push(PendingVectorEmbedding {
                id: scored.id,
                token,
            });
        }
    }
    pending.sort_unstable_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    pending.dedup_by(|left, right| left.id == right.id);
    Ok(pending)
}
