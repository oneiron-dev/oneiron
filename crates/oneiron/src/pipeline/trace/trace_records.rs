//! Pure trace-data shaping: channel, fused, top and stage records, score breakdowns, and candidate-set assembly.

use std::collections::HashMap;

use heed::RoTxn;

use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::Result;
use crate::fusion;
use crate::retrieval_quality::{PprCacheOutcome, RetrievalDiagnostics};
use crate::store::{
    RetrievalScoreBreakdown, RetrievalScoreComponent, RetrievalSignal, RetrievalTraceChannelRecord,
    RetrievalTraceStage, RetrievalTraceStageRecord, Store,
};

use super::super::filters::pipeline_candidate_matches_filters_and_gate;
use super::super::types::{
    ClaimStatusGateCache, EntityMetadataCache, PipelineFilterConfig, RETRIEVAL_TRACE_RRF_K,
    ScoredEntity,
};

/// Aggregate cache operations conservatively: a later hit cannot hide a miss
/// or a deliberately bypassed operation in the same retrieval run.
pub(in crate::pipeline) fn record_ppr_cache_outcome(
    diagnostics: &mut RetrievalDiagnostics,
    cache: PprCacheOutcome,
) {
    diagnostics.ppr_cache = Some(match (diagnostics.ppr_cache, cache) {
        (Some(PprCacheOutcome::Miss), _) | (_, PprCacheOutcome::Miss) => PprCacheOutcome::Miss,
        (Some(PprCacheOutcome::Disabled), _) | (_, PprCacheOutcome::Disabled) => {
            PprCacheOutcome::Disabled
        }
        _ => PprCacheOutcome::Hit,
    });
}

pub(in crate::pipeline) fn merge_retrieval_diagnostics(
    diagnostics: &mut RetrievalDiagnostics,
    next: RetrievalDiagnostics,
) {
    for signal in next.attempted {
        if !diagnostics.attempted.contains(&signal) {
            diagnostics.attempted.push(signal);
        }
    }
    for signal in next.succeeded {
        if !diagnostics.succeeded.contains(&signal) {
            diagnostics.succeeded.push(signal);
        }
    }
    if let Some(cache) = next.ppr_cache {
        record_ppr_cache_outcome(diagnostics, cache);
    }
    diagnostics.degradation.extend(next.degradation);
}

pub(in crate::pipeline) fn add_signal_score_components(
    components: &mut HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    signal: RetrievalSignal,
    scores: &[ScoredEntity],
) {
    for (rank, scored) in scores.iter().enumerate() {
        components
            .entry(scored.id)
            .or_default()
            .push(RetrievalScoreComponent {
                signal,
                rank: (rank + 1).min(u32::MAX as usize) as u32,
                score: scored.score,
            });
    }
}

pub(in crate::pipeline) fn retrieval_trace_channel_record(
    signal: RetrievalSignal,
    scores: &[ScoredEntity],
    limit: usize,
) -> RetrievalTraceChannelRecord {
    RetrievalTraceChannelRecord {
        stage: RetrievalTraceStage::PerChannel,
        signal,
        candidates: scores
            .iter()
            .take(limit)
            .enumerate()
            .map(|(rank, scored)| RetrievalScoreBreakdown {
                result_id: *scored.id.as_bytes(),
                final_rank: (rank + 1).min(u32::MAX as usize) as u32,
                final_score: scored.score,
                components: vec![RetrievalScoreComponent {
                    signal,
                    rank: (rank + 1).min(u32::MAX as usize) as u32,
                    score: scored.score,
                }],
                // A per-channel row is pre-fusion: the multiplier has not
                // been applied to this score, so attributing one would be
                // a fabrication.
                access_factor: None,
            })
            .collect(),
    }
}

pub(in crate::pipeline) fn retrieval_trace_fused_scores(
    ranked_lists: &[Vec<ScoredEntity>],
    limit: usize,
) -> Vec<ScoredEntity> {
    let mut scores = HashMap::<EntityId, f32>::new();
    for ranked in ranked_lists {
        for (rank, scored) in ranked.iter().take(limit).enumerate() {
            let rank = (rank + 1).min(u32::MAX as usize) as f32;
            *scores.entry(scored.id).or_default() += 1.0 / (RETRIEVAL_TRACE_RRF_K + rank);
        }
    }

    let mut scores: Vec<ScoredEntity> = scores
        .into_iter()
        .map(|(id, score)| ScoredEntity { id, score })
        .collect();
    fusion::sort_scored_entities_desc(&mut scores);
    retrieval_trace_top_scores(&scores, limit)
}

pub(in crate::pipeline) fn retrieval_trace_top_scores(
    scores: &[ScoredEntity],
    limit: usize,
) -> Vec<ScoredEntity> {
    scores.iter().take(limit).copied().collect()
}

pub(in crate::pipeline) fn retrieval_trace_stage_record(
    stage: RetrievalTraceStage,
    scores: &[ScoredEntity],
    components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    blend_components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    access_factors: &HashMap<EntityId, f32>,
    limit: usize,
) -> RetrievalTraceStageRecord {
    RetrievalTraceStageRecord {
        stage,
        candidates: retrieval_score_breakdown(
            scores,
            components,
            blend_components,
            access_factors,
            limit,
        ),
    }
}

pub(in crate::pipeline) fn telemetry_score_breakdown(
    scores: &[ScoredEntity],
    components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    blend_components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    access_factors: &HashMap<EntityId, f32>,
) -> Vec<RetrievalScoreBreakdown> {
    retrieval_score_breakdown(
        scores,
        components,
        blend_components,
        access_factors,
        scores.len(),
    )
}

/// One breakdown row per candidate: its components, its final score, and
/// the read-side decay factor that produced that score.
///
/// `access_factors` is the applied-multiplier map of the run's single
/// decay-applying blend. A caller at a pre-fusion stage passes an EMPTY
/// map, so every row there records `None`: telemetry stays total and never
/// fails closed, and an absent entry means "not applicable" rather than a
/// neutral factor that was actually applied.
///
/// This is attribution, never a signal — deliberately NOT a
/// [`RetrievalScoreComponent`], because decay stays out of the
/// z-normalized blend and out of blend-weight tuning.
fn retrieval_score_breakdown(
    scores: &[ScoredEntity],
    components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    blend_components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    access_factors: &HashMap<EntityId, f32>,
    limit: usize,
) -> Vec<RetrievalScoreBreakdown> {
    scores
        .iter()
        .take(limit)
        .enumerate()
        .map(|(rank, scored)| {
            let mut score_components = components.get(&scored.id).cloned().unwrap_or_default();
            if let Some(blend_components) = blend_components.get(&scored.id) {
                score_components.extend_from_slice(blend_components);
            }
            RetrievalScoreBreakdown {
                result_id: *scored.id.as_bytes(),
                final_rank: (rank + 1).min(u32::MAX as usize) as u32,
                final_score: scored.score,
                components: score_components,
                access_factor: access_factors.get(&scored.id).copied(),
            }
        })
        .collect()
}

pub(in crate::pipeline) fn retrieval_trace_candidate_set(
    ranked_lists: &[Vec<ScoredEntity>],
    fused_scores: &[ScoredEntity],
    blended_scores: &[ScoredEntity],
    final_scores: &[ScoredEntity],
) -> Vec<[u8; ENTITY_ID_LEN]> {
    let mut candidates = Vec::<[u8; ENTITY_ID_LEN]>::new();
    for ranked in ranked_lists {
        candidates.extend(ranked.iter().map(|scored| *scored.id.as_bytes()));
    }
    candidates.extend(fused_scores.iter().map(|scored| *scored.id.as_bytes()));
    candidates.extend(blended_scores.iter().map(|scored| *scored.id.as_bytes()));
    candidates.extend(final_scores.iter().map(|scored| *scored.id.as_bytes()));
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

pub(in crate::pipeline) fn filter_retrieval_trace_scores(
    scores: &[ScoredEntity],
    store: &Store,
    rtxn: &RoTxn<'_>,
    filters: PipelineFilterConfig<'_>,
    metadata_cache: &mut EntityMetadataCache,
    claim_gate: &mut ClaimStatusGateCache,
    limit: usize,
) -> Result<Vec<ScoredEntity>> {
    if limit == 0 {
        return Ok(Vec::new());
    }

    let mut filtered = Vec::with_capacity(limit.min(scores.len()));
    for scored in scores.iter().copied() {
        if pipeline_candidate_matches_filters_and_gate(
            store,
            rtxn,
            &scored.id,
            filters,
            metadata_cache,
            claim_gate,
        )? && super::authority::candidate_allowed(
            filters.authority_filter,
            store,
            rtxn,
            &scored.id,
            metadata_cache,
            claim_gate,
        )? {
            filtered.push(scored);
            if filtered.len() == limit {
                break;
            }
        }
    }
    Ok(filtered)
}
