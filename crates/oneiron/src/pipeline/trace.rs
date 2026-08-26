use std::collections::HashMap;

use heed::RoTxn;
use sha2::{Digest, Sha256};

use crate::analyzer::AnalyzerChannel;
use crate::bm25::{Bm25Config, Bm25Formula};
use crate::codebase::RepoRef;
use crate::context_pack::ContextPackRetrievalBudget;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::Result;
use crate::fusion;
use crate::rerank::{RerankOptions, Reranker};
use crate::store::{
    RetrievalBlendWeights, RetrievalScoreBreakdown, RetrievalScoreComponent, RetrievalSignal,
    RetrievalTraceChannelRecord, RetrievalTraceStage, RetrievalTraceStageRecord, Store,
};
use crate::temporal::TemporalAnchorMode;

use super::builder::PipelineBuilder;
use super::filters::pipeline_candidate_matches_filters_and_gate;
use super::types::{
    ALPHA_BASE, ALPHA_RANGE, ALPHA_TAU_SECS, COSINE_GHOST_VECTOR_THRESHOLD, ClaimStatusGateCache,
    DEFAULT_RECENCY_HALF_LIFE_DAYS, EntityMetadataCache, FacetMode, PPR_DAMPING,
    PipelineFilterConfig, RECENCY_DECAY_TAU_SECS, RETRIEVAL_RECENCY_HALF_LIFE_DAYS_BY_TYPE,
    RETRIEVAL_TRACE_RRF_K, RelMode, ScoredEntity, TEMPORAL_FLOOR, TemporalSearchConfig, WorldScope,
};

pub(super) fn add_signal_score_components(
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

pub(super) fn retrieval_trace_channel_record(
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
            })
            .collect(),
    }
}

pub(super) fn retrieval_trace_fused_scores(
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

pub(super) fn retrieval_trace_top_scores(
    scores: &[ScoredEntity],
    limit: usize,
) -> Vec<ScoredEntity> {
    scores.iter().take(limit).copied().collect()
}

pub(super) fn retrieval_trace_stage_record(
    stage: RetrievalTraceStage,
    scores: &[ScoredEntity],
    components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    blend_components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    limit: usize,
) -> RetrievalTraceStageRecord {
    RetrievalTraceStageRecord {
        stage,
        candidates: retrieval_score_breakdown(scores, components, blend_components, limit),
    }
}

pub(super) fn telemetry_score_breakdown(
    scores: &[ScoredEntity],
    components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    blend_components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
) -> Vec<RetrievalScoreBreakdown> {
    retrieval_score_breakdown(scores, components, blend_components, scores.len())
}

fn retrieval_score_breakdown(
    scores: &[ScoredEntity],
    components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    blend_components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
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
            }
        })
        .collect()
}

pub(super) fn retrieval_trace_fork_hash(
    builder: &PipelineBuilder<'_>,
    bm25_config: &Bm25Config,
    blend_weights: RetrievalBlendWeights,
    explicit_time_dependent_now_secs: Option<u64>,
    resolved_occurred_range: Option<(u64, u64)>,
    rerank_query: Option<&str>,
    candidate_set: &[[u8; ENTITY_ID_LEN]],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    fork_hash_bytes(&mut hasher, b"oneiron.retrieval_trace.fork_hash.v1");

    fork_hash_vector_query(
        &mut hasher,
        builder.vector_search.as_ref(),
        builder.skip_vector_rescore,
    );
    fork_hash_text_query(&mut hasher, builder.text_search.as_ref());
    fork_hash_phonetic_query(&mut hasher, builder.phonetic_search.as_deref());
    fork_hash_temporal_query(&mut hasher, builder.temporal_search.as_ref());
    fork_hash_entity_seeds(&mut hasher, builder.ppr_search.as_ref());
    fork_hash_entity_seeds(&mut hasher, builder.ppr_expand.as_ref());

    fork_hash_bm25_config(&mut hasher, bm25_config);
    fork_hash_bool(&mut hasher, builder.recency_blend_enabled);
    fork_hash_opt_u64(&mut hasher, explicit_time_dependent_now_secs);
    fork_hash_bool(&mut hasher, builder.apply_salience);
    fork_hash_bool(&mut hasher, builder.apply_confidence);
    fork_hash_bool(&mut hasher, builder.apply_gravity);
    fork_hash_bool(&mut hasher, builder.apply_contiguity);
    fork_hash_type_filter(&mut hasher, builder.type_filter.as_deref());
    fork_hash_opt_u64(&mut hasher, builder.since_filter);
    fork_hash_opt_range(&mut hasher, resolved_occurred_range);
    fork_hash_opt_range(&mut hasher, builder.learned_range);
    fork_hash_repo_ref(&mut hasher, builder.repo_ref_filter.as_ref());
    fork_hash_opt_str(&mut hasher, builder.project_id_filter.as_deref());
    fork_hash_facet_filter(&mut hasher, builder.facet_filter);
    fork_hash_relationship_filter(&mut hasher, builder.relationship_filter);
    fork_hash_world_scope(&mut hasher, builder.world_scope);
    fork_hash_context_pack_budget(&mut hasher, builder.context_pack_budget);
    fork_hash_len(&mut hasher, builder.result_limit);
    fork_hash_bool(&mut hasher, builder.temporal_adaptive_default);
    fork_hash_recency_weight_table(&mut hasher);
    fork_hash_retrieval_blend_weights(&mut hasher, blend_weights);
    fork_hash_scoring_constants(&mut hasher, builder.vault.config.fast_dims);
    fork_hash_rerank(&mut hasher, builder.rerank.as_ref(), rerank_query);
    fork_hash_candidate_set(&mut hasher, candidate_set);

    hasher.finalize().into()
}

/// RET-010 rerank segment. Appending the active bool shifts ALL fork hashes
/// relative to pre-RET-010 binaries; accepted — 1186-D5 pins
/// schema+determinism within a binary, not cross-version hash stability.
fn fork_hash_rerank(
    hasher: &mut Sha256,
    rerank: Option<&(&dyn Reranker, RerankOptions)>,
    effective_query: Option<&str>,
) {
    let Some((reranker, options)) = rerank else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_str(hasher, reranker.id());
    fork_hash_u64(hasher, options.top_n as u64);
    fork_hash_str(hasher, effective_query.unwrap_or_default());
}

fn fork_hash_vector_query(
    hasher: &mut Sha256,
    query: Option<&(Vec<f32>, usize)>,
    skip_vector_rescore: bool,
) {
    let Some((vector, limit)) = query else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_len(hasher, *limit);
    fork_hash_len(hasher, vector.len());
    for value in vector {
        fork_hash_f32(hasher, *value);
    }
    // EMB-2 hot lane: prefix-only vs rescored orders are different forks.
    fork_hash_bool(hasher, skip_vector_rescore);
}

fn fork_hash_text_query(hasher: &mut Sha256, query: Option<&(String, usize)>) {
    let Some((query, limit)) = query else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_len(hasher, *limit);
    fork_hash_str(hasher, query);
}

fn fork_hash_phonetic_query(hasher: &mut Sha256, codes: Option<&[String]>) {
    let Some(codes) = codes else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    let mut codes = codes.to_vec();
    codes.sort();
    codes.dedup();
    fork_hash_len(hasher, codes.len());
    for code in &codes {
        fork_hash_str(hasher, code);
    }
}

fn fork_hash_temporal_query(hasher: &mut Sha256, config: Option<&TemporalSearchConfig>) {
    let Some(config) = config else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_u64(hasher, config.anchor_start);
    fork_hash_u64(hasher, config.anchor_end);
    fork_hash_opt_u64(hasher, config.learned_start);
    fork_hash_opt_u64(hasher, config.learned_end);
    fork_hash_u64(hasher, config.sigma_secs);
    fork_hash_temporal_anchor_mode(hasher, config.anchor_mode);
    fork_hash_bool(hasher, config.adaptive);
    fork_hash_len(hasher, config.limit);
}

fn fork_hash_temporal_anchor_mode(hasher: &mut Sha256, mode: TemporalAnchorMode) {
    fork_hash_str(
        hasher,
        match mode {
            TemporalAnchorMode::Auto => "auto",
            TemporalAnchorMode::Occurred => "occurred",
            TemporalAnchorMode::Learned => "learned",
            TemporalAnchorMode::Both => "both",
        },
    );
}

fn fork_hash_entity_seeds(hasher: &mut Sha256, seeds: Option<&(Vec<EntityId>, u32)>) {
    let Some((seeds, depth)) = seeds else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_u32(hasher, *depth);
    let mut seed_bytes: Vec<[u8; ENTITY_ID_LEN]> =
        seeds.iter().map(|seed| *seed.as_bytes()).collect();
    seed_bytes.sort_unstable();
    seed_bytes.dedup();
    fork_hash_len(hasher, seed_bytes.len());
    for seed in seed_bytes {
        fork_hash_raw_bytes(hasher, &seed);
    }
}

fn fork_hash_bm25_config(hasher: &mut Sha256, config: &Bm25Config) {
    fork_hash_f64(hasher, config.k1);
    match config.formula {
        Bm25Formula::Okapi => fork_hash_str(hasher, "okapi"),
        Bm25Formula::Plus { delta } => {
            fork_hash_str(hasher, "plus");
            fork_hash_f64(hasher, delta);
        }
    }
    let channels = AnalyzerChannel::ALL_RESERVED;
    fork_hash_len(hasher, channels.len());
    for channel in channels {
        let field = config.field(channel);
        fork_hash_str(hasher, channel.as_str());
        fork_hash_f64(hasher, field.weight);
        fork_hash_f64(hasher, field.b);
        fork_hash_str(hasher, field.length_policy.manifest_tag());
    }
}

fn fork_hash_type_filter(hasher: &mut Sha256, types: Option<&[u8]>) {
    let Some(types) = types else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    let mut types = types.to_vec();
    types.sort_unstable();
    types.dedup();
    fork_hash_len(hasher, types.len());
    for entity_type in types {
        fork_hash_u8(hasher, entity_type);
    }
}

fn fork_hash_repo_ref(hasher: &mut Sha256, repo_ref: Option<&RepoRef>) {
    let Some(repo_ref) = repo_ref else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_str(hasher, &repo_ref.canonical());
}

fn fork_hash_facet_filter(hasher: &mut Sha256, filter: Option<(EntityId, FacetMode)>) {
    let Some((facet_id, mode)) = filter else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_raw_bytes(hasher, facet_id.as_bytes());
    match mode {
        FacetMode::Strict => fork_hash_str(hasher, "strict"),
        FacetMode::Prefer { boost } => {
            fork_hash_str(hasher, "prefer");
            fork_hash_f32(hasher, boost);
        }
    }
}

fn fork_hash_relationship_filter(hasher: &mut Sha256, filter: Option<(EntityId, RelMode)>) {
    let Some((relationship, mode)) = filter else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_raw_bytes(hasher, relationship.as_bytes());
    fork_hash_str(
        hasher,
        match mode {
            RelMode::Filter => "filter",
            RelMode::Demote => "demote",
        },
    );
}

fn fork_hash_world_scope(hasher: &mut Sha256, scope: WorldScope) {
    match scope {
        WorldScope::All => fork_hash_str(hasher, "all"),
        WorldScope::Base => fork_hash_str(hasher, "base"),
        WorldScope::World(id) => {
            fork_hash_str(hasher, "world");
            fork_hash_raw_bytes(hasher, id.as_bytes());
        }
        WorldScope::WorldSet(scope_key) => {
            fork_hash_str(hasher, "world_set");
            fork_hash_raw_bytes(hasher, &scope_key);
        }
    }
}

fn fork_hash_context_pack_budget(hasher: &mut Sha256, budget: Option<ContextPackRetrievalBudget>) {
    let Some(budget) = budget else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_len(hasher, budget.claims);
    fork_hash_len(hasher, budget.turns);
    fork_hash_len(hasher, budget.summaries);
    fork_hash_len(hasher, budget.facets);
    fork_hash_len(hasher, budget.other);
    fork_hash_len(hasher, budget.selected_edges);
}

fn fork_hash_recency_weight_table(hasher: &mut Sha256) {
    fork_hash_len(hasher, RETRIEVAL_RECENCY_HALF_LIFE_DAYS_BY_TYPE.len());
    for (entity_type, half_life_days) in RETRIEVAL_RECENCY_HALF_LIFE_DAYS_BY_TYPE {
        fork_hash_u8(hasher, *entity_type);
        fork_hash_f32(hasher, *half_life_days);
    }
    fork_hash_f32(hasher, DEFAULT_RECENCY_HALF_LIFE_DAYS);
}

fn fork_hash_retrieval_blend_weights(hasher: &mut Sha256, weights: RetrievalBlendWeights) {
    fork_hash_f32(hasher, weights.recency);
    fork_hash_f32(hasher, weights.salience);
    fork_hash_f32(hasher, weights.confidence);
    fork_hash_f32(hasher, weights.gravity);
}

fn fork_hash_scoring_constants(hasher: &mut Sha256, fast_dims: Option<u16>) {
    fork_hash_f32(hasher, RETRIEVAL_TRACE_RRF_K);
    fork_hash_f32(hasher, PPR_DAMPING);
    fork_hash_f64(hasher, RECENCY_DECAY_TAU_SECS);
    fork_hash_f64(hasher, ALPHA_BASE);
    fork_hash_f64(hasher, ALPHA_RANGE);
    fork_hash_f64(hasher, ALPHA_TAU_SECS);
    fork_hash_f64(hasher, TEMPORAL_FLOOR);
    fork_hash_f32(hasher, COSINE_GHOST_VECTOR_THRESHOLD);
    // EMB-2: the funnel prefix changes vector-channel scoring space.
    fork_hash_u32(hasher, u32::from(fast_dims.unwrap_or(0)));
}

pub(super) fn retrieval_trace_candidate_set(
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

fn fork_hash_candidate_set(hasher: &mut Sha256, candidates: &[[u8; ENTITY_ID_LEN]]) {
    fork_hash_len(hasher, candidates.len());
    for candidate in candidates {
        fork_hash_raw_bytes(hasher, candidate);
    }
}

fn fork_hash_opt_range(hasher: &mut Sha256, range: Option<(u64, u64)>) {
    let Some((start, end)) = range else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_u64(hasher, start);
    fork_hash_u64(hasher, end);
}

fn fork_hash_opt_str(hasher: &mut Sha256, value: Option<&str>) {
    let Some(value) = value else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_str(hasher, value);
}

fn fork_hash_opt_u64(hasher: &mut Sha256, value: Option<u64>) {
    let Some(value) = value else {
        fork_hash_bool(hasher, false);
        return;
    };
    fork_hash_bool(hasher, true);
    fork_hash_u64(hasher, value);
}

fn fork_hash_str(hasher: &mut Sha256, value: &str) {
    fork_hash_bytes(hasher, value.as_bytes());
}

fn fork_hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    fork_hash_len(hasher, bytes.len());
    fork_hash_raw_bytes(hasher, bytes);
}

fn fork_hash_raw_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(bytes);
}

fn fork_hash_bool(hasher: &mut Sha256, value: bool) {
    hasher.update([u8::from(value)]);
}

fn fork_hash_u8(hasher: &mut Sha256, value: u8) {
    hasher.update([value]);
}

fn fork_hash_u32(hasher: &mut Sha256, value: u32) {
    hasher.update(value.to_le_bytes());
}

fn fork_hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn fork_hash_len(hasher: &mut Sha256, value: usize) {
    fork_hash_u64(hasher, value as u64);
}

fn fork_hash_f32(hasher: &mut Sha256, value: f32) {
    hasher.update(value.to_bits().to_le_bytes());
}

fn fork_hash_f64(hasher: &mut Sha256, value: f64) {
    hasher.update(value.to_bits().to_le_bytes());
}

pub(super) fn filter_retrieval_trace_scores(
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
        )? {
            filtered.push(scored);
            if filtered.len() == limit {
                break;
            }
        }
    }
    Ok(filtered)
}
