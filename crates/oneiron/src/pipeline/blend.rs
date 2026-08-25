use std::collections::{HashMap, HashSet};

use heed::RoTxn;

use crate::batch::LONG_INTERVAL_THRESHOLD_SECS;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::fusion;
use crate::store::{RetrievalBlendWeights, RetrievalScoreComponent, Store};
use crate::temporal::TemporalAnchorMode;

use super::support::resolve_sigma_secs;
use super::types::{
    COSINE_GHOST_VECTOR_THRESHOLD, EntityMetadataCache, SECONDS_PER_DAY_F64, ScoredEntity,
    TemporalSearchConfig, retrieval_recency_half_life_days_for_type,
};

#[derive(Debug, Clone, Copy)]
pub(super) struct RetrievalBlendConfig {
    pub(super) recency_now_secs: Option<u64>,
    pub(super) salience: bool,
    pub(super) confidence: bool,
    pub(super) gravity: bool,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RetrievalChannelIndexes {
    pub(super) vector: Option<usize>,
    pub(super) text: Option<usize>,
}

pub(super) struct BlendedRetrievalScores {
    pub(super) scores: Vec<ScoredEntity>,
    pub(super) cosine_ghosts_dampened: usize,
    pub(super) components: HashMap<EntityId, Vec<RetrievalScoreComponent>>,
}

pub(super) fn retrieval_blend_weights_for_scoring(
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<RetrievalBlendWeights> {
    match store.retrieval_blend_weight_table_in_txn(rtxn) {
        Ok(entry) => Ok(entry.weights),
        Err(Error::CorruptedIndex("retrieval blend weight table")) => {
            Ok(RetrievalBlendWeights::bootstrap())
        }
        Err(error) => Err(error),
    }
}

pub(super) fn blended_retrieval_scores(
    ranked_lists: &[Vec<ScoredEntity>],
    channel_indexes: RetrievalChannelIndexes,
    store: &Store,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
    config: RetrievalBlendConfig,
    weights: RetrievalBlendWeights,
) -> Result<BlendedRetrievalScores> {
    let mut inputs = fusion::retrieval_candidates_from_ranked_lists(ranked_lists);
    let cosine_ghosts = if config.gravity {
        cosine_ghost_set(ranked_lists, channel_indexes.vector, channel_indexes.text)
    } else {
        HashSet::new()
    };
    let needs_claim_body = config.salience || config.confidence;
    let mut dampened = 0;
    for input in &mut inputs {
        if let Some(now_secs) = config.recency_now_secs
            && let Some(meta) = metadata_cache.get(store, rtxn, &input.id)?
        {
            let half_life_days =
                f64::from(retrieval_recency_half_life_days_for_type(meta.entity_type));
            let seconds_per_half_life = half_life_days * SECONDS_PER_DAY_F64;
            let age_secs = now_secs.saturating_sub(meta.learned_at) as f64;
            input.recency = 2.0_f64.powf(-age_secs / seconds_per_half_life) as f32;
        }

        if needs_claim_body && let Some(raw) = store.entities.get(rtxn, input.id.as_bytes())? {
            if config.salience
                && let Some(salience) = fusion::decode_msgpack_float(&raw, crate::claim::KEY_SAL)
            {
                input.salience = salience;
            }
            if config.confidence
                && let Some(confidence) = fusion::decode_msgpack_float(&raw, crate::claim::KEY_CONF)
            {
                input.confidence = confidence;
            }
        }

        if config.gravity && !cosine_ghosts.is_empty() {
            input.gravity = if cosine_ghosts.contains(&input.id) {
                dampened += 1;
                0.0
            } else {
                1.0
            };
        }
    }

    let blend_components = fusion::retrieval_blend_score_components(&inputs);
    Ok(BlendedRetrievalScores {
        scores: fusion::linear_log_blend_with_weights(&inputs, weights),
        cosine_ghosts_dampened: dampened,
        components: blend_components,
    })
}

pub(super) fn score_id_set(scores: &[ScoredEntity]) -> HashSet<EntityId> {
    scores.iter().map(|scored| scored.id).collect()
}

pub(super) fn filter_blended_scores_to_allowed_ids(
    blended: Vec<ScoredEntity>,
    allowed: &HashSet<EntityId>,
) -> Vec<ScoredEntity> {
    blended
        .into_iter()
        .filter(|scored| allowed.contains(&scored.id))
        .collect()
}

pub(super) fn cosine_ghost_set(
    ranked_lists: &[Vec<ScoredEntity>],
    vector_channel_index: Option<usize>,
    text_channel_index: Option<usize>,
) -> HashSet<EntityId> {
    let (Some(vector_channel_index), Some(text_channel_index)) =
        (vector_channel_index, text_channel_index)
    else {
        return HashSet::new();
    };
    let (Some(vector_results), Some(text_results)) = (
        ranked_lists.get(vector_channel_index),
        ranked_lists.get(text_channel_index),
    ) else {
        return HashSet::new();
    };

    let text_ids: HashSet<EntityId> = text_results.iter().map(|scored| scored.id).collect();
    vector_results
        .iter()
        .filter(|scored| {
            scored.score > COSINE_GHOST_VECTOR_THRESHOLD && !text_ids.contains(&scored.id)
        })
        .map(|scored| scored.id)
        .collect()
}

pub(super) fn boost_contiguity(
    scores: &mut [ScoredEntity],
    temporal_config: Option<&TemporalSearchConfig>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
) -> Result<()> {
    let Some(config) = temporal_config else {
        return Ok(());
    };

    if scores.len() <= 1 {
        return Ok(());
    }

    let sigma_contig = resolve_sigma_secs(config.sigma_secs).min(LONG_INTERVAL_THRESHOLD_SECS);
    let use_learned = config.anchor_mode == TemporalAnchorMode::Learned;

    // Extract (start, end) per entity based on axis mode.
    // Entities with missing metadata get None and are skipped.
    let intervals: Vec<Option<(u64, u64)>> = scores
        .iter()
        .map(|scored| {
            let meta = metadata_cache.get(store, rtxn, &scored.id)?;
            Ok(meta.map(|m| {
                if use_learned {
                    (m.learned_at, m.learned_at)
                } else {
                    (m.occurred_start, m.occurred_end)
                }
            }))
        })
        .collect::<Result<Vec<_>>>()?;

    // Build sorted start/end arrays from present entities only.
    let mut sorted_starts: Vec<u64> = intervals.iter().filter_map(|i| i.map(|(s, _)| s)).collect();
    let mut sorted_ends: Vec<u64> = intervals.iter().filter_map(|i| i.map(|(_, e)| e)).collect();
    sorted_starts.sort_unstable();
    sorted_ends.sort_unstable();

    let n = sorted_starts.len(); // only entities with metadata
    let denom = (scores.len() - 1) as f32;

    for (idx, interval) in intervals.iter().enumerate() {
        let Some((s_i, e_i)) = *interval else {
            continue;
        };

        // Count entities too far left: e_j <= s_i - σ
        // checked_sub: if s_i < σ, no entity can be too far left.
        let too_left = s_i
            .checked_sub(sigma_contig)
            .map_or(0, |t| sorted_ends.partition_point(|&ej| ej <= t));

        // Count entities too far right: s_j >= e_i + σ
        // checked_add: if e_i + σ overflows, no entity can be too far right.
        let too_right = e_i
            .checked_add(sigma_contig)
            .map_or(0, |t| n - sorted_starts.partition_point(|&sj| sj < t));

        let neighbors = (n - 1).saturating_sub(too_left + too_right);
        let contiguity = neighbors as f32 / denom.max(1.0);
        scores[idx].score *= 1.0 + 0.2 * contiguity;
    }

    Ok(())
}
