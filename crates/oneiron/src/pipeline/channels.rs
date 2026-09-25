use crate::ports::EntityStoreRead;
use std::collections::HashSet;

use heed::RoTxn;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use crate::ports::{EntityTime, TimeAxis, TimelineQuery};
use crate::store::Store;
use crate::temporal::TemporalAnchorMode;

use super::filters::pipeline_candidate_matches_filters_and_gate;
use super::support::{
    combine_proximity, compute_radius, effective_range_width, interval_distance,
    learned_anchor_range, midpoint, point_interval_distance, resolve_sigma_secs, sigmoid,
};
use super::types::{
    ADAPTIVE_ROUNDS, ALPHA_BASE, ALPHA_RANGE, ALPHA_TAU_SECS, ClaimStatusGateCache, EntityMetadata,
    EntityMetadataCache, MAX_TEMPORAL_SEEK_BUFFER, PER_SCAN_CAP_FACTOR, PipelineFilterConfig,
    RECENCY_DECAY_TAU_SECS, ScoredEntity, TEMPORAL_FLOOR, TemporalSearchConfig,
};

#[derive(Debug, Clone, Copy)]
struct TemporalCandidateScore {
    id: EntityId,
    score: f32,
    overlap_tiebreak: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct TemporalScoringContext {
    pub(super) sigma: u64,
    pub(super) now: u64,
    pub(super) anchor_mid: u64,
    pub(super) learned_anchor: (u64, u64),
    pub(super) learned_anchor_mid: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct TemporalCandidateCollectionContext {
    pub(super) radius: u64,
    pub(super) per_scan_cap: usize,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct TemporalIndexCollectionContext {
    pub(super) window_start: u64,
    pub(super) window_end: u64,
    pub(super) anchor_mid: u64,
    pub(super) cap: usize,
}

#[derive(Debug, Clone, Copy)]
struct TemporalIndexRow {
    timestamp: u64,
    id: EntityId,
}

pub(super) fn execute_phonetic(
    store: &Store,
    rtxn: &RoTxn<'_>,
    codes: &[String],
) -> Result<Vec<ScoredEntity>> {
    crate::ports::RetrievalIndexRead::port_retrieval_phonetic_search(store, rtxn, codes)
}

pub(super) fn execute_temporal(
    store: &Store,
    rtxn: &RoTxn<'_>,
    config: &TemporalSearchConfig,
    now: u64,
    metadata_cache: &mut EntityMetadataCache,
) -> Result<Vec<ScoredEntity>> {
    if config.limit == 0 {
        return Ok(Vec::new());
    }

    if config.anchor_mode == TemporalAnchorMode::Both
        && (config.learned_start.is_none() || config.learned_end.is_none())
    {
        return Err(Error::InvalidConfig(
            "TemporalAnchorMode::Both requires learned anchor range".to_owned(),
        ));
    }

    let sigma_initial = resolve_sigma_secs(config.sigma_secs);
    let anchor_mid = midpoint(config.anchor_start, config.anchor_end);
    let learned_anchor = learned_anchor_range(config)?;
    let learned_anchor_mid = midpoint(learned_anchor.0, learned_anchor.1);

    let range_width = effective_range_width(config.anchor_start, config.anchor_end);
    let per_scan_cap = config.limit.saturating_mul(PER_SCAN_CAP_FACTOR).max(1);

    let mut sigma = sigma_initial;
    let mut previous_radius = None;
    let mut candidates = HashSet::<EntityId>::new();

    for round in 0..ADAPTIVE_ROUNDS {
        let radius = compute_radius(range_width, sigma);

        if round == 0 || previous_radius != Some(radius) {
            let collection = TemporalCandidateCollectionContext {
                radius,
                per_scan_cap,
            };
            let scoring = TemporalScoringContext {
                sigma,
                now,
                anchor_mid,
                learned_anchor,
                learned_anchor_mid,
            };
            collect_temporal_candidates(
                store,
                rtxn,
                config,
                collection,
                metadata_cache,
                &scoring,
                &mut candidates,
            )?;
        }

        previous_radius = Some(radius);

        if !config.adaptive || candidates.len() >= config.limit || round + 1 == ADAPTIVE_ROUNDS {
            break;
        }

        sigma = sigma.saturating_mul(2).max(1);
    }

    let scoring = TemporalScoringContext {
        sigma,
        now,
        anchor_mid,
        learned_anchor,
        learned_anchor_mid,
    };

    let mut scored = Vec::<TemporalCandidateScore>::new();

    for id in candidates {
        let Some(meta) = metadata_cache.get(store, rtxn, &id)? else {
            continue;
        };
        scored.push(score_temporal_candidate(id, meta, config, &scoring));
    }

    sort_temporal_candidate_scores(&mut scored);
    scored.truncate(config.limit);

    Ok(scored
        .into_iter()
        .map(|entry| ScoredEntity {
            id: entry.id,
            score: entry.score,
        })
        .collect())
}

pub(super) fn collect_temporal_candidates(
    store: &Store,
    rtxn: &RoTxn<'_>,
    config: &TemporalSearchConfig,
    collection: TemporalCandidateCollectionContext,
    metadata_cache: &mut EntityMetadataCache,
    scoring: &TemporalScoringContext,
    out: &mut HashSet<EntityId>,
) -> Result<()> {
    let radius = collection.radius;
    let per_scan_cap = collection.per_scan_cap;
    let occurred_window_start = config.anchor_start.saturating_sub(radius);
    let occurred_window_end = config.anchor_end.saturating_add(radius);
    let occurred_mid = midpoint(config.anchor_start, config.anchor_end);

    let (learned_anchor_start, learned_anchor_end) = learned_anchor_range(config)?;

    let learned_window_start = learned_anchor_start.saturating_sub(radius);
    let learned_window_end = learned_anchor_end.saturating_add(radius);
    let learned_mid = midpoint(learned_anchor_start, learned_anchor_end);

    let occurred_collection = TemporalIndexCollectionContext {
        window_start: occurred_window_start,
        window_end: occurred_window_end,
        anchor_mid: occurred_mid,
        cap: per_scan_cap,
    };
    let learned_collection = TemporalIndexCollectionContext {
        window_start: learned_window_start,
        window_end: learned_window_end,
        anchor_mid: learned_mid,
        cap: per_scan_cap,
    };

    match config.anchor_mode {
        TemporalAnchorMode::Occurred => {
            collect_occurred_candidates(store, rtxn, occurred_collection, out)?;
        }
        TemporalAnchorMode::Learned => {
            collect_index_candidates(store, TimeAxis::Learned, rtxn, learned_collection, out)?;
        }
        TemporalAnchorMode::Auto | TemporalAnchorMode::Both => {
            collect_occurred_candidates(store, rtxn, occurred_collection, out)?;
            collect_index_candidates(store, TimeAxis::Learned, rtxn, learned_collection, out)?;
        }
    }

    if config.anchor_mode != TemporalAnchorMode::Learned {
        // Keep the top `per_scan_cap` spanners by the same exact temporal score
        // used later in `execute_temporal()`. Since `per_scan_cap` is 4x the
        // final result limit, anything outside this top-k cannot enter the
        // final top-k after exact scoring.
        let mut spanners = Vec::<TemporalCandidateScore>::new();
        let trim_threshold = per_scan_cap
            .saturating_mul(2)
            .min(std::cmp::max(MAX_TEMPORAL_SEEK_BUFFER, per_scan_cap));
        for entry in
            store.port_entity_long_spanning(rtxn, occurred_window_start, occurred_window_end)?
        {
            let (id, _) = entry?;
            let Some(meta) = metadata_cache.get(store, rtxn, &id)? else {
                continue;
            };
            spanners.push(score_temporal_candidate(id, meta, config, scoring));

            if spanners.len() > trim_threshold {
                sort_temporal_candidate_scores(&mut spanners);
                spanners.truncate(per_scan_cap);
            }
        }

        sort_temporal_candidate_scores(&mut spanners);
        spanners.truncate(per_scan_cap);
        for candidate in spanners {
            out.insert(candidate.id);
        }
    }

    Ok(())
}

fn score_temporal_candidate(
    id: EntityId,
    meta: EntityMetadata,
    config: &TemporalSearchConfig,
    scoring: &TemporalScoringContext,
) -> TemporalCandidateScore {
    let d_occ = interval_distance(
        meta.occurred_start,
        meta.occurred_end,
        config.anchor_start,
        config.anchor_end,
    );
    let d_lrn = point_interval_distance(
        meta.learned_at,
        scoring.learned_anchor.0,
        scoring.learned_anchor.1,
    );

    let s_occ_prox = sigmoid(d_occ, scoring.sigma, TEMPORAL_FLOOR);
    let s_lrn_prox = sigmoid(d_lrn, scoring.sigma, TEMPORAL_FLOOR);

    let s_proximity = combine_proximity(config.anchor_mode, s_occ_prox, s_lrn_prox, TEMPORAL_FLOOR);

    let age = scoring.now.saturating_sub(meta.learned_at) as f64;
    let s_recency = (-age / RECENCY_DECAY_TAU_SECS).exp();

    let anchor_age = scoring.now.abs_diff(config.anchor_end) as f64;
    let alpha = ALPHA_BASE + ALPHA_RANGE * (1.0 - (-anchor_age / ALPHA_TAU_SECS).exp());

    let score = (alpha * s_proximity + (1.0 - alpha) * s_recency) as f32;
    let overlap_tiebreak = match config.anchor_mode {
        TemporalAnchorMode::Learned => {
            if d_lrn == 0 {
                meta.learned_at.abs_diff(scoring.learned_anchor_mid)
            } else {
                u64::MAX
            }
        }
        TemporalAnchorMode::Both => {
            if d_occ == 0 && d_lrn == 0 {
                midpoint(meta.occurred_start, meta.occurred_end)
                    .abs_diff(scoring.anchor_mid)
                    .saturating_add(meta.learned_at.abs_diff(scoring.learned_anchor_mid))
            } else {
                u64::MAX
            }
        }
        TemporalAnchorMode::Occurred | TemporalAnchorMode::Auto => {
            if d_occ == 0 {
                midpoint(meta.occurred_start, meta.occurred_end).abs_diff(scoring.anchor_mid)
            } else {
                u64::MAX
            }
        }
    };

    TemporalCandidateScore {
        id,
        score,
        overlap_tiebreak,
    }
}

fn sort_temporal_candidate_scores(scores: &mut [TemporalCandidateScore]) {
    scores.sort_unstable_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.overlap_tiebreak.cmp(&b.overlap_tiebreak))
            .then_with(|| a.id.as_bytes().cmp(b.id.as_bytes()))
    });
}

fn collect_occurred_candidates(
    store: &Store,
    rtxn: &RoTxn<'_>,
    collection: TemporalIndexCollectionContext,
    out: &mut HashSet<EntityId>,
) -> Result<()> {
    collect_index_candidates(store, TimeAxis::OccurredStart, rtxn, collection, out)?;
    collect_index_candidates(store, TimeAxis::OccurredEnd, rtxn, collection, out)?;
    Ok(())
}

pub(super) fn collect_index_candidates(
    store: &Store,
    axis: TimeAxis,
    rtxn: &RoTxn<'_>,
    collection: TemporalIndexCollectionContext,
    out: &mut HashSet<EntityId>,
) -> Result<()> {
    let TemporalIndexCollectionContext {
        window_start,
        window_end,
        anchor_mid,
        cap,
    } = collection;
    if cap == 0 || window_start > window_end {
        return Ok(());
    }

    let mut rows =
        Vec::<TemporalIndexRow>::with_capacity(cap.saturating_mul(2).min(MAX_TEMPORAL_SEEK_BUFFER));

    let mut forward = store.port_entity_timeline(
        rtxn,
        TimelineQuery {
            axis,
            start: std::ops::Bound::Included(anchor_mid),
            end: std::ops::Bound::Included(window_end),
            ..Default::default()
        },
    )?;
    while rows.len() < cap {
        let Some(row) = next_temporal_index_row(&mut forward)? else {
            break;
        };
        rows.push(row);
    }

    let mut backward = store.port_entity_timeline(
        rtxn,
        TimelineQuery {
            axis,
            start: std::ops::Bound::Included(window_start),
            end: std::ops::Bound::Excluded(anchor_mid),
            reverse: true,
            ..Default::default()
        },
    )?;
    let mut backward_rows = collect_temporal_index_rows(&mut backward, cap)?;
    normalize_backward_boundary_bucket(store, axis, rtxn, &mut backward_rows)?;
    rows.extend(backward_rows);

    rows.sort_unstable_by(|a, b| compare_temporal_index_rows(a, b, anchor_mid));
    for row in rows.into_iter().take(cap) {
        out.insert(row.id);
    }

    Ok(())
}

fn next_temporal_index_row<I>(iter: &mut I) -> Result<Option<TemporalIndexRow>>
where
    I: Iterator<Item = Result<EntityTime>>,
{
    let Some(entry) = iter.next() else {
        return Ok(None);
    };
    let row = entry?;
    Ok(Some(TemporalIndexRow {
        timestamp: row.timestamp,
        id: row.id,
    }))
}

fn collect_temporal_index_rows<I>(iter: &mut I, cap: usize) -> Result<Vec<TemporalIndexRow>>
where
    I: Iterator<Item = Result<EntityTime>>,
{
    let mut rows = Vec::with_capacity(cap.min(MAX_TEMPORAL_SEEK_BUFFER));

    while rows.len() < cap {
        let Some(row) = next_temporal_index_row(iter)? else {
            return Ok(rows);
        };
        rows.push(row);
    }

    Ok(rows)
}

fn normalize_backward_boundary_bucket(
    store: &Store,
    axis: TimeAxis,
    rtxn: &RoTxn<'_>,
    rows: &mut Vec<TemporalIndexRow>,
) -> Result<()> {
    let Some(boundary_timestamp) = rows.last().map(|row| row.timestamp) else {
        return Ok(());
    };

    let boundary_count = rows
        .iter()
        .rev()
        .take_while(|row| row.timestamp == boundary_timestamp)
        .count();
    if boundary_count == 0 {
        return Ok(());
    }

    let original_boundary_rows = rows.split_off(rows.len().saturating_sub(boundary_count));

    let mut boundary_rows = Vec::with_capacity(boundary_count);
    let mut boundary_iter = store.port_entity_timeline(
        rtxn,
        TimelineQuery {
            axis,
            start: std::ops::Bound::Included(boundary_timestamp),
            end: std::ops::Bound::Included(boundary_timestamp),
            ..Default::default()
        },
    )?;
    while boundary_rows.len() < boundary_count {
        let Some(row) = next_temporal_index_row(&mut boundary_iter)? else {
            break;
        };
        boundary_rows.push(row);
    }
    for row in original_boundary_rows {
        if !boundary_rows.iter().any(|candidate| candidate.id == row.id) {
            boundary_rows.push(row);
        }
    }
    boundary_rows.sort_unstable_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
    boundary_rows.truncate(boundary_count);
    rows.extend(boundary_rows);
    Ok(())
}

fn compare_temporal_index_rows(
    left: &TemporalIndexRow,
    right: &TemporalIndexRow,
    anchor_mid: u64,
) -> std::cmp::Ordering {
    anchor_mid
        .abs_diff(left.timestamp)
        .cmp(&anchor_mid.abs_diff(right.timestamp))
        .then_with(|| left.timestamp.cmp(&right.timestamp))
        .then_with(|| left.id.as_bytes().cmp(right.id.as_bytes()))
}

pub(super) fn scoped_text_channel_limit(
    store: &Store,
    rtxn: &RoTxn<'_>,
    requested: usize,
    text_scope_widening_active: bool,
) -> Result<usize> {
    if !text_scope_widening_active || requested == 0 {
        return Ok(requested);
    }
    let indexed_docs = usize::try_from(crate::bm25::read_total_docs(store, rtxn)?)
        .map_err(|_| Error::IndexOverflow("bm25 total docs"))?;
    Ok(requested.max(indexed_docs))
}

pub(super) fn scoped_vector_channel_limit(
    store: &Store,
    rtxn: &RoTxn<'_>,
    requested: usize,
    scope_widening_active: bool,
) -> Result<usize> {
    if !scope_widening_active || requested == 0 {
        return Ok(requested);
    }
    Ok(requested.max(crate::hnsw::hnsw_entity_count(store, rtxn)?))
}

pub(super) fn scoped_entity_channel_limit(
    store: &Store,
    rtxn: &RoTxn<'_>,
    requested: usize,
    scope_widening_active: bool,
) -> Result<usize> {
    if !scope_widening_active || requested == 0 {
        return Ok(requested);
    }
    let entity_count = usize::try_from(store.port_entity_count(rtxn)?)
        .map_err(|_| Error::IndexOverflow("entity count"))?;
    Ok(requested.max(entity_count))
}

pub(super) fn truncate_widened_channel_results_to_scope(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    requested: usize,
    filters: PipelineFilterConfig<'_>,
    metadata_cache: &mut EntityMetadataCache,
    claim_gate: &mut ClaimStatusGateCache,
) -> Result<()> {
    let mut filtered = Vec::with_capacity(requested.min(scores.len()));
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
            if filtered.len() == requested {
                break;
            }
        }
    }

    *scores = filtered;
    Ok(())
}
