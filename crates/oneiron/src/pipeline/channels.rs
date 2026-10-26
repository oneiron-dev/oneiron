use crate::ports::EntityStoreRead;

use heed::RoTxn;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::retrieval_depth::RetrievalDeadline;
use crate::scan_check::{EngineScan, ScanCount};

use crate::ports::{EntityTime, TimeAxis, TimelineQuery};
use crate::store::StoreRead;
use crate::temporal::TemporalAnchorMode;

use super::filters::pipeline_candidate_matches_filters_and_gate;
use super::support::{
    combine_proximity, compute_radius, effective_range_width, interval_distance,
    learned_anchor_range, midpoint, point_interval_distance, resolve_sigma_secs, sigmoid,
};
use super::temporal_bound::{ReadableRows, TemporalCandidates, TemporalWindow, axis_can_grow};
use super::types::{
    ADAPTIVE_ROUNDS, ALPHA_BASE, ALPHA_RANGE, ALPHA_TAU_SECS, ClaimStatusGateCache, EntityMetadata,
    EntityMetadataCache, MAX_TEMPORAL_SEEK_BUFFER, PER_SCAN_CAP_FACTOR, PipelineFilterConfig,
    RECENCY_DECAY_TAU_SECS, ScoredEntity, TEMPORAL_FLOOR, TemporalSearchConfig,
};

#[derive(Debug, Clone, Copy)]
pub(super) struct TemporalCandidateScore {
    pub(super) id: EntityId,
    pub(super) score: f32,
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

#[derive(Clone, Copy)]
pub(super) struct TemporalCandidateCollectionContext<'a> {
    pub(super) radius: u64,
    pub(super) per_scan_cap: usize,
    pub(super) deadline: Option<&'a RetrievalDeadline>,
    /// The last round's radius, when the collector should say whether a
    /// window that wide could add a row.
    pub(super) widest: Option<u64>,
}

#[derive(Clone, Copy)]
pub(super) struct TemporalIndexCollectionContext<'a> {
    pub(super) window_start: u64,
    pub(super) window_end: u64,
    pub(super) anchor_mid: u64,
    pub(super) cap: usize,
    pub(super) deadline: Option<&'a RetrievalDeadline>,
    /// The widest window's bounds, if the collector should probe it.
    pub(super) widest: Option<(u64, u64)>,
}

#[derive(Debug, Clone, Copy)]
struct TemporalIndexRow {
    timestamp: u64,
    id: EntityId,
}

/// `deadline`'s in-stage checkpoint; with no deadline, nothing.
fn checkpoint(deadline: Option<&RetrievalDeadline>) -> Result<()> {
    deadline.map_or(Ok(()), RetrievalDeadline::checkpoint)
}

pub(super) fn execute_phonetic(
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    codes: &[String],
) -> Result<Vec<ScoredEntity>> {
    crate::ports::RetrievalIndexRead::port_retrieval_phonetic_search(store, rtxn, codes)
}

/// The temporal channel. Under a deadline it checks in at every row whose
/// metadata it reads, so a stage past its share stops there instead of
/// finishing a scan that can cover the whole vault.
pub(super) fn execute_temporal(
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    config: &TemporalSearchConfig,
    now: u64,
    metadata_cache: &mut EntityMetadataCache,
    deadline: Option<&RetrievalDeadline>,
) -> Result<Vec<ScoredEntity>> {
    let Some(mut held) = temporal_window(store, rtxn, config, now, metadata_cache, deadline, None)?
    else {
        return Ok(Vec::new());
    };
    held.scored.truncate(held.rows);
    held.rescore(store, rtxn, config, metadata_cache)?;
    Ok(held.into_scores())
}

/// Runs a temporal call's rounds and scores what its window holds; `None`
/// for a call that asks for nothing. With a `reader`, only the rows it may
/// read count toward either stop ([`ReadableRows`]).
pub(super) fn temporal_window(
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    config: &TemporalSearchConfig,
    now: u64,
    metadata_cache: &mut EntityMetadataCache,
    deadline: Option<&RetrievalDeadline>,
    reader: Option<&ReadableRows<'_, '_>>,
) -> Result<Option<TemporalWindow>> {
    if config.limit == 0 {
        return Ok(None);
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
    // A scoped call scans and returns its widened rows. Its window grows
    // until it can fill them, and it keeps the rows an unscoped call for that
    // many rows would, but scores and orders them with the sigma the request
    // settles on: the one in force once the window could fill the request.
    let rows = config.widened.unwrap_or(config.limit);
    let per_scan_cap = rows.saturating_mul(PER_SCAN_CAP_FACTOR).max(1);

    let mut sigma = sigma_initial;
    let mut settled_sigma = None;
    let mut settled_round = None;
    let mut rounds = 0;
    let mut previous_radius = None;
    let mut candidates = TemporalCandidates::default();
    // With a reader, the collectors say whether the last round's window could
    // add a row; until one says it could not, assume it could.
    let widest = reader.filter(|_| config.adaptive).map(|_| {
        let last = (1..ADAPTIVE_ROUNDS).fold(sigma, |sigma, _| sigma.saturating_mul(2).max(1));
        compute_radius(range_width, last)
    });
    let mut can_grow = true;

    for round in 0..ADAPTIVE_ROUNDS {
        rounds = round + 1;
        let radius = compute_radius(range_width, sigma);

        if can_grow && (round == 0 || previous_radius != Some(radius)) {
            let collection = TemporalCandidateCollectionContext {
                radius,
                per_scan_cap,
                deadline,
                widest,
            };
            let scoring = TemporalScoringContext {
                sigma,
                now,
                anchor_mid,
                learned_anchor,
                learned_anchor_mid,
            };
            can_grow = collect_temporal_candidates(
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

        let last = !config.adaptive || round + 1 == ADAPTIVE_ROUNDS;
        if let Some(reader) = reader {
            // A last round needs no count to settle sigma: unsettled, the
            // request falls back to that round's sigma anyway.
            if settled_sigma.is_none()
                && !last
                && reader.read_at_least(store, rtxn, candidates.ids(), config.limit)?
            {
                settled_sigma = Some(sigma);
                settled_round = Some(rounds);
            }
            // Once no wider window can add a row, the rounds left change
            // only the window's sigma, and that picks nothing: the bound cuts
            // only when the reader may read more rows than it keeps, and then
            // the window stops here anyway. Run them out only to settle
            // sigma, which needs no collection.
            if last
                || (!can_grow && settled_sigma.is_some())
                || (can_grow && reader.read_at_least(store, rtxn, candidates.ids(), rows)?)
            {
                break;
            }
        } else {
            if settled_sigma.is_none() && candidates.count() >= config.limit {
                settled_sigma = Some(sigma);
                settled_round = Some(rounds);
            }
            if last || candidates.count() >= rows {
                break;
            }
        }

        sigma = sigma.saturating_mul(2).max(1);
    }

    let window = TemporalScoringContext {
        sigma,
        now,
        anchor_mid,
        learned_anchor,
        learned_anchor_mid,
    };
    let request = TemporalScoringContext {
        sigma: settled_sigma.unwrap_or(sigma),
        ..window
    };

    metadata_cache.temporal_report = Some(super::TemporalSearchReport {
        sigma_secs: request.sigma,
        rounds: settled_round.unwrap_or(rounds),
    });

    let mut scored = Vec::<TemporalCandidateScore>::new();

    for &id in candidates.ids() {
        checkpoint(deadline)?;
        let Some(meta) = metadata_cache.get(store, rtxn, &id)? else {
            continue;
        };
        if config.query_occurred_range.is_some_and(|(start, end)| {
            !super::support::intervals_overlap(meta.occurred_start, meta.occurred_end, start, end)
        }) {
            continue;
        }
        scored.push(score_temporal_candidate(id, meta, config, &window));
    }

    sort_temporal_candidate_scores(&mut scored);
    Ok(Some(TemporalWindow {
        scored,
        window,
        request,
        rows,
    }))
}

pub(super) fn collect_temporal_candidates(
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    config: &TemporalSearchConfig,
    collection: TemporalCandidateCollectionContext<'_>,
    metadata_cache: &mut EntityMetadataCache,
    scoring: &TemporalScoringContext,
    out: &mut TemporalCandidates,
) -> Result<bool> {
    let deadline = collection.deadline;
    let radius = collection.radius;
    let per_scan_cap = collection.per_scan_cap;
    let occurred_window_start = config.anchor_start.saturating_sub(radius);
    let occurred_window_end = config.anchor_end.saturating_add(radius);
    let occurred_mid = midpoint(config.anchor_start, config.anchor_end);

    let (learned_anchor_start, learned_anchor_end) = learned_anchor_range(config)?;

    let learned_window_start = learned_anchor_start.saturating_sub(radius);
    let learned_window_end = learned_anchor_end.saturating_add(radius);
    let learned_mid = midpoint(learned_anchor_start, learned_anchor_end);

    let widest = |start: u64, end: u64| {
        collection
            .widest
            .map(|radius| (start.saturating_sub(radius), end.saturating_add(radius)))
    };
    let occurred_collection = TemporalIndexCollectionContext {
        window_start: occurred_window_start,
        window_end: occurred_window_end,
        anchor_mid: occurred_mid,
        cap: per_scan_cap,
        deadline,
        widest: widest(config.anchor_start, config.anchor_end),
    };
    let learned_collection = TemporalIndexCollectionContext {
        window_start: learned_window_start,
        window_end: learned_window_end,
        anchor_mid: learned_mid,
        cap: per_scan_cap,
        deadline,
        widest: widest(learned_anchor_start, learned_anchor_end),
    };

    let mut can_grow = match config.anchor_mode {
        TemporalAnchorMode::Occurred => collect_occurred_candidates(
            store,
            rtxn,
            occurred_collection,
            metadata_cache,
            config.query_occurred_range,
            out,
        )?,
        TemporalAnchorMode::Learned => {
            collect_index_candidates(store, TimeAxis::Learned, rtxn, learned_collection, out)?
        }
        TemporalAnchorMode::Auto | TemporalAnchorMode::Both => {
            let occurred = collect_occurred_candidates(
                store,
                rtxn,
                occurred_collection,
                metadata_cache,
                config.query_occurred_range,
                out,
            )?;
            collect_index_candidates(store, TimeAxis::Learned, rtxn, learned_collection, out)?
                || occurred
        }
    };

    if config.anchor_mode != TemporalAnchorMode::Learned {
        // Keep the top `per_scan_cap` spanners by the same exact temporal score
        // used later in `temporal_window()`. Since `per_scan_cap` is 4x the
        // final result limit, anything outside this top-k cannot enter the
        // final top-k after exact scoring. The buffer fills to twice the cap
        // before it drops back to the cap, so a spanner costs amortized
        // constant work however large the cap is.
        let mut spanners = Vec::<TemporalCandidateScore>::new();
        let trim_threshold = per_scan_cap.saturating_mul(2);
        let mut spanning = 0_usize;
        // Every spanner is read, so the exact top-k is kept: past the index's
        // threshold row the scan raises one check and reads on.
        let mut scanned = ScanCount::start(store, rtxn, EngineScan::TemporalSpannerRows, &[])?;
        for entry in store.port_entity_long_ending_after(rtxn, occurred_window_end)? {
            let (id, range) = entry?;
            scanned.row();
            checkpoint(deadline)?;
            if range.start >= occurred_window_start {
                continue;
            }
            let Some(meta) = metadata_cache.get(store, rtxn, &id)? else {
                continue;
            };
            if config.query_occurred_range.is_some_and(|(start, end)| {
                !super::support::intervals_overlap(
                    meta.occurred_start,
                    meta.occurred_end,
                    start,
                    end,
                )
            }) {
                continue;
            }
            spanners.push(score_temporal_candidate(id, meta, config, scoring));
            spanning += 1;

            if spanners.len() >= trim_threshold {
                retain_best_temporal_candidate_scores(&mut spanners, per_scan_cap);
                #[cfg(test)]
                SPANNER_TRIMS.with(|trims| trims.set(trims.get() + 1));
            }
        }
        scanned.defer(store);

        sort_temporal_candidate_scores(&mut spanners);
        spanners.truncate(per_scan_cap);
        for candidate in spanners {
            out.insert(candidate.id);
        }
        // A wider window's spanners span this one too, so it adds none while
        // every one of them is kept here.
        can_grow |= spanning > per_scan_cap;
    }

    Ok(can_grow)
}

pub(super) fn score_temporal_candidate(
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

fn compare_temporal_candidate_scores(
    a: &TemporalCandidateScore,
    b: &TemporalCandidateScore,
) -> std::cmp::Ordering {
    b.score
        .total_cmp(&a.score)
        .then_with(|| a.overlap_tiebreak.cmp(&b.overlap_tiebreak))
        .then_with(|| a.id.as_bytes().cmp(b.id.as_bytes()))
}

pub(super) fn sort_temporal_candidate_scores(scores: &mut [TemporalCandidateScore]) {
    scores.sort_unstable_by(compare_temporal_candidate_scores);
}

/// Keeps the `keep` best of `scores`, unordered: the set a sort and
/// truncation keeps, in linear time.
fn retain_best_temporal_candidate_scores(scores: &mut Vec<TemporalCandidateScore>, keep: usize) {
    if scores.len() > keep {
        scores.select_nth_unstable_by(keep, compare_temporal_candidate_scores);
        scores.truncate(keep);
    }
}

#[cfg(test)]
thread_local! {
    /// Intermediate trims of the spanner buffer on this thread.
    pub(super) static SPANNER_TRIMS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn collect_occurred_candidates(
    store: &StoreRead<'_>,
    rtxn: &RoTxn<'_>,
    collection: TemporalIndexCollectionContext<'_>,
    metadata_cache: &mut EntityMetadataCache,
    query_range: Option<(u64, u64)>,
    out: &mut TemporalCandidates,
) -> Result<bool> {
    let mut can_grow = false;
    for axis in [TimeAxis::OccurredStart, TimeAxis::OccurredEnd] {
        can_grow |= if let Some(range) = query_range {
            // Widened temporal scans include nearby non-overlapping rows.
            // Do not let them consume a scan cap before the occurred filter.
            collect_query_occurred_candidates(
                store,
                axis,
                rtxn,
                collection,
                metadata_cache,
                range,
                out,
            )?
        } else {
            collect_index_candidates(store, axis, rtxn, collection, out)?
        };
    }
    Ok(can_grow)
}

fn collect_query_occurred_candidates(
    store: &StoreRead<'_>,
    axis: TimeAxis,
    rtxn: &RoTxn<'_>,
    collection: TemporalIndexCollectionContext<'_>,
    metadata_cache: &mut EntityMetadataCache,
    query_range: (u64, u64),
    out: &mut TemporalCandidates,
) -> Result<bool> {
    let TemporalIndexCollectionContext {
        window_start,
        window_end,
        anchor_mid,
        cap,
        deadline,
        ..
    } = collection;
    if cap == 0 || window_start > window_end {
        return Ok(cap != 0);
    }
    let forward = store.port_entity_timeline(
        rtxn,
        TimelineQuery {
            axis,
            start: std::ops::Bound::Included(anchor_mid),
            end: std::ops::Bound::Included(window_end),
            ..Default::default()
        },
    )?;
    let backward = store.port_entity_timeline(
        rtxn,
        TimelineQuery {
            axis,
            start: std::ops::Bound::Included(window_start),
            end: std::ops::Bound::Excluded(anchor_mid),
            reverse: true,
            ..Default::default()
        },
    )?;
    let mut rows = Vec::<TemporalIndexRow>::with_capacity(cap.min(MAX_TEMPORAL_SEEK_BUFFER));
    let trim_threshold = cap.saturating_mul(2).max(1);
    let (mut forward_rows, mut backward_rows) = (0_usize, 0_usize);
    // Both halves are read whole, so the range's exact top-k is kept: past the
    // index's threshold row the scan raises one check and reads on.
    let mut scanned = ScanCount::start(store, rtxn, EngineScan::OccurredRangeRows, &[])?;
    for entry in forward.chain(backward) {
        let time = entry?;
        scanned.row();
        checkpoint(deadline)?;
        let Some(meta) = metadata_cache.get(store, rtxn, &time.id)? else {
            continue;
        };
        if !super::support::intervals_overlap(
            meta.occurred_start,
            meta.occurred_end,
            query_range.0,
            query_range.1,
        ) {
            continue;
        }
        if time.timestamp >= anchor_mid {
            forward_rows += 1;
        } else {
            backward_rows += 1;
        }
        rows.push(TemporalIndexRow {
            timestamp: time.timestamp,
            id: time.id,
        });
        if rows.len() > trim_threshold {
            rows.sort_unstable_by(|a, b| compare_temporal_index_rows(a, b, anchor_mid));
            rows.truncate(cap);
        }
    }
    scanned.defer(store);
    rows.sort_unstable_by(|a, b| compare_temporal_index_rows(a, b, anchor_mid));
    for row in rows.into_iter().take(cap) {
        out.insert(row.id);
    }
    Ok(axis_can_grow(
        store,
        axis,
        rtxn,
        collection,
        [forward_rows >= cap, backward_rows >= cap],
    ))
}

pub(super) fn collect_index_candidates(
    store: &StoreRead<'_>,
    axis: TimeAxis,
    rtxn: &RoTxn<'_>,
    collection: TemporalIndexCollectionContext<'_>,
    out: &mut TemporalCandidates,
) -> Result<bool> {
    let TemporalIndexCollectionContext {
        window_start,
        window_end,
        anchor_mid,
        cap,
        ..
    } = collection;
    if cap == 0 || window_start > window_end {
        return Ok(cap != 0);
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
    let forward_full = rows.len() >= cap;

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
    let backward_full = backward_rows.len() >= cap;
    normalize_backward_boundary_bucket(store, axis, rtxn, &mut backward_rows)?;
    rows.extend(backward_rows);

    rows.sort_unstable_by(|a, b| compare_temporal_index_rows(a, b, anchor_mid));
    for row in rows.into_iter().take(cap) {
        out.insert(row.id);
    }

    Ok(axis_can_grow(
        store,
        axis,
        rtxn,
        collection,
        [forward_full, backward_full],
    ))
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
    store: &StoreRead<'_>,
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

/// How many rows a ranked channel fetches for a caller that asked for
/// `requested`: at least the [`FUSION_LIST_LENGTH`] fusion scales each list
/// by, so the scale does not move with the pack's limit. Zero stays zero.
///
/// [`FUSION_LIST_LENGTH`]: crate::fusion::FUSION_LIST_LENGTH
pub(super) fn fusion_fetch_limit(requested: usize) -> usize {
    if requested == 0 {
        0
    } else {
        requested.max(crate::fusion::FUSION_LIST_LENGTH)
    }
}

/// How many rows a text channel fetches for `requested`: never past the
/// window, [`MAX_SEARCH_LIMIT`] or the run's own deeper `depth`. A scoped
/// scan admits through its scope while it scores: no wider fetch.
///
/// [`MAX_SEARCH_LIMIT`]: crate::memory::caps::MAX_SEARCH_LIMIT
pub(super) fn scoped_text_channel_limit(requested: usize, depth: usize) -> usize {
    requested.min(crate::memory::caps::MAX_SEARCH_LIMIT.max(depth))
}

/// How many rows a vector walk fetches for `requested`: a `narrowed` walk,
/// whose scope admits inside it, the whole window (as above); any other the
/// request, never past the window. Zero stays zero.
pub(super) fn scoped_vector_channel_limit(requested: usize, narrowed: bool, depth: usize) -> usize {
    let window = crate::memory::caps::MAX_SEARCH_LIMIT.max(depth);
    if requested == 0 {
        0
    } else if narrowed {
        window
    } else {
        requested.min(window)
    }
}

pub(super) fn truncate_widened_channel_results_to_scope(
    scores: &mut Vec<ScoredEntity>,
    store: &StoreRead<'_>,
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
