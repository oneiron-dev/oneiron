use std::collections::{HashMap, HashSet};

use heed::types::Bytes;
use heed::{Database, RoTxn};

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::error::{Error, Result};
use crate::fusion;
use crate::store::Store;
use crate::types::{EntityId, ScoredEntity, TemporalAnchorMode, TemporalGranularity, TimeRange};
use crate::Vault;

const DEFAULT_RESULT_LIMIT: usize = 20;
const DEFAULT_SIGMA_SECS: u64 = 86_400;
const MIN_WINDOW_RADIUS_SECS: u64 = 7 * 86_400;
const LONG_INTERVAL_THRESHOLD_SECS: u64 = 14 * 86_400;
const TEMPORAL_FLOOR: f64 = 0.05;
const ADAPTIVE_ROUNDS: usize = 3;
const PER_SCAN_CAP_FACTOR: usize = 4;
const RRF_K: f32 = 60.0;

#[derive(Debug, Clone)]
struct TemporalSearchConfig {
    anchor_start: u64,
    anchor_end: u64,
    learned_start: Option<u64>,
    learned_end: Option<u64>,
    sigma_secs: u64,
    anchor_mode: TemporalAnchorMode,
    adaptive: bool,
    limit: usize,
}

#[derive(Debug, Clone, Copy)]
struct EntityMetadata {
    entity_type: u8,
    occurred_start: u64,
    occurred_end: u64,
    learned_at: u64,
}

#[derive(Debug, Clone, Copy)]
struct TemporalCandidateScore {
    id: EntityId,
    score: f32,
    overlap_tiebreak: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct PhoneticAccumulator {
    score: f32,
    matches: usize,
}

pub struct PipelineBuilder<'a> {
    vault: &'a Vault,
    vector_search: Option<(Vec<f32>, usize)>,
    text_search: Option<(String, usize)>,
    phonetic_search: Option<Vec<String>>,
    temporal_search: Option<TemporalSearchConfig>,
    ppr_search: Option<(Vec<EntityId>, u32)>,
    ppr_expand: Option<(Vec<EntityId>, u32)>,
    recency_half_life: Option<f32>,
    apply_salience: bool,
    apply_confidence: bool,
    apply_contiguity: bool,
    type_filter: Option<Vec<u8>>,
    since_filter: Option<u64>,
    occurred_range: Option<(u64, u64)>,
    learned_range: Option<(u64, u64)>,
    result_limit: usize,
    temporal_adaptive_default: bool,
}

impl<'a> PipelineBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            vector_search: None,
            text_search: None,
            phonetic_search: None,
            temporal_search: None,
            ppr_search: None,
            ppr_expand: None,
            recency_half_life: None,
            apply_salience: false,
            apply_confidence: false,
            apply_contiguity: false,
            type_filter: None,
            since_filter: None,
            occurred_range: None,
            learned_range: None,
            result_limit: DEFAULT_RESULT_LIMIT,
            temporal_adaptive_default: true,
        }
    }

    pub fn search_vector(mut self, vector: &[f32], limit: usize) -> Self {
        self.vector_search = Some((vector.to_vec(), limit));
        self
    }

    pub fn search_text(mut self, query: &str, limit: usize) -> Self {
        self.text_search = Some((query.to_owned(), limit));
        self
    }

    pub fn search_phonetic(mut self, codes: &[&str]) -> Self {
        self.phonetic_search = Some(codes.iter().map(|code| (*code).to_owned()).collect());
        self
    }

    pub fn search_temporal(mut self, anchor_start: u64, anchor_end: u64, limit: usize) -> Self {
        let (anchor_start, anchor_end) = normalize_range(anchor_start, anchor_end);
        let width = anchor_end.saturating_sub(anchor_start);
        let sigma_secs = width.max(DEFAULT_SIGMA_SECS);
        self.temporal_search = Some(TemporalSearchConfig {
            anchor_start,
            anchor_end,
            learned_start: None,
            learned_end: None,
            sigma_secs,
            anchor_mode: TemporalAnchorMode::Auto,
            adaptive: self.temporal_adaptive_default,
            limit,
        });
        self
    }

    pub fn search_temporal_with_sigma(
        mut self,
        anchor_start: u64,
        anchor_end: u64,
        sigma_secs: u64,
        anchor_mode: TemporalAnchorMode,
        limit: usize,
    ) -> Self {
        let (anchor_start, anchor_end) = normalize_range(anchor_start, anchor_end);
        self.temporal_search = Some(TemporalSearchConfig {
            anchor_start,
            anchor_end,
            learned_start: None,
            learned_end: None,
            sigma_secs,
            anchor_mode,
            adaptive: self.temporal_adaptive_default,
            limit,
        });
        self
    }

    pub fn search_temporal_with_granularity(
        mut self,
        anchor_start: u64,
        anchor_end: u64,
        granularity: TemporalGranularity,
        anchor_mode: TemporalAnchorMode,
        limit: usize,
    ) -> Self {
        let (anchor_start, anchor_end) = normalize_range(anchor_start, anchor_end);
        self.temporal_search = Some(TemporalSearchConfig {
            anchor_start,
            anchor_end,
            learned_start: None,
            learned_end: None,
            sigma_secs: granularity.sigma_secs(),
            anchor_mode,
            adaptive: self.temporal_adaptive_default,
            limit,
        });
        self
    }

    pub fn search_temporal_bitemporal(
        mut self,
        occurred_start: u64,
        occurred_end: u64,
        learned_start: u64,
        learned_end: u64,
        sigma_secs: u64,
        limit: usize,
    ) -> Self {
        let (anchor_start, anchor_end) = normalize_range(occurred_start, occurred_end);
        let (learned_start, learned_end) = normalize_range(learned_start, learned_end);
        self.temporal_search = Some(TemporalSearchConfig {
            anchor_start,
            anchor_end,
            learned_start: Some(learned_start),
            learned_end: Some(learned_end),
            sigma_secs,
            anchor_mode: TemporalAnchorMode::Both,
            adaptive: self.temporal_adaptive_default,
            limit,
        });
        self
    }

    pub fn temporal_adaptive(mut self, enabled: bool) -> Self {
        self.temporal_adaptive_default = enabled;
        if let Some(config) = self.temporal_search.as_mut() {
            config.adaptive = enabled;
        }
        self
    }

    pub fn search(
        mut self,
        query: &str,
        vector: &[f32],
        time: Option<TimeRange>,
        limit: usize,
    ) -> Self {
        self = self.search_text(query, limit).search_vector(vector, limit);
        if let Some(range) = time {
            self = self.search_temporal(range.start, range.end, limit);
        }
        self.limit(limit)
    }

    pub fn search_ppr(mut self, seeds: &[EntityId], depth: u32) -> Self {
        self.ppr_search = Some((seeds.to_vec(), depth));
        self
    }

    pub fn expand_ppr(mut self, seeds: &[EntityId], depth: u32) -> Self {
        self.ppr_expand = Some((seeds.to_vec(), depth));
        self
    }

    pub fn boost_recency(mut self, half_life_days: f32) -> Self {
        self.recency_half_life = Some(half_life_days);
        self
    }

    pub fn boost_salience(mut self) -> Self {
        self.apply_salience = true;
        self
    }

    pub fn boost_confidence(mut self) -> Self {
        self.apply_confidence = true;
        self
    }

    pub fn boost_contiguity(mut self) -> Self {
        self.apply_contiguity = true;
        self
    }

    pub fn filter_types(mut self, types: &[u8]) -> Self {
        self.type_filter = Some(types.to_vec());
        self
    }

    pub fn filter_since(mut self, timestamp: u64) -> Self {
        self.since_filter = Some(timestamp);
        self
    }

    pub fn filter_occurred_range(mut self, start: u64, end: u64) -> Self {
        self.occurred_range = Some(normalize_range(start, end));
        self
    }

    pub fn filter_learned_range(mut self, start: u64, end: u64) -> Self {
        self.learned_range = Some(normalize_range(start, end));
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.result_limit = n;
        self
    }

    pub fn run(self) -> Result<Vec<ScoredEntity>> {
        let mut ranked_lists = Vec::new();

        {
            let rtxn = self.vault.store.env.read_txn()?;

            if let Some((query_vector, limit)) = &self.vector_search {
                if query_vector.len() != self.vault.config.dimensions {
                    return Err(Error::DimensionMismatch {
                        expected: self.vault.config.dimensions,
                        got: query_vector.len(),
                    });
                }
                if query_vector.iter().any(|value| !value.is_finite()) {
                    return Err(Error::InvalidVector);
                }

                let vector_results = crate::hnsw::hnsw_search(
                    &self.vault.store,
                    &self.vault.config,
                    &rtxn,
                    query_vector,
                    *limit,
                )?;
                ranked_lists.push(vector_results);
            }

            if let Some((query, limit)) = &self.text_search {
                let text_results =
                    crate::bm25::search_text(&self.vault.store, &rtxn, query, *limit)?;
                ranked_lists.push(text_results);
            }

            if let Some(codes) = &self.phonetic_search {
                let phonetic_results = execute_phonetic(&self.vault.store, &rtxn, codes)?;
                ranked_lists.push(phonetic_results);
            }

            if let Some(config) = &self.temporal_search {
                let temporal_results = execute_temporal(&self.vault.store, &rtxn, config)?;
                ranked_lists.push(temporal_results);
            }
        }

        if let Some((seeds, depth)) = &self.ppr_search {
            let ppr_results =
                crate::ppr::ppr_query(&self.vault.store, &self.vault.config, seeds, *depth, 0.15)?;
            ranked_lists.push(ppr_results);
        }

        if ranked_lists.is_empty() {
            return Ok(Vec::new());
        }

        let mut scores = fusion::rrf_fuse(&ranked_lists, RRF_K);

        if let Some((explicit_seeds, depth)) = &self.ppr_expand {
            let mut combined = HashSet::<EntityId>::new();
            for scored in scores.iter().take(self.result_limit) {
                combined.insert(scored.id);
            }
            for seed in explicit_seeds {
                combined.insert(*seed);
            }

            if !combined.is_empty() {
                let mut seeds: Vec<EntityId> = combined.into_iter().collect();
                seeds.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

                let ppr_results = crate::ppr::ppr_query(
                    &self.vault.store,
                    &self.vault.config,
                    &seeds,
                    *depth,
                    0.15,
                )?;
                scores = fusion::rrf_fuse(&[scores, ppr_results], RRF_K);
            }
        }

        {
            let rtxn = self.vault.store.env.read_txn()?;

            if self.temporal_search.is_none() {
                if let Some(half_life_days) = self.recency_half_life {
                    fusion::boost_recency(&mut scores, half_life_days, &self.vault.store, &rtxn)?;
                }
            }

            if self.apply_salience {
                fusion::boost_salience(&mut scores, &self.vault.store, &rtxn)?;
            }

            if self.apply_confidence {
                fusion::boost_confidence(&mut scores, &self.vault.store, &rtxn)?;
            }

            if self.apply_contiguity {
                boost_contiguity(
                    &mut scores,
                    self.temporal_search.as_ref(),
                    &self.vault.store,
                    &rtxn,
                )?;
            }

            apply_filters(
                &mut scores,
                &self.vault.store,
                &rtxn,
                self.type_filter.as_deref(),
                self.since_filter,
                self.occurred_range,
                self.learned_range,
            )?;
        }

        scores.sort_unstable_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.id.as_bytes().cmp(b.id.as_bytes()))
        });
        scores.truncate(self.result_limit);
        Ok(scores)
    }
}

fn execute_phonetic(
    store: &Store,
    rtxn: &RoTxn<'_>,
    codes: &[String],
) -> Result<Vec<ScoredEntity>> {
    let mut unique = codes.to_vec();
    unique.sort();
    unique.dedup();

    let mut accumulators = HashMap::<EntityId, PhoneticAccumulator>::new();

    for code in unique {
        let Some(posting) = store.phonetic_index.get(rtxn, code.as_bytes())? else {
            continue;
        };

        if !posting.len().is_multiple_of(16) {
            return Err(Error::InvalidKey);
        }

        for chunk in posting.chunks_exact(16) {
            let id = EntityId::from_bytes(chunk.try_into().map_err(|_| Error::InvalidKey)?);
            let entry = accumulators.entry(id).or_default();
            entry.score += 1.0;
            entry.matches += 1;
        }
    }

    let mut out: Vec<ScoredEntity> = accumulators
        .into_iter()
        .map(|(id, accumulator)| {
            let boosted = if accumulator.matches >= 2 {
                accumulator.score * 1.2
            } else {
                accumulator.score
            };
            ScoredEntity { id, score: boosted }
        })
        .collect();

    out.sort_unstable_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.id.as_bytes().cmp(b.id.as_bytes()))
    });
    Ok(out)
}

fn execute_temporal(
    store: &Store,
    rtxn: &RoTxn<'_>,
    config: &TemporalSearchConfig,
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

    let range_width = effective_range_width(config.anchor_start, config.anchor_end);
    let per_scan_cap = config.limit.saturating_mul(PER_SCAN_CAP_FACTOR).max(1);

    let mut sigma = sigma_initial;
    let mut previous_radius = None;
    let mut candidates = HashSet::<EntityId>::new();

    for round in 0..ADAPTIVE_ROUNDS {
        let radius = compute_radius(range_width, sigma);

        if round == 0 || previous_radius != Some(radius) {
            collect_temporal_candidates(
                store,
                rtxn,
                config,
                radius,
                per_scan_cap,
                &mut candidates,
            )?;
        }

        previous_radius = Some(radius);

        if !config.adaptive || candidates.len() >= config.limit || round + 1 == ADAPTIVE_ROUNDS {
            break;
        }

        sigma = sigma.saturating_mul(2).max(1);
    }

    let now = crate::unix_seconds_now();
    let anchor_mid = midpoint(config.anchor_start, config.anchor_end);

    let learned_anchor = learned_anchor_range(config)?;

    let mut scored = Vec::<TemporalCandidateScore>::new();

    for id in candidates {
        let Some(meta) = read_entity_metadata(store, rtxn, &id)? else {
            continue;
        };

        let d_occ = interval_distance(
            meta.occurred_start,
            meta.occurred_end,
            config.anchor_start,
            config.anchor_end,
        );
        let d_lrn = point_interval_distance(meta.learned_at, learned_anchor.0, learned_anchor.1);

        let s_occ_prox = sigmoid(d_occ, sigma, TEMPORAL_FLOOR);
        let s_lrn_prox = sigmoid(d_lrn, sigma, TEMPORAL_FLOOR);

        let s_proximity =
            combine_proximity(config.anchor_mode, s_occ_prox, s_lrn_prox, TEMPORAL_FLOOR);

        let age = now.saturating_sub(meta.learned_at) as f64;
        let s_recency = (-age / (28.0 * 86_400.0)).exp();

        let anchor_age = now.abs_diff(config.anchor_end) as f64;
        let alpha = 0.7 + 0.3 * (1.0 - (-anchor_age / (90.0 * 86_400.0)).exp());

        let score = (alpha * s_proximity + (1.0 - alpha) * s_recency) as f32;
        let overlap_tiebreak = if d_occ == 0 {
            midpoint(meta.occurred_start, meta.occurred_end).abs_diff(anchor_mid)
        } else {
            u64::MAX
        };

        scored.push(TemporalCandidateScore {
            id,
            score,
            overlap_tiebreak,
        });
    }

    scored.sort_unstable_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.overlap_tiebreak.cmp(&b.overlap_tiebreak))
            .then_with(|| a.id.as_bytes().cmp(b.id.as_bytes()))
    });
    scored.truncate(config.limit);

    Ok(scored
        .into_iter()
        .map(|entry| ScoredEntity {
            id: entry.id,
            score: entry.score,
        })
        .collect())
}

fn collect_temporal_candidates(
    store: &Store,
    rtxn: &RoTxn<'_>,
    config: &TemporalSearchConfig,
    radius: u64,
    per_scan_cap: usize,
    out: &mut HashSet<EntityId>,
) -> Result<()> {
    let occurred_window_start = config.anchor_start.saturating_sub(radius);
    let occurred_window_end = config.anchor_end.saturating_add(radius);
    let occurred_mid = midpoint(config.anchor_start, config.anchor_end);

    let (learned_anchor_start, learned_anchor_end) = learned_anchor_range(config)?;

    let learned_window_start = learned_anchor_start.saturating_sub(radius);
    let learned_window_end = learned_anchor_end.saturating_add(radius);
    let learned_mid = midpoint(learned_anchor_start, learned_anchor_end);

    match config.anchor_mode {
        TemporalAnchorMode::Occurred => {
            collect_occurred_candidates(
                store,
                rtxn,
                occurred_window_start,
                occurred_window_end,
                occurred_mid,
                per_scan_cap,
                out,
            )?;
        }
        TemporalAnchorMode::Learned => {
            collect_index_candidates(
                &store.temporal_learned,
                rtxn,
                learned_window_start,
                learned_window_end,
                learned_mid,
                per_scan_cap,
                out,
            )?;
        }
        TemporalAnchorMode::Auto | TemporalAnchorMode::Both => {
            collect_occurred_candidates(
                store,
                rtxn,
                occurred_window_start,
                occurred_window_end,
                occurred_mid,
                per_scan_cap,
                out,
            )?;
            collect_index_candidates(
                &store.temporal_learned,
                rtxn,
                learned_window_start,
                learned_window_end,
                learned_mid,
                per_scan_cap,
                out,
            )?;
        }
    }

    if config.anchor_mode != TemporalAnchorMode::Learned {
        for entry in store.temporal_long_intervals.iter(rtxn)? {
            let (id_bytes, value) = entry?;
            if id_bytes.len() != 16 || value.len() != 16 {
                return Err(Error::InvalidKey);
            }

            let id = EntityId::from_bytes(id_bytes.try_into().map_err(|_| Error::InvalidKey)?);
            let occurred_start =
                u64::from_be_bytes(value[..8].try_into().map_err(|_| Error::InvalidKey)?);
            let occurred_end =
                u64::from_be_bytes(value[8..16].try_into().map_err(|_| Error::InvalidKey)?);

            if occurred_start < occurred_window_start && occurred_end > occurred_window_end {
                out.insert(id);
            }
        }
    }

    Ok(())
}

fn collect_occurred_candidates(
    store: &Store,
    rtxn: &RoTxn<'_>,
    window_start: u64,
    window_end: u64,
    anchor_mid: u64,
    cap: usize,
    out: &mut HashSet<EntityId>,
) -> Result<()> {
    collect_index_candidates(
        &store.temporal_occurred_start,
        rtxn,
        window_start,
        window_end,
        anchor_mid,
        cap,
        out,
    )?;
    collect_index_candidates(
        &store.temporal_occurred_end,
        rtxn,
        window_start,
        window_end,
        anchor_mid,
        cap,
        out,
    )?;
    Ok(())
}

fn collect_index_candidates(
    db: &Database<Bytes, Bytes>,
    rtxn: &RoTxn<'_>,
    window_start: u64,
    window_end: u64,
    anchor_mid: u64,
    cap: usize,
    out: &mut HashSet<EntityId>,
) -> Result<()> {
    let mut rows = Vec::<(u64, u64, EntityId)>::new();

    for entry in db.iter(rtxn)? {
        let (key, _) = entry?;
        if key.len() != 24 {
            return Err(Error::InvalidKey);
        }

        let timestamp = u64::from_be_bytes(key[..8].try_into().map_err(|_| Error::InvalidKey)?);
        if timestamp < window_start || timestamp > window_end {
            continue;
        }

        let id = EntityId::from_bytes(key[8..24].try_into().map_err(|_| Error::InvalidKey)?);
        rows.push((anchor_mid.abs_diff(timestamp), timestamp, id));
    }

    rows.sort_unstable_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.cmp(&b.1))
            .then_with(|| a.2.as_bytes().cmp(b.2.as_bytes()))
    });

    for (_, _, id) in rows.into_iter().take(cap) {
        out.insert(id);
    }

    Ok(())
}

fn boost_contiguity(
    scores: &mut [ScoredEntity],
    temporal_config: Option<&TemporalSearchConfig>,
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<()> {
    let Some(config) = temporal_config else {
        return Ok(());
    };

    if scores.len() <= 1 {
        return Ok(());
    }

    let sigma_contig = resolve_sigma_secs(config.sigma_secs).min(LONG_INTERVAL_THRESHOLD_SECS);

    let metadata: Vec<Option<EntityMetadata>> = scores
        .iter()
        .map(|scored| read_entity_metadata(store, rtxn, &scored.id))
        .collect::<Result<Vec<_>>>()?;

    let denom = (scores.len() - 1) as f32;
    for (idx, maybe_current) in metadata.iter().enumerate() {
        let Some(current) = *maybe_current else {
            continue;
        };

        let mut neighbors = 0_usize;
        for (j, maybe_other) in metadata.iter().enumerate() {
            if idx == j {
                continue;
            }
            let Some(other) = *maybe_other else {
                continue;
            };

            let distance = if config.anchor_mode == TemporalAnchorMode::Learned {
                current.learned_at.abs_diff(other.learned_at)
            } else {
                interval_distance(
                    current.occurred_start,
                    current.occurred_end,
                    other.occurred_start,
                    other.occurred_end,
                )
            };

            if distance < sigma_contig {
                neighbors += 1;
            }
        }

        let contiguity = neighbors as f32 / denom.max(1.0);
        scores[idx].score *= 1.0 + 0.2 * contiguity;
    }

    Ok(())
}

fn apply_filters(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    type_filter: Option<&[u8]>,
    since_filter: Option<u64>,
    occurred_range: Option<(u64, u64)>,
    learned_range: Option<(u64, u64)>,
) -> Result<()> {
    let mut filtered = Vec::with_capacity(scores.len());

    for scored in scores.iter().copied() {
        let Some(meta) = read_entity_metadata(store, rtxn, &scored.id)? else {
            continue;
        };

        if let Some(types) = type_filter {
            if !types.contains(&meta.entity_type) {
                continue;
            }
        }

        if let Some(timestamp) = since_filter {
            if meta.learned_at < timestamp {
                continue;
            }
        }

        if let Some((start, end)) = occurred_range {
            if !intervals_overlap(meta.occurred_start, meta.occurred_end, start, end) {
                continue;
            }
        }

        if let Some((start, end)) = learned_range {
            if meta.learned_at < start || meta.learned_at > end {
                continue;
            }
        }

        filtered.push(scored);
    }

    *scores = filtered;
    Ok(())
}

fn read_entity_metadata(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityMetadata>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    if raw.len() < ENTITY_METADATA_HEADER_LEN {
        return Ok(None);
    }

    let entity_type = raw[0];
    let occurred_start = u64::from_be_bytes(raw[1..9].try_into().map_err(|_| Error::InvalidKey)?);
    let occurred_end = u64::from_be_bytes(raw[9..17].try_into().map_err(|_| Error::InvalidKey)?);
    let learned_at = u64::from_be_bytes(raw[17..25].try_into().map_err(|_| Error::InvalidKey)?);

    let (occurred_start, occurred_end) = normalize_range(occurred_start, occurred_end);

    Ok(Some(EntityMetadata {
        entity_type,
        occurred_start,
        occurred_end,
        learned_at,
    }))
}

fn normalize_range(start: u64, end: u64) -> (u64, u64) {
    if start <= end {
        (start, end)
    } else {
        (end, start)
    }
}

fn midpoint(start: u64, end: u64) -> u64 {
    let (start, end) = normalize_range(start, end);
    start / 2 + end / 2 + (start % 2 + end % 2) / 2
}

fn effective_range_width(start: u64, end: u64) -> u64 {
    let width = end.saturating_sub(start);
    if width == 0 {
        DEFAULT_SIGMA_SECS
    } else {
        width
    }
}

fn compute_radius(range_width: u64, sigma_secs: u64) -> u64 {
    let sigma = resolve_sigma_secs(sigma_secs);
    range_width
        .saturating_mul(2)
        .max(sigma.saturating_mul(3))
        .max(MIN_WINDOW_RADIUS_SECS)
}

fn interval_distance(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> u64 {
    let (a_start, a_end) = normalize_range(a_start, a_end);
    let (b_start, b_end) = normalize_range(b_start, b_end);

    if a_start.max(b_start) <= a_end.min(b_end) {
        0
    } else if a_end < b_start {
        b_start.saturating_sub(a_end)
    } else {
        a_start.saturating_sub(b_end)
    }
}

fn point_interval_distance(point: u64, start: u64, end: u64) -> u64 {
    let (start, end) = normalize_range(start, end);

    if point < start {
        start.saturating_sub(point)
    } else if point > end {
        point.saturating_sub(end)
    } else {
        0
    }
}

fn intervals_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    let (a_start, a_end) = normalize_range(a_start, a_end);
    let (b_start, b_end) = normalize_range(b_start, b_end);
    a_start.max(b_start) <= a_end.min(b_end)
}

fn sigmoid(distance_secs: u64, sigma_secs: u64, floor: f64) -> f64 {
    let sigma = resolve_sigma_secs(sigma_secs) as f64;
    let steepness = sigma / 4.0;
    let distance = distance_secs as f64;
    (1.0 - floor) / (1.0 + ((distance - sigma) / steepness).exp()) + floor
}

fn resolve_sigma_secs(sigma_secs: u64) -> u64 {
    if sigma_secs == 0 {
        DEFAULT_SIGMA_SECS
    } else {
        sigma_secs
    }
}

fn learned_anchor_range(config: &TemporalSearchConfig) -> Result<(u64, u64)> {
    match config.anchor_mode {
        TemporalAnchorMode::Both => {
            let start = config.learned_start.ok_or_else(|| {
                Error::InvalidConfig("missing learned_start for Both mode".to_owned())
            })?;
            let end = config.learned_end.ok_or_else(|| {
                Error::InvalidConfig("missing learned_end for Both mode".to_owned())
            })?;
            Ok((start, end))
        }
        _ => Ok((config.anchor_start, config.anchor_end)),
    }
}

fn remove_floor(score: f64, floor: f64) -> f64 {
    ((score - floor) / (1.0 - floor)).clamp(0.0, 1.0)
}

fn apply_floor(score: f64, floor: f64) -> f64 {
    score * (1.0 - floor) + floor
}

fn combine_proximity(mode: TemporalAnchorMode, occurred: f64, learned: f64, floor: f64) -> f64 {
    match mode {
        TemporalAnchorMode::Occurred => occurred,
        TemporalAnchorMode::Learned => learned,
        TemporalAnchorMode::Both => {
            let occurred_net = remove_floor(occurred, floor);
            let learned_net = remove_floor(learned, floor);
            apply_floor(occurred_net * learned_net, floor)
        }
        TemporalAnchorMode::Auto => {
            let occurred_net = remove_floor(occurred, floor);
            let learned_net = remove_floor(learned, floor);
            apply_floor(1.0 - (1.0 - occurred_net) * (1.0 - learned_net), floor)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::types::{HnswConfig, VaultConfig};

    use super::*;

    fn test_config() -> VaultConfig {
        VaultConfig {
            map_size: 16 * 1024 * 1024,
            dimensions: 4,
            embedding_model: None,
            max_readers: 16,
            hnsw: HnswConfig {
                m_max_0: 64,
                ef_construction: 200,
                ef_search: 128,
            },
        }
    }

    fn entity_id(byte: u8) -> EntityId {
        EntityId::from_bytes([byte; 16])
    }

    fn put_entity(
        vault: &Vault,
        id: EntityId,
        entity_type: u8,
        start: u64,
        end: u64,
        learned: u64,
    ) -> Result<()> {
        vault.put_entity(
            &id,
            entity_type,
            TimeRange { start, end },
            learned,
            b"payload",
        )
    }

    fn put_text(vault: &Vault, id: EntityId, text: &str) -> Result<()> {
        vault
            .batch()
            .put(&id, 0, TimeRange { start: 1, end: 1 }, 1, b"payload")
            .text(&id, &[("body", text)])
            .commit()
    }

    fn put_vector(vault: &Vault, id: EntityId, vector: [f32; 4]) -> Result<()> {
        vault
            .batch()
            .put(&id, 0, TimeRange { start: 1, end: 1 }, 1, b"payload")
            .vector(&id, &vector)
            .commit()
    }

    fn to_score_map(scores: &[ScoredEntity]) -> HashMap<EntityId, f32> {
        scores.iter().map(|entry| (entry.id, entry.score)).collect()
    }

    fn approx_eq(left: f32, right: f32, eps: f32) -> bool {
        (left - right).abs() <= eps
    }

    #[test]
    fn text_only_query() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity_id(3);
        let b = entity_id(4);

        put_text(&vault, a, "alpha world")?;
        put_text(&vault, b, "beta world")?;

        let results = vault.query().search_text("alpha", 10).run()?;
        assert!(!results.is_empty());
        assert_eq!(results[0].id, a);
        Ok(())
    }

    #[test]
    fn vector_only_query() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;
        let a = entity_id(10);
        let b = entity_id(11);

        put_vector(&vault, a, [1.0, 0.0, 0.0, 0.0])?;
        put_vector(&vault, b, [0.0, 1.0, 0.0, 0.0])?;

        let results = vault
            .query()
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .run()?;
        assert!(!results.is_empty());
        assert_eq!(results[0].id, a);
        Ok(())
    }

    #[test]
    fn expand_ppr_uses_rrf_results_as_seeds() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let a = entity_id(20);
        let b = entity_id(21);

        vault
            .batch()
            .put(&a, 0, TimeRange { start: 10, end: 10 }, 10, b"payload")
            .text(&a, &[("body", "alpha")])
            .put(&b, 0, TimeRange { start: 11, end: 11 }, 11, b"payload")
            .edge(&a, crate::types::EdgeKind::Supports, &b, 1.0)
            .commit()?;

        let baseline = vault.query().search_text("alpha", 10).run()?;
        assert!(!baseline.iter().any(|entry| entry.id == b));

        let expanded = vault
            .query()
            .search_text("alpha", 10)
            .expand_ppr(&[], 3)
            .run()?;
        assert!(expanded.iter().any(|entry| entry.id == b));
        Ok(())
    }

    #[test]
    fn search_ppr_as_pre_rrf_signal() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let a = entity_id(22);
        let b = entity_id(23);

        vault
            .batch()
            .put(&a, 0, TimeRange { start: 10, end: 10 }, 10, b"payload")
            .put(&b, 0, TimeRange { start: 11, end: 11 }, 11, b"payload")
            .edge(&a, crate::types::EdgeKind::Supports, &b, 1.0)
            .commit()?;

        let results = vault.query().search_ppr(&[a], 3).run()?;
        assert!(results.iter().any(|entry| entry.id == b));
        Ok(())
    }

    #[test]
    fn recency_boost_auto_skips_when_temporal_search_present() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let anchor = 2_000_000;
        let a = entity_id(30);
        let b = entity_id(31);

        put_entity(&vault, a, 0, anchor, anchor, anchor)?;
        put_entity(&vault, b, 0, anchor + 3_600, anchor + 3_600, anchor + 3_600)?;

        let without_boost = vault
            .query()
            .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Auto, 10)
            .run()?;
        let with_boost = vault
            .query()
            .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Auto, 10)
            .boost_recency(7.0)
            .run()?;

        assert_eq!(without_boost.len(), with_boost.len());
        for (left, right) in without_boost.iter().zip(with_boost.iter()) {
            assert_eq!(left.id, right.id);
            assert!(approx_eq(left.score, right.score, 1e-6));
        }

        Ok(())
    }

    #[test]
    fn three_index_scan_discovers_end_only_candidate() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let anchor = 2_000_000;
        let candidate = entity_id(40);

        put_entity(&vault, candidate, 0, 1_000_000, 1_500_000, 10_000_000)?;

        let results = vault
            .query()
            .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 10)
            .run()?;

        assert!(results.iter().any(|entry| entry.id == candidate));
        Ok(())
    }

    #[test]
    fn future_events_are_scored() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let now = crate::unix_seconds_now();
        let start = now + 7 * 86_400;
        let end = now + 8 * 86_400;
        let id = entity_id(50);

        put_entity(&vault, id, 0, start + 3_600, start + 3_600, now)?;

        let config = TemporalSearchConfig {
            anchor_start: start,
            anchor_end: end,
            learned_start: None,
            learned_end: None,
            sigma_secs: TemporalGranularity::Week.sigma_secs(),
            anchor_mode: TemporalAnchorMode::Auto,
            adaptive: true,
            limit: 10,
        };
        let rtxn = vault.store.env.read_txn()?;
        let results = execute_temporal(&vault.store, &rtxn, &config)?;

        let scored = results
            .iter()
            .find(|entry| entry.id == id)
            .expect("missing future entity");
        assert!(scored.score > 0.5_f32);
        Ok(())
    }

    #[test]
    fn temporal_tier_equivalence() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let a = entity_id(60);
        let b = entity_id(61);
        let start = 1_000_000;
        let end = 1_200_000;
        let sigma = end - start;

        put_entity(&vault, a, 0, start + 10_000, start + 10_000, start + 10_000)?;
        put_entity(&vault, b, 0, end + 500_000, end + 500_000, end + 500_000)?;

        let tier1 = vault.query().search_temporal(start, end, 10).run()?;
        let tier2 = vault
            .query()
            .search_temporal_with_sigma(start, end, sigma.max(86_400), TemporalAnchorMode::Auto, 10)
            .run()?;

        assert_eq!(tier1.len(), tier2.len());
        for (left, right) in tier1.iter().zip(tier2.iter()) {
            assert_eq!(left.id, right.id);
            assert!(approx_eq(left.score, right.score, 1e-6));
        }

        Ok(())
    }

    #[test]
    fn per_scan_cap_isolation_keeps_learned_candidates() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let anchor = 2_000_000;
        for i in 0..40_u8 {
            let id = entity_id(80 + i);
            put_entity(
                &vault,
                id,
                0,
                anchor + u64::from(i),
                anchor + u64::from(i),
                9_000_000,
            )?;
        }

        let learned_only = entity_id(70);
        put_entity(
            &vault,
            learned_only,
            0,
            anchor + 10_000_000,
            anchor + 10_000_000,
            anchor,
        )?;

        let results = vault
            .query()
            .search_temporal_with_sigma(anchor, anchor, 3_600, TemporalAnchorMode::Auto, 5)
            .run()?;

        assert!(results.iter().any(|entry| entry.id == learned_only));
        Ok(())
    }

    #[test]
    fn sigma_not_clamped_and_granularity_tiers_differ() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let anchor = 1_000_000;
        let id = entity_id(90);
        put_entity(
            &vault,
            id,
            0,
            anchor + 20_000,
            anchor + 20_000,
            anchor + 20_000,
        )?;

        let base_config = TemporalSearchConfig {
            anchor_start: anchor,
            anchor_end: anchor,
            learned_start: None,
            learned_end: None,
            sigma_secs: 0,
            anchor_mode: TemporalAnchorMode::Occurred,
            adaptive: true,
            limit: 10,
        };
        let exact_config = TemporalSearchConfig {
            sigma_secs: TemporalGranularity::Exact.sigma_secs(),
            ..base_config.clone()
        };
        let hour_config = TemporalSearchConfig {
            sigma_secs: TemporalGranularity::Hour.sigma_secs(),
            ..base_config.clone()
        };
        let day_config = TemporalSearchConfig {
            sigma_secs: TemporalGranularity::Day.sigma_secs(),
            ..base_config
        };

        let rtxn = vault.store.env.read_txn()?;
        let exact = execute_temporal(&vault.store, &rtxn, &exact_config)?[0].score;
        let hour = execute_temporal(&vault.store, &rtxn, &hour_config)?[0].score;
        let day = execute_temporal(&vault.store, &rtxn, &day_config)?[0].score;

        assert!(exact < hour);
        assert!(hour < day);

        Ok(())
    }

    #[test]
    fn sigma_driven_discovery_for_year_granularity() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let anchor = 1_000_000;
        let far = entity_id(100);
        let hundred_days = 100 * 86_400;

        put_entity(
            &vault,
            far,
            0,
            anchor + hundred_days,
            anchor + hundred_days,
            anchor + hundred_days,
        )?;

        let day_results = vault
            .query()
            .search_temporal_with_granularity(
                anchor,
                anchor,
                TemporalGranularity::Day,
                TemporalAnchorMode::Occurred,
                10,
            )
            .run()?;
        assert!(!day_results.iter().any(|entry| entry.id == far));

        let year_results = vault
            .query()
            .search_temporal_with_granularity(
                anchor,
                anchor,
                TemporalGranularity::Year,
                TemporalAnchorMode::Occurred,
                10,
            )
            .run()?;
        assert!(year_results.iter().any(|entry| entry.id == far));

        Ok(())
    }

    #[test]
    fn bidirectional_priority_favors_nearest_candidates() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let anchor = 2_000_000;
        let near = entity_id(110);
        let far_a = entity_id(111);
        let far_b = entity_id(112);

        put_entity(
            &vault,
            near,
            0,
            anchor + 1_000,
            anchor + 1_000,
            anchor + 1_000,
        )?;
        put_entity(
            &vault,
            far_a,
            0,
            anchor - 500_000,
            anchor - 500_000,
            anchor - 500_000,
        )?;
        put_entity(
            &vault,
            far_b,
            0,
            anchor + 500_000,
            anchor + 500_000,
            anchor + 500_000,
        )?;

        let results = vault
            .query()
            .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
            .run()?;

        assert_eq!(results[0].id, near);
        Ok(())
    }

    #[test]
    fn adaptive_widening_and_disable() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let anchor = 5_000_000;
        let target = entity_id(120);

        put_entity(
            &vault,
            target,
            0,
            anchor + 30 * 86_400,
            anchor + 30 * 86_400,
            anchor + 30 * 86_400,
        )?;

        let widened = vault
            .query()
            .search_temporal_with_granularity(
                anchor,
                anchor,
                TemporalGranularity::Week,
                TemporalAnchorMode::Occurred,
                10,
            )
            .run()?;
        assert!(widened.iter().any(|entry| entry.id == target));

        let exact = vault
            .query()
            .search_temporal_with_granularity(
                anchor,
                anchor,
                TemporalGranularity::Week,
                TemporalAnchorMode::Occurred,
                10,
            )
            .temporal_adaptive(false)
            .run()?;
        assert!(!exact.iter().any(|entry| entry.id == target));

        Ok(())
    }

    #[test]
    fn contiguity_boost_behavior() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let anchor = 3_000_000;
        let cluster_a = entity_id(130);
        let cluster_b = entity_id(131);
        let isolated = entity_id(132);

        put_entity(&vault, cluster_a, 0, anchor, anchor, anchor)?;
        put_entity(
            &vault,
            cluster_b,
            0,
            anchor + 3_600,
            anchor + 3_600,
            anchor + 3_600,
        )?;
        put_entity(
            &vault,
            isolated,
            0,
            anchor + 40 * 86_400,
            anchor + 40 * 86_400,
            anchor + 40 * 86_400,
        )?;

        let base = vault
            .query()
            .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 10)
            .run()?;
        let boosted = vault
            .query()
            .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 10)
            .boost_contiguity()
            .run()?;

        let base_map = to_score_map(&base);
        let boosted_map = to_score_map(&boosted);

        assert!(boosted_map[&cluster_a] > base_map[&cluster_a]);
        assert!(boosted_map[&cluster_b] > base_map[&cluster_b]);

        let single_base = vault
            .query()
            .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
            .run()?;
        let single_boost = vault
            .query()
            .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
            .boost_contiguity()
            .run()?;
        assert!(approx_eq(single_base[0].score, single_boost[0].score, 1e-6));

        let text_id = entity_id(133);
        put_text(&vault, text_id, "alpha")?;
        let text_base = vault.query().search_text("alpha", 10).run()?;
        let text_boosted = vault
            .query()
            .search_text("alpha", 10)
            .boost_contiguity()
            .run()?;
        assert!(approx_eq(text_base[0].score, text_boosted[0].score, 1e-6));

        Ok(())
    }

    #[test]
    fn overlap_tiebreak_prefers_closer_midpoint() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let anchor_start = 100;
        let anchor_end = 200;
        let closer = entity_id(140);
        let farther = entity_id(141);

        put_entity(&vault, closer, 0, 120, 130, 150)?;
        put_entity(&vault, farther, 0, 180, 190, 150)?;

        let results = vault
            .query()
            .search_temporal_with_sigma(
                anchor_start,
                anchor_end,
                86_400,
                TemporalAnchorMode::Occurred,
                10,
            )
            .run()?;

        assert_eq!(results[0].id, closer);
        Ok(())
    }

    #[test]
    fn filters_work() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let keep = entity_id(150);
        let drop = entity_id(151);

        put_entity(&vault, keep, 1, 100, 110, 200)?;
        put_entity(&vault, drop, 0, 300, 310, 150)?;

        let results = vault
            .query()
            .search_temporal_with_sigma(105, 105, 86_400, TemporalAnchorMode::Auto, 10)
            .filter_types(&[1])
            .filter_since(190)
            .filter_occurred_range(100, 120)
            .filter_learned_range(190, 210)
            .run()?;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, keep);
        Ok(())
    }

    #[test]
    fn granularity_day_vs_year_distributions_differ() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let anchor = 1_000_000;
        let near = entity_id(160);
        let far = entity_id(161);

        put_entity(
            &vault,
            near,
            0,
            anchor + 3_600,
            anchor + 3_600,
            anchor + 3_600,
        )?;
        put_entity(
            &vault,
            far,
            0,
            anchor + 5 * 86_400,
            anchor + 5 * 86_400,
            anchor + 5 * 86_400,
        )?;

        let base_config = TemporalSearchConfig {
            anchor_start: anchor,
            anchor_end: anchor,
            learned_start: None,
            learned_end: None,
            sigma_secs: 0,
            anchor_mode: TemporalAnchorMode::Occurred,
            adaptive: true,
            limit: 10,
        };
        let day_config = TemporalSearchConfig {
            sigma_secs: TemporalGranularity::Day.sigma_secs(),
            ..base_config.clone()
        };
        let year_config = TemporalSearchConfig {
            sigma_secs: TemporalGranularity::Year.sigma_secs(),
            ..base_config
        };

        let rtxn = vault.store.env.read_txn()?;
        let day = execute_temporal(&vault.store, &rtxn, &day_config)?;
        let year = execute_temporal(&vault.store, &rtxn, &year_config)?;

        let day_far = day
            .iter()
            .find(|entry| entry.id == far)
            .expect("missing far day")
            .score;
        let year_far = year
            .iter()
            .find(|entry| entry.id == far)
            .expect("missing far year")
            .score;

        assert!(year_far > day_far);
        Ok(())
    }

    #[test]
    fn inverted_ranges_are_swapped_on_put() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let vault = Vault::open(temp_dir.path(), test_config())?;

        let id = entity_id(170);
        vault.put_entity(
            &id,
            0,
            TimeRange {
                start: 300,
                end: 100,
            },
            400,
            b"payload",
        )?;

        let rtxn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .entities
            .get(&rtxn, id.as_bytes())?
            .ok_or(Error::EntityNotFound)?;

        let start = u64::from_be_bytes(raw[1..9].try_into().map_err(|_| Error::InvalidKey)?);
        let end = u64::from_be_bytes(raw[9..17].try_into().map_err(|_| Error::InvalidKey)?);
        assert_eq!(start, 100);
        assert_eq!(end, 300);

        Ok(())
    }
}
