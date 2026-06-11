use std::collections::{HashMap, HashSet};

use heed::types::Bytes;
use heed::{Database, RoTxn};

use crate::Vault;
use crate::batch::{
    ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, LONG_INTERVAL_THRESHOLD_SECS,
};
use crate::claim::{ClaimBody, claim_surfaceable};
use crate::error::{Error, Result};
use crate::fusion;
use crate::store::Store;
use crate::types::{
    ENTITY_ID_LEN, ENTITY_TYPE_CLAIM, EntityId, ScoredEntity, TemporalAnchorMode,
    TemporalGranularity, TimeRange,
};

const DEFAULT_RESULT_LIMIT: usize = 20;
const DEFAULT_SIGMA_SECS: u64 = 86_400;
const MIN_WINDOW_RADIUS_SECS: u64 = 7 * 86_400;
const TEMPORAL_KEY_LEN: usize = 24;
const LONG_INTERVAL_VALUE_LEN: usize = 8;
const TEMPORAL_FLOOR: f64 = 0.05;
const SECONDS_PER_DAY_F64: f64 = 86_400.0;
const RECENCY_DECAY_TAU_SECS: f64 = 28.0 * SECONDS_PER_DAY_F64;
const ALPHA_BASE: f64 = 0.7;
const ALPHA_RANGE: f64 = 0.3;
const ALPHA_TAU_SECS: f64 = 90.0 * SECONDS_PER_DAY_F64;
const PPR_DAMPING: f32 = 0.15;
const ADAPTIVE_ROUNDS: usize = 3;
const PER_SCAN_CAP_FACTOR: usize = 4;
const MAX_TEMPORAL_SEEK_BUFFER: usize = 8_192;
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

#[derive(Debug, Clone, Copy)]
struct TemporalScoringContext {
    sigma: u64,
    now: u64,
    anchor_mid: u64,
    learned_anchor: (u64, u64),
    learned_anchor_mid: u64,
}

#[derive(Debug, Clone, Copy)]
struct TemporalCandidateCollectionContext {
    radius: u64,
    per_scan_cap: usize,
}

#[derive(Debug, Clone, Copy)]
struct TemporalIndexRow {
    timestamp: u64,
    id: EntityId,
}

#[derive(Debug, Clone, Copy, Default)]
struct PhoneticAccumulator {
    score: f32,
    matches: usize,
}

#[derive(Debug, Clone, Copy)]
struct PipelineFilterConfig<'a> {
    type_filter: Option<&'a [u8]>,
    since_filter: Option<u64>,
    occurred_range: Option<(u64, u64)>,
    learned_range: Option<(u64, u64)>,
}

#[derive(Default)]
struct EntityMetadataCache {
    entries: HashMap<EntityId, Option<EntityMetadata>>,
}

/// Per-run memo for the D19 claim status gate.
///
/// `None` = the type-0 record is suppressed (failed the
/// [`claim_surfaceable`] predicate, or its body bytes failed the pinned
/// structural decode — fail-closed exclusion, AC 7). `Some(body)` = the
/// claim passed the gate; the decoded body is retained so the context-pack
/// hydrator can project fields WITHOUT a second MessagePack decode (AC 9).
/// Non-type-0 entities never enter this map (their bodies are opaque, AC 5).
#[derive(Default)]
struct ClaimStatusGateCache {
    decisions: HashMap<EntityId, Option<ClaimBody>>,
}

/// Detailed pipeline output for the context-pack path.
///
/// `claim_bodies` carries every claim body decoded (once) by the D19 gate
/// that PASSED it; `claims_suppressed` counts the unique type-0 records the
/// gate excluded (status-failed or undecodable). Bodies were decoded under
/// the pipeline's read transaction; the context pack hydrates under a fresh
/// transaction, so reusing them keeps projection consistent with the gate
/// decision (the same seam the score/hydration split already has).
pub(crate) struct PipelineOutput {
    pub(crate) scores: Vec<ScoredEntity>,
    pub(crate) claim_bodies: HashMap<EntityId, ClaimBody>,
    pub(crate) claims_suppressed: usize,
}

impl EntityMetadataCache {
    fn get(
        &mut self,
        store: &Store,
        rtxn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<Option<EntityMetadata>> {
        if let Some(cached) = self.entries.get(id) {
            return Ok(*cached);
        }

        let metadata = read_entity_metadata(store, rtxn, id)?;
        self.entries.insert(*id, metadata);
        Ok(metadata)
    }
}

#[must_use = "PipelineBuilder executes no query until a terminal `.run*()` method is called"]
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
        Ok(self.run_for_pack()?.scores)
    }

    /// Executes the pipeline and returns the detailed [`PipelineOutput`]
    /// the context-pack path consumes (gated scores + the claim bodies the
    /// D19 gate already decoded + the suppression count).
    pub(crate) fn run_for_pack(self) -> Result<PipelineOutput> {
        if self.text_search.is_some() {
            self.vault.ensure_text_index_trusted()?;
        }

        let (scores, claim_gate, deferred_ppr_cache_writes) = {
            let mut ranked_lists = Vec::new();
            let rtxn = self.vault.store.env.read_txn()?;
            let mut metadata_cache = EntityMetadataCache::default();
            let mut claim_gate = ClaimStatusGateCache::default();
            let mut deferred_ppr_cache_writes = Vec::new();

            if let Some((query_vector, limit)) = &self.vector_search {
                if query_vector.len() != self.vault.config.dimensions {
                    return Err(Error::DimensionMismatch {
                        expected: self.vault.config.dimensions,
                        got: query_vector.len(),
                    });
                }
                if let Some(error) = Error::invalid_vector_component(query_vector) {
                    return Err(error);
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
                let text_results = crate::bm25::search_text(
                    &self.vault.store,
                    &rtxn,
                    &self.vault.analyzer,
                    &crate::bm25::Bm25Config::default(),
                    query,
                    *limit,
                )?;
                ranked_lists.push(text_results);
            }

            if let Some(codes) = &self.phonetic_search {
                let phonetic_results = execute_phonetic(&self.vault.store, &rtxn, codes)?;
                ranked_lists.push(phonetic_results);
            }

            if let Some(config) = &self.temporal_search {
                let temporal_results =
                    execute_temporal(&self.vault.store, &rtxn, config, &mut metadata_cache)?;
                ranked_lists.push(temporal_results);
            }

            if let Some((seeds, depth)) = &self.ppr_search {
                let (ppr_results, deferred_cache_write) =
                    crate::ppr::ppr_query_in_txn_with_deferred_cache(
                        &self.vault.store,
                        &rtxn,
                        seeds,
                        *depth,
                        PPR_DAMPING,
                    )?;
                if let Some(deferred_cache_write) = deferred_cache_write {
                    deferred_ppr_cache_writes.push(deferred_cache_write);
                }
                ranked_lists.push(ppr_results);
            }

            if ranked_lists.is_empty() {
                return Ok(PipelineOutput {
                    scores: Vec::new(),
                    claim_bodies: HashMap::new(),
                    claims_suppressed: 0,
                });
            }

            let mut scores = fusion::rrf_fuse(&ranked_lists, RRF_K);

            // D19 claim status gate, first application: covers the fused
            // candidates of all five channels (text/vector/phonetic/
            // temporal/PPR) AND runs BEFORE expand_ppr implicit seed
            // selection, so a dead claim never seeds the expansion.
            apply_claim_status_gate(
                &mut scores,
                &self.vault.store,
                &rtxn,
                &mut metadata_cache,
                &mut claim_gate,
            )?;

            if let Some((explicit_seeds, depth)) = &self.ppr_expand {
                let mut seen = HashSet::<EntityId>::new();
                let mut seeds = Vec::<EntityId>::new();
                for seed in explicit_seeds {
                    if seen.insert(*seed) {
                        seeds.push(*seed);
                    }
                }
                if seeds.len() < crate::ppr::MAX_PPR_SEEDS {
                    for scored in scores.iter().take(self.result_limit) {
                        if seen.insert(scored.id) {
                            seeds.push(scored.id);
                            if seeds.len() == crate::ppr::MAX_PPR_SEEDS {
                                break;
                            }
                        }
                    }
                }

                if !seeds.is_empty() {
                    seeds.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

                    let (mut ppr_results, deferred_cache_write) =
                        crate::ppr::ppr_query_in_txn_with_deferred_cache(
                            &self.vault.store,
                            &rtxn,
                            &seeds,
                            *depth,
                            PPR_DAMPING,
                        )?;
                    if let Some(deferred_cache_write) = deferred_cache_write {
                        deferred_ppr_cache_writes.push(deferred_cache_write);
                    }
                    // D19 claim status gate, second application: PPR
                    // expansion walks the graph and can pull dead claims
                    // back into the candidate set — gate the expansion
                    // list before fusing it (memoized; claims already
                    // checked above cost nothing). Traversal THROUGH a
                    // dead claim node stays untouched in v1: only the
                    // result surface is gated.
                    apply_claim_status_gate(
                        &mut ppr_results,
                        &self.vault.store,
                        &rtxn,
                        &mut metadata_cache,
                        &mut claim_gate,
                    )?;
                    scores = fusion::rrf_fuse(&[scores, ppr_results], RRF_K);
                }
            }

            if let (None, Some(half_life_days)) =
                (self.temporal_search.as_ref(), self.recency_half_life)
            {
                boost_recency_with_cache(
                    &mut scores,
                    half_life_days,
                    &self.vault.store,
                    &rtxn,
                    &mut metadata_cache,
                )?;
            }

            if self.apply_salience {
                fusion::boost_salience(&mut scores, &self.vault.store, &rtxn)?;
            }

            if self.apply_confidence {
                fusion::boost_confidence(&mut scores, &self.vault.store, &rtxn)?;
            }

            let filter_config = PipelineFilterConfig {
                type_filter: self.type_filter.as_deref(),
                since_filter: self.since_filter,
                occurred_range: self.occurred_range,
                learned_range: self.learned_range,
            };
            apply_filters(
                &mut scores,
                &self.vault.store,
                &rtxn,
                filter_config,
                &mut metadata_cache,
            )?;

            if self.apply_contiguity {
                boost_contiguity(
                    &mut scores,
                    self.temporal_search.as_ref(),
                    &self.vault.store,
                    &rtxn,
                    &mut metadata_cache,
                )?;
            }

            fusion::sort_scored_entities_desc(&mut scores);
            scores.truncate(self.result_limit);
            (scores, claim_gate, deferred_ppr_cache_writes)
        };

        crate::ppr::flush_deferred_ppr_cache_writes(&self.vault.store, &deferred_ppr_cache_writes)?;

        let mut claim_bodies = HashMap::new();
        let mut claims_suppressed = 0_usize;
        for (id, decision) in claim_gate.decisions {
            match decision {
                Some(body) => {
                    claim_bodies.insert(id, body);
                }
                None => claims_suppressed += 1,
            }
        }

        Ok(PipelineOutput {
            scores,
            claim_bodies,
            claims_suppressed,
        })
    }
}

/// D19 read-path status gate (its own pipeline stage; ARCH-0003 retrieval
/// rule, ARCH-0004 §H items 1/2/4).
///
/// Removes from `scores` every type-0 (CLAIM) record that fails
/// [`claim_surfaceable`] — and, fail-closed, every type-0 record whose body
/// is missing or does not decode as the pinned CLAIM ABI (a raw-written
/// non-map body, missing `appr`/`life`, …) — so excluded claims never
/// consume `result_limit` slots (the gate runs before sort/truncate).
/// Exclusion is silent: no error, the claim is dropped and memoized as
/// suppressed in `gate` (surfaced to callers as
/// `PackStats::claims_suppressed`). Entities of every OTHER type byte pass
/// through untouched — their bodies are opaque at the storage layer. The
/// body is decoded at most ONCE per entity per run; passing bodies are kept
/// in `gate` for context-pack field projection.
fn apply_claim_status_gate(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
    gate: &mut ClaimStatusGateCache,
) -> Result<()> {
    let mut kept = Vec::with_capacity(scores.len());

    for scored in scores.iter().copied() {
        // Entities without a parseable envelope are not a claim-status
        // decision; `apply_filters` drops them downstream exactly as before.
        let Some(meta) = metadata_cache.get(store, rtxn, &scored.id)? else {
            kept.push(scored);
            continue;
        };
        if meta.entity_type != ENTITY_TYPE_CLAIM {
            kept.push(scored);
            continue;
        }

        if let Some(decision) = gate.decisions.get(&scored.id) {
            if decision.is_some() {
                kept.push(scored);
            }
            continue;
        }

        // Read path allows reserved `edge.*` predicates so stored
        // provenance Claims gate on their own appr/life/stale like any
        // other claim instead of failing the decode.
        let decision = store
            .entities
            .get(rtxn, scored.id.as_bytes())?
            .and_then(|raw| raw.get(ENTITY_METADATA_HEADER_LEN..))
            .and_then(|body| crate::claim::decode_claim_body(body, true).ok())
            .filter(claim_surfaceable);
        if decision.is_some() {
            kept.push(scored);
        }
        gate.decisions.insert(scored.id, decision);
    }

    *scores = kept;
    Ok(())
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

        if !posting.len().is_multiple_of(ENTITY_ID_LEN) {
            return Err(Error::CorruptedIndex("phonetic posting"));
        }

        for chunk in posting.chunks_exact(ENTITY_ID_LEN) {
            let id = EntityId::from_bytes(
                chunk
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("phonetic posting"))?,
            )
            .map_err(|_| Error::CorruptedIndex("phonetic posting"))?;
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

    fusion::sort_scored_entities_desc(&mut out);
    Ok(out)
}

fn execute_temporal(
    store: &Store,
    rtxn: &RoTxn<'_>,
    config: &TemporalSearchConfig,
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
    let now = crate::unix_seconds_now();
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

fn collect_temporal_candidates(
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
        let long_interval_lower = temporal_key_bound(occurred_window_end, 0xFF);
        // Keep the top `per_scan_cap` spanners by the same exact temporal score
        // used later in `execute_temporal()`. Since `per_scan_cap` is 4x the
        // final result limit, anything outside this top-k cannot enter the
        // final top-k after exact scoring.
        let mut spanners = Vec::<TemporalCandidateScore>::new();
        let trim_threshold = per_scan_cap
            .saturating_mul(2)
            .min(std::cmp::max(MAX_TEMPORAL_SEEK_BUFFER, per_scan_cap));
        for entry in store.temporal_long_intervals.range(
            rtxn,
            &(
                std::ops::Bound::Excluded(&long_interval_lower[..]),
                std::ops::Bound::Unbounded,
            ),
        )? {
            let (key, value) = entry?;
            let (id, occurred_start, _) = decode_long_interval_row(key, value)?;
            if occurred_start >= occurred_window_start {
                continue;
            }

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
    if cap == 0 || window_start > window_end {
        return Ok(());
    }

    let window_start_key = temporal_key_bound(window_start, 0x00);
    let window_end_key = temporal_key_bound(window_end, 0xFF);
    let anchor_key = temporal_key_bound(anchor_mid, 0x00);

    let mut rows =
        Vec::<TemporalIndexRow>::with_capacity(cap.saturating_mul(2).min(MAX_TEMPORAL_SEEK_BUFFER));

    let mut forward = db.range(
        rtxn,
        &(
            std::ops::Bound::Included(&anchor_key[..]),
            std::ops::Bound::Included(&window_end_key[..]),
        ),
    )?;
    for _ in 0..cap {
        let Some(row) = next_temporal_index_row(&mut forward)? else {
            break;
        };
        rows.push(row);
    }

    let mut backward = db.rev_range(
        rtxn,
        &(
            std::ops::Bound::Included(&window_start_key[..]),
            std::ops::Bound::Excluded(&anchor_key[..]),
        ),
    )?;
    let mut backward_rows = collect_temporal_index_rows(&mut backward, cap)?;
    normalize_backward_boundary_bucket(db, rtxn, &mut backward_rows)?;
    rows.extend(backward_rows);

    rows.sort_unstable_by(|a, b| compare_temporal_index_rows(a, b, anchor_mid));
    for row in rows.into_iter().take(cap) {
        out.insert(row.id);
    }

    Ok(())
}

fn next_temporal_index_row<'a, I>(iter: &mut I) -> Result<Option<TemporalIndexRow>>
where
    I: Iterator<Item = std::result::Result<(&'a [u8], &'a [u8]), heed::Error>>,
{
    let Some(entry) = iter.next() else {
        return Ok(None);
    };
    let (key, _) = entry?;
    decode_temporal_index_row(key).map(Some)
}

fn decode_temporal_index_row(key: &[u8]) -> Result<TemporalIndexRow> {
    if key.len() != TEMPORAL_KEY_LEN {
        return Err(Error::CorruptedIndex("temporal index"));
    }

    let timestamp = u64::from_be_bytes(
        key[..8]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("temporal index"))?,
    );
    let id = EntityId::from_bytes(
        key[8..TEMPORAL_KEY_LEN]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("temporal index"))?,
    )
    .map_err(|_| Error::CorruptedIndex("temporal index"))?;
    Ok(TemporalIndexRow { timestamp, id })
}

fn collect_temporal_index_rows<'a, I>(iter: &mut I, cap: usize) -> Result<Vec<TemporalIndexRow>>
where
    I: Iterator<Item = std::result::Result<(&'a [u8], &'a [u8]), heed::Error>>,
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
    db: &Database<Bytes, Bytes>,
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

    rows.truncate(rows.len().saturating_sub(boundary_count));

    let boundary_start_key = temporal_key_bound(boundary_timestamp, 0x00);
    let boundary_end_key = temporal_key_bound(boundary_timestamp, 0xFF);
    let mut boundary_rows = Vec::with_capacity(boundary_count);
    let mut boundary_iter = db.range(
        rtxn,
        &(
            std::ops::Bound::Included(&boundary_start_key[..]),
            std::ops::Bound::Included(&boundary_end_key[..]),
        ),
    )?;
    for _ in 0..boundary_count {
        let Some(row) = next_temporal_index_row(&mut boundary_iter)? else {
            break;
        };
        boundary_rows.push(row);
    }
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

fn temporal_key_bound(ts: u64, fill: u8) -> [u8; TEMPORAL_KEY_LEN] {
    let mut key = [fill; TEMPORAL_KEY_LEN];
    key[..8].copy_from_slice(&ts.to_be_bytes());
    key
}

fn decode_long_interval_row(key: &[u8], value: &[u8]) -> Result<(EntityId, u64, u64)> {
    if key.len() != TEMPORAL_KEY_LEN || value.len() != LONG_INTERVAL_VALUE_LEN {
        return Err(Error::CorruptedIndex("temporal long interval"));
    }

    let occurred_end = u64::from_be_bytes(
        key[..8]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("temporal long interval"))?,
    );
    let id = EntityId::from_bytes(
        key[8..TEMPORAL_KEY_LEN]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("temporal long interval"))?,
    )
    .map_err(|_| Error::CorruptedIndex("temporal long interval"))?;
    let occurred_start = u64::from_be_bytes(
        value
            .try_into()
            .map_err(|_| Error::CorruptedIndex("temporal long interval"))?,
    );
    Ok((id, occurred_start, occurred_end))
}

fn boost_contiguity(
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

fn apply_filters(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    filters: PipelineFilterConfig<'_>,
    metadata_cache: &mut EntityMetadataCache,
) -> Result<()> {
    let mut filtered = Vec::with_capacity(scores.len());

    for scored in scores.iter().copied() {
        let Some(meta) = metadata_cache.get(store, rtxn, &scored.id)? else {
            continue;
        };

        if let Some(types) = filters.type_filter
            && !types.contains(&meta.entity_type)
        {
            continue;
        }

        if let Some(timestamp) = filters.since_filter
            && meta.learned_at < timestamp
        {
            continue;
        }

        if let Some((start, end)) = filters.occurred_range
            && !intervals_overlap(meta.occurred_start, meta.occurred_end, start, end)
        {
            continue;
        }

        if let Some((start, end)) = filters.learned_range
            && (meta.learned_at < start || meta.learned_at > end)
        {
            continue;
        }

        filtered.push(scored);
    }

    *scores = filtered;
    Ok(())
}

fn boost_recency_with_cache(
    scores: &mut [ScoredEntity],
    half_life_days: f32,
    store: &Store,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
) -> Result<()> {
    if !half_life_days.is_finite() || half_life_days <= 0.0 {
        return Ok(());
    }

    let seconds_per_half_life = f64::from(half_life_days) * SECONDS_PER_DAY_F64;
    if seconds_per_half_life <= 0.0 {
        return Ok(());
    }

    let decay = std::f64::consts::LN_2 / seconds_per_half_life;
    let now = crate::unix_seconds_now();

    for scored in scores {
        let Some(meta) = metadata_cache.get(store, rtxn, &scored.id)? else {
            continue;
        };

        let age_secs = now.saturating_sub(meta.learned_at) as f64;
        let recency = (-decay * age_secs).exp();
        scored.score *= (1.0 + 0.5 * recency) as f32;
    }

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
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Ok(None);
    };

    let (occurred_start, occurred_end) =
        normalize_range(header.occurred_start, header.occurred_end);

    Ok(Some(EntityMetadata {
        entity_type: header.entity_type,
        occurred_start,
        occurred_end,
        learned_at: header.learned_at,
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

fn combine_proximity(mode: TemporalAnchorMode, occurred: f64, learned: f64, floor: f64) -> f64 {
    match mode {
        TemporalAnchorMode::Occurred => occurred,
        TemporalAnchorMode::Learned => learned,
        TemporalAnchorMode::Both => {
            // Strip the per-axis floor before combining, then re-add it once.
            let span = 1.0 - floor;
            let occurred_net = ((occurred - floor) / span).clamp(0.0, 1.0);
            let learned_net = ((learned - floor) / span).clamp(0.0, 1.0);
            occurred_net * learned_net * span + floor
        }
        TemporalAnchorMode::Auto => {
            // Normalized noisy-OR with a shared floor.
            let span = 1.0 - floor;
            let occurred_net = ((occurred - floor) / span).clamp(0.0, 1.0);
            let learned_net = ((learned - floor) / span).clamp(0.0, 1.0);
            (1.0 - (1.0 - occurred_net) * (1.0 - learned_net)) * span + floor
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use heed::types::Bytes;

    use crate::types::{HnswConfig, VaultConfig};

    use super::*;

    fn test_config() -> VaultConfig {
        VaultConfig {
            map_size: 16 * 1024 * 1024,
            dimensions: 4,
            embedding_model: Some("test-model-v1".to_owned()),
            max_readers: 16,
            hnsw: HnswConfig {
                m_max_0: 64,
                ef_construction: 200,
                ef_search: 128,
            },
            text_analyzer: crate::types::TextAnalyzerConfig::default(),
            dict_search_paths: Vec::new(),
            skip_text_index_manifest_check: false,
        }
    }

    fn open_test_vault() -> (tempfile::TempDir, Vault) {
        crate::test_util::open_test_vault_with(test_config())
    }

    fn entity_id(byte: u8) -> EntityId {
        let byte = match byte {
            0x00 | 0xFF => 0x01,
            other => other,
        };
        EntityId::from_bytes([byte; 16]).expect("test ids should be valid")
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
            .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
            .text(&id, &[("body", text)])
            .commit()
    }

    fn put_vector(vault: &Vault, id: EntityId, vector: [f32; 4]) -> Result<()> {
        vault
            .batch()
            .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
            .vector(&id, &vector)
            .commit()
    }

    fn count_entries(db: &heed::Database<Bytes, Bytes>, vault: &Vault) -> Result<usize> {
        let rtxn = vault.store.env.read_txn()?;
        let mut count = 0;
        for entry in db.iter(&rtxn)? {
            entry?;
            count += 1;
        }
        Ok(count)
    }

    fn to_score_map(scores: &[ScoredEntity]) -> HashMap<EntityId, f32> {
        scores.iter().map(|entry| (entry.id, entry.score)).collect()
    }

    fn approx_eq(left: f32, right: f32, eps: f32) -> bool {
        (left - right).abs() <= eps
    }

    #[test]
    fn text_only_query() -> Result<()> {
        let (_dir, vault) = open_test_vault();
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
    fn pipeline_search_fails_closed_on_untrusted_text_index() -> Result<()> {
        let temp_dir = tempfile::tempdir()?;
        let a = entity_id(7);

        {
            let vault = Vault::open(temp_dir.path(), test_config())?;
            put_text(&vault, a, "alpha world")?;
        }

        let mut cfg = test_config();
        cfg.skip_text_index_manifest_check = true;
        let vault = Vault::open(temp_dir.path(), cfg)?;
        let err = vault
            .query()
            .search_text("alpha", 10)
            .run()
            .expect_err("pipeline text search must refuse untrusted index");
        assert!(
            matches!(err, Error::CorruptedIndex(_)),
            "expected CorruptedIndex, got {err:?}",
        );
        Ok(())
    }

    #[test]
    fn vector_only_query() -> Result<()> {
        let (_dir, vault) = open_test_vault();
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
        let (_dir, vault) = open_test_vault();

        let a = entity_id(20);
        let b = entity_id(21);

        vault
            .batch()
            .put(&a, 1, TimeRange { start: 10, end: 10 }, 10, b"payload")
            .text(&a, &[("body", "alpha")])
            .put(&b, 1, TimeRange { start: 11, end: 11 }, 11, b"payload")
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
    fn expand_ppr_clamps_internal_seed_growth() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        for i in 0..=crate::ppr::MAX_PPR_SEEDS {
            let id = EntityId::from_bytes((i as u128 + 1).to_be_bytes())?;
            vault
                .batch()
                .put(
                    &id,
                    1,
                    TimeRange {
                        start: 10 + i as u64,
                        end: 10 + i as u64,
                    },
                    10,
                    b"payload",
                )
                .text(&id, &[("body", "alpha")])
                .commit()?;
        }

        let expanded = vault
            .query()
            .search_text("alpha", crate::ppr::MAX_PPR_SEEDS + 1)
            .expand_ppr(&[], 3)
            .run()?;

        assert!(!expanded.is_empty());
        Ok(())
    }

    #[test]
    fn search_ppr_as_pre_rrf_signal() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let a = entity_id(22);
        let b = entity_id(23);

        vault
            .batch()
            .put(&a, 1, TimeRange { start: 10, end: 10 }, 10, b"payload")
            .put(&b, 1, TimeRange { start: 11, end: 11 }, 11, b"payload")
            .edge(&a, crate::types::EdgeKind::Supports, &b, 1.0)
            .commit()?;

        let results = vault.query().search_ppr(&[a], 3).run()?;
        assert!(results.iter().any(|entry| entry.id == b));
        Ok(())
    }

    #[test]
    fn search_ppr_warms_cache_after_pipeline_snapshot() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let a = entity_id(24);
        let b = entity_id(25);

        vault
            .batch()
            .put(&a, 1, TimeRange { start: 10, end: 10 }, 10, b"payload")
            .put(&b, 1, TimeRange { start: 11, end: 11 }, 11, b"payload")
            .edge(&a, crate::types::EdgeKind::Supports, &b, 1.0)
            .commit()?;

        assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 0);
        assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 0);

        let results = vault.query().search_ppr(&[a], 3).run()?;
        assert!(results.iter().any(|entry| entry.id == b));
        assert_eq!(count_entries(&vault.store.ppr_cache, &vault)?, 1);
        assert_eq!(count_entries(&vault.store.ppr_cache_deps, &vault)?, 1);
        Ok(())
    }

    #[test]
    fn search_ppr_rejects_excessive_seed_count_and_depth() {
        let (_dir, vault) = open_test_vault();
        let seeds = vec![entity_id(1); crate::ppr::MAX_PPR_SEEDS + 1];

        let too_many_seeds = vault.query().search_ppr(&seeds, 3).run();
        assert!(matches!(too_many_seeds, Err(Error::InvalidConfig(_))));

        let too_deep = vault.query().search_ppr(&[entity_id(1)], 11).run();
        assert!(matches!(too_deep, Err(Error::InvalidConfig(_))));
    }

    #[test]
    fn recency_boost_auto_skips_when_temporal_search_present() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let anchor = 2_000_000;
        let a = entity_id(30);
        let b = entity_id(31);

        put_entity(&vault, a, 1, anchor, anchor, anchor)?;
        put_entity(&vault, b, 1, anchor + 3_600, anchor + 3_600, anchor + 3_600)?;

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
        let (_dir, vault) = open_test_vault();

        let anchor = 2_000_000;
        let candidate = entity_id(40);

        put_entity(&vault, candidate, 1, 1_000_000, 1_500_000, 10_000_000)?;

        let results = vault
            .query()
            .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 10)
            .run()?;

        assert!(results.iter().any(|entry| entry.id == candidate));
        Ok(())
    }

    #[test]
    fn long_interval_spanner_is_discovered_via_range_query() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let anchor = 2_000_000_u64;
        let candidate = entity_id(41);
        let span = 30_u64 * 86_400;

        put_entity(
            &vault,
            candidate,
            1,
            anchor.saturating_sub(span),
            anchor.saturating_add(span),
            anchor,
        )?;

        let results = vault
            .query()
            .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 10)
            .run()?;

        assert!(results.iter().any(|entry| entry.id == candidate));
        Ok(())
    }

    #[test]
    fn long_interval_scan_counts_only_spanners_toward_cap() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let anchor = 2_000_000_u64;
        let window = 86_400_u64;
        let long_span = LONG_INTERVAL_THRESHOLD_SECS + window;

        for i in 0..PER_SCAN_CAP_FACTOR {
            let id = entity_id(120 + i as u8);
            put_entity(
                &vault,
                id,
                1,
                anchor + i as u64,
                anchor + long_span + i as u64,
                anchor,
            )?;
        }

        let spanner = entity_id(140);
        put_entity(
            &vault,
            spanner,
            1,
            anchor.saturating_sub(long_span),
            anchor + long_span + PER_SCAN_CAP_FACTOR as u64,
            anchor,
        )?;

        let rtxn = vault.store.env.read_txn()?;
        let config = TemporalSearchConfig {
            anchor_start: anchor,
            anchor_end: anchor,
            learned_start: None,
            learned_end: None,
            sigma_secs: window,
            anchor_mode: TemporalAnchorMode::Occurred,
            adaptive: true,
            limit: 1,
        };
        let mut metadata_cache = EntityMetadataCache::default();
        let scoring = TemporalScoringContext {
            sigma: window,
            now: crate::unix_seconds_now(),
            anchor_mid: anchor,
            learned_anchor: (anchor, anchor),
            learned_anchor_mid: anchor,
        };
        let mut candidates = HashSet::new();
        collect_temporal_candidates(
            &vault.store,
            &rtxn,
            &config,
            TemporalCandidateCollectionContext {
                radius: window,
                per_scan_cap: PER_SCAN_CAP_FACTOR,
            },
            &mut metadata_cache,
            &scoring,
            &mut candidates,
        )?;

        assert!(candidates.contains(&spanner));
        Ok(())
    }

    #[test]
    fn long_interval_scan_keeps_best_spanners_beyond_end_order_cap() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let anchor = crate::unix_seconds_now();
        let span = LONG_INTERVAL_THRESHOLD_SECS + 86_400;
        let best = entity_id(214);

        for i in 0..5_u8 {
            let id = entity_id(210 + i);
            let learned_at = if id == best {
                anchor
            } else {
                anchor.saturating_sub((30 + u64::from(i)) * 86_400)
            };
            put_entity(
                &vault,
                id,
                1,
                anchor.saturating_sub(span + 10),
                anchor.saturating_add(span + u64::from(i)),
                learned_at,
            )?;
        }

        let results = vault
            .query()
            .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 1)
            .run()?;

        assert_eq!(results[0].id, best);
        Ok(())
    }

    #[test]
    fn long_interval_scan_does_not_spend_cap_on_preexisting_ids() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let anchor = crate::unix_seconds_now();
        let span = LONG_INTERVAL_THRESHOLD_SECS + 86_400;
        let best = entity_id(224);
        let mut preexisting = HashSet::new();

        for i in 0..5_u8 {
            let id = entity_id(220 + i);
            let learned_at = if id == best {
                anchor
            } else {
                anchor.saturating_sub((30 + u64::from(i)) * 86_400)
            };
            put_entity(
                &vault,
                id,
                1,
                anchor.saturating_sub(span + 10),
                anchor.saturating_add(span + u64::from(i)),
                learned_at,
            )?;
            if id != best {
                preexisting.insert(id);
            }
        }

        let rtxn = vault.store.env.read_txn()?;
        let config = TemporalSearchConfig {
            anchor_start: anchor,
            anchor_end: anchor,
            learned_start: None,
            learned_end: None,
            sigma_secs: 86_400,
            anchor_mode: TemporalAnchorMode::Occurred,
            adaptive: false,
            limit: 1,
        };
        let scoring = TemporalScoringContext {
            sigma: 86_400,
            now: anchor,
            anchor_mid: anchor,
            learned_anchor: (anchor, anchor),
            learned_anchor_mid: anchor,
        };
        let mut metadata_cache = EntityMetadataCache::default();

        collect_temporal_candidates(
            &vault.store,
            &rtxn,
            &config,
            TemporalCandidateCollectionContext {
                radius: 86_400,
                per_scan_cap: PER_SCAN_CAP_FACTOR,
            },
            &mut metadata_cache,
            &scoring,
            &mut preexisting,
        )?;

        assert!(preexisting.contains(&best));
        Ok(())
    }

    #[test]
    fn backward_seek_preserves_lowest_ids_with_same_timestamp() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let timestamp = 99;

        for byte in [40_u8, 41, 42, 43, 44] {
            let id = entity_id(byte);
            put_entity(&vault, id, 1, timestamp, timestamp, timestamp)?;
        }

        let rtxn = vault.store.env.read_txn()?;
        let mut out = HashSet::new();
        collect_index_candidates(
            &vault.store.temporal_occurred_start,
            &rtxn,
            0,
            timestamp,
            100,
            4,
            &mut out,
        )?;

        assert!(out.contains(&entity_id(40)));
        assert!(out.contains(&entity_id(41)));
        assert!(out.contains(&entity_id(42)));
        assert!(out.contains(&entity_id(43)));
        assert!(!out.contains(&entity_id(44)));
        Ok(())
    }

    #[test]
    fn future_events_are_scored() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let now = crate::unix_seconds_now();
        let start = now + 7 * 86_400;
        let end = now + 8 * 86_400;
        let id = entity_id(50);

        put_entity(&vault, id, 1, start + 3_600, start + 3_600, now)?;

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
        let mut metadata_cache = EntityMetadataCache::default();
        let results = execute_temporal(&vault.store, &rtxn, &config, &mut metadata_cache)?;

        let scored = results
            .iter()
            .find(|entry| entry.id == id)
            .expect("missing future entity");
        assert!(scored.score > 0.5_f32);
        Ok(())
    }

    #[test]
    fn temporal_tier_equivalence() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let a = entity_id(60);
        let b = entity_id(61);
        let start = 1_000_000;
        let end = 1_200_000;
        let sigma = end - start;

        put_entity(&vault, a, 1, start + 10_000, start + 10_000, start + 10_000)?;
        put_entity(&vault, b, 1, end + 500_000, end + 500_000, end + 500_000)?;

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
        let (_dir, vault) = open_test_vault();

        let anchor = 2_000_000;
        for i in 0..40_u8 {
            let id = entity_id(80 + i);
            put_entity(
                &vault,
                id,
                1,
                anchor + u64::from(i),
                anchor + u64::from(i),
                9_000_000,
            )?;
        }

        let learned_only = entity_id(70);
        put_entity(
            &vault,
            learned_only,
            1,
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
    fn granularity_sigma_ordering() -> Result<()> {
        // For a fixed entity-to-anchor distance, increasing sigma should
        // monotonically increase the temporal-similarity score (wider Gaussian =
        // higher density at the same offset). The two original tests both
        // assert this monotonicity; we collapse them into a single ordering
        // table that walks adjacent sigma pairs.
        //
        // (case_name, distance_secs, sigma_a (smaller), sigma_b (larger))
        // Assertion per case: score_a < score_b for an entity placed
        // `distance_secs` past the anchor.
        let cases: &[(&str, u64, u64, u64)] = &[
            // From sigma_not_clamped_and_granularity_tiers_differ: distance = 20_000s
            (
                "20ks_exact_lt_hour",
                20_000,
                TemporalGranularity::Exact.sigma_secs(),
                TemporalGranularity::Hour.sigma_secs(),
            ),
            (
                "20ks_hour_lt_day",
                20_000,
                TemporalGranularity::Hour.sigma_secs(),
                TemporalGranularity::Day.sigma_secs(),
            ),
            // From granularity_day_vs_year_distributions_differ: distance = 5 days
            (
                "5d_day_lt_year",
                5 * 86_400,
                TemporalGranularity::Day.sigma_secs(),
                TemporalGranularity::Year.sigma_secs(),
            ),
        ];

        // Use a distinct entity per case to keep score lookup unambiguous.
        // entity_id(90) was the original ID in the first test; use 90+i so
        // there's no collision with other tests in this module.
        for (i, (name, distance, sigma_a, sigma_b)) in cases.iter().enumerate() {
            let (_dir, vault) = open_test_vault();
            let anchor: u64 = 1_000_000;
            let id = entity_id(90_u8.saturating_add(i as u8));
            let ts = anchor + *distance;
            put_entity(&vault, id, 1, ts, ts, ts)?;

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
            let cfg_a = TemporalSearchConfig {
                sigma_secs: *sigma_a,
                ..base_config
            };
            let cfg_b = TemporalSearchConfig {
                sigma_secs: *sigma_b,
                ..base_config
            };

            let rtxn = vault.store.env.read_txn()?;
            let mut metadata_cache = EntityMetadataCache::default();
            let results_a = execute_temporal(&vault.store, &rtxn, &cfg_a, &mut metadata_cache)?;
            let results_b = execute_temporal(&vault.store, &rtxn, &cfg_b, &mut metadata_cache)?;

            let score_a = results_a
                .iter()
                .find(|entry| entry.id == id)
                .unwrap_or_else(|| panic!("case {name}: entity missing in sigma_a results"))
                .score;
            let score_b = results_b
                .iter()
                .find(|entry| entry.id == id)
                .unwrap_or_else(|| panic!("case {name}: entity missing in sigma_b results"))
                .score;

            assert!(
                score_a < score_b,
                "case {name}: expected score_a < score_b (sigma_a={sigma_a}, sigma_b={sigma_b}, distance={distance}); got score_a={score_a}, score_b={score_b}"
            );
        }

        Ok(())
    }

    #[test]
    fn sigma_driven_discovery_for_year_granularity() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let anchor = 1_000_000;
        let far = entity_id(100);
        let hundred_days = 100 * 86_400;

        put_entity(
            &vault,
            far,
            1,
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
        let (_dir, vault) = open_test_vault();

        let anchor = 2_000_000;
        let near = entity_id(110);
        let far_a = entity_id(111);
        let far_b = entity_id(112);

        put_entity(
            &vault,
            near,
            1,
            anchor + 1_000,
            anchor + 1_000,
            anchor + 1_000,
        )?;
        put_entity(
            &vault,
            far_a,
            1,
            anchor - 500_000,
            anchor - 500_000,
            anchor - 500_000,
        )?;
        put_entity(
            &vault,
            far_b,
            1,
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
        let (_dir, vault) = open_test_vault();

        let anchor = 5_000_000;
        let target = entity_id(120);

        put_entity(
            &vault,
            target,
            1,
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
        let (_dir, vault) = open_test_vault();

        let anchor = 3_000_000;
        let cluster_a = entity_id(130);
        let cluster_b = entity_id(131);
        let isolated = entity_id(132);

        put_entity(&vault, cluster_a, 1, anchor, anchor, anchor)?;
        put_entity(
            &vault,
            cluster_b,
            1,
            anchor + 3_600,
            anchor + 3_600,
            anchor + 3_600,
        )?;
        put_entity(
            &vault,
            isolated,
            1,
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
        let (_dir, vault) = open_test_vault();

        let anchor_start = 100;
        let anchor_end = 200;
        let closer = entity_id(140);
        let farther = entity_id(141);

        put_entity(&vault, closer, 1, 120, 130, 150)?;
        put_entity(&vault, farther, 1, 180, 190, 150)?;

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
    fn learned_overlap_tiebreak_uses_learned_axis() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let anchor_start = crate::unix_seconds_now() + 100;
        let anchor_end = anchor_start + 100;
        let closer = entity_id(142);
        let farther = entity_id(143);

        put_entity(
            &vault,
            closer,
            1,
            anchor_start,
            anchor_start + 10,
            anchor_start + 49,
        )?;
        put_entity(
            &vault,
            farther,
            1,
            anchor_start + 49,
            anchor_start + 50,
            anchor_start + 80,
        )?;

        let results = vault
            .query()
            .search_temporal_with_sigma(
                anchor_start,
                anchor_end,
                86_400,
                TemporalAnchorMode::Learned,
                10,
            )
            .run()?;

        assert_eq!(results[0].id, closer);
        Ok(())
    }

    #[test]
    fn filters_work() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let keep = entity_id(150);
        let drop = entity_id(151);

        put_entity(&vault, keep, 1, 100, 110, 200)?;
        put_entity(&vault, drop, 1, 300, 310, 150)?;

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
    fn filters_apply_before_contiguity() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let anchor = 5_000_000;
        for index in 0..5_u8 {
            put_entity(&vault, entity_id(170 + index), 2, anchor, anchor, anchor)?;
        }
        let keep = entity_id(180);
        put_entity(
            &vault,
            keep,
            1,
            anchor + 86_400,
            anchor + 86_400,
            anchor + 86_400,
        )?;

        let results = vault
            .query()
            .search_temporal_with_sigma(anchor, anchor, 86_400, TemporalAnchorMode::Occurred, 20)
            .filter_types(&[1])
            .limit(1)
            .boost_contiguity()
            .run()?;

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, keep);
        Ok(())
    }

    #[test]
    fn inverted_ranges_are_rejected_on_put() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        // The pre-D3 engine silently swapped reversed intervals into
        // (start: 100, end: 300). The fail-closed gate must reject instead
        // and leave nothing behind (M2 pinned decision D3).
        let id = entity_id(170);
        let err = vault
            .put_entity(
                &id,
                1,
                TimeRange {
                    start: 300,
                    end: 100,
                },
                400,
                b"payload",
            )
            .expect_err("reversed occurred interval must be rejected");
        assert!(
            matches!(
                err,
                Error::InvalidTimeRange {
                    start: 300,
                    end: 100
                }
            ),
            "expected InvalidTimeRange {{ start: 300, end: 100 }}, got {err:?}"
        );

        let rtxn = vault.store.env.read_txn()?;
        assert!(
            vault.store.entities.get(&rtxn, id.as_bytes())?.is_none(),
            "rejected put must not write an entity record"
        );

        Ok(())
    }

    // ── D19 read-path claim status gate (ONE-1111) ─────────────────

    use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSubject};
    use crate::types::EdgeKind;

    fn claim_body_bytes(
        appr: ClaimApprovalStatus,
        life: ClaimLifecycleStatus,
        stale: bool,
    ) -> Vec<u8> {
        let mut body = ClaimBody::new(
            "test.status",
            ClaimSubject::Entity(EntityId::from_bytes([0x7C; 16]).expect("valid id")),
            rmpv::Value::from("v"),
            0.9,
            appr,
            life,
        );
        body.stale = stale;
        crate::claim::encode_claim_body(&body).expect("encode claim body")
    }

    fn put_status_claim(
        vault: &Vault,
        id: EntityId,
        text: &str,
        appr: ClaimApprovalStatus,
        life: ClaimLifecycleStatus,
        stale: bool,
    ) -> Result<()> {
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: 1, end: 1 },
                1,
                &claim_body_bytes(appr, life, stale),
            )
            .text(&id, &[("body", text)])
            .commit()
    }

    /// Raw-writes an entity record (25-byte envelope + `body`), bypassing
    /// every write-path validation — the AC 7 corruption fixture.
    fn overwrite_entity_record(
        vault: &Vault,
        id: &EntityId,
        entity_type: u8,
        body: &[u8],
    ) -> Result<()> {
        let mut raw = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
        raw.push(entity_type);
        raw.extend_from_slice(&1_u64.to_be_bytes());
        raw.extend_from_slice(&1_u64.to_be_bytes());
        raw.extend_from_slice(&1_u64.to_be_bytes());
        raw.extend_from_slice(body);
        vault.with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &raw)?;
            Ok(())
        })
    }

    /// AC 1 / AC 3 / AC 4 — the literal status table through the text
    /// channel: ONLY `appr ∈ {auto, approved}` ∧ `life = active` ∧
    /// `stale ∈ {absent, false}` surfaces. The surfaceable rows are written
    /// through `ClaimBody::new` (stale ABSENT on disk), so their presence
    /// also pins "absence alone must NOT exclude".
    #[test]
    fn claim_status_gate_pins_the_literal_status_table() -> Result<()> {
        use ClaimApprovalStatus as A;
        use ClaimLifecycleStatus as L;

        let (_dir, vault) = open_test_vault();

        let cases: &[(u8, A, L, bool, bool)] = &[
            // (id byte, appr, life, stale, must_surface)
            (10, A::Auto, L::Active, false, true),
            (11, A::Approved, L::Active, false, true),
            (12, A::Proposed, L::Active, false, false),
            (13, A::Rejected, L::Active, false, false),
            (14, A::Auto, L::Superseded, false, false),
            (15, A::Auto, L::Retracted, false, false),
            (16, A::Auto, L::Active, true, false),
        ];

        for (byte, appr, life, stale, _) in cases {
            put_status_claim(
                &vault,
                entity_id(*byte),
                "statusneedle",
                *appr,
                *life,
                *stale,
            )?;
        }

        let results = vault.query().search_text("statusneedle", 20).run()?;
        let surfaced = to_score_map(&results);

        for (byte, appr, life, stale, must_surface) in cases {
            assert_eq!(
                surfaced.contains_key(&entity_id(*byte)),
                *must_surface,
                "appr={appr:?} life={life:?} stale={stale} must_surface={must_surface}"
            );
        }
        assert_eq!(results.len(), 2, "exactly the two surfaceable claims");
        Ok(())
    }

    /// AC 2 — the gate covers all five channels: one claim is reachable via
    /// text, vector, phonetic, temporal, and PPR; after `retract_claim`
    /// (which re-puts the body ONLY — every index row survives) it must be
    /// absent from every channel.
    #[test]
    fn claim_status_gate_covers_all_five_channels() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let anchor = 1_000_000_u64;
        let claim = entity_id(20);
        let seed = entity_id(21);

        vault
            .batch()
            .put(
                &claim,
                ENTITY_TYPE_CLAIM,
                TimeRange {
                    start: anchor,
                    end: anchor,
                },
                anchor,
                &claim_body_bytes(
                    ClaimApprovalStatus::Auto,
                    ClaimLifecycleStatus::Active,
                    false,
                ),
            )
            .text(&claim, &[("body", "gateneedle")])
            .vector(&claim, &[0.9, 0.1, 0.0, 0.0])
            .phonetic(&claim, &["KTNTL"])
            .commit()?;

        // PPR channel: a TURN seed with a semantic edge onto the claim.
        vault.put_entity(
            &seed,
            1,
            TimeRange {
                start: anchor,
                end: anchor,
            },
            anchor,
            b"payload",
        )?;
        vault.put_edge(&seed, EdgeKind::Supports, &claim, 0.9)?;

        type ChannelQuery = Box<dyn Fn(&Vault) -> Result<Vec<ScoredEntity>>>;
        let channels: Vec<(&str, ChannelQuery)> = vec![
            (
                "text",
                Box::new(|v: &Vault| v.query().search_text("gateneedle", 10).run()),
            ),
            (
                "vector",
                Box::new(|v: &Vault| v.query().search_vector(&[0.9, 0.1, 0.0, 0.0], 10).run()),
            ),
            (
                "phonetic",
                Box::new(|v: &Vault| v.query().search_phonetic(&["KTNTL"]).run()),
            ),
            (
                "temporal",
                Box::new(move |v: &Vault| {
                    v.query()
                        .search_temporal(anchor - 100, anchor + 100, 10)
                        .run()
                }),
            ),
            (
                "ppr",
                Box::new(move |v: &Vault| v.query().search_ppr(&[seed], 2).run()),
            ),
        ];

        for (name, query) in &channels {
            assert!(
                to_score_map(&query(&vault)?).contains_key(&claim),
                "channel `{name}` must surface the active claim"
            );
        }

        vault.retract_claim(&claim, anchor + 500)?;

        for (name, query) in &channels {
            assert!(
                !to_score_map(&query(&vault)?).contains_key(&claim),
                "channel `{name}` must NOT surface the retracted claim"
            );
        }
        Ok(())
    }

    /// AC 1 — `supersede_claim` closes the OLD claim only: the new claim
    /// keeps surfacing, the superseded one disappears (indexes untouched).
    #[test]
    fn superseded_claim_stops_surfacing_but_successor_does_not() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let old = entity_id(30);
        let new = entity_id(31);
        put_status_claim(
            &vault,
            old,
            "supersedeneedle",
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
            false,
        )?;
        put_status_claim(
            &vault,
            new,
            "supersedeneedle",
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
            false,
        )?;

        vault.supersede_claim(&new, &old, 2_000)?;

        let surfaced = to_score_map(&vault.query().search_text("supersedeneedle", 10).run()?);
        assert!(!surfaced.contains_key(&old), "superseded claim must hide");
        assert!(surfaced.contains_key(&new), "successor must keep surfacing");
        Ok(())
    }

    /// AC 5 — non-type-0 entities are NEVER status-gated: their bodies are
    /// opaque, even when they happen to spell poisonous claim-status keys
    /// or are not MessagePack at all.
    #[test]
    fn non_claim_entities_are_never_status_gated() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        // TURN (type 1) whose body SAYS rejected/retracted/stale.
        let poison = entity_id(40);
        let mut poison_body = Vec::new();
        rmpv::encode::write_value(
            &mut poison_body,
            &rmpv::Value::Map(vec![
                (rmpv::Value::from("appr"), rmpv::Value::from("rejected")),
                (rmpv::Value::from("life"), rmpv::Value::from("retracted")),
                (rmpv::Value::from("stale"), rmpv::Value::Boolean(true)),
            ]),
        )
        .expect("msgpack encode");
        vault
            .batch()
            .put(&poison, 1, TimeRange { start: 1, end: 1 }, 1, &poison_body)
            .text(&poison, &[("body", "opaqueneedle")])
            .commit()?;

        // PERSON-band entity (type 4) whose body is not MessagePack at all.
        let opaque = entity_id(41);
        vault
            .batch()
            .put(&opaque, 4, TimeRange { start: 1, end: 1 }, 1, b"payload")
            .text(&opaque, &[("body", "opaqueneedle")])
            .commit()?;

        let surfaced = to_score_map(&vault.query().search_text("opaqueneedle", 10).run()?);
        assert!(surfaced.contains_key(&poison));
        assert!(surfaced.contains_key(&opaque));
        Ok(())
    }

    /// AC 7 — fail-closed hydration on the pipeline: raw-written type-0
    /// records whose bodies are not the pinned CLAIM ABI never surface
    /// (silent exclusion, not an error).
    #[test]
    fn claim_status_gate_fails_closed_on_undecodable_bodies() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let control = entity_id(50);
        put_status_claim(
            &vault,
            control,
            "rawneedle",
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
            false,
        )?;

        // Three corrupt type-0 records, each text-indexed before the raw
        // overwrite (retraction-style: indexes survive, body goes bad).
        let non_map = entity_id(51);
        let missing_appr = entity_id(52);
        let empty_body = entity_id(53);
        for id in [non_map, missing_appr, empty_body] {
            put_status_claim(
                &vault,
                id,
                "rawneedle",
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
                false,
            )?;
        }

        // (a) body is MessagePack but not a map;
        let mut junk = Vec::new();
        rmpv::encode::write_value(&mut junk, &rmpv::Value::from("junk")).expect("msgpack encode");
        overwrite_entity_record(&vault, &non_map, ENTITY_TYPE_CLAIM, &junk)?;

        // (b) body is a map but missing required `appr`;
        let mut no_appr = Vec::new();
        rmpv::encode::write_value(
            &mut no_appr,
            &rmpv::Value::Map(vec![
                (rmpv::Value::from("pred"), rmpv::Value::from("test.bad")),
                (rmpv::Value::from("val"), rmpv::Value::from("v")),
                (rmpv::Value::from("conf"), rmpv::Value::F32(0.5)),
                (
                    rmpv::Value::from("subj"),
                    rmpv::Value::Binary(vec![0x7C; 16]),
                ),
                (rmpv::Value::from("life"), rmpv::Value::from("active")),
            ]),
        )
        .expect("msgpack encode");
        overwrite_entity_record(&vault, &missing_appr, ENTITY_TYPE_CLAIM, &no_appr)?;

        // (c) body missing entirely (bare 25-byte envelope).
        overwrite_entity_record(&vault, &empty_body, ENTITY_TYPE_CLAIM, &[])?;

        let results = vault.query().search_text("rawneedle", 10).run()?;
        let surfaced = to_score_map(&results);
        assert!(surfaced.contains_key(&control), "control claim surfaces");
        assert_eq!(results.len(), 1, "all three corrupt records suppressed");
        Ok(())
    }

    /// AC 8 — excluded claims never consume `result_limit` slots: the gate
    /// runs before sort/truncate, so retracting the TOP-ranked claim frees
    /// its slot for the next survivor.
    #[test]
    fn excluded_claims_do_not_consume_result_limit_slots() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let c1 = entity_id(60);
        let c2 = entity_id(61);
        let c3 = entity_id(62);
        for (id, text) in [
            (c1, "alpha alpha alpha"),
            (c2, "alpha alpha"),
            (c3, "alpha"),
        ] {
            put_status_claim(
                &vault,
                id,
                text,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
                false,
            )?;
        }

        // Establish the BM25 rank order this test relies on.
        let before = vault.query().search_text("alpha", 10).run()?;
        let before_ids: Vec<EntityId> = before.iter().map(|s| s.id).collect();
        assert_eq!(before_ids, vec![c1, c2, c3], "expected rank order");

        vault.retract_claim(&c1, 2_000)?;

        let after = vault.query().search_text("alpha", 10).limit(2).run()?;
        let after_ids: Vec<EntityId> = after.iter().map(|s| s.id).collect();
        assert_eq!(
            after_ids,
            vec![c2, c3],
            "retracted top claim must not consume a result_limit slot"
        );
        Ok(())
    }

    /// Pinned decision — the gate runs BEFORE expand_ppr implicit seed
    /// selection: a retracted claim never seeds the expansion, so nothing
    /// reachable only through its seeding can surface.
    #[test]
    fn dead_claim_never_seeds_ppr_expansion() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let r = entity_id(70);
        let x = entity_id(71);
        put_status_claim(
            &vault,
            r,
            "seedneedle",
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
            false,
        )?;
        vault.put_entity(&x, 4, TimeRange { start: 1, end: 1 }, 1, b"payload")?;
        vault.put_edge(&r, EdgeKind::Supports, &x, 0.9)?;

        // Control: while active, the claim seeds the expansion and pulls in
        // its neighborhood.
        let before = to_score_map(
            &vault
                .query()
                .search_text("seedneedle", 10)
                .expand_ppr(&[], 2)
                .run()?,
        );
        assert!(before.contains_key(&r));
        assert!(
            before.contains_key(&x),
            "active claim must seed expansion and surface its neighbor"
        );

        vault.retract_claim(&r, 2_000)?;

        let after = vault
            .query()
            .search_text("seedneedle", 10)
            .expand_ppr(&[], 2)
            .run()?;
        assert!(
            after.is_empty(),
            "retracted claim must not seed expansion; got {after:?}"
        );
        Ok(())
    }

    /// Pinned decision — claims PULLED IN by expand_ppr are gated too: the
    /// expansion list is status-gated before fusion, so a dead claim found
    /// through the graph walk cannot surface.
    #[test]
    fn expansion_results_are_status_gated() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let a = entity_id(80);
        let dead = entity_id(81);
        let live = entity_id(82);
        vault
            .batch()
            .put(&a, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
            .text(&a, &[("body", "expneedle")])
            .commit()?;
        put_status_claim(
            &vault,
            dead,
            "deadclaim",
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Retracted,
            false,
        )?;
        put_status_claim(
            &vault,
            live,
            "liveclaim",
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
            false,
        )?;
        vault.put_edge(&a, EdgeKind::Supports, &dead, 0.9)?;
        vault.put_edge(&a, EdgeKind::Supports, &live, 0.9)?;

        let surfaced = to_score_map(
            &vault
                .query()
                .search_text("expneedle", 10)
                .expand_ppr(&[], 2)
                .run()?,
        );
        assert!(surfaced.contains_key(&a), "seed turn surfaces");
        assert!(
            surfaced.contains_key(&live),
            "expansion must surface the ACTIVE claim (control: expansion can surface claims)"
        );
        assert!(
            !surfaced.contains_key(&dead),
            "expansion-introduced retracted claim must be gated"
        );
        Ok(())
    }
}
