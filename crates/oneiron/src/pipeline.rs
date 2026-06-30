use std::collections::{HashMap, HashSet};
use std::time::Instant;

use heed::types::Bytes;
use heed::{Database, RoTxn};

use crate::Vault;
use crate::batch::{
    ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, LONG_INTERVAL_THRESHOLD_SECS,
};
use crate::claim::{ClaimBody, claim_surfaceable};
use crate::codebase::RepoRef;
use crate::error::{Error, Result};
use crate::fusion;
use crate::store::{
    RetrievalAction, RetrievalRunId, RetrievalRunRecord, RetrievalScoreBreakdown,
    RetrievalScoreComponent, RetrievalSignal, Store,
};
use crate::types::{
    EDGE_KEY_LEN, ENTITY_ID_LEN, ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, EdgeKind, EmptyReason,
    EntityId, ScoredEntity, TemporalAnchorMode, TemporalGranularity, TimeRange,
};

const DEFAULT_RESULT_LIMIT: usize = 20;
const DEFAULT_SIGMA_SECS: u64 = 86_400;
const MIN_WINDOW_RADIUS_SECS: u64 = 7 * 86_400;
const TEMPORAL_KEY_LEN: usize = 24;
const LONG_INTERVAL_VALUE_LEN: usize = 8;
const TEMPORAL_FLOOR: f64 = 0.05;
const SECONDS_PER_DAY_F64: f64 = 86_400.0;

/// Default recency half-life in days (ARCH-0004 `RECENCY_DECAY`,
/// 28-day default). The recency signal's source timestamp is the
/// entity's `learned_at` (v1). This named constant is the engine
/// default: the temporal pipeline's recency decay constant
/// (`RECENCY_DECAY_TAU_SECS = 28.0 * 86_400`, the ARCH-0004 §4.5 table
/// value) derives from it, and callers of
/// [`PipelineBuilder::boost_recency`] can pass it explicitly.
pub const DEFAULT_RECENCY_HALF_LIFE_DAYS: f32 = 28.0;

/// ARCH-0004 §4.5 table value (`28.0 * 86_400`), derived from
/// [`DEFAULT_RECENCY_HALF_LIFE_DAYS`]. The temporal scorer applies it as
/// the decay constant in `exp(-age / tau)` — existing behavior, kept
/// unchanged.
const RECENCY_DECAY_TAU_SECS: f64 = DEFAULT_RECENCY_HALF_LIFE_DAYS as f64 * SECONDS_PER_DAY_F64;
const ALPHA_BASE: f64 = 0.7;
const ALPHA_RANGE: f64 = 0.3;
const ALPHA_TAU_SECS: f64 = 90.0 * SECONDS_PER_DAY_F64;
const PPR_DAMPING: f32 = 0.15;
const ADAPTIVE_ROUNDS: usize = 3;
const PER_SCAN_CAP_FACTOR: usize = 4;
const MAX_TEMPORAL_SEEK_BUFFER: usize = 8_192;
const RRF_K: f32 = 60.0;
const COSINE_GHOST_VECTOR_THRESHOLD: f32 = 0.3;
const GRAVITY_DAMPENING_FACTOR: f32 = 0.5;

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
    repo_ref_filter: Option<&'a RepoRef>,
    project_id_filter: Option<&'a str>,
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
    pub(crate) pending_vectors: Vec<PendingVectorEmbedding>,
    pub(crate) claims_suppressed: usize,
    pub(crate) cosine_ghosts_dampened: usize,
    pub(crate) total_in_scope: usize,
    pub(crate) empty_reason: Option<EmptyReason>,
    pub(crate) telemetry_run_id: Option<RetrievalRunId>,
}

#[derive(Debug, Clone)]
pub struct RetrievalWithTelemetry<T> {
    pub value: T,
    pub run_id: Option<RetrievalRunId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingVectorEmbedding {
    pub id: EntityId,
    pub token: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RetrievalWithPendingVectors<T> {
    pub value: T,
    pub pending_vector_ids: Vec<EntityId>,
    pub pending_vectors: Vec<PendingVectorEmbedding>,
    pub run_id: Option<RetrievalRunId>,
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

/// Facet filter mode for the post-fusion claim facet filter (ARCH-0039
/// facet modes table; ARCH-0022 retrieval-filter rule).
///
/// Selected per query via [`PipelineBuilder::facet`]. Not setting a facet on
/// the builder is the contract's third mode — *(no facet)* — and performs no
/// filtering at all (backward compatible).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FacetMode {
    /// Only core + active-facet claims surface — a claim whose `FacetOf`
    /// edges all target other facets is removed from the results (never
    /// leak RP claims into IRL). Claims with no `FacetOf` edge (core /
    /// unfaceted) and entities of every non-CLAIM type pass untouched.
    /// Strict never rescores.
    Strict,
    /// Return all, boost the active facet: nothing is removed; claims with
    /// a `FacetOf` edge to the active facet have their fused score
    /// multiplied by `boost` (cross-facet analysis, psych mirror
    /// generation). The multiplier is CALLER-SUPPLIED — the contract pins
    /// no constant — and must be finite and positive; it is applied at
    /// most once per claim regardless of how many `FacetOf` edges match.
    Prefer {
        /// Score multiplier for active-facet claims. Must be finite and
        /// `> 0`, enforced fail-closed at [`PipelineBuilder::run`] time
        /// with [`Error::InvalidConfig`].
        boost: f32,
    },
}

/// World retrieval scope for the post-fusion claim world filter (ARCH-0004
/// claim-filtering: `worldId = vault.baseWorld` unless the query targets a
/// fictional world; ARCH-0022 world model). Selected per query via
/// [`PipelineBuilder::world`]; the default is [`WorldScope::All`].
///
/// A claim's world is the `world` key in its body — an absent key is base
/// reality (the elide-the-default pattern). Non-claim entities have no world
/// and are treated as base, so they pass every scope untouched. This is a
/// pure post-fusion filter in the same stage as the facet filter; scoring and
/// fusion are never touched.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum WorldScope {
    /// Span every world — base-reality claims plus every fictional / dream
    /// world's claims surface. The default; the context pack groups the
    /// survivors by world (base section first).
    All,
    /// Only base-reality claims — claims with NO `world` key (and all
    /// non-claim entities). Every world-scoped claim is removed.
    Base,
    /// Claims scoped to this world id PLUS base-reality claims. Claims scoped
    /// to any OTHER world are removed.
    World(EntityId),
}

/// A claim's facet scope relative to the query's active facet, derived from
/// its outgoing `FacetOf` (`CLAIM → FACET`, u8 17) adjacency.
enum ClaimFacetScope {
    /// No `FacetOf` edge: a core / unfaceted claim. Passes every mode.
    Unfaceted,
    /// At least one `FacetOf` edge targets the active facet.
    ActiveFacet,
    /// Has `FacetOf` edges, none targeting the active facet.
    OtherFacetsOnly,
}

#[must_use = "PipelineBuilder executes no query until a terminal `.run*()` method is called"]
pub struct PipelineBuilder<'a> {
    vault: &'a Vault,
    vector_search: Option<(Vec<f32>, usize)>,
    text_search: Option<(String, usize)>,
    rank_profile: Option<crate::types::Bm25RankProfile>,
    phonetic_search: Option<Vec<String>>,
    temporal_search: Option<TemporalSearchConfig>,
    ppr_search: Option<(Vec<EntityId>, u32)>,
    ppr_expand: Option<(Vec<EntityId>, u32)>,
    recency_half_life: Option<f32>,
    apply_salience: bool,
    apply_confidence: bool,
    apply_gravity: bool,
    apply_contiguity: bool,
    type_filter: Option<Vec<u8>>,
    since_filter: Option<u64>,
    occurred_range: Option<(u64, u64)>,
    learned_range: Option<(u64, u64)>,
    repo_ref_filter: Option<RepoRef>,
    project_id_filter: Option<String>,
    facet_filter: Option<(EntityId, FacetMode)>,
    world_scope: WorldScope,
    result_limit: usize,
    temporal_adaptive_default: bool,
    telemetry_action: RetrievalAction,
}

impl<'a> PipelineBuilder<'a> {
    pub(crate) fn new(vault: &'a Vault) -> Self {
        Self {
            vault,
            vector_search: None,
            text_search: None,
            rank_profile: None,
            phonetic_search: None,
            temporal_search: None,
            ppr_search: None,
            ppr_expand: None,
            recency_half_life: None,
            apply_salience: false,
            apply_confidence: false,
            apply_gravity: false,
            apply_contiguity: false,
            type_filter: None,
            since_filter: None,
            occurred_range: None,
            learned_range: None,
            repo_ref_filter: None,
            project_id_filter: None,
            facet_filter: None,
            world_scope: WorldScope::All,
            result_limit: DEFAULT_RESULT_LIMIT,
            temporal_adaptive_default: true,
            telemetry_action: RetrievalAction::Pipeline,
        }
    }

    pub(crate) fn telemetry_action(mut self, action: RetrievalAction) -> Self {
        self.telemetry_action = action;
        self
    }

    pub fn search_vector(mut self, vector: &[f32], limit: usize) -> Self {
        self.vector_search = Some((vector.to_vec(), limit));
        self
    }

    pub fn search_text(mut self, query: &str, limit: usize) -> Self {
        self.text_search = Some((query.to_owned(), limit));
        self
    }

    /// Applies a scoring-only BM25F rank profile to the text signal
    /// (ARCH-0031: Okapi default, `Plus { delta }` and per-channel
    /// weight / `b` are non-reindexing options). The profile is
    /// validated fail-closed when the pipeline runs; an invalid
    /// parameter returns [`crate::Error::InvalidRankProfile`], even when
    /// no text search is configured.
    pub fn rank_profile(mut self, profile: crate::types::Bm25RankProfile) -> Self {
        self.rank_profile = Some(profile);
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

    pub fn boost_gravity(mut self) -> Self {
        self.apply_gravity = true;
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

    pub fn filter_repo_ref(mut self, repo_ref: RepoRef) -> Self {
        self.repo_ref_filter = Some(repo_ref);
        self
    }

    pub fn filter_project_id(mut self, project_id: impl Into<String>) -> Self {
        self.project_id_filter = Some(project_id.into());
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.result_limit = n;
        self
    }

    /// Activates the ARCH-0039 facet filter for this query: `facet_id` is
    /// the active FACET entity and `mode` selects `strict` (only core +
    /// active-facet claims) or `prefer` (return all, boost active facet).
    /// Not calling this method is the contract's *(no facet)* mode — no
    /// facet filtering at all.
    ///
    /// The filter runs post-fusion/post-boosts, before the
    /// `result_limit` truncation and under the same read transaction, so
    /// claims excluded by `strict` never consume result slots. It reads
    /// each candidate CLAIM's outgoing `FacetOf` (`CLAIM → FACET`) edges;
    /// claim bodies are never decoded by this stage.
    pub fn facet(mut self, facet_id: &EntityId, mode: FacetMode) -> Self {
        self.facet_filter = Some((*facet_id, mode));
        self
    }

    /// Sets the ARCH-0004 / ARCH-0022 world scope for this query. The default
    /// is [`WorldScope::All`] (span every world). [`WorldScope::Base`] keeps
    /// only claims with no `world` key; [`WorldScope::World`] keeps that
    /// world's claims plus base claims. The filter runs post-fusion /
    /// post-boosts, before the `result_limit` truncation and under the same
    /// read transaction — in the same stage as the facet filter — so claims
    /// excluded by scope never consume result slots. Scoring and fusion are
    /// untouched.
    pub fn world(mut self, scope: WorldScope) -> Self {
        self.world_scope = scope;
        self
    }

    pub fn run(self) -> Result<Vec<ScoredEntity>> {
        Ok(self.run_with_telemetry()?.value)
    }

    pub fn run_with_telemetry(self) -> Result<RetrievalWithTelemetry<Vec<ScoredEntity>>> {
        let output = self.run_for_pack()?;
        Ok(RetrievalWithTelemetry {
            value: output.scores,
            run_id: output.telemetry_run_id,
        })
    }

    pub fn run_with_pending_vectors(
        self,
    ) -> Result<RetrievalWithPendingVectors<Vec<ScoredEntity>>> {
        let output = self.run_for_pack()?;
        let pending_vector_ids = pending_vector_ids(&output.pending_vectors);
        Ok(RetrievalWithPendingVectors {
            value: output.scores,
            pending_vector_ids,
            pending_vectors: output.pending_vectors,
            run_id: output.telemetry_run_id,
        })
    }

    /// Executes the pipeline and returns the detailed [`PipelineOutput`]
    /// the context-pack path consumes (gated scores + the claim bodies the
    /// D19 gate already decoded + the suppression count).
    pub(crate) fn run_for_pack(self) -> Result<PipelineOutput> {
        let started = Instant::now();
        let started_at = crate::unix_seconds_now();
        let telemetry_action = self.telemetry_action;
        let mut telemetry_signals = self.telemetry_signals();
        let no_data_fallback_eligible = self.no_data_fallback_eligible();
        let mut ppr_expand_executed = false;

        // Resolve the rank profile before anything else: an invalid
        // profile is a caller bug and fails closed even when no text
        // search would consume it on this run.
        let bm25_config = match self.rank_profile.as_ref() {
            Some(profile) => profile.to_bm25_config()?,
            None => crate::bm25::Bm25Config::default(),
        };

        // ARCH-0039 facet `prefer` boost is a caller-supplied multiplier
        // (ONE-1117): reject a non-finite or non-positive boost fail-closed
        // here, before any work, in the same spirit as the rank profile above.
        if let Some((_, FacetMode::Prefer { boost })) = self.facet_filter
            && (!boost.is_finite() || boost <= 0.0)
        {
            return Err(Error::InvalidConfig(format!(
                "facet prefer boost must be finite and positive, got {boost}"
            )));
        }

        if self.text_search.is_some() {
            self.vault.ensure_text_index_trusted()?;
        }

        let (
            scores,
            pending_vectors,
            claim_gate,
            deferred_ppr_cache_writes,
            cosine_ghosts_dampened,
            total_in_scope,
            empty_reason,
            signal_components,
        ) = {
            let mut ranked_lists = Vec::new();
            let mut signal_components = HashMap::<EntityId, Vec<RetrievalScoreComponent>>::new();
            let mut vector_channel_index = None;
            let mut text_channel_index = None;
            let rtxn = self.vault.store.env.read_txn()?;
            let mut metadata_cache = EntityMetadataCache::default();
            let mut claim_gate = ClaimStatusGateCache::default();
            let mut deferred_ppr_cache_writes = Vec::new();
            let codebase_scope_active = self.has_codebase_scope_filter();

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

                let channel_limit = scoped_vector_channel_limit(
                    &self.vault.store,
                    &rtxn,
                    *limit,
                    codebase_scope_active,
                )?;
                let vector_results = crate::hnsw::hnsw_search(
                    &self.vault.store,
                    &self.vault.config,
                    &rtxn,
                    query_vector,
                    channel_limit,
                )?;
                add_signal_score_components(
                    &mut signal_components,
                    RetrievalSignal::Vector,
                    &vector_results,
                );
                vector_channel_index = Some(ranked_lists.len());
                ranked_lists.push(vector_results);
            }

            if let Some((query, limit)) = &self.text_search {
                let channel_limit = scoped_text_channel_limit(
                    &self.vault.store,
                    &rtxn,
                    *limit,
                    codebase_scope_active,
                )?;
                let text_results = crate::bm25::search_text(
                    &self.vault.store,
                    &rtxn,
                    &self.vault.analyzer,
                    &bm25_config,
                    query,
                    channel_limit,
                )?;
                add_signal_score_components(
                    &mut signal_components,
                    RetrievalSignal::Text,
                    &text_results,
                );
                text_channel_index = Some(ranked_lists.len());
                ranked_lists.push(text_results);
            }

            if let Some(codes) = &self.phonetic_search {
                let phonetic_results = execute_phonetic(&self.vault.store, &rtxn, codes)?;
                add_signal_score_components(
                    &mut signal_components,
                    RetrievalSignal::Phonetic,
                    &phonetic_results,
                );
                ranked_lists.push(phonetic_results);
            }

            if let Some(config) = &self.temporal_search {
                let mut scoped_config = config.clone();
                scoped_config.limit = scoped_entity_channel_limit(
                    &self.vault.store,
                    &rtxn,
                    config.limit,
                    codebase_scope_active,
                )?;
                let temporal_results = execute_temporal(
                    &self.vault.store,
                    &rtxn,
                    &scoped_config,
                    &mut metadata_cache,
                )?;
                add_signal_score_components(
                    &mut signal_components,
                    RetrievalSignal::Temporal,
                    &temporal_results,
                );
                ranked_lists.push(temporal_results);
            }

            if let Some((seeds, depth)) = &self.ppr_search {
                // ARCH-0039 Layer 2: seed specificity applies ONLY to
                // search_ppr — seeds are weighted 1/ln(1 + passage_count)
                // instead of uniform 1/n.
                let (ppr_results, deferred_cache_write) =
                    crate::ppr::ppr_query_in_txn_with_deferred_cache(
                        &self.vault.store,
                        &rtxn,
                        seeds,
                        *depth,
                        PPR_DAMPING,
                        crate::ppr::SeedWeighting::Specificity,
                    )?;
                add_signal_score_components(
                    &mut signal_components,
                    RetrievalSignal::Ppr,
                    &ppr_results,
                );
                if let Some(deferred_cache_write) = deferred_cache_write {
                    deferred_ppr_cache_writes.push(deferred_cache_write);
                }
                ranked_lists.push(ppr_results);
            }

            if ranked_lists.is_empty() {
                return Ok(PipelineOutput {
                    scores: Vec::new(),
                    claim_bodies: HashMap::new(),
                    pending_vectors: Vec::new(),
                    claims_suppressed: 0,
                    cosine_ghosts_dampened: 0,
                    total_in_scope: 0,
                    empty_reason: None,
                    telemetry_run_id: None,
                });
            }

            let mut scores = fusion::rrf_fuse(&ranked_lists, RRF_K);
            let total_in_scope = scores.len();
            let mut empty_reason = None;

            // D19 claim status gate, first application: covers the fused
            // candidates of all five channels (text/vector/phonetic/
            // temporal/PPR) AND runs BEFORE expand_ppr implicit seed
            // selection, so a dead claim never seeds the expansion.
            let before_status_gate = scores.len();
            apply_claim_status_gate(
                &mut scores,
                &self.vault.store,
                &rtxn,
                &mut metadata_cache,
                &mut claim_gate,
            )?;
            if before_status_gate > 0 && scores.is_empty() {
                empty_reason = Some(EmptyReason::AllActivated);
            }

            if let Some((explicit_seeds, depth)) = &self.ppr_expand {
                let mut seen = HashSet::<EntityId>::new();
                let mut seeds = Vec::<EntityId>::new();
                for seed in explicit_seeds {
                    if seen.insert(*seed) {
                        seeds.push(*seed);
                    }
                }
                if seeds.len() < crate::ppr::MAX_PPR_SEEDS {
                    let implicit_seed_limit = if codebase_scope_active {
                        scores.len()
                    } else {
                        self.result_limit
                    };
                    for scored in scores.iter().take(implicit_seed_limit) {
                        if seen.insert(scored.id) {
                            seeds.push(scored.id);
                            if seeds.len() == crate::ppr::MAX_PPR_SEEDS {
                                break;
                            }
                        }
                    }
                }

                if !seeds.is_empty() {
                    ppr_expand_executed = true;
                    seeds.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));

                    // expand_ppr seeds stay UNIFORM — ARCH-0039 Layer-2
                    // specificity weighting is search_ppr-only.
                    let (mut ppr_results, deferred_cache_write) =
                        crate::ppr::ppr_query_in_txn_with_deferred_cache(
                            &self.vault.store,
                            &rtxn,
                            &seeds,
                            *depth,
                            PPR_DAMPING,
                            crate::ppr::SeedWeighting::Uniform,
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
                    add_signal_score_components(
                        &mut signal_components,
                        RetrievalSignal::Ppr,
                        &ppr_results,
                    );
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

            let cosine_ghosts_dampened = if self.apply_gravity {
                apply_gravity(
                    &mut scores,
                    &ranked_lists,
                    vector_channel_index,
                    text_channel_index,
                )
            } else {
                0
            };

            let filter_config = PipelineFilterConfig {
                type_filter: self.type_filter.as_deref(),
                since_filter: self.since_filter,
                occurred_range: self.occurred_range,
                learned_range: self.learned_range,
                repo_ref_filter: self.repo_ref_filter.as_ref(),
                project_id_filter: self.project_id_filter.as_deref(),
            };
            let before_filters = scores.len();
            apply_filters(
                &mut scores,
                &self.vault.store,
                &rtxn,
                filter_config,
                &mut metadata_cache,
            )?;
            if before_filters > 0 && scores.is_empty() {
                empty_reason = Some(EmptyReason::FilterMatchedNone);
            }

            if self.apply_contiguity {
                boost_contiguity(
                    &mut scores,
                    self.temporal_search.as_ref(),
                    &self.vault.store,
                    &rtxn,
                    &mut metadata_cache,
                )?;
            }

            // ARCH-0039 facet filter (ONE-1117): post-fusion / post-boosts,
            // before truncate, same read txn — strict-excluded claims never
            // consume `result_limit` slots.
            if let Some((facet_id, mode)) = self.facet_filter {
                let before_facet = scores.len();
                apply_facet_filter(
                    &mut scores,
                    &self.vault.store,
                    &rtxn,
                    &mut metadata_cache,
                    &facet_id,
                    mode,
                )?;
                if before_facet > 0 && scores.is_empty() {
                    empty_reason = Some(EmptyReason::FilterMatchedNone);
                }
            }

            // ARCH-0004 world filter (ONE-1117): same post-fusion stage as the
            // facet filter, before truncate, same read txn. A no-op under the
            // default `WorldScope::All`.
            let before_world = scores.len();
            apply_world_filter(&mut scores, &self.vault.store, &rtxn, self.world_scope)?;
            if before_world > 0 && scores.is_empty() {
                empty_reason = Some(EmptyReason::FilterMatchedNone);
            }

            let before_limit = scores.len();
            fusion::sort_scored_entities_desc(&mut scores);
            scores.truncate(self.result_limit);
            if before_limit > 0 && scores.is_empty() {
                empty_reason = Some(EmptyReason::BelowThreshold);
            }
            if no_data_fallback_eligible
                && total_in_scope == 0
                && scores.is_empty()
                && empty_reason.is_none()
            {
                empty_reason = Some(EmptyReason::NoData);
            }
            let pending_vectors = pending_vectors_for_scores(&self.vault.store, &rtxn, &scores)?;
            (
                scores,
                pending_vectors,
                claim_gate,
                deferred_ppr_cache_writes,
                cosine_ghosts_dampened,
                total_in_scope,
                empty_reason,
                signal_components,
            )
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

        let score_breakdown = telemetry_score_breakdown(&scores, &signal_components);
        let ppr_search_executed = self
            .ppr_search
            .as_ref()
            .is_some_and(|(seeds, _)| !seeds.is_empty());
        if !ppr_search_executed && self.ppr_expand.is_some() && !ppr_expand_executed {
            telemetry_signals.retain(|signal| *signal != RetrievalSignal::Ppr);
        }
        let run_id = RetrievalRunId::now();
        let run_record = RetrievalRunRecord::new(
            run_id,
            telemetry_action,
            started_at,
            started.elapsed().as_micros().min(u64::MAX as u128) as u64,
            telemetry_signals,
            score_breakdown,
            total_in_scope,
            claims_suppressed,
            empty_reason.map(|reason| format!("{reason:?}")),
        );
        let write_result = if telemetry_action == RetrievalAction::ContextPack {
            self.vault
                .store
                .record_context_pack_provisional_retrieval_run(&run_record)
        } else {
            self.vault.store.record_retrieval_run(&run_record)
        };
        let telemetry_run_id = match write_result {
            Ok(()) => Some(run_id),
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "retrieval telemetry run write failed; continuing retrieval"
                );
                None
            }
        };

        Ok(PipelineOutput {
            scores,
            claim_bodies,
            pending_vectors,
            claims_suppressed,
            cosine_ghosts_dampened,
            total_in_scope,
            empty_reason,
            telemetry_run_id,
        })
    }

    fn telemetry_signals(&self) -> Vec<RetrievalSignal> {
        let mut signals = Vec::new();
        if self.vector_search.is_some() {
            signals.push(RetrievalSignal::Vector);
        }
        if self.text_search.is_some() {
            signals.push(RetrievalSignal::Text);
        }
        if self
            .phonetic_search
            .as_ref()
            .is_some_and(|codes| !codes.is_empty())
        {
            signals.push(RetrievalSignal::Phonetic);
        }
        if self.temporal_search.is_some() {
            signals.push(RetrievalSignal::Temporal);
        }
        if self
            .ppr_search
            .as_ref()
            .is_some_and(|(seeds, _)| !seeds.is_empty())
            || self.ppr_expand.is_some()
        {
            signals.push(RetrievalSignal::Ppr);
        }
        signals
    }

    fn no_data_fallback_eligible(&self) -> bool {
        self.vector_search
            .as_ref()
            .is_some_and(|(_, limit)| *limit > 0)
            || self
                .text_search
                .as_ref()
                .is_some_and(|(_, limit)| *limit > 0)
            || self
                .phonetic_search
                .as_ref()
                .is_some_and(|codes| !codes.is_empty())
            || self
                .temporal_search
                .as_ref()
                .is_some_and(|config| config.limit > 0)
            || self
                .ppr_search
                .as_ref()
                .is_some_and(|(seeds, _)| !seeds.is_empty())
            || self
                .ppr_expand
                .as_ref()
                .is_some_and(|(seeds, _)| !seeds.is_empty())
    }

    fn has_codebase_scope_filter(&self) -> bool {
        self.repo_ref_filter.is_some() || self.project_id_filter.is_some()
    }
}

fn pending_vectors_for_scores(
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

fn pending_vector_ids(pending: &[PendingVectorEmbedding]) -> Vec<EntityId> {
    pending.iter().map(|pending| pending.id).collect()
}

fn add_signal_score_components(
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

fn telemetry_score_breakdown(
    scores: &[ScoredEntity],
    components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
) -> Vec<RetrievalScoreBreakdown> {
    scores
        .iter()
        .enumerate()
        .map(|(rank, scored)| RetrievalScoreBreakdown {
            result_id: *scored.id.as_bytes(),
            final_rank: (rank + 1).min(u32::MAX as usize) as u32,
            final_score: scored.score,
            components: components.get(&scored.id).cloned().unwrap_or_default(),
        })
        .collect()
}

fn scoped_text_channel_limit(
    store: &Store,
    rtxn: &RoTxn<'_>,
    requested: usize,
    codebase_scope_active: bool,
) -> Result<usize> {
    if !codebase_scope_active || requested == 0 {
        return Ok(requested);
    }
    let indexed_docs = usize::try_from(crate::bm25::read_total_docs(store, rtxn)?)
        .map_err(|_| Error::IndexOverflow("bm25 total docs"))?;
    Ok(requested.max(indexed_docs))
}

fn scoped_vector_channel_limit(
    store: &Store,
    rtxn: &RoTxn<'_>,
    requested: usize,
    codebase_scope_active: bool,
) -> Result<usize> {
    if !codebase_scope_active || requested == 0 {
        return Ok(requested);
    }
    Ok(requested.max(crate::hnsw::hnsw_entity_count(store, rtxn)?))
}

fn scoped_entity_channel_limit(
    store: &Store,
    rtxn: &RoTxn<'_>,
    requested: usize,
    codebase_scope_active: bool,
) -> Result<usize> {
    if !codebase_scope_active || requested == 0 {
        return Ok(requested);
    }
    let entity_count = usize::try_from(store.entities.len(rtxn)?)
        .map_err(|_| Error::IndexOverflow("entity count"))?;
    Ok(requested.max(entity_count))
}

fn apply_gravity(
    scores: &mut [ScoredEntity],
    ranked_lists: &[Vec<ScoredEntity>],
    vector_channel_index: Option<usize>,
    text_channel_index: Option<usize>,
) -> usize {
    let (Some(vector_channel_index), Some(text_channel_index)) =
        (vector_channel_index, text_channel_index)
    else {
        return 0;
    };
    let (Some(vector_results), Some(text_results)) = (
        ranked_lists.get(vector_channel_index),
        ranked_lists.get(text_channel_index),
    ) else {
        return 0;
    };

    let text_ids: HashSet<EntityId> = text_results.iter().map(|scored| scored.id).collect();
    let cosine_ghosts: HashSet<EntityId> = vector_results
        .iter()
        .filter(|scored| {
            scored.score > COSINE_GHOST_VECTOR_THRESHOLD && !text_ids.contains(&scored.id)
        })
        .map(|scored| scored.id)
        .collect();

    let mut dampened = 0;
    for scored in scores {
        if cosine_ghosts.contains(&scored.id) {
            scored.score *= GRAVITY_DAMPENING_FACTOR;
            dampened += 1;
        }
    }
    dampened
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

/// ARCH-0039 facet filter (its own pipeline stage, ONE-1117): the
/// post-fusion claim filter for the `strict` / `prefer` facet modes.
///
/// Operates on type-0 (CLAIM) records only — entities of every other type
/// byte pass through untouched, even when they carry `FacetOf` edges. A
/// claim's facet scope is its outgoing `FacetOf` (`CLAIM → FACET`, u8 17)
/// adjacency; no other edge kind participates and claim bodies are never
/// decoded (so this stage shares nothing with the claim-status decode path
/// beyond the entity-metadata cache).
///
/// * [`FacetMode::Strict`] — claims scoped exclusively to other facets are
///   removed; core/unfaceted and active-facet claims pass with their score
///   untouched. Removal is silent (no error) and happens before the
///   `result_limit` truncation, so excluded claims free their slots.
/// * [`FacetMode::Prefer`] — nothing is removed; active-facet claims have
///   their score multiplied by the caller-supplied boost exactly once.
///
/// Fail-closed: a malformed `edges_out` key under the scanned
/// `(claim, FacetOf)` prefix is a typed [`Error::CorruptedIndex`], never a
/// skip.
fn apply_facet_filter(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
    active_facet: &EntityId,
    mode: FacetMode,
) -> Result<()> {
    // Fail-closed: the active facet MUST resolve to an existing FACET entity
    // (type byte 13, per contracts.ts §1 / ARCH-0022 `facet_of` is CLAIM →
    // FACET). A bogus id or a wrong-type id is rejected with a typed error —
    // otherwise strict mode would silently treat every scoped claim as
    // belonging to another facet and drop them all.
    let active_facet_type = metadata_cache
        .get(store, rtxn, active_facet)?
        .map(|meta| meta.entity_type);
    if active_facet_type != Some(ENTITY_TYPE_FACET) {
        return Err(Error::InvalidFacet {
            facet: *active_facet,
            found: active_facet_type,
        });
    }

    let mut kept = Vec::with_capacity(scores.len());

    for mut scored in scores.iter().copied() {
        // Entities without a parseable envelope are not a facet decision;
        // `apply_filters` handles them downstream exactly as before.
        let Some(meta) = metadata_cache.get(store, rtxn, &scored.id)? else {
            kept.push(scored);
            continue;
        };
        if meta.entity_type != ENTITY_TYPE_CLAIM {
            kept.push(scored);
            continue;
        }

        match claim_facet_scope(store, rtxn, &scored.id, active_facet)? {
            ClaimFacetScope::Unfaceted => kept.push(scored),
            ClaimFacetScope::ActiveFacet => {
                if let FacetMode::Prefer { boost } = mode {
                    scored.score *= boost;
                }
                kept.push(scored);
            }
            ClaimFacetScope::OtherFacetsOnly => {
                if let FacetMode::Prefer { .. } = mode {
                    kept.push(scored);
                }
                // Strict: removed — never leak another facet's claims.
            }
        }
    }

    *scores = kept;
    Ok(())
}

/// Resolves a claim's [`ClaimFacetScope`] by prefix-scanning `edges_out`
/// over the 17-byte `(claim_id ‖ FacetOf)` prefix. Only the edge KEY is
/// read — `(source, kind, target)` carries the whole facet-scope signal.
fn claim_facet_scope(
    store: &Store,
    rtxn: &RoTxn<'_>,
    claim_id: &EntityId,
    active_facet: &EntityId,
) -> Result<ClaimFacetScope> {
    let mut prefix = [0_u8; ENTITY_ID_LEN + 1];
    prefix[..ENTITY_ID_LEN].copy_from_slice(claim_id.as_bytes());
    prefix[ENTITY_ID_LEN] = EdgeKind::FacetOf as u8;

    let mut any_facet_edge = false;
    for row in store.edges_out.prefix_iter(rtxn, prefix.as_slice())? {
        let (key, _value) = row?;
        if key.len() != EDGE_KEY_LEN {
            return Err(Error::CorruptedIndex("edge record"));
        }
        any_facet_edge = true;
        if &key[ENTITY_ID_LEN + 1..] == active_facet.as_bytes() {
            return Ok(ClaimFacetScope::ActiveFacet);
        }
    }

    if any_facet_edge {
        Ok(ClaimFacetScope::OtherFacetsOnly)
    } else {
        Ok(ClaimFacetScope::Unfaceted)
    }
}

/// ARCH-0004 world filter (ONE-1117): the post-fusion claim world filter for
/// the `Base` / `World(id)` scopes. A pure removal filter — scores are never
/// rewritten, mirroring the facet filter's `strict` removal.
///
/// * [`WorldScope::All`] — a no-op; every candidate passes (the context pack
///   groups them by world downstream).
/// * [`WorldScope::Base`] — only base-reality claims (no `world` key) survive;
///   every world-scoped claim is removed.
/// * [`WorldScope::World`] — claims scoped to the target world plus base
///   claims survive; claims scoped to any other world are removed.
///
/// Non-claim entities have no world and are treated as base, so they pass
/// every scope untouched. Removal happens before the `result_limit`
/// truncation, so excluded claims free their slots.
fn apply_world_filter(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    scope: WorldScope,
) -> Result<()> {
    let target = match scope {
        WorldScope::All => return Ok(()),
        WorldScope::Base => None,
        WorldScope::World(id) => Some(id),
    };

    let mut kept = Vec::with_capacity(scores.len());
    for scored in scores.iter().copied() {
        let keep = match claim_world(store, rtxn, &scored.id)? {
            // Base reality (no world key, or a non-claim entity) always passes.
            None => true,
            // A world-scoped claim passes only for its own world.
            Some(world) => target == Some(world),
        };
        if keep {
            kept.push(scored);
        }
    }

    *scores = kept;
    Ok(())
}

/// Reads a candidate's world for the post-fusion world filter (ARCH-0004 /
/// ARCH-0022). Returns `None` for base reality — a non-claim entity, a claim
/// with no `world` key, or an entity with no parseable envelope — and
/// `Some(world_id)` for a world-scoped claim. The claim body is decoded once
/// through the pinned claim validator (the world key was structurally
/// validated to 16 bytes at write time).
fn claim_world(store: &Store, rtxn: &RoTxn<'_>, id: &EntityId) -> Result<Option<EntityId>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    let body = crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    Ok(body.world)
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

        let (chunks, rem) = posting.as_chunks::<ENTITY_ID_LEN>();
        debug_assert!(rem.is_empty());
        for bytes in chunks {
            let id = EntityId::from_bytes(*bytes)
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

        if !crate::codebase::codebase_candidate_matches_filters(
            store,
            rtxn,
            &scored.id,
            filters.repo_ref_filter,
            filters.project_id_filter,
        )? {
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
    use core::assert_matches;
    use std::collections::{BTreeMap, HashMap};

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

    fn put_text_and_vector(
        vault: &Vault,
        id: EntityId,
        text: &str,
        vector: [f32; 4],
    ) -> Result<()> {
        vault
            .batch()
            .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
            .text(&id, &[("body", text)])
            .vector(&id, &vector)
            .commit()
    }

    fn scored(id: EntityId, score: f32) -> ScoredEntity {
        ScoredEntity { id, score }
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

    /// ARCH-0004 §4.5: the recency default is a named 28-day constant
    /// (`RECENCY_DECAY`, source timestamp = `learned_at` v1), and the
    /// temporal scorer's decay constant is the table-pinned
    /// `28.0 * 86_400 = 2_419_200` seconds derived from it.
    #[test]
    fn default_recency_half_life_is_28_days() {
        assert_eq!(DEFAULT_RECENCY_HALF_LIFE_DAYS, 28.0);
        assert_eq!(RECENCY_DECAY_TAU_SECS, 2_419_200.0);
        assert_eq!(RECENCY_DECAY_TAU_SECS, 28.0 * 86_400.0);
    }

    #[test]
    fn dampens_cosine_ghost() {
        assert_eq!(COSINE_GHOST_VECTOR_THRESHOLD, 0.3);
        assert_eq!(GRAVITY_DAMPENING_FACTOR, 0.5);

        let ghost = entity_id(0xA0);
        let vector = vec![scored(ghost, 0.6)];
        let text = Vec::new();
        let mut fused = fusion::rrf_fuse(&[vector.clone(), text.clone()], RRF_K);
        let pre = to_score_map(&fused);

        let dampened = apply_gravity(&mut fused, &[vector, text], Some(0), Some(1));
        let post = to_score_map(&fused);

        assert_eq!(dampened, 1);
        assert!(approx_eq(post[&ghost], pre[&ghost] * 0.5, 1e-7));
    }

    #[test]
    fn threshold_boundary() {
        let boundary = entity_id(0xA1);
        let above = entity_id(0xA2);
        let vector = vec![scored(boundary, 0.30), scored(above, 0.31)];
        let text = Vec::new();
        let mut fused = fusion::rrf_fuse(&[vector.clone(), text.clone()], RRF_K);
        let pre = to_score_map(&fused);

        let dampened = apply_gravity(&mut fused, &[vector, text], Some(0), Some(1));
        let post = to_score_map(&fused);

        assert_eq!(dampened, 1);
        assert!(approx_eq(post[&boundary], pre[&boundary], 1e-7));
        assert!(approx_eq(post[&above], pre[&above] * 0.5, 1e-7));
    }

    #[test]
    fn lexical_overlap_protects() {
        let protected = entity_id(0xA3);
        let vector = vec![scored(protected, 0.6)];
        let text = vec![scored(protected, 9.0)];
        let mut fused = fusion::rrf_fuse(&[vector.clone(), text.clone()], RRF_K);
        let pre = to_score_map(&fused);

        let dampened = apply_gravity(&mut fused, &[vector, text], Some(0), Some(1));
        let post = to_score_map(&fused);

        assert_eq!(dampened, 0);
        assert!(approx_eq(post[&protected], pre[&protected], 1e-7));
    }

    #[test]
    fn single_channel_noop() {
        let ghost = entity_id(0xA4);
        let vector = vec![scored(ghost, 0.6)];
        let mut fused = fusion::rrf_fuse(std::slice::from_ref(&vector), RRF_K);
        let pre = to_score_map(&fused);

        let dampened = apply_gravity(&mut fused, &[vector], Some(0), None);
        let post = to_score_map(&fused);

        assert_eq!(dampened, 0);
        assert!(approx_eq(post[&ghost], pre[&ghost], 1e-7));
    }

    #[test]
    fn metric_counts_dampened() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let ghost_a = entity_id(0xA5);
        let ghost_b = entity_id(0xA6);
        let lexical = entity_id(0xA7);
        let low_similarity = entity_id(0xA8);

        put_vector(&vault, ghost_a, [1.0, 0.0, 0.0, 0.0])?;
        put_vector(&vault, ghost_b, [0.6, 0.8, 0.0, 0.0])?;
        put_text_and_vector(&vault, lexical, "gravityneedle", [0.8, 0.6, 0.0, 0.0])?;
        put_vector(&vault, low_similarity, [0.0, 1.0, 0.0, 0.0])?;

        let output = vault
            .query()
            .search_text("gravityneedle", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .boost_gravity()
            .run_for_pack()?;

        assert_eq!(output.cosine_ghosts_dampened, 2);
        Ok(())
    }

    #[test]
    fn disabled_by_default() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let ghost = entity_id(0xA9);
        let lexical = entity_id(0xAA);

        put_vector(&vault, ghost, [1.0, 0.0, 0.0, 0.0])?;
        put_text(&vault, lexical, "defaultoffneedle")?;

        let baseline = vault
            .query()
            .search_text("defaultoffneedle", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .run_for_pack()?;
        let boosted = vault
            .query()
            .search_text("defaultoffneedle", 10)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .boost_gravity()
            .run_for_pack()?;

        let baseline_scores = to_score_map(&baseline.scores);
        let boosted_scores = to_score_map(&boosted.scores);

        assert_eq!(baseline.cosine_ghosts_dampened, 0);
        assert!(approx_eq(baseline_scores[&ghost], 1.0 / 61.0, 1e-7));
        assert_eq!(boosted.cosine_ghosts_dampened, 1);
        assert!(approx_eq(
            boosted_scores[&ghost],
            baseline_scores[&ghost] * 0.5,
            1e-7
        ));
        Ok(())
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
    fn retrieval_telemetry_records_vector_text_and_ppr_runs() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let a = entity_id(0x31);
        let b = entity_id(0x32);

        vault
            .batch()
            .put(&a, 1, TimeRange { start: 1, end: 1 }, 1, b"payload")
            .text(&a, &[("body", "telemetry alpha")])
            .vector(&a, &[1.0, 0.0, 0.0, 0.0])
            .put(&b, 1, TimeRange { start: 2, end: 2 }, 2, b"payload")
            .vector(&b, &[0.0, 1.0, 0.0, 0.0])
            .edge(&a, EdgeKind::Supports, &b, 1.0)
            .commit()?;

        let vector = vault
            .query()
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 10)
            .run()?;
        let text = vault.query().search_text("alpha", 10).run()?;
        let ppr = vault.query().search_ppr(&[a], 2).run()?;
        assert!(!vector.is_empty());
        assert!(!text.is_empty());
        assert!(!ppr.is_empty());

        let runs = vault.retrieval_runs(10)?;
        let vector_run = runs
            .iter()
            .find(|run| run.signals == vec![RetrievalSignal::Vector])
            .expect("vector telemetry run");
        assert_eq!(vector_run.action, RetrievalAction::Pipeline);
        assert!(vector_run.result_ids.contains(a.as_bytes()));
        assert!(vector_run.score_breakdown.iter().any(|entry| {
            entry
                .components
                .iter()
                .any(|component| component.signal == RetrievalSignal::Vector)
        }));

        let text_run = runs
            .iter()
            .find(|run| run.signals == vec![RetrievalSignal::Text])
            .expect("text telemetry run");
        assert!(text_run.result_ids.contains(a.as_bytes()));
        assert!(text_run.score_breakdown.iter().any(|entry| {
            entry
                .components
                .iter()
                .any(|component| component.signal == RetrievalSignal::Text)
        }));

        let ppr_run = runs
            .iter()
            .find(|run| run.signals == vec![RetrievalSignal::Ppr])
            .expect("ppr telemetry run");
        assert!(ppr_run.score_breakdown.iter().any(|entry| {
            entry
                .components
                .iter()
                .any(|component| component.signal == RetrievalSignal::Ppr)
        }));
        Ok(())
    }

    #[test]
    fn retrieval_outcome_writer_is_idempotent() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = entity_id(0x33);
        put_text(&vault, id, "outcome telemetry")?;

        let results = vault
            .query()
            .search_text("outcome", 10)
            .run_with_telemetry()?;
        assert!(!results.value.is_empty());
        let run_id = results.run_id.expect("outcome telemetry run id");

        let mut metadata = BTreeMap::new();
        metadata.insert("source".to_owned(), "unit-test".to_owned());
        vault.record_retrieval_outcome(crate::store::RetrievalOutcome {
            run_id,
            key: "click".to_owned(),
            reward: Some(1.0),
            accepted: Some(true),
            metadata: metadata.clone(),
        })?;
        metadata.insert("revision".to_owned(), "2".to_owned());
        vault.record_retrieval_outcome(crate::store::RetrievalOutcome {
            run_id,
            key: "click".to_owned(),
            reward: Some(0.5),
            accepted: Some(false),
            metadata,
        })?;

        let outcomes = vault.retrieval_outcomes(run_id)?;
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].key, "click");
        assert_eq!(outcomes[0].reward, Some(0.5));
        assert_eq!(outcomes[0].accepted, Some(false));
        assert_eq!(
            outcomes[0].metadata.get("revision").map(String::as_str),
            Some("2")
        );
        Ok(())
    }

    #[test]
    fn retrieval_outcome_rejects_unknown_run_id() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let unknown_run_id = RetrievalRunId::now();

        let error = vault
            .record_retrieval_outcome(crate::store::RetrievalOutcome {
                run_id: unknown_run_id,
                key: "click".to_owned(),
                reward: Some(1.0),
                accepted: Some(true),
                metadata: BTreeMap::new(),
            })
            .expect_err("unknown run id should be rejected");
        assert!(matches!(error, Error::InvalidConfig(_)));
        assert!(vault.retrieval_outcomes(unknown_run_id)?.is_empty());
        Ok(())
    }

    #[test]
    fn retrieval_outcome_rejects_active_write_transaction() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = entity_id(0x3C);
        put_text(&vault, id, "outcome active transaction")?;

        let results = vault
            .query()
            .search_text("outcome active", 10)
            .run_with_telemetry()?;
        assert!(!results.value.is_empty());
        let run_id = results.run_id.expect("outcome telemetry run id");

        let error = vault
            .with_write_txn(|_wtxn| {
                vault.record_retrieval_outcome(crate::store::RetrievalOutcome {
                    run_id,
                    key: "click".to_owned(),
                    reward: Some(1.0),
                    accepted: Some(true),
                    metadata: BTreeMap::new(),
                })
            })
            .expect_err("outcome write should fail fast inside active write transaction");
        assert!(matches!(error, Error::ConcurrentWrite(_)));
        assert!(vault.retrieval_outcomes(run_id)?.is_empty());
        Ok(())
    }

    #[test]
    fn context_pack_records_context_pack_telemetry() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = entity_id(0x34);
        put_text(&vault, id, "context telemetry")?;

        let pack = vault.context_pack().search_text("context", 10).run()?;
        assert_eq!(pack.results.len(), 1);

        let runs = vault.retrieval_runs(1)?;
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].action, RetrievalAction::ContextPack);
        assert_eq!(runs[0].signals, vec![RetrievalSignal::Text]);
        assert_eq!(runs[0].elapsed_us, pack.stats.query_time_us);
        assert!(runs[0].result_ids.contains(id.as_bytes()));
        Ok(())
    }

    #[test]
    fn direct_vault_searches_emit_retrieval_telemetry() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = entity_id(0x36);
        put_text_and_vector(&vault, id, "direct telemetry", [1.0, 0.0, 0.0, 0.0])?;

        let vector = vault.search_vector_with_telemetry(&[1.0, 0.0, 0.0, 0.0], 10)?;
        let text = vault.search_text_with_telemetry("direct", 10)?;
        assert_eq!(vector.value.len(), 1);
        assert_eq!(text.value.len(), 1);
        let vector_run_id = vector.run_id.expect("direct vector telemetry run id");
        let text_run_id = text.run_id.expect("direct text telemetry run id");

        let runs = vault.retrieval_runs(10)?;
        let vector_run = runs
            .iter()
            .find(|run| {
                run.action == RetrievalAction::VaultSearch
                    && run.signals == vec![RetrievalSignal::Vector]
            })
            .expect("direct vector telemetry run");
        assert_eq!(vector_run.run_id, vector_run_id);
        assert_eq!(vector_run.claims_suppressed, 0);
        assert_eq!(vector_run.result_ids, vec![*id.as_bytes()]);
        assert!(vector_run.score_breakdown.iter().any(|entry| {
            entry
                .components
                .iter()
                .any(|component| component.signal == RetrievalSignal::Vector)
        }));

        let text_run = runs
            .iter()
            .find(|run| {
                run.action == RetrievalAction::VaultSearch
                    && run.signals == vec![RetrievalSignal::Text]
            })
            .expect("direct text telemetry run");
        assert_eq!(text_run.run_id, text_run_id);
        assert_eq!(text_run.claims_suppressed, 0);
        assert_eq!(text_run.result_ids, vec![*id.as_bytes()]);
        assert!(text_run.score_breakdown.iter().any(|entry| {
            entry
                .components
                .iter()
                .any(|component| component.signal == RetrievalSignal::Text)
        }));
        Ok(())
    }

    #[test]
    fn direct_vault_zero_limit_telemetry_has_no_empty_reason() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = entity_id(0x37);
        put_text_and_vector(&vault, id, "zero limit telemetry", [1.0, 0.0, 0.0, 0.0])?;

        let text = vault.search_text_with_telemetry("zero limit", 0)?;
        let vector = vault.search_vector_with_telemetry(&[1.0, 0.0, 0.0, 0.0], 0)?;
        assert!(text.value.is_empty());
        assert!(vector.value.is_empty());
        let text_run_id = text.run_id.expect("text zero-limit telemetry run id");
        let vector_run_id = vector.run_id.expect("vector zero-limit telemetry run id");

        let runs = vault.retrieval_runs(10)?;
        let text_run = runs
            .iter()
            .find(|run| run.run_id == text_run_id)
            .expect("text zero-limit telemetry row");
        let vector_run = runs
            .iter()
            .find(|run| run.run_id == vector_run_id)
            .expect("vector zero-limit telemetry row");
        assert!(text_run.result_ids.is_empty());
        assert!(vector_run.result_ids.is_empty());
        assert_eq!(text_run.empty_reason, None);
        assert_eq!(vector_run.empty_reason, None);
        Ok(())
    }

    #[test]
    fn retrieval_telemetry_records_no_hit_empty_reason() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let results = vault
            .query()
            .search_text("definitelymissing", 10)
            .run_with_telemetry()?;
        assert!(results.value.is_empty());
        let run_id = results.run_id.expect("no-hit telemetry run id");

        let runs = vault.retrieval_runs(1)?;
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, run_id);
        assert!(runs[0].result_ids.is_empty());
        assert_eq!(runs[0].empty_reason.as_deref(), Some("NoData"));
        Ok(())
    }

    #[test]
    fn retrieval_telemetry_zero_limit_pipeline_has_no_empty_reason() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = entity_id(0x3E);
        put_text_and_vector(
            &vault,
            id,
            "pipeline zero limit telemetry",
            [1.0, 0.0, 0.0, 0.0],
        )?;

        let results = vault
            .query()
            .search_text("pipeline zero limit", 0)
            .search_vector(&[1.0, 0.0, 0.0, 0.0], 0)
            .run_with_telemetry()?;
        assert!(results.value.is_empty());
        let run_id = results.run_id.expect("zero-limit telemetry run id");

        let runs = vault.retrieval_runs(1)?;
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, run_id);
        assert!(runs[0].result_ids.is_empty());
        assert_eq!(runs[0].empty_reason, None);
        Ok(())
    }

    #[test]
    fn retrieval_telemetry_omits_noop_ppr_and_phonetic_signals() -> Result<()> {
        let (_dir, vault) = open_test_vault();

        let phonetic = vault.query().search_phonetic(&[]).run_with_telemetry()?;
        assert!(phonetic.value.is_empty());
        let phonetic_run_id = phonetic.run_id.expect("phonetic noop telemetry run id");

        let ppr = vault.query().search_ppr(&[], 2).run_with_telemetry()?;
        assert!(ppr.value.is_empty());
        let ppr_run_id = ppr.run_id.expect("ppr noop telemetry run id");

        let combined_ppr = vault
            .query()
            .search_ppr(&[], 2)
            .expand_ppr(&[], 2)
            .run_with_telemetry()?;
        assert!(combined_ppr.value.is_empty());
        let combined_ppr_run_id = combined_ppr
            .run_id
            .expect("combined ppr noop telemetry run id");

        let runs = vault.retrieval_runs(10)?;
        let phonetic_run = runs
            .iter()
            .find(|run| run.run_id == phonetic_run_id)
            .expect("phonetic noop telemetry row");
        let ppr_run = runs
            .iter()
            .find(|run| run.run_id == ppr_run_id)
            .expect("ppr noop telemetry row");
        let combined_ppr_run = runs
            .iter()
            .find(|run| run.run_id == combined_ppr_run_id)
            .expect("combined ppr noop telemetry row");

        assert!(!phonetic_run.signals.contains(&RetrievalSignal::Phonetic));
        assert!(phonetic_run.score_breakdown.is_empty());
        assert!(!ppr_run.signals.contains(&RetrievalSignal::Ppr));
        assert!(ppr_run.score_breakdown.is_empty());
        assert!(!combined_ppr_run.signals.contains(&RetrievalSignal::Ppr));
        assert!(combined_ppr_run.score_breakdown.is_empty());
        Ok(())
    }

    #[test]
    fn retrieval_telemetry_omits_ppr_for_noop_expansion() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let dead = entity_id(0x3D);
        put_status_claim(
            &vault,
            dead,
            "noop ppr telemetry",
            crate::claim::ClaimApprovalStatus::Auto,
            crate::claim::ClaimLifecycleStatus::Retracted,
            false,
        )?;

        let results = vault
            .query()
            .search_text("noop ppr telemetry", 10)
            .expand_ppr(&[], 2)
            .run_with_telemetry()?;
        assert!(results.value.is_empty());
        let run_id = results.run_id.expect("noop ppr telemetry run id");

        let runs = vault.retrieval_runs(1)?;
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, run_id);
        assert_eq!(runs[0].signals, vec![RetrievalSignal::Text]);
        assert!(!runs[0].signals.contains(&RetrievalSignal::Ppr));
        assert_eq!(runs[0].claims_suppressed, 1);
        assert_eq!(runs[0].empty_reason.as_deref(), Some("AllActivated"));
        Ok(())
    }

    #[test]
    fn retrieval_runs_returns_bounded_newest_first() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let first_id = entity_id(0x38);
        let second_id = entity_id(0x39);
        let third_id = entity_id(0x3A);

        put_text(&vault, first_id, "alphaone")?;
        assert_eq!(vault.search_text("alphaone", 10)?.len(), 1);
        let first_run = vault.retrieval_runs(1)?[0].run_id;
        std::thread::sleep(std::time::Duration::from_millis(2));

        put_text(&vault, second_id, "betatwo")?;
        assert_eq!(vault.search_text("betatwo", 10)?.len(), 1);
        let second_run = vault.retrieval_runs(1)?[0].run_id;
        std::thread::sleep(std::time::Duration::from_millis(2));

        put_text(&vault, third_id, "gammathree")?;
        assert_eq!(vault.search_text("gammathree", 10)?.len(), 1);
        let third_run = vault.retrieval_runs(1)?[0].run_id;

        let newest_two = vault.retrieval_runs(2)?;
        assert_eq!(newest_two.len(), 2);
        assert_eq!(newest_two[0].run_id, third_run);
        assert_eq!(newest_two[1].run_id, second_run);
        assert!(!newest_two.iter().any(|run| run.run_id == first_run));
        assert!(vault.retrieval_runs(0)?.is_empty());
        Ok(())
    }

    #[test]
    fn telemetry_write_failure_is_best_effort_for_retrieval() -> Result<()> {
        let (dir, vault) = open_test_vault();
        let id = entity_id(0x3A);
        put_text(&vault, id, "best effort telemetry")?;
        let vault_path = dir.path().canonicalize()?;

        crate::store::test_hooks::fail_next_retrieval_run_write_for(vault_path.clone());
        let pipeline = vault.query().search_text("best effort", 10).run()?;
        assert_eq!(pipeline.len(), 1);
        assert!(vault.retrieval_runs(1)?.is_empty());

        crate::store::test_hooks::fail_next_retrieval_run_write_for(vault_path);
        let direct = vault.search_text("best effort", 10)?;
        assert_eq!(direct.len(), 1);
        assert!(vault.retrieval_runs(1)?.is_empty());
        Ok(())
    }

    #[test]
    fn retrieval_telemetry_skips_active_write_transaction() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = entity_id(0x3B);
        put_text(&vault, id, "active write telemetry")?;

        vault.with_write_txn(|_wtxn| {
            let direct = vault.search_text("active", 10)?;
            assert_eq!(direct.len(), 1);
            let pipeline = vault.query().search_text("active", 10).run()?;
            assert_eq!(pipeline.len(), 1);
            Ok(())
        })?;

        assert!(vault.retrieval_runs(10)?.is_empty());
        Ok(())
    }

    #[test]
    fn retrieval_telemetry_does_not_mutate_short_id_counters() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let id = entity_id(0x35);
        put_text(&vault, id, "counter telemetry")?;

        let counter_key = crate::store::short_id_counter_key(1);
        let before = {
            let rtxn = vault.store.env.read_txn()?;
            vault
                .store
                .vault_meta
                .get(&rtxn, &counter_key)?
                .map(<[u8]>::to_vec)
        };

        let results = vault.query().search_text("counter", 10).run()?;
        assert!(!results.is_empty());
        assert_eq!(vault.retrieval_runs(1)?.len(), 1);

        let after = {
            let rtxn = vault.store.env.read_txn()?;
            vault
                .store
                .vault_meta
                .get(&rtxn, &counter_key)?
                .map(<[u8]>::to_vec)
        };
        assert_eq!(before, after);
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
        assert_matches!(too_many_seeds, Err(Error::InvalidConfig(_)));

        let too_deep = vault.query().search_ppr(&[entity_id(1)], 11).run();
        assert_matches!(too_deep, Err(Error::InvalidConfig(_)));
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

    // ── ARCH-0039 facet filter (ONE-1117) ──────────────────────────

    use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
    use crate::types::{ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_TURN};

    /// The query vector every facet test searches with.
    const FACET_QUERY: [f32; 4] = [1.0, 0.0, 0.0, 0.0];

    /// LITERAL single-channel RRF fused scores for ranks 0–3 with the
    /// engine's pinned `RRF_K = 60`: `1 / (60 + rank + 1)`. Derived by hand,
    /// NOT read back from the code under test.
    const FACET_R0: f32 = 1.0 / 61.0;
    const FACET_R1: f32 = 1.0 / 62.0;
    const FACET_R2: f32 = 1.0 / 63.0;
    const FACET_R3: f32 = 1.0 / 64.0;

    struct FacetFixture {
        facet_a: EntityId,
        /// CLAIM, `FacetOf → facet_b`, vector rank 0.
        claim_other: EntityId,
        /// CLAIM, `FacetOf → facet_a`, vector rank 1.
        claim_active: EntityId,
        /// CLAIM, no `FacetOf` edge (core / unfaceted), vector rank 2.
        claim_core: EntityId,
        /// Non-claim (EVENT) carrying a `FacetOf → facet_b` edge, rank 3.
        event_faceted: EntityId,
    }

    fn facet_claim_body() -> Vec<u8> {
        let body = ClaimBody::new(
            "facet.scope_test",
            ClaimSubject::Entity(entity_id(0x7C)),
            rmpv::Value::from("v"),
            0.9,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        crate::claim::encode_claim_body(&body).expect("encode claim body")
    }

    fn put_claim_with_vector(vault: &Vault, id: EntityId, vector: [f32; 4]) -> Result<()> {
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: 1, end: 1 },
                1,
                &facet_claim_body(),
            )
            .vector(&id, &vector)
            .commit()
    }

    /// A vector-ranked CLAIM whose body carries an optional `world` scope
    /// (`None` = base reality). Built through the pinned claim encoder so the
    /// `world` key is the real 16-byte binary the read side groups by.
    fn put_claim_with_vector_world(
        vault: &Vault,
        id: EntityId,
        vector: [f32; 4],
        world: Option<EntityId>,
    ) -> Result<()> {
        let mut body = ClaimBody::new(
            "facet.scope_test",
            ClaimSubject::Entity(entity_id(0x7C)),
            rmpv::Value::from("v"),
            0.9,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.world = world;
        let encoded = crate::claim::encode_claim_body(&body).expect("encode claim body");
        vault
            .batch()
            .put(
                &id,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: 1, end: 1 },
                1,
                &encoded,
            )
            .vector(&id, &vector)
            .commit()
    }

    /// Two FACET entities + four vector-ranked candidates. Vector channel
    /// distances to [`FACET_QUERY`] are strictly increasing, so the fused
    /// baseline is exactly `[claim_other R0, claim_active R1, claim_core R2,
    /// event_faceted R3]`.
    fn setup_facet_fixture(vault: &Vault) -> Result<FacetFixture> {
        let facet_a = entity_id(0xA1);
        let facet_b = entity_id(0xB1);
        put_entity(vault, facet_a, ENTITY_TYPE_FACET, 1, 1, 1)?;
        put_entity(vault, facet_b, ENTITY_TYPE_FACET, 1, 1, 1)?;

        let fixture = FacetFixture {
            facet_a,
            claim_other: entity_id(0x21),
            claim_active: entity_id(0x22),
            claim_core: entity_id(0x23),
            event_faceted: entity_id(0x24),
        };

        put_claim_with_vector(vault, fixture.claim_other, [1.0, 0.0, 0.0, 0.0])?;
        put_claim_with_vector(vault, fixture.claim_active, [0.8, 0.6, 0.0, 0.0])?;
        put_claim_with_vector(vault, fixture.claim_core, [0.6, 0.8, 0.0, 0.0])?;
        vault
            .batch()
            .put(
                &fixture.event_faceted,
                ENTITY_TYPE_EVENT,
                TimeRange { start: 1, end: 1 },
                1,
                b"payload",
            )
            .vector(&fixture.event_faceted, &[0.0, 1.0, 0.0, 0.0])
            .commit()?;

        vault
            .batch()
            .edge(&fixture.claim_other, EdgeKind::FacetOf, &facet_b, 0.7)
            .edge(&fixture.claim_active, EdgeKind::FacetOf, &facet_a, 0.7)
            .edge(&fixture.event_faceted, EdgeKind::FacetOf, &facet_b, 0.7)
            .commit()?;

        Ok(fixture)
    }

    fn ordered_results(scores: &[ScoredEntity]) -> Vec<(EntityId, f32)> {
        scores.iter().map(|entry| (entry.id, entry.score)).collect()
    }

    /// AC 3 — *(no facet)* mode regression pin: a query that never calls
    /// `.facet()` returns every candidate, other-facet claims included,
    /// with the exact unfiltered/unboosted RRF scores in the exact
    /// pre-feature order. Any accidental default-on filtering or rescoring
    /// fails this literal pin.
    #[test]
    fn facet_absent_is_a_no_op_regression_pin() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let fixture = setup_facet_fixture(&vault)?;

        let results = vault.query().search_vector(&FACET_QUERY, 10).run()?;
        assert_eq!(
            ordered_results(&results),
            vec![
                (fixture.claim_other, FACET_R0),
                (fixture.claim_active, FACET_R1),
                (fixture.claim_core, FACET_R2),
                (fixture.event_faceted, FACET_R3),
            ],
            "no-facet mode must be identical to the pre-feature pipeline"
        );
        Ok(())
    }

    /// AC 1 — strict mode: the claim whose `FacetOf` edge targets a
    /// different facet is removed; the active-facet claim and the
    /// core/unfaceted claim pass with their scores UNTOUCHED (strict never
    /// boosts); the non-claim entity passes even though it carries a
    /// `FacetOf` edge to the other facet.
    #[test]
    fn facet_strict_removes_other_facet_claims_only() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let fixture = setup_facet_fixture(&vault)?;

        let results = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .facet(&fixture.facet_a, FacetMode::Strict)
            .run()?;
        assert_eq!(
            ordered_results(&results),
            vec![
                (fixture.claim_active, FACET_R1),
                (fixture.claim_core, FACET_R2),
                (fixture.event_faceted, FACET_R3),
            ],
            "strict must drop claim_other, keep core + active claims and \
             non-claim entities at unchanged scores"
        );
        Ok(())
    }

    /// AC 2 — prefer mode: nothing is removed; the active-facet claim's
    /// score is multiplied by the caller-supplied boost EXACTLY
    /// (`R1 * 3.0`), which reorders it above the baseline rank-0 entity;
    /// every other score is byte-identical to the baseline.
    #[test]
    fn facet_prefer_boosts_active_facet_with_exact_derived_values() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let fixture = setup_facet_fixture(&vault)?;

        let results = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .facet(&fixture.facet_a, FacetMode::Prefer { boost: 3.0 })
            .run()?;
        assert_eq!(
            ordered_results(&results),
            vec![
                (fixture.claim_active, FACET_R1 * 3.0),
                (fixture.claim_other, FACET_R0),
                (fixture.claim_core, FACET_R2),
                (fixture.event_faceted, FACET_R3),
            ],
            "prefer must keep all candidates, boost only the active-facet \
             claim, and reorder it by the exact derived score"
        );
        Ok(())
    }

    /// AC 4 — strict-excluded claims do not consume `result_limit` slots:
    /// with `limit(2)` and the top-ranked candidate excluded, BOTH
    /// remaining passing candidates fill the page. A filter applied after
    /// truncation would return a single result here.
    #[test]
    fn facet_strict_excluded_claims_free_result_limit_slots() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let fixture = setup_facet_fixture(&vault)?;

        let results = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .limit(2)
            .facet(&fixture.facet_a, FacetMode::Strict)
            .run()?;
        assert_eq!(
            ordered_results(&results),
            vec![
                (fixture.claim_active, FACET_R1),
                (fixture.claim_core, FACET_R2),
            ],
            "the excluded rank-0 claim must free its slot for claim_core"
        );
        Ok(())
    }

    /// AC 5 — a claim with no `FacetOf` edge surfaces under all three
    /// modes with the exact same (never boosted) score.
    #[test]
    fn facet_unfaceted_claim_passes_all_three_modes_unchanged() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let fixture = setup_facet_fixture(&vault)?;

        let no_facet = vault.query().search_vector(&FACET_QUERY, 10).run()?;
        let strict = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .facet(&fixture.facet_a, FacetMode::Strict)
            .run()?;
        let prefer = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .facet(&fixture.facet_a, FacetMode::Prefer { boost: 2.5 })
            .run()?;

        for (label, results) in [
            ("no facet", &no_facet),
            ("strict", &strict),
            ("prefer", &prefer),
        ] {
            let score = to_score_map(results)
                .get(&fixture.claim_core)
                .copied()
                .unwrap_or_else(|| panic!("unfaceted claim missing under {label} mode"));
            assert_eq!(
                score, FACET_R2,
                "unfaceted claim score must be exactly R2 under {label} mode"
            );
        }
        Ok(())
    }

    /// Multi-facet claims: a claim with `FacetOf` edges to BOTH facets is
    /// scoped to each of them — strict keeps it for either active facet,
    /// removes it for a third facet, and prefer boosts it exactly ONCE.
    #[test]
    fn facet_multi_scoped_claim_matches_any_of_its_facets() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let facet_a = entity_id(0xA1);
        let facet_b = entity_id(0xB1);
        let facet_c = entity_id(0xC1);
        put_entity(&vault, facet_a, ENTITY_TYPE_FACET, 1, 1, 1)?;
        put_entity(&vault, facet_b, ENTITY_TYPE_FACET, 1, 1, 1)?;
        put_entity(&vault, facet_c, ENTITY_TYPE_FACET, 1, 1, 1)?;

        let claim_multi = entity_id(0x31);
        put_claim_with_vector(&vault, claim_multi, [1.0, 0.0, 0.0, 0.0])?;
        vault
            .batch()
            .edge(&claim_multi, EdgeKind::FacetOf, &facet_a, 0.7)
            .edge(&claim_multi, EdgeKind::FacetOf, &facet_b, 0.7)
            .commit()?;

        for facet in [facet_a, facet_b] {
            let results = vault
                .query()
                .search_vector(&FACET_QUERY, 10)
                .facet(&facet, FacetMode::Strict)
                .run()?;
            assert_eq!(
                ordered_results(&results),
                vec![(claim_multi, FACET_R0)],
                "strict must keep a claim scoped to the active facet"
            );
        }

        let strict_c = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .facet(&facet_c, FacetMode::Strict)
            .run()?;
        assert!(
            strict_c.is_empty(),
            "strict must remove a claim scoped only to other facets, got {strict_c:?}"
        );

        // Two FacetOf edges, one matching: the boost applies exactly once.
        let prefer = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .facet(&facet_a, FacetMode::Prefer { boost: 2.0 })
            .run()?;
        assert_eq!(
            ordered_results(&prefer),
            vec![(claim_multi, FACET_R0 * 2.0)],
            "prefer must apply the boost exactly once per claim"
        );
        Ok(())
    }

    /// Only the `FacetOf` kind (u8 17) carries claim facet scope: a
    /// `HasFacet` (u8 16) edge neither scopes a claim (strict treats it as
    /// unfaceted) nor rescues one scoped elsewhere via `FacetOf`.
    #[test]
    fn facet_filter_reads_only_facet_of_edges() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let facet_a = entity_id(0xA1);
        let facet_b = entity_id(0xB1);
        put_entity(&vault, facet_a, ENTITY_TYPE_FACET, 1, 1, 1)?;
        put_entity(&vault, facet_b, ENTITY_TYPE_FACET, 1, 1, 1)?;

        // `HasFacet → facet_b` only: NOT facet scope — unfaceted.
        let claim_has_facet = entity_id(0x41);
        // `FacetOf → facet_b` + `HasFacet → facet_a`: scoped to facet_b;
        // the HasFacet edge to the active facet must not rescue it.
        let claim_scoped_b = entity_id(0x42);
        put_claim_with_vector(&vault, claim_has_facet, [1.0, 0.0, 0.0, 0.0])?;
        put_claim_with_vector(&vault, claim_scoped_b, [0.8, 0.6, 0.0, 0.0])?;
        vault
            .batch()
            .edge(&claim_has_facet, EdgeKind::HasFacet, &facet_b, 0.7)
            .edge(&claim_scoped_b, EdgeKind::FacetOf, &facet_b, 0.7)
            .edge(&claim_scoped_b, EdgeKind::HasFacet, &facet_a, 0.7)
            .commit()?;

        let strict = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .facet(&facet_a, FacetMode::Strict)
            .run()?;
        assert_eq!(
            ordered_results(&strict),
            vec![(claim_has_facet, FACET_R0)],
            "HasFacet must not scope a claim, and must not rescue a \
             FacetOf-scoped one"
        );

        let prefer = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .facet(&facet_b, FacetMode::Prefer { boost: 4.0 })
            .run()?;
        assert_eq!(
            ordered_results(&prefer),
            vec![
                (claim_scoped_b, FACET_R1 * 4.0),
                (claim_has_facet, FACET_R0),
            ],
            "prefer must boost via FacetOf only — a HasFacet edge to the \
             active facet earns no boost"
        );
        Ok(())
    }

    /// Non-claim entities are never boosted nor removed, whatever edges
    /// they carry — the filter discriminates on the type byte first.
    #[test]
    fn facet_filter_never_rescores_non_claim_entities() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let facet_a = entity_id(0xA1);
        put_entity(&vault, facet_a, ENTITY_TYPE_FACET, 1, 1, 1)?;

        let event_active = entity_id(0x51);
        vault
            .batch()
            .put(
                &event_active,
                ENTITY_TYPE_EVENT,
                TimeRange { start: 1, end: 1 },
                1,
                b"payload",
            )
            .vector(&event_active, &[1.0, 0.0, 0.0, 0.0])
            .edge(&event_active, EdgeKind::FacetOf, &facet_a, 0.7)
            .commit()?;

        for mode in [FacetMode::Strict, FacetMode::Prefer { boost: 5.0 }] {
            let results = vault
                .query()
                .search_vector(&FACET_QUERY, 10)
                .facet(&facet_a, mode)
                .run()?;
            assert_eq!(
                ordered_results(&results),
                vec![(event_active, FACET_R0)],
                "non-claim entity must pass unchanged under {mode:?}"
            );
        }
        Ok(())
    }

    /// Fail-closed: a non-finite or non-positive prefer boost is a typed
    /// [`Error::InvalidConfig`] from `run()`, never a silent skip or a
    /// poisoned score.
    #[test]
    fn facet_prefer_rejects_invalid_boost_typed() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let fixture = setup_facet_fixture(&vault)?;

        for bad_boost in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, 0.0, -1.0] {
            let err = vault
                .query()
                .search_vector(&FACET_QUERY, 10)
                .facet(&fixture.facet_a, FacetMode::Prefer { boost: bad_boost })
                .run()
                .expect_err("invalid prefer boost must be rejected");
            assert!(
                matches!(err, Error::InvalidConfig(_)),
                "expected InvalidConfig for boost {bad_boost}, got {err:?}"
            );
        }
        Ok(())
    }

    // ── D19 read-path claim status gate (ONE-1111) ─────────────────

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

    #[test]
    fn pipeline_reports_pending_vector_state_for_retrieved_claim() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let claim = entity_id(0x71);
        put_status_claim(
            &vault,
            claim,
            "pendingvectorneedle",
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
            false,
        )?;

        let pending = vault
            .query()
            .search_text("pendingvectorneedle", 10)
            .run_with_pending_vectors()?;
        assert!(
            pending.value.iter().any(|scored| scored.id == claim),
            "claim should be retrievable through text before embedding fill"
        );
        assert_eq!(pending.pending_vector_ids, vec![claim]);
        let token = pending
            .pending_vectors
            .iter()
            .find(|pending| pending.id == claim)
            .expect("pending marker token for claim")
            .token
            .clone();

        vault
            .batch()
            .vector_for_pending_embedding(&claim, &[1.0, 0.0, 0.0, 0.0], &token)
            .commit()?;

        let filled = vault
            .query()
            .search_text("pendingvectorneedle", 10)
            .run_with_pending_vectors()?;
        assert!(
            filled.value.iter().any(|scored| scored.id == claim),
            "claim should remain retrievable after embedding fill"
        );
        assert!(
            filled.pending_vector_ids.is_empty(),
            "embedding fill should clear pending vector state"
        );
        Ok(())
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

    /// Blocker 1 fail-closed: the active facet must resolve to an EXISTING
    /// FACET entity. A bogus id and a wrong-type (TURN) id both reject with
    /// the typed [`Error::InvalidFacet`] carrying what was actually found; a
    /// real FACET passes. A wrong impl that stores arbitrary facet bytes and
    /// strict-drops every scoped claim fails the wrong-type leg.
    #[test]
    fn facet_query_rejects_invalid_active_facet_typed() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let fixture = setup_facet_fixture(&vault)?;

        // Bogus id: no such entity → InvalidFacet { found: None }.
        let bogus = entity_id(0xEE);
        let err = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .facet(&bogus, FacetMode::Strict)
            .run()
            .expect_err("a bogus active facet must be rejected");
        assert!(
            matches!(err, Error::InvalidFacet { found: None, .. }),
            "expected InvalidFacet {{ found: None }}, got {err:?}"
        );

        // Wrong type: an existing TURN is not a FACET → found = Some(TURN).
        let turn = entity_id(0xDD);
        put_entity(&vault, turn, ENTITY_TYPE_TURN, 1, 1, 1)?;
        let err = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .facet(&turn, FacetMode::Strict)
            .run()
            .expect_err("a non-FACET active facet must be rejected");
        assert!(
            matches!(err, Error::InvalidFacet { found: Some(t), .. } if t == ENTITY_TYPE_TURN),
            "expected InvalidFacet {{ found: Some(TURN) }}, got {err:?}"
        );

        // A real FACET entity (the fixture's facet_a) passes.
        let ok = vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .facet(&fixture.facet_a, FacetMode::Strict)
            .run()?;
        assert!(!ok.is_empty(), "a valid FACET must not be rejected");
        Ok(())
    }

    /// Blocker 2 world filter visibility matrix: an absent-world (base) claim
    /// surfaces under ALL three scopes; a world=W claim surfaces under All and
    /// World(W) but NOT under Base nor World(V). Pins the exact membership a
    /// wrong (or absent) world filter would violate.
    #[test]
    fn world_scope_filter_visibility_matrix() -> Result<()> {
        let (_dir, vault) = open_test_vault();
        let world_w = entity_id(0xE1);
        let world_v = entity_id(0xE2);

        let claim_base = entity_id(0x61); // no `world` key — base reality
        let claim_w = entity_id(0x62); // `world` = W
        put_claim_with_vector_world(&vault, claim_base, [1.0, 0.0, 0.0, 0.0], None)?;
        put_claim_with_vector_world(&vault, claim_w, [0.8, 0.6, 0.0, 0.0], Some(world_w))?;

        let ids = |scores: &[ScoredEntity]| -> HashSet<EntityId> {
            scores.iter().map(|s| s.id).collect()
        };

        // All (default): both worlds span.
        let all = ids(&vault.query().search_vector(&FACET_QUERY, 10).run()?);
        assert!(
            all.contains(&claim_base) && all.contains(&claim_w),
            "All scope must span base + world claims, got {all:?}"
        );

        // Base: only the absent-world claim; the W-scoped claim is removed.
        let base = ids(&vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .world(WorldScope::Base)
            .run()?);
        assert!(
            base.contains(&claim_base),
            "base claim must surface in Base"
        );
        assert!(
            !base.contains(&claim_w),
            "W-scoped claim must NOT surface in Base"
        );

        // World(W): the W-scoped claim plus base claims.
        let in_w = ids(&vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .world(WorldScope::World(world_w))
            .run()?);
        assert!(
            in_w.contains(&claim_base) && in_w.contains(&claim_w),
            "World(W) must surface the W claim + base claim, got {in_w:?}"
        );

        // World(V): base claim only — the W claim belongs to another world.
        let in_v = ids(&vault
            .query()
            .search_vector(&FACET_QUERY, 10)
            .world(WorldScope::World(world_v))
            .run()?);
        assert!(
            in_v.contains(&claim_base),
            "base claim must surface in World(V)"
        );
        assert!(
            !in_v.contains(&claim_w),
            "W-scoped claim must NOT surface in World(V)"
        );
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
