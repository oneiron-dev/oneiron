use std::collections::{HashMap, HashSet};
use std::time::Instant;

use heed::RoTxn;
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::affect::coping::{
    COPING_OUTCOME_PREDICATE, CopingOutcomeRecord, decode_coping_outcome_claim,
    validate_coping_outcome_claim_structure,
};
use crate::analyzer::AnalyzerChannel;
use crate::batch::{
    ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, LONG_INTERVAL_THRESHOLD_SECS,
};
use crate::bm25::{Bm25Config, Bm25Formula};
use crate::claim::{ClaimBody, claim_surfaceable};
use crate::codebase::{CodebaseScopeKey, RepoRef, codebase_candidate_matches_scope_key};
use crate::context_pack::ContextPackRetrievalBudget;
use crate::context_pack::EmptyReason;
use crate::edge::{EDGE_KEY_LEN, EdgeKind};
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
use crate::fusion;
use crate::overlay_db::OverlayDb;
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT, ENTITY_TYPE_CLAIM,
    ENTITY_TYPE_CODE_ARTIFACT, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_COUNTERPARTY_CONTACT,
    ENTITY_TYPE_EVENT, ENTITY_TYPE_FACET, ENTITY_TYPE_FEDERATION_GRANT, ENTITY_TYPE_MACHINE,
    ENTITY_TYPE_MESSAGE, ENTITY_TYPE_MODEL, ENTITY_TYPE_NOTIFICATION, ENTITY_TYPE_ORG,
    ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_PERSON, ENTITY_TYPE_PLACE, ENTITY_TYPE_POLICY_MANIFEST,
    ENTITY_TYPE_PSYCH_PROFILE, ENTITY_TYPE_REDACTION_AUDIT, ENTITY_TYPE_RELATIONSHIP,
    ENTITY_TYPE_SESSION, ENTITY_TYPE_SKILL, ENTITY_TYPE_SUMMARY, ENTITY_TYPE_TASK,
    ENTITY_TYPE_TASK_LIST, ENTITY_TYPE_TURN, ENTITY_TYPE_WORLD,
};
use crate::rerank::{RerankCandidate, RerankOptions, Reranker};
use crate::store::{
    RetrievalAction, RetrievalBlendWeights, RetrievalRunId, RetrievalRunRecord,
    RetrievalScoreBreakdown, RetrievalScoreComponent, RetrievalSignal, RetrievalTrace,
    RetrievalTraceChannelRecord, RetrievalTraceStage, RetrievalTraceStageRecord, Store,
};
use crate::temporal::TemporalAnchorMode;
use crate::temporal::TemporalExpressionParseError;
use crate::temporal::TemporalGranularity;
use crate::temporal::TimeRange;
use crate::temporal::temporal_expression_from_query;

pub(crate) const DEFAULT_RESULT_LIMIT: usize = 20;
const DEFAULT_SIGMA_SECS: u64 = 86_400;
const MIN_WINDOW_RADIUS_SECS: u64 = 7 * 86_400;
const TEMPORAL_KEY_LEN: usize = 24;
const LONG_INTERVAL_VALUE_LEN: usize = 8;
const TEMPORAL_FLOOR: f64 = 0.05;

/// A scored entity result.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ScoredEntity {
    /// Entity identifier.
    pub id: EntityId,
    /// Ranking score.
    pub score: f32,
}

/// Retrieval signal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Signal {
    Vector,
    Text,
    Phonetic,
    Temporal,
    Ppr,
}

fn retrieval_blend_weights_for_scoring(
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
const SECONDS_PER_DAY_F64: f64 = 86_400.0;
const RETRIEVAL_TRACE_RRF_K: f32 = 60.0;

/// Default recency half-life in days (ARCH-0004 `RECENCY_DECAY`,
/// 28-day default). The recency signal's source timestamp is the
/// entity's `learned_at` (v1). This named constant is the engine
/// default for unlisted dynamic type bytes; the temporal pipeline's
/// recency decay constant (`RECENCY_DECAY_TAU_SECS = 28.0 * 86_400`,
/// the ARCH-0004 §4.5 table value) derives from it.
pub const DEFAULT_RECENCY_HALF_LIFE_DAYS: f32 = 28.0;

/// RET-010c recency half-life table, keyed by entity type byte. Values are
/// explicit contract rows, not derived from type defaults; unknown dynamic
/// type bytes fall back to [`DEFAULT_RECENCY_HALF_LIFE_DAYS`].
pub(crate) const RETRIEVAL_RECENCY_HALF_LIFE_DAYS_BY_TYPE: &[(u8, f32)] = &[
    (ENTITY_TYPE_CLAIM, 28.0),
    (ENTITY_TYPE_TURN, 28.0),
    (ENTITY_TYPE_SESSION, 28.0),
    (ENTITY_TYPE_MESSAGE, 28.0),
    (ENTITY_TYPE_PERSON, 365.0),
    (ENTITY_TYPE_RELATIONSHIP, 180.0),
    (ENTITY_TYPE_EVENT, 30.0),
    (ENTITY_TYPE_SKILL, 90.0),
    (ENTITY_TYPE_SUMMARY, 90.0),
    (ENTITY_TYPE_PLACE, 180.0),
    (ENTITY_TYPE_ASSET_TEXT, 90.0),
    (ENTITY_TYPE_CONVERSATION, 30.0),
    (ENTITY_TYPE_ORG, 180.0),
    (ENTITY_TYPE_FACET, 180.0),
    (ENTITY_TYPE_WORLD, 180.0),
    (ENTITY_TYPE_ASSET, 90.0),
    (ENTITY_TYPE_NOTIFICATION, 7.0),
    (ENTITY_TYPE_TASK_LIST, 30.0),
    (ENTITY_TYPE_TASK, 30.0),
    (ENTITY_TYPE_MACHINE, 180.0),
    (ENTITY_TYPE_CODE_ARTIFACT, 90.0),
    (ENTITY_TYPE_REDACTION_AUDIT, 365.0),
    (ENTITY_TYPE_MODEL, 180.0),
    (ENTITY_TYPE_POLICY_MANIFEST, 365.0),
    (ENTITY_TYPE_FEDERATION_GRANT, 365.0),
    (ENTITY_TYPE_ACCESS_GRANT, 365.0),
    (ENTITY_TYPE_COUNTERPARTY_CONTACT, 365.0),
    (ENTITY_TYPE_OUTBOUND_GRANT, 365.0),
    (ENTITY_TYPE_PSYCH_PROFILE, 365.0),
];

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
const COSINE_GHOST_VECTOR_THRESHOLD: f32 = 0.3;
// RET-01 only gates context-pack assembly. These are deliberately
// conservative: the vector floor needs an absent keyword signal too, while
// the score-gap check only compares raw cosine scores from the same channel.
const CONTEXT_PACK_MIN_VECTOR_SIMILARITY: f32 = 0.3;
const CONTEXT_PACK_MEDIOCRE_VECTOR_SIMILARITY: f32 = 0.5;
const CONTEXT_PACK_MIN_VECTOR_SCORE_GAP_RATIO: f32 = 0.1;
const CONTEXT_PACK_SCORE_GAP_EPSILON: f32 = f32::EPSILON;
const CONTEXT_PACK_ANOMALOUS_REPEAT_RUN: usize = 32;

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
    off_record_fences_present: bool,
}

#[derive(Debug, Clone, Copy)]
struct TemporalIndexCollectionContext {
    window_start: u64,
    window_end: u64,
    anchor_mid: u64,
    cap: usize,
    off_record_fences_present: bool,
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
    facet_filter: Option<(EntityId, FacetMode)>,
    world_scope: WorldScope,
    off_record_fences_present: bool,
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
    pub(crate) signals: Vec<RetrievalSignal>,
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
/// and are treated as base for the `Base` / `World` scopes. `WorldSet` is the
/// repo-world scope key: it keeps only entities explicitly indexed as members
/// of that codebase scope.
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
    /// Entities explicitly indexed under this codebase scope key. This is the
    /// repository-backed world-set clamp and does not include base reality by
    /// default.
    WorldSet(CodebaseScopeKey),
}

/// Opaque Dreamer working-set cursor.
///
/// The cursor is an offset into the caller's bounded working set. It is not a
/// vault snapshot handle and cannot be used to request the whole vault.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DreamerWorkingSetCursor {
    offset: usize,
}

impl DreamerWorkingSetCursor {
    #[must_use]
    pub const fn start() -> Self {
        Self { offset: 0 }
    }

    #[must_use]
    pub const fn from_offset(offset: usize) -> Self {
        Self { offset }
    }

    #[must_use]
    pub const fn offset(self) -> usize {
        self.offset
    }
}

/// Hard cap for one Dreamer ingress working set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DreamerWorkingSetBudget {
    max_items: usize,
}

impl DreamerWorkingSetBudget {
    #[must_use]
    pub const fn new(max_items: usize) -> Self {
        Self { max_items }
    }

    #[must_use]
    pub const fn max_items(self) -> usize {
        self.max_items
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DreamerWorkingSetStopReason {
    BudgetExhausted,
    EndOfWorkingSet,
}

/// Budget-capped page of retrieval candidates for Dreamer ingress.
#[derive(Debug, Clone)]
pub struct DreamerWorkingSet {
    pub cursor: DreamerWorkingSetCursor,
    pub next_cursor: Option<DreamerWorkingSetCursor>,
    pub budget: DreamerWorkingSetBudget,
    pub rows: Vec<ScoredEntity>,
    pub stop_reason: Option<DreamerWorkingSetStopReason>,
    pub telemetry_run_id: Option<RetrievalRunId>,
}

/// A claim's facet scope relative to the query's active facet, derived from
/// its outgoing `FacetOf` (`CLAIM → FACET`, u8 17) adjacency.
///
/// CLAIM-sourced adjacency only — this is the local query door. The write
/// table also admits `TURN | EVENT → FACET`, and those stamps carry disclosure
/// weight on the federation selector door even though they never reach this
/// enum (see [`crate::batch::validate_facet_of_edge`]).
enum ClaimFacetScope {
    /// No `FacetOf` edge — a relevance-neutral claim. Passes every mode.
    ///
    /// NOT invariant evidence: absence of a facet stamp never widens
    /// disclosure (ONE-1645, P3/V2). The disclosure conjunct (ONE-1646) must
    /// derive invariant admission from POSITIVE evidence only — a stored
    /// public stamp or a promotion record — never from this variant. The
    /// live disclosure floor for unstamped provenance is
    /// `claim_sensitivity_band`, which reads band 2 on a missing stamp.
    Unfaceted,
    /// At least one `FacetOf` edge targets the active facet.
    ActiveFacet,
    /// Has `FacetOf` edges, none targeting the active facet.
    OtherFacetsOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextPackBudgetKind {
    Claim,
    Turn,
    Summary,
    Facet,
    Other,
}

#[derive(Debug, Clone, Copy, Default)]
struct ContextPackBudgetCounts {
    claims: usize,
    turns: usize,
    summaries: usize,
    facets: usize,
    other: usize,
}

impl ContextPackBudgetKind {
    fn from_entity_type(entity_type: u8) -> Self {
        match entity_type {
            ENTITY_TYPE_CLAIM => Self::Claim,
            ENTITY_TYPE_TURN => Self::Turn,
            ENTITY_TYPE_SUMMARY => Self::Summary,
            ENTITY_TYPE_FACET => Self::Facet,
            _ => Self::Other,
        }
    }
}

impl ContextPackBudgetCounts {
    fn from_budget(budget: ContextPackRetrievalBudget) -> Self {
        Self {
            claims: budget.claims,
            turns: budget.turns,
            summaries: budget.summaries,
            facets: budget.facets,
            other: budget.other,
        }
    }

    fn get(self, kind: ContextPackBudgetKind) -> usize {
        match kind {
            ContextPackBudgetKind::Claim => self.claims,
            ContextPackBudgetKind::Turn => self.turns,
            ContextPackBudgetKind::Summary => self.summaries,
            ContextPackBudgetKind::Facet => self.facets,
            ContextPackBudgetKind::Other => self.other,
        }
    }

    fn add(&mut self, kind: ContextPackBudgetKind, amount: usize) {
        let slot = match kind {
            ContextPackBudgetKind::Claim => &mut self.claims,
            ContextPackBudgetKind::Turn => &mut self.turns,
            ContextPackBudgetKind::Summary => &mut self.summaries,
            ContextPackBudgetKind::Facet => &mut self.facets,
            ContextPackBudgetKind::Other => &mut self.other,
        };
        *slot = slot.saturating_add(amount);
    }

    fn increment(&mut self, kind: ContextPackBudgetKind) {
        self.add(kind, 1);
    }
}

#[must_use = "PipelineBuilder executes no query until a terminal `.run*()` method is called"]
pub struct PipelineBuilder<'a> {
    vault: &'a Vault,
    vector_search: Option<(Vec<f32>, usize)>,
    text_search: Option<(String, usize)>,
    rank_profile: Option<crate::config::Bm25RankProfile>,
    phonetic_search: Option<Vec<String>>,
    temporal_search: Option<TemporalSearchConfig>,
    ppr_search: Option<(Vec<EntityId>, u32)>,
    ppr_expand: Option<(Vec<EntityId>, u32)>,
    recency_blend_enabled: bool,
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
    context_pack_budget: Option<ContextPackRetrievalBudget>,
    result_limit: usize,
    temporal_adaptive_default: bool,
    temporal_now: Option<u64>,
    telemetry_action: RetrievalAction,
    capture_retrieval_trace: bool,
    rerank: Option<(&'a dyn Reranker, RerankOptions)>,
    skip_vector_rescore: bool,
    /// Additive session routing (ONE-1728 K10). `None` on every canonical
    /// entry, which is therefore behaviorally unchanged; the session
    /// retrieval entries pass their composed view so the retrieval-run
    /// registration writes into the room's overlay `VaultMeta` instead of the
    /// base ledger. Retrieval SCORING is untouched by this field.
    session_view: Option<&'a crate::store::SessionStoreView<'a>>,
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
            recency_blend_enabled: false,
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
            context_pack_budget: None,
            result_limit: DEFAULT_RESULT_LIMIT,
            temporal_adaptive_default: true,
            temporal_now: None,
            telemetry_action: RetrievalAction::Pipeline,
            capture_retrieval_trace: false,
            rerank: None,
            skip_vector_rescore: false,
            session_view: None,
        }
    }

    /// Routes this run's retrieval-run registration into a live session's
    /// overlay (ONE-1728 K10). Additive: retrieval scoring, filters, and
    /// every base reader stay exactly as they were.
    #[allow(
        dead_code,
        reason = "the registration site routes on this field today; its builder caller arrives \
                  with ONE-1729's session context-pack runs (P4a pins the routing, not the entry)"
    )]
    pub(crate) fn in_session(mut self, view: &'a crate::store::SessionStoreView<'a>) -> Self {
        self.session_view = Some(view);
        self
    }

    pub(crate) fn telemetry_action(mut self, action: RetrievalAction) -> Self {
        self.telemetry_action = action;
        self
    }

    pub(crate) fn result_limit(&self) -> usize {
        self.result_limit
    }

    pub(crate) fn context_pack_budget(mut self, budget: ContextPackRetrievalBudget) -> Self {
        self.context_pack_budget = Some(budget);
        self
    }

    /// Enables opt-in per-stage retrieval trace capture for this run.
    pub fn capture_retrieval_trace(mut self, enabled: bool) -> Self {
        self.capture_retrieval_trace = enabled;
        self
    }

    /// Attaches a host-injected top-N reranker for this run (RET-010,
    /// 1186-D2). Presence IS the feature flag: no reranker attached means
    /// rerank is off and the pipeline behaves exactly as before. The block
    /// size is `options.top_n`; the pipeline never overfetches on rerank's
    /// behalf — the reranker only sees more than `result_limit` candidates
    /// when the caller's per-channel limits exceed `result_limit`.
    pub fn rerank(mut self, reranker: &'a dyn Reranker, options: RerankOptions) -> Self {
        self.rerank = Some((reranker, options));
        self
    }

    pub fn search_vector(mut self, vector: &[f32], limit: usize) -> Self {
        self.vector_search = Some((vector.to_vec(), limit));
        self
    }

    /// Voice-hot-lane knob (ONE-EMBED E3): score the vector channel on the
    /// `fast_dims` prefix only, skipping the exact full-dim rescore. Inert
    /// when `fast_dims` is not configured.
    pub fn skip_vector_rescore(mut self, skip: bool) -> Self {
        self.skip_vector_rescore = skip;
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
    pub fn rank_profile(mut self, profile: crate::config::Bm25RankProfile) -> Self {
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

    /// Overrides the clock used to resolve natural-language temporal query
    /// hints and time-dependent retrieval scoring. Production callers normally
    /// use the default wall clock; tests and replay fixtures can inject a
    /// frozen Unix timestamp.
    pub fn with_temporal_now(mut self, now: u64) -> Self {
        self.temporal_now = Some(now);
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
            self = self
                .search_temporal(range.start, range.end, limit)
                .filter_occurred_range(range.start, range.end);
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

    /// Enables the recency signal for the retrieval blend.
    ///
    /// `half_life_days` is retained as a compatibility toggle: finite
    /// positive values enable recency, but the actual decay half-life comes
    /// from the per-entity-type RET-010c contract table.
    pub fn boost_recency(mut self, half_life_days: f32) -> Self {
        self.recency_blend_enabled = half_life_days.is_finite() && half_life_days > 0.0;
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

    pub fn prior_successful_coping_strategies(
        self,
        affected_person: &EntityId,
        limit: usize,
    ) -> Result<Vec<CopingOutcomeRecord>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut records = Vec::new();
        for claim_id in self.vault.claims_for_subject(affected_person)? {
            let Some(body) = self.vault.get_claim(&claim_id)? else {
                continue;
            };
            if body.predicate != COPING_OUTCOME_PREDICATE || !claim_surfaceable(&body) {
                continue;
            }
            validate_coping_outcome_claim_structure(&body)?;
            let Some(value) = decode_coping_outcome_claim(&body)? else {
                continue;
            };
            if !value.successful() {
                continue;
            }
            records.push(CopingOutcomeRecord {
                claim_id,
                learned_at: self.vault.get_learned_at(&claim_id)?,
                valid_from: body.valid_from.ok_or(Error::InvalidClaimBody(
                    "coping.outcome valid_from is required",
                ))?,
                valid_to: body.valid_to,
                value,
            });
        }
        records.sort_by(|a, b| {
            b.learned_at
                .cmp(&a.learned_at)
                .then_with(|| b.claim_id.as_bytes().cmp(a.claim_id.as_bytes()))
        });
        records.truncate(limit);
        Ok(records)
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
        #[cfg(feature = "sync")]
        let vault = self.vault;
        // K6: the enqueue arm is BASE-ONLY. A session surfacing returns its
        // pending vectors to the caller for inline handling and never writes
        // a `pe:` marker or an embed job row — there is no overlay `pe:`
        // keyspace, so redirecting is not an option and skipping is the rule.
        #[cfg(feature = "sync")]
        let enqueue = self.session_view.is_none();
        let output = self.run_for_pack()?;
        let pending_vector_ids = pending_vector_ids(&output.pending_vectors);
        #[cfg(feature = "sync")]
        if enqueue {
            crate::embed::enqueue_pending_embedding_jobs(
                vault,
                &pending_vector_ids,
                crate::embed::EMBED_PRIORITY_SURFACED_HOT,
            )?;
        }
        Ok(RetrievalWithPendingVectors {
            value: output.scores,
            pending_vector_ids,
            pending_vectors: output.pending_vectors,
            run_id: output.telemetry_run_id,
        })
    }

    pub fn run_dreamer_working_set(
        mut self,
        cursor: DreamerWorkingSetCursor,
        budget: DreamerWorkingSetBudget,
        page_limit: usize,
    ) -> Result<DreamerWorkingSet> {
        if page_limit == 0 {
            return Err(Error::InvalidConfig(
                "dreamer working-set page_limit must be greater than zero".to_owned(),
            ));
        }

        let remaining = budget.max_items().saturating_sub(cursor.offset());
        if remaining == 0 {
            return Ok(DreamerWorkingSet {
                cursor,
                next_cursor: None,
                budget,
                rows: Vec::new(),
                stop_reason: Some(DreamerWorkingSetStopReason::BudgetExhausted),
                telemetry_run_id: None,
            });
        }

        let ingress_limit = page_limit.min(remaining);
        let page_end = cursor.offset().saturating_add(ingress_limit);
        let lookahead = usize::from(page_end < budget.max_items());
        let fetch_limit = page_end.saturating_add(lookahead);
        self.result_limit = fetch_limit;

        let output = self.run_for_pack()?;
        let loaded = output.scores.len();
        let rows: Vec<_> = output
            .scores
            .into_iter()
            .skip(cursor.offset())
            .take(ingress_limit)
            .collect();
        let next_offset = cursor.offset().saturating_add(rows.len());
        let budget_exhausted = next_offset >= budget.max_items();
        let stop_reason = if budget_exhausted {
            Some(DreamerWorkingSetStopReason::BudgetExhausted)
        } else if loaded <= next_offset {
            Some(DreamerWorkingSetStopReason::EndOfWorkingSet)
        } else {
            None
        };
        let next_cursor = stop_reason
            .is_none()
            .then(|| DreamerWorkingSetCursor::from_offset(next_offset));

        Ok(DreamerWorkingSet {
            cursor,
            next_cursor,
            budget,
            rows,
            stop_reason,
            telemetry_run_id: output.telemetry_run_id,
        })
    }

    /// Executes the pipeline and returns the detailed [`PipelineOutput`]
    /// the context-pack path consumes (gated scores + the claim bodies the
    /// D19 gate already decoded + the suppression count).
    #[expect(clippy::too_many_lines)]
    pub(crate) fn run_for_pack(self) -> Result<PipelineOutput> {
        let started = Instant::now();
        let started_at = crate::unix_seconds_now();
        let temporal_now = self.temporal_now.unwrap_or(started_at);
        let occurred_range = self.resolved_occurred_range(temporal_now)?;
        let telemetry_action = self.telemetry_action;
        let mut telemetry_signals = self.telemetry_signals();
        if occurred_range.is_some() && !telemetry_signals.contains(&RetrievalSignal::Temporal) {
            telemetry_signals.push(RetrievalSignal::Temporal);
        }
        let no_data_fallback_eligible = self.no_data_fallback_eligible();
        let mut ppr_expand_executed = false;
        let capture_retrieval_trace = self.capture_retrieval_trace;
        let trace_candidate_limit = self.result_limit;

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

        // RET-010 rerank knobs fail closed before any channel work, in the
        // same spirit as the rank profile above: an invalid `top_n` or a
        // missing query is a caller bug even when the block would be empty
        // on this run.
        let rerank_query = match self.rerank.as_ref() {
            None => None,
            Some((_, options)) => {
                if options.top_n == 0 {
                    return Err(Error::InvalidConfig(
                        "rerank top_n must be greater than zero".to_owned(),
                    ));
                }
                let query = options
                    .query
                    .as_deref()
                    .or_else(|| self.text_search.as_ref().map(|(query, _)| query.as_str()));
                let Some(query) = query else {
                    return Err(Error::InvalidConfig(
                        "rerank requires a query: set RerankOptions::query or search_text"
                            .to_owned(),
                    ));
                };
                Some(query.to_owned())
            }
        };

        if self.text_search.is_some() {
            self.vault.ensure_text_index_trusted()?;
        }

        let recency = if self.temporal_search.is_none() && self.recency_blend_enabled {
            Some(temporal_now)
        } else {
            None
        };
        let explicit_time_dependent_now = (recency.is_some() || self.temporal_search.is_some())
            .then_some(self.temporal_now)
            .flatten();

        let (
            scores,
            pending_vectors,
            claim_gate,
            deferred_ppr_cache_writes,
            cosine_ghosts_dampened,
            total_in_scope,
            empty_reason,
            signal_components,
            blend_components,
            rerank_merged_components,
            retrieval_trace,
        ) = {
            let mut ranked_lists = Vec::new();
            let mut signal_components = HashMap::<EntityId, Vec<RetrievalScoreComponent>>::new();
            let mut trace_channels = Vec::<RetrievalTraceChannelRecord>::new();
            let mut trace_ranked_lists = Vec::<Vec<ScoredEntity>>::new();
            let mut trace_claim_gate = ClaimStatusGateCache::default();
            let mut fused_trace_scores = None;
            let mut blended_trace_scores = None;
            let mut vector_channel_index = None;
            let mut text_channel_index = None;
            let rtxn = self.vault.store.env.read_txn()?;
            let blend_weights = retrieval_blend_weights_for_scoring(&self.vault.store, &rtxn)?;
            let mut metadata_cache = EntityMetadataCache::default();
            let mut claim_gate = ClaimStatusGateCache::default();
            let mut deferred_ppr_cache_writes = Vec::new();
            let codebase_scope_active = self.has_codebase_scope_filter();
            let off_record_fences_present =
                crate::off_record::off_record_fences_present(&self.vault.store, &rtxn)?;
            let filter_config = PipelineFilterConfig {
                type_filter: self.type_filter.as_deref(),
                since_filter: self.since_filter,
                occurred_range,
                learned_range: self.learned_range,
                repo_ref_filter: self.repo_ref_filter.as_ref(),
                project_id_filter: self.project_id_filter.as_deref(),
                facet_filter: self.facet_filter,
                world_scope: self.world_scope,
                off_record_fences_present,
            };
            // D19 is always active. For final-token prefix queries, a dead
            // claim can outrank a live prefix hit in BM25, then be removed
            // after fusion; overfetch prevents that dead hit from consuming
            // the only text-channel slot. Live exact claims already satisfy
            // the D19 gate, so they must not widen ordinary
            // `search_text(..., limit)` calls.
            let mut claim_gate_widening_probe = ClaimStatusGateCache::default();
            let claim_gate_text_widening_active = if let Some((query, limit)) = &self.text_search
                && *limit > 0
            {
                let exact_posting_fails_claim_gate = {
                    let mut exact_posting_fails_claim_gate = |id: &EntityId| {
                        claim_status_gate_allows(
                            &self.vault.store,
                            &rtxn,
                            id,
                            &mut metadata_cache,
                            &mut claim_gate_widening_probe,
                        )
                        .map(|allowed| !allowed)
                    };
                    crate::bm25::final_token_exact_posting_matches(
                        &self.vault.store,
                        &rtxn,
                        &self.vault.analyzer,
                        &bm25_config,
                        query,
                        &mut exact_posting_fails_claim_gate,
                    )?
                };
                if exact_posting_fails_claim_gate {
                    true
                } else {
                    let mut classify_prefix_posting = |id: &EntityId| {
                        let rejected_by_gate = !claim_status_gate_allows(
                            &self.vault.store,
                            &rtxn,
                            id,
                            &mut metadata_cache,
                            &mut claim_gate_widening_probe,
                        )?;
                        let matches_scope = !rejected_by_gate
                            && pipeline_candidate_matches_filters_and_gate(
                                &self.vault.store,
                                &rtxn,
                                id,
                                filter_config,
                                &mut metadata_cache,
                                &mut claim_gate_widening_probe,
                            )?;
                        Ok(crate::bm25::PrefixExpansionPostingDecision {
                            matches_scope,
                            rejected_by_gate,
                        })
                    };
                    crate::bm25::final_token_prefix_expansion_has_scoped_and_rejected_postings(
                        &self.vault.store,
                        &rtxn,
                        &self.vault.analyzer,
                        &bm25_config,
                        query,
                        &mut classify_prefix_posting,
                    )?
                }
            } else {
                false
            };
            let text_scope_widening_active = codebase_scope_active
                || self.has_strict_text_scope_filter()
                || occurred_range.is_some()
                || claim_gate_text_widening_active;

            if let Some((query_vector, limit)) = &self.vector_search {
                // EMB-2: a `fast_dims`-length query is a first-class prefix
                // query on the funnel read path.
                if query_vector.len() != self.vault.config.dimensions
                    && self.vault.config.fast_dims.map(usize::from) != Some(query_vector.len())
                {
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
                let mut vector_results = crate::hnsw::hnsw_search(
                    &self.vault.store,
                    &self.vault.config,
                    &rtxn,
                    query_vector,
                    channel_limit,
                    self.skip_vector_rescore,
                )?;
                // OFRC-2iii: preserve the fence-free channel path; widen
                // only when a returned row would otherwise consume a slot.
                let mut vector_probe_claim_gate = ClaimStatusGateCache::default();
                if off_record_fences_present
                    && contains_off_record_fence(&vector_results, &self.vault.store, &rtxn)?
                {
                    if channel_limit > *limit {
                        apply_off_record_fence(&mut vector_results, &self.vault.store, &rtxn)?;
                    } else {
                        let entity_count =
                            crate::hnsw::hnsw_entity_count(&self.vault.store, &rtxn)?;
                        let mut search_limit = channel_limit;
                        loop {
                            let mut filtered_results = vector_results;
                            let mut filtered_claim_gate = ClaimStatusGateCache::default();
                            truncate_vector_fence_replacements(
                                &mut filtered_results,
                                &self.vault.store,
                                &rtxn,
                                *limit,
                                &mut metadata_cache,
                                &mut filtered_claim_gate,
                            )?;
                            if filtered_results.len() >= *limit || search_limit >= entity_count {
                                vector_results = filtered_results;
                                vector_probe_claim_gate = filtered_claim_gate;
                                break;
                            }

                            let next_limit = next_vector_fence_search_limit(
                                search_limit,
                                filtered_results.len(),
                                *limit,
                                entity_count,
                            );
                            if next_limit == search_limit {
                                vector_results = filtered_results;
                                vector_probe_claim_gate = filtered_claim_gate;
                                break;
                            }
                            search_limit = next_limit;
                            vector_results = crate::hnsw::hnsw_search(
                                &self.vault.store,
                                &self.vault.config,
                                &rtxn,
                                query_vector,
                                search_limit,
                                self.skip_vector_rescore,
                            )?;
                        }
                    }
                }
                import_claim_gate_decisions_for_scores(
                    &mut claim_gate,
                    &mut vector_probe_claim_gate,
                    &vector_results,
                );
                add_signal_score_components(
                    &mut signal_components,
                    RetrievalSignal::Vector,
                    &vector_results,
                );
                if capture_retrieval_trace {
                    let trace_results = filter_retrieval_trace_scores(
                        &vector_results,
                        &self.vault.store,
                        &rtxn,
                        filter_config,
                        &mut metadata_cache,
                        &mut trace_claim_gate,
                        trace_candidate_limit,
                    )?;
                    trace_channels.push(retrieval_trace_channel_record(
                        RetrievalSignal::Vector,
                        &trace_results,
                        trace_candidate_limit,
                    ));
                    trace_ranked_lists.push(trace_results);
                }
                vector_channel_index = Some(ranked_lists.len());
                ranked_lists.push(vector_results);
            }

            if let Some((query, limit)) = &self.text_search {
                let scoped_text_limit = scoped_text_channel_limit(
                    &self.vault.store,
                    &rtxn,
                    *limit,
                    text_scope_widening_active,
                )?;
                let text_channel_limit = if recency.is_some() {
                    scoped_text_limit.max(limit.saturating_mul(PER_SCAN_CAP_FACTOR))
                } else {
                    scoped_text_limit
                };
                let mut prefix_probe_claim_gate = claim_gate_widening_probe;
                let mut exact_posting_matches_scope = |id: &EntityId| {
                    pipeline_candidate_matches_filters_and_gate(
                        &self.vault.store,
                        &rtxn,
                        id,
                        filter_config,
                        &mut metadata_cache,
                        &mut prefix_probe_claim_gate,
                    )
                };
                let mut text_results = crate::bm25::search_text_scoped_with_recency(
                    &self.vault.store,
                    &rtxn,
                    &self.vault.analyzer,
                    &bm25_config,
                    query,
                    text_channel_limit,
                    crate::bm25::Bm25SearchOptions {
                        recency: None,
                        exact_posting_matches_scope: &mut exact_posting_matches_scope,
                    },
                )?;
                // OFRC-2iii: the D19 widening path below already fences
                // before truncation. For an otherwise exact text limit,
                // widen only after a fenced hit is observed.
                if text_channel_limit > *limit && text_scope_widening_active {
                    let scoped_result_limit = if recency.is_some() {
                        limit.saturating_mul(PER_SCAN_CAP_FACTOR)
                    } else {
                        *limit
                    };
                    truncate_widened_channel_results_to_scope(
                        &mut text_results,
                        &self.vault.store,
                        &rtxn,
                        scoped_result_limit,
                        filter_config,
                        &mut metadata_cache,
                        &mut prefix_probe_claim_gate,
                    )?;
                } else if off_record_fences_present
                    && contains_off_record_fence(&text_results, &self.vault.store, &rtxn)?
                {
                    let restore_text_limit = text_channel_limit == *limit;
                    let widened_limit =
                        scoped_text_channel_limit(&self.vault.store, &rtxn, *limit, true)?;
                    if widened_limit > text_channel_limit {
                        text_results = crate::bm25::search_text_scoped_with_recency(
                            &self.vault.store,
                            &rtxn,
                            &self.vault.analyzer,
                            &bm25_config,
                            query,
                            widened_limit,
                            crate::bm25::Bm25SearchOptions {
                                recency: None,
                                exact_posting_matches_scope: &mut exact_posting_matches_scope,
                            },
                        )?;
                    }
                    if restore_text_limit {
                        truncate_widened_channel_results_to_scope(
                            &mut text_results,
                            &self.vault.store,
                            &rtxn,
                            *limit,
                            filter_config,
                            &mut metadata_cache,
                            &mut prefix_probe_claim_gate,
                        )?;
                    } else {
                        apply_off_record_fence_with_cap(
                            &mut text_results,
                            &self.vault.store,
                            &rtxn,
                            text_channel_limit,
                        )?;
                    }
                }
                import_claim_gate_decisions_for_scores(
                    &mut claim_gate,
                    &mut prefix_probe_claim_gate,
                    &text_results,
                );
                add_signal_score_components(
                    &mut signal_components,
                    RetrievalSignal::Text,
                    &text_results,
                );
                if capture_retrieval_trace {
                    let trace_results = filter_retrieval_trace_scores(
                        &text_results,
                        &self.vault.store,
                        &rtxn,
                        filter_config,
                        &mut metadata_cache,
                        &mut trace_claim_gate,
                        trace_candidate_limit,
                    )?;
                    trace_channels.push(retrieval_trace_channel_record(
                        RetrievalSignal::Text,
                        &trace_results,
                        trace_candidate_limit,
                    ));
                    trace_ranked_lists.push(trace_results);
                }
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
                if capture_retrieval_trace {
                    let trace_results = filter_retrieval_trace_scores(
                        &phonetic_results,
                        &self.vault.store,
                        &rtxn,
                        filter_config,
                        &mut metadata_cache,
                        &mut trace_claim_gate,
                        trace_candidate_limit,
                    )?;
                    trace_channels.push(retrieval_trace_channel_record(
                        RetrievalSignal::Phonetic,
                        &trace_results,
                        trace_candidate_limit,
                    ));
                    trace_ranked_lists.push(trace_results);
                }
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
                    off_record_fences_present,
                    temporal_now,
                    &mut metadata_cache,
                )?;
                add_signal_score_components(
                    &mut signal_components,
                    RetrievalSignal::Temporal,
                    &temporal_results,
                );
                if capture_retrieval_trace {
                    let trace_results = filter_retrieval_trace_scores(
                        &temporal_results,
                        &self.vault.store,
                        &rtxn,
                        filter_config,
                        &mut metadata_cache,
                        &mut trace_claim_gate,
                        trace_candidate_limit,
                    )?;
                    trace_channels.push(retrieval_trace_channel_record(
                        RetrievalSignal::Temporal,
                        &trace_results,
                        trace_candidate_limit,
                    ));
                    trace_ranked_lists.push(trace_results);
                }
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
                if capture_retrieval_trace {
                    let trace_results = filter_retrieval_trace_scores(
                        &ppr_results,
                        &self.vault.store,
                        &rtxn,
                        filter_config,
                        &mut metadata_cache,
                        &mut trace_claim_gate,
                        trace_candidate_limit,
                    )?;
                    trace_channels.push(retrieval_trace_channel_record(
                        RetrievalSignal::Ppr,
                        &trace_results,
                        trace_candidate_limit,
                    ));
                    trace_ranked_lists.push(trace_results);
                }
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
                    signals: telemetry_signals,
                });
            }

            let blend_config = RetrievalBlendConfig {
                recency_now_secs: recency,
                salience: self.apply_salience,
                confidence: self.apply_confidence,
                gravity: self.apply_gravity,
            };
            if capture_retrieval_trace {
                fused_trace_scores = Some(retrieval_trace_fused_scores(
                    &trace_ranked_lists,
                    trace_candidate_limit,
                ));
            }
            let first_blend = blended_retrieval_scores(
                &ranked_lists,
                RetrievalChannelIndexes {
                    vector: vector_channel_index,
                    text: text_channel_index,
                },
                &self.vault.store,
                &rtxn,
                &mut metadata_cache,
                blend_config,
                blend_weights,
            )?;
            let mut scores = first_blend.scores;
            let mut cosine_ghosts_dampened = first_blend.cosine_ghosts_dampened;
            let mut blend_components = first_blend.components;
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
            // OF-326 THE FENCE, first application: like the claim status
            // gate above, this runs BEFORE `blend_allowed_ids` and the
            // expand_ppr implicit seed selection below, so a fenced
            // off-record turn can neither seed graph expansion (pulling its
            // on-record neighbors into the results) nor ride the blended
            // candidate set. The late per-candidate filter remains as
            // defense-in-depth.
            apply_off_record_fence(&mut scores, &self.vault.store, &rtxn)?;
            let mut blend_allowed_ids = score_id_set(&scores);

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
                    // OF-326 THE FENCE, second application: expansion can
                    // pull a fenced off-record entity back in as a
                    // neighbor — drop it before the expansion list fuses.
                    apply_off_record_fence(&mut ppr_results, &self.vault.store, &rtxn)?;
                    add_signal_score_components(
                        &mut signal_components,
                        RetrievalSignal::Ppr,
                        &ppr_results,
                    );
                    if capture_retrieval_trace {
                        let trace_results = filter_retrieval_trace_scores(
                            &ppr_results,
                            &self.vault.store,
                            &rtxn,
                            filter_config,
                            &mut metadata_cache,
                            &mut trace_claim_gate,
                            trace_candidate_limit,
                        )?;
                        trace_channels.push(retrieval_trace_channel_record(
                            RetrievalSignal::Ppr,
                            &trace_results,
                            trace_candidate_limit,
                        ));
                        trace_ranked_lists.push(trace_results);
                    }
                    blend_allowed_ids.extend(ppr_results.iter().map(|scored| scored.id));
                    ranked_lists.push(ppr_results);
                    if capture_retrieval_trace {
                        fused_trace_scores = Some(retrieval_trace_fused_scores(
                            &trace_ranked_lists,
                            trace_candidate_limit,
                        ));
                    }
                    let expanded_blend = blended_retrieval_scores(
                        &ranked_lists,
                        RetrievalChannelIndexes {
                            vector: vector_channel_index,
                            text: text_channel_index,
                        },
                        &self.vault.store,
                        &rtxn,
                        &mut metadata_cache,
                        blend_config,
                        blend_weights,
                    )?;
                    scores = filter_blended_scores_to_allowed_ids(
                        expanded_blend.scores,
                        &blend_allowed_ids,
                    );
                    cosine_ghosts_dampened = expanded_blend.cosine_ghosts_dampened;
                    blend_components = expanded_blend.components;
                }
            }

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
            if capture_retrieval_trace {
                blended_trace_scores =
                    Some(retrieval_trace_top_scores(&scores, trace_candidate_limit));
            }

            let before_limit = scores.len();
            fusion::sort_scored_entities_desc(&mut scores);

            // RET-010 rerank hook: post-sort, pre-budget/pre-truncate, so the
            // reranker sees the blended+filtered ordering over more than
            // `result_limit` candidates and the budget/truncate operate on
            // the final relevance order. Score-ladder reassignment: the block
            // is permuted by (rerank score desc, id bytes asc) but position i
            // keeps the i-th highest ENGINE score, so every downstream
            // order-by-score is stable with the rerank order; raw reranker
            // scores survive in the Rerank components.
            let mut rerank_merged_components = None;
            let mut reranked_trace_scores = None;
            // Empty block: reranking zero candidates is a semantic no-op —
            // never invoke the host impl, so an otherwise-empty retrieval
            // cannot fail on reranker behavior and no needless work happens
            // under the held read txn. (The fail-closed top_n/query
            // validation at the top of run_for_pack still applies.)
            if let Some((reranker, options)) = self.rerank.as_ref()
                && options.top_n.min(scores.len()) > 0
            {
                let query = rerank_query.as_deref().unwrap_or_default();
                let block_len = options.top_n.min(scores.len());
                let block_ids: Vec<EntityId> =
                    scores[..block_len].iter().map(|scored| scored.id).collect();
                let ladder: Vec<f32> = scores[..block_len]
                    .iter()
                    .map(|scored| scored.score)
                    .collect();
                let candidates: Vec<RerankCandidate<'_>> = scores[..block_len]
                    .iter()
                    .enumerate()
                    .map(|(index, scored)| RerankCandidate {
                        id: scored.id,
                        score: scored.score,
                        rank: (index + 1).min(u32::MAX as usize) as u32,
                        claim: claim_gate
                            .decisions
                            .get(&scored.id)
                            .and_then(|decision| decision.as_ref()),
                    })
                    .collect();
                let rerank_scores = reranker.rerank(query, &candidates)?;
                drop(candidates);
                if rerank_scores.len() != block_len {
                    return Err(Error::InvariantViolation(
                        "reranker returned mismatched score count",
                    ));
                }
                if rerank_scores.iter().any(|score| !score.is_finite()) {
                    return Err(Error::InvariantViolation(
                        "reranker returned non-finite score",
                    ));
                }

                let mut order: Vec<usize> = (0..block_len).collect();
                order.sort_by(|&left, &right| {
                    rerank_scores[right]
                        .partial_cmp(&rerank_scores[left])
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| block_ids[left].as_bytes().cmp(block_ids[right].as_bytes()))
                });
                let mut rerank_components =
                    HashMap::<EntityId, Vec<RetrievalScoreComponent>>::new();
                for (new_pos, &old_pos) in order.iter().enumerate() {
                    scores[new_pos] = ScoredEntity {
                        id: block_ids[old_pos],
                        score: ladder[new_pos],
                    };
                    rerank_components
                        .entry(block_ids[old_pos])
                        .or_default()
                        .push(RetrievalScoreComponent {
                            signal: RetrievalSignal::Rerank,
                            rank: (new_pos + 1).min(u32::MAX as usize) as u32,
                            score: rerank_scores[old_pos],
                        });
                }

                // Rerank components append AFTER the blend components in each
                // entity's vector (pinned merge order; no dedup, no re-sort).
                let mut merged = blend_components.clone();
                for (id, components) in rerank_components {
                    merged.entry(id).or_default().extend(components);
                }
                rerank_merged_components = Some(merged);

                if capture_retrieval_trace {
                    reranked_trace_scores =
                        Some(retrieval_trace_top_scores(&scores, trace_candidate_limit));
                }
            }

            // RET-01: abstention is a context-pack assembly decision, never a
            // mutation of stored memory or a behavior change for direct
            // retrieval. Clear the candidate list structurally so hydration
            // cannot surface weak evidence; `BelowThreshold` is carried to
            // the public `ContextPack.empty` response as the typed confidence
            // adjustment.
            if self.context_pack_budget.is_some()
                && context_pack_evidence_abstains(
                    &scores,
                    &signal_components,
                    self.text_search.as_ref().map(|(query, _)| query.as_str()),
                    self.vector_search.is_some(),
                )
            {
                scores.clear();
                empty_reason = Some(EmptyReason::BelowThreshold);
            }

            if let Some(context_pack_budget) = self.context_pack_budget {
                apply_context_pack_retrieval_budget(
                    &mut scores,
                    &self.vault.store,
                    &rtxn,
                    &mut metadata_cache,
                    context_pack_budget,
                )?;
            }
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
            let retrieval_trace = if capture_retrieval_trace {
                let final_scores = retrieval_trace_top_scores(&scores, trace_candidate_limit);
                let blended_scores = blended_trace_scores.unwrap_or_default();
                let candidate_set = retrieval_trace_candidate_set(
                    &trace_ranked_lists,
                    fused_trace_scores.as_deref().unwrap_or(&[]),
                    &blended_scores,
                    &final_scores,
                );
                let fork_hash = retrieval_trace_fork_hash(
                    &self,
                    &bm25_config,
                    blend_weights,
                    explicit_time_dependent_now,
                    occurred_range,
                    rerank_query.as_deref(),
                    &candidate_set,
                );
                Some(RetrievalTrace {
                    fork_hash,
                    per_channel: trace_channels,
                    fused: retrieval_trace_stage_record(
                        RetrievalTraceStage::Fused,
                        &fused_trace_scores.unwrap_or_default(),
                        &signal_components,
                        &HashMap::new(),
                        trace_candidate_limit,
                    ),
                    blended: retrieval_trace_stage_record(
                        RetrievalTraceStage::Blended,
                        &blended_scores,
                        &signal_components,
                        &blend_components,
                        trace_candidate_limit,
                    ),
                    // Rerank inactive: passthrough mirror of `final` (the
                    // 1186-D5 reserved slot). Active: the post-rerank,
                    // pre-budget/pre-truncate ordering with the rerank
                    // components appended after the blend components.
                    reranked: retrieval_trace_stage_record(
                        RetrievalTraceStage::Reranked,
                        reranked_trace_scores.as_deref().unwrap_or(&final_scores),
                        &signal_components,
                        rerank_merged_components
                            .as_ref()
                            .unwrap_or(&blend_components),
                        trace_candidate_limit,
                    ),
                    final_stage: retrieval_trace_stage_record(
                        RetrievalTraceStage::Final,
                        &final_scores,
                        &signal_components,
                        &blend_components,
                        trace_candidate_limit,
                    ),
                })
            } else {
                None
            };
            (
                scores,
                pending_vectors,
                claim_gate,
                deferred_ppr_cache_writes,
                cosine_ghosts_dampened,
                total_in_scope,
                empty_reason,
                signal_components,
                blend_components,
                rerank_merged_components,
                retrieval_trace,
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

        let score_breakdown = telemetry_score_breakdown(
            &scores,
            &signal_components,
            rerank_merged_components
                .as_ref()
                .unwrap_or(&blend_components),
        );
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
            telemetry_signals.clone(),
            score_breakdown,
            total_in_scope,
            claims_suppressed,
            empty_reason.map(|reason| format!("{reason:?}")),
        )
        .with_trace(retrieval_trace);
        // ONE-1728 K10: the retrieval-run registration routes by the caller's
        // write target. A session run's row stages into the room's overlay
        // `VaultMeta` and evaporates at close, so the base telemetry ledger
        // gains ZERO rows from an OffRecord session; canonical entries carry
        // `None` and take the unchanged base path. Both arms ride the same
        // extracted staging body, so the key format and the provisional /
        // fork-index side writes cannot drift between targets.
        let provisional = telemetry_action == RetrievalAction::ContextPack;
        let write_result = match self.session_view {
            Some(view) => self.vault.try_with_write_txn(|wtxn| {
                if provisional {
                    view.record_context_pack_provisional_retrieval_run_in_txn(wtxn, &run_record)
                } else {
                    view.record_retrieval_run_in_txn(wtxn, &run_record)
                }
            }),
            None if provisional => self
                .vault
                .store
                .record_context_pack_provisional_retrieval_run(&run_record),
            None => self.vault.store.record_retrieval_run(&run_record),
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
            signals: telemetry_signals,
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

    fn has_strict_text_scope_filter(&self) -> bool {
        self.type_filter.is_some()
            || self.since_filter.is_some()
            || self.occurred_range.is_some()
            || self.learned_range.is_some()
            || matches!(self.facet_filter, Some((_, FacetMode::Strict)))
            || self.world_scope != WorldScope::All
    }

    fn resolved_occurred_range(&self, now: u64) -> Result<Option<(u64, u64)>> {
        if self.occurred_range.is_some() || self.temporal_search.is_some() {
            return Ok(self.occurred_range);
        }

        let Some((query, _)) = self.text_search.as_ref() else {
            return Ok(None);
        };

        temporal_expression_from_query(query)
            .map(|expression| expression.map(|expression| expression.resolve(now)))
            .map(|range| range.map(|range| normalize_range(range.start, range.end)))
            .map_err(invalid_temporal_expression)
    }
}

fn invalid_temporal_expression(error: TemporalExpressionParseError) -> Error {
    Error::InvalidTemporalExpression(error)
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

fn retrieval_trace_channel_record(
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

fn retrieval_trace_fused_scores(
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

fn retrieval_trace_top_scores(scores: &[ScoredEntity], limit: usize) -> Vec<ScoredEntity> {
    scores.iter().take(limit).copied().collect()
}

fn retrieval_trace_stage_record(
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

fn telemetry_score_breakdown(
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

fn retrieval_trace_fork_hash(
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

fn retrieval_trace_candidate_set(
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

fn scoped_text_channel_limit(
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

fn truncate_widened_channel_results_to_scope(
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

fn filter_retrieval_trace_scores(
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

fn contains_off_record_fence(
    scores: &[ScoredEntity],
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<bool> {
    for scored in scores {
        if crate::off_record::off_record_fence_active(store, rtxn, &scored.id)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn truncate_vector_fence_replacements(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    requested: usize,
    metadata_cache: &mut EntityMetadataCache,
    claim_gate: &mut ClaimStatusGateCache,
) -> Result<()> {
    let mut filtered = Vec::with_capacity(requested.min(scores.len()));
    for scored in scores.iter().copied() {
        if crate::off_record::off_record_fence_active(store, rtxn, &scored.id)? {
            continue;
        }
        if !claim_status_gate_allows(store, rtxn, &scored.id, metadata_cache, claim_gate)? {
            continue;
        }
        filtered.push(scored);
        if filtered.len() == requested {
            break;
        }
    }

    *scores = filtered;
    Ok(())
}

fn next_vector_fence_search_limit(
    current: usize,
    filtered: usize,
    requested: usize,
    entity_count: usize,
) -> usize {
    let missing = requested.saturating_sub(filtered).max(1);
    current
        .saturating_add(current.max(missing))
        .min(entity_count)
}

fn temporal_fence_scan_budget(cap: usize, off_record_fences_present: bool) -> usize {
    if off_record_fences_present {
        cap.saturating_mul(PER_SCAN_CAP_FACTOR)
            .min(MAX_TEMPORAL_SEEK_BUFFER)
            .max(cap)
    } else {
        cap
    }
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

fn retrieval_recency_half_life_days_for_type(entity_type: u8) -> f32 {
    RETRIEVAL_RECENCY_HALF_LIFE_DAYS_BY_TYPE
        .iter()
        .find_map(|(kind, half_life_days)| (*kind == entity_type).then_some(*half_life_days))
        .unwrap_or(DEFAULT_RECENCY_HALF_LIFE_DAYS)
}

#[derive(Debug, Clone, Copy)]
struct RetrievalBlendConfig {
    recency_now_secs: Option<u64>,
    salience: bool,
    confidence: bool,
    gravity: bool,
}

#[derive(Debug, Clone, Copy)]
struct RetrievalChannelIndexes {
    vector: Option<usize>,
    text: Option<usize>,
}

struct BlendedRetrievalScores {
    scores: Vec<ScoredEntity>,
    cosine_ghosts_dampened: usize,
    components: HashMap<EntityId, Vec<RetrievalScoreComponent>>,
}

fn blended_retrieval_scores(
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

fn score_id_set(scores: &[ScoredEntity]) -> HashSet<EntityId> {
    scores.iter().map(|scored| scored.id).collect()
}

fn filter_blended_scores_to_allowed_ids(
    blended: Vec<ScoredEntity>,
    allowed: &HashSet<EntityId>,
) -> Vec<ScoredEntity> {
    blended
        .into_iter()
        .filter(|scored| allowed.contains(&scored.id))
        .collect()
}

fn cosine_ghost_set(
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
        if claim_status_gate_allows(store, rtxn, &scored.id, metadata_cache, gate)? {
            kept.push(scored);
        }
    }

    *scores = kept;
    Ok(())
}

fn claim_status_gate_allows(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    metadata_cache: &mut EntityMetadataCache,
    gate: &mut ClaimStatusGateCache,
) -> Result<bool> {
    // Entities without a parseable envelope are not a claim-status
    // decision; `apply_filters` drops them downstream exactly as before.
    let Some(meta) = metadata_cache.get(store, rtxn, id)? else {
        return Ok(true);
    };
    if meta.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(true);
    }

    if let Some(decision) = gate.decisions.get(id) {
        return Ok(decision.is_some());
    }

    // Read path allows reserved `edge.*` predicates so stored provenance
    // Claims gate on their own appr/life/stale like any other claim instead
    // of failing the decode.
    let decision = store
        .entities
        .get(rtxn, id.as_bytes())?
        .and_then(|raw| {
            raw.get(ENTITY_METADATA_HEADER_LEN..)
                .and_then(|body| crate::claim::decode_claim_body(body, true).ok())
        })
        .filter(claim_surfaceable);
    let allowed = decision.is_some();
    gate.decisions.insert(*id, decision);
    Ok(allowed)
}

fn import_claim_gate_decisions_for_scores(
    claim_gate: &mut ClaimStatusGateCache,
    probe_gate: &mut ClaimStatusGateCache,
    scores: &[ScoredEntity],
) {
    for scored in scores {
        let Some(decision) = probe_gate.decisions.remove(&scored.id) else {
            continue;
        };
        claim_gate.decisions.entry(scored.id).or_insert(decision);
    }
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
///
/// Disclosure contract (ONE-1645): this is the ARCH-0039 RELEVANCE stage, not
/// an exposure boundary. Keeping an unfaceted claim here says nothing about
/// whether it may be disclosed — stamp-absence is never invariant evidence.
/// The exposure decision lives on the disclosure axis: the unstamped
/// sensitivity floor (`claim_sensitivity_band` reads band 2 on a missing
/// stamp) today, and the ONE-1646 `disclosable_set` conjunct inside
/// `admits()` next. Relevance never bypasses that conjunct (P7).
///
/// Scope of the CLAIM-only reading: this stage is the LOCAL QUERY door, and a
/// non-CLAIM `FacetOf` stamp being inert HERE is not a statement about the
/// entity's exposure anywhere else. `crate::sync::selector` is a second door
/// that scopes by every source type the ONE-1645 table admits, so a TURN- or
/// EVENT-sourced stamp is disclosure-effective there. "Inert on this door"
/// never generalizes to "disclosure-inert".
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
        WorldScope::WorldSet(scope_key) => {
            let mut kept = Vec::with_capacity(scores.len());
            for scored in scores.iter().copied() {
                if codebase_candidate_matches_scope_key(store, rtxn, &scored.id, &scope_key)? {
                    kept.push(scored);
                }
            }
            *scores = kept;
            return Ok(());
        }
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
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
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
    off_record_fences_present: bool,
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
                off_record_fences_present,
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
        // OF-326 THE FENCE: temporal candidate collection deliberately
        // overfetches before this per-channel limit is applied. Drop fenced
        // entities first so they cannot consume the channel's result slots.
        if off_record_fences_present
            && crate::off_record::off_record_fence_active(store, rtxn, &id)?
        {
            continue;
        }
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
    let off_record_fences_present = collection.off_record_fences_present;
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
        off_record_fences_present,
    };
    let learned_collection = TemporalIndexCollectionContext {
        window_start: learned_window_start,
        window_end: learned_window_end,
        anchor_mid: learned_mid,
        cap: per_scan_cap,
        off_record_fences_present,
    };

    match config.anchor_mode {
        TemporalAnchorMode::Occurred => {
            collect_occurred_candidates(store, rtxn, occurred_collection, out)?;
        }
        TemporalAnchorMode::Learned => {
            collect_index_candidates(
                &store.temporal_learned,
                store,
                rtxn,
                learned_collection,
                out,
            )?;
        }
        TemporalAnchorMode::Auto | TemporalAnchorMode::Both => {
            collect_occurred_candidates(store, rtxn, occurred_collection, out)?;
            collect_index_candidates(
                &store.temporal_learned,
                store,
                rtxn,
                learned_collection,
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
            let (id, occurred_start, _) = decode_long_interval_row(&key, &value)?;
            if occurred_start >= occurred_window_start {
                continue;
            }
            if off_record_fences_present
                && crate::off_record::off_record_fence_active(store, rtxn, &id)?
            {
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
    collection: TemporalIndexCollectionContext,
    out: &mut HashSet<EntityId>,
) -> Result<()> {
    collect_index_candidates(&store.temporal_occurred_start, store, rtxn, collection, out)?;
    collect_index_candidates(&store.temporal_occurred_end, store, rtxn, collection, out)?;
    Ok(())
}

fn collect_index_candidates(
    db: &OverlayDb,
    store: &Store,
    rtxn: &RoTxn<'_>,
    collection: TemporalIndexCollectionContext,
    out: &mut HashSet<EntityId>,
) -> Result<()> {
    let TemporalIndexCollectionContext {
        window_start,
        window_end,
        anchor_mid,
        cap,
        off_record_fences_present,
    } = collection;
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
    let scan_budget = temporal_fence_scan_budget(cap, off_record_fences_present);
    let mut scanned = 0_usize;
    while rows.len() < cap && scanned < scan_budget {
        let Some(row) = next_temporal_index_row(&mut forward)? else {
            break;
        };
        scanned = scanned.saturating_add(1);
        if off_record_fences_present
            && crate::off_record::off_record_fence_active(store, rtxn, &row.id)?
        {
            continue;
        }
        rows.push(row);
    }

    let mut backward = db.rev_range(
        rtxn,
        &(
            std::ops::Bound::Included(&window_start_key[..]),
            std::ops::Bound::Excluded(&anchor_key[..]),
        ),
    )?;
    let mut backward_rows =
        collect_temporal_index_rows(&mut backward, cap, store, rtxn, off_record_fences_present)?;
    normalize_backward_boundary_bucket(
        db,
        store,
        rtxn,
        &mut backward_rows,
        off_record_fences_present,
    )?;
    rows.extend(backward_rows);

    rows.sort_unstable_by(|a, b| compare_temporal_index_rows(a, b, anchor_mid));
    for row in rows.into_iter().take(cap) {
        out.insert(row.id);
    }

    Ok(())
}

fn next_temporal_index_row<'a, I>(iter: &mut I) -> Result<Option<TemporalIndexRow>>
where
    I: Iterator<Item = Result<(std::borrow::Cow<'a, [u8]>, std::borrow::Cow<'a, [u8]>)>>,
{
    let Some(entry) = iter.next() else {
        return Ok(None);
    };
    let (key, _) = entry?;
    decode_temporal_index_row(&key).map(Some)
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

fn collect_temporal_index_rows<'a, I>(
    iter: &mut I,
    cap: usize,
    store: &Store,
    rtxn: &RoTxn<'_>,
    off_record_fences_present: bool,
) -> Result<Vec<TemporalIndexRow>>
where
    I: Iterator<Item = Result<(std::borrow::Cow<'a, [u8]>, std::borrow::Cow<'a, [u8]>)>>,
{
    let mut rows = Vec::with_capacity(cap.min(MAX_TEMPORAL_SEEK_BUFFER));
    let scan_budget = temporal_fence_scan_budget(cap, off_record_fences_present);
    let mut scanned = 0_usize;

    while rows.len() < cap && scanned < scan_budget {
        let Some(row) = next_temporal_index_row(iter)? else {
            return Ok(rows);
        };
        scanned = scanned.saturating_add(1);
        if off_record_fences_present
            && crate::off_record::off_record_fence_active(store, rtxn, &row.id)?
        {
            continue;
        }
        rows.push(row);
    }

    Ok(rows)
}

fn normalize_backward_boundary_bucket(
    db: &OverlayDb,
    store: &Store,
    rtxn: &RoTxn<'_>,
    rows: &mut Vec<TemporalIndexRow>,
    off_record_fences_present: bool,
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
    let scan_budget = temporal_fence_scan_budget(boundary_count, off_record_fences_present);
    let mut scanned = 0_usize;
    while boundary_rows.len() < boundary_count && scanned < scan_budget {
        let Some(row) = next_temporal_index_row(&mut boundary_iter)? else {
            break;
        };
        scanned = scanned.saturating_add(1);
        if off_record_fences_present
            && crate::off_record::off_record_fence_active(store, rtxn, &row.id)?
        {
            continue;
        }
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

/// OF-326 THE FENCE as a candidate-list sweep: drops entities carrying an
/// off-record fence row. Applied to the fused scores BEFORE expand_ppr seed
/// selection and to the PPR expansion list before it fuses, mirroring the
/// two claim-status-gate applications.
fn apply_off_record_fence(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
) -> Result<()> {
    let mut kept = Vec::with_capacity(scores.len());
    for scored in scores.iter().copied() {
        if !crate::off_record::off_record_fence_active(store, rtxn, &scored.id)? {
            kept.push(scored);
        }
    }
    *scores = kept;
    Ok(())
}

fn apply_off_record_fence_with_cap(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    cap: usize,
) -> Result<()> {
    apply_off_record_fence(scores, store, rtxn)?;
    scores.truncate(cap);
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

        // OF-326 THE FENCE (ONE-1546): off-record-tagged entities never
        // surface, independent of the owning session's current mode.
        if crate::off_record::off_record_fence_active(store, rtxn, &scored.id)? {
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

fn pipeline_candidate_matches_filters_and_gate(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    filters: PipelineFilterConfig<'_>,
    metadata_cache: &mut EntityMetadataCache,
    claim_gate: &mut ClaimStatusGateCache,
) -> Result<bool> {
    let Some(meta) = metadata_cache.get(store, rtxn, id)? else {
        return Ok(false);
    };

    if let Some(types) = filters.type_filter
        && !types.contains(&meta.entity_type)
    {
        return Ok(false);
    }

    if let Some(timestamp) = filters.since_filter
        && meta.learned_at < timestamp
    {
        return Ok(false);
    }

    if let Some((start, end)) = filters.occurred_range
        && !intervals_overlap(meta.occurred_start, meta.occurred_end, start, end)
    {
        return Ok(false);
    }

    if let Some((start, end)) = filters.learned_range
        && (meta.learned_at < start || meta.learned_at > end)
    {
        return Ok(false);
    }

    // OF-326 THE FENCE (ONE-1546): entities tagged off-record never surface
    // to any retrieval/extraction consumer of this filter, independent of
    // the owning session's current mode — the tag outlives a same-session
    // flip back on-record, and only promote or delete-at-close lifts it.
    if filters.off_record_fences_present
        && crate::off_record::off_record_fence_active(store, rtxn, id)?
    {
        return Ok(false);
    }

    if !crate::codebase::codebase_candidate_matches_filters(
        store,
        rtxn,
        id,
        filters.repo_ref_filter,
        filters.project_id_filter,
    )? {
        return Ok(false);
    }

    if !claim_status_gate_allows(store, rtxn, id, metadata_cache, claim_gate)? {
        return Ok(false);
    }

    if !pipeline_candidate_matches_facet_filter(
        store,
        rtxn,
        id,
        meta.entity_type,
        filters.facet_filter,
        metadata_cache,
    )? {
        return Ok(false);
    }

    if !pipeline_candidate_matches_world_filter(store, rtxn, id, filters.world_scope)? {
        return Ok(false);
    }

    Ok(true)
}

/// The candidate-scan twin of [`apply_facet_filter`], with the same
/// disclosure contract (ONE-1645): this is a RELEVANCE decision. Admitting an
/// unfaceted claim here is not evidence that it is invariant or publicly
/// disclosable — the unstamped sensitivity floor and the ONE-1646
/// `disclosable_set` conjunct own that axis.
fn pipeline_candidate_matches_facet_filter(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    facet_filter: Option<(EntityId, FacetMode)>,
    metadata_cache: &mut EntityMetadataCache,
) -> Result<bool> {
    let Some((active_facet, mode)) = facet_filter else {
        return Ok(true);
    };

    let active_facet_type = metadata_cache
        .get(store, rtxn, &active_facet)?
        .map(|meta| meta.entity_type);
    if active_facet_type != Some(ENTITY_TYPE_FACET) {
        return Err(Error::InvalidFacet {
            facet: active_facet,
            found: active_facet_type,
        });
    }

    if entity_type != ENTITY_TYPE_CLAIM {
        return Ok(true);
    }

    match claim_facet_scope(store, rtxn, id, &active_facet)? {
        ClaimFacetScope::OtherFacetsOnly => Ok(matches!(mode, FacetMode::Prefer { .. })),
        ClaimFacetScope::Unfaceted | ClaimFacetScope::ActiveFacet => Ok(true),
    }
}

fn pipeline_candidate_matches_world_filter(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
    scope: WorldScope,
) -> Result<bool> {
    let target = match scope {
        WorldScope::All => return Ok(true),
        WorldScope::Base => None,
        WorldScope::World(id) => Some(id),
        WorldScope::WorldSet(scope_key) => {
            return codebase_candidate_matches_scope_key(store, rtxn, id, &scope_key);
        }
    };

    Ok(match claim_world(store, rtxn, id)? {
        None => true,
        Some(world) => target == Some(world),
    })
}

fn apply_context_pack_retrieval_budget(
    scores: &mut Vec<ScoredEntity>,
    store: &Store,
    rtxn: &RoTxn<'_>,
    metadata_cache: &mut EntityMetadataCache,
    budget: ContextPackRetrievalBudget,
) -> Result<()> {
    if scores.is_empty() {
        return Ok(());
    }

    let mut candidates = Vec::with_capacity(scores.len());
    let mut available = ContextPackBudgetCounts::default();
    for scored in scores.iter().copied() {
        let Some(meta) = metadata_cache.get(store, rtxn, &scored.id)? else {
            continue;
        };
        let kind = ContextPackBudgetKind::from_entity_type(meta.entity_type);
        available.increment(kind);
        candidates.push((scored, kind));
    }

    let caps =
        redistribute_context_pack_budget(ContextPackBudgetCounts::from_budget(budget), available);
    let mut used = ContextPackBudgetCounts::default();
    let mut kept = Vec::with_capacity(candidates.len().min(scores.len()));
    for (scored, kind) in candidates {
        if used.get(kind) >= caps.get(kind) {
            continue;
        }
        used.increment(kind);
        kept.push(scored);
    }

    *scores = kept;
    Ok(())
}

/// Returns whether a context pack must withhold every candidate before
/// hydration. The predicate intentionally reads raw per-channel evidence,
/// rather than the blended score: blend dimensions can be incomparable or
/// flat, while cosine scores have a stable similarity meaning.
fn context_pack_evidence_abstains(
    scores: &[ScoredEntity],
    signal_components: &HashMap<EntityId, Vec<RetrievalScoreComponent>>,
    text_query: Option<&str>,
    has_vector_query: bool,
) -> bool {
    if text_query.is_some_and(context_pack_text_is_anomalous) {
        return true;
    }
    if scores.is_empty() {
        return false;
    }

    let mut has_keyword_hit = false;
    let mut vector_scores = Vec::new();
    for scored in scores {
        let Some(components) = signal_components.get(&scored.id) else {
            continue;
        };
        for component in components {
            match component.signal {
                RetrievalSignal::Text => has_keyword_hit = true,
                RetrievalSignal::Vector => vector_scores.push(component.score),
                _ => {}
            }
        }
    }

    // A semantic-only result is not rejected merely for being below the
    // floor: this branch requires both caller-supplied channels and no
    // surviving keyword evidence, matching the RET-01 dual-signal rule.
    let absent_keyword_and_low_vector = text_query.is_some()
        && has_vector_query
        && !has_keyword_hit
        && !vector_scores.is_empty()
        && vector_scores
            .iter()
            .all(|score| !score.is_finite() || *score < CONTEXT_PACK_MIN_VECTOR_SIMILARITY);

    absent_keyword_and_low_vector || context_pack_vector_score_gap_is_poor(&mut vector_scores)
}

/// RET-01 pack hygiene for malformed or degenerate text input. Newlines and
/// tabs remain legitimate natural-language formatting; other controls and a
/// long non-whitespace character run are treated as anomalous evidence.
fn context_pack_text_is_anomalous(text: &str) -> bool {
    let mut previous = None;
    let mut repeated = 0_usize;

    for character in text.chars() {
        if character.is_control() && !matches!(character, '\n' | '\r' | '\t') {
            return true;
        }
        if character.is_whitespace() {
            previous = None;
            repeated = 0;
            continue;
        }
        if previous == Some(character) {
            repeated += 1;
            if repeated >= CONTEXT_PACK_ANOMALOUS_REPEAT_RUN {
                return true;
            }
        } else {
            previous = Some(character);
            repeated = 1;
        }
    }

    false
}

/// Score-gap evidence is meaningful only within the same raw vector channel.
/// The ratio follows `(top1 - top2) / max(top1, epsilon)`; it suppresses
/// uniformly mediocre results, not a close cluster of strong matches.
fn context_pack_vector_score_gap_is_poor(vector_scores: &mut [f32]) -> bool {
    if vector_scores.len() < 2 {
        return false;
    }

    vector_scores.sort_unstable_by(|left, right| right.total_cmp(left));
    let top = vector_scores[0];
    let next = vector_scores[1];
    if !top.is_finite() || !next.is_finite() || top <= 0.0 {
        return true;
    }
    if top >= CONTEXT_PACK_MEDIOCRE_VECTOR_SIMILARITY {
        return false;
    }

    let gap_ratio = (top - next) / top.max(CONTEXT_PACK_SCORE_GAP_EPSILON);
    gap_ratio < CONTEXT_PACK_MIN_VECTOR_SCORE_GAP_RATIO
}

fn redistribute_context_pack_budget(
    mut caps: ContextPackBudgetCounts,
    available: ContextPackBudgetCounts,
) -> ContextPackBudgetCounts {
    let kinds = [
        ContextPackBudgetKind::Claim,
        ContextPackBudgetKind::Turn,
        ContextPackBudgetKind::Summary,
        ContextPackBudgetKind::Facet,
        ContextPackBudgetKind::Other,
    ];

    let mut surplus = 0_usize;
    let mut hungry = Vec::new();
    for kind in kinds {
        let cap = caps.get(kind);
        let count = available.get(kind);
        if count <= cap {
            surplus = surplus.saturating_add(cap.saturating_sub(count));
        } else if cap > 0 {
            hungry.push((kind, count - cap));
        }
    }

    if surplus == 0 || hungry.is_empty() {
        return caps;
    }

    hungry.sort_unstable_by_key(|(kind, _)| match kind {
        ContextPackBudgetKind::Claim => 0,
        ContextPackBudgetKind::Turn => 1,
        ContextPackBudgetKind::Summary => 2,
        ContextPackBudgetKind::Facet => 3,
        ContextPackBudgetKind::Other => 4,
    });

    while surplus > 0 && !hungry.is_empty() {
        let mut still_hungry = Vec::with_capacity(hungry.len());
        for (kind, need) in hungry {
            if surplus == 0 {
                still_hungry.push((kind, need));
                continue;
            }
            caps.increment(kind);
            surplus -= 1;
            if need > 1 {
                still_hungry.push((kind, need - 1));
            }
        }
        hungry = still_hungry;
    }

    caps
}

fn read_entity_metadata(
    store: &Store,
    rtxn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityMetadata>> {
    let Some(raw) = store.entities.get(rtxn, id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
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
mod tests;
