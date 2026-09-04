use std::collections::HashMap;

use heed::RoTxn;

use crate::claim::ClaimBody;
use crate::codebase::{CodebaseScopeKey, RepoRef};
use crate::context_pack::EmptyReason;
use crate::corpus::CorpusScope;
use crate::entity_id::EntityId;
use crate::error::Result;
// Referenced only by an intra-doc link below; `cfg(doc)` keeps it out of
// ordinary builds, where it would be an unused import.
#[cfg(doc)]
use crate::error::Error;
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
use crate::store::{RetrievalRunId, RetrievalSignal, Store};
use crate::temporal::TemporalAnchorMode;

// Referenced only by the intra-doc links below; `cfg(doc)` keeps it out of
// ordinary builds, where it would be an unused import.
#[cfg(doc)]
use super::builder::PipelineBuilder;
use super::support::read_entity_metadata;

pub(crate) const DEFAULT_RESULT_LIMIT: usize = 20;
pub(super) const DEFAULT_SIGMA_SECS: u64 = 86_400;
pub(super) const MIN_WINDOW_RADIUS_SECS: u64 = 7 * 86_400;
pub(super) const TEMPORAL_KEY_LEN: usize = 24;
pub(super) const LONG_INTERVAL_VALUE_LEN: usize = 8;
pub(super) const TEMPORAL_FLOOR: f64 = 0.05;

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
    Hyde,
}

pub(super) const SECONDS_PER_DAY_F64: f64 = 86_400.0;
pub(super) const RETRIEVAL_TRACE_RRF_K: f32 = 60.0;

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

pub(super) fn retrieval_recency_half_life_days_for_type(entity_type: u8) -> f32 {
    RETRIEVAL_RECENCY_HALF_LIFE_DAYS_BY_TYPE
        .iter()
        .find_map(|(kind, half_life_days)| (*kind == entity_type).then_some(*half_life_days))
        .unwrap_or(DEFAULT_RECENCY_HALF_LIFE_DAYS)
}

/// ARCH-0004 §4.5 table value (`28.0 * 86_400`), derived from
/// [`DEFAULT_RECENCY_HALF_LIFE_DAYS`]. The temporal scorer applies it as
/// the decay constant in `exp(-age / tau)` — existing behavior, kept
/// unchanged.
pub(super) const RECENCY_DECAY_TAU_SECS: f64 =
    DEFAULT_RECENCY_HALF_LIFE_DAYS as f64 * SECONDS_PER_DAY_F64;
pub(super) const ALPHA_BASE: f64 = 0.7;
pub(super) const ALPHA_RANGE: f64 = 0.3;
pub(super) const ALPHA_TAU_SECS: f64 = 90.0 * SECONDS_PER_DAY_F64;
pub(super) const PPR_DAMPING: f32 = 0.15;
pub(super) const ADAPTIVE_ROUNDS: usize = 3;
pub(super) const PER_SCAN_CAP_FACTOR: usize = 4;
pub(super) const MAX_TEMPORAL_SEEK_BUFFER: usize = 8_192;
pub(super) const COSINE_GHOST_VECTOR_THRESHOLD: f32 = 0.3;
// RET-01 only gates context-pack assembly. These are deliberately
// conservative: the vector floor needs an absent keyword signal too, while
// the score-gap check only compares raw cosine scores from the same channel.
pub(super) const CONTEXT_PACK_MIN_VECTOR_SIMILARITY: f32 = 0.3;
pub(super) const CONTEXT_PACK_MEDIOCRE_VECTOR_SIMILARITY: f32 = 0.5;
pub(super) const CONTEXT_PACK_MIN_VECTOR_SCORE_GAP_RATIO: f32 = 0.1;
pub(super) const CONTEXT_PACK_SCORE_GAP_EPSILON: f32 = f32::EPSILON;
pub(super) const CONTEXT_PACK_ANOMALOUS_REPEAT_RUN: usize = 32;

#[derive(Debug, Clone)]
pub(super) struct TemporalSearchConfig {
    pub(super) anchor_start: u64,
    pub(super) anchor_end: u64,
    pub(super) learned_start: Option<u64>,
    pub(super) learned_end: Option<u64>,
    pub(super) sigma_secs: u64,
    pub(super) anchor_mode: TemporalAnchorMode,
    pub(super) adaptive: bool,
    pub(super) limit: usize,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct EntityMetadata {
    pub(super) entity_type: u8,
    pub(super) occurred_start: u64,
    pub(super) occurred_end: u64,
    pub(super) learned_at: u64,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PipelineFilterConfig<'a> {
    pub(super) type_filter: Option<&'a [u8]>,
    pub(super) since_filter: Option<u64>,
    pub(super) occurred_range: Option<(u64, u64)>,
    pub(super) learned_range: Option<(u64, u64)>,
    pub(super) repo_ref_filter: Option<&'a RepoRef>,
    pub(super) project_id_filter: Option<&'a str>,
    pub(super) facet_filter: Option<(EntityId, FacetMode)>,
    pub(super) relationship_filter: Option<(EntityId, RelMode)>,
    pub(super) world_scope: WorldScope,
    /// The query's audience scope (ONE-1914); [`CorpusScope::All`] is the
    /// default and a no-op, exactly like [`WorldScope::All`].
    ///
    /// Borrowed, not owned, so this config stays `Copy`
    /// ([`CorpusScope::AnyOf`] carries a `Vec`). The referent is
    /// canonicalized ONCE per run before this config is built, so an empty
    /// `AnyOf` fails the run closed before the first candidate is scanned and
    /// the candidate-scan twin stays a pure predicate.
    pub(super) corpus_scope: &'a CorpusScope,
}

#[derive(Default)]
pub(super) struct EntityMetadataCache {
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
pub(super) struct ClaimStatusGateCache {
    pub(super) decisions: HashMap<EntityId, Option<ClaimBody>>,
}

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
    pub(super) fn get(
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

/// Relationship retrieval scope behavior for a query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelMode {
    /// Remove claims bound to another relationship.
    Filter,
    /// Retain other-relationship claims, after all in-scope rows.
    Demote,
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
