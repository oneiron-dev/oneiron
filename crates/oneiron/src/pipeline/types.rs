use std::collections::{BTreeSet, HashMap};

use heed::RoTxn;
use rmpv::Value;

use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::codebase::{CodebaseScopeKey, RepoRef};
use crate::context_pack::EmptyReason;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};
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
    /// The turn's resolved [`WorldScope::ActiveSet`] membership, resolved ONCE
    /// per run under the run's read transaction and borrowed by every
    /// per-candidate check. `None` for every other scope.
    pub(super) world_active_set: Option<&'a WorldAuthoritySet>,
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
    /// The claim-backed per-turn ActiveSet (ONE-1420): reads are restricted to
    /// the base/world members the turn selected, and the selection itself must
    /// sit inside the owner-granted ALLOWED-SET.
    ///
    /// The selection is NOT carried by the variant — it lives on the builder
    /// sidecar written by [`PipelineBuilder::active_worlds`] /
    /// [`PipelineBuilder::default_active_worlds`], because it is per-turn state
    /// that is never stored. Selecting this variant through
    /// [`PipelineBuilder::world`] alone leaves no selection behind and fails
    /// the run closed with [`Error::InvalidConfig`]; it never degrades to
    /// [`WorldScope::All`].
    ActiveSet,
}

/// Pinned schema version of both world-access authority claim values
/// (ONE-1420). A stored row carrying any other version fails closed instead of
/// being read under an assumed shape.
pub const WORLD_ACCESS_SCHEMA_VERSION: u64 = 1;

/// Predicate of the OWNER-granted ALLOWED-SET rows — the outer bound on what
/// an agent may ever read.
///
/// Every ACTIVE, APPROVED, USER-STATED row folds by INTERSECTION, so writing
/// another row can only NARROW the grant, and no row at all resolves to the
/// EMPTY authority (never to [`WorldScope::All`]). Ordinary bitemporal CLAIM
/// rows: `valid_from` / `valid_to`, lifecycle, source, approval and
/// supersession all apply, and no new entity type or table is introduced.
pub const PREDICATE_WORLD_ACCESS_ALLOWED_SET: &str = "core.world_access.allowed_set";

/// Predicate of the DEFAULT-SUBSET rows — the selection a turn inherits when
/// it supplies none of its own.
///
/// The active default may be written by the agent itself, which is why the
/// resolver REJECTS a default that exceeds the owner's ALLOWED-SET rather than
/// clamping it: an agent must never reach a wider read through its own
/// default. Consumed only when the turn supplies no explicit selection.
pub const PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET: &str = "core.world_access.default_subset";

/// Hard cap on the world members ONE authority row (or one per-turn selection)
/// may carry. A longer list fails closed rather than being truncated.
pub const MAX_WORLD_ACCESS_MEMBERS: usize = 256;

const WORLD_ACCESS_VALUE_KEY_SCHEMA_VERSION: &str = "schema_version";
const WORLD_ACCESS_VALUE_KEY_INCLUDE_BASE: &str = "include_base";
const WORLD_ACCESS_VALUE_KEY_WORLDS: &str = "worlds";

/// One world-access authority value: base reality plus a sorted, unique set of
/// world ids.
///
/// The same shape carries all three tiers — the owner's ALLOWED-SET, the
/// stored DEFAULT-SUBSET, and the per-turn ActiveSet — so subset checking is
/// one predicate ([`WorldAuthoritySet::is_subset_of`]) rather than three.
/// [`Default`] is the EMPTY authority (`include_base == false`, no worlds):
/// the fail-closed value an absent grant resolves to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorldAuthoritySet {
    /// Whether base reality — claims with no `world` key, and every non-claim
    /// entity — is readable under this set.
    pub include_base: bool,
    /// The readable world ids. Sorted and unique by construction.
    pub worlds: BTreeSet<EntityId>,
}

impl WorldAuthoritySet {
    /// Builds an authority set from any world-id iterator, normalizing it to
    /// sorted-unique order.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the deduplicated membership exceeds
    /// [`MAX_WORLD_ACCESS_MEMBERS`].
    pub fn new(include_base: bool, worlds: impl IntoIterator<Item = EntityId>) -> Result<Self> {
        let worlds: BTreeSet<EntityId> = worlds.into_iter().collect();
        if worlds.len() > MAX_WORLD_ACCESS_MEMBERS {
            return Err(Error::InvalidConfig(format!(
                "world-access set carries {} worlds, above the {MAX_WORLD_ACCESS_MEMBERS} cap",
                worlds.len()
            )));
        }
        Ok(Self {
            include_base,
            worlds,
        })
    }

    /// Whether every member of `self` is also a member of `allowed`.
    ///
    /// Base reality is a MEMBER of this containment, not a side channel:
    /// asking for base without an owner grant for base is a widening and is
    /// refused like any world id would be.
    #[must_use]
    pub fn is_subset_of(&self, allowed: &Self) -> bool {
        (!self.include_base || allowed.include_base) && self.worlds.is_subset(&allowed.worlds)
    }

    /// Whether this authority admits nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.include_base && self.worlds.is_empty()
    }

    /// The narrowing fold of two owner grants: base survives only if BOTH
    /// rows grant it, and a world survives only if BOTH rows list it.
    pub(super) fn intersect(&self, other: &Self) -> Self {
        Self {
            include_base: self.include_base && other.include_base,
            worlds: self.worlds.intersection(&other.worlds).copied().collect(),
        }
    }
}

/// The per-turn world selection carried on [`PipelineBuilder`] — in memory for
/// exactly one query, never written to the vault.
///
/// `agent_ref` names the CLAIM subject whose stored authority rows the
/// resolver reads; it is not itself a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveWorldSelection {
    /// The agent entity the ALLOWED-SET / DEFAULT-SUBSET rows are about.
    pub agent_ref: EntityId,
    /// `None` means use the resolved DEFAULT-SUBSET.
    pub selected: Option<WorldAuthoritySet>,
}

/// The outcome of one authority resolution: the three tiers plus the claim
/// provenance each tier came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedWorldAuthority {
    /// The owner grant: the intersection of every qualifying ALLOWED-SET row.
    pub allowed_set: WorldAuthoritySet,
    /// The stored default, already checked against `allowed_set`.
    pub default_subset: WorldAuthoritySet,
    /// What this turn actually reads: the explicit selection, else the default.
    pub active_set: WorldAuthoritySet,
    /// The ALLOWED-SET claim rows folded into `allowed_set`, in scan order.
    pub allowed_claim_ids: Vec<EntityId>,
    /// The DEFAULT-SUBSET claim row `default_subset` was read from.
    pub default_claim_id: Option<EntityId>,
}

/// Builds the CLAIM body for one world-access authority row.
///
/// The row is an ORDINARY bitemporal claim: subject = the agent entity, value
/// = the pinned strict map, lifecycle = active, and the caller's `source` /
/// `approval` / `valid_from` / `valid_to` verbatim. Writing it goes through the
/// ordinary claim door, so supersession, retraction and the write gate behave
/// exactly as they do for every other claim.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when `predicate` is not one of the two pinned
/// world-access predicates, when the value exceeds
/// [`MAX_WORLD_ACCESS_MEMBERS`], or when the validity window is empty
/// (`valid_to <= valid_from`), which would mint a row that is never in force.
pub fn world_access_claim_body(
    predicate: &'static str,
    agent_ref: EntityId,
    value: &WorldAuthoritySet,
    source: ClaimSource,
    approval: ClaimApprovalStatus,
    valid_from: Option<u64>,
    valid_to: Option<u64>,
) -> Result<ClaimBody> {
    if predicate != PREDICATE_WORLD_ACCESS_ALLOWED_SET
        && predicate != PREDICATE_WORLD_ACCESS_DEFAULT_SUBSET
    {
        return Err(Error::InvalidConfig(format!(
            "{predicate} is not a world-access authority predicate"
        )));
    }
    if value.worlds.len() > MAX_WORLD_ACCESS_MEMBERS {
        return Err(Error::InvalidConfig(format!(
            "world-access set carries {} worlds, above the {MAX_WORLD_ACCESS_MEMBERS} cap",
            value.worlds.len()
        )));
    }
    if let (Some(from), Some(to)) = (valid_from, valid_to)
        && to <= from
    {
        return Err(Error::InvalidConfig(format!(
            "world-access validity window is empty: valid_to {to} does not follow valid_from {from}"
        )));
    }

    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(agent_ref),
        encode_world_access_claim_value(value),
        1.0,
        approval,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(source);
    body.valid_from = valid_from;
    body.valid_to = valid_to;
    Ok(body)
}

/// Encodes an authority set as the pinned strict claim value.
///
/// `worlds` is emitted from the `BTreeSet`, so the array is sorted and unique
/// on the wire by construction — the exact shape
/// [`decode_world_access_claim_value`] admits.
fn encode_world_access_claim_value(value: &WorldAuthoritySet) -> Value {
    Value::Map(vec![
        (
            Value::from(WORLD_ACCESS_VALUE_KEY_SCHEMA_VERSION),
            Value::from(WORLD_ACCESS_SCHEMA_VERSION),
        ),
        (
            Value::from(WORLD_ACCESS_VALUE_KEY_INCLUDE_BASE),
            Value::Boolean(value.include_base),
        ),
        (
            Value::from(WORLD_ACCESS_VALUE_KEY_WORLDS),
            Value::Array(
                value
                    .worlds
                    .iter()
                    .map(|world| Value::Binary(world.as_bytes().to_vec()))
                    .collect(),
            ),
        ),
    ])
}

/// Decodes the strict world-access claim value:
///
/// ```text
/// { "schema_version": 1, "include_base": <bool>, "worlds": [<16-byte binary>, ...] }
/// ```
///
/// Every deviation fails CLOSED with [`Error::InvalidConfig`]: a non-map value,
/// a non-string key, an unknown or duplicated key, a missing key, an
/// unsupported `schema_version`, a non-boolean `include_base`, a non-array
/// `worlds`, an element that is not exactly 16 bytes of MessagePack binary, an
/// out-of-order or duplicated world id, and a list above
/// [`MAX_WORLD_ACCESS_MEMBERS`]. A malformed authority row can therefore never
/// be read as a WIDER authority than it encodes — the read that consulted it
/// refuses instead.
///
/// # Errors
///
/// [`Error::InvalidConfig`] for every shape listed above.
pub fn decode_world_access_claim_value(body: &ClaimBody) -> Result<WorldAuthoritySet> {
    let Value::Map(entries) = &body.value else {
        return Err(invalid_world_access_value("must be a MessagePack map"));
    };

    let mut schema_version: Option<u64> = None;
    let mut include_base: Option<bool> = None;
    let mut worlds: Option<BTreeSet<EntityId>> = None;

    for (key, value) in entries {
        let Some(key) = key.as_str() else {
            return Err(invalid_world_access_value("keys must be strings"));
        };
        match key {
            WORLD_ACCESS_VALUE_KEY_SCHEMA_VERSION => {
                if schema_version.is_some() {
                    return Err(invalid_world_access_value("repeats schema_version"));
                }
                let version = value.as_u64().ok_or_else(|| {
                    invalid_world_access_value("schema_version must be an unsigned integer")
                })?;
                schema_version = Some(version);
            }
            WORLD_ACCESS_VALUE_KEY_INCLUDE_BASE => {
                if include_base.is_some() {
                    return Err(invalid_world_access_value("repeats include_base"));
                }
                let Value::Boolean(flag) = value else {
                    return Err(invalid_world_access_value("include_base must be a boolean"));
                };
                include_base = Some(*flag);
            }
            WORLD_ACCESS_VALUE_KEY_WORLDS => {
                if worlds.is_some() {
                    return Err(invalid_world_access_value("repeats worlds"));
                }
                worlds = Some(decode_world_access_members(value)?);
            }
            _ => {
                return Err(invalid_world_access_value(
                    "carries a key outside schema_version/include_base/worlds",
                ));
            }
        }
    }

    let schema_version =
        schema_version.ok_or_else(|| invalid_world_access_value("is missing schema_version"))?;
    if schema_version != WORLD_ACCESS_SCHEMA_VERSION {
        return Err(Error::InvalidConfig(format!(
            "world-access claim value schema_version {schema_version} is not the supported \
             {WORLD_ACCESS_SCHEMA_VERSION}"
        )));
    }
    let include_base =
        include_base.ok_or_else(|| invalid_world_access_value("is missing include_base"))?;
    let worlds = worlds.ok_or_else(|| invalid_world_access_value("is missing worlds"))?;

    WorldAuthoritySet::new(include_base, worlds)
}

/// Decodes the `worlds` array: strictly ascending 16-byte binary ids, at most
/// [`MAX_WORLD_ACCESS_MEMBERS`] of them.
fn decode_world_access_members(value: &Value) -> Result<BTreeSet<EntityId>> {
    let Value::Array(items) = value else {
        return Err(invalid_world_access_value("worlds must be an array"));
    };
    if items.len() > MAX_WORLD_ACCESS_MEMBERS {
        return Err(Error::InvalidConfig(format!(
            "world-access value lists {} worlds, above the {MAX_WORLD_ACCESS_MEMBERS} cap",
            items.len()
        )));
    }

    let mut members = BTreeSet::new();
    let mut previous: Option<EntityId> = None;
    for item in items {
        let Value::Binary(bytes) = item else {
            return Err(invalid_world_access_value(
                "world ids must be MessagePack binary",
            ));
        };
        let raw: [u8; ENTITY_ID_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid_world_access_value("world ids must be exactly 16 binary bytes"))?;
        let world = EntityId::from_bytes(raw)
            .map_err(|_| invalid_world_access_value("carries a reserved world id"))?;
        if previous.is_some_and(|previous| previous >= world) {
            return Err(invalid_world_access_value(
                "worlds must be sorted ascending and unique",
            ));
        }
        previous = Some(world);
        members.insert(world);
    }
    Ok(members)
}

fn invalid_world_access_value(reason: &str) -> Error {
    Error::InvalidConfig(format!("world-access claim value {reason}"))
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
