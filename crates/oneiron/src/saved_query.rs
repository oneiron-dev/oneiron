//! SAVED_QUERY — durable standing queries with staged evaluation (CA-02).
//!
//! A saved query is a *definition* plus a *staged evaluator*. Stage 1 is a
//! typed, cheap claim/edge expression; stage 2 is a hard expression, a semantic
//! threshold against an exemplar, or a rubric-driven LLM judge. Stage 1 failure
//! prevents every stage-2 call — that ordering is the whole cost model, so it
//! is a structural property of [`SavedQueryEvaluator::evaluate_entity`] rather
//! than a convention.
//!
//! What this module deliberately is NOT:
//!
//! * **Not a projector runtime.** ARCH-0035's `ProjectionState` is design-only.
//!   Membership lives as the CA-01-owned `campaign.member` derived claim plus
//!   entered/exited event rows; verdicts live as evidence-hash-keyed memo rows.
//!   No projector DAG, no live-subscription registry, no OF-241 dependency:
//!   evaluation runs on demand and on bounded wake batches.
//! * **Not a second member model.** [`CampaignMemberValue`] and its optional
//!   `derivation` are owned by `campaign::claims`; this module populates the
//!   derivation and writes through that module's encoder.
//! * **Not a byte allocator.** The structural kind takes a caller-assigned byte
//!   from the CRM band at registration time. There is no constant here, no
//!   `registry.rs` row, and no static byte anywhere in this ticket.
//!
//! ## Where the bytes live
//!
//! `vault_meta` rows do NOT replicate — sync exports entities, edges, and
//! claims. So the split here is by AUTHORITY, not by convenience:
//!
//! * **The definition is a real entity** of the dynamically registered
//!   SAVED_QUERY kind, written through the batch put chokepoint. A dynamic
//!   registration IS writable (`Store::validate_entity_type` accepts it), so
//!   there is no reason for the authority of a saved query to be a node-local
//!   sidecar — a peer that never received the definition could not evaluate,
//!   repair, or even name the query that derived its cohort.
//! * **The membership epoch is replica-convergent.** The `vault_meta` watermark
//!   row is a local fast path; the FLOOR is recomputed from the replicated
//!   `campaign.member` claims, whose CA-01 derivation carries the epoch. A
//!   promoted peer therefore continues the epoch sequence instead of restarting
//!   at 1 (see [`next_membership_epoch`]).
//! * **Memos, event rows, repair receipts, and migration maps stay
//!   node-local.** A memo is a derivation cache, not authority. Event rows are
//!   a local audit projection of transitions whose authoritative record is the
//!   replicated claim chain; losing them on a peer loses history, never truth.
//!
//! ## Principal binding
//!
//! The owner actor stored on the definition is the ONLY evaluation principal.
//! [`create_saved_query`] sets it from the authenticated principal (the request
//! DTO has no owner field, so no caller can choose another owner), and
//! [`update_saved_query`] / [`archive_saved_query`] re-check it before writing.
//! A principal that does not own a query cannot observe that it exists: reads
//! answer `None` and writes answer [`Error::EntityNotFound`], so the lifecycle
//! API leaks nothing to a caller who was never granted the query.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};
use sha2::{Digest, Sha256};

use crate::Vault;
use crate::batch::{BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_ops};
use crate::campaign::CRM_PACK_ID;
use crate::campaign::claims::{
    CampaignMemberDerivation, CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    decode_campaign_member_value, encode_campaign_member_value,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, claim_surfaceable,
    decode_claim_body,
};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{
    BudgetLease, CallEnvelope, ContentPart, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId,
};
use crate::registry::{ENTITY_TYPE_CLAIM, StructuralKindRegistration, TypeByteZone};
use crate::temporal::TimeRange;

/// Stable short-id namespace for SAVED_QUERY entities. Two lowercase ASCII
/// letters per the short-id convention; a namespace token, never a type byte.
pub const SAVED_QUERY_SHORT_ID_PREFIX: &str = "sq";

/// Schema version of the definition shape this build reads and writes.
pub const SAVED_QUERY_SCHEMA_VERSION: u32 = 1;

/// Version token stamped into every [`SavedQueryDerivationEnvelope`]. It names
/// the EVALUATOR, not the definition — the definition's own movement is carried
/// by [`VerdictMemoRow::definition_version`].
const EVALUATOR_VERSION: &str = "saved_query.v1";

/// Upper bound for every bounded text field in this module.
const MAX_TEXT_BYTES: usize = 512;

/// Registers the SAVED_QUERY structural kind for a NEW vault.
///
/// `assigned_type_byte` comes from the byte-space-v3 registration flow run by
/// the vault/pack initializer; this module never chooses, infers, or hard-codes
/// a byte. Mirrors [`crate::campaign::register_campaign_kind`] exactly: the CRM
/// pack has ONE identity, and both kinds enter through the same registrar.
///
/// # Errors
///
/// Propagates the existing registration errors unchanged — a byte outside the
/// `Crm` band yields `StructuralKindZoneViolation`, and a taken byte or prefix
/// yields `StructuralKindTypeByteCollision` / `StructuralKindPrefixCollision`.
/// SAVED_QUERY adds no registration failure mode of its own.
pub fn register_saved_query_kind(
    vault: &Vault,
    assigned_type_byte: u8,
) -> Result<StructuralKindRegistration> {
    vault.register_structural_kind(
        assigned_type_byte,
        SAVED_QUERY_SHORT_ID_PREFIX,
        TypeByteZone::CompiledProduct,
        CRM_PACK_ID,
    )
}

// ---------------------------------------------------------------------------
// Definition data model
// ---------------------------------------------------------------------------

/// A versioned saved-query definition.
///
/// Not serde-derived: [`EntityId`] has no serde impl and `entity_id.rs` is a CA
/// non-claim, so entity references cross the wire as canonical hex through
/// `definition_to_json` / `definition_from_json` — the same door CA-01 uses
/// for `CrmStageValue`.
#[derive(Debug, Clone, PartialEq)]
pub struct SavedQueryDefinition {
    /// Definition schema version.
    pub schema_version: u32,
    /// The principal whose reach bounds every evaluation of this query.
    pub owner_actor: EntityId,
    /// Scope the owner DECLARED. The effective scope is this intersected with
    /// the owner's reach at evaluation time.
    pub scope: QueryScope,
    /// Monotonic version, incremented by every accepted update.
    pub definition_version: u64,
    /// Stage-1 filter.
    pub filter: FilterAst,
    /// Stage-2 matcher.
    pub matcher: MatcherSpec,
    /// Execution policy and wake bounds.
    pub eval: EvalPolicy,
    /// Lifecycle state.
    pub lifecycle: SavedQueryLifecycle,
}

/// World/facet reach.
///
/// An EMPTY axis means "unrestricted on that axis", which is what makes
/// [`QueryScope::intersect`] total: intersecting an unrestricted axis with a
/// restricted one yields the restricted one, and intersecting two disjoint
/// restricted axes yields an axis that is restricted to nothing — the
/// fail-closed case [`QueryScope::is_closed_against`] names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryScope {
    /// WORLD entities in reach; empty means unrestricted.
    pub worlds: Vec<EntityId>,
    /// Facet tokens in reach; empty means unrestricted.
    pub facets: Vec<String>,
}

impl QueryScope {
    /// Intersects a DECLARED scope with a grant scope, per-axis.
    ///
    /// Returns `None` when an axis both sides restricted intersects to nothing:
    /// that is a closed scope, distinct from the unrestricted empty axis, and
    /// the caller must fail closed rather than treat it as "no restriction".
    #[must_use]
    pub fn intersect(&self, grants: &Self) -> Option<Self> {
        let worlds = intersect_axis(&self.worlds, &grants.worlds)?;
        let facets = intersect_axis(&self.facets, &grants.facets)?;
        Some(Self { worlds, facets })
    }

    /// Whether intersecting this DECLARED scope with `grants` closes an axis.
    #[must_use]
    pub fn is_closed_against(&self, grants: &Self) -> bool {
        self.intersect(grants).is_none()
    }

    /// Whether an entity carrying `membership` is inside THIS scope.
    ///
    /// `membership` is the entity's own world/facet reach as
    /// [`SavedQueryEvaluator`] observed it — its `in_world` and `has_facet`
    /// edges, narrowed to this scope. A restricted axis demands a witness on
    /// that axis, so an entity with no world membership at all is OUTSIDE a
    /// world-scoped query rather than universally inside it. An unrestricted
    /// axis admits everything, which is what makes the default scope total.
    #[must_use]
    pub fn admits(&self, membership: &Self) -> bool {
        let axis_admits = |declared: &[EntityId], held: &[EntityId]| {
            declared.is_empty() || held.iter().any(|value| declared.contains(value))
        };
        axis_admits(&self.worlds, &membership.worlds)
            && (self.facets.is_empty()
                || membership
                    .facets
                    .iter()
                    .any(|facet| self.facets.contains(facet)))
    }
}

/// Per-axis intersection with the "empty means unrestricted" rule.
fn intersect_axis<T: Clone + Ord>(declared: &[T], granted: &[T]) -> Option<Vec<T>> {
    let sorted = |values: &[T]| values.iter().cloned().collect::<BTreeSet<T>>();
    match (declared.is_empty(), granted.is_empty()) {
        (true, true) => Some(Vec::new()),
        (true, false) => Some(sorted(granted).into_iter().collect()),
        (false, true) => Some(sorted(declared).into_iter().collect()),
        (false, false) => {
            let granted = sorted(granted);
            let kept = sorted(declared)
                .into_iter()
                .filter(|value| granted.contains(value))
                .collect::<Vec<T>>();
            (!kept.is_empty()).then_some(kept)
        }
    }
}

/// Stage-1 filter expression.
///
/// Every operator is per-entity-decidable by construction. Ranked or
/// global-relative operators are not modeled here AND are named explicitly at
/// parse time (see [`parse_filter_ast`]), so a `top_k` predicate cannot arrive
/// as an unknown-variant error that a permissive reader might later widen.
#[derive(Debug, Clone, PartialEq)]
pub enum FilterAst {
    /// Conjunction. An empty term list is vacuously true.
    All {
        /// Conjuncts.
        terms: Vec<FilterAst>,
    },
    /// Disjunction. An empty term list is vacuously false.
    Any {
        /// Disjuncts.
        terms: Vec<FilterAst>,
    },
    /// Negation.
    Not {
        /// Negated term.
        term: Box<FilterAst>,
    },
    /// Comparison against one claim predicate's live value.
    Claim {
        /// Claim predicate.
        predicate: String,
        /// Comparison operator.
        cmp: ClaimComparison,
        /// Right-hand operand; ignored by [`ClaimComparison::Exists`].
        value: Value,
    },
    /// Existence of an outbound edge of one kind, optionally to a named target.
    EdgeExists {
        /// snake_case `EdgeKind` name.
        edge_kind: String,
        /// Optional exact target; `None` matches any target of that kind.
        target: Option<EntityId>,
    },
}

/// Comparison operators available to a [`FilterAst::Claim`] term.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimComparison {
    /// The predicate has at least one live claim.
    Exists,
    /// Some live value equals the operand.
    Eq,
    /// No live value equals the operand.
    NotEq,
    /// Some live numeric value is less than the operand.
    Lt,
    /// Some live numeric value is at most the operand.
    Lte,
    /// Some live numeric value is greater than the operand.
    Gt,
    /// Some live numeric value is at least the operand.
    Gte,
    /// Some live string contains the operand, or some live array contains it.
    Contains,
}

impl ClaimComparison {
    /// Wire token for this comparison.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exists => "exists",
            Self::Eq => "eq",
            Self::NotEq => "not_eq",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Contains => "contains",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::Exists,
            Self::Eq,
            Self::NotEq,
            Self::Lt,
            Self::Lte,
            Self::Gt,
            Self::Gte,
            Self::Contains,
        ]
        .into_iter()
        .find(|candidate| candidate.as_str() == value)
    }
}

/// Stage-2 matcher.
#[derive(Debug, Clone, PartialEq)]
pub enum MatcherSpec {
    /// A second hard expression over the same evidence.
    Hard {
        /// Expression evaluated after stage 1 passes.
        expression: FilterAst,
    },
    /// Cosine similarity against an exemplar's stored vector.
    SemanticThreshold {
        /// Entity whose vector is the exemplar.
        exemplar_ref: EntityId,
        /// Inclusive floor, in millionths of a unit similarity.
        minimum_similarity_micros: u32,
    },
    /// Owner-supplied rubric adjudicated by a host-injected LLM backend.
    LlmJudge {
        /// `provider/name@revision` model id.
        model_id: String,
        /// Owner-supplied rubric, passed through verbatim.
        rubric: Value,
        /// Owner's version token for the rubric.
        rubric_version: String,
    },
}

/// Execution mode and per-wake bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvalPolicy {
    /// Declared execution mode.
    pub mode: EvalMode,
    /// Hard cap on entities visited per wake batch.
    pub max_entities_per_wake: u32,
    /// Hard cap on stage-2 LLM judgements per wake batch.
    pub max_judges_per_wake: u32,
}

/// Declared execution mode.
///
/// [`Self::Reactive`] is STORED but not wired: reactive delivery adopts OF-241
/// when it exists. Until then every mode executes through the same explicit
/// on-demand and bounded-wake calls, so a reactive query is never silently
/// inert — it is evaluated by whatever calls the evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvalMode {
    /// Re-evaluate when relevant evidence moves.
    Reactive,
    /// Re-evaluate on enrollment epochs / wake batches.
    Wake,
    /// Re-evaluate only when explicitly asked.
    Manual,
}

impl EvalMode {
    /// Wire token for this mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reactive => "reactive",
            Self::Wake => "wake",
            Self::Manual => "manual",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "reactive" => Some(Self::Reactive),
            "wake" => Some(Self::Wake),
            "manual" => Some(Self::Manual),
            _ => None,
        }
    }
}

/// Lifecycle state of a saved query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SavedQueryLifecycle {
    /// Evaluable.
    Active,
    /// Held with a visible error. Pack drift that cannot be repaired lands
    /// here rather than silently disabling or partially evaluating the query.
    Paused {
        /// Operator-visible reason.
        error: String,
    },
    /// Retired. Archive is a transition, not a deletion: the record stays
    /// addressable for ONE-1778.
    Archived,
}

impl SavedQueryLifecycle {
    /// Whether a query in this state may be evaluated.
    #[must_use]
    pub const fn is_evaluable(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Create request. There is no owner field: the owner is bound from the
/// authenticated principal at the write boundary.
#[derive(Debug, Clone, PartialEq)]
pub struct CreateSavedQueryRequest {
    /// Definition schema version.
    pub schema_version: u32,
    /// Declared scope.
    pub scope: QueryScope,
    /// Stage-1 filter.
    pub filter: FilterAst,
    /// Stage-2 matcher.
    pub matcher: MatcherSpec,
    /// Execution policy.
    pub eval: EvalPolicy,
}

/// Update request. Also carries no owner field.
#[derive(Debug, Clone, PartialEq)]
pub struct UpdateSavedQueryRequest {
    /// Version the caller believes is current; the compare half of the CAS.
    pub expected_definition_version: u64,
    /// Replacement scope.
    pub scope: QueryScope,
    /// Replacement stage-1 filter.
    pub filter: FilterAst,
    /// Replacement stage-2 matcher.
    pub matcher: MatcherSpec,
    /// Replacement execution policy.
    pub eval: EvalPolicy,
}

/// A stored saved query.
#[derive(Debug, Clone, PartialEq)]
pub struct SavedQueryRecord {
    /// Identity of the saved query.
    pub query_ref: EntityId,
    /// Current definition.
    pub definition: SavedQueryDefinition,
    /// Creation time.
    pub created_at: u64,
    /// Last accepted write.
    pub updated_at: u64,
}

// ---------------------------------------------------------------------------
// Filter AST parsing and validation
// ---------------------------------------------------------------------------

/// Operators that express ranked or global-relative membership.
///
/// Named explicitly so the rejection is a specific, greppable error instead of
/// a generic "unknown operator". Standing membership must be decidable from one
/// entity's own evidence: a top-K or PPR-score predicate makes one entity's
/// membership depend on every other entity's, which no per-entity evaluator,
/// memo key, or entered/exited event can honestly represent.
const RANKED_OPERATORS: [&str; 8] = [
    "top_k",
    "topk",
    "ppr_score",
    "ppr",
    "rank",
    "percentile",
    "global_count",
    "relative_score",
];

/// Parses a filter AST from its JSON wire form.
///
/// Hand-written rather than derived: `#[serde(tag = "op")]` would collapse
/// `top_k` into one indistinguishable unknown-variant error, and a future
/// `#[serde(other)]` catch-all would silently admit it. Rejection of the ranked
/// family is a named behavior here, not a side effect of the deserializer.
///
/// # Errors
///
/// [`Error::InvalidConfig`] naming the offending operator or field.
pub fn parse_filter_ast(raw: &Value) -> Result<FilterAst> {
    let object = raw
        .as_object()
        .ok_or_else(|| invalid("saved query filter term must be a JSON object"))?;
    let op = object
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("saved query filter term requires a string op"))?;
    if RANKED_OPERATORS.contains(&op) {
        return Err(Error::InvalidConfig(format!(
            "saved query filter operator {op:?} is ranked or global-relative; \
             standing membership must be per-entity-decidable"
        )));
    }
    match op {
        "all" => Ok(FilterAst::All {
            terms: parse_terms(object)?,
        }),
        "any" => Ok(FilterAst::Any {
            terms: parse_terms(object)?,
        }),
        "not" => Ok(FilterAst::Not {
            term: Box::new(parse_filter_ast(
                object
                    .get("term")
                    .ok_or_else(|| invalid("saved query not requires a term"))?,
            )?),
        }),
        "claim" => parse_claim_term(object),
        "edge_exists" => parse_edge_exists_term(object),
        other => Err(Error::InvalidConfig(format!(
            "saved query filter operator {other:?} is not a per-entity-decidable operator"
        ))),
    }
}

fn parse_terms(object: &JsonMap<String, Value>) -> Result<Vec<FilterAst>> {
    object
        .get("terms")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("saved query boolean term requires a terms array"))?
        .iter()
        .map(parse_filter_ast)
        .collect()
}

fn parse_claim_term(object: &JsonMap<String, Value>) -> Result<FilterAst> {
    let predicate = object
        .get("predicate")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("saved query claim term requires a predicate"))?;
    validate_bounded_text(predicate, "claim predicate")?;
    let cmp = object
        .get("cmp")
        .and_then(Value::as_str)
        .and_then(ClaimComparison::parse)
        .ok_or_else(|| invalid("saved query claim term requires a known cmp"))?;
    Ok(FilterAst::Claim {
        predicate: predicate.to_owned(),
        cmp,
        value: object.get("value").cloned().unwrap_or(Value::Null),
    })
}

fn parse_edge_exists_term(object: &JsonMap<String, Value>) -> Result<FilterAst> {
    let edge_kind = object
        .get("edge_kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("saved query edge term requires an edge_kind"))?;
    if edge_kind_from_name(edge_kind).is_none() {
        return Err(Error::InvalidConfig(format!(
            "saved query edge_kind {edge_kind:?} is not a known EdgeKind"
        )));
    }
    let target = match object.get("target") {
        None | Some(Value::Null) => None,
        Some(value) => Some(parse_entity_ref(value)?),
    };
    Ok(FilterAst::EdgeExists {
        edge_kind: edge_kind.to_owned(),
        target,
    })
}

/// Re-checks that a constructed AST is per-entity-decidable.
///
/// [`parse_filter_ast`] already refuses ranked operators, but an AST can also
/// be built in Rust; this is the door every write path calls so both origins
/// meet the same law.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when a term names an unknown edge kind or carries
/// unbounded text.
pub fn validate_per_entity_decidable(ast: &FilterAst) -> Result<()> {
    match ast {
        FilterAst::All { terms } | FilterAst::Any { terms } => {
            terms.iter().try_for_each(validate_per_entity_decidable)
        }
        FilterAst::Not { term } => validate_per_entity_decidable(term),
        FilterAst::Claim { predicate, .. } => {
            validate_bounded_text(predicate, "claim predicate")?;
            if RANKED_OPERATORS.contains(&predicate.as_str()) {
                return Err(invalid("saved query claim predicate is a ranked operator"));
            }
            Ok(())
        }
        FilterAst::EdgeExists { edge_kind, .. } => edge_kind_from_name(edge_kind)
            .map(|_| ())
            .ok_or_else(|| invalid("saved query edge_kind is not a known EdgeKind")),
    }
}

/// The evidence a definition can possibly read.
///
/// Kept sufficient for later OF-241 subscription wiring — a subscriber needs
/// exactly these three axes to know when to wake — without shipping any live
/// subscription runtime now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceDependencies {
    /// Claim predicates read by stage 1 or stage 2.
    pub claim_predicates: Vec<String>,
    /// Edge kinds read by stage 1 or stage 2.
    pub edge_kinds: Vec<String>,
    /// Exemplars whose vectors stage 2 compares against.
    pub semantic_exemplars: Vec<EntityId>,
}

/// Collects the evidence axes a definition reads, deduplicated and sorted.
///
/// This is what makes the evidence hash honest: hashing every claim on an
/// entity would invalidate memos on irrelevant movement, and hashing a
/// hand-listed subset would drift from the AST. The dependency set is DERIVED
/// from the AST and matcher, so the two cannot disagree.
#[must_use]
pub fn filter_dependencies(ast: &FilterAst, matcher: &MatcherSpec) -> EvidenceDependencies {
    let mut predicates = BTreeSet::new();
    let mut edge_kinds = BTreeSet::new();
    let mut exemplars = BTreeSet::new();
    collect_filter_dependencies(ast, &mut predicates, &mut edge_kinds);
    match matcher {
        MatcherSpec::Hard { expression } => {
            collect_filter_dependencies(expression, &mut predicates, &mut edge_kinds);
        }
        MatcherSpec::SemanticThreshold { exemplar_ref, .. } => {
            exemplars.insert(*exemplar_ref);
        }
        // A judge reads the evidence stage 1 already declared; it introduces no
        // axis of its own, and the rubric itself is covered by the definition
        // version rather than by an evidence axis.
        MatcherSpec::LlmJudge { .. } => {}
    }
    EvidenceDependencies {
        claim_predicates: predicates.into_iter().collect(),
        edge_kinds: edge_kinds.into_iter().collect(),
        semantic_exemplars: exemplars.into_iter().collect(),
    }
}

fn collect_filter_dependencies(
    ast: &FilterAst,
    predicates: &mut BTreeSet<String>,
    edge_kinds: &mut BTreeSet<String>,
) {
    match ast {
        FilterAst::All { terms } | FilterAst::Any { terms } => {
            for term in terms {
                collect_filter_dependencies(term, predicates, edge_kinds);
            }
        }
        FilterAst::Not { term } => collect_filter_dependencies(term, predicates, edge_kinds),
        FilterAst::Claim { predicate, .. } => {
            predicates.insert(predicate.clone());
        }
        FilterAst::EdgeExists { edge_kind, .. } => {
            edge_kinds.insert(edge_kind.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// Lifecycle API
// ---------------------------------------------------------------------------

/// Creates a saved query owned by the authenticated principal.
///
/// `owner_actor` is set from `authenticated_principal` and from nowhere else —
/// [`CreateSavedQueryRequest`] has no owner field, so an untrusted request
/// cannot name a different owner even by accident.
///
/// # Errors
///
/// [`Error::InvalidConfig`] when the definition fails validation or the
/// SAVED_QUERY kind is not registered in this vault; storage errors propagate
/// unchanged.
pub fn create_saved_query(
    vault: &Vault,
    authenticated_principal: EntityId,
    request: &CreateSavedQueryRequest,
    now: u64,
) -> Result<SavedQueryRecord> {
    let definition = SavedQueryDefinition {
        schema_version: request.schema_version,
        owner_actor: authenticated_principal,
        scope: request.scope.clone(),
        definition_version: 1,
        filter: request.filter.clone(),
        matcher: request.matcher.clone(),
        eval: request.eval,
        lifecycle: SavedQueryLifecycle::Active,
    };
    validate_definition(&definition)?;
    let record = SavedQueryRecord {
        query_ref: EntityId::now(),
        definition,
        created_at: now,
        updated_at: now,
    };
    let kind = saved_query_type_byte(vault)?;
    vault.with_write_txn(|wtxn| store_record_in_txn(vault, wtxn, &record, kind))?;
    Ok(record)
}

/// Reads a saved query the principal owns.
///
/// A principal that does not own the query gets `Ok(None)` — the same answer as
/// a query that does not exist. Ownership is not a filter applied after the
/// caller already learned the row exists; it IS the read.
///
/// # Errors
///
/// Storage or decode errors propagate unchanged.
pub fn read_saved_query(
    vault: &Vault,
    authenticated_principal: EntityId,
    query_ref: EntityId,
) -> Result<Option<SavedQueryRecord>> {
    Ok(load_record(vault, query_ref)?
        .filter(|record| record.definition.owner_actor == authenticated_principal))
}

/// Replaces a saved query's definition under a version CAS.
///
/// The compare and the write share ONE write transaction. LMDB's single-writer
/// rule serializes the writes but not a compare performed before the writer
/// transaction opens: two callers that both read version 1 outside the txn
/// would both store "version 2", and the first update would vanish with no
/// error. The CAS is only a CAS inside the txn that performs it.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the query is absent OR owned by another
/// principal, [`Error::ConcurrentWrite`] when the expected version is not
/// current, and [`Error::InvalidConfig`] when the replacement fails validation.
pub fn update_saved_query(
    vault: &Vault,
    authenticated_principal: EntityId,
    query_ref: EntityId,
    request: &UpdateSavedQueryRequest,
    now: u64,
) -> Result<SavedQueryRecord> {
    let kind = saved_query_type_byte(vault)?;
    vault.with_write_txn(|wtxn| {
        let mut record =
            owned_record_in_txn(vault, wtxn, authenticated_principal, query_ref, kind)?;
        require_expected_version(&record, request.expected_definition_version)?;
        let definition = SavedQueryDefinition {
            schema_version: record.definition.schema_version,
            owner_actor: record.definition.owner_actor,
            scope: request.scope.clone(),
            definition_version: next_version(record.definition.definition_version)?,
            filter: request.filter.clone(),
            matcher: request.matcher.clone(),
            eval: request.eval,
            // An update is the operator's answer to a paused query, so it
            // clears the pause. Archived is terminal and is not reopened here.
            lifecycle: match record.definition.lifecycle {
                SavedQueryLifecycle::Archived => SavedQueryLifecycle::Archived,
                SavedQueryLifecycle::Active | SavedQueryLifecycle::Paused { .. } => {
                    SavedQueryLifecycle::Active
                }
            },
        };
        validate_definition(&definition)?;
        record.definition = definition;
        record.updated_at = now;
        store_record_in_txn(vault, wtxn, &record, kind)?;
        Ok(record)
    })
}

/// Archives a saved query. A lifecycle transition, never a delete: the record
/// stays readable so ONE-1778 can still address it.
///
/// Shares [`update_saved_query`]'s single-transaction CAS for the same reason.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the query is absent or owned by another
/// principal; [`Error::ConcurrentWrite`] when the expected version is stale.
pub fn archive_saved_query(
    vault: &Vault,
    authenticated_principal: EntityId,
    query_ref: EntityId,
    expected_definition_version: u64,
    now: u64,
) -> Result<SavedQueryRecord> {
    let kind = saved_query_type_byte(vault)?;
    vault.with_write_txn(|wtxn| {
        let mut record =
            owned_record_in_txn(vault, wtxn, authenticated_principal, query_ref, kind)?;
        require_expected_version(&record, expected_definition_version)?;
        record.definition.definition_version = next_version(record.definition.definition_version)?;
        record.definition.lifecycle = SavedQueryLifecycle::Archived;
        record.updated_at = now;
        store_record_in_txn(vault, wtxn, &record, kind)?;
        Ok(record)
    })
}

/// Loads a record the principal owns THROUGH the caller's transaction, or
/// reports it as absent. Ownership is part of the read, not a post-filter.
fn owned_record_in_txn(
    vault: &Vault,
    wtxn: &heed::RwTxn<'_>,
    authenticated_principal: EntityId,
    query_ref: EntityId,
    kind: u8,
) -> Result<SavedQueryRecord> {
    load_record_in_txn(vault, wtxn, query_ref, kind)?
        .filter(|record| record.definition.owner_actor == authenticated_principal)
        .ok_or(Error::EntityNotFound)
}

fn require_expected_version(record: &SavedQueryRecord, expected: u64) -> Result<()> {
    if record.definition.definition_version == expected {
        return Ok(());
    }
    Err(Error::ConcurrentWrite(
        "saved query definition version is not current",
    ))
}

fn next_version(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("saved query definition version"))
}

fn validate_definition(definition: &SavedQueryDefinition) -> Result<()> {
    if definition.schema_version != SAVED_QUERY_SCHEMA_VERSION {
        return Err(invalid("saved query schema_version is unsupported"));
    }
    validate_per_entity_decidable(&definition.filter)?;
    validate_matcher(&definition.matcher)?;
    for facet in &definition.scope.facets {
        validate_bounded_text(facet, "scope facet")?;
    }
    // A zero bound is not "unbounded" and it is not a working budget either: a
    // zero-judge wake would still spend the first judge before the post-hoc
    // count stopped it, and a zero-entity wake reports "exhausted" without
    // visiting anything. Both are budget lies, so the definition never stores
    // one.
    if definition.eval.max_entities_per_wake == 0 || definition.eval.max_judges_per_wake == 0 {
        return Err(invalid("saved query wake bounds must be at least one"));
    }
    Ok(())
}

fn validate_matcher(matcher: &MatcherSpec) -> Result<()> {
    match matcher {
        MatcherSpec::Hard { expression } => validate_per_entity_decidable(expression),
        MatcherSpec::SemanticThreshold {
            minimum_similarity_micros,
            ..
        } => {
            if *minimum_similarity_micros > MICROS_PER_UNIT {
                return Err(invalid(
                    "saved query similarity floor exceeds one unit of similarity",
                ));
            }
            Ok(())
        }
        MatcherSpec::LlmJudge {
            model_id,
            rubric_version,
            ..
        } => {
            ModelId::new(model_id.clone())
                .map_err(|_| invalid("saved query judge model_id is not provider/name@revision"))?;
            validate_bounded_text(rubric_version, "rubric_version")
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence, hashing, and verdict memos
// ---------------------------------------------------------------------------

/// One entity's evidence, narrowed to what a definition declared relevant.
#[derive(Debug, Clone, PartialEq)]
pub struct RelevantEvidence {
    /// The entity this evidence describes.
    pub entity_ref: EntityId,
    /// Live claim values for the declared predicates.
    pub claim_values: Vec<(String, Value)>,
    /// Outbound edge targets for the declared edge kinds.
    pub edge_targets: Vec<(String, EntityId)>,
    /// Per-exemplar fingerprint of the compared vectors. The string is a hex
    /// digest, not prose: its only job is to move when either vector moves, so
    /// a re-embedding invalidates the memo.
    pub semantic_inputs: Vec<(EntityId, String)>,
    /// The entity's OWN world/facet membership, narrowed to the effective
    /// scope. It is evidence, not a read filter: membership is what decides
    /// whether the entity is inside the query's reach at all, and putting it
    /// here is what makes moving between worlds invalidate the memo.
    pub scope_membership: QueryScope,
}

/// The `Of360DerivationEnvelope` shape, mirrored for saved-query verdicts.
///
/// Field-for-field the same envelope `extraction_eval.rs` established. It is
/// copied rather than shared on purpose: generalizing that type into a common
/// envelope would make one struct answerable to two evolving derivations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedQueryDerivationEnvelope {
    /// Hex evidence hash the verdict was derived from.
    pub content_hash: String,
    /// Model id for a judged verdict, or the matcher kind token otherwise.
    pub model_id: String,
    /// Evaluator version token.
    pub version: String,
    /// Hex digest of the canonical matcher specification.
    pub params_hash: String,
}

/// Memo identity: one verdict per (query, entity, evidence).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerdictMemoKey {
    /// The saved query.
    pub query_ref: EntityId,
    /// The entity evaluated.
    pub entity_ref: EntityId,
    /// Hash over the definition version, effective scope, and relevant evidence.
    pub evidence_hash: [u8; EVIDENCE_HASH_LEN],
}

/// A stage-2 verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchVerdict {
    /// The entity is a member.
    Match,
    /// The entity is not a member.
    NoMatch,
}

impl MatchVerdict {
    /// Wire token for this verdict.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::NoMatch => "no_match",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "match" => Some(Self::Match),
            "no_match" => Some(Self::NoMatch),
            _ => None,
        }
    }
}

/// A verdict plus the reason it was reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchDecision {
    /// The verdict.
    pub verdict: MatchVerdict,
    /// Human-readable justification, persisted with the memo.
    pub why: String,
}

/// Result of evaluating one entity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationOutcome {
    /// The decision.
    pub decision: MatchDecision,
    /// Hash the decision is memoized under.
    pub evidence_hash: [u8; EVIDENCE_HASH_LEN],
    /// Whether a stored memo answered without running the matcher.
    pub memo_hit: bool,
}

/// Progress report for a bounded wake batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WakeEvaluationReport {
    /// Entities evaluated in this batch.
    pub evaluated: u32,
    /// Evaluations answered by a memo.
    pub memo_hits: u32,
    /// Stage-2 judgements actually executed.
    pub judges_run: u32,
    /// Last entity visited when a bound stopped the batch early. `None` means
    /// the candidate set was exhausted.
    pub resume_after: Option<EntityId>,
}

/// A persisted verdict memo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictMemoRow {
    /// Memo identity.
    pub key: VerdictMemoKey,
    /// Definition version at evaluation time.
    pub definition_version: u64,
    /// Memoized verdict.
    pub verdict: MatchVerdict,
    /// Memoized justification.
    pub why: String,
    /// Local derivation envelope.
    pub envelope: SavedQueryDerivationEnvelope,
    /// Evaluation timestamp.
    pub evaluated_at: u64,
}

/// SHA-256-sized evidence hashes, matching CA-01's derivation contract.
pub const EVIDENCE_HASH_LEN: usize = 32;

/// One unit of cosine similarity expressed in the micros scale.
const MICROS_PER_UNIT: u32 = 1_000_000;

/// Domain separator for the evidence hash.
const EVIDENCE_HASH_DOMAIN: &[u8] = b"oneiron.saved_query.evidence.v1";

/// Hashes the definition version, its scope, and the relevant evidence.
///
/// Callers pass the definition AS EVALUATED — [`SavedQueryEvaluator`] narrows
/// `scope` to the owner's effective reach before calling. The scope is IN the
/// hash, not merely in the read path: the owner's reach can change without the
/// definition version moving, and a memo that survived that change would answer
/// with a verdict the owner is no longer entitled to. Evidence outside the
/// declared dependency set never reaches this function, which is what keeps
/// irrelevant movement from invalidating memos.
///
/// # Errors
///
/// [`Error::InvariantViolation`] when a claim value cannot be canonicalized.
pub fn compute_evidence_hash(
    definition: &SavedQueryDefinition,
    evidence: &RelevantEvidence,
) -> Result<[u8; EVIDENCE_HASH_LEN]> {
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_HASH_DOMAIN);
    hasher.update(definition.schema_version.to_be_bytes());
    hasher.update(definition.definition_version.to_be_bytes());
    hasher.update(definition.owner_actor.as_bytes());
    hash_scope(&mut hasher, &definition.scope);
    hasher.update(evidence.entity_ref.as_bytes());
    hash_claim_values(&mut hasher, &evidence.claim_values)?;
    hash_edge_targets(&mut hasher, &evidence.edge_targets);
    hash_semantic_inputs(&mut hasher, &evidence.semantic_inputs);
    hash_scope(&mut hasher, &evidence.scope_membership);
    Ok(hasher.finalize().into())
}

fn hash_scope(hasher: &mut Sha256, scope: &QueryScope) {
    hash_len(hasher, scope.worlds.len());
    for world in &scope.worlds {
        hasher.update(world.as_bytes());
    }
    hash_len(hasher, scope.facets.len());
    for facet in &scope.facets {
        hash_bytes(hasher, facet.as_bytes());
    }
}

fn hash_claim_values(hasher: &mut Sha256, values: &[(String, Value)]) -> Result<()> {
    hash_len(hasher, values.len());
    for (predicate, value) in values {
        hash_bytes(hasher, predicate.as_bytes());
        hash_bytes(hasher, &canonical_json_bytes(value)?);
    }
    Ok(())
}

fn hash_edge_targets(hasher: &mut Sha256, targets: &[(String, EntityId)]) {
    hash_len(hasher, targets.len());
    for (kind, target) in targets {
        hash_bytes(hasher, kind.as_bytes());
        hasher.update(target.as_bytes());
    }
}

fn hash_semantic_inputs(hasher: &mut Sha256, inputs: &[(EntityId, String)]) {
    hash_len(hasher, inputs.len());
    for (exemplar, fingerprint) in inputs {
        hasher.update(exemplar.as_bytes());
        hash_bytes(hasher, fingerprint.as_bytes());
    }
}

/// Length-prefixes every variable-length field so no two distinct evidence sets
/// can serialize to the same byte stream.
fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hash_len(hasher, bytes.len());
    hasher.update(bytes);
}

fn hash_len(hasher: &mut Sha256, len: usize) {
    hasher.update((len as u64).to_be_bytes());
}

/// Reads the memo stored under `key`, if any.
///
/// # Errors
///
/// Storage errors propagate; a malformed row is rejected as
/// [`Error::CorruptedIndex`] rather than silently treated as a miss — a memo
/// that cannot be read is not the same as a memo that says "no match".
pub fn verdict_memo(vault: &Vault, key: &VerdictMemoKey) -> Result<Option<VerdictMemoRow>> {
    let Some(raw) = meta_row(vault, &keys::memo(key))? else {
        return Ok(None);
    };
    decode_memo_row(&raw).map(Some)
}

/// Persists a verdict memo.
///
/// # Errors
///
/// Storage errors propagate unchanged.
pub fn put_verdict_memo(vault: &Vault, row: &VerdictMemoRow) -> Result<()> {
    put_meta_row(vault, &keys::memo(&row.key), &encode_memo_row(row)?)
}

// ---------------------------------------------------------------------------
// Staged evaluation
// ---------------------------------------------------------------------------

/// The LLM dependency of a rubric-driven judge.
///
/// Backend, budget lease, and call envelope travel as ONE binding so no caller
/// can present a backend without a lease: the admission token is not an
/// optional decoration on the call, it is half of what makes the call legal.
pub struct SavedQueryJudgeBinding<'a> {
    /// Host-injected backend.
    pub backend: &'a dyn LlmBackend,
    /// Budget admission token.
    pub lease: &'a BudgetLease,
    /// Host-owned call envelope. Model policy is the host's, not this module's.
    pub envelope: &'a CallEnvelope,
}

/// Staged evaluator over one vault.
///
/// `owner_grants` is the saved query owner's reach AT EVALUATION TIME. There is
/// deliberately no viewer/caller principal on this struct: a viewer cannot
/// change membership because a viewer is not an input to it.
pub struct SavedQueryEvaluator<'a> {
    /// Vault the evidence is read from.
    pub vault: &'a Vault,
    /// The owner's reach; intersected with the definition's declared scope.
    pub owner_grants: &'a QueryScope,
    /// Judge dependency; absent means no LLM matcher can run.
    pub judge: Option<SavedQueryJudgeBinding<'a>>,
}

/// One entity evaluation request.
pub struct EvaluationRequest<'a> {
    /// The saved query.
    pub query_ref: EntityId,
    /// Campaign the membership consequence is scoped to.
    pub campaign_ref: EntityId,
    /// Entity being evaluated.
    pub entity_ref: EntityId,
    /// Definition to evaluate.
    pub definition: &'a SavedQueryDefinition,
    /// Why this evaluation is happening.
    pub cause: MembershipCause,
    /// Valid time of the evaluation.
    pub valid_at: u64,
    /// Detection time of the evaluation.
    pub detected_at: u64,
}

/// Whether a stage-2 judge actually ran, tracked so wake batches can honor
/// `max_judges_per_wake` without inferring it from the verdict.
struct StagedOutcome {
    outcome: EvaluationOutcome,
    judge_ran: bool,
}

/// One evidence collection, plus the vectors the fingerprints were taken from.
///
/// Stage 2 scores THESE vectors rather than re-reading them: each
/// `Vault::get_vector` opens its own read transaction, so a re-read could see a
/// re-embedding that landed after fingerprinting and store a verdict derived
/// from new vectors under the old vectors' evidence hash. A memo must be
/// derived from exactly the evidence its key names.
struct CollectedEvidence {
    evidence: RelevantEvidence,
    subject_vector: Option<Vec<f32>>,
    exemplar_vectors: Vec<(EntityId, Option<Vec<f32>>)>,
}

impl SavedQueryEvaluator<'_> {
    /// Evaluates one entity against one definition.
    ///
    /// Order is the cost model: scope gate, evidence, memo, stage 1, stage 2.
    /// Stage 2 is reached from exactly one place — inside the stage-1 success
    /// branch — so a failing filter cannot spend a judge call.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidConfig`] when the query is not evaluable or a judge is
    /// required but unbound; storage and backend errors propagate.
    pub async fn evaluate_entity(
        &self,
        request: &EvaluationRequest<'_>,
    ) -> Result<EvaluationOutcome> {
        self.evaluate_staged(request).await.map(|it| it.outcome)
    }

    async fn evaluate_staged(&self, request: &EvaluationRequest<'_>) -> Result<StagedOutcome> {
        if !request.definition.lifecycle.is_evaluable() {
            return Err(invalid("saved query is not active"));
        }

        // The authorization gate runs FIRST and is never memoized. A memo caches
        // a DERIVATION; caching an authorization outcome would let a verdict
        // outlive the grant that produced it — the owner loses the world, the
        // memo keeps answering "member".
        let Some(effective_scope) = request.definition.scope.intersect(self.owner_grants) else {
            return Self::denied_outcome(request);
        };

        // Evaluate against the definition AS IT WILL ACTUALLY RUN: the declared
        // scope narrowed to the owner's reach. That narrowed scope is what the
        // evidence hash covers, so a grant change the definition version cannot
        // see still invalidates the memo.
        let definition = SavedQueryDefinition {
            scope: effective_scope,
            ..request.definition.clone()
        };
        let collected = self.collect_evidence(&definition, request.entity_ref, request.valid_at)?;
        let evidence_hash = compute_evidence_hash(&definition, &collected.evidence)?;
        let key = VerdictMemoKey {
            query_ref: request.query_ref,
            entity_ref: request.entity_ref,
            evidence_hash,
        };
        if let Some(memo) = verdict_memo(self.vault, &key)? {
            return Ok(StagedOutcome {
                outcome: EvaluationOutcome {
                    decision: MatchDecision {
                        verdict: memo.verdict,
                        why: memo.why,
                    },
                    evidence_hash,
                    memo_hit: true,
                },
                judge_ran: false,
            });
        }

        // Stage 0: the entity must be INSIDE the effective scope. A closed
        // intersection is not the only way to be out of reach — a query
        // declared for world A must not enroll a person who lives in world B or
        // in no world at all, however well that person's claims read. The
        // entity's membership is in the evidence hash, so joining or leaving a
        // world invalidates this verdict instead of freezing it.
        let (decision, judge_ran) = if definition
            .scope
            .admits(&collected.evidence.scope_membership)
        {
            if evaluate_filter(&definition.filter, &collected.evidence) {
                self.run_stage_two(&definition, &collected).await?
            } else {
                (no_match("stage-1 filter did not match"), false)
            }
        } else {
            (no_match("entity is outside the effective scope"), false)
        };

        put_verdict_memo(
            self.vault,
            &VerdictMemoRow {
                key,
                definition_version: definition.definition_version,
                verdict: decision.verdict,
                why: decision.why.clone(),
                envelope: derivation_envelope(&evidence_hash, &definition.matcher)?,
                evaluated_at: request.detected_at,
            },
        )?;
        Ok(StagedOutcome {
            outcome: EvaluationOutcome {
                decision,
                evidence_hash,
                memo_hit: false,
            },
            judge_ran,
        })
    }

    /// The closed-scope answer: no evidence is read, no memo is touched, and the
    /// reported hash is the definition over an EMPTY evidence set — an honest
    /// statement that nothing was examined, and one that cannot collide with the
    /// hash of a verdict derived while the grant still held.
    fn denied_outcome(request: &EvaluationRequest<'_>) -> Result<StagedOutcome> {
        let evidence = RelevantEvidence {
            entity_ref: request.entity_ref,
            claim_values: Vec::new(),
            edge_targets: Vec::new(),
            semantic_inputs: Vec::new(),
            scope_membership: QueryScope::default(),
        };
        Ok(StagedOutcome {
            outcome: EvaluationOutcome {
                decision: no_match("effective scope is closed against owner grants"),
                evidence_hash: compute_evidence_hash(request.definition, &evidence)?,
                memo_hit: false,
            },
            judge_ran: false,
        })
    }

    /// Stage 2. Only ever called from the stage-1 success branch.
    async fn run_stage_two(
        &self,
        definition: &SavedQueryDefinition,
        collected: &CollectedEvidence,
    ) -> Result<(MatchDecision, bool)> {
        let evidence = &collected.evidence;
        match &definition.matcher {
            MatcherSpec::Hard { expression } => Ok((
                if evaluate_filter(expression, evidence) {
                    MatchDecision {
                        verdict: MatchVerdict::Match,
                        why: "hard matcher expression matched".to_owned(),
                    }
                } else {
                    no_match("hard matcher expression did not match")
                },
                false,
            )),
            MatcherSpec::SemanticThreshold {
                exemplar_ref,
                minimum_similarity_micros,
            } => Ok((
                semantic_decision(collected, *exemplar_ref, *minimum_similarity_micros),
                false,
            )),
            MatcherSpec::LlmJudge {
                model_id, rubric, ..
            } => {
                let judge = self.judge.as_ref().ok_or_else(|| {
                    invalid("saved query judge requires an injected backend and budget lease")
                })?;
                let request = judge_request(judge.envelope, model_id, rubric, evidence)?;
                let decision = run_llm_judge(judge.backend, judge.lease, request).await?;
                Ok((decision, true))
            }
        }
    }

    /// Evaluates a bounded slice of a candidate set.
    ///
    /// Degrades with VISIBLE progress: when a bound stops the batch,
    /// [`WakeEvaluationReport::resume_after`] names where to continue. A query
    /// that outruns its budget is never silently disabled.
    ///
    /// # Errors
    ///
    /// [`Error::EntityNotFound`] when the query is absent; evaluation errors
    /// propagate.
    pub async fn evaluate_wake_batch(
        &self,
        query_ref: EntityId,
        candidates: &[EntityId],
        now: u64,
    ) -> Result<WakeEvaluationReport> {
        let record = load_record(self.vault, query_ref)?.ok_or(Error::EntityNotFound)?;
        let mut report = WakeEvaluationReport {
            evaluated: 0,
            memo_hits: 0,
            judges_run: 0,
            resume_after: None,
        };
        // `resume_after` names the last entity actually VISITED, tracked rather
        // than derived from the loop index: an index-relative "previous
        // candidate" reports `None` at index 0, and `None` is documented to
        // mean the candidate set was exhausted.
        let mut last_visited = None;
        for entity_ref in candidates {
            if report.evaluated >= record.definition.eval.max_entities_per_wake {
                report.resume_after = last_visited;
                return Ok(report);
            }
            let staged = self
                .evaluate_staged(&EvaluationRequest {
                    query_ref,
                    campaign_ref: query_ref,
                    entity_ref: *entity_ref,
                    definition: &record.definition,
                    cause: MembershipCause::DataChange,
                    valid_at: now,
                    detected_at: now,
                })
                .await?;
            report.evaluated = report.evaluated.saturating_add(1);
            last_visited = Some(*entity_ref);
            if staged.outcome.memo_hit {
                report.memo_hits = report.memo_hits.saturating_add(1);
            }
            if staged.judge_ran {
                report.judges_run = report.judges_run.saturating_add(1);
                if report.judges_run >= record.definition.eval.max_judges_per_wake {
                    report.resume_after = Some(*entity_ref);
                    return Ok(report);
                }
            }
        }
        Ok(report)
    }

    /// Reads the entity's effective claims and edges, narrowed to the declared
    /// axes and to the effective scope.
    fn collect_evidence(
        &self,
        definition: &SavedQueryDefinition,
        entity_ref: EntityId,
        valid_at: u64,
    ) -> Result<CollectedEvidence> {
        let deps = filter_dependencies(&definition.filter, &definition.matcher);
        let scope_membership = self.scope_membership(entity_ref, &definition.scope)?;
        let claim_values =
            self.relevant_claim_values(entity_ref, &deps.claim_predicates, definition, valid_at)?;
        let edge_targets = self.relevant_edge_targets(entity_ref, &deps.edge_kinds)?;
        let subject_vector = if deps.semantic_exemplars.is_empty() {
            None
        } else {
            self.vault.get_vector(&entity_ref)?
        };
        let mut exemplar_vectors = Vec::with_capacity(deps.semantic_exemplars.len());
        let mut semantic_inputs = Vec::with_capacity(deps.semantic_exemplars.len());
        for exemplar in &deps.semantic_exemplars {
            let against = self.vault.get_vector(exemplar)?;
            semantic_inputs.push((
                *exemplar,
                vector_pair_fingerprint(&subject_vector, &against),
            ));
            exemplar_vectors.push((*exemplar, against));
        }
        Ok(CollectedEvidence {
            evidence: RelevantEvidence {
                entity_ref,
                claim_values,
                edge_targets,
                semantic_inputs,
                scope_membership,
            },
            subject_vector,
            exemplar_vectors,
        })
    }

    /// The entity's own world/facet membership, narrowed to `scope`.
    ///
    /// Worlds come from `in_world` edges and facets from `has_facet` edges,
    /// with a facet spelled as its FACET entity's canonical hex — the same
    /// spelling `gate.rs` uses for a facet reference in a scoped-read grant.
    fn scope_membership(&self, entity_ref: EntityId, scope: &QueryScope) -> Result<QueryScope> {
        if scope.worlds.is_empty() && scope.facets.is_empty() {
            return Ok(QueryScope::default());
        }
        let mut worlds = Vec::new();
        let mut facets = Vec::new();
        for edge in self.vault.edges_out(&entity_ref)? {
            match edge.kind {
                EdgeKind::InWorld if scope.worlds.contains(&edge.target) => {
                    worlds.push(edge.target);
                }
                EdgeKind::HasFacet => {
                    let token = edge.target.to_hex();
                    if scope.facets.contains(&token) {
                        facets.push(token);
                    }
                }
                _ => {}
            }
        }
        worlds.sort_unstable();
        worlds.dedup();
        facets.sort();
        facets.dedup();
        Ok(QueryScope { worlds, facets })
    }

    fn relevant_claim_values(
        &self,
        entity_ref: EntityId,
        predicates: &[String],
        definition: &SavedQueryDefinition,
        valid_at: u64,
    ) -> Result<Vec<(String, Value)>> {
        if predicates.is_empty() {
            return Ok(Vec::new());
        }
        let mut values = Vec::new();
        for edge in self.vault.edges_in(&entity_ref)? {
            if edge.kind != EdgeKind::ClaimOf {
                continue;
            }
            let Some(body) = self.effective_claim_body(&edge.target, valid_at)? else {
                continue;
            };
            if predicates.contains(&body.predicate) && claim_in_scope(&body, &definition.scope) {
                values.push((body.predicate, rmpv_to_json(&body.value)));
            }
        }
        // Claim discovery order is edge-index order; the hash must not depend
        // on it.
        values.sort_by(|left, right| {
            (&left.0, left.1.to_string()).cmp(&(&right.0, right.1.to_string()))
        });
        Ok(values)
    }

    /// The claim body at `claim_ref` IF it is effective truth at `valid_at`.
    ///
    /// "Active" alone is not effective: an `Active` `Proposed` claim is an
    /// unapproved suggestion, a `stale` derived claim is known to be behind its
    /// source, and a claim whose valid-time window has not opened (or has
    /// closed) is not true now. Membership derived from any of those would
    /// enroll a person on evidence the rest of the engine refuses to read, so
    /// this mirrors `claim.rs`'s `claim_surfaceable` plus `comm.rs`'s
    /// valid-time window rather than inventing a looser rule.
    fn effective_claim_body(
        &self,
        claim_ref: &EntityId,
        valid_at: u64,
    ) -> Result<Option<ClaimBody>> {
        if self.vault.get_entity_type(claim_ref)? != Some(ENTITY_TYPE_CLAIM) {
            return Ok(None);
        }
        let Some(raw) = self.vault.get(claim_ref)? else {
            return Ok(None);
        };
        let body = decode_claim_body(&raw, true)?;
        Ok(claim_effective_at(&body, valid_at).then_some(body))
    }

    fn relevant_edge_targets(
        &self,
        entity_ref: EntityId,
        edge_kinds: &[String],
    ) -> Result<Vec<(String, EntityId)>> {
        if edge_kinds.is_empty() {
            return Ok(Vec::new());
        }
        let wanted = edge_kinds
            .iter()
            .filter_map(|name| edge_kind_from_name(name).map(|kind| (kind, name.clone())))
            .collect::<Vec<(EdgeKind, String)>>();
        let mut targets = self
            .vault
            .edges_out(&entity_ref)?
            .into_iter()
            .filter_map(|edge| {
                wanted
                    .iter()
                    .find(|(kind, _)| *kind == edge.kind)
                    .map(|(_, name)| (name.clone(), edge.target))
            })
            .collect::<Vec<_>>();
        targets.sort_unstable();
        Ok(targets)
    }
}

/// Whether a claim contributes to standing state at `at`: the engine's
/// read-admission predicate plus the valid-time window.
fn claim_effective_at(body: &ClaimBody, at: u64) -> bool {
    claim_surfaceable(body)
        && body.valid_from.is_none_or(|from| from <= at)
        && body.valid_to.is_none_or(|to| at <= to)
}

/// Whether a claim's WORLD scope is inside the query's effective scope.
///
/// A world-less claim is base reality and is admitted under any world axis —
/// the same rule `gate.rs`'s `scoped_read_world_matches_claim` applies to a
/// scoped-read grant. A claim scoped to a world OUTSIDE the axis is not
/// evidence this query may read at all.
fn claim_in_scope(body: &ClaimBody, scope: &QueryScope) -> bool {
    match body.world {
        None => true,
        Some(world) => scope.worlds.is_empty() || scope.worlds.contains(&world),
    }
}

/// Scores the vectors the evidence hash was taken from — never a re-read.
fn semantic_decision(
    collected: &CollectedEvidence,
    exemplar_ref: EntityId,
    floor_micros: u32,
) -> MatchDecision {
    let exemplar = collected
        .exemplar_vectors
        .iter()
        .find(|(id, _)| *id == exemplar_ref)
        .and_then(|(_, vector)| vector.as_ref());
    let (Some(subject), Some(exemplar)) = (collected.subject_vector.as_ref(), exemplar) else {
        // No vector is not "dissimilar", it is unknowable — and an unknowable
        // similarity must not admit membership.
        return no_match("semantic matcher found no vector to compare");
    };
    let similarity = cosine_similarity_micros(subject, exemplar);
    if similarity >= floor_micros {
        MatchDecision {
            verdict: MatchVerdict::Match,
            why: format!("similarity {similarity} reached floor {floor_micros}"),
        }
    } else {
        no_match(&format!(
            "similarity {similarity} below floor {floor_micros}"
        ))
    }
}

/// Adjudicates one rubric through a host-injected backend.
///
/// The backend and the lease are both required arguments, so a judged verdict
/// cannot be produced without budget admission. The response must be a JSON
/// object naming a closed-set verdict; free prose is a decode failure, not a
/// coin flip.
///
/// # Errors
///
/// [`Error::UpstreamToolFailure`] when the backend fails or answers off-schema.
pub async fn run_llm_judge(
    backend: &dyn LlmBackend,
    lease: &BudgetLease,
    request: LlmRequest,
) -> Result<MatchDecision> {
    let response = backend
        .generate(request, lease)
        .await
        .map_err(|error| judge_failure(error.to_string()))?;
    let text = response
        .message
        .content
        .iter()
        .find_map(|part| match part {
            ContentPart::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .ok_or_else(|| judge_failure("response carried no text part".to_owned()))?;
    decode_judge_decision(text)
}

fn decode_judge_decision(text: &str) -> Result<MatchDecision> {
    let parsed = serde_json::from_str::<Value>(text)
        .map_err(|_| judge_failure("response is not JSON".to_owned()))?;
    let verdict = parsed
        .get("verdict")
        .and_then(Value::as_str)
        .and_then(MatchVerdict::parse)
        .ok_or_else(|| judge_failure("verdict is not match/no_match".to_owned()))?;
    let why = parsed
        .get("why")
        .and_then(Value::as_str)
        .ok_or_else(|| judge_failure("response carried no why".to_owned()))?;
    Ok(MatchDecision {
        verdict,
        why: why.chars().take(MAX_TEXT_BYTES).collect(),
    })
}

/// Builds the judge request from the host's envelope and the owner's rubric.
///
/// No prompt text is authored here: the system message IS the owner's rubric
/// and the user message IS the evidence, both as canonical JSON. This module
/// selects no provider and writes no instructions.
fn judge_request(
    envelope: &CallEnvelope,
    model_id: &str,
    rubric: &Value,
    evidence: &RelevantEvidence,
) -> Result<LlmRequest> {
    let model = ModelId::new(model_id.to_owned())
        .map_err(|_| invalid("saved query judge model_id is not provider/name@revision"))?;
    Ok(LlmRequest {
        model,
        envelope: envelope.clone(),
        messages: vec![
            json_message(LlmMessageRole::System, rubric)?,
            json_message(LlmMessageRole::User, &evidence_to_json(evidence))?,
        ],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
    })
}

fn json_message(role: LlmMessageRole, value: &Value) -> Result<LlmMessage> {
    let bytes = canonical_json_bytes(value)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| Error::InvariantViolation("canonical JSON is not UTF-8"))?;
    Ok(LlmMessage {
        role,
        content: vec![ContentPart::Text { text }],
    })
}

/// The judge's view of the evidence.
///
/// Claims are PAIRS, not a predicate-keyed object: an entity can carry two live
/// values for one predicate, and a map would silently show the judge only the
/// last one while the evidence hash covered both. What the judge reads and what
/// the memo key hashes have to be the same evidence.
fn evidence_to_json(evidence: &RelevantEvidence) -> Value {
    let pairs = |entries: &mut dyn Iterator<Item = (String, Value)>| {
        Value::Array(
            entries
                .map(|(left, right)| Value::Array(vec![Value::String(left), right]))
                .collect(),
        )
    };
    let mut root = JsonMap::new();
    root.insert(
        "entity".to_owned(),
        Value::String(evidence.entity_ref.to_hex()),
    );
    root.insert(
        "claims".to_owned(),
        pairs(
            &mut evidence
                .claim_values
                .iter()
                .map(|(predicate, value)| (predicate.clone(), value.clone())),
        ),
    );
    root.insert(
        "edges".to_owned(),
        pairs(
            &mut evidence
                .edge_targets
                .iter()
                .map(|(kind, target)| (kind.clone(), Value::String(target.to_hex()))),
        ),
    );
    Value::Object(root)
}

fn derivation_envelope(
    evidence_hash: &[u8; EVIDENCE_HASH_LEN],
    matcher: &MatcherSpec,
) -> Result<SavedQueryDerivationEnvelope> {
    let model_id = match matcher {
        MatcherSpec::Hard { .. } => "hard".to_owned(),
        MatcherSpec::SemanticThreshold { .. } => "semantic_threshold".to_owned(),
        MatcherSpec::LlmJudge { model_id, .. } => model_id.clone(),
    };
    let params = canonical_json_bytes(&matcher_to_json(matcher))?;
    Ok(SavedQueryDerivationEnvelope {
        content_hash: hex_lower(evidence_hash),
        model_id,
        version: EVALUATOR_VERSION.to_owned(),
        params_hash: hex_lower(&Sha256::digest(&params)),
    })
}

/// Every judge rejection names ONE tool, so an operator grepping for judge
/// failures finds all of them.
fn judge_failure(code: String) -> Error {
    Error::UpstreamToolFailure {
        tool: "saved_query.judge",
        code,
    }
}

fn no_match(why: &str) -> MatchDecision {
    MatchDecision {
        verdict: MatchVerdict::NoMatch,
        why: why.to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Stage-1 expression evaluation
// ---------------------------------------------------------------------------

fn evaluate_filter(ast: &FilterAst, evidence: &RelevantEvidence) -> bool {
    match ast {
        FilterAst::All { terms } => terms.iter().all(|term| evaluate_filter(term, evidence)),
        FilterAst::Any { terms } => terms.iter().any(|term| evaluate_filter(term, evidence)),
        FilterAst::Not { term } => !evaluate_filter(term, evidence),
        FilterAst::Claim {
            predicate,
            cmp,
            value,
        } => evaluate_claim_term(evidence, predicate, *cmp, value),
        FilterAst::EdgeExists { edge_kind, target } => {
            evidence.edge_targets.iter().any(|(kind, edge_target)| {
                kind == edge_kind && target.is_none_or(|wanted| wanted == *edge_target)
            })
        }
    }
}

fn evaluate_claim_term(
    evidence: &RelevantEvidence,
    predicate: &str,
    cmp: ClaimComparison,
    operand: &Value,
) -> bool {
    let mut matching = evidence
        .claim_values
        .iter()
        .filter(|(candidate, _)| candidate == predicate)
        .map(|(_, value)| value)
        .peekable();
    match cmp {
        ClaimComparison::Exists => matching.peek().is_some(),
        // NotEq is "no live value equals the operand" — the restrictive
        // reading. An entity with two values, one equal, must not satisfy both
        // Eq and NotEq for the same predicate.
        ClaimComparison::NotEq => !matching.any(|value| value == operand),
        ClaimComparison::Eq => matching.any(|value| value == operand),
        ClaimComparison::Contains => matching.any(|value| json_contains(value, operand)),
        ClaimComparison::Lt | ClaimComparison::Lte | ClaimComparison::Gt | ClaimComparison::Gte => {
            let Some(bound) = operand.as_f64() else {
                return false;
            };
            matching.filter_map(Value::as_f64).any(|value| match cmp {
                ClaimComparison::Lt => value < bound,
                ClaimComparison::Lte => value <= bound,
                ClaimComparison::Gt => value > bound,
                _ => value >= bound,
            })
        }
    }
}

fn json_contains(value: &Value, operand: &Value) -> bool {
    match (value, operand) {
        (Value::String(haystack), Value::String(needle)) => haystack.contains(needle.as_str()),
        (Value::Array(values), _) => values.contains(operand),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Membership events and the commit boundary
// ---------------------------------------------------------------------------

/// Why a membership transition happened. A CLOSED set: an unknown cause fails
/// decoding rather than becoming an opaque token nobody can route on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipCause {
    /// The entity's own evidence moved.
    DataChange,
    /// The owner's effective reach moved.
    ScopeChange,
    /// The query definition moved.
    DefinitionChange,
}

impl MembershipCause {
    /// Every cause, in wire order.
    pub const ALL: [Self; 3] = [Self::DataChange, Self::ScopeChange, Self::DefinitionChange];

    /// Wire token for this cause.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DataChange => "data_change",
            Self::ScopeChange => "scope_change",
            Self::DefinitionChange => "definition_change",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|cause| cause.as_str() == value)
    }
}

/// Direction of a membership transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipTransition {
    /// The entity joined the cohort.
    Entered,
    /// The entity left the cohort.
    Exited,
}

impl MembershipTransition {
    /// Wire token for this transition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Entered => "entered",
            Self::Exited => "exited",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "entered" => Some(Self::Entered),
            "exited" => Some(Self::Exited),
            _ => None,
        }
    }
}

/// One entered/exited event row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipEvent {
    /// Query that derived the transition.
    pub query_ref: EntityId,
    /// Campaign the membership is scoped to.
    pub campaign_ref: EntityId,
    /// Entity whose membership changed.
    pub entity_ref: EntityId,
    /// Monotonic per-(query, entity) epoch.
    pub epoch: u64,
    /// When the transition became true.
    pub valid_at: u64,
    /// When the engine detected it.
    pub detected_at: u64,
    /// Direction.
    pub transition: MembershipTransition,
    /// Cause.
    pub cause: MembershipCause,
    /// Evidence the verdict was derived from.
    pub evidence_hash: [u8; EVIDENCE_HASH_LEN],
}

/// An event plus the CA-01 claim value it must be written with.
///
/// ONE-1774 builds this after home-node admission and hands it to
/// [`commit_membership_plan`]; the two halves travel together so the commit can
/// prove they agree before either lands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipWritePlan {
    /// The event row.
    pub event: MembershipEvent,
    /// The `campaign.member` value, carrying the matching derivation.
    pub value: CampaignMemberValue,
}

/// What a commit did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipCommitOutcome {
    /// The plan landed.
    Applied,
    /// The exact same plan had already landed at this epoch.
    AlreadyApplied,
    /// The plan's epoch is behind the watermark, or conflicts with it.
    RejectedStaleEpoch {
        /// Watermark that rejected the plan.
        current_epoch: u64,
    },
}

/// The next epoch a transition on this `(query, entity)` pair may claim.
///
/// Re-entry after exit is a NEW epoch, never a resurrection of the old one, and
/// this is the only door that mints one. The floor is
/// `current_watermark`-derived, so a node that was promoted to home after a
/// failover continues the sequence its peers already replicated instead of
/// restarting at 1 against `campaign.member` claims that carry later epochs.
///
/// # Errors
///
/// Storage errors propagate; [`Error::ArithmeticOverflow`] at `u64::MAX`.
pub fn next_membership_epoch(
    vault: &Vault,
    query_ref: EntityId,
    entity_ref: EntityId,
) -> Result<u64> {
    let rtxn = vault.store.env.read_txn()?;
    let current = current_watermark(vault, &rtxn, query_ref, entity_ref)?;
    current.map_or(Ok(1), |(epoch, _)| {
        epoch
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("membership epoch"))
    })
}

/// Commits one membership transition atomically.
///
/// Watermark-guarded, not dedupe-guarded. The distinction is the whole point:
/// a queue that de-duplicates by payload would report a REPLAYED `Entered` from
/// before an exit as "already applied" and leave the cohort holding a
/// resurrected member. Here the compare is against a monotonic watermark inside
/// the same transaction as the write, so a stale `Entered` after exit/re-entry
/// is [`MembershipCommitOutcome::RejectedStaleEpoch`], never `AlreadyApplied`.
///
/// # Errors
///
/// [`Error::InvalidClaimBody`] when the event and the claim value disagree;
/// claim-validation and storage errors propagate.
pub fn commit_membership_plan(
    vault: &Vault,
    plan: &MembershipWritePlan,
    now: u64,
) -> Result<MembershipCommitOutcome> {
    validate_plan_coherence(plan)?;
    let content = plan_content_digest(plan)?;
    let event = &plan.event;
    let claim_body = ClaimBody::new(
        PREDICATE_CAMPAIGN_MEMBER,
        ClaimSubject::Entity(event.entity_ref),
        encode_campaign_member_value(&plan.value),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    );
    let encoded_event = encode_event(event)?;
    vault.with_write_txn(|wtxn| {
        let watermark = current_watermark(vault, wtxn, event.query_ref, event.entity_ref)?;
        if let Some(outcome) = watermark_verdict(watermark, event.epoch, &content) {
            return Ok(outcome);
        }
        // The prior heads are read BEFORE the replacement lands, so the
        // replacement is never its own competition.
        let superseded = live_member_heads_in_txn(
            vault,
            wtxn,
            event.query_ref,
            event.campaign_ref,
            event.entity_ref,
        )?;
        vault.store.vault_meta.put(
            wtxn,
            &keys::watermark(&event.query_ref, &event.entity_ref),
            &encode_watermark(event.epoch, &content),
        )?;
        vault.store.vault_meta.put(
            wtxn,
            &keys::event(&event.query_ref, &event.entity_ref, event.epoch),
            &encoded_event,
        )?;
        let claim_id = EntityId::now();
        vault.put_claim_in_txn(
            wtxn,
            &claim_id,
            &claim_body,
            TimeRange {
                start: event.valid_at,
                end: event.valid_at,
            },
            now,
        )?;
        // A transition REPLACES the cohort head; it does not add a second one.
        // Without this, Entered(1) -> Exited(2) -> Entered(3) would leave three
        // live `campaign.member` claims on the person carrying mutually
        // incompatible states, and `claims_for_subject` would expose all three
        // as current truth. Same-txn supersession is the CA-01 `crm.stage`
        // pattern: a rejection rolls the replacement back with it.
        for old_id in superseded {
            vault.supersede_claim_in_txn(wtxn, &claim_id, &old_id, now)?;
        }
        Ok(MembershipCommitOutcome::Applied)
    })
}

/// `None` means "proceed"; `Some` is the terminal outcome.
///
/// `stored` is the content digest of the plan the watermark records, and is
/// absent when the watermark came from the replicated claim chain rather than
/// this node's own row. An unprovable retry is a stale epoch, never
/// `AlreadyApplied`: reporting success for a plan this node cannot show it
/// applied is the one answer the watermark exists to prevent.
fn watermark_verdict(
    watermark: Option<(u64, Option<[u8; EVIDENCE_HASH_LEN]>)>,
    epoch: u64,
    content: &[u8; EVIDENCE_HASH_LEN],
) -> Option<MembershipCommitOutcome> {
    let (current_epoch, stored) = watermark?;
    if epoch > current_epoch {
        return None;
    }
    if epoch == current_epoch && stored == Some(*content) {
        return Some(MembershipCommitOutcome::AlreadyApplied);
    }
    Some(MembershipCommitOutcome::RejectedStaleEpoch { current_epoch })
}

/// Live `campaign.member` claim ids on `entity_ref` derived from this
/// `(query, campaign)` pair — the heads a new transition must close.
fn live_member_heads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query_ref: EntityId,
    campaign_ref: EntityId,
    entity_ref: EntityId,
) -> Result<Vec<EntityId>> {
    let mut heads = Vec::new();
    for claim_id in vault.claims_for_subject_in_txn(txn, &entity_ref)? {
        let Some((body, value)) = member_claim_in_txn(vault, txn, &claim_id)? else {
            continue;
        };
        if body.lifecycle != ClaimLifecycleStatus::Active || value.campaign != campaign_ref {
            continue;
        }
        if value
            .derivation
            .is_some_and(|derivation| derivation.source_query == query_ref)
        {
            heads.push(claim_id);
        }
    }
    Ok(heads)
}

/// Decodes the `campaign.member` claim at `claim_id`, or `None` when the row is
/// absent, is not a CLAIM, or carries another predicate.
fn member_claim_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim_id: &EntityId,
) -> Result<Option<(ClaimBody, CampaignMemberValue)>> {
    let Some(raw) = vault.store.entities.get(txn, claim_id.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("saved query member claim header"));
    };
    if header.entity_type != ENTITY_TYPE_CLAIM {
        return Ok(None);
    }
    let body = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
    if body.predicate != PREDICATE_CAMPAIGN_MEMBER {
        return Ok(None);
    }
    let value = decode_campaign_member_value(&body.value)?;
    Ok(Some((body, value)))
}

/// Proves the event and the CA-01 claim value describe the same transition.
fn validate_plan_coherence(plan: &MembershipWritePlan) -> Result<()> {
    let event = &plan.event;
    if plan.value.campaign != event.campaign_ref {
        return Err(Error::InvalidClaimBody(
            "membership plan campaign does not match the event",
        ));
    }
    let derivation = plan
        .value
        .derivation
        .as_ref()
        .ok_or(Error::InvalidClaimBody(
            "derived membership requires a derivation",
        ))?;
    if derivation.source_query != event.query_ref
        || derivation.evidence_hash != event.evidence_hash
        || derivation.epoch != event.epoch
    {
        return Err(Error::InvalidClaimBody(
            "membership derivation does not match the event",
        ));
    }
    let exited = plan.value.state == CampaignMemberState::Exited;
    if (event.transition == MembershipTransition::Exited) != exited {
        return Err(Error::InvalidClaimBody(
            "membership transition does not match the member state",
        ));
    }
    Ok(())
}

/// Digest over everything a replay must reproduce EXACTLY to count as the same
/// plan. Two plans that differ anywhere here are different plans at the same
/// epoch, which is a conflict rather than a retry.
fn plan_content_digest(plan: &MembershipWritePlan) -> Result<[u8; EVIDENCE_HASH_LEN]> {
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.saved_query.plan.v1");
    hash_bytes(&mut hasher, &encode_event(&plan.event)?);
    hash_bytes(&mut hasher, &encode_member_value_bytes(&plan.value)?);
    Ok(hasher.finalize().into())
}

/// Builds the CA-01 member value for a derived membership.
///
/// The derivation is composed HERE, from the event, so the two cannot drift:
/// a caller that hand-built both halves could put a different epoch in each.
#[must_use]
pub fn derived_member_value(
    event: &MembershipEvent,
    state: CampaignMemberState,
    channels: Vec<crate::campaign::claims::CampaignMemberChannel>,
) -> CampaignMemberValue {
    CampaignMemberValue {
        campaign: event.campaign_ref,
        state,
        channels,
        derivation: Some(CampaignMemberDerivation {
            source_query: event.query_ref,
            evidence_hash: event.evidence_hash,
            epoch: event.epoch,
        }),
    }
}

/// Reads the entered/exited history for one `(query, entity)` pair, oldest
/// epoch first. History is preserved: a re-entry appends, it never rewrites.
///
/// # Errors
///
/// Storage errors propagate; a malformed row is [`Error::CorruptedIndex`].
pub fn membership_events(
    vault: &Vault,
    query_ref: EntityId,
    entity_ref: EntityId,
) -> Result<Vec<MembershipEvent>> {
    let rtxn = vault.store.env.read_txn()?;
    let prefix = keys::event_prefix(&query_ref, &entity_ref);
    let mut events = Vec::new();
    for row in vault.store.vault_meta.prefix_iter(&rtxn, &prefix)? {
        let (_, value) = row?;
        events.push(decode_event(&value)?);
    }
    Ok(events)
}

// ---------------------------------------------------------------------------
// Pack drift repair ladder
// ---------------------------------------------------------------------------

/// A pack version move that touches predicates a query reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackDrift {
    /// Pack the definition was written against.
    pub from_pack_id: String,
    /// Version the definition was written against.
    pub from_version: String,
    /// Pack now installed.
    pub to_pack_id: String,
    /// Version now installed.
    pub to_version: String,
    /// Predicates whose meaning or spelling moved.
    pub affected_predicates: Vec<String>,
}

/// How one affected predicate can be carried across a pack move.
///
/// The CLASSIFICATION lives on the map entry, supplied by whoever authored the
/// pack move, because only that author knows whether a rename preserves
/// meaning. The engine's job is to apply the ladder faithfully, not to guess.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PackPredicateRewrite {
    /// Pure rename. Auto-migrates.
    Rename {
        /// New predicate.
        to: String,
    },
    /// Different spelling, same meaning. Auto-rewrites with a notice.
    Equivalent {
        /// New predicate.
        to: String,
        /// Notice recorded on the receipt.
        note: String,
    },
    /// Meaning changed. Requires an owner proposal.
    SemanticsChanging {
        /// Proposed new predicate.
        to: String,
        /// What changed.
        note: String,
    },
}

/// Per-predicate rewrites for one pack move.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackMigrationMap {
    /// Old predicate to its rewrite.
    pub rewrites: BTreeMap<String, PackPredicateRewrite>,
}

/// The rung the repair ladder settled on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackDriftResolution {
    /// Every affected predicate had a rename; the definition was migrated.
    AutoMigrated {
        /// Receipt row recording the migration.
        receipt_ref: EntityId,
    },
    /// A semantics-preserving rewrite was applied with a notice.
    AutoRewritten {
        /// Receipt row recording the rewrite and its notices.
        receipt_ref: EntityId,
    },
    /// A meaning-changing rewrite needs the owner's answer; nothing changed.
    ProposalRequired {
        /// Proposal row the owner rules on.
        proposal_ref: EntityId,
    },
    /// No viable rewrite. The query is paused with a visible error.
    Paused {
        /// Operator-visible reason.
        error: String,
    },
}

/// Records the migration map for one pack move.
///
/// # Errors
///
/// Storage errors propagate unchanged.
pub fn put_pack_migration_map(
    vault: &Vault,
    drift: &PackDrift,
    map: &PackMigrationMap,
) -> Result<()> {
    let encoded = serde_json::to_vec(map)
        .map_err(|_| Error::InvariantViolation("pack migration map encode failed"))?;
    put_meta_row(vault, &keys::migration_map(drift), &encoded)
}

/// Runs the ratified pack-drift ladder, in order.
///
/// Rung order is worst-case-wins across the affected predicates: an unmapped
/// predicate pauses the query even if every other predicate renames cleanly. So
/// the WHOLE affected set is classified before a rung is chosen — returning on
/// the first bad predicate would make the outcome depend on the order the pack
/// author happened to list them in, and could leave a query Active whose other
/// predicate has no rewrite at all. A partially-migrated query would evaluate
/// against a definition nobody wrote, which is the one outcome the ladder
/// exists to prevent.
///
/// `definition` is the snapshot the repair was PLANNED from: the replacement is
/// built from the stored record, and a version that has moved since planning
/// loses rather than overwriting the owner's concurrent update.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the query is absent, [`Error::ConcurrentWrite`]
/// when the plan is stale, [`Error::InvalidConfig`] when the query is archived;
/// storage errors propagate.
pub fn repair_pack_drift(
    vault: &Vault,
    query_ref: EntityId,
    definition: &SavedQueryDefinition,
    drift: &PackDrift,
    now: u64,
) -> Result<PackDriftResolution> {
    let map = load_migration_map(vault, drift)?.unwrap_or_default();
    let mut unmapped = Vec::new();
    let mut proposals = Vec::new();
    let mut renames = BTreeMap::new();
    let mut notices = Vec::new();
    for predicate in &drift.affected_predicates {
        match map.rewrites.get(predicate) {
            None => unmapped.push(predicate.clone()),
            Some(PackPredicateRewrite::SemanticsChanging { to, note }) => {
                proposals.push(format!("{predicate} -> {to} ({note})"));
            }
            Some(PackPredicateRewrite::Rename { to }) => {
                renames.insert(predicate.clone(), to.clone());
            }
            Some(PackPredicateRewrite::Equivalent { to, note }) => {
                renames.insert(predicate.clone(), to.clone());
                notices.push(format!("{predicate} -> {to} ({note})"));
            }
        }
    }
    let moved = format!(
        "pack move {}@{} -> {}@{}",
        drift.from_pack_id, drift.from_version, drift.to_pack_id, drift.to_version
    );
    let kind = saved_query_type_byte(vault)?;
    vault.with_write_txn(|wtxn| {
        let mut record =
            load_record_in_txn(vault, wtxn, query_ref, kind)?.ok_or(Error::EntityNotFound)?;
        if record.definition.definition_version != definition.definition_version {
            return Err(Error::ConcurrentWrite(
                "saved query definition version is not current",
            ));
        }
        if record.definition.lifecycle == SavedQueryLifecycle::Archived {
            return Err(invalid(
                "saved query is archived; pack drift repair does not reopen it",
            ));
        }
        if !unmapped.is_empty() {
            let error = format!(
                "{moved} has no rewrite for predicate(s) {}",
                unmapped.join(", ")
            );
            return pause_in_txn(vault, wtxn, record, kind, error, now);
        }
        if !proposals.is_empty() {
            let summary = format!("proposal: {}", proposals.join("; "));
            return record_repair_in_txn(vault, wtxn, query_ref, drift, &summary, now)
                .map(|proposal_ref| PackDriftResolution::ProposalRequired { proposal_ref });
        }
        let migrated = SavedQueryDefinition {
            filter: rewrite_predicates(&record.definition.filter, &renames),
            matcher: rewrite_matcher(&record.definition.matcher, &renames),
            definition_version: next_version(record.definition.definition_version)?,
            lifecycle: SavedQueryLifecycle::Active,
            ..record.definition.clone()
        };
        // The ladder's own last rung: a rewrite target the write door would
        // never have accepted is no viable rewrite, so it PAUSES rather than
        // being persisted as an active definition nobody could have authored.
        if let Err(error) = validate_definition(&migrated) {
            let error = format!("{moved} produced an invalid definition: {error}");
            return pause_in_txn(vault, wtxn, record, kind, error, now);
        }
        record.definition = migrated;
        record.updated_at = now;
        store_record_in_txn(vault, wtxn, &record, kind)?;
        let summary = if notices.is_empty() {
            format!("auto-migrated {} predicate(s)", renames.len())
        } else {
            format!("auto-rewritten with notices: {}", notices.join("; "))
        };
        let receipt_ref = record_repair_in_txn(vault, wtxn, query_ref, drift, &summary, now)?;
        Ok(if notices.is_empty() {
            PackDriftResolution::AutoMigrated { receipt_ref }
        } else {
            PackDriftResolution::AutoRewritten { receipt_ref }
        })
    })
}

fn pause_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    mut record: SavedQueryRecord,
    kind: u8,
    error: String,
    now: u64,
) -> Result<PackDriftResolution> {
    record.definition.lifecycle = SavedQueryLifecycle::Paused {
        error: error.clone(),
    };
    record.updated_at = now;
    store_record_in_txn(vault, wtxn, &record, kind)?;
    Ok(PackDriftResolution::Paused { error })
}

fn record_repair_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    query_ref: EntityId,
    drift: &PackDrift,
    summary: &str,
    now: u64,
) -> Result<EntityId> {
    let repair_ref = EntityId::now();
    let mut row = JsonMap::new();
    row.insert("query_ref".to_owned(), Value::String(query_ref.to_hex()));
    row.insert("summary".to_owned(), Value::String(summary.to_owned()));
    row.insert("recorded_at".to_owned(), Value::from(now));
    row.insert(
        "drift".to_owned(),
        serde_json::to_value(drift)
            .map_err(|_| Error::InvariantViolation("pack drift encode failed"))?,
    );
    let encoded = canonical_json_bytes(&Value::Object(row))?;
    vault
        .store
        .vault_meta
        .put(wtxn, &keys::repair(&repair_ref), &encoded)?;
    Ok(repair_ref)
}

fn rewrite_predicates(ast: &FilterAst, renames: &BTreeMap<String, String>) -> FilterAst {
    match ast {
        FilterAst::All { terms } => FilterAst::All {
            terms: rewrite_terms(terms, renames),
        },
        FilterAst::Any { terms } => FilterAst::Any {
            terms: rewrite_terms(terms, renames),
        },
        FilterAst::Not { term } => FilterAst::Not {
            term: Box::new(rewrite_predicates(term, renames)),
        },
        FilterAst::Claim {
            predicate,
            cmp,
            value,
        } => FilterAst::Claim {
            predicate: renames
                .get(predicate)
                .cloned()
                .unwrap_or_else(|| predicate.clone()),
            cmp: *cmp,
            value: value.clone(),
        },
        FilterAst::EdgeExists { .. } => ast.clone(),
    }
}

fn rewrite_terms(terms: &[FilterAst], renames: &BTreeMap<String, String>) -> Vec<FilterAst> {
    terms
        .iter()
        .map(|term| rewrite_predicates(term, renames))
        .collect()
}

fn rewrite_matcher(matcher: &MatcherSpec, renames: &BTreeMap<String, String>) -> MatcherSpec {
    match matcher {
        MatcherSpec::Hard { expression } => MatcherSpec::Hard {
            expression: rewrite_predicates(expression, renames),
        },
        other => other.clone(),
    }
}

fn load_migration_map(vault: &Vault, drift: &PackDrift) -> Result<Option<PackMigrationMap>> {
    let Some(raw) = meta_row(vault, &keys::migration_map(drift))? else {
        return Ok(None);
    };
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|_| Error::CorruptedIndex("saved query pack migration map"))
}

// ---------------------------------------------------------------------------
// vault_meta keyspace
// ---------------------------------------------------------------------------

/// Versioned `vault_meta` key builders owned by this module.
///
/// Every prefix carries its own `v1` so a later shape change is a new keyspace
/// rather than a reinterpretation of rows already on disk.
mod keys {
    use super::{EVIDENCE_HASH_LEN, PackDrift, VerdictMemoKey};
    use crate::entity_id::EntityId;

    const MEMO: &[u8] = b"saved_query.memo.v1:";
    const WATERMARK: &[u8] = b"saved_query.epoch.v1:";
    const EVENT: &[u8] = b"saved_query.event.v1:";
    const REPAIR: &[u8] = b"saved_query.repair.v1:";
    const MIGRATION_MAP: &[u8] = b"saved_query.packmap.v1:";

    fn keyed(prefix: &[u8], parts: &[&[u8]]) -> Vec<u8> {
        let mut key =
            Vec::with_capacity(prefix.len() + parts.iter().map(|p| p.len()).sum::<usize>());
        key.extend_from_slice(prefix);
        for part in parts {
            key.extend_from_slice(part);
        }
        key
    }

    pub(super) fn memo(key: &VerdictMemoKey) -> Vec<u8> {
        keyed(
            MEMO,
            &[
                key.query_ref.as_bytes(),
                key.entity_ref.as_bytes(),
                &key.evidence_hash,
            ],
        )
    }

    pub(super) fn watermark(query_ref: &EntityId, entity_ref: &EntityId) -> Vec<u8> {
        keyed(WATERMARK, &[query_ref.as_bytes(), entity_ref.as_bytes()])
    }

    pub(super) fn event_prefix(query_ref: &EntityId, entity_ref: &EntityId) -> Vec<u8> {
        keyed(EVENT, &[query_ref.as_bytes(), entity_ref.as_bytes()])
    }

    /// Big-endian epoch suffix so a prefix scan returns history in epoch order.
    pub(super) fn event(query_ref: &EntityId, entity_ref: &EntityId, epoch: u64) -> Vec<u8> {
        let mut key = event_prefix(query_ref, entity_ref);
        key.extend_from_slice(&epoch.to_be_bytes());
        key
    }

    pub(super) fn repair(repair_ref: &EntityId) -> Vec<u8> {
        keyed(REPAIR, &[repair_ref.as_bytes()])
    }

    pub(super) fn migration_map(drift: &PackDrift) -> Vec<u8> {
        keyed(
            MIGRATION_MAP,
            &[
                drift.from_pack_id.as_bytes(),
                b"@",
                drift.from_version.as_bytes(),
                b"->",
                drift.to_pack_id.as_bytes(),
                b"@",
                drift.to_version.as_bytes(),
            ],
        )
    }

    /// Watermark rows are `epoch || content digest`.
    pub(super) const WATERMARK_ROW_LEN: usize = 8 + EVIDENCE_HASH_LEN;
}

/// Reads one `vault_meta` row into an owned buffer, opening its own read txn.
fn meta_row(vault: &Vault, key: &[u8]) -> Result<Option<Vec<u8>>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(vault
        .store
        .vault_meta
        .get(&rtxn, key)?
        .map(|bytes| bytes.to_vec()))
}

/// Writes one `vault_meta` row in its own write txn. Multi-row writes
/// (the membership commit) keep their own transaction instead.
fn put_meta_row(vault: &Vault, key: &[u8], value: &[u8]) -> Result<()> {
    vault.with_write_txn(|wtxn| vault.store.vault_meta.put(wtxn, key, value))
}

/// The type byte this vault assigned the SAVED_QUERY kind at pack registration.
///
/// Resolved from the vault-scoped registry rather than a constant: the byte is
/// caller-assigned per vault, and this module owns none. A vault that never
/// installed the CRM pack has no namespace to write into, which is a
/// configuration error, not a silent sidecar fallback.
fn saved_query_type_byte(vault: &Vault) -> Result<u8> {
    vault
        .structural_kind_registrations()
        .into_iter()
        .find(|registration| {
            registration.short_id_prefix == SAVED_QUERY_SHORT_ID_PREFIX
                && registration.pack == CRM_PACK_ID
        })
        .map(|registration| registration.type_byte)
        .ok_or_else(|| invalid("saved query kind is not registered in this vault"))
}

/// Reads the SAVED_QUERY entity body through the caller's transaction.
fn load_record_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query_ref: EntityId,
    kind: u8,
) -> Result<Option<SavedQueryRecord>> {
    let Some(raw) = vault.store.entities.get(txn, query_ref.as_bytes())? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Err(Error::CorruptedIndex("saved query entity header"));
    };
    if header.entity_type != kind {
        return Ok(None);
    }
    decode_record(&raw[ENTITY_METADATA_HEADER_LEN..]).map(Some)
}

fn load_record(vault: &Vault, query_ref: EntityId) -> Result<Option<SavedQueryRecord>> {
    let kind = saved_query_type_byte(vault)?;
    let rtxn = vault.store.env.read_txn()?;
    load_record_in_txn(vault, &rtxn, query_ref, kind)
}

/// Writes the definition through the batch put chokepoint, in the caller's
/// transaction, so the definition replicates like every other entity.
fn store_record_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: &SavedQueryRecord,
    kind: u8,
) -> Result<()> {
    apply_ops(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![BatchOp::Put {
            id: record.query_ref,
            entity_type: kind,
            occurred: TimeRange {
                start: record.created_at,
                end: record.updated_at,
            },
            learned_at: record.updated_at,
            data: encode_record(record)?,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        false,
        false,
    )
}

/// The epoch floor this `(query, entity)` pair may not write at or below.
///
/// `vault_meta` does not replicate, so the local watermark row alone is a
/// node-local opinion: a peer promoted to home after a failover would read
/// `None` and restart at epoch 1 while the replicated `campaign.member` claims
/// already carry later epochs. The CA-01 derivation carries the epoch on a
/// claim that DOES replicate, so the claim chain is the convergent floor and
/// the local row is only the fast path that can also prove content equality.
fn current_watermark(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query_ref: EntityId,
    entity_ref: EntityId,
) -> Result<Option<(u64, Option<[u8; EVIDENCE_HASH_LEN]>)>> {
    let local = read_watermark(vault, txn, query_ref, entity_ref)?;
    let replicated = replicated_epoch_floor(vault, txn, query_ref, entity_ref)?;
    Ok(match (local, replicated) {
        (None, None) => None,
        (Some((epoch, content)), None) => Some((epoch, Some(content))),
        (None, Some(floor)) => Some((floor, None)),
        (Some((epoch, content)), Some(floor)) => {
            if floor > epoch {
                Some((floor, None))
            } else {
                Some((epoch, Some(content)))
            }
        }
    })
}

/// Highest epoch any replicated `campaign.member` claim on `entity_ref` carries
/// for `query_ref`. Every lifecycle counts: a superseded head still proves its
/// epoch was spent.
fn replicated_epoch_floor(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    query_ref: EntityId,
    entity_ref: EntityId,
) -> Result<Option<u64>> {
    let mut floor = None;
    for claim_id in vault.claims_for_subject_in_txn(txn, &entity_ref)? {
        let Some((_, value)) = member_claim_in_txn(vault, txn, &claim_id)? else {
            continue;
        };
        if let Some(derivation) = value.derivation
            && derivation.source_query == query_ref
        {
            floor = floor.max(Some(derivation.epoch));
        }
    }
    Ok(floor)
}

fn read_watermark(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    query_ref: EntityId,
    entity_ref: EntityId,
) -> Result<Option<(u64, [u8; EVIDENCE_HASH_LEN])>> {
    let Some(raw) = vault
        .store
        .vault_meta
        .get(rtxn, &keys::watermark(&query_ref, &entity_ref))?
    else {
        return Ok(None);
    };
    decode_watermark(raw.as_ref()).map(Some)
}

fn encode_watermark(epoch: u64, content: &[u8; EVIDENCE_HASH_LEN]) -> Vec<u8> {
    let mut row = Vec::with_capacity(keys::WATERMARK_ROW_LEN);
    row.extend_from_slice(&epoch.to_be_bytes());
    row.extend_from_slice(content);
    row
}

fn decode_watermark(raw: &[u8]) -> Result<(u64, [u8; EVIDENCE_HASH_LEN])> {
    if raw.len() != keys::WATERMARK_ROW_LEN {
        return Err(Error::CorruptedIndex("saved query epoch watermark"));
    }
    let (epoch, content) = raw.split_at(8);
    let epoch = u64::from_be_bytes(
        epoch
            .try_into()
            .map_err(|_| Error::CorruptedIndex("saved query epoch watermark"))?,
    );
    let content = content
        .try_into()
        .map_err(|_| Error::CorruptedIndex("saved query epoch watermark"))?;
    Ok((epoch, content))
}

// ---------------------------------------------------------------------------
// JSON codecs
// ---------------------------------------------------------------------------

fn encode_record(record: &SavedQueryRecord) -> Result<Vec<u8>> {
    let mut root = JsonMap::new();
    root.insert(
        "query_ref".to_owned(),
        Value::String(record.query_ref.to_hex()),
    );
    root.insert(
        "definition".to_owned(),
        definition_to_json(&record.definition)?,
    );
    root.insert("created_at".to_owned(), Value::from(record.created_at));
    root.insert("updated_at".to_owned(), Value::from(record.updated_at));
    canonical_json_bytes(&Value::Object(root))
}

fn decode_record(raw: &[u8]) -> Result<SavedQueryRecord> {
    let value = parse_row(raw, "saved query record")?;
    Ok(SavedQueryRecord {
        query_ref: required_entity_ref(&value, "query_ref", "saved query record")?,
        definition: definition_from_json(
            value
                .get("definition")
                .ok_or(Error::CorruptedIndex("saved query record"))?,
        )?,
        created_at: required_u64(&value, "created_at", "saved query record")?,
        updated_at: required_u64(&value, "updated_at", "saved query record")?,
    })
}

fn definition_to_json(definition: &SavedQueryDefinition) -> Result<Value> {
    let mut root = JsonMap::new();
    root.insert(
        "schema_version".to_owned(),
        Value::from(definition.schema_version),
    );
    root.insert(
        "owner_actor".to_owned(),
        Value::String(definition.owner_actor.to_hex()),
    );
    root.insert("scope".to_owned(), scope_to_json(&definition.scope));
    root.insert(
        "definition_version".to_owned(),
        Value::from(definition.definition_version),
    );
    root.insert("filter".to_owned(), filter_to_json(&definition.filter));
    root.insert("matcher".to_owned(), matcher_to_json(&definition.matcher));
    root.insert(
        "eval".to_owned(),
        serde_json::to_value(definition.eval)
            .map_err(|_| Error::InvariantViolation("saved query eval policy encode failed"))?,
    );
    root.insert(
        "lifecycle".to_owned(),
        serde_json::to_value(&definition.lifecycle)
            .map_err(|_| Error::InvariantViolation("saved query lifecycle encode failed"))?,
    );
    Ok(Value::Object(root))
}

fn definition_from_json(value: &Value) -> Result<SavedQueryDefinition> {
    const CONTEXT: &str = "saved query definition";
    let scope = value.get("scope").ok_or(Error::CorruptedIndex(CONTEXT))?;
    Ok(SavedQueryDefinition {
        schema_version: u32::try_from(required_u64(value, "schema_version", CONTEXT)?)
            .map_err(|_| Error::CorruptedIndex(CONTEXT))?,
        owner_actor: required_entity_ref(value, "owner_actor", CONTEXT)?,
        scope: scope_from_json(scope)?,
        definition_version: required_u64(value, "definition_version", CONTEXT)?,
        filter: parse_filter_ast(value.get("filter").ok_or(Error::CorruptedIndex(CONTEXT))?)
            .map_err(|_| Error::CorruptedIndex(CONTEXT))?,
        matcher: matcher_from_json(value.get("matcher").ok_or(Error::CorruptedIndex(CONTEXT))?)?,
        eval: serde_json::from_value(
            value
                .get("eval")
                .cloned()
                .ok_or(Error::CorruptedIndex(CONTEXT))?,
        )
        .map_err(|_| Error::CorruptedIndex(CONTEXT))?,
        lifecycle: serde_json::from_value(
            value
                .get("lifecycle")
                .cloned()
                .ok_or(Error::CorruptedIndex(CONTEXT))?,
        )
        .map_err(|_| Error::CorruptedIndex(CONTEXT))?,
    })
}

fn scope_to_json(scope: &QueryScope) -> Value {
    let mut root = JsonMap::new();
    root.insert(
        "worlds".to_owned(),
        Value::Array(
            scope
                .worlds
                .iter()
                .map(|world| Value::String(world.to_hex()))
                .collect(),
        ),
    );
    root.insert(
        "facets".to_owned(),
        Value::Array(
            scope
                .facets
                .iter()
                .map(|facet| Value::String(facet.clone()))
                .collect(),
        ),
    );
    Value::Object(root)
}

fn scope_from_json(value: &Value) -> Result<QueryScope> {
    const CONTEXT: &str = "saved query scope";
    let worlds = value
        .get("worlds")
        .and_then(Value::as_array)
        .ok_or(Error::CorruptedIndex(CONTEXT))?
        .iter()
        .map(|world| parse_entity_ref(world).map_err(|_| Error::CorruptedIndex(CONTEXT)))
        .collect::<Result<Vec<_>>>()?;
    let facets = value
        .get("facets")
        .and_then(Value::as_array)
        .ok_or(Error::CorruptedIndex(CONTEXT))?
        .iter()
        .map(|facet| {
            facet
                .as_str()
                .map(str::to_owned)
                .ok_or(Error::CorruptedIndex(CONTEXT))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(QueryScope { worlds, facets })
}

fn filter_to_json(ast: &FilterAst) -> Value {
    let mut root = JsonMap::new();
    match ast {
        FilterAst::All { terms } | FilterAst::Any { terms } => {
            root.insert(
                "op".to_owned(),
                Value::String(
                    if matches!(ast, FilterAst::All { .. }) {
                        "all"
                    } else {
                        "any"
                    }
                    .to_owned(),
                ),
            );
            root.insert(
                "terms".to_owned(),
                Value::Array(terms.iter().map(filter_to_json).collect()),
            );
        }
        FilterAst::Not { term } => {
            root.insert("op".to_owned(), Value::String("not".to_owned()));
            root.insert("term".to_owned(), filter_to_json(term));
        }
        FilterAst::Claim {
            predicate,
            cmp,
            value,
        } => {
            root.insert("op".to_owned(), Value::String("claim".to_owned()));
            root.insert("predicate".to_owned(), Value::String(predicate.clone()));
            root.insert("cmp".to_owned(), Value::String(cmp.as_str().to_owned()));
            root.insert("value".to_owned(), value.clone());
        }
        FilterAst::EdgeExists { edge_kind, target } => {
            root.insert("op".to_owned(), Value::String("edge_exists".to_owned()));
            root.insert("edge_kind".to_owned(), Value::String(edge_kind.clone()));
            root.insert(
                "target".to_owned(),
                target.map_or(Value::Null, |id| Value::String(id.to_hex())),
            );
        }
    }
    Value::Object(root)
}

fn matcher_to_json(matcher: &MatcherSpec) -> Value {
    let mut root = JsonMap::new();
    match matcher {
        MatcherSpec::Hard { expression } => {
            root.insert("kind".to_owned(), Value::String("hard".to_owned()));
            root.insert("expression".to_owned(), filter_to_json(expression));
        }
        MatcherSpec::SemanticThreshold {
            exemplar_ref,
            minimum_similarity_micros,
        } => {
            root.insert(
                "kind".to_owned(),
                Value::String("semantic_threshold".to_owned()),
            );
            root.insert(
                "exemplar_ref".to_owned(),
                Value::String(exemplar_ref.to_hex()),
            );
            root.insert(
                "minimum_similarity_micros".to_owned(),
                Value::from(*minimum_similarity_micros),
            );
        }
        MatcherSpec::LlmJudge {
            model_id,
            rubric,
            rubric_version,
        } => {
            root.insert("kind".to_owned(), Value::String("llm_judge".to_owned()));
            root.insert("model_id".to_owned(), Value::String(model_id.clone()));
            root.insert("rubric".to_owned(), rubric.clone());
            root.insert(
                "rubric_version".to_owned(),
                Value::String(rubric_version.clone()),
            );
        }
    }
    Value::Object(root)
}

fn matcher_from_json(value: &Value) -> Result<MatcherSpec> {
    const CONTEXT: &str = "saved query matcher";
    match value.get("kind").and_then(Value::as_str) {
        Some("hard") => Ok(MatcherSpec::Hard {
            expression: parse_filter_ast(
                value
                    .get("expression")
                    .ok_or(Error::CorruptedIndex(CONTEXT))?,
            )
            .map_err(|_| Error::CorruptedIndex(CONTEXT))?,
        }),
        Some("semantic_threshold") => Ok(MatcherSpec::SemanticThreshold {
            exemplar_ref: required_entity_ref(value, "exemplar_ref", CONTEXT)?,
            minimum_similarity_micros: u32::try_from(required_u64(
                value,
                "minimum_similarity_micros",
                CONTEXT,
            )?)
            .map_err(|_| Error::CorruptedIndex(CONTEXT))?,
        }),
        Some("llm_judge") => Ok(MatcherSpec::LlmJudge {
            model_id: required_string(value, "model_id", CONTEXT)?,
            rubric: value
                .get("rubric")
                .cloned()
                .ok_or(Error::CorruptedIndex(CONTEXT))?,
            rubric_version: required_string(value, "rubric_version", CONTEXT)?,
        }),
        _ => Err(Error::CorruptedIndex(CONTEXT)),
    }
}

fn encode_memo_row(row: &VerdictMemoRow) -> Result<Vec<u8>> {
    let mut root = JsonMap::new();
    root.insert(
        "query_ref".to_owned(),
        Value::String(row.key.query_ref.to_hex()),
    );
    root.insert(
        "entity_ref".to_owned(),
        Value::String(row.key.entity_ref.to_hex()),
    );
    root.insert(
        "evidence_hash".to_owned(),
        Value::String(hex_lower(&row.key.evidence_hash)),
    );
    root.insert(
        "definition_version".to_owned(),
        Value::from(row.definition_version),
    );
    root.insert(
        "verdict".to_owned(),
        Value::String(row.verdict.as_str().to_owned()),
    );
    root.insert("why".to_owned(), Value::String(row.why.clone()));
    root.insert(
        "envelope".to_owned(),
        serde_json::to_value(&row.envelope)
            .map_err(|_| Error::InvariantViolation("saved query envelope encode failed"))?,
    );
    root.insert("evaluated_at".to_owned(), Value::from(row.evaluated_at));
    canonical_json_bytes(&Value::Object(root))
}

fn decode_memo_row(raw: &[u8]) -> Result<VerdictMemoRow> {
    const CONTEXT: &str = "saved query verdict memo";
    let value = parse_row(raw, CONTEXT)?;
    Ok(VerdictMemoRow {
        key: VerdictMemoKey {
            query_ref: required_entity_ref(&value, "query_ref", CONTEXT)?,
            entity_ref: required_entity_ref(&value, "entity_ref", CONTEXT)?,
            evidence_hash: required_hash(&value, "evidence_hash", CONTEXT)?,
        },
        definition_version: required_u64(&value, "definition_version", CONTEXT)?,
        verdict: MatchVerdict::parse(&required_string(&value, "verdict", CONTEXT)?)
            .ok_or(Error::CorruptedIndex(CONTEXT))?,
        why: required_string(&value, "why", CONTEXT)?,
        envelope: serde_json::from_value(
            value
                .get("envelope")
                .cloned()
                .ok_or(Error::CorruptedIndex(CONTEXT))?,
        )
        .map_err(|_| Error::CorruptedIndex(CONTEXT))?,
        evaluated_at: required_u64(&value, "evaluated_at", CONTEXT)?,
    })
}

fn encode_event(event: &MembershipEvent) -> Result<Vec<u8>> {
    let mut root = JsonMap::new();
    root.insert(
        "query_ref".to_owned(),
        Value::String(event.query_ref.to_hex()),
    );
    root.insert(
        "campaign_ref".to_owned(),
        Value::String(event.campaign_ref.to_hex()),
    );
    root.insert(
        "entity_ref".to_owned(),
        Value::String(event.entity_ref.to_hex()),
    );
    root.insert("epoch".to_owned(), Value::from(event.epoch));
    root.insert("valid_at".to_owned(), Value::from(event.valid_at));
    root.insert("detected_at".to_owned(), Value::from(event.detected_at));
    root.insert(
        "transition".to_owned(),
        Value::String(event.transition.as_str().to_owned()),
    );
    root.insert(
        "cause".to_owned(),
        Value::String(event.cause.as_str().to_owned()),
    );
    root.insert(
        "evidence_hash".to_owned(),
        Value::String(hex_lower(&event.evidence_hash)),
    );
    canonical_json_bytes(&Value::Object(root))
}

fn decode_event(raw: &[u8]) -> Result<MembershipEvent> {
    const CONTEXT: &str = "saved query membership event";
    let value = parse_row(raw, CONTEXT)?;
    Ok(MembershipEvent {
        query_ref: required_entity_ref(&value, "query_ref", CONTEXT)?,
        campaign_ref: required_entity_ref(&value, "campaign_ref", CONTEXT)?,
        entity_ref: required_entity_ref(&value, "entity_ref", CONTEXT)?,
        epoch: required_u64(&value, "epoch", CONTEXT)?,
        valid_at: required_u64(&value, "valid_at", CONTEXT)?,
        detected_at: required_u64(&value, "detected_at", CONTEXT)?,
        transition: MembershipTransition::parse(&required_string(&value, "transition", CONTEXT)?)
            .ok_or(Error::CorruptedIndex(CONTEXT))?,
        cause: MembershipCause::parse(&required_string(&value, "cause", CONTEXT)?)
            .ok_or(Error::CorruptedIndex(CONTEXT))?,
        evidence_hash: required_hash(&value, "evidence_hash", CONTEXT)?,
    })
}

fn encode_member_value_bytes(value: &CampaignMemberValue) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &encode_campaign_member_value(value))
        .map_err(|_| Error::InvariantViolation("campaign member value encode failed"))?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Small shared helpers
// ---------------------------------------------------------------------------

fn parse_row(raw: &[u8], context: &'static str) -> Result<Value> {
    serde_json::from_slice(raw).map_err(|_| Error::CorruptedIndex(context))
}

fn required_string(value: &Value, key: &str, context: &'static str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Error::CorruptedIndex(context))
}

fn required_u64(value: &Value, key: &str, context: &'static str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(Error::CorruptedIndex(context))
}

fn required_entity_ref(value: &Value, key: &str, context: &'static str) -> Result<EntityId> {
    let hex = required_string(value, key, context)?;
    EntityId::from_hex(&hex).map_err(|_| Error::CorruptedIndex(context))
}

fn required_hash(
    value: &Value,
    key: &str,
    context: &'static str,
) -> Result<[u8; EVIDENCE_HASH_LEN]> {
    let hex = required_string(value, key, context)?;
    if hex.len() != EVIDENCE_HASH_LEN * 2 {
        return Err(Error::CorruptedIndex(context));
    }
    let mut bytes = [0u8; EVIDENCE_HASH_LEN];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(
            hex.get(index * 2..index * 2 + 2)
                .ok_or(Error::CorruptedIndex(context))?,
            16,
        )
        .map_err(|_| Error::CorruptedIndex(context))?;
    }
    Ok(bytes)
}

/// Canonical-hex entity reference, mirroring CA-01's one-wire-form-per-identity
/// rule: a non-canonical spelling is rejected rather than normalized.
fn parse_entity_ref(value: &Value) -> Result<EntityId> {
    let hex = value
        .as_str()
        .ok_or_else(|| invalid("saved query entity reference must be a hex string"))?;
    let id = EntityId::from_hex(hex)
        .map_err(|_| invalid("saved query entity reference is not a valid entity id"))?;
    if id.to_hex() != hex {
        return Err(invalid("saved query entity reference is not canonical hex"));
    }
    Ok(id)
}

/// Deterministic JSON bytes with recursively sorted object keys.
///
/// The crate builds `serde_json` with `preserve_order`, so its maps are
/// insertion-ordered and `to_vec` alone is NOT canonical. Anything hashed or
/// compared byte-wise has to come through here.
fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>> {
    serde_json::to_vec(&canonicalize_json(value))
        .map_err(|_| Error::InvariantViolation("saved query canonical JSON encode failed"))
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_json).collect()),
        Value::Object(entries) => {
            let sorted = entries
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize_json(value)))
                .collect::<BTreeMap<String, Value>>();
            Value::Object(sorted.into_iter().collect())
        }
        scalar => scalar.clone(),
    }
}

/// Projects a MessagePack claim value into JSON, INJECTIVELY.
///
/// The projection is what gets hashed into the memo key, so two distinct claim
/// values must never land on the same JSON. Binary, Ext, and non-string-keyed
/// maps therefore carry a `$`-tagged wrapper instead of being flattened into a
/// bare string or silently dropped, and a genuine map key that starts with `$`
/// is escaped by doubling it. Without this, `Binary([0x61])` and the literal
/// string `"61"` produce the same bytes and evidence can change type without
/// moving the hash.
fn rmpv_to_json(value: &rmpv::Value) -> Value {
    match value {
        rmpv::Value::Nil => Value::Null,
        rmpv::Value::Boolean(flag) => Value::Bool(*flag),
        rmpv::Value::Integer(number) => number
            .as_i64()
            .map(Value::from)
            .or_else(|| number.as_u64().map(Value::from))
            .or_else(|| {
                number
                    .as_f64()
                    .and_then(serde_json::Number::from_f64)
                    .map(Value::Number)
            })
            .unwrap_or(Value::Null),
        rmpv::Value::F32(number) => json_number(f64::from(*number)),
        rmpv::Value::F64(number) => json_number(*number),
        // A non-UTF-8 MessagePack string is bytes, so it is tagged as bytes
        // rather than collapsing to null alongside every other undecodable
        // value.
        rmpv::Value::String(text) => text.as_str().map_or_else(
            || tagged_json("$bin", Value::String(hex_lower(text.as_bytes()))),
            |text| Value::String(text.to_owned()),
        ),
        rmpv::Value::Binary(bytes) => tagged_json("$bin", Value::String(hex_lower(bytes))),
        rmpv::Value::Array(values) => Value::Array(values.iter().map(rmpv_to_json).collect()),
        rmpv::Value::Map(entries) => rmpv_map_to_json(entries),
        rmpv::Value::Ext(tag, bytes) => tagged_json(
            "$ext",
            Value::Array(vec![Value::from(*tag), Value::String(hex_lower(bytes))]),
        ),
    }
}

fn rmpv_map_to_json(entries: &[(rmpv::Value, rmpv::Value)]) -> Value {
    if entries.iter().all(|(key, _)| key.as_str().is_some()) {
        return Value::Object(
            entries
                .iter()
                .filter_map(|(key, value)| {
                    key.as_str()
                        .map(|key| (escape_json_key(key), rmpv_to_json(value)))
                })
                .collect(),
        );
    }
    // A map with non-string keys has no lossless JSON object form; erasing
    // those entries would let the map change without moving the hash.
    tagged_json(
        "$map",
        Value::Array(
            entries
                .iter()
                .map(|(key, value)| Value::Array(vec![rmpv_to_json(key), rmpv_to_json(value)]))
                .collect(),
        ),
    )
}

fn tagged_json(tag: &str, payload: Value) -> Value {
    let mut wrapper = JsonMap::new();
    wrapper.insert(tag.to_owned(), payload);
    Value::Object(wrapper)
}

/// Doubles a leading `$` so a real key can never impersonate a wrapper tag.
fn escape_json_key(key: &str) -> String {
    if key.starts_with('$') {
        format!("${key}")
    } else {
        key.to_owned()
    }
}

fn json_number(number: f64) -> Value {
    serde_json::Number::from_f64(number).map_or(Value::Null, Value::Number)
}

/// Cosine similarity clamped to `[0, 1]` and scaled to millionths.
///
/// Negative similarity clamps to zero rather than mapping onto a positive
/// range: an anti-correlated embedding is "not similar", and a threshold set at
/// zero must not admit it merely because the scale was recentered.
fn cosine_similarity_micros(left: &[f32], right: &[f32]) -> u32 {
    if left.len() != right.len() || left.is_empty() {
        return 0;
    }
    let dot = f64::from(left.iter().zip(right).map(|(l, r)| l * r).sum::<f32>());
    let norm = |values: &[f32]| f64::from(values.iter().map(|v| v * v).sum::<f32>()).sqrt();
    let denominator = norm(left) * norm(right);
    if denominator <= 0.0 {
        return 0;
    }
    let similarity = (dot / denominator).clamp(0.0, 1.0);
    // Rounding to nearest keeps an exact-match pair at exactly 1_000_000.
    (similarity * f64::from(MICROS_PER_UNIT)).round() as u32
}

/// Fingerprint that moves when EITHER vector moves.
fn vector_pair_fingerprint(subject: &Option<Vec<f32>>, exemplar: &Option<Vec<f32>>) -> String {
    let mut hasher = Sha256::new();
    for vector in [subject, exemplar] {
        match vector {
            None => hasher.update([0u8]),
            Some(values) => {
                hasher.update([1u8]);
                hash_len(&mut hasher, values.len());
                for value in values {
                    hasher.update(value.to_be_bytes());
                }
            }
        }
    }
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn validate_bounded_text(value: &str, field: &'static str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(Error::InvalidConfig(format!(
            "saved query {field} length is invalid"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(Error::InvalidConfig(format!(
            "saved query {field} has control characters"
        )));
    }
    Ok(())
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}

/// snake_case `EdgeKind` names, the same spelling the facade uses on the wire.
fn edge_kind_from_name(value: &str) -> Option<EdgeKind> {
    let kind = match value {
        "authored_by" => EdgeKind::AuthoredBy,
        "scoped_to" => EdgeKind::ScopedTo,
        "part_of" => EdgeKind::PartOf,
        "supersedes" => EdgeKind::Supersedes,
        "belongs_to" => EdgeKind::BelongsTo,
        "claim_of" => EdgeKind::ClaimOf,
        "child_of" => EdgeKind::ChildOf,
        "assigned_to" => EdgeKind::AssignedTo,
        "derived_from" => EdgeKind::DerivedFrom,
        "mentions" => EdgeKind::Mentions,
        "about" => EdgeKind::About,
        "supports" => EdgeKind::Supports,
        "opposes" => EdgeKind::Opposes,
        "participates_in" => EdgeKind::ParticipatesIn,
        "attached" => EdgeKind::Attached,
        "employed_by" => EdgeKind::EmployedBy,
        "has_facet" => EdgeKind::HasFacet,
        "facet_of" => EdgeKind::FacetOf,
        "in_world" => EdgeKind::InWorld,
        "set_in" => EdgeKind::SetIn,
        "merged_into" => EdgeKind::MergedInto,
        "split_into" => EdgeKind::SplitInto,
        _ => return None,
    };
    Some(kind)
}

/// Private-encoding unit tests: memo-key canonicalization, malformed-row
/// rejection, and the pure predicates the evaluator composes. Public
/// behavior lives in `tests/saved_query_oracle.rs`.
#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::entity_id::EntityId;

    fn id(seed: u8) -> EntityId {
        crate::test_util::entity(seed)
    }

    fn sample_definition() -> SavedQueryDefinition {
        SavedQueryDefinition {
            schema_version: SAVED_QUERY_SCHEMA_VERSION,
            owner_actor: id(0x21),
            scope: QueryScope::default(),
            definition_version: 3,
            filter: FilterAst::Claim {
                predicate: "crm.fit".to_owned(),
                cmp: ClaimComparison::Exists,
                value: Value::Null,
            },
            matcher: MatcherSpec::Hard {
                expression: FilterAst::All { terms: Vec::new() },
            },
            eval: EvalPolicy {
                mode: EvalMode::Manual,
                max_entities_per_wake: 8,
                max_judges_per_wake: 2,
            },
            lifecycle: SavedQueryLifecycle::Active,
        }
    }

    fn sample_memo_row() -> VerdictMemoRow {
        VerdictMemoRow {
            key: VerdictMemoKey {
                query_ref: id(0x22),
                entity_ref: id(0x23),
                evidence_hash: [7u8; EVIDENCE_HASH_LEN],
            },
            definition_version: 3,
            verdict: MatchVerdict::Match,
            why: "because".to_owned(),
            envelope: SavedQueryDerivationEnvelope {
                content_hash: hex_lower(&[7u8; EVIDENCE_HASH_LEN]),
                model_id: "hard".to_owned(),
                version: EVALUATOR_VERSION.to_owned(),
                params_hash: hex_lower(&[9u8; EVIDENCE_HASH_LEN]),
            },
            evaluated_at: 1_700,
        }
    }

    /// The memo key is the three identity components concatenated, in a fixed
    /// order, under a versioned prefix. Nothing else may enter it — a key that also
    /// hashed the verdict would never hit.
    #[test]
    fn memo_key_is_prefix_plus_three_fixed_width_components() {
        let key = VerdictMemoKey {
            query_ref: id(0x24),
            entity_ref: id(0x25),
            evidence_hash: [0x5A; EVIDENCE_HASH_LEN],
        };
        let encoded = keys::memo(&key);
        let prefix = b"saved_query.memo.v1:";
        assert!(encoded.starts_with(prefix));
        assert_eq!(encoded.len(), prefix.len() + 16 + 16 + EVIDENCE_HASH_LEN);
        assert_eq!(
            &encoded[prefix.len()..prefix.len() + 16],
            id(0x24).as_bytes()
        );
        assert_eq!(
            &encoded[prefix.len() + 16..prefix.len() + 32],
            id(0x25).as_bytes()
        );
        assert_eq!(&encoded[prefix.len() + 32..], &[0x5A; EVIDENCE_HASH_LEN]);
    }

    /// Swapping the query and entity refs must produce a different key: a single
    /// concatenation with fixed widths is only unambiguous if the order is honored.
    #[test]
    fn memo_key_distinguishes_swapped_refs() {
        let forward = keys::memo(&VerdictMemoKey {
            query_ref: id(0x26),
            entity_ref: id(0x27),
            evidence_hash: [1u8; EVIDENCE_HASH_LEN],
        });
        let swapped = keys::memo(&VerdictMemoKey {
            query_ref: id(0x27),
            entity_ref: id(0x26),
            evidence_hash: [1u8; EVIDENCE_HASH_LEN],
        });
        assert_ne!(forward, swapped);
    }

    /// Event keys sort by epoch under a `(query, entity)` prefix scan, so history
    /// reads back oldest-first without a sort step that could disagree with disk.
    #[test]
    fn event_keys_sort_by_epoch_within_the_pair_prefix() {
        let (query, entity) = (id(0x28), id(0x29));
        let prefix = keys::event_prefix(&query, &entity);
        let mut keys = [
            keys::event(&query, &entity, 10),
            keys::event(&query, &entity, 2),
            keys::event(&query, &entity, 300),
        ];
        assert!(keys.iter().all(|key| key.starts_with(&prefix)));
        keys.sort();
        assert_eq!(keys[0], keys::event(&query, &entity, 2));
        assert_eq!(keys[1], keys::event(&query, &entity, 10));
        assert_eq!(keys[2], keys::event(&query, &entity, 300));
    }

    #[test]
    fn memo_row_round_trips_through_its_codec() {
        let row = sample_memo_row();
        let encoded = encode_memo_row(&row).expect("encode");
        assert_eq!(decode_memo_row(&encoded).expect("decode"), row);
    }

    /// A row that is not JSON, is missing a field, or names a verdict outside the
    /// closed set is CorruptedIndex — never a silent miss and never a default.
    #[test]
    fn malformed_memo_rows_are_rejected() {
        let encoded = encode_memo_row(&sample_memo_row()).expect("encode");
        let mut truncated = encoded.clone();
        truncated.truncate(encoded.len() / 2);

        let mut parsed: Value = serde_json::from_slice(&encoded).expect("row is json");
        parsed["verdict"] = json!("maybe");
        let unknown_verdict = serde_json::to_vec(&parsed).expect("re-encode");

        let mut parsed: Value = serde_json::from_slice(&encoded).expect("row is json");
        parsed["evidence_hash"] = json!("00ff");
        let short_hash = serde_json::to_vec(&parsed).expect("re-encode");

        let mut parsed: Value = serde_json::from_slice(&encoded).expect("row is json");
        parsed.as_object_mut().expect("object").remove("why");
        let missing_field = serde_json::to_vec(&parsed).expect("re-encode");

        for (label, bytes) in [
            ("truncated", truncated),
            ("unknown verdict", unknown_verdict),
            ("short hash", short_hash),
            ("missing field", missing_field),
        ] {
            assert!(
                matches!(decode_memo_row(&bytes), Err(Error::CorruptedIndex(_))),
                "{label} memo row must be rejected"
            );
        }
    }

    #[test]
    fn definition_round_trips_through_its_codec() {
        let definition = sample_definition();
        let json = definition_to_json(&definition).expect("encode");
        assert_eq!(definition_from_json(&json).expect("decode"), definition);
    }

    /// Canonical JSON sorts object keys recursively; the crate builds `serde_json`
    /// with `preserve_order`, so two equal values with different insertion orders
    /// would otherwise hash differently.
    #[test]
    fn canonical_json_is_insertion_order_independent() {
        let first = json!({"b": 1, "a": {"d": 2, "c": 3}});
        let second = json!({"a": {"c": 3, "d": 2}, "b": 1});
        assert_ne!(
            serde_json::to_vec(&first).expect("raw"),
            serde_json::to_vec(&second).expect("raw"),
            "the fixture must actually differ before canonicalization"
        );
        assert_eq!(
            canonical_json_bytes(&first).expect("canonical"),
            canonical_json_bytes(&second).expect("canonical")
        );
    }

    /// The watermark row is `epoch || content digest`; any other length is disk
    /// corruption, not a shorter epoch.
    #[test]
    fn watermark_rows_round_trip_and_reject_wrong_lengths() {
        let content = [3u8; EVIDENCE_HASH_LEN];
        let encoded = encode_watermark(42, &content);
        assert_eq!(decode_watermark(&encoded).expect("decode"), (42, content));
        assert!(matches!(
            decode_watermark(&encoded[..encoded.len() - 1]),
            Err(Error::CorruptedIndex(_))
        ));
    }

    /// An exact-match vector pair reaches the full micros scale, so a query with a
    /// 1_000_000 floor can still match its own exemplar.
    #[test]
    fn cosine_similarity_saturates_on_identical_vectors() {
        assert_eq!(
            cosine_similarity_micros(&[1.0, 2.0], &[1.0, 2.0]),
            1_000_000
        );
        assert_eq!(cosine_similarity_micros(&[1.0, 0.0], &[0.0, 1.0]), 0);
        // Anti-correlated clamps to zero rather than recentering onto a positive
        // range that a zero floor would admit.
        assert_eq!(cosine_similarity_micros(&[1.0, 0.0], &[-1.0, 0.0]), 0);
        assert_eq!(cosine_similarity_micros(&[1.0], &[1.0, 2.0]), 0);
    }

    /// The fingerprint's only job is to move when either vector moves.
    #[test]
    fn vector_pair_fingerprint_tracks_both_sides() {
        let base = vector_pair_fingerprint(&Some(vec![1.0, 2.0]), &Some(vec![3.0, 4.0]));
        assert_ne!(
            base,
            vector_pair_fingerprint(&Some(vec![1.0, 2.5]), &Some(vec![3.0, 4.0]))
        );
        assert_ne!(
            base,
            vector_pair_fingerprint(&Some(vec![1.0, 2.0]), &Some(vec![3.0, 4.5]))
        );
        assert_ne!(base, vector_pair_fingerprint(&None, &Some(vec![3.0, 4.0])));
    }

    /// Empty axes mean "unrestricted"; two disjoint restricted axes CLOSE, which is
    /// the fail-closed signal, not an unrestricted empty result.
    #[test]
    fn scope_intersection_separates_unrestricted_from_closed() {
        let unrestricted = QueryScope::default();
        let alpha = QueryScope {
            worlds: vec![id(0x2A)],
            facets: vec!["work".to_owned()],
        };
        let beta = QueryScope {
            worlds: vec![id(0x2B)],
            facets: vec!["work".to_owned()],
        };

        assert_eq!(alpha.intersect(&unrestricted), Some(alpha.clone()));
        assert_eq!(unrestricted.intersect(&alpha), Some(alpha.clone()));
        assert_eq!(alpha.intersect(&alpha), Some(alpha.clone()));
        assert_eq!(alpha.intersect(&beta), None);
        assert!(alpha.is_closed_against(&beta));
        assert!(!alpha.is_closed_against(&unrestricted));
    }

    /// Irrelevant evidence must not move the hash, and relevant evidence must.
    #[test]
    fn evidence_hash_covers_relevant_evidence_and_scope() {
        let definition = sample_definition();
        let base = RelevantEvidence {
            entity_ref: id(0x2C),
            claim_values: vec![("crm.fit".to_owned(), json!("fit"))],
            edge_targets: Vec::new(),
            semantic_inputs: Vec::new(),
            scope_membership: QueryScope::default(),
        };
        let hash = compute_evidence_hash(&definition, &base).expect("hash");

        let mut moved = base.clone();
        moved.claim_values = vec![("crm.fit".to_owned(), json!("not_fit"))];
        assert_ne!(
            hash,
            compute_evidence_hash(&definition, &moved).expect("hash")
        );

        let mut bumped = definition.clone();
        bumped.definition_version += 1;
        assert_ne!(hash, compute_evidence_hash(&bumped, &base).expect("hash"));

        let mut rescoped = definition.clone();
        rescoped.scope = QueryScope {
            worlds: vec![id(0x2D)],
            facets: Vec::new(),
        };
        assert_ne!(hash, compute_evidence_hash(&rescoped, &base).expect("hash"));

        // Scope MEMBERSHIP is evidence too: moving into or out of a world has
        // to invalidate the memo, and nothing else carries that movement.
        let mut moved_world = base.clone();
        moved_world.scope_membership = QueryScope {
            worlds: vec![id(0x2D)],
            facets: Vec::new(),
        };
        assert_ne!(
            hash,
            compute_evidence_hash(&definition, &moved_world).expect("hash")
        );

        assert_eq!(
            hash,
            compute_evidence_hash(&definition, &base).expect("hash")
        );
    }

    /// A restricted axis needs a WITNESS on that axis. An entity with no world
    /// membership is outside a world-scoped query, not universally inside it.
    #[test]
    fn scope_admits_only_entities_holding_the_restricted_axis() {
        let (alpha, beta, facet) = (id(0x2F), id(0x30), id(0x31).to_hex());
        let world_scoped = QueryScope {
            worlds: vec![alpha],
            facets: Vec::new(),
        };
        assert!(world_scoped.admits(&QueryScope {
            worlds: vec![alpha],
            facets: Vec::new(),
        }));
        assert!(!world_scoped.admits(&QueryScope::default()));
        assert!(!world_scoped.admits(&QueryScope {
            worlds: vec![beta],
            facets: Vec::new(),
        }));

        // An unrestricted scope admits everything, including a bare entity.
        assert!(QueryScope::default().admits(&QueryScope::default()));

        // Both axes must be witnessed when both are restricted.
        let both = QueryScope {
            worlds: vec![alpha],
            facets: vec![facet.clone()],
        };
        assert!(!both.admits(&QueryScope {
            worlds: vec![alpha],
            facets: Vec::new(),
        }));
        assert!(both.admits(&QueryScope {
            worlds: vec![alpha],
            facets: vec![facet],
        }));
    }

    /// Claim evidence is admitted by WORLD: base reality reads everywhere, a
    /// claim scoped to an out-of-reach world reads nowhere.
    #[test]
    fn claim_world_scope_admission_mirrors_the_gate_rule() {
        let scoped_to = |world: Option<EntityId>| {
            let mut body = ClaimBody::new(
                "crm.fit",
                ClaimSubject::Entity(id(0x32)),
                rmpv::Value::from("fit"),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            );
            body.world = world;
            body
        };
        let scope = QueryScope {
            worlds: vec![id(0x33)],
            facets: Vec::new(),
        };
        assert!(claim_in_scope(&scoped_to(None), &scope));
        assert!(claim_in_scope(&scoped_to(Some(id(0x33))), &scope));
        assert!(!claim_in_scope(&scoped_to(Some(id(0x34))), &scope));
        // An unrestricted world axis admits every claim world.
        assert!(claim_in_scope(
            &scoped_to(Some(id(0x34))),
            &QueryScope::default()
        ));
    }

    /// Active alone is not effective. Approval, staleness, and the valid-time
    /// window all gate whether a claim is standing truth at the requested time.
    #[test]
    fn only_effective_claims_count_as_evidence() {
        let base = || {
            ClaimBody::new(
                "crm.fit",
                ClaimSubject::Entity(id(0x35)),
                rmpv::Value::from("fit"),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            )
        };
        assert!(claim_effective_at(&base(), 1_000));

        let mut proposed = base();
        proposed.approval = ClaimApprovalStatus::Proposed;
        assert!(!claim_effective_at(&proposed, 1_000));

        let mut stale = base();
        stale.stale = true;
        assert!(!claim_effective_at(&stale, 1_000));

        let mut superseded = base();
        superseded.lifecycle = ClaimLifecycleStatus::Superseded;
        assert!(!claim_effective_at(&superseded, 1_000));

        let mut not_yet = base();
        not_yet.valid_from = Some(2_000);
        assert!(!claim_effective_at(&not_yet, 1_000));
        assert!(claim_effective_at(&not_yet, 2_000));

        let mut expired = base();
        expired.valid_to = Some(500);
        assert!(!claim_effective_at(&expired, 1_000));
        assert!(claim_effective_at(&expired, 500));
    }

    /// The MessagePack projection must be injective: a byte string and the
    /// literal text of its hex spelling cannot land on the same JSON, and a map
    /// key that looks like a wrapper tag cannot impersonate one.
    #[test]
    fn rmpv_projection_is_injective_across_types() {
        assert_ne!(
            rmpv_to_json(&rmpv::Value::Binary(vec![0x61])),
            rmpv_to_json(&rmpv::Value::from("61"))
        );
        assert_ne!(
            rmpv_to_json(&rmpv::Value::Ext(1, vec![0x61])),
            rmpv_to_json(&rmpv::Value::Binary(vec![0x61]))
        );
        let impersonator =
            rmpv::Value::Map(vec![(rmpv::Value::from("$bin"), rmpv::Value::from("61"))]);
        assert_ne!(
            rmpv_to_json(&impersonator),
            rmpv_to_json(&rmpv::Value::Binary(vec![0x61]))
        );
        // Non-string map keys are preserved rather than erased.
        let numeric_keys = rmpv::Value::Map(vec![(rmpv::Value::from(1), rmpv::Value::from("a"))]);
        assert_ne!(
            rmpv_to_json(&numeric_keys),
            rmpv_to_json(&rmpv::Value::Map(Vec::new()))
        );
    }

    /// Two live values for one predicate must both reach the judge; a
    /// predicate-keyed object would show it only the last one while the hash
    /// covered both.
    #[test]
    fn judge_evidence_preserves_every_live_claim_value() {
        let evidence = RelevantEvidence {
            entity_ref: id(0x36),
            claim_values: vec![
                ("crm.fit".to_owned(), json!("fit")),
                ("crm.fit".to_owned(), json!("not_fit")),
            ],
            edge_targets: Vec::new(),
            semantic_inputs: Vec::new(),
            scope_membership: QueryScope::default(),
        };
        let projected = evidence_to_json(&evidence);
        let claims = projected["claims"].as_array().expect("claims are pairs");
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0], json!(["crm.fit", "fit"]));
        assert_eq!(claims[1], json!(["crm.fit", "not_fit"]));
    }

    /// Stage 2 scores the vectors the fingerprint was taken from. The function
    /// takes NO vault, so a re-read cannot creep back in: a verdict derived
    /// from vectors the evidence hash does not name is a memo that lies.
    #[test]
    fn semantic_decision_scores_the_fingerprinted_vectors() {
        let exemplar_ref = id(0x37);
        let collected = |subject: Option<Vec<f32>>, exemplar: Option<Vec<f32>>| CollectedEvidence {
            evidence: RelevantEvidence {
                entity_ref: id(0x38),
                claim_values: Vec::new(),
                edge_targets: Vec::new(),
                semantic_inputs: vec![(exemplar_ref, vector_pair_fingerprint(&subject, &exemplar))],
                scope_membership: QueryScope::default(),
            },
            subject_vector: subject,
            exemplar_vectors: vec![(exemplar_ref, exemplar)],
        };

        let identical = collected(Some(vec![1.0, 2.0]), Some(vec![1.0, 2.0]));
        assert_eq!(
            semantic_decision(&identical, exemplar_ref, MICROS_PER_UNIT).verdict,
            MatchVerdict::Match
        );

        let orthogonal = collected(Some(vec![1.0, 0.0]), Some(vec![0.0, 1.0]));
        assert_eq!(
            semantic_decision(&orthogonal, exemplar_ref, 1).verdict,
            MatchVerdict::NoMatch
        );

        // An unknowable similarity never admits membership.
        let missing = collected(None, Some(vec![1.0, 2.0]));
        assert_eq!(
            semantic_decision(&missing, exemplar_ref, 0).verdict,
            MatchVerdict::NoMatch
        );
    }

    /// A zero bound is a budget lie, not an unbounded budget.
    #[test]
    fn zero_wake_bounds_are_rejected_at_the_write_door() {
        let mut definition = sample_definition();
        definition.eval.max_judges_per_wake = 0;
        assert!(matches!(
            validate_definition(&definition),
            Err(Error::InvalidConfig(_))
        ));

        let mut definition = sample_definition();
        definition.eval.max_entities_per_wake = 0;
        assert!(matches!(
            validate_definition(&definition),
            Err(Error::InvalidConfig(_))
        ));

        assert!(validate_definition(&sample_definition()).is_ok());
    }

    /// Length prefixes exist so `("ab", "c")` and `("a", "bc")` cannot collide.
    #[test]
    fn evidence_hash_length_prefixes_prevent_field_smearing() {
        let definition = sample_definition();
        let left = RelevantEvidence {
            entity_ref: id(0x2E),
            claim_values: vec![("ab".to_owned(), json!("c"))],
            edge_targets: Vec::new(),
            semantic_inputs: Vec::new(),
            scope_membership: QueryScope::default(),
        };
        let right = RelevantEvidence {
            claim_values: vec![("a".to_owned(), json!("bc"))],
            ..left.clone()
        };
        assert_ne!(
            compute_evidence_hash(&definition, &left).expect("hash"),
            compute_evidence_hash(&definition, &right).expect("hash")
        );
    }

    /// A judge answer must be a closed-set verdict in a JSON object. Prose, a
    /// missing reason, and an unknown verdict token are all upstream failures.
    #[test]
    fn judge_responses_must_be_closed_set_json() {
        assert_eq!(
            decode_judge_decision(r#"{"verdict":"match","why":"fits the rubric"}"#)
                .expect("decode"),
            MatchDecision {
                verdict: MatchVerdict::Match,
                why: "fits the rubric".to_owned(),
            }
        );
        for bad in [
            "yes, definitely a match",
            r#"{"verdict":"probably","why":"x"}"#,
            r#"{"verdict":"match"}"#,
            r#"{"why":"x"}"#,
        ] {
            assert!(
                matches!(
                    decode_judge_decision(bad),
                    Err(Error::UpstreamToolFailure { .. })
                ),
                "{bad:?} must not decode to a verdict"
            );
        }
    }

    /// The watermark decides the outcome; payload equality alone never does.
    #[test]
    fn watermark_verdict_rejects_stale_epochs_without_calling_them_applied() {
        let content = [1u8; EVIDENCE_HASH_LEN];
        let other = [2u8; EVIDENCE_HASH_LEN];

        assert_eq!(watermark_verdict(None, 1, &content), None);
        assert_eq!(
            watermark_verdict(Some((1, Some(content))), 2, &content),
            None
        );
        assert_eq!(
            watermark_verdict(Some((1, Some(content))), 1, &content),
            Some(MembershipCommitOutcome::AlreadyApplied)
        );
        // Same epoch, different content: a conflict, not a retry.
        assert_eq!(
            watermark_verdict(Some((1, Some(content))), 1, &other),
            Some(MembershipCommitOutcome::RejectedStaleEpoch { current_epoch: 1 })
        );
        // The replayed-Entered-after-re-entry case.
        assert_eq!(
            watermark_verdict(Some((3, Some(other))), 1, &content),
            Some(MembershipCommitOutcome::RejectedStaleEpoch { current_epoch: 3 })
        );
        // A watermark recovered from the replicated claim chain carries no
        // content digest, so a same-epoch replay it cannot prove is stale —
        // never "already applied".
        assert_eq!(
            watermark_verdict(Some((2, None)), 2, &content),
            Some(MembershipCommitOutcome::RejectedStaleEpoch { current_epoch: 2 })
        );
        assert_eq!(watermark_verdict(Some((2, None)), 3, &content), None);
    }
}
