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
//! Every durable row this module owns is a `vault_meta` sidecar under a
//! versioned prefix (see [`keys`]). That is a deliberate posture, not an
//! oversight: `registry::validate_entity_type` resolves against the STATIC
//! entity-type registry only, so a *dynamically* registered structural kind has
//! a reserved byte and short-id namespace but is not yet writable through the
//! batch put path. Registering the kind stakes the namespace (exactly as CA-00
//! does for CAMPAIGN); the records themselves are module-owned sidecars until
//! the write path honors runtime registrations. Memo rows would be sidecars
//! either way — they are memos, not synced authority.
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
use crate::campaign::CRM_PACK_ID;
use crate::campaign::claims::{
    CampaignMemberDerivation, CampaignMemberState, CampaignMemberValue, PREDICATE_CAMPAIGN_MEMBER,
    encode_campaign_member_value,
};
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{
    BudgetLease, CallEnvelope, ContentPart, LlmBackend, LlmMessage, LlmMessageRole, LlmRequest,
    ModelId,
};
use crate::registry::{StructuralKindRegistration, TypeByteBand};
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
/// `Crm` band yields `StructuralKindBandViolation`, and a taken byte or prefix
/// yields `StructuralKindTypeByteCollision` / `StructuralKindPrefixCollision`.
/// SAVED_QUERY adds no registration failure mode of its own.
pub fn register_saved_query_kind(
    vault: &Vault,
    assigned_type_byte: u8,
) -> Result<StructuralKindRegistration> {
    vault.register_structural_kind(
        assigned_type_byte,
        SAVED_QUERY_SHORT_ID_PREFIX,
        TypeByteBand::Crm,
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
/// [`definition_to_json`] / [`definition_from_json`] — the same door CA-01 uses
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
/// [`Error::InvalidConfig`] when the definition fails validation; storage
/// errors propagate unchanged.
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
    store_record(vault, &record)?;
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
    let mut record = owned_record(vault, authenticated_principal, query_ref)?;
    require_expected_version(&record, request.expected_definition_version)?;
    let definition = SavedQueryDefinition {
        schema_version: record.definition.schema_version,
        owner_actor: record.definition.owner_actor,
        scope: request.scope.clone(),
        definition_version: next_version(record.definition.definition_version)?,
        filter: request.filter.clone(),
        matcher: request.matcher.clone(),
        eval: request.eval,
        // An update is the operator's answer to a paused query, so it clears
        // the pause. Archived is terminal and is not reopened here.
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
    store_record(vault, &record)?;
    Ok(record)
}

/// Archives a saved query. A lifecycle transition, never a delete: the record
/// stays readable so ONE-1778 can still address it.
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
    let mut record = owned_record(vault, authenticated_principal, query_ref)?;
    require_expected_version(&record, expected_definition_version)?;
    record.definition.definition_version = next_version(record.definition.definition_version)?;
    record.definition.lifecycle = SavedQueryLifecycle::Archived;
    record.updated_at = now;
    store_record(vault, &record)?;
    Ok(record)
}

/// Loads a record the principal owns, or reports it as absent.
fn owned_record(
    vault: &Vault,
    authenticated_principal: EntityId,
    query_ref: EntityId,
) -> Result<SavedQueryRecord> {
    read_saved_query(vault, authenticated_principal, query_ref)?.ok_or(Error::EntityNotFound)
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
        let evidence = self.collect_evidence(&definition, request.entity_ref)?;
        let evidence_hash = compute_evidence_hash(&definition, &evidence)?;
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

        let (decision, judge_ran) = if evaluate_filter(&definition.filter, &evidence) {
            self.run_stage_two(&definition, &evidence).await?
        } else {
            (no_match("stage-1 filter did not match"), false)
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
        evidence: &RelevantEvidence,
    ) -> Result<(MatchDecision, bool)> {
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
                self.semantic_decision(
                    evidence.entity_ref,
                    *exemplar_ref,
                    *minimum_similarity_micros,
                )?,
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

    fn semantic_decision(
        &self,
        entity_ref: EntityId,
        exemplar_ref: EntityId,
        floor_micros: u32,
    ) -> Result<MatchDecision> {
        let (Some(subject), Some(exemplar)) = (
            self.vault.get_vector(&entity_ref)?,
            self.vault.get_vector(&exemplar_ref)?,
        ) else {
            // No vector is not "dissimilar", it is unknowable — and an
            // unknowable similarity must not admit membership.
            return Ok(no_match("semantic matcher found no vector to compare"));
        };
        let similarity = cosine_similarity_micros(&subject, &exemplar);
        Ok(if similarity >= floor_micros {
            MatchDecision {
                verdict: MatchVerdict::Match,
                why: format!("similarity {similarity} reached floor {floor_micros}"),
            }
        } else {
            no_match(&format!(
                "similarity {similarity} below floor {floor_micros}"
            ))
        })
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
        for (index, entity_ref) in candidates.iter().enumerate() {
            if report.evaluated >= record.definition.eval.max_entities_per_wake {
                report.resume_after = candidates.get(index.wrapping_sub(1)).copied();
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

    /// Reads the entity's live claims and edges, narrowed to the declared axes.
    fn collect_evidence(
        &self,
        definition: &SavedQueryDefinition,
        entity_ref: EntityId,
    ) -> Result<RelevantEvidence> {
        let deps = filter_dependencies(&definition.filter, &definition.matcher);
        Ok(RelevantEvidence {
            entity_ref,
            claim_values: self.relevant_claim_values(entity_ref, &deps.claim_predicates)?,
            edge_targets: self.relevant_edge_targets(entity_ref, &deps.edge_kinds)?,
            semantic_inputs: self.semantic_fingerprints(entity_ref, &deps.semantic_exemplars)?,
        })
    }

    fn relevant_claim_values(
        &self,
        entity_ref: EntityId,
        predicates: &[String],
    ) -> Result<Vec<(String, Value)>> {
        if predicates.is_empty() {
            return Ok(Vec::new());
        }
        let mut values = Vec::new();
        for edge in self.vault.edges_in(&entity_ref)? {
            if edge.kind != EdgeKind::ClaimOf {
                continue;
            }
            let Some(body) = self.live_claim_body(&edge.target)? else {
                continue;
            };
            if predicates.contains(&body.predicate) {
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

    fn live_claim_body(&self, claim_ref: &EntityId) -> Result<Option<ClaimBody>> {
        if self.vault.get_entity_type(claim_ref)? != Some(crate::registry::ENTITY_TYPE_CLAIM) {
            return Ok(None);
        }
        let Some(raw) = self.vault.get(claim_ref)? else {
            return Ok(None);
        };
        let body = crate::claim::decode_claim_body(&raw, true)?;
        Ok((body.lifecycle == ClaimLifecycleStatus::Active).then_some(body))
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

    fn semantic_fingerprints(
        &self,
        entity_ref: EntityId,
        exemplars: &[EntityId],
    ) -> Result<Vec<(EntityId, String)>> {
        let subject = self.vault.get_vector(&entity_ref)?;
        let mut inputs = Vec::with_capacity(exemplars.len());
        for exemplar in exemplars {
            let against = self.vault.get_vector(exemplar)?;
            inputs.push((*exemplar, vector_pair_fingerprint(&subject, &against)));
        }
        Ok(inputs)
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

fn evidence_to_json(evidence: &RelevantEvidence) -> Value {
    let mut claims = JsonMap::new();
    for (predicate, value) in &evidence.claim_values {
        claims.insert(predicate.clone(), value.clone());
    }
    let edges = evidence
        .edge_targets
        .iter()
        .map(|(kind, target)| {
            Value::Array(vec![
                Value::String(kind.clone()),
                Value::String(target.to_hex()),
            ])
        })
        .collect();
    let mut root = JsonMap::new();
    root.insert(
        "entity".to_owned(),
        Value::String(evidence.entity_ref.to_hex()),
    );
    root.insert("claims".to_owned(), Value::Object(claims));
    root.insert("edges".to_owned(), Value::Array(edges));
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
/// this is the only door that mints one.
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
    let current = read_watermark(vault, &rtxn, query_ref, entity_ref)?;
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
        let watermark = read_watermark(vault, wtxn, event.query_ref, event.entity_ref)?;
        if let Some(outcome) = watermark_verdict(watermark, event.epoch, &content) {
            return Ok(outcome);
        }
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
        vault.put_claim_in_txn(
            wtxn,
            &EntityId::now(),
            &claim_body,
            TimeRange {
                start: event.valid_at,
                end: event.valid_at,
            },
            now,
        )?;
        Ok(MembershipCommitOutcome::Applied)
    })
}

/// `None` means "proceed"; `Some` is the terminal outcome.
fn watermark_verdict(
    watermark: Option<(u64, [u8; EVIDENCE_HASH_LEN])>,
    epoch: u64,
    content: &[u8; EVIDENCE_HASH_LEN],
) -> Option<MembershipCommitOutcome> {
    let (current_epoch, stored) = watermark?;
    if epoch > current_epoch {
        return None;
    }
    if epoch == current_epoch && stored == *content {
        return Some(MembershipCommitOutcome::AlreadyApplied);
    }
    Some(MembershipCommitOutcome::RejectedStaleEpoch { current_epoch })
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
/// predicate pauses the query even if every other predicate renames cleanly. A
/// partially-migrated query would evaluate against a definition nobody wrote,
/// which is the one outcome the ladder exists to prevent.
///
/// # Errors
///
/// [`Error::EntityNotFound`] when the query is absent; storage errors propagate.
pub fn repair_pack_drift(
    vault: &Vault,
    query_ref: EntityId,
    definition: &SavedQueryDefinition,
    drift: &PackDrift,
    now: u64,
) -> Result<PackDriftResolution> {
    let map = load_migration_map(vault, drift)?.unwrap_or_default();
    let mut renames = BTreeMap::new();
    let mut notices = Vec::new();
    for predicate in &drift.affected_predicates {
        match map.rewrites.get(predicate) {
            None => {
                return pause_query(
                    vault,
                    query_ref,
                    format!(
                        "pack move {}@{} -> {}@{} has no rewrite for predicate {predicate:?}",
                        drift.from_pack_id, drift.from_version, drift.to_pack_id, drift.to_version
                    ),
                    now,
                );
            }
            Some(PackPredicateRewrite::SemanticsChanging { to, note }) => {
                return record_repair(
                    vault,
                    query_ref,
                    drift,
                    &format!("proposal: {predicate} -> {to} ({note})"),
                    now,
                )
                .map(|proposal_ref| PackDriftResolution::ProposalRequired { proposal_ref });
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
    apply_pack_migration(vault, query_ref, definition, drift, &renames, &notices, now)
}

fn apply_pack_migration(
    vault: &Vault,
    query_ref: EntityId,
    definition: &SavedQueryDefinition,
    drift: &PackDrift,
    renames: &BTreeMap<String, String>,
    notices: &[String],
    now: u64,
) -> Result<PackDriftResolution> {
    let mut record = load_record(vault, query_ref)?.ok_or(Error::EntityNotFound)?;
    record.definition = SavedQueryDefinition {
        filter: rewrite_predicates(&definition.filter, renames),
        matcher: rewrite_matcher(&definition.matcher, renames),
        definition_version: next_version(definition.definition_version)?,
        lifecycle: SavedQueryLifecycle::Active,
        ..definition.clone()
    };
    record.updated_at = now;
    store_record(vault, &record)?;
    let summary = if notices.is_empty() {
        format!("auto-migrated {} predicate(s)", renames.len())
    } else {
        format!("auto-rewritten with notices: {}", notices.join("; "))
    };
    let receipt_ref = record_repair(vault, query_ref, drift, &summary, now)?;
    Ok(if notices.is_empty() {
        PackDriftResolution::AutoMigrated { receipt_ref }
    } else {
        PackDriftResolution::AutoRewritten { receipt_ref }
    })
}

fn pause_query(
    vault: &Vault,
    query_ref: EntityId,
    error: String,
    now: u64,
) -> Result<PackDriftResolution> {
    let mut record = load_record(vault, query_ref)?.ok_or(Error::EntityNotFound)?;
    record.definition.lifecycle = SavedQueryLifecycle::Paused {
        error: error.clone(),
    };
    record.updated_at = now;
    store_record(vault, &record)?;
    Ok(PackDriftResolution::Paused { error })
}

fn record_repair(
    vault: &Vault,
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
    put_meta_row(vault, &keys::repair(&repair_ref), &encoded)?;
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

    const RECORD: &[u8] = b"saved_query.def.v1:";
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

    pub(super) fn record(query_ref: &EntityId) -> Vec<u8> {
        keyed(RECORD, &[query_ref.as_bytes()])
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

fn load_record(vault: &Vault, query_ref: EntityId) -> Result<Option<SavedQueryRecord>> {
    let Some(raw) = meta_row(vault, &keys::record(&query_ref))? else {
        return Ok(None);
    };
    decode_record(&raw).map(Some)
}

fn store_record(vault: &Vault, record: &SavedQueryRecord) -> Result<()> {
    put_meta_row(
        vault,
        &keys::record(&record.query_ref),
        &encode_record(record)?,
    )
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
        rmpv::Value::String(text) => text
            .as_str()
            .map_or(Value::Null, |text| Value::String(text.to_owned())),
        rmpv::Value::Binary(bytes) => Value::String(hex_lower(bytes)),
        rmpv::Value::Array(values) => Value::Array(values.iter().map(rmpv_to_json).collect()),
        rmpv::Value::Map(entries) => Value::Object(
            entries
                .iter()
                .filter_map(|(key, value)| {
                    key.as_str()
                        .map(|key| (key.to_owned(), rmpv_to_json(value)))
                })
                .collect(),
        ),
        rmpv::Value::Ext(tag, bytes) => Value::String(format!("ext:{tag}:{}", hex_lower(bytes))),
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

#[cfg(test)]
mod tests;
