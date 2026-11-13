//! Moved from `crates/oneiron/src/memory/query_records/surface.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::campaign_records::membership::MembershipReadRequest;
use crate::memory::campaign_records::membership::MembershipRowSource;
use crate::memory::query_records::definition::EvalMode;
use crate::memory::query_records::definition::EvalPolicy;
use crate::memory::query_records::definition::QueryScope;
use crate::memory::query_records::definition::SavedQueryLifecycle;
use crate::memory::query_records::definition::UpdateSavedQueryRequest;
use crate::memory::query_records::filter::ClaimComparison;
use crate::memory::query_records::filter::FilterAst;
use crate::memory::query_records::filter::MatcherSpec;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::query_memos::MatchVerdict;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// A saved query's declared scope on the wire. An empty axis is
/// unrestricted on that axis, exactly as [`QueryScope`] reads it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryScopeSpec {
    /// WORLD entities in reach; absent or empty is unrestricted.
    #[serde(default)]
    pub worlds: Vec<EntityId>,
    /// Facet tokens in reach; absent or empty is unrestricted.
    #[serde(default)]
    pub facets: Vec<String>,
}

impl SavedQueryScopeSpec {
    fn scope(&self) -> QueryScope {
        QueryScope {
            worlds: self.worlds.clone(),
            facets: self.facets.clone(),
        }
    }

    fn of(scope: &QueryScope) -> Self {
        Self {
            worlds: scope.worlds.clone(),
            facets: scope.facets.clone(),
        }
    }
}

/// Stage-1 filter on the wire: one `op` per term, per-entity-decidable by
/// construction. Ranked or global-relative operators have no variant here,
/// and CA-02 re-validates every converted AST.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum SavedQueryFilterSpec {
    /// Membership in the shared tasks-by-owner index.
    TaskOwner {
        /// The task owner.
        owner: EntityId,
    },
    /// Conjunction; an empty term list is vacuously true.
    All {
        /// Conjuncts.
        terms: Vec<SavedQueryFilterSpec>,
    },
    /// Disjunction; an empty term list is vacuously false.
    Any {
        /// Disjuncts.
        terms: Vec<SavedQueryFilterSpec>,
    },
    /// Negation.
    Not {
        /// Negated term.
        term: Box<SavedQueryFilterSpec>,
    },
    /// Comparison against one claim predicate's live value.
    Claim {
        /// Claim predicate.
        predicate: String,
        /// Comparison operator.
        cmp: ClaimComparison,
        /// Right-hand operand; ignored by `exists`.
        #[serde(default)]
        value: Value,
    },
    /// Existence of an outbound edge of one kind, optionally to a target.
    EdgeExists {
        /// snake_case edge kind name.
        edge_kind: String,
        /// Optional exact target.
        #[serde(default)]
        target: Option<EntityId>,
    },
}

impl SavedQueryFilterSpec {
    fn filter(&self) -> FilterAst {
        match self {
            Self::TaskOwner { owner } => FilterAst::TaskOwner { owner: *owner },
            Self::All { terms } => FilterAst::All {
                terms: terms.iter().map(Self::filter).collect(),
            },
            Self::Any { terms } => FilterAst::Any {
                terms: terms.iter().map(Self::filter).collect(),
            },
            Self::Not { term } => FilterAst::Not {
                term: Box::new(term.filter()),
            },
            Self::Claim {
                predicate,
                cmp,
                value,
            } => FilterAst::Claim {
                predicate: predicate.clone(),
                cmp: *cmp,
                value: value.clone(),
            },
            Self::EdgeExists { edge_kind, target } => FilterAst::EdgeExists {
                edge_kind: edge_kind.clone(),
                target: *target,
            },
        }
    }

    fn of(filter: &FilterAst) -> Self {
        match filter {
            FilterAst::TaskOwner { owner } => Self::TaskOwner { owner: *owner },
            FilterAst::All { terms } => Self::All {
                terms: terms.iter().map(Self::of).collect(),
            },
            FilterAst::Any { terms } => Self::Any {
                terms: terms.iter().map(Self::of).collect(),
            },
            FilterAst::Not { term } => Self::Not {
                term: Box::new(Self::of(term)),
            },
            FilterAst::Claim {
                predicate,
                cmp,
                value,
            } => Self::Claim {
                predicate: predicate.clone(),
                cmp: *cmp,
                value: value.clone(),
            },
            FilterAst::EdgeExists { edge_kind, target } => Self::EdgeExists {
                edge_kind: edge_kind.clone(),
                target: *target,
            },
        }
    }
}

/// Stage-2 matcher on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SavedQueryMatcherSpec {
    /// A second hard expression over the same evidence.
    Hard {
        /// Expression evaluated after stage 1 passes.
        expression: SavedQueryFilterSpec,
    },
    /// Cosine similarity against an exemplar's stored vector.
    SemanticThreshold {
        /// Entity whose vector is the exemplar.
        exemplar_ref: EntityId,
        /// Inclusive floor, in millionths of a unit similarity.
        minimum_similarity_micros: u32,
    },
    /// Owner-supplied rubric adjudicated by a host-injected judge.
    LlmJudge {
        /// `provider/name@revision` model id.
        model_id: String,
        /// Owner-supplied rubric, passed through verbatim.
        #[serde(default)]
        rubric: Value,
        /// Owner's version token for the rubric.
        rubric_version: String,
    },
}

impl SavedQueryMatcherSpec {
    fn matcher(&self) -> MatcherSpec {
        match self {
            Self::Hard { expression } => MatcherSpec::Hard {
                expression: expression.filter(),
            },
            Self::SemanticThreshold {
                exemplar_ref,
                minimum_similarity_micros,
            } => MatcherSpec::SemanticThreshold {
                exemplar_ref: *exemplar_ref,
                minimum_similarity_micros: *minimum_similarity_micros,
            },
            Self::LlmJudge {
                model_id,
                rubric,
                rubric_version,
            } => MatcherSpec::LlmJudge {
                model_id: model_id.clone(),
                rubric: rubric.clone(),
                rubric_version: rubric_version.clone(),
            },
        }
    }

    fn of(matcher: &MatcherSpec) -> Self {
        match matcher {
            MatcherSpec::Hard { expression } => Self::Hard {
                expression: SavedQueryFilterSpec::of(expression),
            },
            MatcherSpec::SemanticThreshold {
                exemplar_ref,
                minimum_similarity_micros,
            } => Self::SemanticThreshold {
                exemplar_ref: *exemplar_ref,
                minimum_similarity_micros: *minimum_similarity_micros,
            },
            MatcherSpec::LlmJudge {
                model_id,
                rubric,
                rubric_version,
            } => Self::LlmJudge {
                model_id: model_id.clone(),
                rubric: rubric.clone(),
                rubric_version: rubric_version.clone(),
            },
        }
    }
}

/// Execution mode and per-wake bounds on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryEvalSpec {
    /// Declared execution mode.
    pub mode: EvalMode,
    /// Hard cap on entities visited per wake batch.
    pub max_entities_per_wake: u32,
    /// Hard cap on stage-2 judgements per wake batch.
    pub max_judges_per_wake: u32,
}

impl SavedQueryEvalSpec {
    fn policy(self) -> EvalPolicy {
        EvalPolicy {
            mode: self.mode,
            max_entities_per_wake: self.max_entities_per_wake,
            max_judges_per_wake: self.max_judges_per_wake,
        }
    }

    fn of(policy: EvalPolicy) -> Self {
        Self {
            mode: policy.mode,
            max_entities_per_wake: policy.max_entities_per_wake,
            max_judges_per_wake: policy.max_judges_per_wake,
        }
    }
}

/// `self.saved_query.read`'s input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryReadRequest {
    /// The saved query.
    pub query_ref: EntityId,
}

/// `self.saved_query.update`'s input: a whole definition replacement under
/// a version CAS. Also carries no owner field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryUpdateRequest {
    /// The saved query.
    pub query_ref: EntityId,
    /// Version the caller believes is current; the compare half of the CAS.
    pub expected_definition_version: u64,
    /// Replacement scope; absent is unrestricted.
    #[serde(default)]
    pub scope: SavedQueryScopeSpec,
    /// Replacement stage-1 filter.
    pub filter: SavedQueryFilterSpec,
    /// Replacement stage-2 matcher.
    pub matcher: SavedQueryMatcherSpec,
    /// Replacement execution policy.
    pub eval: SavedQueryEvalSpec,
}

impl SavedQueryUpdateRequest {
    /// The engine request this wire request writes.
    pub fn engine_request(&self) -> UpdateSavedQueryRequest {
        UpdateSavedQueryRequest {
            expected_definition_version: self.expected_definition_version,
            scope: self.scope.scope(),
            filter: self.filter.filter(),
            matcher: self.matcher.matcher(),
            eval: self.eval.policy(),
        }
    }
}

/// `self.saved_query.archive`'s input. Archive keeps the query addressable;
/// there is no saved-query delete verb, by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryArchiveRequest {
    /// The saved query.
    pub query_ref: EntityId,
    /// Version the caller believes is current.
    pub expected_definition_version: u64,
}

/// `self.saved_query.members`'s input: one cursor-bounded page of the
/// membership this query derived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryMembersRequest {
    /// The saved query.
    pub query_ref: EntityId,
    /// Opaque cursor from a prior page's `next_cursor`.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Requested page size; 0 takes the default.
    #[serde(default)]
    pub limit: u32,
    /// Optional epoch ceiling: the cohort as of that membership epoch.
    #[serde(default)]
    pub at_epoch: Option<u64>,
}

impl SavedQueryMembersRequest {
    /// The engine page request this wire request reads.
    pub fn read_request(&self) -> MembershipReadRequest {
        MembershipReadRequest {
            owner_ref: self.query_ref,
            cursor: self.cursor.clone(),
            limit: self.limit,
            at_epoch: self.at_epoch,
        }
    }
}

/// `self.saved_query.evaluate`'s input: one manual, bounded evaluation of
/// the query under its owner's own read. Named `candidates` are evaluated
/// in order; with none, one page of the vault's people after `after` is,
/// bounded by the definition's own per-wake caps either way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryEvaluateRequest {
    /// The saved query, which the caller must own.
    pub query_ref: EntityId,
    /// Entities to evaluate, in order; absent pages the vault's people.
    #[serde(default)]
    pub candidates: Vec<EntityId>,
    /// People-page cursor: the last person a prior evaluation visited.
    #[serde(default)]
    pub after: Option<EntityId>,
}

/// A stored saved query's definition on the wire.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryDefinitionView {
    /// Definition schema version.
    pub schema_version: u32,
    /// The principal whose reach bounds every evaluation.
    pub owner_actor: EntityId,
    /// Scope the owner declared.
    pub scope: SavedQueryScopeSpec,
    /// Monotonic version, incremented by every accepted update.
    pub definition_version: u64,
    /// Stage-1 filter.
    pub filter: SavedQueryFilterSpec,
    /// Stage-2 matcher.
    pub matcher: SavedQueryMatcherSpec,
    /// Execution policy.
    pub eval: SavedQueryEvalSpec,
    /// Lifecycle state.
    pub lifecycle: SavedQueryLifecycle,
}

/// A stored saved query, as the create, update and archive verbs answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryRecordView {
    /// Identity of the saved query.
    pub query_ref: EntityId,
    /// Current definition.
    pub definition: SavedQueryDefinitionView,
    /// Creation time.
    pub created_at: u64,
    /// Last accepted write.
    pub updated_at: u64,
}

/// `self.saved_query.read`'s output. A query absent or not the caller's
/// reads `found: false` with a null `record`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryReadResult {
    /// Whether the query was found.
    pub found: bool,
    /// The query, when found.
    pub record: Option<SavedQueryRecordView>,
}

/// One entity's folded membership row on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryMembershipRowView {
    /// The member.
    pub entity_ref: EntityId,
    /// `entered` or `exited`.
    pub state: String,
    /// Valid time of the newest entry.
    pub entered_valid: u64,
    /// Detection time of the newest entry.
    pub entered_detected: u64,
    /// Valid time of the newest exit, when currently out.
    pub exited_valid: Option<u64>,
    /// Detection time of the newest exit, when currently out.
    pub exited_detected: Option<u64>,
    /// Cause of the newest folded event.
    pub cause: Option<String>,
    /// Where the row comes from: on a query's page, always that query.
    pub source: MembershipRowSource,
}

/// One page of membership rows, as `self.saved_query.members` answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryMembershipPageView {
    /// Rows in stable cursor order.
    pub rows: Vec<SavedQueryMembershipRowView>,
    /// Cursor for the next page; null when this page is the last.
    pub next_cursor: Option<String>,
}

/// One persisted verdict memo, as an evaluation receipt carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SavedQueryMemoReceipt {
    /// Definition version at evaluation time.
    pub definition_version: u64,
    /// Memoized verdict.
    pub verdict: MatchVerdict,
    /// Memoized justification.
    pub why: String,
    /// Hex evidence hash the verdict was derived from.
    pub content_hash: String,
    /// Model id for a judged verdict, or the matcher kind token otherwise.
    pub model_id: String,
    /// Evaluator version token.
    pub version: String,
    /// Hex digest of the canonical matcher specification.
    pub params_hash: String,
    /// Evaluation timestamp.
    pub evaluated_at: u64,
}
