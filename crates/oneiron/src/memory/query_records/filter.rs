//! Per-entity filter and matcher vocabulary.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::entity_id::EntityId;

/// Stage-1 filter expression.
///
/// Every operator is per-entity-decidable by construction. Ranked or
/// global-relative operators are not modeled here AND are named explicitly at
/// parse time (see [`parse_filter_ast`]), so a `top_k` predicate cannot arrive
/// as an unknown-variant error that a permissive reader might later widen.
#[derive(Debug, Clone, PartialEq)]
pub enum FilterAst {
    /// Membership in the shared tasks-by-owner index.
    TaskOwner { owner: EntityId },
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
