use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value};

use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::evidence::RelevantEvidence;
use super::support::{edge_kind_from_name, invalid, parse_entity_ref, validate_bounded_text};

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

pub(super) fn evaluate_filter(ast: &FilterAst, evidence: &RelevantEvidence) -> bool {
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
