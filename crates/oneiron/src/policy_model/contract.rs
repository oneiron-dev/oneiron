//! The output contract a substrate owner's policy document asks the model for,
//! and the strict reader that turns an answer back into engine terms.
//!
//! The engine does not tell the model how to answer — the policy document does,
//! top and bottom, in the substrate owner's own words. What the engine holds is
//! the DECLARATION of which shape those words asked for, so it can parse the
//! answer without guessing. That is the whole division: the owner writes the
//! instruction, the engine declares the shape and reads the result.
//!
//! Parsing is strict on purpose. An answer the engine cannot read is a
//! CLASSIFICATION FAILURE, not an allow: the plane that required the call
//! treats it exactly as it treats a model that never answered — a hosted plane
//! fails closed, and the owner's sovereign plane fails open.

use serde::Deserialize;
use serde_json::{Value as JsonValue, json};

use crate::error::{Error, Result};
use crate::llm::ResponseFormat;

/// The answer shapes the engine can read.
///
/// `non_exhaustive` on purpose: a new preset is how this list grows, and a
/// downstream exhaustive match would turn that into a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PolicyOutputContract {
    /// Exactly `0` or `1`, nothing else. Carries no category, so a violation
    /// resolves to the STRICTEST row the plane registered — the same rule the
    /// engine already uses when several of a plane's own rows could govern.
    Binary,
    /// `{"violation": 0|1, "policy_category": string|null}`.
    CategoryJson,
    /// [`Self::CategoryJson`] plus `rule_ids`, `confidence` and `rationale` —
    /// the audit trail a substrate owner reads to improve their policy.
    RationaleJson,
}

impl PolicyOutputContract {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::CategoryJson => "category_json",
            Self::RationaleJson => "rationale_json",
        }
    }

    /// Parses the wire spelling; `None` for anything else, so a manifest
    /// naming an unknown contract fails closed.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "binary" => Some(Self::Binary),
            "category_json" => Some(Self::CategoryJson),
            "rationale_json" => Some(Self::RationaleJson),
            _ => None,
        }
    }

    /// The response format the request declares. `Binary` is plain text: a
    /// JSON schema around a single digit would contradict the instruction the
    /// policy document gave the model.
    pub(crate) fn response_format(self, categories: Vec<JsonValue>) -> ResponseFormat {
        match self {
            Self::Binary => ResponseFormat::Text,
            Self::CategoryJson => ResponseFormat::Json {
                schema: category_schema(categories, false),
            },
            Self::RationaleJson => ResponseFormat::Json {
                schema: category_schema(categories, true),
            },
        }
    }
}

/// What the model said, in engine terms and nothing more. `policy_category` is
/// the label the model chose; resolving it to a row belongs to the plane that
/// asked, not here.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyModelAnswer {
    pub violation: bool,
    pub policy_category: Option<String>,
    /// The rules the model says it applied, RAW as it named them.
    ///
    /// Unvalidated at this layer on purpose: reading the answer and knowing
    /// which rules exist are two different jobs, and only the caller holds the
    /// resolved plane. `resolve_policy_model_response` dedupes this and drops
    /// every id that names no resolved rule before it reaches an audit.
    pub rule_ids: Vec<String>,
    pub confidence: Option<String>,
    pub rationale: Option<String>,
}

/// Longest rationale the engine carries into a receipt. Anything past this is
/// truncated on a character boundary rather than refused: an over-long
/// rationale is a verbose model, not an unusable answer.
pub(crate) const POLICY_RATIONALE_MAX_LEN: usize = 1024;

/// Longest confidence token the engine carries. The presets take a STRING
/// because policy documents phrase confidence in words (`high`, `medium`), not
/// in a calibrated float the engine would have to pretend to trust.
pub(crate) const POLICY_CONFIDENCE_MAX_LEN: usize = 32;

/// Most rule ids one model answer may CARRY INTO the reader.
///
/// Not the old per-answer cap that used to survive into the receipt — that one
/// was arbitrary, silently dropped valid citations from a talkative model, and
/// was removed deliberately. This is a parse-time FLOOD STOP, an order of
/// magnitude above [`POLICY_PATTERN_RULES_MAX`], which is itself well above
/// any legitimate policy's row count. Nothing honest comes near it.
///
/// It exists because the array is MODEL-SUPPLIED and arrives before anything
/// has validated it: with no bound, one answer makes the reader materialize an
/// arbitrarily large `Vec<String>` before the resolvable-set filter downstream
/// ever gets to throw it away. An answer that far out is not verbose, it is
/// unusable — so this REFUSES rather than truncating, and an unreadable answer
/// is a case every plane already knows how to handle.
///
/// [`POLICY_PATTERN_RULES_MAX`]: super::pattern::POLICY_PATTERN_RULES_MAX
pub(crate) const POLICY_MODEL_RULE_IDS_PARSE_MAX: usize =
    super::pattern::POLICY_PATTERN_RULES_MAX * 10;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CategoryWire {
    violation: u8,
    policy_category: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RationaleWire {
    violation: u8,
    policy_category: Option<String>,
    rule_ids: Vec<String>,
    confidence: String,
    rationale: String,
}

/// Reads a model answer under `contract`. Every failure is the same kind of
/// failure — the engine could not read the answer — so the caller has one thing
/// to handle rather than a taxonomy of malformations.
///
/// Everything the model supplies is BOUNDED here, at the only place it enters
/// engine terms: the rationale and the confidence word by length, the rule-id
/// array by count. Downstream this text becomes ledger rows, and the ledger
/// must not be floodable by an answer.
pub(crate) fn parse_model_answer(
    contract: PolicyOutputContract,
    text: &str,
) -> Result<PolicyModelAnswer> {
    let text = strip_json_fence(text);
    match contract {
        PolicyOutputContract::Binary => parse_binary(text),
        PolicyOutputContract::CategoryJson => parse_category_json(text),
        PolicyOutputContract::RationaleJson => parse_rationale_json(text),
    }
}

fn parse_binary(text: &str) -> Result<PolicyModelAnswer> {
    let violation = match text.trim() {
        "0" => false,
        "1" => true,
        _ => return Err(unreadable("binary answer must be exactly 0 or 1")),
    };
    Ok(PolicyModelAnswer {
        violation,
        ..PolicyModelAnswer::default()
    })
}

fn parse_category_json(text: &str) -> Result<PolicyModelAnswer> {
    let wire: CategoryWire =
        serde_json::from_str(text).map_err(|error| unreadable_owned(format!("{error}")))?;
    let violation = violation_bit(wire.violation)?;
    let policy_category = category_field(violation, wire.policy_category)?;
    Ok(PolicyModelAnswer {
        violation,
        policy_category,
        ..PolicyModelAnswer::default()
    })
}

fn parse_rationale_json(text: &str) -> Result<PolicyModelAnswer> {
    let wire: RationaleWire =
        serde_json::from_str(text).map_err(|error| unreadable_owned(format!("{error}")))?;
    let violation = violation_bit(wire.violation)?;
    let policy_category = category_field(violation, wire.policy_category)?;
    if wire.rule_ids.len() > POLICY_MODEL_RULE_IDS_PARSE_MAX {
        return Err(unreadable(
            "rule_ids carries more entries than an answer may cite",
        ));
    }
    Ok(PolicyModelAnswer {
        violation,
        policy_category,
        // Bounded above only as a flood stop. WHICH ids survive, and the
        // dedupe, still belong to `resolve_policy_model_response`: this reader
        // sees an answer, not the plane it was answered against — see
        // `PolicyModelAnswer::rule_ids`.
        rule_ids: wire.rule_ids,
        confidence: Some(truncate_on_char_boundary(
            wire.confidence,
            POLICY_CONFIDENCE_MAX_LEN,
        )),
        rationale: Some(truncate_on_char_boundary(
            wire.rationale,
            POLICY_RATIONALE_MAX_LEN,
        )),
    })
}

/// The violation field is a BIT, not a number: `2` is not "more violating", it
/// is an answer the policy document did not ask for.
fn violation_bit(value: u8) -> Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(unreadable("violation must be 0 or 1")),
    }
}

/// A violation names its category and a clean answer names none. The
/// asymmetric cases are both unreadable: a violation with no category cannot be
/// routed to a row, and a category beside `violation: 0` says two things at
/// once.
fn category_field(violation: bool, category: Option<String>) -> Result<Option<String>> {
    match (violation, category) {
        (true, Some(category)) if !category.trim().is_empty() => Ok(Some(category)),
        (true, _) => Err(unreadable("a violation must name a policy_category")),
        (false, None) => Ok(None),
        (false, Some(category)) if category.trim().is_empty() => Ok(None),
        (false, Some(_)) => Err(unreadable("a clean answer must not name a policy_category")),
    }
}

fn truncate_on_char_boundary(mut value: String, max_len: usize) -> String {
    if value.len() <= max_len {
        return value;
    }
    let mut end = max_len;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value
}

fn unreadable(reason: &str) -> Error {
    Error::InvalidConfig(format!("policy model answer is unreadable: {reason}"))
}

fn unreadable_owned(reason: String) -> Error {
    unreadable(&reason)
}

/// Models fence JSON out of habit. Stripping the fence is typography, not
/// leniency: everything inside it still has to parse strictly.
fn strip_json_fence(text: &str) -> &str {
    let trimmed = text.trim();
    let Some(after_fence) = trimmed.strip_prefix("```") else {
        return trimmed;
    };
    let after_header = after_fence
        .split_once('\n')
        .map_or(after_fence, |(_, rest)| rest);
    after_header
        .strip_suffix("```")
        .map_or(after_header, str::trim)
}

/// The JSON schema for the category-bearing presets, scoped to the categories
/// the calling plane actually publishes.
///
/// Scoping matters: handing a plane's model a vocabulary from some other plane
/// teaches it labels that have no authority over this content, which is the
/// factory-taxonomy leak the classifier binding exists to suppress.
fn category_schema(categories: Vec<JsonValue>, rationale: bool) -> JsonValue {
    let mut required = vec![json!("violation"), json!("policy_category")];
    let mut properties = json!({
        "violation": { "type": "integer", "enum": [0, 1] },
        "policy_category": { "type": ["string", "null"], "enum": categories },
    });
    if rationale {
        required.extend([json!("rule_ids"), json!("confidence"), json!("rationale")]);
        if let Some(map) = properties.as_object_mut() {
            map.insert(
                "rule_ids".to_owned(),
                json!({ "type": "array", "items": { "type": "string" } }),
            );
            map.insert("confidence".to_owned(), json!({ "type": "string" }));
            map.insert("rationale".to_owned(), json!({ "type": "string" }));
        }
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
    })
}
