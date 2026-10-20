//! The quality check: does the reply keep the Dreamer's reply contract, and
//! how much of the case's gold does it reach. Deterministic; no model judges.
//!
//! * `claims`: `{"candidates":[...]}`, each candidate exactly `subject`
//!   (32 hex), `predicate` (two or more dotted identifier segments), `value`,
//!   `confidence` (a number) and `evidence_turn_refs` (one or more 32-hex
//!   ids). Score: the valid-count ratio against `n_gold` when every candidate
//!   is valid, else 0.
//! * `decisions`: exactly `{"answers":[{"id","action","reason"}...]}`. Score:
//!   gold ids whose answer names the gold action (trimmed, any case), over
//!   gold ids.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{Value as JsonValue, json};

use super::cases::{Case, Scorer};

/// The predicate rule the claims schema states, as the regex the
/// `response_format` schema carries. [`is_predicate`] checks the same rule.
const PREDICATE_PATTERN: &str = "^[A-Za-z_][A-Za-z0-9_-]*([.][A-Za-z_][A-Za-z0-9_-]*)+$";
const HEX32_PATTERN: &str = "^[0-9a-fA-F]{32}$";
const CANDIDATE_KEYS: [&str; 5] = [
    "subject",
    "predicate",
    "value",
    "confidence",
    "evidence_turn_refs",
];
const ANSWER_KEYS: [&str; 3] = ["id", "action", "reason"];

#[derive(Clone, Debug, Serialize)]
pub(super) struct Quality {
    pub(super) scorer: Scorer,
    pub(super) parse_ok: bool,
    pub(super) schema_ok: bool,
    pub(super) n_candidates: Option<usize>,
    pub(super) n_valid: Option<usize>,
    pub(super) n_gold: Option<u64>,
    pub(super) count_ratio: Option<f64>,
    pub(super) n_answers: Option<usize>,
    pub(super) gold_ids: Option<usize>,
    pub(super) gold_matched: Option<usize>,
    pub(super) score: f64,
}

impl Quality {
    fn unparsed(scorer: Scorer) -> Self {
        Self {
            scorer,
            parse_ok: false,
            schema_ok: false,
            n_candidates: None,
            n_valid: None,
            n_gold: None,
            count_ratio: None,
            n_answers: None,
            gold_ids: None,
            gold_matched: None,
            score: 0.0,
        }
    }
}

/// The `response_format` schema `--schema on` sends: the same shape the
/// check below holds the reply to.
pub(super) fn response_schema(scorer: Scorer) -> JsonValue {
    let hex32 = json!({"type": "string", "pattern": HEX32_PATTERN});
    match scorer {
        Scorer::Claims => json!({
            "type": "object",
            "required": ["candidates"],
            "properties": {
                "candidates": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": CANDIDATE_KEYS,
                        "properties": {
                            "subject": hex32.clone(),
                            "predicate": {"type": "string", "pattern": PREDICATE_PATTERN},
                            "value": {},
                            "confidence": {"type": "number"},
                            "evidence_turn_refs": {"type": "array", "minItems": 1, "items": hex32},
                        },
                    },
                },
            },
        }),
        Scorer::Decisions => json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["answers"],
            "properties": {
                "answers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ANSWER_KEYS,
                        "properties": {
                            "id": {"type": "string"},
                            "action": {"type": "string"},
                            "reason": {"type": "string"},
                        },
                    },
                },
            },
        }),
    }
}

pub(super) fn score(case: &Case, reply: &str) -> Quality {
    let parsed = serde_json::from_str::<JsonValue>(unfenced(reply)).ok();
    match case.scorer {
        Scorer::Claims => claims(parsed.as_ref(), case.n_gold),
        Scorer::Decisions => decisions(parsed.as_ref(), case.gold.as_ref()),
    }
}

/// The reply without one surrounding ```` ``` ```` or ```` ```json ```` fence.
fn unfenced(reply: &str) -> &str {
    let trimmed = reply.trim();
    let Some(inner) = trimmed
        .strip_prefix("```")
        .and_then(|rest| rest.strip_suffix("```"))
    else {
        return trimmed;
    };
    let Some((info, body)) = inner.split_once('\n') else {
        return trimmed;
    };
    let info = info.trim();
    if info.is_empty() || info.eq_ignore_ascii_case("json") {
        body.trim()
    } else {
        trimmed
    }
}

fn is_hex32(text: &str) -> bool {
    text.len() == 32 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// [`PREDICATE_PATTERN`] by hand: two or more `.`-joined segments, each a
/// letter or `_` then letters, digits, `_` or `-`.
fn is_predicate(text: &str) -> bool {
    let mut segments = 0;
    for segment in text.split('.') {
        let mut bytes = segment.bytes();
        let Some(first) = bytes.next() else {
            return false;
        };
        let head = first.is_ascii_alphabetic() || first == b'_';
        if !(head && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')) {
            return false;
        }
        segments += 1;
    }
    segments >= 2
}

fn valid_candidate(candidate: &JsonValue) -> bool {
    let Some(fields) = candidate.as_object() else {
        return false;
    };
    let text = |key: &str| fields.get(key).and_then(JsonValue::as_str);
    fields.len() == CANDIDATE_KEYS.len()
        && text("subject").is_some_and(is_hex32)
        && text("predicate").is_some_and(is_predicate)
        && fields.contains_key("value")
        && fields.get("confidence").is_some_and(JsonValue::is_number)
        && fields
            .get("evidence_turn_refs")
            .and_then(JsonValue::as_array)
            .is_some_and(|refs| {
                !refs.is_empty() && refs.iter().all(|r| r.as_str().is_some_and(is_hex32))
            })
}

fn claims(parsed: Option<&JsonValue>, n_gold: Option<u64>) -> Quality {
    let Some(candidates) = parsed
        .and_then(|reply| reply.get("candidates"))
        .and_then(JsonValue::as_array)
    else {
        return Quality::unparsed(Scorer::Claims);
    };
    let n_valid = candidates.iter().filter(|c| valid_candidate(c)).count();
    let schema_ok = n_valid == candidates.len();
    // A count ratio needs gold to count against; `n_gold: 0` has none.
    let count_ratio = n_gold.filter(|gold| *gold > 0).map(|gold| {
        let gold = usize::try_from(gold).unwrap_or(usize::MAX);
        n_valid.min(gold) as f64 / gold as f64
    });
    Quality {
        scorer: Scorer::Claims,
        parse_ok: true,
        schema_ok,
        n_candidates: Some(candidates.len()),
        n_valid: Some(n_valid),
        n_gold,
        count_ratio,
        n_answers: None,
        gold_ids: None,
        gold_matched: None,
        score: if schema_ok {
            count_ratio.unwrap_or(1.0)
        } else {
            0.0
        },
    }
}

fn valid_answer(answer: &JsonValue) -> bool {
    answer.as_object().is_some_and(|fields| {
        fields.len() == ANSWER_KEYS.len()
            && ANSWER_KEYS
                .iter()
                .all(|key| fields.get(*key).is_some_and(JsonValue::is_string))
    })
}

fn decisions(parsed: Option<&JsonValue>, gold: Option<&BTreeMap<String, String>>) -> Quality {
    let top = parsed.and_then(JsonValue::as_object);
    let Some(answers) = top
        .and_then(|top| top.get("answers"))
        .and_then(JsonValue::as_array)
    else {
        return Quality::unparsed(Scorer::Decisions);
    };
    let schema_ok = top.is_some_and(|top| top.len() == 1) && answers.iter().all(valid_answer);
    // An id answered twice keeps its first answer.
    let mut chosen: BTreeMap<&str, &str> = BTreeMap::new();
    for answer in answers {
        if let (Some(id), Some(action)) = (
            answer.get("id").and_then(JsonValue::as_str),
            answer.get("action").and_then(JsonValue::as_str),
        ) {
            chosen.entry(id).or_insert(action);
        }
    }
    let (gold_ids, gold_matched, score) = match gold.filter(|gold| !gold.is_empty()) {
        Some(gold) => {
            let matched = gold
                .iter()
                .filter(|(id, want)| {
                    chosen
                        .get(id.as_str())
                        .is_some_and(|got| got.trim().eq_ignore_ascii_case(want.trim()))
                })
                .count();
            (
                Some(gold.len()),
                Some(matched),
                matched as f64 / gold.len() as f64,
            )
        }
        // No gold to match: the score is the contract alone.
        None => (Some(0), None, if schema_ok { 1.0 } else { 0.0 }),
    };
    Quality {
        scorer: Scorer::Decisions,
        parse_ok: true,
        schema_ok,
        n_candidates: None,
        n_valid: None,
        n_gold: None,
        count_ratio: None,
        n_answers: Some(answers.len()),
        gold_ids,
        gold_matched,
        score,
    }
}
