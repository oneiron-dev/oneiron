//! A generated read's Score question (OF-498a, L06 ack 10-22): one number in the question's
//! range and how sure the generation is of it, beside the pack's noul and choice questions in
//! the same request. Its entry is the score and that probability; a missing, unreadable or
//! out-of-range one is no answer, so the question abstains, as a noul or choice question with
//! no weight does. A score is never guessed.

use serde_json::{Value, json};

use super::super::ladder::{PairedAnswer, ProviderDecision};
use super::super::{DecisionAnswer, DecisionQuestion};

/// The entry's score field.
const SCORE: &str = "score";
/// The entry's probability field: how sure the generation is of its score.
const PROBABILITY: &str = "probability";

/// The answer format of a score question's entry: its score from `min` to `max`, and the
/// probability that the score is right.
pub(super) fn property(min: f64, max: f64) -> Value {
    json!({
        "type": "object",
        "description": "This question's score, and the probability that the score is right.",
        "properties": {
            SCORE: {"type": "number", "minimum": min, "maximum": max},
            PROBABILITY: {"type": "number", "minimum": 0, "maximum": 1},
        },
        "required": [SCORE, PROBABILITY],
        "additionalProperties": false,
    })
}

/// How the request's turn names a score question: its wire key, its text and its range.
pub(super) fn shown(key: String, question: &DecisionQuestion, min: f64, max: f64) -> Value {
    json!({"id": key, "question": question.text, "range": [min, max]})
}

/// The answer a score question's `entry` gives: its score, at the probability the entry
/// states. Anything else abstains; `paired` stays the paired reading either way.
pub(super) fn answer(
    entry: Option<&Value>,
    min: f64,
    max: f64,
    paired: Option<PairedAnswer>,
) -> ProviderDecision {
    let read = entry.and_then(|entry| {
        let score = entry
            .get(SCORE)
            .and_then(Value::as_f64)
            .filter(|score| score.is_finite() && *score >= min && *score <= max)?;
        let probability = entry
            .get(PROBABILITY)
            .and_then(Value::as_f64)
            .filter(|probability| probability.is_finite() && (0.0..=1.0).contains(probability))?;
        Some((score, probability))
    });
    match read {
        Some((score, probability)) => ProviderDecision {
            answer: DecisionAnswer::Score(score),
            probability: Some(probability),
            paired,
            person: None,
            served: None,
        },
        None => ProviderDecision {
            answer: DecisionAnswer::Abstain,
            probability: None,
            paired,
            person: None,
            served: None,
        },
    }
}
