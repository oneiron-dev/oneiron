//! Gold-anchored QA lane with exact normalized-answer scoring.
use super::{Of360EvalError, Of360GoldCase, Of360RateMetric, Of360Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Of360GoldQa {
    pub question_id: String,
    pub question: String,
    pub accepted_answers: Vec<String>,
    pub evidence_memory_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Of360QaAnswer {
    pub question_id: String,
    pub answer: String,
}

pub(super) fn score_qa(
    case: &Of360GoldCase,
    answers: &[Of360QaAnswer],
) -> Of360Result<Of360RateMetric> {
    let invalid = |reason| Of360EvalError::InvalidQa {
        case_id: case.case_id.clone(),
        reason,
    };
    let mut gold = HashMap::new();
    for qa in &case.qa {
        if qa.question_id.is_empty()
            || qa.question.trim().is_empty()
            || qa.accepted_answers.is_empty()
            || qa.accepted_answers.iter().any(|s| s.trim().is_empty())
            || qa.evidence_memory_ids.is_empty()
            || qa
                .evidence_memory_ids
                .iter()
                .any(|id| !case.gold_memory_points.iter().any(|m| m.memory_id == *id))
        {
            return Err(invalid(
                "QA must name a question, answers, and known evidence",
            ));
        }
        if gold.insert(qa.question_id.as_str(), qa).is_some() {
            return Err(invalid("duplicate gold question"));
        }
    }
    let mut seen = HashSet::new();
    let mut correct = 0;
    for answer in answers {
        let qa = gold
            .get(answer.question_id.as_str())
            .ok_or_else(|| invalid("unknown question"))?;
        if !seen.insert(&answer.question_id) {
            return Err(invalid("duplicate answer"));
        }
        if qa
            .accepted_answers
            .iter()
            .any(|expected| normalize(expected) == normalize(&answer.answer))
        {
            correct += 1;
        }
    }
    // Unanswered gold questions remain in the fixed denominator.
    Ok(Of360RateMetric::new(
        f64::from(correct),
        case.qa.len() as f64,
    ))
}

fn normalize(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}
