//! The bench's two operator inputs, each checked whole before any vault
//! exists: the one standing question definition, and the known-answer cases.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use oneiron::llm::decision::questions::{
    OutcomeBinding, OutcomeSource, QuestionActivation, QuestionDefinitionInput,
};
use oneiron::llm::decision::{AnswerContract, DecisionRung};
use serde::Deserialize;

use super::failure;
use crate::eval::EvalResult;

/// The outcome predicate: each case's gold is a claim of it on the case's unit.
pub(super) const TRUTH_PREDICATE: &str = "bench.route_calibration.truth";
/// The gold claim's value when the case's statement holds: a yes outcome.
pub(super) const GOLD_TRUE: &str = "true";
/// The gold claim's value when it does not: a no outcome.
pub(super) const GOLD_FALSE: &str = "false";
/// A gold label is exact, so the binding weighs each one fully.
const GOLD_NOISE_WEIGHT: f64 = 1.0;
/// The adapter of a standing graph question, as the standing doors read it.
const GRAPH_ADAPTER: &str = "graph";

/// One cases line as the operator writes it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaseLine {
    id: String,
    source: String,
    body: String,
    /// Optional here only so a missing known answer is refused by name.
    gold: Option<bool>,
}

/// One known-answer case: its unit's body, and the answer that only its gold
/// fact carries, written after the case is answered.
pub(super) struct Case {
    pub(super) id: String,
    /// The source case it was drawn from. The report's split joins only cases
    /// that share an answer or a fact, so one source is one case.
    pub(super) source: String,
    pub(super) body: String,
    pub(super) gold: bool,
}

pub(super) struct CaseFile {
    /// BLAKE3 of the file's bytes, as read.
    pub(super) blake3: String,
    pub(super) cases: Vec<Case>,
}

pub(super) struct Definition {
    /// BLAKE3 of the file's bytes, as read.
    pub(super) blake3: String,
    pub(super) input: QuestionDefinitionInput,
}

/// Reads one case per non-blank JSONL line. A missing or null `gold`, an
/// empty field, a repeated `id` and a second case of one `source` are refused.
pub(super) fn load_cases(path: &Path) -> EvalResult<CaseFile> {
    let bytes = std::fs::read(path)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| failure(format!("--cases {} is not UTF-8", path.display())))?;
    let mut cases = Vec::new();
    let mut ids = BTreeSet::new();
    let mut sources = BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let number = index + 1;
        let case = case_of(number, line)?;
        if !ids.insert(case.id.clone()) {
            return Err(failure(format!(
                "cases line {number}: case id {:?} repeats",
                case.id
            )));
        }
        if !sources.insert(case.source.clone()) {
            return Err(failure(format!(
                "cases line {number}: source {:?} already names a case; variants of one source would fall on both halves of the split",
                case.source
            )));
        }
        cases.push(case);
    }
    if cases.is_empty() {
        return Err(failure(format!("--cases {} holds no case", path.display())));
    }
    Ok(CaseFile {
        blake3: blake3::hash(&bytes).to_hex().to_string(),
        cases,
    })
}

fn case_of(number: usize, line: &str) -> EvalResult<Case> {
    let parsed: CaseLine = serde_json::from_str(line)
        .map_err(|error| failure(format!("cases line {number}: {error}")))?;
    let Some(gold) = parsed.gold else {
        return Err(failure(format!(
            "cases line {number}: gold is missing; every case carries its known answer"
        )));
    };
    for (field, value) in [
        ("id", &parsed.id),
        ("source", &parsed.source),
        ("body", &parsed.body),
    ] {
        if value.trim().is_empty() {
            return Err(failure(format!("cases line {number}: {field} is empty")));
        }
    }
    Ok(Case {
        id: parsed.id,
        source: parsed.source,
        body: parsed.body,
        gold,
    })
}

/// Reads the one question definition and refuses any shape this bench does
/// not measure; the engine's own validation runs again when it is stored.
pub(super) fn load_definition(path: &Path) -> EvalResult<Definition> {
    let bytes = std::fs::read(path)?;
    let input: QuestionDefinitionInput = serde_json::from_slice(&bytes)
        .map_err(|error| failure(format!("--definition {}: {error}", path.display())))?;
    if let Some(reason) = definition_refusal(&input) {
        return Err(failure(format!(
            "--definition {}: {reason}",
            path.display()
        )));
    }
    Ok(Definition {
        blake3: blake3::hash(&bytes).to_hex().to_string(),
        input,
    })
}

/// Why `definition` is not one this bench runs, or `None` when it is.
fn definition_refusal(definition: &QuestionDefinitionInput) -> Option<&'static str> {
    let dial = definition.dial;
    if !matches!(definition.question.contract, AnswerContract::Noul) {
        Some("question.contract must be noul: each gold is one yes/no outcome")
    } else if definition.adapter != GRAPH_ADAPTER {
        Some("adapter must be graph")
    } else if definition.activation != QuestionActivation::Standing {
        Some("activation must be standing")
    } else if !definition.learning {
        Some("learning must be true: the gold facts label its answers")
    } else if definition.refresh.on_arrival || definition.refresh.every_seconds.is_some() {
        Some("refresh must be on_arrival false and every_seconds null: each case is answered once")
    } else if !definition.units.is_empty() {
        Some("units must be []: the bench seeds one unit per case")
    } else if definition.posture.is_some() {
        Some("posture must be null: the bench reads under the vault's own posture")
    } else if dial.first > DecisionRung::Escalation
        || dial.ceiling < DecisionRung::Escalation
        || dial.ceiling == DecisionRung::Human
    {
        Some(
            "dial must span escalation and stop below human: the house read is the one rung filled and no person answers",
        )
    } else if !binds_truth(definition.binding.as_ref()) {
        Some(
            "binding must read the bench.route_calibration.truth claim, map \"true\" to true and \"false\" to false, weigh noise 1 and name no link; its horizon is yours",
        )
    } else {
        None
    }
}

/// Whether `binding` labels an answer by the bench's gold claim on its own
/// unit, exactly as the gold is written.
fn binds_truth(binding: Option<&OutcomeBinding>) -> bool {
    let Some(binding) = binding else {
        return false;
    };
    let mapping = BTreeMap::from([(GOLD_TRUE.to_owned(), true), (GOLD_FALSE.to_owned(), false)]);
    matches!(&binding.source, OutcomeSource::Claim { predicate } if predicate == TRUTH_PREDICATE)
        && binding.mapping == mapping
        && binding.noise_weight == GOLD_NOISE_WEIGHT
        && binding.linked_by.is_none()
}
