//! Held-out measurements for the worker's exported binary question head.
//! Calibration uses training-side logits, never the held-out answers.

use std::collections::{BTreeMap, BTreeSet};

use oneiron::training_pack::{
    CalibrationResult, CheckpointFileUpload, CheckpointUpload, HeldOutResult, QuestionTarget,
    SplitSide, TrainingEvalInput, TrainingRun,
};
use oneiron::{Error, Vault};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::oneironer::QuestionHead;

mod calibration;

const LOG_FORMAT: &str = "oneiron.question-held-out/1";
const ROW_FORMAT: &str = "oneiron.detector-target-row/1";

fn invalid(detail: &str) -> Error {
    Error::InvalidConfig(detail.into())
}

/// No quality floor is implicit. An authored recipe may request one.
#[derive(Default, Serialize)]
struct Criterion {
    minimum_accuracy: Option<f64>,
}

impl Criterion {
    fn from_settings(settings: &Value) -> oneiron::Result<Self> {
        let Some(value) = settings.get("evaluation") else {
            return Ok(Self::default());
        };
        let fields = value
            .as_object()
            .ok_or_else(|| invalid("question evaluation settings must be an object"))?;
        if fields.keys().any(|key| key != "minimum_accuracy") {
            return Err(invalid("unknown question evaluation setting"));
        }
        let minimum_accuracy = fields
            .get("minimum_accuracy")
            .map(|value| {
                value
                    .as_f64()
                    .filter(|value| value.is_finite() && (0.0..=1.0).contains(value))
                    .ok_or_else(|| invalid("minimum_accuracy must be a finite number in 0..=1"))
            })
            .transpose()?;
        Ok(Self { minimum_accuracy })
    }

    fn passed(&self, accuracy: f64) -> bool {
        self.minimum_accuracy
            .is_none_or(|minimum| accuracy >= minimum)
    }
}

#[derive(Deserialize)]
struct Row {
    format: String,
    row: String,
    question_id: String,
    question_version: u32,
    corpus_revision: String,
    feature_schema: String,
    label_schema: String,
    split: SplitSide,
    label: Label,
    input: Value,
}

#[derive(Deserialize)]
struct Label {
    answer: Answer,
    unit: String,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Answer {
    No,
    Yes,
}

impl Answer {
    fn yes(self) -> bool {
        matches!(self, Self::Yes)
    }

    fn predicted(logits: [f64; 2]) -> Self {
        if logits[1] > logits[0] {
            Self::Yes
        } else {
            Self::No
        }
    }
}

fn rows(bytes: &[u8], question: &QuestionTarget, side: SplitSide) -> oneiron::Result<Vec<Row>> {
    let mut ids = BTreeSet::new();
    let mut rows = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let row: Row = serde_json::from_slice(line)
            .map_err(|_| invalid("question evaluation row is malformed"))?;
        if row.format != ROW_FORMAT
            || row.row.trim().is_empty()
            || !ids.insert(row.row.clone())
            || row.question_id != question.question_id
            || row.question_version != question.question_version
            || row.corpus_revision != question.corpus_revision
            || row.feature_schema != question.feature_schema
            || row.label_schema != question.label_schema
            || row.label.unit != "target"
            || row.split != side
        {
            return Err(invalid(
                "question evaluation row differs from its target or split",
            ));
        }
        question.render_target_text(&row.input)?;
        rows.push(row);
    }
    if rows.is_empty() {
        return Err(invalid("question evaluation needs a nonempty pinned split"));
    }
    Ok(rows)
}

fn logits(head: &QuestionHead, input: &Value) -> oneiron::Result<[f64; 2]> {
    head.logits(input)
        .map_err(|_| invalid("the exported question head could not score a corpus row"))
}

#[derive(Serialize)]
struct CaseLog {
    row: String,
    input_blake3: [u8; 32],
    answer: Answer,
    prediction: Answer,
    logits: [f64; 2],
    yes_probability: f64,
}

/// The caller opened this run's held-out exposure. Custody and the existing
/// record door retain the measurements; this does not approve or serve a head.
pub(super) fn evaluate(
    vault: &Vault,
    run: &TrainingRun,
    input: &TrainingEvalInput,
) -> oneiron::Result<HeldOutResult> {
    let question = run
        .plan
        .target
        .question()
        .ok_or_else(|| invalid("this evaluator scores a question, not a role"))?;
    let criterion = Criterion::from_settings(&run.plan.settings)?;
    let returned = run
        .result
        .as_ref()
        .ok_or_else(|| invalid("question evaluation requires a returned checkpoint"))?;
    if input.checkpoint != returned.exported_checkpoint
        || input.harness != run.plan.harness
        || blake3::hash(&input.held_out_jsonl).as_bytes() != &run.corpus.held_out.blake3
    {
        return Err(invalid(
            "question evaluation input differs from its pinned run",
        ));
    }
    let training = rows(
        &vault.read_training_artifact(&run.corpus.training)?,
        question,
        SplitSide::Training,
    )?;
    let held_out = rows(&input.held_out_jsonl, question, SplitSide::HeldOut)?;
    let export = CheckpointUpload {
        model: input.checkpoint.model.clone(),
        files: input
            .checkpoint
            .files
            .iter()
            .map(|file| {
                Ok(CheckpointFileUpload {
                    name: file.name.clone(),
                    kind: file.kind,
                    source: file.source.clone(),
                    blake3: file.content.blake3,
                    bytes: vault.read_training_artifact(&file.content)?,
                })
            })
            .collect::<oneiron::Result<Vec<_>>>()?,
    };
    let inputs: Vec<_> = training
        .iter()
        .chain(&held_out)
        .map(|row| &row.input)
        .collect();
    let head = QuestionHead::load(question, &export, &inputs)
        .map_err(|_| invalid("the returned question-head load set could not be loaded"))?;
    drop(inputs);
    drop(export);
    let fitting = training
        .iter()
        .map(|row| Ok((logits(&head, &row.input)?, row.label.answer.yes())))
        .collect::<oneiron::Result<Vec<_>>>()?;
    let fit = calibration::fit(&fitting);
    drop(fitting);
    drop(training);

    let mut confusion = [[0u64; 2]; 2];
    let mut probabilities = Vec::with_capacity(held_out.len());
    let mut uncalibrated = Vec::with_capacity(held_out.len());
    let mut cases = Vec::with_capacity(held_out.len());
    for row in held_out {
        let raw = logits(&head, &row.input)?;
        let prediction = Answer::predicted(raw);
        let answer = row.label.answer.yes();
        let probability = calibration::yes_probability(raw, fit.temperature);
        confusion[usize::from(answer)][usize::from(prediction.yes())] += 1;
        probabilities.push((probability, answer));
        uncalibrated.push((calibration::yes_probability(raw, 1.0), answer));
        let bytes = oneiron::llm::canonical_json_bytes(&row.input)
            .map_err(|_| invalid("question input could not be encoded"))?;
        cases.push(CaseLog {
            row: row.row,
            input_blake3: *blake3::hash(&bytes).as_bytes(),
            answer: row.label.answer,
            prediction,
            logits: raw,
            yes_probability: probability,
        });
    }
    let count = cases.len() as u64;
    let correct = confusion[0][0] + confusion[1][1];
    let accuracy = correct as f64 / count as f64;
    let (brier_score, calibration_error) = calibration::metrics(&probabilities);
    let (raw_brier, raw_ece) = calibration::metrics(&uncalibrated);
    let metrics = BTreeMap::from([
        ("binary_accuracy".into(), accuracy),
        ("correct".into(), correct as f64),
        ("incorrect".into(), (count - correct) as f64),
        ("true_no".into(), confusion[0][0] as f64),
        ("false_yes".into(), confusion[0][1] as f64),
        ("false_no".into(), confusion[1][0] as f64),
        ("true_yes".into(), confusion[1][1] as f64),
        (
            "no_support".into(),
            (confusion[0][0] + confusion[0][1]) as f64,
        ),
        (
            "yes_support".into(),
            (confusion[1][0] + confusion[1][1]) as f64,
        ),
        ("binary_brier".into(), brier_score),
        ("binary_ece".into(), calibration_error),
        ("uncalibrated_binary_brier".into(), raw_brier),
        ("uncalibrated_binary_ece".into(), raw_ece),
    ]);
    let passed = criterion.passed(accuracy);
    let checkpoint_blake3 = input.checkpoint.content_hash()?;
    let log = json!({
        "format": LOG_FORMAT,
        "run": run.id,
        "spec_blake3": run.spec_blake3,
        "exposure": input.exposure.id,
        "checkpoint_blake3": checkpoint_blake3,
        "training_blake3": run.corpus.training.blake3,
        "held_out_blake3": run.corpus.held_out.blake3,
        "harness": input.harness,
        "question_id": question.question_id,
        "question_version": question.question_version,
        "definition_blake3": question.definition_blake3,
        "criterion": criterion,
        "verdict": "complete_measurement; apply minimum_accuracy only when explicitly set",
        "prediction": "raw [no,yes] argmax; tie=no; exact target answer",
        "calibration": fit,
        "calibration_fitting_split": "training",
        "brier_definition": "mean((P(yes)-I(answer=yes))^2) on held-out rows",
        "ece_definition": "sum_bin(n_bin/N * abs(mean_P_yes - fraction_yes))",
        "ece_bins": calibration::ECE_BINS,
        "metrics": metrics,
        "passed": passed,
        "cases": cases,
    });
    let bytes = serde_json::to_vec(&log)
        .map_err(|_| invalid("question verifier log could not be serialized"))?;
    let pin =
        vault.keep_training_verifier_log_for_run(&run.id, "question-held-out.json", &bytes)?;
    Ok(HeldOutResult {
        exposure: input.exposure.id,
        checkpoint_blake3,
        held_out_blake3: run.corpus.held_out.blake3,
        harness: input.harness.clone(),
        cases: count,
        metrics,
        calibration: Some(CalibrationResult {
            temperature: fit.temperature,
            brier_score,
            calibration_error,
        }),
        verifier_logs: vec![pin],
        passed,
    })
}
