//! Offline extraction-teacher admission over the fixed CoNLL BIO probe.
//!
//! A model-repository runner performs inference. This bench only scores its output and
//! releases a candidate manifest file if the probe passes; it does not serve a teacher.
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use oneiron::llm::manifest::{ModelManifest, ModelRole};
use serde::Deserialize;

const GOLD: &str = include_str!("../fixtures/teacher_probe/conll_bio.v1.json");
// Exact typed-entity span micro-F1, in millionths; not token accuracy.
const MIN_F1: u64 = 800_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sentence {
    tokens: Vec<String>,
    tags: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    name: String,
    sentences: Vec<Sentence>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerOutput {
    model_id: String,
    predictions: Vec<Vec<String>>,
}

type Span = (usize, usize, usize, String); // sentence, start, end-exclusive, type

fn spans(sentences: &[Vec<String>]) -> Result<BTreeSet<Span>, String> {
    let mut all = BTreeSet::new();
    for (sentence, tags) in sentences.iter().enumerate() {
        let mut open: Option<(usize, &str)> = None;
        for (index, tag) in tags.iter().map(String::as_str).chain(["O"]).enumerate() {
            let (prefix, kind) = if tag == "O" {
                ("O", "")
            } else {
                tag.split_once('-')
                    .ok_or_else(|| format!("invalid BIO tag {tag:?}"))?
            };
            if tag != "O"
                && (!matches!(prefix, "B" | "I") || !matches!(kind, "PER" | "ORG" | "LOC" | "MISC"))
            {
                return Err(format!("invalid BIO tag {tag:?}"));
            }
            if prefix == "I" && open.is_none_or(|(_, active)| active != kind) {
                return Err(format!(
                    "orphan I tag in sentence {sentence} at token {index}"
                ));
            }
            if prefix != "I" {
                if let Some((start, active)) = open.take() {
                    all.insert((sentence, start, index, active.to_owned()));
                }
                if prefix == "B" {
                    open = Some((index, kind));
                }
            }
        }
    }
    Ok(all)
}

fn evaluate(gold: &Probe, result: &RunnerOutput) -> Result<(u64, usize, usize, usize), String> {
    if gold.name != "oneiron-conll-bio-v1"
        || gold.sentences.is_empty()
        || gold.sentences.len() != result.predictions.len()
    {
        return Err("probe identity or sentence count mismatch".into());
    }
    for (sentence, tags) in gold.sentences.iter().zip(&result.predictions) {
        if sentence.tokens.is_empty()
            || sentence.tags.len() != sentence.tokens.len()
            || tags.len() != sentence.tokens.len()
        {
            return Err("probe token/tag alignment mismatch".into());
        }
    }
    let expected = spans(
        &gold
            .sentences
            .iter()
            .map(|s| s.tags.clone())
            .collect::<Vec<_>>(),
    )?;
    let predicted = spans(&result.predictions)?;
    let correct = predicted.intersection(&expected).count();
    let denominator = predicted.len() + expected.len();
    if denominator == 0 {
        return Err("empty probe spans".into());
    }
    let f1 = (2 * correct as u64 * 1_000_000) / denominator as u64;
    Ok((f1, correct, predicted.len(), expected.len()))
}

fn gate(
    checkpoint: &Path,
    runner: &Path,
    manifest_path: &Path,
    out: &Path,
) -> Result<String, String> {
    if out == manifest_path || out.exists() {
        return Err("output must be a new file, distinct from candidate manifest".into());
    }
    let gold: Probe = serde_json::from_str(GOLD).map_err(|e| e.to_string())?;
    let manifest_bytes = std::fs::read(manifest_path).map_err(|e| e.to_string())?;
    let manifest = ModelManifest::from_json(&manifest_bytes).map_err(|e| e.to_string())?;
    let model = manifest
        .binding(ModelRole::ExtractionTeacher)
        .map_err(|e| e.to_string())?
        .model
        .to_string();
    if !checkpoint.is_dir()
        || std::fs::read_to_string(checkpoint.join("model_id"))
            .map_err(|e| e.to_string())?
            .trim()
            != model
    {
        return Err("checkpoint model identity does not match teacher binding".into());
    }
    // Pass the compiled, immutable probe to an external runner without relying on
    // CARGO_MANIFEST_DIR (which may name a different build host at runtime).
    let probe_file = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    std::fs::write(probe_file.path(), GOLD).map_err(|e| e.to_string())?;
    let output = Command::new(runner)
        .arg("--checkpoint")
        .arg(checkpoint)
        .arg("--probe")
        .arg(probe_file.path())
        .output()
        .map_err(|e| format!("runner failed to start: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "runner exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let result: RunnerOutput = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("invalid runner output: {e}"))?;
    if result.model_id != model {
        return Err("runner model identity or checkpoint directory mismatch".into());
    }
    let (f1, correct, predicted, expected) = evaluate(&gold, &result)?;
    let report = format!(
        "teacher probe: model={model} exact_span_micro_f1={:.6} correct={correct} predicted={predicted} gold={expected} bar={:.6}",
        f1 as f64 / 1_000_000.0,
        MIN_F1 as f64 / 1_000_000.0
    );
    if f1 < MIN_F1 {
        return Err(format!("{report}: FAIL (manifest not released)"));
    }
    // No manifest artifact exists before all checks pass. An existing artifact is never overwritten.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(|e| e.to_string())?;
    if let Err(e) = file
        .write_all(&manifest_bytes)
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = std::fs::remove_file(out);
        return Err(format!("failed to release manifest: {e}"));
    }
    Ok(format!(
        "{report}: PASS (manifest released to {})",
        out.display()
    ))
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    let [
        checkpoint_flag,
        checkpoint,
        runner_flag,
        runner,
        manifest_flag,
        manifest,
        out_flag,
        out,
    ] = args
    else {
        eprintln!(
            "usage: oneiron-bench teacher-probe --checkpoint DIR --runner EXECUTABLE --manifest CANDIDATE.json --out APPROVED.json"
        );
        return ExitCode::FAILURE;
    };
    if checkpoint_flag != "--checkpoint"
        || runner_flag != "--runner"
        || manifest_flag != "--manifest"
        || out_flag != "--out"
    {
        eprintln!("teacher-probe: invalid options");
        return ExitCode::FAILURE;
    }
    let (checkpoint, runner, manifest, out) = (
        PathBuf::from(checkpoint),
        PathBuf::from(runner),
        PathBuf::from(manifest),
        PathBuf::from(out),
    );
    match gate(&checkpoint, &runner, &manifest, &out) {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("teacher-probe: {reason}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[path = "teacher_probe_tests.rs"]
mod tests;
