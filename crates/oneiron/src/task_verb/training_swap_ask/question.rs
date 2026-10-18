//! What a training swap question says and which results get one: the
//! result in brief, and the expectation and digest a question freezes.

use crate::Vault;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::llm::manifest::{ModelManifest, ModelRole};
use crate::training_pack::{SwapExpectation, TrainingRun, TrainingState};

/// The most held-out metrics a question names; it counts the rest.
const QUESTION_METRICS: usize = 8;

fn not_scored() -> Error {
    Error::InvalidConfig("a training swap question needs a scored result".into())
}

fn role_name(role: ModelRole) -> String {
    serde_json::to_value(role)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{role:?}"))
}

/// The witnessed question: the result in brief, from the run and the
/// expectation it froze. A paired comparison with the current model is not
/// measured yet, so it reads unknown; the question never claims the trained
/// model is not worse.
pub(super) fn swap_question_text(run: &TrainingRun, expected: &SwapExpectation) -> Result<String> {
    let result = run.result.as_ref().ok_or_else(not_scored)?;
    let evaluation = run.evaluation.as_ref().ok_or_else(not_scored)?;
    let start = &run.plan.starting_checkpoint;
    let harness = if evaluation.harness == run.plan.harness {
        "the plan's harness"
    } else {
        "not the plan's harness"
    };
    let checks = &result.checks;
    let mut shown = evaluation
        .metrics
        .iter()
        .take(QUESTION_METRICS)
        .map(|(name, value)| format!("{name} {value}"))
        .collect::<Vec<_>>();
    if evaluation.metrics.len() > QUESTION_METRICS {
        shown.push(format!(
            "{} more",
            evaluation.metrics.len() - QUESTION_METRICS
        ));
    }
    let calibration = evaluation.calibration.as_ref().map_or_else(
        || "not reported".to_owned(),
        |calibration| {
            format!(
                "temperature {}, Brier {}, calibration error {}",
                calibration.temperature, calibration.brier_score, calibration.calibration_error
            )
        },
    );
    let current = expected.incumbent.as_ref().map_or_else(
        || "none bound".to_owned(),
        |binding| binding.model.to_string(),
    );
    Ok(format!(
        "The Coach trained a model for your {role} role and scored it; it does not swap in by \
         itself. Starting checkpoint: {start_model} (load set {start_hash}). Returned \
         checkpoint: {model} (load set {checkpoint}). Harness: {repository}@{revision}, \
         {harness}. Export checks: {checks_read} ({mismatches} hash mismatches, {flips} argmax \
         flips, max logit difference {difference} against tolerance {tolerance}). Exact-hash \
         overlaps with the held-out set: {overlaps}. Held-out: {cases} cases, {metrics}; \
         calibration: {calibration}; evaluator verdict: {verdict}. Paired comparison with the \
         current model: unknown (not measured yet). Current model: {current}. Doing nothing \
         keeps it.",
        role = role_name(run.plan.role),
        start_model = start.model,
        start_hash = bytes_to_hex_lower(&start.content_hash()?),
        model = result.exported_checkpoint.model,
        checkpoint = bytes_to_hex_lower(&expected.checkpoint_blake3),
        repository = evaluation.harness.repository,
        revision = evaluation.harness.revision,
        checks_read = if checks.passed() { "passed" } else { "failed" },
        mismatches = checks.hash_mismatches.len(),
        flips = checks.argmax_flips,
        difference = checks.max_logit_difference,
        tolerance = checks.tolerance,
        overlaps = run.corpus.exact_hash_overlaps,
        cases = evaluation.cases,
        metrics = shown.join(", "),
        verdict = if evaluation.passed {
            "passed"
        } else {
            "not passed"
        },
    ))
}

/// What a swap of `run` binds against and the digest its question freezes,
/// when the Coach may ask about it: Scored, its checks allowing a proposal,
/// not an embedder, and not the run its role last bound.
pub(super) fn candidate_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    run: &TrainingRun,
    manifest: Option<&ModelManifest>,
) -> Result<Option<(SwapExpectation, String)>> {
    if run.state != TrainingState::Scored
        || !run.can_propose_swap()
        || run.plan.role == ModelRole::RetrievalEmbedder
        || crate::training_pack::role_swap_receipt_in(vault, txn, run.plan.role)?
            .is_some_and(|receipt| receipt.run == run.id)
    {
        return Ok(None);
    }
    let expected = SwapExpectation::of(run, manifest)?;
    let checks = &run.result.as_ref().ok_or_else(not_scored)?.checks;
    let bytes = crate::llm::canonical_json_bytes(&(&expected, checks))
        .map_err(|_| Error::InvalidConfig("training swap digest encoding failed".into()))?;
    let digest = bytes_to_hex_lower(blake3::hash(&bytes).as_bytes());
    Ok(Some((expected, digest)))
}
