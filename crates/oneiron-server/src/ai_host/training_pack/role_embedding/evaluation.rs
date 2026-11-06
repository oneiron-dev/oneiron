//! Paired-view retrieval on the sealed split, using the actual custody loader.
use std::collections::BTreeMap;

use oneiron::Vault;
use oneiron::training_pack::{HeldOutResult, TrainingEvalInput, TrainingRun};
use serde_json::json;

use super::super::wire::invalid;
use super::{host_config, pairs};
use crate::config::EmbedderConfig;
use crate::embedder::CheckpointEmbedder;

pub(in crate::ai_host::training_pack) fn evaluate(
    vault: &Vault,
    run: &TrainingRun,
    input: &TrainingEvalInput,
    host: &EmbedderConfig,
) -> oneiron::Result<HeldOutResult> {
    let result = run
        .result
        .as_ref()
        .ok_or_else(|| invalid("projection evaluation needs a returned checkpoint"))?;
    if input.checkpoint != result.exported_checkpoint
        || input.harness != run.plan.harness
        || blake3::hash(&input.held_out_jsonl).as_bytes() != &run.corpus.held_out.blake3
    {
        return Err(invalid("projection evaluation differs from the pinned run"));
    }
    let rows = pairs(&input.held_out_jsonl)?;
    let host = host_config(&run.plan.settings, host)?;
    let encoder = CheckpointEmbedder::load(vault, &input.checkpoint, &host)?;
    let texts: Vec<_> = rows
        .iter()
        .flat_map(|row| [row.chosen.clone(), row.rejected.clone()])
        .collect();
    let vectors = encoder.training_features(&texts)?;
    let cosine = |a: &[f32], b: &[f32]| -> oneiron::Result<f64> {
        if a.is_empty() || a.len() != b.len() || !a.iter().chain(b).all(|x| x.is_finite()) {
            return Err(invalid("projection evaluator received invalid vectors"));
        }
        let dot: f64 = a
            .iter()
            .zip(b)
            .map(|(a, b)| f64::from(*a) * f64::from(*b))
            .sum();
        let norm = |v: &[f32]| v.iter().map(|x| f64::from(*x).powi(2)).sum::<f64>().sqrt();
        let denominator = norm(a) * norm(b);
        if denominator == 0.0 {
            return Err(invalid("projection evaluator received a zero vector"));
        }
        Ok(dot / denominator)
    };
    let mut reciprocal = 0.0;
    let mut top = 0u64;
    let mut cases = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let anchor = &vectors[index * 2];
        let paired = cosine(anchor, &vectors[index * 2 + 1])?;
        let mut rank = 1u64;
        for (other, vector) in vectors.chunks_exact(2).enumerate() {
            // Pessimistic ties: an indistinguishable non-pair is not a success.
            if other != index && cosine(anchor, &vector[1])? >= paired {
                rank += 1;
            }
        }
        reciprocal += 1.0 / rank as f64;
        top += u64::from(rank == 1);
        cases.push(json!({"receipt": row.receipt_ref, "paired_cosine": paired, "rank": rank}));
    }
    let count = rows.len() as u64;
    let mrr = reciprocal / count as f64;
    let evaluation = run.plan.settings.get("evaluation");
    let minimum = evaluation
        .and_then(|v| v.get("minimum_mrr"))
        .map(|value| {
            value
                .as_f64()
                .filter(|v| v.is_finite() && (0.0..=1.0).contains(v))
                .ok_or_else(|| invalid("minimum_mrr must be finite in 0..=1"))
        })
        .transpose()?;
    let passed = minimum.is_none_or(|minimum| mrr >= minimum);
    let metrics = BTreeMap::from([
        ("paired_view_mrr".into(), mrr),
        ("paired_view_recall_at_1".into(), top as f64 / count as f64),
        ("paired_view_candidates".into(), count as f64),
    ]);
    let checkpoint_blake3 = input.checkpoint.content_hash()?;
    let log = json!({"format": "oneiron.embedding-projection.held-out/1", "run": run.id,
        "spec_blake3": run.spec_blake3, "exposure": input.exposure.id,
        "checkpoint_blake3": checkpoint_blake3, "held_out_blake3": run.corpus.held_out.blake3,
        "harness": input.harness, "criterion": evaluation, "metrics": metrics, "passed": passed,
        "encoder_provenance": encoder.provenance(), "requested_max_input_tokens": host.max_input_tokens,
        "task": "retrieve the rejected view of the same reservoir artifact from its chosen view",
        "ties": "all other candidates with equal similarity rank ahead of the pair", "cases": cases});
    let bytes =
        serde_json::to_vec(&log).map_err(|_| invalid("projection verifier log did not encode"))?;
    let pin =
        vault.keep_training_verifier_log_for_run(&run.id, "projection-held-out.json", &bytes)?;
    Ok(HeldOutResult {
        exposure: input.exposure.id,
        checkpoint_blake3,
        held_out_blake3: run.corpus.held_out.blake3,
        harness: input.harness.clone(),
        cases: count,
        metrics,
        calibration: None,
        verifier_logs: vec![pin],
        passed,
    })
}
