//! Reproduce the trainer's question-head probes on the native Candle stack.
//! Token windows and raw logits are measured independently; a failed load
//! never masquerades as a successful or unattempted logit reproduction.

use oneiron::training_pack::{
    CandleParityCheck, CheckpointUpload, ProbeCase, ProbeMeasurement, QuestionTarget,
};

use crate::oneironer::{QuestionHead, QuestionTokenizer};

/// The export's native reproduction of every planned probe. Reference logits
/// are the actual receipt's exported logits in `probes` order, not guessed
/// from an argmax or the producer's aggregate difference.
pub(super) fn candle_parity(
    question: &QuestionTarget,
    cases: &[ProbeCase],
    export: &CheckpointUpload,
    probes: &[ProbeMeasurement],
    reference_logits: &[Vec<f64>],
    tolerance: f64,
) -> CandleParityCheck {
    let tokenizer = QuestionTokenizer::load(export).ok();
    let token_mismatches: Vec<String> = probes
        .iter()
        .filter(|probe| {
            let reproduced = tokenizer
                .as_ref()
                .zip(cases.iter().find(|case| case.id == probe.probe_id))
                .and_then(|(tokenizer, case)| tokenizer.tokens_blake3(question, &case.input).ok());
            reproduced.is_none() || reproduced != probe.tokens_blake3
        })
        .map(|probe| probe.probe_id.clone())
        .collect();
    let inputs: Vec<_> = probes
        .iter()
        .filter_map(|probe| cases.iter().find(|case| case.id == probe.probe_id))
        .map(|case| &case.input)
        .collect();
    let head = QuestionHead::load(question, export, &inputs).ok();
    let logits_match = tolerance.is_finite()
        && tolerance >= 0.0
        && reference_logits.len() == probes.len()
        && head.as_ref().is_some_and(|head| {
            probes
                .iter()
                .zip(reference_logits)
                .all(|(probe, reference)| {
                    let Some(case) = cases.iter().find(|case| case.id == probe.probe_id) else {
                        return false;
                    };
                    let Ok(actual) = head.logits(&case.input) else {
                        return false;
                    };
                    reference.len() == actual.len()
                        && reference.iter().zip(actual).all(|(reference, actual)| {
                            reference.is_finite() && (actual - reference).abs() <= tolerance
                        })
                        && u64::from(actual[1] > actual[0]) == probe.export_argmax
                })
        });
    CandleParityCheck {
        tokens_match: token_mismatches.is_empty(),
        token_mismatches,
        logits_match: Some(logits_match),
    }
}
