//! ONE-1579 axis 1: the warm and cold retrieval passes.
//!
//! Warm and cold are two POPULATIONS, never one average. Each pass produces
//! its own [`SampleSet`], and a call that ERRORED is counted as an error and
//! contributes to neither latency nor recall — which is why the completed
//! sample floor in `axes.rs` is counted on what came back rather than on what
//! the plan asked for.
//!
//! Engine boundary: retrieval is `Vault::search_text_with_telemetry` through
//! the public seam. No retrieval internal in `vault.rs` or `ppr.rs` is
//! instrumented.

use std::time::Instant;

use oneiron::Vault;

use super::axes::SampleSet;
use super::corpus::Corpus;

/// One pass over every query. Latency, recall and telemetry presence are kept
/// as parallel per-query samples so no caller can collapse them.
struct QueryPass {
    latency_ms: Vec<f64>,
    recall: Vec<f64>,
    telemetry_run_ids: usize,
    errors: usize,
}

fn query_pass(vault: &Vault, corpus: &Corpus, k: usize) -> QueryPass {
    let mut pass = QueryPass {
        latency_ms: Vec::with_capacity(corpus.queries.len()),
        recall: Vec::with_capacity(corpus.queries.len()),
        telemetry_run_ids: 0,
        errors: 0,
    };
    for query in &corpus.queries {
        let started = Instant::now();
        let outcome = vault.search_text_with_telemetry(&query.text, k);
        let elapsed_ms = started.elapsed().as_secs_f64() * 1e3;
        match outcome {
            Ok(result) => {
                pass.latency_ms.push(elapsed_ms);
                if result.run_id.is_some() {
                    pass.telemetry_run_ids += 1;
                }
                let found = result.value.iter().any(|hit| hit.id == query.expected);
                pass.recall.push(if found { 1.0 } else { 0.0 });
            }
            Err(_) => pass.errors += 1,
        }
    }
    pass
}

fn sample_set(label: &'static str, pass: &QueryPass) -> SampleSet {
    SampleSet::new(
        label,
        &pass.latency_ms,
        &pass.recall,
        pass.telemetry_run_ids,
        pass.errors,
    )
}

/// COLD: the caller must hand a vault handle that has just been opened and has
/// served nothing. Nothing is pre-seeded, warmed or replayed before this call,
/// and the pass runs exactly once.
pub(crate) fn measure_cold(vault: &Vault, corpus: &Corpus, k: usize) -> SampleSet {
    sample_set("cold", &query_pass(vault, corpus, k))
}

/// WARM: `warmup_passes` discarded passes first, then one measured pass. The
/// samples never join the cold set.
pub(crate) fn measure_warm(
    vault: &Vault,
    corpus: &Corpus,
    k: usize,
    warmup_passes: usize,
) -> SampleSet {
    for _ in 0..warmup_passes {
        let _ = query_pass(vault, corpus, k);
    }
    sample_set("warm", &query_pass(vault, corpus, k))
}

#[cfg(test)]
mod tests {
    use super::super::corpus::{generate_corpus, index_corpus, perf_vault_config};
    use super::*;

    #[test]
    fn warm_and_cold_passes_read_the_same_corpus_into_separate_sets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let corpus = generate_corpus(3, 24, 6, 4).expect("corpus");
        let config = perf_vault_config(24, 2);
        {
            let vault = Vault::open(dir.path(), config.clone()).expect("vault opens");
            index_corpus(&vault, &corpus).expect("corpus indexes");
        }
        let vault = Vault::open(dir.path(), config).expect("vault reopens");
        let cold = measure_cold(&vault, &corpus, 10);
        let warm = measure_warm(&vault, &corpus, 10, 1);
        assert_eq!(cold.label, "cold");
        assert_eq!(warm.label, "warm");
        assert_eq!(cold.samples, corpus.queries.len());
        assert_eq!(warm.samples, corpus.queries.len());
        assert!(cold.latency_ms.is_measured());
        assert!(warm.latency_ms.is_measured());
        assert_eq!(cold.errors, 0);
        assert!(
            !cold.meets_completed_sample_floor,
            "six completed calls is deliberately below the full-run completed-sample floor"
        );
    }
}
