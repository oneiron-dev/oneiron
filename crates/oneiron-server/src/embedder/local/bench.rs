//! Throughput and query latency of the local provider on synthetic text, the
//! numbers its PR bodies report.
//!
//! Ignored: each row needs the default model's 2.4 GB checkpoint, named by
//! `ONEIRON_EMBED_TEST_PPLX_MODEL_DIR` or fetched on first use. Threads come
//! from `RAYON_NUM_THREADS` and `CANDLE_NUM_THREADS`. Every row prints one
//! `BENCH` line. The text is invented here, never anyone's history.

use std::time::{Duration, Instant};

use oneiron::embed::{Embedder, PendingEmbeddingInput, PendingEmbeddingPayload};

use super::model_manager::{ModelManager, PINNED_MODELS};
use super::{LocalEmbedder, batcher};
use crate::config::{EmbedderConfig, EmbedderDevice, LocalEmbedderConfig};
use crate::embedder::QueryEmbedder;

/// Syllables the invented words are made of.
const SYLLABLES: [&str; 24] = [
    "ka", "lo", "mi", "ren", "to", "sa", "vel", "nor", "ix", "pa", "qu", "do", "mer", "shi", "an",
    "te", "rol", "gu", "fa", "zen", "ho", "bri", "op", "lu",
];

/// A fixed pseudo-random sequence, so every run embeds the same text.
struct Sequence(u64);

impl Sequence {
    fn below(&mut self, bound: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) % bound.max(1)
    }
}

/// `count` texts of invented words, as long as `length` picks for each.
fn invented(count: usize, seed: u64, length: impl Fn(&mut Sequence) -> u64) -> Vec<String> {
    let mut sequence = Sequence(seed);
    (0..count)
        .map(|_| {
            let target = usize::try_from(length(&mut sequence)).unwrap_or(usize::MAX);
            let mut text = String::with_capacity(target + 16);
            while text.len() < target {
                if !text.is_empty() {
                    text.push_str(if sequence.below(12) == 0 { ". " } else { " " });
                }
                for _ in 0..2 + sequence.below(3) {
                    let syllable =
                        usize::try_from(sequence.below(SYLLABLES.len() as u64)).unwrap_or_default();
                    text.push_str(SYLLABLES[syllable]);
                }
            }
            text
        })
        .collect()
}

/// Documents spread like an imported history of turns and claims: most a few
/// hundred characters, some over a thousand, a few up to three thousand.
pub(crate) fn synthetic_documents(count: usize, seed: u64) -> Vec<String> {
    invented(count, seed, |sequence| match sequence.below(10) {
        0..=5 => 100 + sequence.below(300),
        6..=8 => 400 + sequence.below(800),
        _ => 1_200 + sequence.below(1_800),
    })
}

/// Recall-sized queries: a short phrase to a sentence or two.
pub(crate) fn synthetic_queries(count: usize, seed: u64) -> Vec<String> {
    invented(count, seed, |sequence| 20 + sequence.below(140))
}

pub(crate) fn document(text: &str) -> PendingEmbeddingInput {
    PendingEmbeddingInput {
        entity_id: oneiron::entity_id::EntityId::from_bytes([0x5b; 16]).expect("entity id"),
        payload: PendingEmbeddingPayload::TurnText(text.to_owned()),
        pending_embedding_token: vec![1],
    }
}

/// The default model on the CPU, as `init --embedder local` configures it.
pub(crate) fn cpu_config() -> EmbedderConfig {
    let model = &PINNED_MODELS[0];
    EmbedderConfig {
        model_id: format!("{}@{}", model.repo, model.revision),
        dimensions: 1024,
        local: LocalEmbedderConfig {
            repo: model.repo.to_owned(),
            revision: model.revision.to_owned(),
            device: EmbedderDevice::Cpu,
            model_dir: std::env::var_os("ONEIRON_EMBED_TEST_PPLX_MODEL_DIR")
                .map(std::path::PathBuf::from),
            ..LocalEmbedderConfig::default()
        },
        ..EmbedderConfig::default()
    }
}

fn env_count(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn threads() -> String {
    std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "default".to_owned())
}

fn tokens(embedder: &LocalEmbedder, texts: &[String]) -> usize {
    batcher::tokenize(&embedder.tokenizer, texts)
        .expect("tokenized")
        .iter()
        .map(|item| item.ids.len())
        .sum()
}

/// Embeds `texts` the way the fill worker does: leases of the configured
/// batch size, one `embed` call each.
fn fill(embedder: &LocalEmbedder, texts: &[String]) -> Vec<Vec<f32>> {
    let mut vectors = Vec::with_capacity(texts.len());
    for lease in texts.chunks(cpu_config().batch_size) {
        let inputs: Vec<PendingEmbeddingInput> = lease.iter().map(|text| document(text)).collect();
        vectors.extend(embedder.embed(&inputs).expect("embedded"));
    }
    vectors
}

fn percentile(sorted: &[Duration], fraction: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = ((sorted.len() - 1) as f64 * fraction).round() as usize;
    sorted[rank.min(sorted.len() - 1)].as_secs_f64() * 1_000.0
}

