//! ONE-1579 corpus: the seeded, deterministic documents, queries and vectors a
//! run is measured against, and the vault configuration it is indexed into.
//!
//! Ground truth is PLANTED rather than guessed: every document carries a
//! unique nonsense marker token, and the query that must retrieve it is that
//! token. The whole corpus is drawn from one seeded `StdRng` stream in a fixed
//! order, so the same seed reproduces the same documents, the same queries and
//! the same hash.
//!
//! Engine boundary: indexing goes through the public `Vault::batch` door and
//! nothing else.

use std::time::Instant;

use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Embedding identity stamped on every perf vault. Bench-owned; it never
/// collides with a product vault's model id.
pub(crate) const BENCH_EMBEDDING_MODEL: &str = "bench/perf-harness@v1";
/// Entity type used for the corpus documents and the gated-write subject.
pub(crate) const BENCH_ENTITY_TYPE: u8 = 1;

const VOCAB: [&str; 24] = [
    "vault",
    "recall",
    "latency",
    "session",
    "commit",
    "gate",
    "vector",
    "prefix",
    "rescore",
    "cache",
    "rung",
    "fsync",
    "cold",
    "warm",
    "child",
    "probe",
    "corpus",
    "seed",
    "sample",
    "budget",
    "curve",
    "throughput",
    "envelope",
    "candidate",
];

/// One indexed document. The marker is a unique nonsense token planted in the
/// body so the harness owns its ground truth instead of guessing at it.
pub(crate) struct CorpusDoc {
    pub(crate) id: EntityId,
    pub(crate) marker: String,
    pub(crate) text: String,
}

/// One query plus the document it must retrieve.
pub(crate) struct CorpusQuery {
    pub(crate) text: String,
    pub(crate) expected: EntityId,
}

/// The seeded, deterministic corpus a run is measured against.
pub(crate) struct Corpus {
    pub(crate) docs: Vec<CorpusDoc>,
    pub(crate) queries: Vec<CorpusQuery>,
    /// Bench-side vectors for the precision axis. These never reach a vault.
    pub(crate) vectors: Vec<Vec<f32>>,
    pub(crate) query_vectors: Vec<Vec<f32>>,
    pub(crate) hash: String,
}

/// Builds the corpus from one seeded `StdRng` stream in a fixed order, so the
/// same seed reproduces the same corpus, the same queries and the same hash.
pub(crate) fn generate_corpus(
    seed: u64,
    docs: usize,
    queries: usize,
    dimensions: usize,
) -> Result<Corpus, String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut corpus_docs = Vec::with_capacity(docs);
    let mut vectors = Vec::with_capacity(docs);
    for index in 0..docs {
        let marker = marker_token(index);
        let body = doc_text(&mut rng, &marker);
        corpus_docs.push(CorpusDoc {
            id: gen_entity_id(&mut rng)?,
            marker,
            text: body,
        });
        vectors.push(gen_vector(&mut rng, dimensions));
    }

    let mut corpus_queries = Vec::with_capacity(queries);
    let mut query_vectors = Vec::with_capacity(queries);
    for index in 0..queries {
        let anchor = if corpus_docs.is_empty() {
            0
        } else {
            (index * corpus_docs.len()) / queries.max(1)
        };
        let Some(doc) = corpus_docs.get(anchor) else {
            break;
        };
        corpus_queries.push(CorpusQuery {
            text: doc.marker.clone(),
            expected: doc.id,
        });
        query_vectors.push(perturb(&mut rng, &vectors[anchor]));
    }

    let hash = corpus_hash(&corpus_docs, &vectors);
    Ok(Corpus {
        docs: corpus_docs,
        queries: corpus_queries,
        vectors,
        query_vectors,
        hash,
    })
}

/// `qzmk` plus five base-26 letters: a unique, pure-ASCII-lowercase token that
/// survives analysis as one surface form.
fn marker_token(index: usize) -> String {
    let mut token = String::from("qzmk");
    let mut remaining = index;
    for _ in 0..5 {
        let letter = b'a' + u8::try_from(remaining % 26).unwrap_or(0);
        token.push(char::from(letter));
        remaining /= 26;
    }
    token
}

fn doc_text(rng: &mut StdRng, marker: &str) -> String {
    let mut text = String::from(marker);
    for _ in 0..8 {
        text.push(' ');
        text.push_str(VOCAB[rng.gen_range(0..VOCAB.len())]);
    }
    text
}

fn gen_entity_id(rng: &mut StdRng) -> Result<EntityId, String> {
    for _ in 0..64 {
        let mut bytes = [0_u8; 16];
        rng.fill(&mut bytes);
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return Ok(id);
        }
    }
    Err("could not draw a valid entity id from the seeded stream".to_owned())
}

fn gen_vector(rng: &mut StdRng, dimensions: usize) -> Vec<f32> {
    (0..dimensions)
        .map(|_| rng.gen_range(-1.0_f32..1.0))
        .collect()
}

fn perturb(rng: &mut StdRng, base: &[f32]) -> Vec<f32> {
    base.iter()
        .map(|value| value + 0.1 * rng.gen_range(-1.0_f32..1.0))
        .collect()
}

fn corpus_hash(docs: &[CorpusDoc], vectors: &[Vec<f32>]) -> String {
    let mut hasher = blake3::Hasher::new();
    for doc in docs {
        hasher.update(doc.id.as_bytes());
        hasher.update(doc.text.as_bytes());
    }
    for vector in vectors {
        for value in vector {
            hasher.update(&value.to_le_bytes());
        }
    }
    hasher.finalize().to_hex().to_string()
}

/// Vault config for a perf run. Text-only: the precision axis works on the
/// bench's own vectors, so no vector or embedding row is ever written.
pub(crate) fn perf_vault_config(docs: usize, max_sessions: usize) -> VaultConfig {
    const MIB: usize = 1024 * 1024;
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some(BENCH_EMBEDDING_MODEL.to_owned());
    config.map_size = docs
        .saturating_mul(16 * 1024)
        .saturating_add(512 * MIB)
        .div_ceil(MIB)
        .saturating_mul(MIB);
    config.max_readers = u32::try_from(max_sessions.saturating_mul(2).saturating_add(64))
        .unwrap_or(1024)
        .max(128);
    config
}

/// Indexes the corpus in chunks through the public batch door.
pub(crate) fn index_corpus(vault: &Vault, corpus: &Corpus) -> Result<f64, String> {
    let started = Instant::now();
    for chunk in corpus.docs.chunks(200) {
        let mut batch = vault.batch();
        for doc in chunk {
            batch = batch
                .put(
                    &doc.id,
                    BENCH_ENTITY_TYPE,
                    TimeRange { start: 1, end: 1 },
                    1,
                    b"perf-doc",
                )
                .text(&doc.id, &[("body", doc.text.as_str())]);
        }
        batch
            .commit()
            .map_err(|error| format!("corpus index commit failed: {error}"))?;
    }
    Ok(started.elapsed().as_secs_f64() * 1e3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_corpus_is_reproducible_from_its_seed() {
        let left = generate_corpus(1579, 8, 4, 6).expect("corpus");
        let right = generate_corpus(1579, 8, 4, 6).expect("corpus");
        let other = generate_corpus(1580, 8, 4, 6).expect("corpus");
        assert_eq!(left.hash, right.hash);
        assert_ne!(left.hash, other.hash);
        assert_eq!(left.queries.len(), 4);
        assert_eq!(left.vectors.len(), 8);
        assert_eq!(left.query_vectors.len(), 4);
        for query in &left.queries {
            assert!(query.text.starts_with("qzmk"), "{}", query.text);
        }
        let markers: std::collections::BTreeSet<&str> =
            left.docs.iter().map(|doc| doc.marker.as_str()).collect();
        assert_eq!(markers.len(), left.docs.len(), "markers are unique");
    }
}
