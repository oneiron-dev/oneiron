//! ANN recall corpus `ann_seed42.v1` (source: ec9cbdec92e7dbcc865b9958dd1ff8652714d6c7).
//! rand 0.8.8 StdRng seed 42; 1,000 x 128 f32 samples in [-1, 1), 25 stride-40
//! queries, top-10 mean set recall strictly > 0.95, no acceptance tolerance.
//! Reference: original pre-storage f32 vectors; the index persists f16 rows.
//! v1 changes only IDs (ascending big-endian counters instead of wall-clock IDs)
//! and uses the source scalar f32 cosine path instead of platform dispatch.
//! AVX2/FMA and NEON reductions can change near-tie order; no bit-exactness or
//! cross-platform equivalence is claimed. Run records include host and timings.

use std::collections::HashSet;
use std::time::Instant;

use oneiron::{EntityId, HnswConfig, Result, TimeRange, Vault, VaultConfig};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

fn test_config() -> VaultConfig {
    let mut config = VaultConfig::device();
    config.map_size = 16 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = Some("test/model@v1".to_owned());
    config.max_readers = 16;
    config.hnsw = HnswConfig::default();
    config.hnsw.m_max_0 = 64;
    config.hnsw.ef_construction = 200;
    config.hnsw.ef_search = 128;
    config
}

fn id_from_u64(value: u64) -> EntityId {
    assert!(value >= 1);
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    EntityId::from_bytes(bytes).expect("nonzero counter id is not a reserved sentinel")
}

// Copied from the source scalar path, including its f32 normalization.
fn cosine_distance(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 1.0;
    }
    1.0 - cosine_similarity_scalar(a, b)
}

fn cosine_similarity_scalar(a: &[f32], b: &[f32]) -> f32 {
    let len = a.len();
    let mut i = 0;

    let mut dot = 0.0_f32;
    let mut norm_a = 0.0_f32;
    let mut norm_b = 0.0_f32;

    while i + 8 <= len {
        let a0 = a[i];
        let a1 = a[i + 1];
        let a2 = a[i + 2];
        let a3 = a[i + 3];
        let a4 = a[i + 4];
        let a5 = a[i + 5];
        let a6 = a[i + 6];
        let a7 = a[i + 7];

        let b0 = b[i];
        let b1 = b[i + 1];
        let b2 = b[i + 2];
        let b3 = b[i + 3];
        let b4 = b[i + 4];
        let b5 = b[i + 5];
        let b6 = b[i + 6];
        let b7 = b[i + 7];

        dot += a0 * b0 + a1 * b1 + a2 * b2 + a3 * b3 + a4 * b4 + a5 * b5 + a6 * b6 + a7 * b7;
        norm_a += a0 * a0 + a1 * a1 + a2 * a2 + a3 * a3 + a4 * a4 + a5 * a5 + a6 * a6 + a7 * a7;
        norm_b += b0 * b0 + b1 * b1 + b2 * b2 + b3 * b3 + b4 * b4 + b5 * b5 + b6 * b6 + b7 * b7;

        i += 8;
    }

    while i + 4 <= len {
        let a0 = a[i];
        let a1 = a[i + 1];
        let a2 = a[i + 2];
        let a3 = a[i + 3];

        let b0 = b[i];
        let b1 = b[i + 1];
        let b2 = b[i + 2];
        let b3 = b[i + 3];

        dot += a0 * b0 + a1 * b1 + a2 * b2 + a3 * b3;
        norm_a += a0 * a0 + a1 * a1 + a2 * a2 + a3 * a3;
        norm_b += b0 * b0 + b1 * b1 + b2 * b2 + b3 * b3;

        i += 4;
    }

    while i < len {
        let ai = a[i];
        let bi = b[i];
        dot += ai * bi;
        norm_a += ai * ai;
        norm_b += bi * bi;
        i += 1;
    }

    normalize(dot, norm_a, norm_b)
}

#[inline]
fn normalize(dot: f32, norm_a: f32, norm_b: f32) -> f32 {
    normalize_prepared(dot, norm_a, norm_a.sqrt(), norm_b)
}

#[inline]
fn normalize_prepared(dot: f32, norm_a: f32, norm_a_sqrt: f32, norm_b: f32) -> f32 {
    if !dot.is_finite()
        || !norm_a.is_finite()
        || !norm_b.is_finite()
        || norm_a <= 0.0
        || norm_b <= 0.0
    {
        return 0.0;
    }

    let similarity = dot / (norm_a_sqrt * norm_b.sqrt());
    similarity.clamp(-1.0, 1.0)
}

// Keep the original name substring so default nextest still skips this slow case.
#[test]
fn hnsw_recall_at_10_vs_bruteforce_meets_quality_floor() -> Result<()> {
    const DIMENSIONS: usize = 128;
    const NODE_COUNT: usize = 1_000;
    const LIMIT: usize = 10;
    const QUERY_COUNT: usize = 25;

    let temp_dir = tempfile::tempdir()?;
    let mut config = test_config();
    config.dimensions = DIMENSIONS;
    config.map_size = 128 * 1024 * 1024;
    config.hnsw.m_max_0 = 64;
    config.hnsw.ef_construction = 256;
    config.hnsw.ef_search = 256;

    let vault = Vault::open(temp_dir.path(), config)?;
    let mut rng = StdRng::seed_from_u64(42);
    let mut corpus = Vec::with_capacity(NODE_COUNT);

    let insert_started = Instant::now();
    for index in 1..=NODE_COUNT as u64 {
        let id = id_from_u64(index);
        let vector: Vec<f32> = (0..DIMENSIONS)
            .map(|_| rng.gen_range(-1.0_f32..1.0_f32))
            .collect();

        vault.put_entity(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"recall-node")?;
        vault.put_vector(&id, &vector)?;
        corpus.push((id, vector));
    }
    let insert_elapsed = insert_started.elapsed();

    let search_started = Instant::now();
    let mut recall_sum = 0.0_f32;
    for query_idx in 0..QUERY_COUNT {
        let stride = NODE_COUNT / QUERY_COUNT;
        let query_vector = &corpus[query_idx * stride].1;

        let ann = vault.search_vector(query_vector, LIMIT)?;
        let ann_ids: HashSet<EntityId> = ann.iter().map(|item| item.id).collect();

        let mut brute_force: Vec<(EntityId, f32)> = corpus
            .iter()
            .map(|(id, vector)| (*id, cosine_distance(query_vector, vector)))
            .collect();
        brute_force.sort_by(|left, right| {
            left.1
                .total_cmp(&right.1)
                .then_with(|| left.0.as_bytes().cmp(right.0.as_bytes()))
        });

        let brute_ids: HashSet<EntityId> =
            brute_force.iter().take(LIMIT).map(|(id, _)| *id).collect();
        let hits = brute_ids.intersection(&ann_ids).count();
        recall_sum += hits as f32 / LIMIT as f32;
    }
    let search_elapsed = search_started.elapsed();

    let recall_at_10 = recall_sum / QUERY_COUNT as f32;
    eprintln!(
        "ann_seed42.v1 seed=42 rand=0.8.8 dtype=f32/f16 reference=scalar-f32 \
         corpus={NODE_COUNT}x{DIMENSIONS} queries={QUERY_COUNT} stride=40 k={LIMIT} \
         m_max_0=64 ef_construction=256 ef_search=256 host={}/{} \
         recall@10={recall_at_10:.4} insert_ms={} search_ms={}",
        std::env::consts::ARCH,
        std::env::consts::OS,
        insert_elapsed.as_millis(),
        search_elapsed.as_millis()
    );

    assert!(
        recall_at_10 > 0.95,
        "expected recall@10 > 0.95, got {recall_at_10:.4}"
    );

    Ok(())
}
