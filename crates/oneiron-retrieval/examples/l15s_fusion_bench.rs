//! L15-S fusion micro-bench (bench only, never merges): the pure fusion slice of one light
//! recall — candidate union + z-normalize, the sal/conf msgpack reads blend.rs does per
//! candidate, and the linear-log blend — over corpus-shaped inputs (9 queries, 80+80 ranked
//! lists, 501 claim bodies from l15s-inputs/claims.tsv: the seeded 4-person corpus's notes).
//! Prints median ms per 9-query set and a hash of every output (id, score bits, order).
//! An optimization attempt keeps its change only if ms drops AND the hash is unchanged.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Instant;

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_contracts::retrieval_telemetry::RetrievalBlendWeights;
use oneiron_retrieval::fusion::{
    decode_msgpack_float, linear_log_blend_scores_with_weights,
    retrieval_candidates_from_ranked_lists,
};
use oneiron_retrieval::pipeline::ScoredEntity;

fn id_of(index: u64) -> EntityId {
    let mut bytes = [0u8; 16];
    bytes[8..].copy_from_slice(&index.to_be_bytes());
    EntityId::from_bytes_unchecked(bytes)
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// One claim's stored row bytes: 25-byte header + the canonical body map shape
/// (pred, val, conf, sal, src), sizes from the real corpus notes.
fn claim_raw(pred: &str, val: &str, conf: f32, sal: f32) -> Vec<u8> {
    let body = rmpv::Value::Map(vec![
        (rmpv::Value::from("pred"), rmpv::Value::from(pred)),
        (rmpv::Value::from("val"), rmpv::Value::from(val)),
        (rmpv::Value::from("conf"), rmpv::Value::F32(conf)),
        (rmpv::Value::from("sal"), rmpv::Value::F32(sal)),
        (rmpv::Value::from("src"), rmpv::Value::from("user_stated")),
    ]);
    let mut raw = vec![0u8; ENTITY_METADATA_HEADER_LEN];
    rmpv::encode::write_value(&mut raw, &body).expect("encode claim body");
    raw
}

fn slug(key: &str) -> String {
    key.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect()
}

fn ranked_list(rng: &mut Rng, pool: u64, len: usize, top: f32) -> Vec<ScoredEntity> {
    let mut seen = std::collections::HashSet::new();
    let mut list = Vec::with_capacity(len);
    while list.len() < len {
        let idx = rng.below(pool);
        if seen.insert(idx) {
            let decay = 1.0 - (list.len() as f32 / len as f32) * 0.7;
            list.push(ScoredEntity { id: id_of(idx), score: top * decay });
        }
    }
    list
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let claims_path = args.get(1).map(String::as_str).unwrap_or("l15s-inputs/claims.tsv");
    let sets: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(60);

    let text = std::fs::read_to_string(claims_path).expect("read claims.tsv");
    let raws: Vec<Vec<u8>> = text
        .lines()
        .enumerate()
        .map(|(i, line)| {
            let mut parts = line.splitn(3, '\t');
            let _world = parts.next().unwrap_or("");
            let key = parts.next().unwrap_or("");
            let val = parts.next().unwrap_or("");
            let sal = ((i * 37) % 100) as f32 / 100.0;
            claim_raw(&format!("note.{}", slug(key)), val, 0.9, sal)
        })
        .collect();
    let n_claims = raws.len() as u64;
    // Candidate pool: claims + turns/messages of the corpus (501 + 457).
    let pool = n_claims + 457;

    // 9 queries x (text 80 + temporal 80), fixed seeds.
    let mut queries = Vec::new();
    for q in 0..9u64 {
        let mut rng = Rng(0x9e3779b97f4a7c15 ^ (q + 1));
        let text_list = ranked_list(&mut rng, pool, 80, 12.0);
        let temporal_list = ranked_list(&mut rng, pool, 80, 1.0);
        queries.push(vec![text_list, temporal_list]);
    }

    let weights = RetrievalBlendWeights::bootstrap();
    let run_set = |hash: &mut u64| {
        let mut hasher = DefaultHasher::new();
        for lists in &queries {
            let mut inputs = retrieval_candidates_from_ranked_lists(lists, &[]);
            for input in &mut inputs {
                // The blend.rs fill, over retrieval-crate reads only.
                let idx = u64::from_be_bytes(input.id.as_bytes()[8..].try_into().unwrap());
                input.recency = 0.5 + ((idx % 50) as f64) / 100.0;
                if idx < n_claims {
                    let raw = &raws[idx as usize];
                    if let Some(sal) = decode_msgpack_float(raw, "sal") {
                        input.salience = sal;
                    }
                    if let Some(conf) = decode_msgpack_float(raw, "conf") {
                        input.confidence = conf;
                    }
                }
            }
            let out = linear_log_blend_scores_with_weights(&inputs, weights);
            for s in out.scores.iter().chain(out.base_scores.iter()) {
                s.id.as_bytes().hash(&mut hasher);
                s.score.to_bits().hash(&mut hasher);
            }
        }
        *hash = hasher.finish();
    };

    let mut hash = 0u64;
    for _ in 0..5 {
        run_set(&mut hash);
    }
    let mut times = Vec::with_capacity(sets);
    for _ in 0..sets {
        let start = Instant::now();
        run_set(&mut hash);
        times.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    times.sort_by(|a, b| a.total_cmp(b));
    let median = times[times.len() / 2];
    println!(
        "L15S-BENCH fusion ms_per_set={median:.3} ms_per_query={:.3} hash={hash:016x} claims={n_claims} pool={pool} sets={sets}",
        median / 9.0
    );
}
