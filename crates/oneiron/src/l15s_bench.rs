//! L15-S in-crate micro-benches (bench only, never merges): real stage fns over
//! corpus-shaped inputs from l15s-inputs/ (the seeded 4-person corpus: 457 turns,
//! 1,413 messages, 501 note claims). Each stage prints median ms and a hash of every
//! output; an optimization attempt keeps its change only if ms drops AND the hash
//! is unchanged. Run through src/bin/l15s_bench.rs on a fleet host.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Instant;

use crate::entity_id::EntityId;

pub fn run(stage: &str) -> String {
    let dir = std::env::var("L15S_INPUTS").unwrap_or_else(|_| "l15s-inputs".to_string());
    match stage {
        "bm25" => bm25(&dir),
        "hydrate" => hydrate(&dir),
        "temporal" => crate::pipeline::l15s_bench::run(),
        "secret" => crate::secret_custody::known_values::l15s_bench::run(&dir),
        other => format!("L15S-BENCH unknown stage {other}"),
    }
}

fn sets_from_env(default: usize) -> usize {
    std::env::var("L15S_SETS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn median(mut times: Vec<f64>) -> f64 {
    times.sort_by(|a, b| a.total_cmp(b));
    times[times.len() / 2]
}

pub(crate) fn det_id(seed: &str) -> EntityId {
    for salt in 0u8..=255 {
        let digest = blake3::hash(format!("{seed}:{salt}").as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest.as_bytes()[..16]);
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return id;
        }
    }
    unreachable!("no valid id drawn")
}

pub(crate) fn read_inputs(dir: &str, name: &str) -> String {
    std::fs::read_to_string(format!("{dir}/{name}")).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

pub(crate) fn claim_rows(dir: &str) -> Vec<(String, String, String)> {
    read_inputs(dir, "claims.tsv")
        .lines()
        .map(|line| {
            let mut parts = line.splitn(3, '\t');
            (
                parts.next().unwrap_or("").to_string(),
                parts.next().unwrap_or("").to_string(),
                parts.next().unwrap_or("").to_string(),
            )
        })
        .collect()
}

/// bm25: the real scoring path through the public Vault door — index every corpus
/// message + note as a document in a throwaway vault, then time search_text for the
/// 9 bench queries at the text stage's fetch limit (80).
fn bm25(dir: &str) -> String {
    use crate::vault::Vault;
    use oneiron_contracts::temporal::TimeRange;

    let sets = sets_from_env(40);
    let mut docs: Vec<String> = read_inputs(dir, "texts.txt")
        .lines()
        .map(str::to_string)
        .collect();
    for (_world, key, value) in claim_rows(dir) {
        docs.push(format!("{key} {value}"));
    }
    let n_docs = docs.len();

    let vault_dir = std::env::temp_dir().join(format!("l15s-bm25-vault-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&vault_dir);
    let mut config = crate::config::VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("bench/perf-harness@v1".to_string());
    config.map_size = 1024 * 1024 * 1024;
    config.max_readers = 128;
    let vault = match Vault::open(&vault_dir, config) {
        Ok(vault) => vault,
        Err(e) => return format!("L15S-BENCH bm25 ERR open: {e}"),
    };
    let index_start = Instant::now();
    let indexed_docs: Vec<(usize, &String)> = docs.iter().enumerate().collect();
    for chunk in indexed_docs.chunks(200) {
        let mut batch = vault.batch();
        for (index, text) in chunk {
            let id = det_id(&format!("l15s-doc-{index}"));
            batch = batch
                .put(&id, 1, TimeRange { start: 1, end: 1 }, 1, b"perf-doc")
                .text(&id, &[("body", text.as_str())]);
        }
        if let Err(e) = batch.commit() {
            return format!("L15S-BENCH bm25 ERR index commit: {e}");
        }
    }
    let index_ms = index_start.elapsed().as_secs_f64() * 1000.0;

    let queries = [
        "what do we know about Ines Varga",
        "what do we know about Tomas Hale",
        "what do we know about Jonas Heller",
        "what do we know about Elin Sorensen",
        "Kestrel Fabrication anodizing supplier",
        "who handles the calibrations at the sites",
        "thesis deadline",
        "who is the safety officer",
        "zqxwvprobe",
    ];
    let run_set = |hash: &mut u64| -> Result<(), String> {
        let mut hasher = DefaultHasher::new();
        for query in queries {
            let hits = vault
                .search_text(query, 80)
                .map_err(|e| format!("search {query}: {e}"))?;
            for hit in &hits {
                hit.id.as_bytes().hash(&mut hasher);
                hit.score.to_bits().hash(&mut hasher);
            }
        }
        *hash = hasher.finish();
        Ok(())
    };
    let mut hash = 0u64;
    for _ in 0..3 {
        if let Err(e) = run_set(&mut hash) {
            return format!("L15S-BENCH bm25 ERR {e}");
        }
    }
    let mut times = Vec::with_capacity(sets);
    for _ in 0..sets {
        let start = Instant::now();
        if let Err(e) = run_set(&mut hash) {
            return format!("L15S-BENCH bm25 ERR {e}");
        }
        times.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    let med = median(times);
    format!(
        "L15S-BENCH bm25 ms_per_set={med:.3} ms_per_query={:.3} hash={hash:016x} docs={n_docs} index_ms={index_ms:.0} sets={sets}",
        med / 9.0
    )
}

/// hydrate (pure slice): decode + judge every corpus claim body — decode_claim_body and
/// claim_surfaceable over encode_claim_body bytes, the per-item pure work of hydrate.
fn hydrate(dir: &str) -> String {
    use crate::claim::source_trust::claim_surfaceable;
    use crate::claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, decode_claim_body,
        encode_claim_body,
    };
    use rmpv::Value;

    let sets = sets_from_env(200);
    let mut encoded = Vec::new();
    for (i, (_world, key, value)) in claim_rows(dir).into_iter().enumerate() {
        let slug: String = key
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect();
        let make = |predicate: String| {
            ClaimBody::new(
                predicate,
                ClaimSubject::Entity(det_id(&format!("l15s-subj-{i}"))),
                Value::from(value.clone()),
                0.9,
                ClaimApprovalStatus::Auto,
                ClaimLifecycleStatus::Active,
            )
        };
        let mut body = match make(format!("note.{slug}")) {
            Ok(body) => body,
            Err(_) => match make("note.bench".to_string()) {
                Ok(body) => body,
                Err(e) => return format!("L15S-BENCH hydrate ERR body: {e}"),
            },
        };
        body.salience = Some(((i * 37) % 100) as f32 / 100.0);
        match encode_claim_body(&body) {
            Ok(bytes) => encoded.push(bytes),
            Err(e) => return format!("L15S-BENCH hydrate ERR encode: {e}"),
        }
    }
    let n = encoded.len();
    let run_set = |hash: &mut u64| -> Result<(), String> {
        let mut hasher = DefaultHasher::new();
        for bytes in &encoded {
            let body = decode_claim_body(bytes, false).map_err(|e| format!("decode: {e}"))?;
            claim_surfaceable(&body).hash(&mut hasher);
            body.predicate.hash(&mut hasher);
            body.confidence.to_bits().hash(&mut hasher);
            body.salience.map(f32::to_bits).hash(&mut hasher);
            format!("{:?}", body.value).hash(&mut hasher);
        }
        *hash = hasher.finish();
        Ok(())
    };
    let mut hash = 0u64;
    for _ in 0..3 {
        if let Err(e) = run_set(&mut hash) {
            return format!("L15S-BENCH hydrate ERR {e}");
        }
    }
    let mut times = Vec::with_capacity(sets);
    for _ in 0..sets {
        let start = Instant::now();
        if let Err(e) = run_set(&mut hash) {
            return format!("L15S-BENCH hydrate ERR {e}");
        }
        times.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    let med = median(times);
    format!(
        "L15S-BENCH hydrate ms_per_set={med:.3} us_per_item={:.2} hash={hash:016x} items={n} sets={sets}",
        med * 1000.0 / n as f64
    )
}
