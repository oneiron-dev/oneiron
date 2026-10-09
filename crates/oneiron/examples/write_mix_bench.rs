//! Agent write-mix bench for the vault's single writer (OF-536 group commit).
//!
//! N writer threads share one fresh vault and run a fixed agent mix: 50% a
//! note-like batch (put + text), 20% a turn-like write through the
//! caller-transaction door, 10% a batch carrying an embedding, and 20% a
//! recall that writes its retrieval-telemetry row. One JSON line per writer
//! count reports logical writes/s, durable commits/s (LMDB's own transaction
//! id, read from the data file's meta pages), fsyncs/s (when
//! `fsync_count.so` is preloaded) and p50/p95 write latency. Public API only,
//! so the same file measures any engine revision.
//!
//! usage: write_mix_bench <scratch dir> [--writers 1,10,100,200] [--ops 4000]
use std::path::Path;
use std::time::{Duration, Instant};

use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use rand::{Rng, SeedableRng, rngs::StdRng};

const CORPUS: usize = 2048;
const DIMS: usize = 64;
const SEED: u64 = 42;

#[derive(Clone, Copy, PartialEq)]
enum Op {
    Note,
    Turn,
    Embedded,
    Recall,
}

impl Op {
    /// The fixed mix, by position in a writer's sequence.
    fn at(index: usize) -> Self {
        match index % 10 {
            0..=4 => Self::Note,
            5 | 6 => Self::Turn,
            7 => Self::Embedded,
            _ => Self::Recall,
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let scratch = args.next().ok_or("expected a scratch directory")?;
    let mut writer_counts = vec![1, 10, 100, 200];
    let mut total_ops = 4000;
    while let Some(flag) = args.next() {
        let value = args.next().ok_or("flag without a value")?;
        match flag.as_str() {
            "--writers" => {
                writer_counts = value.split(',').map(str::parse).collect::<Result<_, _>>()?;
            }
            "--ops" => total_ops = value.parse()?,
            _ => return Err(format!("unknown flag {flag}").into()),
        }
    }
    for writers in writer_counts {
        let dir = tempfile::tempdir_in(&scratch)?;
        let line = measure(dir.path(), writers, total_ops)?;
        println!("{line}");
    }
    Ok(())
}

fn id(rng: &mut StdRng) -> EntityId {
    loop {
        if let Ok(id) = EntityId::from_bytes(rng.r#gen()) {
            return id;
        }
    }
}

// A unique alphabetic token survives the analyzer; each recall has a planted
// target document.
fn marker(index: usize) -> String {
    let mut n = index;
    let mut text = String::from("qzmk");
    for _ in 0..5 {
        text.push(char::from(b'a' + (n % 26) as u8));
        n /= 26;
    }
    text
}

fn unit_vector(rng: &mut StdRng) -> Vec<f32> {
    let raw: Vec<f32> = (0..DIMS).map(|_| rng.r#gen::<f32>() - 0.5).collect();
    let norm = raw
        .iter()
        .map(|x| x * x)
        .sum::<f32>()
        .sqrt()
        .max(f32::EPSILON);
    raw.into_iter().map(|x| x / norm).collect()
}

struct Samples {
    writes_ms: Vec<f64>,
    recalls_ms: Vec<f64>,
    logical_writes: usize,
}

fn measure(dir: &Path, writers: usize, total_ops: usize) -> Result<String, String> {
    let mut config = VaultConfig::device();
    config.retrieval_telemetry_capture = true;
    config.dimensions = DIMS;
    config.fast_dims = None;
    config.embedding_model = Some("bench/write-mix@v1".into());
    config.map_size = 4 * 1024 * 1024 * 1024;
    config.max_readers = 1024;
    let vault = Vault::open(dir, config).map_err(|e| format!("open: {e}"))?;
    let mut rng = StdRng::seed_from_u64(SEED);
    let corpus: Vec<(EntityId, String)> = (0..CORPUS).map(|i| (id(&mut rng), marker(i))).collect();
    for chunk in corpus.chunks(128) {
        let mut batch = vault.batch();
        for (entity, token) in chunk {
            batch = batch
                .put(
                    entity,
                    1,
                    TimeRange { start: 1, end: 1 },
                    1,
                    b"write-mix-corpus",
                )
                .text(entity, &[("body", token.as_str())])
                .vector(entity, &unit_vector(&mut rng));
        }
        batch.commit().map_err(|e| format!("seed: {e}"))?;
    }
    let per_writer = total_ops.div_ceil(writers);
    let plans: Vec<Vec<(EntityId, Vec<f32>)>> = (0..writers)
        .map(|_| {
            (0..per_writer)
                .map(|_| (id(&mut rng), unit_vector(&mut rng)))
                .collect()
        })
        .collect();

    let commits_before = lmdb_txnid(dir);
    let fsyncs_before = fsync_count();
    let start = std::sync::Barrier::new(writers + 1);
    let (samples, window) = std::thread::scope(|scope| {
        let handles: Vec<_> = plans
            .iter()
            .enumerate()
            .map(|(writer, plan)| {
                let (vault, corpus, start) = (&vault, &corpus, &start);
                scope.spawn(move || run_writer(vault, corpus, writer, plan, start))
            })
            .collect();
        start.wait();
        let began = Instant::now();
        let samples: Vec<Result<Samples, String>> = handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .unwrap_or_else(|_| Err("writer panicked".into()))
            })
            .collect();
        (samples, began.elapsed())
    });
    let commits = lmdb_txnid(dir)
        .zip(commits_before)
        .map(|(after, before)| after - before);
    let fsyncs = fsync_count()
        .zip(fsyncs_before)
        .map(|(after, before)| after - before);
    let mut writes_ms = Vec::new();
    let mut recalls_ms = Vec::new();
    let mut logical_writes = 0;
    for sample in samples {
        let sample = sample?;
        writes_ms.extend(sample.writes_ms);
        recalls_ms.extend(sample.recalls_ms);
        logical_writes += sample.logical_writes;
    }
    let seconds = window.as_secs_f64();
    let rate = |count: u64| count as f64 / seconds;
    Ok(serde_json::json!({
        "writers": writers,
        "ops": writers * per_writer,
        "window_s": seconds,
        "logical_writes": logical_writes,
        "logical_writes_per_s": logical_writes as f64 / seconds,
        "durable_commits": commits,
        "commits_per_s": commits.map(rate),
        "fsyncs": fsyncs,
        "fsyncs_per_s": fsyncs.map(rate),
        "write_p50_ms": percentile(&mut writes_ms, 50),
        "write_p95_ms": percentile(&mut writes_ms, 95),
        "recall_p50_ms": percentile(&mut recalls_ms, 50),
        "recall_p95_ms": percentile(&mut recalls_ms, 95),
    })
    .to_string())
}

fn run_writer(
    vault: &Vault,
    corpus: &[(EntityId, String)],
    writer: usize,
    plan: &[(EntityId, Vec<f32>)],
    start: &std::sync::Barrier,
) -> Result<Samples, String> {
    let mut samples = Samples {
        writes_ms: Vec::with_capacity(plan.len()),
        recalls_ms: Vec::new(),
        logical_writes: 0,
    };
    start.wait();
    for (index, (entity, vector)) in plan.iter().enumerate() {
        let body = format!("{} agent {writer} step {index}", marker(CORPUS + index));
        let at = TimeRange {
            start: index as u64 + 2,
            end: index as u64 + 2,
        };
        let began = Instant::now();
        let op = Op::at(index + writer);
        match op {
            Op::Note => vault
                .batch()
                .put(entity, 1, at, index as u64 + 2, b"write-mix-note")
                .text(entity, &[("body", body.as_str())])
                .commit(),
            Op::Turn => vault.with_write_txn(|txn| {
                vault
                    .batch_in()
                    .put(entity, 1, at, index as u64 + 2, b"write-mix-turn")
                    .text(entity, &[("body", body.as_str())])
                    .apply(txn)
            }),
            Op::Embedded => vault
                .batch()
                .put(entity, 1, at, index as u64 + 2, b"write-mix-embedded")
                .text(entity, &[("body", body.as_str())])
                .vector(entity, vector)
                .commit(),
            Op::Recall => {
                let (expected, query) = &corpus[(index * 31 + writer) % corpus.len()];
                let found = vault
                    .search_text_with_telemetry(query, 5)
                    .map_err(|e| format!("recall: {e}"))?;
                if !found.value.iter().any(|hit| hit.id == *expected) {
                    return Err("recall lost its planted document".into());
                }
                samples.logical_writes += usize::from(found.run_id.is_some());
                samples.recalls_ms.push(ms(began.elapsed()));
                continue;
            }
        }
        .map_err(|e| format!("write: {e}"))?;
        samples.logical_writes += 1;
        samples.writes_ms.push(ms(began.elapsed()));
    }
    Ok(samples)
}

fn ms(elapsed: Duration) -> f64 {
    elapsed.as_secs_f64() * 1000.0
}

fn percentile(samples: &mut [f64], percent: usize) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    samples.sort_by(f64::total_cmp);
    Some(samples[(samples.len() * percent).div_ceil(100).max(1) - 1])
}

/// LMDB's last committed transaction id, read from the two meta pages of
/// `data.mdb` (64-bit layout: page header 16 bytes, magic at 16, txnid at
/// 144). Every durable commit raises it by one.
fn lmdb_txnid(dir: &Path) -> Option<u64> {
    use std::io::Read;
    const MAGIC: u32 = 0xBEEF_C0DE;
    let page_size = 4096;
    let mut pages = vec![0_u8; page_size * 2];
    std::fs::File::open(dir.join("data.mdb"))
        .ok()?
        .read_exact(&mut pages)
        .ok()?;
    let txnid = |page: &[u8]| -> Option<u64> {
        let magic = u32::from_le_bytes(page.get(16..20)?.try_into().ok()?);
        if magic != MAGIC {
            return None;
        }
        Some(u64::from_le_bytes(page.get(144..152)?.try_into().ok()?))
    };
    let (first, second) = pages.split_at(page_size);
    txnid(first).max(txnid(second))
}

/// fsync, fdatasync and synchronous msync calls so far, when the counting
/// shim is preloaded.
#[cfg(unix)]
fn fsync_count() -> Option<u64> {
    // SAFETY: a symbol lookup by a NUL-terminated name in the global scope; it
    // reads no memory of ours.
    let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"oneiron_bench_fsyncs".as_ptr()) };
    if symbol.is_null() {
        return None;
    }
    // SAFETY: the shim exports `unsigned long oneiron_bench_fsyncs(void)`, a
    // 64-bit count on the hosts this bench runs on.
    let count = unsafe { std::mem::transmute::<*mut libc::c_void, extern "C" fn() -> u64>(symbol) };
    Some(count())
}

#[cfg(not(unix))]
fn fsync_count() -> Option<u64> {
    None
}
