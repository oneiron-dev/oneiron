//! Seeded single-vault, in-process agent-swarm baseline. No engine internals.
use std::process::ExitCode;
use std::sync::Barrier;
use std::time::Instant;

use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use serde::Serialize;

const CORPUS: usize = 256;
const SEED: u64 = 42;
const OPS: usize = 1200;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Write,
    Recall,
    Mixed,
}

impl Mode {
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "write" => Ok(Self::Write),
            "recall" => Ok(Self::Recall),
            "mixed" => Ok(Self::Mixed),
            _ => Err(format!("mode must be write|recall|mixed, got {s}")),
        }
    }

    fn writes(self, index: usize) -> bool {
        self == Self::Write || (self == Self::Mixed && index % 5 == 0)
    }
}

#[derive(Serialize)]
struct Metric {
    count: usize,
    per_second: f64,
    p50_ms: f64,
    p99_ms: f64,
}

impl Metric {
    fn new(mut samples: Vec<f64>, seconds: f64) -> Self {
        samples.sort_by(f64::total_cmp);
        let rank = |percent: usize| samples[(samples.len() * percent).div_ceil(100).max(1) - 1];
        Self {
            count: samples.len(),
            per_second: samples.len() as f64 / seconds,
            p50_ms: rank(50),
            p99_ms: rank(99),
        }
    }
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    mode: Mode,
    agents: usize,
    operations: usize,
    seed: u64,
    corpus_docs: usize,
    write_fraction: &'static str,
    recall_api: &'static str,
    synchronized: bool,
    window_seconds: f64,
    operations_per_second: f64,
    writes: Option<Metric>,
    recalls: Option<Metric>,
    recall_telemetry_rows: usize,
}

fn id(rng: &mut StdRng) -> EntityId {
    loop {
        let mut bytes = [0; 16];
        rng.fill_bytes(&mut bytes);
        if let Ok(id) = EntityId::from_bytes(bytes) {
            return id;
        }
    }
}

// A unique alphabetic token survives the text analyzer without relying on
// numeric-token handling; every query has one planted ground-truth document.
fn marker(index: usize) -> String {
    let mut n = index;
    let mut text = String::from("qzmk");
    for _ in 0..5 {
        text.push(char::from(b'a' + (n % 26) as u8));
        n /= 26;
    }
    text
}

fn parse(args: &[String]) -> Result<(Mode, usize, usize, u64), String> {
    let mut mode = None;
    let mut agents = None;
    let mut ops = OPS;
    let mut seed = SEED;
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let value = iter
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--mode" => mode = Some(Mode::parse(value)?),
            "--agents" => agents = Some(value.parse::<usize>().map_err(|_| "invalid agents")?),
            "--ops" => ops = value.parse().map_err(|_| "invalid ops")?,
            "--seed" => seed = value.parse().map_err(|_| "invalid seed")?,
            _ => return Err(format!("unknown flag: {flag}")),
        }
    }
    let agents = agents.ok_or("missing --agents")?;
    if ![1, 10, 100, 300].contains(&agents) || ops == 0 || ops % agents != 0 || ops % 5 != 0 {
        return Err(
            "agents must be 1|10|100|300; ops must be positive and divisible by agents and 5"
                .into(),
        );
    }
    Ok((mode.ok_or("missing --mode")?, agents, ops, seed))
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    if args == ["--matrix"] {
        return run_matrix();
    }
    match parse(args).and_then(|(mode, agents, ops, seed)| measure(mode, agents, ops, seed)) {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_string(&report).expect("report serializes")
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("swarm: {error}");
            eprintln!(
                "usage: oneiron-bench swarm --mode write|recall|mixed --agents 1|10|100|300 [--ops 1200] [--seed 42]"
            );
            ExitCode::FAILURE
        }
    }
}

/// Each JSONL row is an independent fresh-vault trial. Host load is sampled
/// directly beside the run, not once for the whole matrix.
fn run_matrix() -> ExitCode {
    for mode in [Mode::Write, Mode::Recall, Mode::Mixed] {
        for agents in [1, 10, 100, 300] {
            for trial in 1..=3 {
                let load_start = std::fs::read_to_string("/proc/loadavg")
                    .unwrap_or_else(|_| "unavailable".to_owned());
                eprintln!("START {mode:?} {agents} trial={trial}");
                match measure(mode, agents, OPS, SEED) {
                    Ok(report) => {
                        let load_end = std::fs::read_to_string("/proc/loadavg")
                            .unwrap_or_else(|_| "unavailable".to_owned());
                        println!(
                            "{}",
                            serde_json::json!({
                                "trial": trial,
                                "loadavg_start": load_start.trim(),
                                "loadavg_end": load_end.trim(),
                                "report": report,
                            })
                        );
                        use std::io::Write;
                        std::io::stdout().flush().expect("flush JSONL row");
                    }
                    Err(error) => {
                        eprintln!("FAIL {mode:?} {agents} trial={trial}: {error}");
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
    }
    ExitCode::SUCCESS
}

fn measure(mode: Mode, agents: usize, ops: usize, seed: u64) -> Result<Report, String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let corpus: Vec<_> = (0..CORPUS).map(|i| (id(&mut rng), marker(i))).collect();
    let write_ids: Vec<_> = (0..ops).map(|_| id(&mut rng)).collect();
    let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let mut config = VaultConfig::device();
    config.dimensions = 4;
    config.embedding_model = Some("bench/swarm-baseline@v1".into());
    config.map_size = 1024 * 1024 * 1024;
    config.max_readers = 700;
    let vault = Vault::open(dir.path(), config).map_err(|e| format!("open: {e}"))?;
    for chunk in corpus.chunks(64) {
        let mut batch = vault.batch();
        for (entity, token) in chunk {
            batch = batch
                .put(
                    entity,
                    1,
                    TimeRange { start: 1, end: 1 },
                    1,
                    b"swarm-corpus",
                )
                .text(entity, &[("body", token.as_str())]);
        }
        batch.commit().map_err(|e| format!("index: {e}"))?;
    }
    // Warm the exact public retrieval path before the timed cohort.
    for (entity, token) in &corpus {
        let hits = vault
            .search_text_with_telemetry(token, 5)
            .map_err(|e| format!("warmup: {e}"))?;
        if !hits.value.iter().any(|hit| hit.id == *entity) {
            return Err(format!("warmup lost planted document {token}"));
        }
    }
    let barrier = Barrier::new(agents + 1);
    let mut writes = Vec::new();
    let mut reads = Vec::new();
    let mut telemetry_rows = 0;
    let mut failure = None;
    let mut window_seconds = 0.0;
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(agents);
        for agent in 0..agents {
            let barrier = &barrier;
            let vault = &vault;
            let corpus = &corpus;
            let write_ids = &write_ids;
            handles.push(scope.spawn(move || {
                let mut writes = Vec::new();
                let mut reads = Vec::new();
                let mut telemetry_rows = 0;
                barrier.wait();
                // Fixed disjoint action slots, with per-agent deterministic query rotation.
                for index in (agent * ops / agents)..((agent + 1) * ops / agents) {
                    let started = Instant::now();
                    if mode.writes(index) {
                        let entity = &write_ids[index];
                        let token = marker(CORPUS + index);
                        vault
                            .batch()
                            .put(
                                entity,
                                1,
                                TimeRange {
                                    start: index as u64 + 2,
                                    end: index as u64 + 2,
                                },
                                index as u64 + 2,
                                b"swarm-action",
                            )
                            .text(entity, &[("body", token.as_str())])
                            .commit()
                            .map_err(|e| format!("write {index}: {e}"))?;
                        writes.push(started.elapsed().as_secs_f64() * 1000.0);
                    } else {
                        let (expected, query) = &corpus[(index + agent) % corpus.len()];
                        let result = vault
                            .search_text_with_telemetry(query, 5)
                            .map_err(|e| format!("recall {index}: {e}"))?;
                        if !result.value.iter().any(|hit| hit.id == *expected) {
                            return Err(format!("recall {index}: planted document missing"));
                        }
                        telemetry_rows += usize::from(result.run_id.is_some());
                        reads.push(started.elapsed().as_secs_f64() * 1000.0);
                    }
                }
                Ok::<_, String>((writes, reads, telemetry_rows))
            }));
        }
        let start = Instant::now();
        barrier.wait();
        for handle in handles {
            match handle.join() {
                Ok(Ok((w, r, t))) => {
                    writes.extend(w);
                    reads.extend(r);
                    telemetry_rows += t;
                }
                Ok(Err(e)) => failure = Some(e),
                Err(_) => failure = Some("worker panicked".to_owned()),
            }
        }
        window_seconds = start.elapsed().as_secs_f64();
    });
    if let Some(error) = failure {
        return Err(error);
    }
    if writes.len() + reads.len() != ops {
        return Err("incomplete operations".into());
    }
    Ok(Report {
        schema: "oneiron.bench.swarm.v1",
        mode,
        agents,
        operations: ops,
        seed,
        corpus_docs: CORPUS,
        write_fraction: if mode == Mode::Mixed {
            "1/5"
        } else if mode == Mode::Write {
            "1"
        } else {
            "0"
        },
        recall_api: "Vault::search_text_with_telemetry (best-effort telemetry writes)",
        synchronized: true,
        window_seconds,
        operations_per_second: ops as f64 / window_seconds,
        writes: (!writes.is_empty()).then(|| Metric::new(writes, window_seconds)),
        recalls: (!reads.is_empty()).then(|| Metric::new(reads, window_seconds)),
        recall_telemetry_rows: telemetry_rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deterministic_plan_and_validated_tiers() {
        assert_eq!(marker(0), "qzmkaaaaa");
        assert_ne!(marker(0), marker(1200));
        assert!(
            parse(&[
                "--mode".into(),
                "mixed".into(),
                "--agents".into(),
                "300".into()
            ])
            .is_ok()
        );
        assert!(
            parse(&[
                "--mode".into(),
                "mixed".into(),
                "--agents".into(),
                "42".into()
            ])
            .is_err()
        );
        let writes = (0..1200).filter(|i| Mode::Mixed.writes(*i)).count();
        assert_eq!(writes, 240);
    }
    #[test]
    fn public_doors_return_all_operations() {
        let result = measure(Mode::Mixed, 1, 10, SEED).expect("seeded smoke");
        assert_eq!(result.writes.as_ref().map(|m| m.count), Some(2));
        assert_eq!(result.recalls.as_ref().map(|m| m.count), Some(8));
    }
}
