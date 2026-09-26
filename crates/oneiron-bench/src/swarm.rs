//! Seeded single-vault, in-process agent-swarm baseline. No engine internals.
use std::io::Write;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use crate::perf::sessions::ReleaseGate;

use oneiron::{EntityId, RetrievalRunId, TimeRange, Vault, VaultConfig};
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
        self == Self::Write || (self == Self::Mixed && index.is_multiple_of(5))
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

/// Diagnostic percentiles collected after the operation window from public
/// retrieval telemetry; not part of throughput or the steady-state hot path.
#[derive(Serialize)]
struct LatencyEvidence {
    count: usize,
    p50_ms: f64,
    p99_ms: f64,
}

impl LatencyEvidence {
    fn new(mut samples: Vec<f64>) -> Self {
        samples.sort_by(f64::total_cmp);
        let rank = |percent: usize| samples[(samples.len() * percent).div_ceil(100).max(1) - 1];
        Self {
            count: samples.len(),
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
    /// Public run records store search time BEFORE the telemetry writer runs.
    /// Present only with SWARM_DIAGNOSTIC=1 (recall-only trials).
    #[serde(skip_serializing_if = "Option::is_none")]
    search_only_ms: Option<LatencyEvidence>,
    /// API latency minus its own search-only duration; includes telemetry
    /// commit plus other post-search work, not an exact fsync timer.
    #[serde(skip_serializing_if = "Option::is_none")]
    post_search_ms: Option<LatencyEvidence>,
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
    if ![1, 10, 100, 300].contains(&agents)
        || ops == 0
        || !ops.is_multiple_of(agents)
        || !ops.is_multiple_of(5)
    {
        return Err(
            "agents must be 1|10|100|300; ops must be positive and divisible by agents and 5"
                .into(),
        );
    }
    Ok((mode.ok_or("missing --mode")?, agents, ops, seed))
}

#[derive(Clone, Serialize)]
struct Storage {
    temp_root: String,
    device: String,
    rotational: bool,
    filesystem: String,
}

/// Caller-supplied device identity, checked against findmnt/lsblk before a run.
/// Requiring it avoids silently publishing tmpfs runs as disk baselines.
fn storage() -> Result<Storage, String> {
    let temp_root = std::env::var("TMPDIR").map_err(|_| "set TMPDIR to a disk-backed root")?;
    let temp_root = std::fs::canonicalize(temp_root)
        .map_err(|e| format!("TMPDIR does not resolve: {e}"))?
        .display()
        .to_string();
    let device = std::env::var("SWARM_DISK_DEVICE").map_err(|_| "set SWARM_DISK_DEVICE")?;
    let rotational = match std::env::var("SWARM_DISK_ROTATIONAL").as_deref() {
        Ok("0") => false,
        Ok("1") => true,
        _ => return Err("set SWARM_DISK_ROTATIONAL=0|1".into()),
    };
    let filesystem =
        std::env::var("SWARM_DISK_FILESYSTEM").map_err(|_| "set SWARM_DISK_FILESYSTEM")?;
    if device.is_empty() || filesystem.is_empty() || filesystem == "tmpfs" {
        return Err("disk device and non-tmpfs filesystem must be specified".into());
    }
    Ok(Storage {
        temp_root,
        device,
        rotational,
        filesystem,
    })
}

pub(crate) fn run(args: &[String]) -> ExitCode {
    if args == ["--matrix"] {
        return run_matrix();
    }
    match parse(args).and_then(|(mode, agents, ops, seed)| {
        let storage = storage()?;
        measure(mode, agents, ops, seed).map(|report| (report, storage))
    }) {
        Ok((report, storage)) => {
            writeln!(
                std::io::stdout(),
                "{}",
                serde_json::json!({
                    "report": report, "storage": storage
                })
            )
            .expect("write single-run JSON");
            ExitCode::SUCCESS
        }
        Err(error) => {
            writeln!(std::io::stderr(), "swarm: {error}").expect("write error");
            writeln!(std::io::stderr(), "usage: oneiron-bench swarm --mode write|recall|mixed --agents 1|10|100|300 [--ops 1200] [--seed 42] | --matrix; set TMPDIR and SWARM_DISK_DEVICE, SWARM_DISK_ROTATIONAL, SWARM_DISK_FILESYSTEM")
                .expect("write usage");
            ExitCode::FAILURE
        }
    }
}

/// Each JSONL row is an independent fresh-vault trial. Host load is sampled
/// directly beside the run, not once for the whole matrix.
fn run_matrix() -> ExitCode {
    let storage = match storage() {
        Ok(storage) => storage,
        Err(error) => {
            writeln!(std::io::stderr(), "swarm: {error}").expect("write error");
            return ExitCode::FAILURE;
        }
    };
    for mode in [Mode::Write, Mode::Recall, Mode::Mixed] {
        for agents in [1, 10, 100, 300] {
            for trial in 1..=3 {
                let load_start = std::fs::read_to_string("/proc/loadavg")
                    .unwrap_or_else(|_| "unavailable".to_owned());
                writeln!(std::io::stderr(), "START {mode:?} {agents} trial={trial}")
                    .expect("write progress");
                match measure(mode, agents, OPS, SEED) {
                    Ok(report) => {
                        let load_end = std::fs::read_to_string("/proc/loadavg")
                            .unwrap_or_else(|_| "unavailable".to_owned());
                        writeln!(
                            std::io::stdout(),
                            "{}",
                            serde_json::json!({
                                "trial": trial,
                                "loadavg_start": load_start.trim(),
                                "loadavg_end": load_end.trim(),
                                "storage": &storage,
                                "report": report,
                            })
                        )
                        .expect("write JSONL row");
                        std::io::stdout().flush().expect("flush JSONL row");
                    }
                    Err(error) => {
                        writeln!(
                            std::io::stderr(),
                            "FAIL {mode:?} {agents} trial={trial}: {error}"
                        )
                        .expect("write error");
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
    }
    ExitCode::SUCCESS
}

/// Start is captured inside the release gate after every worker is ready.
/// End is the latest worker timestamp, before joining and merging samples.
struct Cohort<T> {
    results: Vec<T>,
    started_at: Instant,
    finished_at: Instant,
    #[cfg(test)]
    collected_at: Instant,
}

fn run_cohort<T, F>(agents: usize, work: F) -> Result<Cohort<T>, String>
where
    T: Send,
    F: Fn(usize, &ReleaseGate) -> Result<(T, Instant), String> + Sync,
{
    let gate = ReleaseGate::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(agents);
        let mut error = None;
        for agent in 0..agents {
            let gate = &gate;
            let work = &work;
            match std::thread::Builder::new().spawn_scoped(scope, move || work(agent, gate)) {
                Ok(handle) => handles.push(handle),
                Err(cause) => error = Some(format!("worker {agent} spawn: {cause}")),
            }
        }
        let release = gate.release_all(handles.len(), Duration::from_secs(120));
        let mut finished_at = release.window_started;
        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.join() {
                Ok(Ok((result, instant))) => {
                    finished_at = finished_at.max(instant);
                    results.push(result);
                }
                Ok(Err(cause)) => error = Some(cause),
                Err(_) => error = Some("worker panicked".into()),
            }
        }
        if release.arrived != agents || error.is_some() {
            return Err(error.unwrap_or_else(|| {
                format!(
                    "only {} of {agents} workers reached the release gate",
                    release.arrived
                )
            }));
        }
        Ok(Cohort {
            results,
            started_at: release.window_started,
            finished_at,
            #[cfg(test)]
            collected_at: Instant::now(),
        })
    })
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
    let diagnostic =
        mode == Mode::Recall && std::env::var("SWARM_DIAGNOSTIC").as_deref() == Ok("1");
    let cohort = run_cohort(agents, |agent, gate| {
        let mut writes = Vec::new();
        let mut reads = Vec::new();
        let mut diagnostic_runs: Vec<(f64, Option<RetrievalRunId>)> = Vec::new();
        let mut telemetry_rows = 0;
        gate.arrive_and_wait();
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
                let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
                if diagnostic {
                    diagnostic_runs.push((elapsed_ms, result.run_id));
                }
                reads.push(elapsed_ms);
            }
        }
        Ok((
            (writes, reads, telemetry_rows, diagnostic_runs),
            Instant::now(),
        ))
    })?;
    let window_seconds = cohort
        .finished_at
        .duration_since(cohort.started_at)
        .as_secs_f64();
    let mut writes = Vec::new();
    let mut reads = Vec::new();
    let mut telemetry_rows = 0;
    let mut diagnostic_runs = Vec::new();
    for (w, r, t, observed) in cohort.results {
        writes.extend(w);
        reads.extend(r);
        telemetry_rows += t;
        diagnostic_runs.extend(observed);
    }
    // Every read below happens AFTER the end timestamp; it cannot change the
    // measured operation window or its successful-call latency samples.
    let (search_only_ms, post_search_ms) = if diagnostic {
        if diagnostic_runs.len() != ops {
            return Err("diagnostic missing recall samples".into());
        }
        let mut searches = Vec::with_capacity(ops);
        let mut residuals = Vec::with_capacity(ops);
        for (api_ms, run_id) in diagnostic_runs {
            let id = run_id.ok_or("diagnostic missing telemetry run id")?;
            let row = vault
                .retrieval_run(id)
                .map_err(|e| format!("diagnostic retrieval run read: {e}"))?
                .ok_or("diagnostic telemetry row absent")?;
            let search_ms = row.elapsed_us as f64 / 1000.0;
            if search_ms > api_ms + 0.1 {
                return Err("diagnostic search time exceeds API duration".into());
            }
            searches.push(search_ms);
            residuals.push((api_ms - search_ms).max(0.0));
        }
        (
            Some(LatencyEvidence::new(searches)),
            Some(LatencyEvidence::new(residuals)),
        )
    } else {
        (None, None)
    };
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
        search_only_ms,
        post_search_ms,
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
    /// A late arrival and slow result collection must not enter the operation
    /// window; its end is the last completed action, not the last join.
    #[test]
    fn cohort_window_excludes_readiness_and_collection() {
        let ready = std::sync::Mutex::new(Vec::new());
        let cohort = run_cohort(2, |agent, gate| {
            if agent == 1 {
                std::thread::sleep(Duration::from_millis(90));
            }
            ready.lock().expect("ready lock").push(Instant::now());
            gate.arrive_and_wait();
            std::thread::sleep(Duration::from_millis(5));
            let completed = Instant::now();
            std::thread::sleep(Duration::from_millis(90));
            Ok(((agent, completed), completed))
        })
        .expect("cohort completes");
        let last_ready = ready
            .lock()
            .expect("ready lock")
            .iter()
            .copied()
            .max()
            .expect("ready");
        assert!(cohort.started_at >= last_ready);
        let last_action = cohort
            .results
            .iter()
            .map(|(_, at)| *at)
            .max()
            .expect("action");
        assert_eq!(cohort.finished_at, last_action);
        assert!(
            cohort.collected_at.duration_since(cohort.finished_at) >= Duration::from_millis(80)
        );
        assert_eq!(cohort.results.len(), 2);
    }

    #[test]
    fn public_doors_return_all_operations() {
        let result = measure(Mode::Mixed, 1, 10, SEED).expect("seeded smoke");
        assert_eq!(result.writes.as_ref().map(|m| m.count), Some(2));
        assert_eq!(result.recalls.as_ref().map(|m| m.count), Some(8));
    }
}
