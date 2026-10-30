//! `load` subcommand — the engine's load bench on the shipped server binary.
//!
//! It spawns the real `oneiron-server` (`init`, `token agent`, `serve` on
//! loopback), writes a synthetic corpus through the facade doors as signed
//! agents, and measures what an agent living in Oneiron feels: ingest writes/s
//! for one caller and for many, recall latency at each grade (call, light,
//! medium) and agent count, mixed grades, one heavy agent beside call-grade
//! callers, memory per resident agent, and startup and steady memory. Fixed
//! seeds; one command; one JSON result. `docs/ops/load-bench.md` says how to
//! run it and compare two commits.
//!
//! * `oneiron-bench load run --server <oneiron-server> --work <dir> --out <file.json> [flags]`
//! * `oneiron-bench load startup --server <oneiron-server> --work <dir> --out <file.json>`
//!   — the startup peak while the shipped local embedding model loads
//! * `oneiron-bench load corpus-recall --server <oneiron-server> --corpus <turns.jsonl> --work <dir> --out <file.json>`
//!   — warm recall latency, per stage when the server logs stage timers, on a
//!   vault seeded from a recorded conversation corpus
//! * `oneiron-bench load compare <a.json> <b.json>`
//!
//! Latencies are measured by the client on loopback, so they include HTTP and
//! JSON work on both ends: a little above the server-side time. `run` and
//! `startup` read the server's `/proc` files, so they run on Linux only.

mod client;
mod corpus;
mod corpus_recall;
mod embedder;
mod phases;
mod report;
pub(crate) mod server;
mod startup;
mod stats;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;

use client::Agent;
use corpus::{Corpus, Record, Subject};
use embedder::StubEmbedder;
use phases::{Ctx, Grade};
use report::{Host, Report, Rows, Run, Startup};
use server::{Embedding, Running, Vault};

/// The parsed `load run` flags.
struct Plan {
    server: PathBuf,
    work: PathBuf,
    out: PathBuf,
    label: Option<String>,
    scales: Vec<usize>,
    vectors: Vec<bool>,
    agents: Vec<usize>,
    ingest_callers: usize,
    single_writes: usize,
    seed: u64,
    hot_subject: f64,
    queries: usize,
    dimensions: usize,
    grades: Vec<Grade>,
    cell_requests: usize,
    cell_seconds: f64,
    drain_settle_seconds: u64,
    server_env: Vec<(String, String)>,
    signal_cells: Vec<(String, String)>,
    skip: Vec<String>,
}

const USAGE: &str = "usage: oneiron-bench load run --server <oneiron-server> --work <dir> --out <file.json>\n\
  [--label TEXT] [--records 1000,10000] [--vectors off|on|both] [--agents 1,8,32,128]\n\
  [--ingest-callers 32] [--single-writes 200] [--seed 7] [--hot-subject 0.2] [--queries 50]\n\
  [--dimensions 1024] [--grades call,light,medium] [--call-deadline-ms N] [--cell-requests 200]\n\
  [--cell-seconds 60] [--drain-settle-seconds 35] [--server-env KEY=VALUE]...\n\
  [--signal-cell CELL:SIGNAL]...\n\
  [--skip mixed,fairness,agent-memory,restart]\n\
or:    oneiron-bench load startup --server <oneiron-server> --work <dir> --out <file.json>\n\
  [--label TEXT] [--repeat 3] [--server-env KEY=VALUE]...\n\
or:    oneiron-bench load corpus-recall --server <oneiron-server> --corpus <turns.jsonl> --work <dir>\n\
  --out <file.json> [--query TEXT]... [--repeat 10] [--warmup 2] [--limit 20] [--effort light]\n\
  [--as-of corpus|none] [--claims notes|none] [--profile-repeat N] [--server-env KEY=VALUE]...\n\
or:    oneiron-bench load compare <a.json> <b.json>";

fn list<T: std::str::FromStr>(value: &str) -> Result<Vec<T>, String> {
    value
        .split(',')
        .map(|v| {
            v.trim()
                .parse::<T>()
                .map_err(|_| format!("bad list item `{v}`"))
        })
        .collect()
}

fn parse(args: &[String]) -> Result<Plan, String> {
    let mut plan = Plan {
        server: PathBuf::new(),
        work: PathBuf::new(),
        out: PathBuf::new(),
        label: None,
        scales: vec![1_000, 10_000],
        vectors: vec![false],
        agents: vec![1, 8, 32, 128],
        ingest_callers: 32,
        single_writes: 200,
        seed: 7,
        hot_subject: 0.2,
        queries: 50,
        dimensions: 1024,
        grades: ["call", "light", "medium"].map(Grade::named).to_vec(),
        cell_requests: 200,
        cell_seconds: 60.0,
        drain_settle_seconds: 35,
        server_env: Vec::new(),
        signal_cells: Vec::new(),
        skip: Vec::new(),
    };
    let mut call_deadline = None;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let num = |v: &str| {
            v.parse::<usize>()
                .map_err(|_| format!("{flag}: `{v}` is not a number"))
        };
        match flag.as_str() {
            "--server" => plan.server = PathBuf::from(value),
            "--work" => plan.work = PathBuf::from(value),
            "--out" => plan.out = PathBuf::from(value),
            "--label" => plan.label = Some(value.clone()),
            "--records" => plan.scales = list(value)?,
            "--vectors" => {
                plan.vectors = match value.as_str() {
                    "off" => vec![false],
                    "on" => vec![true],
                    "both" => vec![false, true],
                    _ => return Err("--vectors is off, on or both".into()),
                }
            }
            "--agents" => plan.agents = list(value)?,
            "--ingest-callers" => plan.ingest_callers = num(value)?.max(1),
            "--single-writes" => plan.single_writes = num(value)?,
            "--seed" => plan.seed = num(value)? as u64,
            "--hot-subject" => {
                plan.hot_subject = value.parse().map_err(|_| "--hot-subject is a fraction")?;
            }
            "--queries" => plan.queries = num(value)?.max(1),
            "--dimensions" => plan.dimensions = num(value)?,
            "--grades" => plan.grades = value.split(',').map(Grade::named).collect(),
            "--call-deadline-ms" => call_deadline = Some(num(value)? as u64),
            "--cell-requests" => plan.cell_requests = num(value)?,
            "--cell-seconds" => plan.cell_seconds = num(value)? as f64,
            "--drain-settle-seconds" => plan.drain_settle_seconds = num(value)? as u64,
            "--server-env" => {
                let (k, v) = value.split_once('=').ok_or("--server-env is KEY=VALUE")?;
                plan.server_env.push((k.to_owned(), v.to_owned()));
            }
            "--signal-cell" => {
                let (cell, signal) = value
                    .split_once(':')
                    .ok_or("--signal-cell is CELL:SIGNAL")?;
                plan.signal_cells.push((cell.to_owned(), signal.to_owned()));
            }
            "--skip" => plan.skip = value.split(',').map(str::to_owned).collect(),
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    for grade in plan.grades.iter_mut().filter(|g| g.name == "call") {
        grade.deadline_ms = call_deadline;
    }
    if plan.server.as_os_str().is_empty()
        || plan.work.as_os_str().is_empty()
        || plan.out.as_os_str().is_empty()
    {
        return Err("--server, --work and --out are required".into());
    }
    Ok(plan)
}

const LINUX_ONLY: &str =
    "load run and load startup read the server's /proc files: run them on Linux";

pub(crate) fn run(args: &[String]) -> ExitCode {
    let linux = cfg!(target_os = "linux");
    let result = match args {
        [cmd, ..] if (cmd == "run" || cmd == "startup" || cmd == "corpus-recall") && !linux => {
            Err(LINUX_ONLY.to_owned())
        }
        [cmd, rest @ ..] if cmd == "run" => parse(rest).and_then(|plan| execute(&plan)),
        [cmd, rest @ ..] if cmd == "startup" => startup::run(rest),
        [cmd, rest @ ..] if cmd == "corpus-recall" => corpus_recall::run(rest),
        [cmd, a, b] if cmd == "compare" => {
            report::compare(Path::new(a), Path::new(b)).and_then(|table| {
                writeln!(std::io::stdout().lock(), "{table}").map_err(|e| e.to_string())
            })
        }
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(std::io::stderr().lock(), "load: {error}");
            ExitCode::FAILURE
        }
    }
}

fn say(text: &str) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "[load {}] {text}",
        phases::loadavg()
    );
}

fn host() -> Host {
    let read = |path: &str| std::fs::read_to_string(path).unwrap_or_default();
    let cgroup = read("/proc/self/cgroup")
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_owned));
    Host {
        hostname: read("/proc/sys/kernel/hostname").trim().to_owned(),
        cpu: read("/proc/cpuinfo")
            .lines()
            .find_map(|l| {
                l.strip_prefix("model name")
                    .map(|m| m.trim_start_matches([' ', '\t', ':']).to_owned())
            })
            .unwrap_or_default(),
        logical_cpus: std::thread::available_parallelism().map_or(0, std::num::NonZero::get),
        cgroup_cpu_max: cgroup
            .and_then(|path| std::fs::read_to_string(format!("/sys/fs/cgroup{path}/cpu.max")).ok())
            .map(|s| s.trim().to_owned()),
        load_start: phases::loadavg(),
        load_end: String::new(),
    }
}

fn execute(plan: &Plan) -> Result<(), String> {
    let mut report = Report {
        bench: "oneiron-bench load v1".to_owned(),
        label: plan.label.clone(),
        started_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        host: host(),
        server_bin: plan.server.display().to_string(),
        server_bytes: std::fs::metadata(&plan.server)
            .map_err(|e| format!("--server: {e}"))?
            .len(),
        plan: plan_echo(plan),
        runs: Vec::new(),
    };
    for &records in &plan.scales {
        for &vectors in &plan.vectors {
            say(&format!("run: {records} records, vectors {vectors}"));
            let run = one_run(plan, records, vectors)?;
            report.runs.push(run);
            report.host.load_end = phases::loadavg();
            let text = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
            std::fs::write(&plan.out, text).map_err(|e| format!("{}: {e}", plan.out.display()))?;
        }
    }
    say(&format!("wrote {}", plan.out.display()));
    Ok(())
}

fn plan_echo(plan: &Plan) -> serde_json::Value {
    json!({
        "scales": plan.scales, "vectors": plan.vectors, "agents": plan.agents,
        "ingest_callers": plan.ingest_callers, "single_writes": plan.single_writes,
        "seed": plan.seed, "hot_subject": plan.hot_subject, "queries": plan.queries,
        "dimensions": plan.dimensions,
        "grades": plan.grades.iter().map(|g| json!({"name": g.name, "effort": g.effort, "deadline_ms": g.deadline_ms, "limit": g.limit})).collect::<Vec<_>>(),
        "cell_requests": plan.cell_requests, "cell_seconds": plan.cell_seconds,
        "drain_settle_seconds": plan.drain_settle_seconds,
        // Names only: values (often credentials) stay in the spawned server's environment.
        "server_env": plan.server_env.iter().map(|(k, _)| k).collect::<Vec<_>>(),
        "signal_cells": plan.signal_cells, "skip": plan.skip,
    })
}

fn rows(corpus: &Corpus, records: usize) -> Rows {
    let mut rows = Rows::default();
    for i in 0..records {
        match corpus.record(i) {
            Record::Turn { messages, .. } => {
                rows.turns += 1;
                rows.messages += messages.len();
                rows.edges_written += 1 + 3 * messages.len();
            }
            Record::Claim { subject, .. } => {
                rows.claims += 1;
                rows.edges_written += 1;
                rows.owner_claims += usize::from(matches!(subject, Subject::Owner));
            }
        }
    }
    rows.conversations = rows.turns.div_ceil(corpus::TURNS_PER_CONVERSATION);
    rows
}

fn startup_of(server: &Running) -> Startup {
    let (at_ready, sampled) = server.memory();
    Startup {
        ready_ms: server.ready_ms,
        at_ready,
        peak: sampled.peak_with(at_ready),
    }
}

fn one_run(plan: &Plan, records: usize, vectors: bool) -> Result<Run, String> {
    let dir = plan.work.join(format!(
        "r{records}-{}",
        if vectors { "vec" } else { "novec" }
    ));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| format!("clear {}: {e}", dir.display()))?;
    }
    let stub = if vectors {
        Some(StubEmbedder::start(plan.dimensions)?)
    } else {
        None
    };
    let embedding = stub.as_ref().map_or(Embedding::None, |s| Embedding::Stub {
        endpoint: s.endpoint(),
        dimensions: plan.dimensions,
    });
    let vault = Vault::init(&plan.server, &dir, &embedding, &plan.server_env)?;
    let corpus = Corpus::new(plan.seed, plan.hot_subject);
    let mut run = Run {
        records,
        documents: 0,
        secret_scan: vault.secret_scan(&plan.server)?,
        vectors,
        rows: rows(&corpus, records),
        ..Run::default()
    };
    // Recall cells use agents from 0, the ingest callers too; the agents
    // after both are fresh for the memory-per-agent cell; the last is heavy.
    let agent_count = plan
        .agents
        .iter()
        .copied()
        .max()
        .unwrap_or(1)
        .max(plan.ingest_callers)
        + plan.agents.iter().copied().max().unwrap_or(1)
        + 1;
    let minted = Instant::now();
    let credentials = (0..agent_count)
        .map(|i| vault.mint_agent(&plan.server, &format!("bench-agent-{i:04}")))
        .collect::<Result<Vec<_>, _>>()?;
    run.mint_seconds = minted.elapsed().as_secs_f64();
    say(&format!(
        "minted {agent_count} agents in {:.1} s",
        run.mint_seconds
    ));
    let server = Running::start(&plan.server, &vault, &plan.server_env, "serve.log", "warn")?;
    run.startup_empty = startup_of(&server);
    let http = Agent::http()?;
    run.clock_skew_secs = Agent::new(&http, &server.base, &credentials[0], 0)?.clock_skew()?;
    if run.clock_skew_secs != 0 {
        say(&format!(
            "holder proofs are signed {} s off the wall clock",
            run.clock_skew_secs
        ));
    }
    let agents = credentials
        .iter()
        .map(|c| Agent::new(&http, &server.base, c, run.clock_skew_secs))
        .collect::<Result<Vec<_>, _>>()?;
    let queries = corpus.queries(records, plan.queries);
    let secret_scan = run.secret_scan.clone();
    let mut ctx = Ctx {
        corpus: &corpus,
        documents: run.documents,
        secret_scan: &secret_scan,
        owner: &vault.owner,
        server: &server,
        agents: &agents,
        queries: &queries,
        now: corpus::recall_now(records + plan.single_writes),
        cell_requests: plan.cell_requests,
        cell_seconds: plan.cell_seconds,
        signal_cells: plan.signal_cells.clone(),
    };
    measure(plan, &mut ctx, &mut run, records, stub.as_ref(), &vault)?;
    let exit = server.stop();
    run.notes.push(format!("serve exit: {exit}"));
    if !plan.skip.iter().any(|s| s == "restart") {
        let again = Running::start(
            &plan.server,
            &vault,
            &plan.server_env,
            "serve-restart.log",
            "warn",
        )?;
        run.startup_full = startup_of(&again);
        let exit = again.stop();
        run.notes.push(format!("restart exit: {exit}"));
    }
    Ok(run)
}

fn measure(
    plan: &Plan,
    ctx: &mut Ctx<'_>,
    run: &mut Run,
    records: usize,
    stub: Option<&StubEmbedder>,
    vault: &Vault,
) -> Result<(), String> {
    if let Some(stub) = stub {
        stub.watch_passes(ctx.server.log_counter(phases::PASS_DONE));
    }
    let single = plan.single_writes.min(records);
    say("ingest: one caller on the empty vault");
    run.ingest
        .push(ctx.ingest_single("ingest_single_empty", 0..single));
    say(&format!("ingest: {} callers", plan.ingest_callers));
    run.ingest
        .push(ctx.ingest_parallel(single..records, plan.ingest_callers));
    say("ingest: one caller on the full vault");
    run.ingest
        .push(ctx.ingest_single("ingest_single_full", records..records + plan.single_writes));
    ctx.documents = run.ingest.iter().map(|cell| cell.summary.completed).sum();
    run.documents = ctx.documents;
    if let Some(stub) = stub {
        say("drain: waiting for the embedding worker");
        let expected = records + plan.single_writes;
        run.drain_seconds = Some(phases::drain(
            ctx.server,
            stub,
            expected,
            Duration::from_secs(plan.drain_settle_seconds),
            Duration::from_secs(3600),
        )?);
        run.notes.push(format!(
            "stub embedded {} inputs for {expected} records",
            stub.embedded()
        ));
    }
    std::thread::sleep(Duration::from_secs(2));
    run.steady = ctx.server.memory().0;
    run.disk_mib = vault.disk_bytes() as f64 / 1_048_576.0;
    say("golden queries");
    (run.golden, run.hit_at_10) = ctx.golden(&plan.grades);
    if !plan.skip.iter().any(|s| s == "agent-memory") {
        let used = plan
            .agents
            .iter()
            .copied()
            .max()
            .unwrap_or(1)
            .max(plan.ingest_callers);
        let fresh = used.min(ctx.agents.len() - 1)..ctx.agents.len() - 1;
        if !fresh.is_empty() {
            run.memory_per_agent = Some(ctx.agent_memory(fresh));
        }
    }
    for grade in &plan.grades {
        for &agents in &plan.agents {
            say(&format!("recall {} x{agents}", grade.name));
            run.recall.push(ctx.recall_cell(grade, agents));
        }
    }
    let call = plan
        .grades
        .iter()
        .find(|g| g.name == "call")
        .cloned()
        .unwrap_or_else(|| Grade::named("light"));
    let normal = Grade::named("medium");
    if !plan.skip.iter().any(|s| s == "mixed") {
        for &agents in plan.agents.iter().filter(|&&a| a >= 2) {
            say(&format!("mixed x{agents}"));
            run.mixed.extend(ctx.mixed_cell(&call, &normal, agents));
        }
    }
    if !plan.skip.iter().any(|s| s == "fairness") {
        say("fairness");
        run.fairness = Some(ctx.fairness(&call, &normal, 8, 8));
    }
    Ok(())
}
