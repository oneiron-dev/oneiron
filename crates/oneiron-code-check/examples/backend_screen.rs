//! Fleet-only, sequential direction screen; no fallback and no default switch.
//! Build: cargo build --locked --release -p oneiron-code-check --example backend_screen
//! Run with --microsoft-tsc /srv/typescript/package/lib/tsc --output /srv/evidence/codecheck.

use oneiron_code_check::{
    BackendId, CheckInput, CodeCheck, Declaration, Diagnostic, MICROSOFT_TS_VERSION, MicrosoftTsc,
    TscRsBudget, TscRsWasm, TsrsWasm,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const DECLARATIONS: [Declaration<'static>; 3] = [
    Declaration {
        name: "code-run.d.ts",
        text: include_str!("../../oneiron/wit/generated/code-run.d.ts"),
    },
    Declaration {
        name: "code-mode.d.ts",
        text: include_str!("../../oneiron/src/verbs/generated/catalog_fragment.d.ts"),
    },
    Declaration {
        name: "runtime.d.ts",
        text: include_str!("../../../components/code-run-quickjs/runtime.d.ts"),
    },
];
const CONTROLS: [(&str, &str); 7] = [
    (
        "01-correct",
        include_str!("../tests/fixtures/01-correct.js"),
    ),
    (
        "02-wrong-verb",
        include_str!("../tests/fixtures/02-wrong-verb.js"),
    ),
    (
        "03-wrong-argument",
        include_str!("../tests/fixtures/03-wrong-argument.js"),
    ),
    (
        "04-missing-await",
        include_str!("../tests/fixtures/04-missing-await.js"),
    ),
    (
        "05-undefined-path",
        include_str!("../tests/fixtures/05-undefined-path.js"),
    ),
    (
        "06-floating-promise",
        include_str!("../tests/fixtures/06-floating-promise.js"),
    ),
    (
        "07-any-null-path",
        include_str!("../tests/fixtures/07-any-null-path.js"),
    ),
];

struct Args {
    rounds: usize,
    warmup: usize,
    microsoft: PathBuf,
    programs: PathBuf,
    output: PathBuf,
}

fn arguments() -> Result<Args> {
    let mut args = Args {
        rounds: 50,
        warmup: 3,
        microsoft: PathBuf::new(),
        programs: PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/examples/screen-programs"
        )),
        output: PathBuf::from("/srv/evidence/codecheck-8255"),
    };
    let mut input = std::env::args().skip(1);
    while let Some(flag) = input.next() {
        let value = input
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--rounds" => args.rounds = value.parse()?,
            "--warmup" => args.warmup = value.parse()?,
            "--microsoft-tsc" => args.microsoft = value.into(),
            "--programs" => args.programs = value.into(),
            "--output" => args.output = value.into(),
            _ => return Err(format!("unknown argument {flag}").into()),
        }
    }
    if args.rounds == 0 || args.microsoft.as_os_str().is_empty() {
        return Err("--rounds must be positive; --microsoft-tsc is required (microsoft unavailable without it)".into());
    }
    Ok(args)
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Deserialize, Serialize)]
struct Entry {
    id: String,
    file: String,
    source_path: String,
    sha256: String,
    #[serde(flatten)]
    provenance: BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct Program {
    entry: Entry,
    group: &'static str,
    bytes: usize,
    lines: usize,
    text: String,
    microsoft_screened_tokens: Vec<&'static str>,
}

fn program(entry: Entry, text: String, group: &'static str) -> Result<Program> {
    if sha(text.as_bytes()) != entry.sha256 {
        return Err(format!("program hash mismatch: {}", entry.id).into());
    }
    // Reporting only: MicrosoftTsc::check remains the authority on exclusions.
    let lower = text.to_ascii_lowercase();
    let microsoft_screened_tokens = ["import", "export", "require", "reference", "module", "\\u"]
        .into_iter()
        .filter(|token| lower.contains(*token))
        .collect();
    Ok(Program {
        entry,
        group,
        bytes: text.len(),
        lines: text.lines().count(),
        text,
        microsoft_screened_tokens,
    })
}

fn programs(directory: &Path) -> Result<Vec<Program>> {
    let entries: Vec<Entry> =
        serde_json::from_slice(&std::fs::read(directory.join("manifest.json"))?)?;
    if entries.len() != 5 {
        return Err("the primary corpus must contain five programs (15 cells)".into());
    }
    let mut all = Vec::new();
    for entry in entries {
        let text = std::fs::read_to_string(directory.join(&entry.file))?;
        all.push(program(entry, text, "primary")?);
    }
    for (id, text) in CONTROLS {
        let entry = Entry {
            id: id.into(),
            file: format!("{id}.js"),
            source_path: format!("crates/oneiron-code-check/tests/fixtures/{id}.js"),
            sha256: sha(text.as_bytes()),
            provenance: BTreeMap::new(),
        };
        all.push(program(entry, text.into(), "control")?);
    }
    let ids: BTreeSet<_> = all.iter().map(|p| &p.entry.id).collect();
    if ids.len() != all.len() {
        return Err("duplicate program ids".into());
    }
    Ok(all)
}

struct Loaded {
    checker: Box<dyn CodeCheck>,
    id: BackendId,
    load_ms: f64,
}

fn load(
    name: &str,
    make: impl FnOnce() -> std::result::Result<Box<dyn CodeCheck>, oneiron_code_check::CheckFailure>,
) -> Result<Loaded> {
    let started = Instant::now();
    let checker = make().map_err(|failure| format!("{name} unavailable: {failure}"))?;
    let load_ms = started.elapsed().as_secs_f64() * 1000.0;
    println!("{name} load: {load_ms:.3} ms");
    Ok(Loaded {
        id: checker.backend(),
        checker,
        load_ms,
    })
}

#[derive(Serialize)]
struct Sample {
    program: String,
    backend: String,
    repetition: usize,
    ms: f64,
    result: &'static str,
    failure: Option<&'static str>,
    diagnostics: Option<Vec<Diagnostic>>,
    peak_memory_bytes: Option<u64>,
    reported_backend: Option<BackendId>,
}

fn measure(program: &Program, backend: &Loaded, repetition: usize) -> Sample {
    let started = Instant::now();
    let result = backend.checker.check(&CheckInput {
        declarations: &DECLARATIONS,
        program: &program.text,
    });
    let ms = started.elapsed().as_secs_f64() * 1000.0;
    let mut sample = Sample {
        program: program.entry.id.clone(),
        backend: backend.id.name.into(),
        repetition,
        ms,
        result: "failure",
        failure: None,
        diagnostics: None,
        peak_memory_bytes: None,
        reported_backend: None,
    };
    match result {
        Ok(report) => {
            sample.result = if report.diagnostics.is_empty() {
                "clean"
            } else {
                "diagnostics"
            };
            sample.diagnostics = Some(report.diagnostics);
            sample.peak_memory_bytes = report.peak_memory_bytes;
            sample.reported_backend = Some(report.backend);
        }
        Err(failure) => sample.failure = Some(failure.code()),
    }
    sample
}

fn key(d: &Diagnostic) -> (Option<&str>, u32, u32, &str, u32, &str) {
    (
        d.file.as_deref(),
        d.line,
        d.column,
        &d.category,
        d.code,
        &d.message,
    )
}

fn sorted(sample: &Sample) -> Option<Vec<Diagnostic>> {
    sample.diagnostics.as_ref().map(|diagnostics| {
        let mut all = diagnostics.clone();
        all.sort_by(|a, b| key(a).cmp(&key(b)));
        all
    })
}

fn locations(diagnostics: &[Diagnostic]) -> Vec<(Option<&str>, u32, u32, u32)> {
    let mut all: Vec<_> = diagnostics
        .iter()
        .map(|d| (d.file.as_deref(), d.line, d.column, d.code))
        .collect();
    all.sort_unstable();
    all
}

fn difference(left: &[Diagnostic], right: &[Diagnostic]) -> Vec<Diagnostic> {
    let (mut at, mut other) = (0, 0);
    let mut only = Vec::new();
    while at < left.len() {
        if other == right.len() || key(&left[at]) < key(&right[other]) {
            only.push(left[at].clone());
            at += 1;
        } else if key(&left[at]) == key(&right[other]) {
            at += 1;
            other += 1;
        } else {
            other += 1;
        }
    }
    only
}

#[derive(Serialize)]
struct Agreement {
    program: String,
    backend: String,
    repetition: usize,
    exact_vs_ms: Option<bool>,
    code_location_vs_ms: Option<bool>,
    three_way_exact: bool,
    backend_only: Vec<Diagnostic>,
    microsoft_only: Vec<Diagnostic>,
}

fn agreements(samples: &[Sample], programs: &[Program], rounds: usize) -> Vec<Agreement> {
    let mut all = Vec::new();
    for program in programs {
        for repetition in 0..rounds {
            let cell: Vec<_> = samples
                .iter()
                .filter(|s| s.program == program.entry.id && s.repetition == repetition)
                .collect();
            let oracle = cell
                .iter()
                .find(|s| s.backend == "microsoft")
                .and_then(|s| sorted(s));
            let three_way_exact = oracle.as_ref().is_some_and(|ms| {
                cell.len() == 3 && cell.iter().all(|s| sorted(s).as_ref() == Some(ms))
            });
            for sample in cell {
                let own = sorted(sample);
                let pair = own.as_ref().zip(oracle.as_ref());
                all.push(Agreement {
                    program: sample.program.clone(),
                    backend: sample.backend.clone(),
                    repetition,
                    exact_vs_ms: pair.map(|(a, b)| a == b),
                    code_location_vs_ms: pair.map(|(a, b)| locations(a) == locations(b)),
                    three_way_exact,
                    backend_only: pair.map_or_else(Vec::new, |(a, b)| difference(a, b)),
                    microsoft_only: pair.map_or_else(Vec::new, |(a, b)| difference(b, a)),
                });
            }
        }
    }
    all
}

fn percentile(values: &[f64], quantile: usize) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    Some(sorted[(sorted.len() * quantile).div_ceil(100).saturating_sub(1)])
}

fn number(value: Option<f64>) -> String {
    value.map_or_else(|| "N/A".into(), |v| format!("{v:.3}"))
}

fn agreement_text(values: impl Iterator<Item = Option<bool>>, reference: bool) -> String {
    let (mut yes, mut no, mut missing) = (0, 0, 0);
    for value in values {
        match value {
            Some(true) => yes += 1,
            Some(false) => no += 1,
            None => missing += 1,
        }
    }
    let status = if no > 0 {
        "no"
    } else if missing > 0 {
        "N/A-failure"
    } else {
        "yes"
    };
    let prefix = if reference { "self-reference: " } else { "" };
    format!("{prefix}{status} ({yes} yes / {no} no / {missing} N/A)")
}

fn markdown(
    programs: &[Program],
    backends: &[Loaded],
    samples: &[Sample],
    comparisons: &[Agreement],
    args: &Args,
    hash: &str,
) -> String {
    let (rounds, warmup) = (args.rounds, args.warmup);
    let mut md = format!(
        "# Backend direction screen\n\nRaw samples, pins, environment and full diagnostics: [screen.json](screen.json), SHA-256 `{hash}`.\n\nMultiset differences by program/backend/repetition: [diffs.json](diffs.json).\n\nProtocol: {warmup} discarded warmups and {rounds} recorded checks per program/backend; concurrency 1; deterministic rotating order.\n\n"
    );
    md.push_str("Checks are sequential. Warmups are discarded; successful clean **and diagnostic** reports enter nearest-rank p50/p95. Failures do not. Agreement pairs the same recorded repetition with Microsoft; duplicates are retained. Exact uses file/line/column/category/code/message. Code/location omits category/message. A missing report is N/A, never agreement. Three-way is false if any backend fails. Peak is reported linear memory, not RSS; Microsoft is N/A.\n\n");
    for group in ["primary", "control"] {
        let _ = writeln!(
            md,
            "## {}\n",
            if group == "primary" {
                "Primary corpus (15 rows)"
            } else {
                "Secondary diagnostic controls (not pooled into the summary)"
            }
        );
        md.push_str("| Program | Backend + pin | Input bytes/lines | Answered/attempted | Failures by code | p50 ms | p95 ms | Diagnostics (# / codes) | Exact vs MS | Code/location vs MS | Three-way exact | Peak linear MiB | Load ms |\n|---|---|---:|---:|---|---:|---:|---|---|---|---|---:|---:|\n");
        for program in programs.iter().filter(|p| p.group == group) {
            for backend in backends {
                let cell: Vec<_> = samples
                    .iter()
                    .filter(|s| s.program == program.entry.id && s.backend == backend.id.name)
                    .collect();
                let compared: Vec<_> = comparisons
                    .iter()
                    .filter(|a| a.program == program.entry.id && a.backend == backend.id.name)
                    .collect();
                let times: Vec<_> = cell
                    .iter()
                    .filter(|s| s.failure.is_none())
                    .map(|s| s.ms)
                    .collect();
                let mut failures = BTreeMap::new();
                let mut diagnostic_sets = BTreeSet::new();
                for s in &cell {
                    if let Some(code) = s.failure {
                        *failures.entry(code).or_insert(0) += 1;
                    }
                    if let Some(ds) = &s.diagnostics {
                        let codes: BTreeSet<_> = ds.iter().map(|d| d.code).collect();
                        diagnostic_sets.insert(format!("{} / {:?}", ds.len(), codes));
                    }
                }
                let peak = cell
                    .iter()
                    .filter_map(|s| s.peak_memory_bytes)
                    .max()
                    .map(|n| n as f64 / 1048576.0);
                let exact = agreement_text(
                    compared.iter().map(|a| a.exact_vs_ms),
                    backend.id.name == "microsoft",
                );
                let location = agreement_text(
                    compared.iter().map(|a| a.code_location_vs_ms),
                    backend.id.name == "microsoft",
                );
                let three = compared.iter().filter(|a| a.three_way_exact).count();
                let _ = writeln!(
                    md,
                    "| {} | {} `{}` | {}/{} | {}/{} | {:?} | {} | {} | [{}](screen.json) | [{}](diffs.json) | {} | {} ({}/{}) | {} | {:.3} |",
                    program.entry.id,
                    backend.id.name,
                    backend.id.pin,
                    program.bytes,
                    program.lines,
                    times.len(),
                    cell.len(),
                    failures,
                    number(percentile(&times, 50)),
                    number(percentile(&times, 95)),
                    diagnostic_sets.into_iter().collect::<Vec<_>>().join("; "),
                    exact,
                    location,
                    if three == compared.len() { "yes" } else { "no" },
                    three,
                    compared.len(),
                    number(peak),
                    backend.load_ms
                );
            }
        }
        md.push('\n');
    }
    md.push_str("## Equal-weight primary-program summary\n\nArithmetic mean of the five per-program p50s and, separately, the five per-program p95s: **not pooled percentiles**. A missing cell makes the corresponding mean N/A. Coverage and failures must be read alongside latency. Controls are excluded.\n\n| Backend | Programs answered | Answered/attempted | Mean program p50 ms | Mean program p95 ms | Exact pairs vs MS | Code/location pairs vs MS |\n|---|---:|---:|---:|---:|---|---|\n");
    for backend in backends {
        let mut p50s = Vec::new();
        let mut p95s = Vec::new();
        let (mut answered, mut attempted) = (0, 0);
        let mut compared = Vec::new();
        for program in programs.iter().filter(|p| p.group == "primary") {
            let cell: Vec<_> = samples
                .iter()
                .filter(|s| s.program == program.entry.id && s.backend == backend.id.name)
                .collect();
            let times: Vec<_> = cell
                .iter()
                .filter(|s| s.failure.is_none())
                .map(|s| s.ms)
                .collect();
            attempted += cell.len();
            answered += times.len();
            if let Some(v) = percentile(&times, 50) {
                p50s.push(v);
            }
            if let Some(v) = percentile(&times, 95) {
                p95s.push(v);
            }
            compared.extend(
                comparisons
                    .iter()
                    .filter(|a| a.program == program.entry.id && a.backend == backend.id.name),
            );
        }
        let mean = |v: &[f64]| (v.len() == 5).then(|| v.iter().sum::<f64>() / 5.0);
        let _ = writeln!(
            md,
            "| {} | {}/5 | {}/{} | {} | {} | {} | {} |",
            backend.id.name,
            p50s.len(),
            answered,
            attempted,
            number(mean(&p50s)),
            number(mean(&p95s)),
            agreement_text(
                compared.iter().map(|a| a.exact_vs_ms),
                backend.id.name == "microsoft"
            ),
            agreement_text(
                compared.iter().map(|a| a.code_location_vs_ms),
                backend.id.name == "microsoft"
            )
        );
    }
    md.push_str("\n## Unsupported-token preflight\n\nThe same programs are still attempted; none is silently excluded. These are reporting-only matches of the native backend's token filter.\n\n");
    for p in programs {
        let _ = writeln!(md, "- {}: {:?}", p.entry.id, p.microsoft_screened_tokens);
    }
    md.push_str("\n## Historical context (not comparable measurements)\n\n| 11 Oct 2026, engine a6b9d512f / PR #1380, gce | tsc-rs | Microsoft |\n|---|---:|---:|\n| Archived p50 citation | 138 ms | 31 ms |\n| Archived 8,000-line citation | 428 ms | 245 ms |\n\nSource: archived architecture page `/oneiron/agents/oneiron-arch-0028-mcp-external-agent-surface-v1/#code-check-built`. Original raw logs, exact CLI/round count and host details were not recovered. Today's declarations/pins have evolved. A newly booked host is not comparable to those old gce numbers; no regression claim follows. This is a small direction screen, not conformance proof or runtime-safety proof. Microsoft is a subprocess without the in-process file boundary.\n\n## Engine decision: pending\n\n| Engine decision | pending |\n|---|---|\n");
    md
}

fn command(name: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(name).args(args).output().ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn machine_state() -> Value {
    json!({
        "unix_ms": SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_millis()),
        "loadavg": std::fs::read_to_string("/proc/loadavg").ok(),
        "cpu_affinity_status": std::fs::read_to_string("/proc/self/status").ok().map(|s| {
            s.lines().filter(|l| l.starts_with("Cpus_allowed")).collect::<Vec<_>>().join("\n")
        }),
    })
}

fn run() -> Result<()> {
    let args = arguments()?;
    std::fs::create_dir_all(&args.output)?;
    if args.output.join("screen.json").exists() || args.output.join("screen.md").exists() {
        return Err("output already contains a screen; use a fresh output directory".into());
    }
    let programs = programs(&args.programs)?;
    let budget = TscRsBudget::default();
    let environment = json!({
        "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
        "host": command("uname", &["-n"]), "kernel": command("uname", &["-a"]),
        "cpu": std::fs::read_to_string("/proc/cpuinfo").ok(),
        "os_release": std::fs::read_to_string("/etc/os-release").ok(),
        "rustc": command("rustc", &["--version", "--verbose"]),
        "git_head": command("git", &["rev-parse", "HEAD"]),
        "wrapper": std::env::var("ONEIRON_SCREEN_ENV_JSON").ok()
            .map(|s| serde_json::from_str::<Value>(&s)).transpose()?,
    });
    let backends = vec![
        load("tsc-rs", || Ok(Box::new(TscRsWasm::load(budget)?)))?,
        load("microsoft", || {
            Ok(Box::new(MicrosoftTsc::new(&args.microsoft)?))
        })?,
        load("tsrs", || Ok(Box::new(TsrsWasm::load(budget)?)))?,
    ];
    let before = machine_state();
    let mut samples = Vec::new();
    let mut rotation = 0;
    for program in &programs {
        println!("checking {} ({})", program.entry.id, program.group);
        for _ in 0..args.warmup {
            for offset in 0..3 {
                drop(measure(program, &backends[(rotation + offset) % 3], 0));
            }
            rotation = (rotation + 1) % 3;
        }
        for repetition in 0..args.rounds {
            for offset in 0..3 {
                samples.push(measure(
                    program,
                    &backends[(rotation + offset) % 3],
                    repetition,
                ));
            }
            rotation = (rotation + 1) % 3;
        }
    }
    let after = machine_state();
    let comparisons = agreements(&samples, &programs, args.rounds);
    let declarations: Vec<_> = DECLARATIONS
        .iter()
        .map(|d| {
            json!({
                "name": d.name, "bytes": d.text.len(), "sha256": sha(d.text.as_bytes()),
            })
        })
        .collect();
    let pins: Vec<_> = backends
        .iter()
        .map(|b| json!({"backend": b.id, "load_ms": b.load_ms}))
        .collect();
    let payload = json!({
        "schema_version": 1, "engine_decision": "pending", "environment": environment,
        "measurement_start": before, "measurement_end": after,
        "protocol": {"rounds": args.rounds, "warmup": args.warmup, "warmups_recorded": false,
            "concurrency": 1, "backend_order": ["tsc-rs", "microsoft", "tsrs"],
            "rotation": "left by one per repetition, continuing across warmups and programs",
            "percentiles": "nearest rank over successful reports only",
            "agreement": "same-repetition sorted diagnostic multiset vs Microsoft; no deduplication",
            "code_location_fields": ["file", "line", "column", "code"], "profile": "release"},
        "wasm_budget": {"wall_ms": budget.wall_time.as_millis(), "memory_bytes": budget.memory_bytes,
            "output_bytes": budget.output_bytes, "concurrent_slots": budget.concurrent},
        "native_budget": {"wall_ms": budget.wall_time.as_millis(), "output_bytes": budget.output_bytes,
            "note": "compiled-in defaults, not a process RSS limit"},
        "contract_source_sha256": sha(include_bytes!("../src/lib.rs")),
        "catalog_revision": format!("sha256:{}", sha(DECLARATIONS[1].text.as_bytes())),
        "catalog_revision_source": include_str!("../../oneiron/src/verbs/generated/catalog_fragment_revision.rs"),
        "declarations": declarations, "backends": pins,
        "artifacts": {
            "tsc-rs": serde_json::from_str::<Value>(include_str!("../../../components/tsc-rs/artifacts/manifest.json"))?,
            "tsrs": serde_json::from_str::<Value>(include_str!("../vendor/tsrs/manifest.json"))?,
            "microsoft": {"version": MICROSOFT_TS_VERSION,
                "executable_sha256": sha(&std::fs::read(&args.microsoft)?)}},
        "programs": programs, "samples": samples, "comparisons": comparisons,
    });
    let mut raw = serde_json::to_vec_pretty(&payload)?;
    raw.push(b'\n');
    std::fs::write(args.output.join("screen.json"), &raw)?;
    std::fs::write(
        args.output.join("diffs.json"),
        serde_json::to_vec_pretty(&comparisons)?,
    )?;
    let md = markdown(
        &programs,
        &backends,
        &samples,
        &comparisons,
        &args,
        &sha(&raw),
    );
    std::fs::write(args.output.join("screen.md"), md)?;
    println!("screen complete: {}", args.output.display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("backend screen: {error}");
        std::process::exit(1);
    }
}
