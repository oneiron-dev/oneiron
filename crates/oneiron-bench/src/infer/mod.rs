//! `infer` subcommand — the built-in inference bench (FIX 6559): the proof
//! harness for each inference trick an arm applies to what ships.
//!
//! * `oneiron-bench infer run --arm-id ID --transport direct|own-server
//!   --models-toml FILE --model PROVIDER:MODEL --cases /ABS/cases.jsonl
//!   --out /ABS/rows.jsonl [flags]` — one arm over runtime-only case packets:
//!   TTFT, native and end-to-end rates, sampled VRAM and a deterministic
//!   quality check per (case, rep), one appended row each, resumable.
//! * `oneiron-bench infer summarize --out ROWS.jsonl [--out ...]` — the
//!   per-arm table of finished rows.
//!
//! Calls go through the production seams (`ModelRuntime` and `RunBackend`,
//! or `RemoteLlmClient` and `OwnServerBackend` to a loopback server), never a
//! bench-side HTTP client. The engine is either already up or started here
//! (`--engine-cmd`), in which case its load time and idle and loaded VRAM are
//! recorded too. Cases and rows live outside the source tree; the bench
//! holds no case text and writes no reply text into a row.

mod args;
mod arms;
mod cases;
mod config;
mod engine;
mod measure;
mod request;
mod rows;
mod scoring;
mod summary;
mod vram;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oneiron::{BudgetExhaustionPolicy, BudgetGuard, LlmRequest};
use serde_json::json;

use args::{RunArgs, Transport};
use arms::Arm;
use cases::{Case, CaseFile};
use config::Models;
use measure::{Failed, Measured, Timing};
use rows::RunIdentity;

/// How long a VRAM reading taken at a phase boundary waits for a new sample.
const SAMPLE_WAIT: Duration = Duration::from_secs(2);

/// One row's identity within a result file.
type Key = (String, String, u32);

pub(crate) fn run(args: &[String]) -> ExitCode {
    let outcome = match args {
        [sub, rest @ ..] if sub == "run" => args::parse_run(rest).and_then(execute),
        [sub, rest @ ..] if sub == "summarize" => {
            args::parse_summarize(rest).and_then(|outs| summarize(&outs))
        }
        [flag] if flag == "--help" || flag == "-h" => {
            println!("{}", args::USAGE);
            return ExitCode::SUCCESS;
        }
        _ => Err(args::USAGE.to_owned()),
    };
    match outcome {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("infer: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `path` with `suffix` added to its file name: `rows.jsonl` →
/// `rows.jsonl.engine.log`.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn key(arm_id: &str, case: &Case, rep: u32) -> Key {
    (arm_id.to_owned(), case.id.clone(), rep)
}

fn select<'a>(cases: &'a [Case], only: &[String]) -> Result<Vec<&'a Case>, String> {
    if let Some(missing) = only
        .iter()
        .find(|id| !cases.iter().any(|case| case.id == **id))
    {
        return Err(format!("--only {missing}: the cases file has no such id"));
    }
    Ok(cases
        .iter()
        .filter(|case| only.is_empty() || only.contains(&case.id))
        .collect())
}

/// BLAKE3 over the run config's RFC 8785 JSON: everything that changes what
/// a row measures, but not the arm's label or the case set.
fn config_digest(args: &RunArgs, models: &Models) -> Result<String, String> {
    let engine = args.engine.as_ref();
    let config = json!({
        "transport": args.transport.as_str(),
        "model": args.model,
        "served_model": models.engine_id.as_str(),
        "sampling": args.sampling.as_str(),
        "schema": args.schema,
        "cache_bust": args.cache_bust,
        "max_tokens_source": "case",
        "thinking_source": "case",
        "engine_cmd": engine.map(|engine| engine.cmd.display().to_string()),
        "engine_env": engine.map(|engine| &engine.env),
        "models_toml_blake3": models.toml_digest,
        "role_added": models.role_added,
        "server": args.server.as_ref().map(|server| server.display().to_string()),
    });
    let bytes = serde_json_canonicalizer::to_vec(&config)
        .map_err(|e| format!("encode the run config: {e}"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn execute(args: RunArgs) -> Result<bool, String> {
    cases::refuse_in_tree("--out", &args.out)?;
    if let Some(dir) = &args.keep_outputs {
        cases::refuse_in_tree("--keep-outputs", dir)?;
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    let file = cases::load(&args.cases)?;
    let selected = select(&file.cases, &args.only)?;
    let models = config::load(&args.models_toml, &args.model)?;
    let config_digest = config_digest(&args, &models)?;
    let (existing, unreadable, cut) = rows::read(&args.out)?;
    if unreadable > 0 {
        eprintln!(
            "infer: {unreadable} line(s) of {} do not parse as rows; ignored",
            args.out.display()
        );
    }
    let mut done = rows::done(&existing, &config_digest);
    let pending: Vec<(&Case, u32)> = selected
        .iter()
        .flat_map(|case| (0..args.reps).map(move |rep| (*case, rep)))
        .filter(|(case, rep)| !done.contains(&key(&args.arm_id, case, *rep)))
        .collect();
    let total = selected.len() * args.reps as usize;
    println!(
        "infer: skipped {} of {total} rows already ok under config {}",
        total - pending.len(),
        config_digest.get(..12).unwrap_or(&config_digest)
    );
    if !pending.is_empty() {
        let run = Run {
            args: &args,
            models: &models,
            file: &file,
            config_digest: &config_digest,
        };
        run.session(&pending, cut, &mut done)?;
    }
    let (rows, _, _) = rows::read(&args.out)?;
    let arms = summary::summarize(&rows);
    println!("{}", summary::markdown(&arms));
    summary::write_json(&args.out, &arms)?;
    Ok(selected
        .iter()
        .all(|case| (0..args.reps).all(|rep| done.contains(&key(&args.arm_id, case, rep)))))
}

fn summarize(outs: &[PathBuf]) -> Result<bool, String> {
    let mut all = Vec::new();
    for out in outs {
        let (rows, unreadable, _) = rows::read(out)?;
        if unreadable > 0 {
            eprintln!(
                "infer: {unreadable} line(s) of {} do not parse as rows; ignored",
                out.display()
            );
        }
        summary::write_json(out, &summary::summarize(&rows))?;
        all.extend(rows);
    }
    println!("{}", summary::markdown(&summary::summarize(&all)));
    Ok(true)
}

/// What a measuring session reads.
struct Run<'a> {
    args: &'a RunArgs,
    models: &'a Models,
    file: &'a CaseFile,
    config_digest: &'a str,
}

/// The arm and meters every call of a session uses.
struct Caller<'a> {
    rt: &'a tokio::runtime::Runtime,
    arm: &'a Arm,
    budget: &'a BudgetGuard,
}

impl Caller<'_> {
    /// One call under its own lease from the caller's meter, settled on its
    /// usage or released on failure.
    fn call(&self, request: LlmRequest) -> Result<Measured, Failed> {
        let lease = self
            .budget
            .admit_for_request(&request)
            .map_err(|e| Failed {
                error: format!("the caller's meter refused the call: {e}"),
                wall_ms: 0.0,
            })?
            .lease;
        let outcome = self
            .rt
            .block_on(measure::drive(self.arm.backend.as_ref(), request, &lease));
        let refused = match &outcome {
            Ok(measured) => self.budget.settle_per_call(&lease, &measured.usage).err(),
            Err(_) => self.budget.abort(&lease).err(),
        };
        if let Some(e) = refused {
            eprintln!("infer: settling a call's lease failed: {e}");
        }
        outcome
    }
}

/// Writes a reply's text to `<dir>/<case>-<rep>.txt`, the case id made safe
/// for a file name.
fn keep_output(dir: Option<&Path>, case: &Case, rep: u32, text: &str) {
    let Some(dir) = dir else {
        return;
    };
    let name: String = case
        .id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = dir.join(format!("{name}-{rep}.txt"));
    if let Err(e) = std::fs::write(&path, text) {
        eprintln!("infer: keep output {}: {e}", path.display());
    }
}

fn shown(value: Option<f64>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| format!("{value:.1}"))
}

impl Run<'_> {
    fn identity(
        &self,
        arm: &Arm,
        engine: Option<&engine::Engine>,
        vram: &vram::Vram,
        vram_idle_mib: Option<u64>,
        vram_loaded_mib: Option<u64>,
    ) -> RunIdentity {
        let args = self.args;
        let gpu = vram.gpu();
        RunIdentity {
            arm_id: args.arm_id.clone(),
            transport: args.transport.as_str(),
            model: args.model.clone(),
            served_model: arm.model.to_string(),
            served_revision: self.models.revision.clone(),
            role_added: self.models.role_added.clone(),
            cases_digest: self.file.digest.clone(),
            config_digest: self.config_digest.to_owned(),
            git_sha: crate::perf::git_sha::build_git_sha().sha,
            checkout_sha: crate::perf::git_sha::source_checkout_git_sha().sha,
            hostname: rows::hostname(),
            sampling: args.sampling.as_str(),
            schema_flag: args.schema,
            cache_bust: args.cache_bust,
            engine_cmd: args
                .engine
                .as_ref()
                .map(|engine| engine.cmd.display().to_string()),
            engine_env_keys: args
                .engine
                .iter()
                .flat_map(|engine| engine.env.iter().map(|(name, _)| name.clone()))
                .collect(),
            engine_pid: engine.map(|engine| engine.pid),
            engine_load_ms: engine.map(|engine| engine.load_ms),
            gpu_index: args.gpu_index,
            gpu_name: gpu.name,
            gpu_uuid: gpu.uuid,
            vram_total_mib: gpu.total_mib,
            vram_poll_ms: args.vram_poll_ms,
            vram_idle_mib,
            vram_loaded_mib,
        }
    }

    /// Starts what the arm needs, warms it, measures every pending (case,
    /// rep) into a row, and stops what it started.
    fn session(
        &self,
        pending: &[(&Case, u32)],
        cut: bool,
        done: &mut BTreeSet<Key>,
    ) -> Result<(), String> {
        let args = self.args;
        let reaper = engine::Reaper::default();
        reaper.arm();
        let vram = vram::Vram::start(args.gpu_index, args.vram_poll_ms);
        let (engine, vram_idle_mib) = match &args.engine {
            Some(engine_args) => {
                let idle = vram.fresh(SAMPLE_WAIT);
                let log = sibling(&args.out, ".engine.log");
                (
                    Some(engine::Engine::start(engine_args, &log, &reaper)?),
                    idle,
                )
            }
            None => (None, None),
        };
        let vram_loaded_mib = vram.fresh(SAMPLE_WAIT);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("tokio runtime: {e}"))?;
        let arm = match (args.transport, &args.server) {
            (Transport::Direct, _) => arms::direct(self.models, &rt)?,
            (Transport::OwnServer, Some(server)) => {
                let work = sibling(&args.out, &format!(".server-{}", unix_ms()));
                arms::own_server(self.models, server, &work, &rt, &reaper)?
            }
            (Transport::OwnServer, None) => return Err("own-server needs --server".to_owned()),
        };
        let identity = self.identity(&arm, engine.as_ref(), &vram, vram_idle_mib, vram_loaded_mib);
        let shape = request::Shape {
            model: arm.model.clone(),
            locality: arm.locality,
            sampling: args.sampling,
            schema: args.schema,
            cache_bust: args.cache_bust,
            reasoning: arm.reasoning,
        };
        let budget = BudgetGuard::new(
            "infer-bench-caller",
            arms::RUN_UNITS,
            BudgetExhaustionPolicy::Suspend,
        );
        let caller = Caller {
            rt: &rt,
            arm: &arm,
            budget: &budget,
        };
        for n in 0..args.warmup {
            match caller.call(shape.warmup()) {
                Ok(measured) => println!(
                    "warmup {n}: {} ms (not recorded)",
                    shown(measured.timing.wall_ms)
                ),
                Err(failed) => eprintln!(
                    "warmup {n} failed after {:.0} ms: {}",
                    failed.wall_ms, failed.error
                ),
            }
        }
        let mut writer = rows::Writer::open(&args.out, cut)?;
        for (case, rep) in pending {
            let (request, sent) = shape.case(case);
            let started_at = rows::now_rfc3339();
            vram.open_window();
            let outcome = caller.call(request);
            let vram_case_peak_mib = vram.close_window();
            let (status, error, timing, quality) = match outcome {
                Ok(measured) => {
                    keep_output(args.keep_outputs.as_deref(), case, *rep, &measured.text);
                    let quality = scoring::score(case, &measured.text);
                    ("ok", None, measured.timing, Some(quality))
                }
                Err(failed) => (
                    "error",
                    Some(failed.error),
                    Timing {
                        wall_ms: Some(failed.wall_ms),
                        ..Timing::default()
                    },
                    None,
                ),
            };
            let row = rows::Row {
                schema: rows::SCHEMA,
                run: &identity,
                case_id: &case.id,
                case_kind: &case.kind,
                scorer: case.scorer,
                case_digest: &case.digest,
                case_prompt_tokens: case.prompt_tokens,
                case_approx_input_tokens: case.approx_input_tokens,
                rep: *rep,
                started_at,
                status,
                error,
                sent: &sent,
                timing,
                vram_case_peak_mib,
                quality,
            };
            writer.append(&row)?;
            match &row.error {
                None => println!(
                    "{} rep {rep}: ok, ttft_any {} ms, ttft_text {} ms, out {} tok, decode_e2e {} tok/s, score {}",
                    case.id,
                    shown(row.timing.ttft_any_ms),
                    shown(row.timing.ttft_text_ms),
                    row.timing.output_tokens.unwrap_or(0),
                    shown(row.timing.decode_tps_e2e),
                    shown(row.quality.as_ref().map(|quality| quality.score)),
                ),
                Some(error) => println!("{} rep {rep}: error: {error}", case.id),
            }
            if row.error.is_none() {
                done.insert(key(&args.arm_id, case, *rep));
            }
        }
        if let Some(status) = arm.finish(&reaper) {
            println!("loopback server stopped: {status}");
        }
        if let Some(engine) = engine {
            let pid = engine.pid;
            println!("engine pid {pid} stopped: {}", engine.stop());
        }
        if let Some(peak) = vram.run_peak() {
            println!("VRAM session peak (sampled, includes load): {peak} MiB");
        }
        Ok(())
    }
}
