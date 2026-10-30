//! `load dream` — one Dreamer cycle end to end on the shipped server binary
//! (L07 DREAM-BENCH).
//!
//! It checks the model behind an OpenAI-compatible gateway, inits a vault
//! whose `[models]` routes every role a consolidation pass calls to that
//! model, serves it, opens one sitting, witnesses a recorded corpus into it
//! (and with `--notes` upserts its saved notes as claims), then ends the
//! sitting: the end enqueues one Meso round, a partition attempt per
//! conversation (`session_lifecycle.rs`). An agent recalls on a fixed rhythm
//! before, during and 30 s after the round. The report says whether the
//! round's write landed, whether a recall built from a landed claim's own
//! words finds it, whether the round ended inside the stated bound, how many
//! Loro SnapshotAt exports each pass made, and the ms of each stage (from the
//! server's `dreamer partition stages` and `dreamer wake pass` lines) and of
//! each recall.
//!
//! The model key is read from a file and reaches the server's environment
//! only. The report holds ids, counts, ms and the recall query strings (the
//! corpus is synthetic test data), never the key.

mod cycle;
mod proof;
mod report;
mod server_log;
mod setup;
mod turns;

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use super::client::Agent;
use super::phases::loadavg;
use super::server::{Credential, Embedding, Running, Vault, free_port};
use super::stats::{Sample, Summary};
use cycle::{Tick, Wait, Waited, ms_between};
use report::{Measured, report, summary};
use server_log::{Scan, Tail};
use turns::{Selection, Turn};

const USAGE: &str = "usage: oneiron-bench load dream --server <oneiron-server> --work <dir>\n\
  --corpus <turns.jsonl> --out <file.json> --model-base-url <url> --model <slug>\n\
  --model-key-file <path> [--worlds w1,w2] [--days 1-6] [--notes] [--recall-every-ms 1000]\n\
  [--cycle-timeout-s 1200] [--model-context-tokens N] [--label TEXT] [--log-extra DIRECTIVES]\n\
  (--model-base-url ends where /chat/completions follows, usually in /v1)";

/// The server's log level: the Dreamer's stage and pass lines are info.
const RUST_LOG: &str = "warn,oneiron::dreamer::stages=info";
const LOG_NAME: &str = "serve.log";
/// Recalls before the cycle, and the most queries the loop rotates over.
const BASELINE: usize = 20;
const QUERY_CAP: usize = 40;
/// How long the recall loop runs past the cycle's end.
const AFTER: Duration = Duration::from_secs(30);
/// Between the sitting's open and the first write: the driver applies the
/// hint off the request.
const OPEN_SETTLE: Duration = Duration::from_secs(2);
/// An activity hint this often while seeding keeps the sitting open.
const ACTIVITY_EVERY: Duration = Duration::from_secs(60);

/// The parsed `load dream` flags.
struct Plan {
    server: PathBuf,
    work: PathBuf,
    corpus: PathBuf,
    out: PathBuf,
    model_base_url: String,
    model: String,
    model_key_file: PathBuf,
    model_context_tokens: Option<u64>,
    selection: Selection,
    notes: bool,
    recall_every: Duration,
    cycle_timeout: Duration,
    label: Option<String>,
    /// More `RUST_LOG` directives for the server, after the stage lines'.
    log_extra: Option<String>,
}

fn parse(args: &[String]) -> Result<Plan, String> {
    let mut plan = Plan {
        server: PathBuf::new(),
        work: PathBuf::new(),
        corpus: PathBuf::new(),
        out: PathBuf::new(),
        model_base_url: String::new(),
        model: String::new(),
        model_key_file: PathBuf::new(),
        model_context_tokens: None,
        selection: Selection::default(),
        notes: false,
        recall_every: Duration::from_millis(1000),
        cycle_timeout: Duration::from_secs(1200),
        label: None,
        log_extra: None,
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        if flag == "--notes" {
            plan.notes = true;
            continue;
        }
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let num = |v: &str| {
            v.parse::<u64>()
                .map_err(|_| format!("{flag}: `{v}` is not a number"))
        };
        match flag.as_str() {
            "--server" => plan.server = PathBuf::from(value),
            "--work" => plan.work = PathBuf::from(value),
            "--corpus" => plan.corpus = PathBuf::from(value),
            "--out" => plan.out = PathBuf::from(value),
            "--model-base-url" => plan.model_base_url = value.clone(),
            "--model" => plan.model = value.clone(),
            "--model-key-file" => plan.model_key_file = PathBuf::from(value),
            "--model-context-tokens" => plan.model_context_tokens = Some(num(value)?),
            "--worlds" => {
                plan.selection.worlds =
                    Some(value.split(',').map(|w| w.trim().to_owned()).collect());
            }
            "--days" => plan.selection.days = Some(turns::days(value)?),
            "--recall-every-ms" => plan.recall_every = Duration::from_millis(num(value)?.max(1)),
            "--cycle-timeout-s" => plan.cycle_timeout = Duration::from_secs(num(value)?),
            "--label" => plan.label = Some(value.clone()),
            "--log-extra" => plan.log_extra = Some(value.clone()),
            _ => return Err(format!("unknown flag {flag}\n{USAGE}")),
        }
    }
    let required = [
        plan.server.as_os_str().is_empty(),
        plan.work.as_os_str().is_empty(),
        plan.corpus.as_os_str().is_empty(),
        plan.out.as_os_str().is_empty(),
        plan.model_base_url.is_empty(),
        plan.model.is_empty(),
        plan.model_key_file.as_os_str().is_empty(),
    ];
    if required.contains(&true) {
        return Err(USAGE.into());
    }
    Ok(plan)
}

pub(super) fn run(args: &[String]) -> Result<(), String> {
    execute(&parse(args)?)
}

fn say(text: &str) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "[load dream {}] {text}",
        loadavg()
    );
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn execute(plan: &Plan) -> Result<(), String> {
    let origin = Instant::now();
    let started_unix = unix_now();
    let turns = turns::read(&plan.corpus, &plan.selection)?;
    let queries = turns::queries(&turns, QUERY_CAP);
    let key = setup::read_key(&plan.model_key_file)?;
    say(&format!("model preflight: {}", plan.model));
    let preflight = setup::preflight(&plan.model_base_url, &plan.model, &key)?;
    let dir = plan.work.join("dream");
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| format!("clear {}: {e}", dir.display()))?;
    }
    let vault = Vault::init(&plan.server, &dir, &Embedding::None, &[])?;
    setup::write_models(
        &vault,
        &plan.model_base_url,
        &plan.model,
        plan.model_context_tokens,
    )?;
    let grant = setup::grant(&plan.server, &vault)?;
    let credentials = [
        vault.mint_agent(&plan.server, "dream-seed")?,
        vault.mint_agent(&plan.server, "dream-recall")?,
    ];
    // The key goes to the child's environment and nowhere else.
    let env = vec![
        (setup::MODEL_KEY_ENV.to_owned(), key),
        (
            "RUST_LOG".to_owned(),
            plan.log_extra.as_ref().map_or_else(
                || RUST_LOG.to_owned(),
                |extra| format!("{RUST_LOG},{extra}"),
            ),
        ),
    ];
    let server = Running::start_on(&plan.server, &vault, &env, LOG_NAME, "warn", free_port()?)?;
    drop(env);
    say(&format!("server ready in {:.0} ms", server.ready_ms));
    let measured = measure(&Run {
        plan,
        vault: &vault,
        server: &server,
        credentials: &credentials,
        turns: &turns,
        queries: &queries,
        origin,
    });
    let exit = server.stop();
    let mut report = measured?;
    report["label"] = json!(plan.label);
    report["started_unix"] = json!(started_unix);
    report["server"] = json!({
        "bin": plan.server.display().to_string(),
        "version": setup::version(&plan.server),
        "exit": exit,
    });
    report["model"] = json!({
        "base_url": plan.model_base_url, "slug": plan.model,
        "reply_model": preflight.reply_model, "preflight_ms": preflight.ms,
        "context_tokens": plan.model_context_tokens,
    });
    report["grant"] = grant;
    let text = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    std::fs::write(&plan.out, text).map_err(|e| format!("{}: {e}", plan.out.display()))?;
    let _ = writeln!(std::io::stdout().lock(), "{}", summary(&report));
    say(&format!("serve exit: {exit}; wrote {}", plan.out.display()));
    Ok(())
}

/// What one run measures with.
struct Run<'a> {
    plan: &'a Plan,
    vault: &'a Vault,
    server: &'a Running,
    /// The seeding agent (it opens, fills and ends the sitting, and proves
    /// the row), then the recall loop's agent.
    credentials: &'a [Credential; 2],
    turns: &'a [Turn],
    queries: &'a [String],
    origin: Instant,
}

/// What seeding wrote and how long it took.
struct Seeded {
    seconds: f64,
    witness: Vec<Sample>,
    claims: Vec<Sample>,
    activity_hints: usize,
    hint_errors: Vec<String>,
}

fn seed(run: &Run<'_>, agent: &Agent, http: &reqwest::blocking::Client) -> Seeded {
    let started = Instant::now();
    let mut seeded = Seeded {
        seconds: 0.0,
        witness: Vec::new(),
        claims: Vec::new(),
        activity_hints: 0,
        hint_errors: Vec::new(),
    };
    let mut last_hint = Instant::now();
    for (index, turn) in run.turns.iter().enumerate() {
        for speaker in &turn.runs {
            let (ms, answer) = agent.post("vault.witness", &turns::witness_body(turn, speaker));
            seeded.witness.push(Sample {
                ms,
                error: answer.err(),
                partial: false,
                items: speaker.texts.len(),
            });
        }
        if run.plan.notes {
            for (key, value) in turn.notes.iter().filter_map(turns::Note::pair) {
                let (ms, answer) =
                    agent.post("vault.claims.upsert", &turns::note_body(turn, key, value));
                seeded.claims.push(Sample {
                    ms,
                    error: answer.err(),
                    partial: false,
                    items: 1,
                });
            }
        }
        if last_hint.elapsed() >= ACTIVITY_EVERY {
            last_hint = Instant::now();
            seeded.activity_hints += 1;
            if let Err(error) = cycle::hint(agent, http, &run.server.base, "activity") {
                seeded.hint_errors.push(error);
            }
        }
        if (index + 1) % 50 == 0 {
            say(&format!(
                "seeded {} of {} turns",
                index + 1,
                run.turns.len()
            ));
        }
    }
    seeded.seconds = started.elapsed().as_secs_f64();
    seeded
}

/// The cycle and what ran beside it.
struct Cycle {
    t0_ms: f64,
    waited: Waited,
    ticks: Vec<Tick>,
}

/// Steps 6 to 9a: the recall loop on its own thread, the sitting's end
/// (t0), the wait, and the loop's last `AFTER`.
fn cycle_with_recalls(
    run: &Run<'_>,
    seeder: &Agent,
    reader: &Agent,
    http: &reqwest::blocking::Client,
    tail: &mut Tail,
    scan: &mut Scan,
) -> Cycle {
    let base = run.server.base.as_str();
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let looper = scope.spawn(|| {
            cycle::recall_loop(
                reader,
                run.queries,
                run.plan.recall_every,
                run.origin,
                &stop,
            )
        });
        scan.read(tail, run.origin);
        let before = cycle::status(seeder, http, base).unwrap_or_default();
        let t0 = Instant::now();
        let t0_ms = ms_between(run.origin, t0);
        say("ending the sitting (t0)");
        let waited = match cycle::hint(seeder, http, base, "end") {
            Ok(()) => Wait {
                agent: seeder,
                http,
                base,
                origin: run.origin,
                bound: run.plan.cycle_timeout,
                conversations: turns::Counts::of(run.turns).conversations,
            }
            .run(tail, scan, t0, before),
            Err(error) => Waited::refused(error, t0_ms, before),
        };
        say(&format!(
            "cycle: {} after {:.0} ms",
            waited.reason,
            waited.end_ms - t0_ms
        ));
        let stop_at = run.origin + Duration::from_secs_f64(waited.end_ms / 1000.0) + AFTER;
        while Instant::now() < stop_at {
            std::thread::sleep(Duration::from_millis(500));
            scan.read(tail, run.origin);
        }
        stop.store(true, Ordering::Relaxed);
        let ticks = looper.join().unwrap_or_default();
        Cycle {
            t0_ms,
            waited,
            ticks,
        }
    })
}

fn measure(run: &Run<'_>) -> Result<Value, String> {
    let http = Agent::http()?;
    let base = run.server.base.as_str();
    let skew = Agent::new(&http, base, &run.credentials[0], 0)?.clock_skew()?;
    let seeder = Agent::new(&http, base, &run.credentials[0], skew)?;
    let reader = Agent::new(&http, base, &run.credentials[1], skew)?;
    let ready = cycle::dreamer_ready(&seeder, &http, base)?;
    say(&format!("dreamer {}; opening the sitting", ready.state));
    cycle::hint(&seeder, &http, base, "open")?;
    std::thread::sleep(OPEN_SETTLE);
    let seeded = seed(run, &seeder, &http);
    say(&format!(
        "seeded {} witness and {} claim writes in {:.1} s",
        seeded.witness.len(),
        seeded.claims.len(),
        seeded.seconds
    ));
    let listed_before = proof::listed(&seeder);
    let baseline_started = Instant::now();
    let baseline = (0..BASELINE)
        .map(|k| {
            let (ms, answer) = cycle::recall(&reader, &run.queries[k % run.queries.len()]);
            sample(ms, answer)
        })
        .collect::<Vec<_>>();
    let baseline_seconds = baseline_started.elapsed().as_secs_f64();
    let mut tail = Tail::new(run.vault.dir.join(LOG_NAME));
    let mut scan = Scan::default();
    let ran = cycle_with_recalls(run, &seeder, &reader, &http, &mut tail, &mut scan);
    scan.read(&mut tail, run.origin);
    let mut landed = proof::landed_from_stages(&scan, ran.t0_ms);
    let mut source = "stage_lines";
    if landed.is_empty() {
        source = "none";
        if let (Ok((before, _)), Ok((after, capped))) = (&listed_before, proof::listed(&seeder)) {
            landed = after.difference(before).cloned().collect();
            source = if capped {
                "claims_list_diff_capped"
            } else {
                "claims_list_diff"
            };
        }
    }
    say(&format!("proof: {} landed claims ({source})", landed.len()));
    let tried = proof::prove(&seeder, &landed);
    let status_after = cycle::status(&seeder, &http, base).ok();
    Ok(report(&Measured {
        run,
        seeded: &seeded,
        baseline: Summary::of(&baseline, baseline_seconds),
        cycle: &ran,
        scan: &scan,
        landed: &landed,
        source,
        tried: &tried,
        status_after,
    }))
}

fn sample(ms: f64, answer: Result<Value, String>) -> Sample {
    let (error, items) = match answer {
        Ok(pack) => (None, pack["items"].as_array().map_or(0, Vec::len)),
        Err(error) => (Some(error), 0),
    };
    Sample {
        ms,
        error,
        partial: false,
        items,
    }
}
