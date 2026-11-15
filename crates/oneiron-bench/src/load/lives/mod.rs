//! `load lives` — the synthetic-lives screen (ARCH-0042 #lives-bench; census
//! row L9-36): every system ingests the same synthetic lives and answers the
//! same questions, and each row reports accuracy and latency together.
//!
//! The rulings (Engine, Sun 15 Nov 01:00): one store per system holds all the
//! screen's lives, and the seeded pick grows to at least 1,000 turns so the
//! latency clears canon's corpus floor (L9-36-STORE = B); the accuracy column
//! here is context accuracy, with no model (L9-36-ACCURACY = C, its first
//! column). This change measures the Oneiron store; other systems plug in
//! through the adapter seam that follows it (L9-36-COMPETITORS = A).
//!
//! The lives stay outside the repository: pass their files or directories.

mod corpus;
mod oneiron;
mod report;
mod score;

use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::json;

use super::phases::loadavg;
use super::server::{Embedding, loopback_url};
use corpus::Pick;
use report::{CorpusInfo, FileDigest, LifeInfo, Report};

const USAGE: &str = "usage: oneiron-bench load lives (--server <oneiron-server> --embedder <embedder> | --in-process)\n\
  --lives <file|dir>... --work <dir> --out <file.json> [--label TEXT]\n\
  [--life ID]... | [--sample N] [--seed 7] [--min-turns 1000]\n\
  [--grades call,light,medium] [--limit 10] [--settle-max-seconds 300]\n\
  [--drain-settle-seconds 35] [--embedder-api-key-env NAME] [--server-env KEY=VALUE]...\n\
  <embedder>: none | local | endpoint=<url>,<model-key>,<model-id@revision>,<dimensions>";

const LINUX_ONLY: &str = "load lives --server reads the server's /proc files: run it on Linux, or check the harness with --in-process";

/// Where the Oneiron store runs.
pub(super) enum Mode {
    /// The shipped binary, spawned on loopback: the measuring mode.
    Spawned { bin: PathBuf, embedding: Embedding },
    /// The engine linked into this bench: for checking the harness.
    InProcess,
}

/// The parsed `load lives` flags.
pub(super) struct Plan {
    pub(super) mode: Mode,
    lives: Vec<PathBuf>,
    pub(super) work: PathBuf,
    out: PathBuf,
    label: Option<String>,
    pick: Pick,
    pub(super) grades: Vec<String>,
    pub(super) limit: usize,
    pub(super) settle_max: Duration,
    pub(super) drain_settle: Duration,
    pub(super) server_env: Vec<(String, String)>,
}

/// `--embedder`'s value, with `--embedder-api-key-env`'s NAME.
fn embedding(value: &str, api_key_env: Option<String>) -> Result<Embedding, String> {
    match value {
        "none" => Ok(Embedding::None),
        "local" => Ok(Embedding::Local),
        _ => {
            let spec = value.strip_prefix("endpoint=").ok_or(
                "--embedder is none, local or endpoint=<url>,<model-key>,<model-id@revision>,<dimensions>",
            )?;
            let parts = spec.split(',').collect::<Vec<_>>();
            let [url, model_key, model_id, dimensions] = parts.as_slice() else {
                return Err(
                    "--embedder endpoint= takes <url>,<model-key>,<model-id@revision>,<dimensions>"
                        .into(),
                );
            };
            if !model_id.contains('@') {
                return Err("--embedder endpoint=: the model id is model_id@revision".into());
            }
            // `oneiron-server init` takes a network endpoint only with an
            // on-device fallback serving the same model and an egress grant;
            // the screen sets neither, so a GPU host comes in over a tunnel.
            if !reqwest::Url::parse(url).is_ok_and(|url| loopback_url(&url)) {
                return Err(format!(
                    "--embedder endpoint=: `{url}` is not a loopback url; reach a GPU host \
                     through a tunnel (ssh -L), because a network endpoint needs an on-device \
                     fallback model and an egress grant that the screen does not set"
                ));
            }
            Ok(Embedding::Endpoint {
                url: (*url).to_owned(),
                model_key: (*model_key).to_owned(),
                model_id: (*model_id).to_owned(),
                dimensions: dimensions
                    .parse()
                    .map_err(|_| format!("--embedder endpoint=: `{dimensions}` is not a number"))?,
                api_key_env,
            })
        }
    }
}

fn parse(args: &[String]) -> Result<Plan, String> {
    let mut server = None;
    let mut in_process = false;
    let mut embedder = None;
    let mut api_key_env = None;
    let mut lives = Vec::new();
    let mut work = PathBuf::new();
    let mut out = PathBuf::new();
    let mut label = None;
    let mut named = Vec::new();
    let mut sample = None;
    let mut seed = 7;
    let mut min_turns = 1_000;
    let mut grades = ["call", "light", "medium"].map(str::to_owned).to_vec();
    let mut limit = 10;
    let mut settle_max = Duration::from_secs(300);
    let mut drain_settle = Duration::from_secs(35);
    let mut server_env = Vec::new();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        if flag == "--in-process" {
            in_process = true;
            continue;
        }
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let num = |v: &str| {
            v.parse::<usize>()
                .map_err(|_| format!("{flag}: `{v}` is not a number"))
        };
        match flag.as_str() {
            "--server" => server = Some(PathBuf::from(value)),
            "--embedder" => embedder = Some(value.clone()),
            "--embedder-api-key-env" => api_key_env = Some(value.clone()),
            "--lives" => lives.push(PathBuf::from(value)),
            "--work" => work = PathBuf::from(value),
            "--out" => out = PathBuf::from(value),
            "--label" => label = Some(value.clone()),
            "--life" => named.push(value.clone()),
            "--sample" => sample = Some(num(value)?.max(1)),
            "--seed" => seed = num(value)? as u64,
            "--min-turns" => min_turns = num(value)?,
            "--grades" => grades = value.split(',').map(|g| g.trim().to_owned()).collect(),
            "--limit" => limit = num(value)?.max(1),
            "--settle-max-seconds" => settle_max = Duration::from_secs(num(value)? as u64),
            "--drain-settle-seconds" => drain_settle = Duration::from_secs(num(value)? as u64),
            "--server-env" => {
                let (k, v) = value.split_once('=').ok_or("--server-env is KEY=VALUE")?;
                server_env.push((k.to_owned(), v.to_owned()));
            }
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    if lives.is_empty() || work.as_os_str().is_empty() || out.as_os_str().is_empty() {
        return Err(USAGE.into());
    }
    let mode = match (server, in_process) {
        (Some(bin), false) => {
            // A run always names what it measured (ARCH-0042 #lives-bench:
            // every system uses the same model).
            let value = embedder.ok_or("--server needs --embedder none|local|endpoint=...")?;
            Mode::Spawned {
                bin,
                embedding: embedding(&value, api_key_env)?,
            }
        }
        (None, true) => {
            if embedder.as_deref().is_some_and(|e| e != "none") {
                return Err("--in-process takes --embedder none only".into());
            }
            Mode::InProcess
        }
        _ => return Err(format!("name one of --server or --in-process\n{USAGE}")),
    };
    let pick = match (named.is_empty(), sample) {
        (true, None) => Pick::All,
        (false, None) => Pick::Named(named),
        (true, Some(lives)) => Pick::Sample {
            lives,
            seed,
            min_turns,
        },
        (false, Some(_)) => return Err("--life and --sample do not go together".into()),
    };
    if grades.iter().any(String::is_empty) {
        return Err("--grades has an empty grade".into());
    }
    Ok(Plan {
        mode,
        lives,
        work,
        out,
        label,
        pick,
        grades,
        limit,
        settle_max,
        drain_settle,
        server_env,
    })
}

pub(super) fn say(text: &str) {
    let _ = writeln!(std::io::stderr().lock(), "[lives {}] {text}", loadavg());
}

fn plan_echo(plan: &Plan) -> serde_json::Value {
    let pick = match &plan.pick {
        Pick::All => json!({"all": true}),
        Pick::Named(keys) => json!({"lives": keys}),
        Pick::Sample {
            lives,
            seed,
            min_turns,
        } => json!({"sample": lives, "seed": seed, "min_turns": min_turns}),
    };
    let embedder = match &plan.mode {
        Mode::Spawned {
            embedding:
                Embedding::Endpoint {
                    url,
                    model_key,
                    model_id,
                    dimensions,
                    api_key_env,
                },
            ..
        } => json!({
            "endpoint": url, "model_key": model_key, "model_id": model_id,
            "dimensions": dimensions, "api_key_env": api_key_env,
        }),
        Mode::Spawned {
            embedding: Embedding::Local,
            ..
        } => json!("local"),
        _ => json!("none"),
    };
    json!({
        "lives": plan.lives.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        "pick": pick, "grades": plan.grades, "limit": plan.limit, "embedder": embedder,
        "settle_max_seconds": plan.settle_max.as_secs(),
        "drain_settle_seconds": plan.drain_settle.as_secs(),
        // Names only: values (often credentials) stay in the spawned server's environment.
        "server_env": plan.server_env.iter().map(|(k, _)| k).collect::<Vec<_>>(),
    })
}

fn write(plan: &Plan, report: &Report) -> Result<(), String> {
    let text = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
    std::fs::write(&plan.out, text).map_err(|e| format!("{}: {e}", plan.out.display()))
}

pub(super) fn run(args: &[String]) -> Result<(), String> {
    let plan = parse(args)?;
    if matches!(plan.mode, Mode::Spawned { .. }) && !cfg!(target_os = "linux") {
        return Err(LINUX_ONLY.into());
    }
    let started_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut host = super::host();
    let corpus = corpus::read(&plan.lives)?;
    let lives = corpus::pick(corpus.lives, &plan.pick)?;
    let documents = lives.iter().map(|life| life.turns.len()).sum();
    say(&format!(
        "picked {} lives, {documents} turns, from {} files",
        lives.len(),
        corpus.files.len()
    ));
    let (server, system) = oneiron::measure(&plan, &lives)?;
    host.load_end = loadavg();
    let report = Report {
        bench: "oneiron-bench lives v1",
        label: plan.label.clone(),
        started_unix,
        host,
        server,
        plan: plan_echo(&plan),
        corpus: CorpusInfo {
            files: corpus
                .files
                .into_iter()
                .map(|f| FileDigest {
                    path: f.path,
                    sha256: f.sha256,
                })
                .collect(),
            lives: lives
                .iter()
                .map(|life| LifeInfo {
                    life: life.key.clone(),
                    life_id: life.life_id.clone(),
                    file: life.file.clone(),
                    line: life.line,
                    lang: life.lang.clone(),
                    turns: life.turns.len(),
                    questions: life.questions.len(),
                })
                .collect(),
            documents,
        },
        systems: vec![system],
    };
    write(&plan, &report)?;
    say(&format!("wrote {}", plan.out.display()));
    Ok(())
}
