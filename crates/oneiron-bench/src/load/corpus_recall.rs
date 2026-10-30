//! `load corpus-recall` — warm recall latency on a vault seeded from a
//! recorded conversation corpus, on the shipped server binary.
//!
//! The corpus is one JSON line per witnessed turn (world, person, day, turn,
//! conversation_ref, speaker runs with message ids and times, saved notes).
//! The bench seeds a fresh vault the way a live app does (`vault.witness` per
//! speaker run, each saved note as `vault.claims.upsert`), waits until the
//! server's CPU goes quiet, then sends each query `--warmup` times untimed and
//! `--repeat` times timed, strictly one request at a time. Each answer gets a
//! fingerprint (item ids, kinds and order; and the same over content), so a
//! change meant to keep results can be checked on a copy of the same vault.
//!
//! A server built with per-stage timers logs one `L15STAGES {json}` line per
//! recall; the bench reads them from the server log and reports the median of
//! each stage beside the client's round trip. A server without them reports
//! the round trip only.
//!
//! After a run the vault directory holds `seeded.json` (the issuer secret,
//! owner, agent credential and corpus end), so `--seeded <that dir>` times a
//! copy of the same vault with another server binary: identical ids, so the
//! id fingerprints compare across binaries. The secret and credential are
//! the bench's own throwaway values for a loopback vault.
//!
//! The corpus stays outside the repository: pass its path.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::{Value, json};

use super::client::Agent;
use super::phases::loadavg;
use super::server::{Credential, Embedding, Running, Vault, cpu_seconds};

const USAGE: &str = "usage: oneiron-bench load corpus-recall --server <oneiron-server> --corpus <turns.jsonl>\n\
  --work <dir> --out <file.json> [--label TEXT] [--query TEXT]... [--repeat 10] [--warmup 2]\n\
  [--limit 20] [--effort light] [--deadline-ms N] [--as-of corpus|none] [--claims notes|none]\n\
  [--settle-max-seconds 300] [--profile-repeat 0] [--seeded <dir>] [--server-env KEY=VALUE]...";

/// Marker the per-stage timers print before their JSON.
const STAGE_MARK: &str = "L15STAGES ";

#[derive(Deserialize)]
struct Turn {
    person: String,
    conversation_ref: String,
    runs: Vec<SpeakerRun>,
    #[serde(default)]
    notes: Vec<Note>,
}

#[derive(Deserialize)]
struct SpeakerRun {
    author: String,
    texts: Vec<String>,
    at: u64,
    #[serde(default)]
    ids: Vec<String>,
}

#[derive(Deserialize)]
struct Note {
    key: Option<String>,
    value: Option<String>,
}

struct Plan {
    server: PathBuf,
    corpus: PathBuf,
    work: PathBuf,
    out: PathBuf,
    label: Option<String>,
    queries: Vec<String>,
    repeat: usize,
    warmup: usize,
    limit: usize,
    effort: String,
    deadline_ms: Option<u64>,
    as_of_corpus: bool,
    claims: bool,
    settle_max: Duration,
    profile_repeat: usize,
    seeded: Option<PathBuf>,
    server_env: Vec<(String, String)>,
}

fn parse(args: &[String]) -> Result<Plan, String> {
    let mut plan = Plan {
        server: PathBuf::new(),
        corpus: PathBuf::new(),
        work: PathBuf::new(),
        out: PathBuf::new(),
        label: None,
        queries: Vec::new(),
        repeat: 10,
        warmup: 2,
        limit: 20,
        effort: "light".to_owned(),
        deadline_ms: None,
        as_of_corpus: true,
        claims: true,
        settle_max: Duration::from_secs(300),
        profile_repeat: 0,
        seeded: None,
        server_env: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        let num = |v: &str| {
            v.parse::<usize>()
                .map_err(|_| format!("{flag}: `{v}` is not a number"))
        };
        match flag.as_str() {
            "--server" => plan.server = PathBuf::from(value),
            "--corpus" => plan.corpus = PathBuf::from(value),
            "--work" => plan.work = PathBuf::from(value),
            "--out" => plan.out = PathBuf::from(value),
            "--label" => plan.label = Some(value.clone()),
            "--query" => plan.queries.push(value.clone()),
            "--repeat" => plan.repeat = num(value)?.max(1),
            "--warmup" => plan.warmup = num(value)?,
            "--limit" => plan.limit = num(value)?.max(1),
            "--effort" => plan.effort = value.clone(),
            "--deadline-ms" => plan.deadline_ms = Some(num(value)? as u64),
            "--as-of" => {
                plan.as_of_corpus = match value.as_str() {
                    "corpus" => true,
                    "none" => false,
                    _ => return Err("--as-of is corpus or none".into()),
                }
            }
            "--claims" => {
                plan.claims = match value.as_str() {
                    "notes" => true,
                    "none" => false,
                    _ => return Err("--claims is notes or none".into()),
                }
            }
            "--settle-max-seconds" => {
                plan.settle_max = Duration::from_secs(num(value)? as u64);
            }
            "--profile-repeat" => plan.profile_repeat = num(value)?,
            "--seeded" => plan.seeded = Some(PathBuf::from(value)),
            "--server-env" => {
                let (k, v) = value.split_once('=').ok_or("--server-env is KEY=VALUE")?;
                plan.server_env.push((k.to_owned(), v.to_owned()));
            }
            _ => return Err(format!("unknown flag {flag}")),
        }
    }
    if plan.server.as_os_str().is_empty()
        || plan.corpus.as_os_str().is_empty()
        || plan.work.as_os_str().is_empty()
        || plan.out.as_os_str().is_empty()
    {
        return Err(USAGE.into());
    }
    Ok(plan)
}

pub(super) fn run(args: &[String]) -> Result<(), String> {
    let plan = parse(args)?;
    execute(&plan)
}

fn say(text: &str) {
    let _ = writeln!(
        std::io::stderr().lock(),
        "[corpus-recall {}] {text}",
        loadavg()
    );
}

fn read_corpus(plan: &Plan) -> Result<Vec<Turn>, String> {
    let text = std::fs::read_to_string(&plan.corpus)
        .map_err(|e| format!("{}: {e}", plan.corpus.display()))?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
        .map(|(i, line)| {
            serde_json::from_str(line).map_err(|e| format!("corpus line {}: {e}", i + 1))
        })
        .collect()
}

/// A note key as a claim predicate: lower-case ASCII words joined by `_`.
fn predicate_of(key: &str) -> String {
    let mut slug = String::new();
    for c in key.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.ends_with('_') && !slug.is_empty() {
            slug.push('_');
        }
        if slug.len() >= 48 {
            break;
        }
    }
    format!("note.{}", slug.trim_end_matches('_'))
}

fn percentile(sorted: &[f64], pct: usize) -> Option<f64> {
    let n = sorted.len();
    (n > 0).then(|| sorted[(n * pct).div_ceil(100).max(1) - 1])
}

fn summary(samples: &[f64]) -> Value {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mean = (!sorted.is_empty()).then(|| sorted.iter().sum::<f64>() / sorted.len() as f64);
    json!({
        "n": sorted.len(),
        "p50_ms": percentile(&sorted, 50),
        "p90_ms": percentile(&sorted, 90),
        "min_ms": sorted.first(),
        "max_ms": sorted.last(),
        "mean_ms": mean,
    })
}

/// Seconds since the epoch, for the report.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The ids, kinds and order of a pack's items, and the same over content.
fn fingerprints(pack: &Value) -> (String, String, Vec<String>) {
    let items = pack["items"].as_array().cloned().unwrap_or_default();
    let mut by_id = blake3::Hasher::new();
    let mut by_content = blake3::Hasher::new();
    let mut ids = Vec::new();
    for item in &items {
        let short_id = item["short_id"].as_str().unwrap_or("");
        let kind = item["kind"].as_str().unwrap_or("");
        let cited = item["cited_messages"]
            .as_array()
            .map(|c| {
                c.iter()
                    .map(|m| m["short_id"].as_str().unwrap_or(""))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        by_id.update(format!("{short_id}|{kind}|{cited}\n").as_bytes());
        by_content.update(
            format!(
                "{kind}|{}|{}|{}|{}\n",
                item["predicate"].as_str().unwrap_or(""),
                item["value_text"].as_str().unwrap_or(""),
                item["confidence"],
                item["salience"],
            )
            .as_bytes(),
        );
        ids.push(format!("{kind}:{short_id}"));
    }
    let partial = pack["retrieval_meta"]["partial"].as_bool() == Some(true);
    by_id.update(format!("partial={partial}").as_bytes());
    by_content.update(format!("partial={partial}").as_bytes());
    (
        by_id.finalize().to_hex()[..16].to_owned(),
        by_content.finalize().to_hex()[..16].to_owned(),
        ids,
    )
}

/// The newest per-stage line the server logged after `seen` such lines.
fn stage_line(server: &Running, seen: usize) -> (usize, Option<BTreeMap<String, f64>>) {
    let lines = server.log_lines(STAGE_MARK);
    let count = lines.len();
    let parsed = (count > seen)
        .then(|| lines.last().cloned())
        .flatten()
        .and_then(|line| {
            let json = line.split_once(STAGE_MARK)?.1;
            let value: Value = serde_json::from_str(json.trim()).ok()?;
            let stages = value
                .as_object()?
                .iter()
                .filter_map(|(name, v)| {
                    let x = if name.starts_with("count.") {
                        v["n"].as_f64()
                    } else {
                        v["ms"].as_f64()
                    };
                    Some((name.clone(), x?))
                })
                .collect::<BTreeMap<_, _>>();
            Some(stages)
        });
    (count, parsed)
}

/// Waits until the server's CPU stays under 2% for five straight seconds, or
/// `max` passes; returns the seconds waited.
fn settle(server: &Running, max: Duration) -> f64 {
    let started = Instant::now();
    let mut quiet = 0;
    let mut last = cpu_seconds(server.pid).unwrap_or(0.0);
    while started.elapsed() < max && quiet < 5 {
        std::thread::sleep(Duration::from_secs(1));
        let now = cpu_seconds(server.pid).unwrap_or(last);
        quiet = if now - last < 0.02 { quiet + 1 } else { 0 };
        last = now;
    }
    started.elapsed().as_secs_f64()
}

struct Seeded {
    runs: usize,
    messages: usize,
    claims: usize,
    errors: BTreeMap<String, usize>,
    witness_ms: Vec<f64>,
    claim_ms: Vec<f64>,
    last_at: u64,
}

/// Witnesses every turn, then writes each saved note as a claim.
fn seed(plan: &Plan, agent: &Agent, corpus: &[Turn], owner: &str) -> Result<Seeded, String> {
    let mut seeded = Seeded {
        runs: 0,
        messages: 0,
        claims: 0,
        errors: BTreeMap::new(),
        witness_ms: Vec::new(),
        claim_ms: Vec::new(),
        last_at: 0,
    };
    for (index, turn) in corpus.iter().enumerate() {
        for run in &turn.runs {
            let messages = run
                .texts
                .iter()
                .enumerate()
                .map(|(order, content)| {
                    let mut m = json!({
                        "author": run.author,
                        "message_type": "text",
                        "content": content,
                        "is_visible": true,
                        "order": order,
                    });
                    if let Some(id) = run.ids.get(order) {
                        m["id"] = json!(id);
                    }
                    m
                })
                .collect::<Vec<_>>();
            let body = json!({
                "conversation_ref": turn.conversation_ref,
                "occurred_at": run.at,
                "messages": messages,
            });
            let (ms, result) = agent.post("vault.witness", &body);
            seeded.witness_ms.push(ms);
            seeded.runs += 1;
            seeded.messages += run.texts.len();
            seeded.last_at = seeded.last_at.max(run.at);
            if let Err(error) = result {
                *seeded.errors.entry(format!("witness {error}")).or_default() += 1;
            }
        }
        if (index + 1) % 50 == 0 {
            say(&format!(
                "witnessed {} of {} turns",
                index + 1,
                corpus.len()
            ));
        }
    }
    if !plan.claims {
        return Ok(seeded);
    }
    let scope = super::client::claim_scope(owner)?;
    for turn in corpus {
        let at = turn.runs.last().map_or(0, |r| r.at);
        for note in &turn.notes {
            let (Some(key), Some(value)) = (&note.key, &note.value) else {
                continue;
            };
            let body = json!({
                "predicate": predicate_of(key),
                "subject_ref": turn.conversation_ref,
                "value": value,
                "occurred_at": at,
                "learned_at": at,
                "confidence": 0.9,
                "source": "user_stated",
                "scope": scope,
            });
            let (ms, result) = agent.post("vault.claims.upsert", &body);
            seeded.claim_ms.push(ms);
            seeded.claims += 1;
            if let Err(error) = result {
                *seeded.errors.entry(format!("claim {error}")).or_default() += 1;
            }
        }
    }
    Ok(seeded)
}

struct Timed {
    ms: Vec<f64>,
    stages: Vec<BTreeMap<String, f64>>,
    fingerprints: BTreeMap<String, usize>,
    content: BTreeMap<String, usize>,
    ids: Vec<String>,
    items: usize,
    partial: usize,
    errors: BTreeMap<String, usize>,
}

fn recall_body(plan: &Plan, query: &str, as_of: Option<u64>) -> Value {
    let mut body = json!({"query": query, "effort": plan.effort, "limit": plan.limit});
    if let Some(deadline) = plan.deadline_ms {
        body["deadline_ms"] = json!(deadline);
    }
    if let Some(as_of) = as_of {
        body["as_of"] = json!(as_of);
    }
    body
}

fn time_query(
    plan: &Plan,
    agent: &Agent,
    server: &Running,
    query: &str,
    as_of: Option<u64>,
    repeat: usize,
) -> Timed {
    let body = recall_body(plan, query, as_of);
    let mut timed = Timed {
        ms: Vec::new(),
        stages: Vec::new(),
        fingerprints: BTreeMap::new(),
        content: BTreeMap::new(),
        ids: Vec::new(),
        items: 0,
        partial: 0,
        errors: BTreeMap::new(),
    };
    let mut seen = server.log_lines(STAGE_MARK).len();
    for _ in 0..repeat {
        let (ms, result) = agent.post("vault.recall", &body);
        let (count, stages) = stage_line(server, seen);
        seen = count;
        match result {
            Ok(pack) => {
                let (fp, content, ids) = fingerprints(&pack);
                *timed.fingerprints.entry(fp).or_default() += 1;
                *timed.content.entry(content).or_default() += 1;
                timed.items = ids.len();
                timed.ids = ids;
                timed.partial +=
                    usize::from(pack["retrieval_meta"]["partial"].as_bool() == Some(true));
                timed.ms.push(ms);
                if let Some(stages) = stages {
                    timed.stages.push(stages);
                }
            }
            Err(error) => *timed.errors.entry(error).or_default() += 1,
        }
    }
    timed
}

/// The median of each stage over `samples` (a stage missing from a sample counts as 0).
fn stage_medians(samples: &[BTreeMap<String, f64>]) -> BTreeMap<String, f64> {
    let mut names = Vec::<String>::new();
    for s in samples {
        for name in s.keys() {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
    }
    names
        .into_iter()
        .map(|name| {
            let mut v = samples
                .iter()
                .map(|s| s.get(&name).copied().unwrap_or(0.0))
                .collect::<Vec<_>>();
            v.sort_by(f64::total_cmp);
            let median = percentile(&v, 50).unwrap_or(0.0);
            (name, median)
        })
        .collect()
}

fn execute(plan: &Plan) -> Result<(), String> {
    let corpus = read_corpus(plan)?;
    let mut queries = plan.queries.clone();
    if queries.is_empty() {
        for turn in &corpus {
            let q = format!("what do we know about {}", turn.person);
            if !queries.contains(&q) {
                queries.push(q);
            }
        }
    }
    let dir = plan.work.join("corpus-recall");
    if dir.exists() {
        std::fs::remove_dir_all(&dir).map_err(|e| format!("clear {}: {e}", dir.display()))?;
    }
    let (vault, credential, reused) = match &plan.seeded {
        Some(from) => {
            let (vault, credential, last_at) = reuse_seeded(from, &dir)?;
            (vault, credential, Some(last_at))
        }
        None => {
            let vault = Vault::init(&plan.server, &dir, &Embedding::None, &plan.server_env)?;
            let credential = vault.mint_agent(&plan.server, "corpus-recall-agent")?;
            (vault, credential, None)
        }
    };
    let server = Running::start(&plan.server, &vault, &plan.server_env, "serve.log", "warn")?;
    say(&format!("server ready in {:.0} ms", server.ready_ms));
    let http = Agent::http()?;
    let skew = Agent::new(&http, &server.base, &credential, 0)?.clock_skew()?;
    let agent = Agent::new(&http, &server.base, &credential, skew)?;

    let cpu_before_seed = cpu_seconds(server.pid);
    let seed_started = Instant::now();
    let seeded = match reused {
        Some(last_at) => Seeded {
            runs: 0,
            messages: 0,
            claims: 0,
            errors: BTreeMap::new(),
            witness_ms: Vec::new(),
            claim_ms: Vec::new(),
            last_at,
        },
        None => seed(plan, &agent, &corpus, &vault.owner)?,
    };
    let seed_seconds = seed_started.elapsed().as_secs_f64();
    let seed_cpu = cpu_before_seed
        .zip(cpu_seconds(server.pid))
        .map(|(a, b)| b - a);
    say(&format!(
        "seeded {} runs ({} messages) and {} claims in {seed_seconds:.1} s; errors {:?}",
        seeded.runs, seeded.messages, seeded.claims, seeded.errors
    ));
    let settle_seconds = settle(&server, plan.settle_max);
    say(&format!("settled after {settle_seconds:.1} s"));
    let disk_mib = vault.disk_bytes() as f64 / 1_048_576.0;
    let as_of = plan.as_of_corpus.then_some(seeded.last_at + 3600);

    let mut per_query = Vec::new();
    let mut all_ms = Vec::new();
    let mut all_stages = Vec::new();
    let mut overall = blake3::Hasher::new();
    for query in &queries {
        let _ = time_query(plan, &agent, &server, query, as_of, plan.warmup);
        let cpu_before = cpu_seconds(server.pid);
        let timed = time_query(plan, &agent, &server, query, as_of, plan.repeat);
        let cpu = cpu_before
            .zip(cpu_seconds(server.pid))
            .map(|(a, b)| (b - a) / plan.repeat as f64 * 1000.0);
        let medians = stage_medians(&timed.stages);
        let stable = timed.fingerprints.len() == 1;
        let fingerprint = timed
            .fingerprints
            .keys()
            .next()
            .cloned()
            .unwrap_or_default();
        let content = timed.content.keys().next().cloned().unwrap_or_default();
        overall.update(format!("{query}|{fingerprint}|{content}\n").as_bytes());
        let s = summary(&timed.ms);
        say(&format!(
            "{query:?}: p50 {:.1} ms, {} items, fingerprint {fingerprint} ({}), stable {stable}",
            s["p50_ms"].as_f64().unwrap_or(f64::NAN),
            timed.items,
            content,
        ));
        all_ms.extend(timed.ms.iter().copied());
        all_stages.extend(timed.stages.iter().cloned());
        per_query.push(json!({
            "query": query,
            "round_trip": s,
            "server_cpu_ms_per_recall": cpu,
            "items": timed.items,
            "partial": timed.partial,
            "errors": timed.errors,
            "fingerprint": fingerprint,
            "fingerprint_content": content,
            "fingerprint_stable": stable,
            "fingerprints_seen": timed.fingerprints,
            "ids": timed.ids,
            "stage_median_ms": medians,
        }));
    }
    let profile = if plan.profile_repeat > 0 {
        say(&format!(
            "profile phase: {} recalls per query, server pid {}",
            plan.profile_repeat, server.pid
        ));
        let marker = plan.work.join("profile-window");
        std::fs::write(&marker, server.pid.to_string()).map_err(|e| e.to_string())?;
        for query in &queries {
            let _ = time_query(plan, &agent, &server, query, as_of, plan.profile_repeat);
        }
        let _ = std::fs::remove_file(&marker);
        Some(plan.profile_repeat)
    } else {
        None
    };
    let medians = stage_medians(&all_stages);
    let report = json!({
        "bench": "oneiron-bench load corpus-recall v1",
        "label": plan.label,
        "started_unix": unix_now(),
        "server_bin": plan.server.display().to_string(),
        "seeded_from": plan.seeded.as_ref().map(|p| p.display().to_string()),
        "corpus": plan.corpus.display().to_string(),
        "load": loadavg(),
        "plan": {
            "repeat": plan.repeat, "warmup": plan.warmup, "limit": plan.limit,
            "effort": plan.effort, "deadline_ms": plan.deadline_ms, "as_of": as_of,
            "claims": plan.claims, "profile_repeat": profile,
            "server_env": plan.server_env.iter().map(|(k, _)| k).collect::<Vec<_>>(),
        },
        "seed": {
            "turns": corpus.len(), "runs": seeded.runs, "messages": seeded.messages,
            "claims": seeded.claims, "errors": seeded.errors, "seconds": seed_seconds,
            "server_cpu_seconds": seed_cpu,
            "witness": summary(&seeded.witness_ms), "claim_upsert": summary(&seeded.claim_ms),
        },
        "settle_seconds": settle_seconds,
        "disk_mib": disk_mib,
        "server_ready_ms": server.ready_ms,
        "round_trip": summary(&all_ms),
        "stage_median_ms": medians,
        "fingerprint_all": overall.finalize().to_hex()[..16].to_owned(),
        "queries": per_query,
    });
    let text = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    std::fs::write(&plan.out, text).map_err(|e| format!("{}: {e}", plan.out.display()))?;
    let mut table = String::from("| stage | median ms |\n|---|---|\n");
    for (name, ms) in &medians {
        table.push_str(&format!("| {name} | {ms:.3} |\n"));
    }
    let _ = writeln!(
        std::io::stdout().lock(),
        "round trip p50 {:.1} ms over {} recalls; fingerprint_all {}\n{table}",
        report["round_trip"]["p50_ms"].as_f64().unwrap_or(f64::NAN),
        all_ms.len(),
        report["fingerprint_all"].as_str().unwrap_or("")
    );
    let exit = server.stop();
    let record = json!({
        "secret": vault.secret, "owner": vault.owner, "token": credential.token,
        "binding_key": credential.binding_key, "last_at": seeded.last_at,
    });
    std::fs::write(dir.join("seeded.json"), record.to_string())
        .map_err(|e| format!("seeded.json: {e}"))?;
    say(&format!("serve exit: {exit}; wrote {}", plan.out.display()));
    Ok(())
}

/// Copies a vault directory an earlier run left (with its `seeded.json`) to
/// `dir`, and returns it with its agent credential and corpus end.
fn reuse_seeded(
    from: &std::path::Path,
    dir: &std::path::Path,
) -> Result<(Vault, Credential, u64), String> {
    let status = std::process::Command::new("cp")
        .arg("-a")
        .arg(from)
        .arg(dir)
        .status()
        .map_err(|e| format!("cp -a {}: {e}", from.display()))?;
    if !status.success() {
        return Err(format!("cp -a {} {} failed", from.display(), dir.display()));
    }
    let text = std::fs::read_to_string(dir.join("seeded.json"))
        .map_err(|e| format!("{}/seeded.json: {e}", from.display()))?;
    let record: Value = serde_json::from_str(&text).map_err(|e| format!("seeded.json: {e}"))?;
    let field = |name: &str| {
        record[name]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("seeded.json has no {name}"))
    };
    let vault = Vault {
        dir: dir.to_owned(),
        path: dir.join("vault"),
        config: dir.join("vault.toml"),
        secret: field("secret")?,
        owner: field("owner")?,
    };
    let credential = Credential {
        token: field("token")?,
        binding_key: field("binding_key")?,
    };
    let last_at = record["last_at"]
        .as_u64()
        .ok_or("seeded.json has no last_at")?;
    Ok((vault, credential, last_at))
}
