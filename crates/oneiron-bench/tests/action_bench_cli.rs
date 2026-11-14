//! `oneiron-bench beam action-bench` (census L9-34; ARCH-0042 #action-bench,
//! owner ruling 2026-10-21): the in-house bench that asks whether memory
//! changes what a reader later does. The shipped binary runs the shipped
//! tasks file through all five memory arms against a loopback reader, so no
//! model, key or GPU is needed. On a tree without the subcommand the binary
//! answers "unknown BEAM invocation" and exits non-zero.
//!
//! The loopback reader reads only what it is sent: for each field of the
//! question's first tool it answers the option the context names last, and
//! the field's first option when the context names none. In the shipped
//! tasks a field's first option is the worst answer: a superseded value,
//! another world's value or a deleted one.
//!
//! The same loopback serves the extraction arms' Dreamer calls. Its
//! extractor answers from the shipped tasks: for each listed turn a user
//! said a claim in, one candidate with that claim's predicate whose value is
//! the turn's own words, quoted whole, about the entity the listing shows
//! that predicate under (else the first listed entity). An extracted claim
//! therefore reads as a turn's words, never as an authored claim's value.
//!
//! `cargo test --locked -p oneiron-bench --test action_bench_cli`.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const READER_MODEL: &str = "openai/action-reader@v1";
const PROVIDER_MODEL: &str = "action-reader";
const READER_PROMPT: &str = "You act for the user. Reply with one JSON action.";
const ARMS: [&str; 5] = ["none", "raw", "derived", "raw_plus_derived", "gold"];
const CORRECTIONS: [&str; 3] = ["owen-dentist", "yuki-locker", "mara-taxi"];
const SCOPED: [&str; 3] = ["owen-playlist", "yuki-signoff", "mara-signature"];
const DELETIONS: [&str; 3] = ["owen-card", "yuki-delivery", "mara-contact"];
const EXTRACTION_MODEL: &str = "openai/action-extractor@v1";
const EXTRACTION_PROVIDER_MODEL: &str = "action-extractor";
const EXTRACTION_ARMS: [&str; 4] = [
    "none",
    "extract_online",
    "extract_background",
    "extract_combined",
];
/// The shipped extraction prompt's opening words.
const EXTRACTION_SYSTEM: &str = "Extract durable memory claims";

fn shipped_tasks_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/action_bench.tasks.v1.json")
}

fn shipped_tasks() -> Value {
    serde_json::from_slice(&std::fs::read(shipped_tasks_path()).unwrap()).unwrap()
}

fn follow_up_count(tasks: &Value) -> usize {
    tasks["follow_ups"].as_array().unwrap().len()
}

/// Every value of a rubric map whose values are lists.
fn listed(named: &Value) -> Vec<String> {
    named
        .as_object()
        .unwrap()
        .values()
        .flat_map(|values| values.as_array().unwrap())
        .map(|value| value.as_str().unwrap().to_owned())
        .collect()
}

fn history<'a>(tasks: &'a Value, id: &str) -> &'a Value {
    tasks["histories"]
        .as_array()
        .unwrap()
        .iter()
        .find(|history| history["id"] == id)
        .unwrap()
}

fn history_mut<'a>(tasks: &'a mut Value, id: &str) -> &'a mut Value {
    tasks["histories"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|history| history["id"] == id)
        .unwrap()
}

fn follow_up_mut<'a>(tasks: &'a mut Value, id: &str) -> &'a mut Value {
    tasks["follow_ups"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|follow_up| follow_up["id"] == id)
        .unwrap()
}

/// The loopback reader, every request body the reader was sent, and every
/// Dreamer call the extraction arms made.
struct Reader {
    endpoint: String,
    requests: Arc<Mutex<Vec<Value>>>,
    dreamer: Arc<Mutex<Vec<DreamerCall>>>,
}

/// One Dreamer call the loopback answered, and the usage it reported.
#[derive(Clone)]
struct DreamerCall {
    request: Value,
    prompt_tokens: u64,
    completion_tokens: u64,
}

/// What the loopback holds: the forced reader replies and the extractor's
/// answer key, each user turn's words to the predicates said at its time.
struct Loopback {
    forced: BTreeMap<String, String>,
    said: BTreeMap<String, Vec<String>>,
    requests: Arc<Mutex<Vec<Value>>>,
    dreamer: Arc<Mutex<Vec<DreamerCall>>>,
}

/// Each user turn of the shipped tasks, and the predicates of the claims
/// said at its time in its history.
fn said_in_turns(tasks: &Value) -> BTreeMap<String, Vec<String>> {
    let mut said: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for history in tasks["histories"].as_array().unwrap() {
        for turn in history["turns"].as_array().unwrap() {
            if turn["author"] != "user" {
                continue;
            }
            let predicates = history["claims"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|claim| claim["at"] == turn["at"])
                .map(|claim| claim["predicate"].as_str().unwrap().to_owned());
            said.entry(turn["text"].as_str().unwrap().to_owned())
                .or_default()
                .extend(predicates);
        }
    }
    said
}

/// Starts the loopback reader. `forced` maps a follow-up prompt to the reply
/// the reader gives it, whatever the context.
fn start_reader(forced: BTreeMap<String, String>) -> Reader {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let loopback = Loopback {
        forced,
        said: said_in_turns(&shipped_tasks()),
        requests: Arc::new(Mutex::new(Vec::new())),
        dreamer: Arc::new(Mutex::new(Vec::new())),
    };
    let requests = Arc::clone(&loopback.requests);
    let dreamer = Arc::clone(&loopback.dreamer);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            serve(stream, &loopback);
        }
    });
    Reader {
        endpoint,
        requests,
        dreamer,
    }
}

fn serve(mut stream: TcpStream, loopback: &Loopback) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut length = 0_usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 {
            return;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            length = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).unwrap();
    let request: Value = serde_json::from_slice(&body).unwrap();
    let reader = system_text(&request) == READER_PROMPT;
    let reply = if reader {
        let input: Value = serde_json::from_str(&message(&request, "user")).unwrap();
        let question = input["question"].as_str().unwrap();
        let context = input["context"].as_str().unwrap();
        let prompt = question.split("\n\nTools:").next().unwrap();
        loopback
            .forced
            .get(prompt)
            .cloned()
            .unwrap_or_else(|| act(question, context))
    } else {
        dreamer_reply(&request, &loopback.said)
    };
    let prompt_tokens = body.len() as u64 / 4 + 1;
    let completion_tokens = reply.len() as u64 / 4 + 1;
    let response = json!({
        "id": "action-reader-reply",
        "object": "chat.completion",
        "model": request["model"],
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": reply},
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        },
    })
    .to_string();
    if reader {
        loopback.requests.lock().unwrap().push(request);
    } else {
        loopback.dreamer.lock().unwrap().push(DreamerCall {
            request,
            prompt_tokens,
            completion_tokens,
        });
    }
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
        response.len()
    )
    .unwrap();
}

/// A request message's text, by role: the first message in that role.
fn message(request: &Value, role: &str) -> String {
    let message = request["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == role)
        .unwrap();
    text_of(message)
}

/// The last message's text in `role`: an extraction call's transcript
/// follows its worked examples.
fn last_message(request: &Value, role: &str) -> String {
    let message = request["messages"]
        .as_array()
        .unwrap()
        .iter()
        .rfind(|message| message["role"] == role)
        .unwrap();
    text_of(message)
}

/// The first system message's text; empty when there is none.
fn system_text(request: &Value) -> String {
    request["messages"]
        .as_array()
        .and_then(|messages| messages.iter().find(|message| message["role"] == "system"))
        .map(text_of)
        .unwrap_or_default()
}

fn text_of(message: &Value) -> String {
    match &message["content"] {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect(),
        // A message with no text (an assistant turn of tool calls) reads
        // as empty.
        _ => String::new(),
    }
}

/// The merged-value call's system text opening (`merge_resolution.rs`).
const MERGED_VALUE_SYSTEM: &str = "Conflicting values were extracted for one claim identity";
/// The Macro nightly narrative's system text opening.
const NARRATIVE_SYSTEM: &str = "Write a concise arc summary";
/// The Micro window audit's system text opening.
const WINDOW_AUDIT_SYSTEM: &str = "The window is a stretch of source text";

/// A Dreamer call's reply, by what the call is:
/// - an extraction call: the loopback extractor's candidates ([`extract`]);
/// - a merged-value call: the value of the candidate the resolution keeps;
/// - a typed decision pack (one user turn of JSON questions, each with its
///   labels): a weight of one on one label per question ([`decide`]);
/// - the nightly narrative: a blank reply, refused and never landed, so no
///   arc summary claim enters a context;
/// - the window audit: no finding;
/// - anything else: an empty object, which its contract refuses (the
///   attempt parks and the report counts it).
fn dreamer_reply(request: &Value, said: &BTreeMap<String, Vec<String>>) -> String {
    let system = system_text(request);
    let user = last_message(request, "user");
    if system.starts_with(EXTRACTION_SYSTEM) {
        return extract(&user, said);
    }
    if system.starts_with(MERGED_VALUE_SYSTEM) {
        return merged_value(&user);
    }
    if let Ok(turn) = serde_json::from_str::<Value>(&user)
        && turn["questions"].is_array()
    {
        return decide(&turn);
    }
    if system.starts_with(NARRATIVE_SYSTEM) {
        return String::new();
    }
    if system.starts_with(WINDOW_AUDIT_SYSTEM) {
        return "{\"discovered\": []}".to_owned();
    }
    "{}".to_owned()
}

/// A merged-value reply: `{"value": ..}`, the value of the candidate named
/// on the `keeps candidate_ref` line, else of the last candidate row.
fn merged_value(lines: &str) -> String {
    let kept = lines
        .lines()
        .find_map(|line| line.strip_prefix("keeps candidate_ref "))
        .map(str::trim);
    let rows: Vec<(&str, &str)> = lines
        .lines()
        .filter_map(|line| line.strip_prefix("- candidate_ref: "))
        .filter_map(|row| {
            let (label, rest) = row.split_once(' ')?;
            let (_, value) = rest.split_once(" value: ")?;
            Some((label, value))
        })
        .collect();
    let value = rows
        .iter()
        .find(|(label, _)| Some(*label) == kept)
        .or(rows.last())
        .and_then(|(_, value)| serde_json::from_str::<Value>(value).ok())
        .unwrap_or(Value::Null);
    json!({ "value": value }).to_string()
}

/// A typed decision pack's reply: per question id, weight one on one label.
/// The correction pack's question picks the listed claim that carries its
/// candidate's predicate, else `none`. A conflict's resolution supersedes
/// when the conflict has a prior head and accumulates when it has none; its
/// identity groups keep the conflict's own (`none`). A nightly link stays
/// unresolved. Any other question takes `none` when offered, else its first
/// label; a score question answers 80 at probability 0.7.
fn decide(turn: &Value) -> String {
    let state = &turn["state"];
    let correction = find_key(state, "listed").zip(find_key(state, "candidates"));
    let prior_heads = find_key(state, "prior_heads")
        .and_then(Value::as_array)
        .is_some_and(|heads| !heads.is_empty());
    let mut answer = Map::new();
    for question in turn["questions"].as_array().unwrap() {
        let Some(id) = question["id"].as_str() else {
            continue;
        };
        let Some(labels) = question["labels"].as_array() else {
            answer.insert(id.to_owned(), json!({"score": 80, "probability": 0.7}));
            continue;
        };
        let labels: Vec<&str> = labels.iter().filter_map(Value::as_str).collect();
        let offered = |label: &str| labels.contains(&label).then(|| label.to_owned());
        let resolution = if prior_heads {
            "supersede"
        } else {
            "accumulate"
        };
        let chosen = if labels.contains(&"supersede") {
            resolution.to_owned()
        } else if let Some(unresolved) = offered("unresolved") {
            unresolved
        } else if let Some((listed, candidates)) = correction {
            corrected_claim(id, &labels, listed, candidates)
                .or_else(|| offered("none"))
                .unwrap_or_else(|| labels.first().copied().unwrap_or_default().to_owned())
        } else {
            offered("none")
                .unwrap_or_else(|| labels.first().copied().unwrap_or_default().to_owned())
        };
        let weights: Map<String, Value> = labels
            .iter()
            .map(|label| {
                let weight = if *label == chosen { 1.0 } else { 0.0 };
                ((*label).to_owned(), json!(weight))
            })
            .collect();
        answer.insert(id.to_owned(), Value::Object(weights));
    }
    Value::Object(answer).to_string()
}

/// The listed claim among `labels` that carries the predicate of the
/// candidate question `id` asks about.
fn corrected_claim(
    id: &str,
    labels: &[&str],
    listed: &Value,
    candidates: &Value,
) -> Option<String> {
    let predicate = candidates.as_array()?.iter().find(|candidate| {
        candidate["questions"]
            .as_array()
            .is_some_and(|questions| questions.iter().any(|question| question == id))
    })?["predicate"]
        .as_str()?;
    listed
        .as_array()?
        .iter()
        .find(|claim| {
            claim["predicate"] == predicate
                && claim["claim"]
                    .as_str()
                    .is_some_and(|label| labels.contains(&label))
        })
        .and_then(|claim| claim["claim"].as_str())
        .map(str::to_owned)
}

/// The first value under `key` anywhere in `value`.
fn find_key<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map
            .get(key)
            .or_else(|| map.values().find_map(|inner| find_key(inner, key))),
        Value::Array(items) => items.iter().find_map(|inner| find_key(inner, key)),
        _ => None,
    }
}

/// The loopback extractor over one call's transcript. Each listed entity
/// opens with `entity <label>`, its newest claims follow as
/// `claim <label> <predicate> = <value>`, and each turn reads
/// `[<label> <speaker>] <text>`. For each turn a user said a claim in, one
/// candidate per such claim: its predicate, the turn's words as its value,
/// the whole turn as its quote, about the entity the listing shows that
/// predicate under (a correction then names the head it corrects), else the
/// first listed entity. A turn restating a listed claim's value cites that
/// claim too.
fn extract(transcript: &str, said: &BTreeMap<String, Vec<String>>) -> String {
    let mut entities: Vec<String> = Vec::new();
    let mut heads: BTreeMap<String, (String, String, Value)> = BTreeMap::new();
    let mut candidates: Vec<String> = Vec::new();
    for line in transcript.lines() {
        if let Some(rest) = line.strip_prefix("entity ") {
            entities.push(rest.split(' ').next().unwrap().to_owned());
        } else if let Some(rest) = line.trim_start().strip_prefix("claim ") {
            let (Some(entity), Some((label, rest))) = (entities.last(), rest.split_once(' '))
            else {
                continue;
            };
            let Some((predicate, value)) = rest.split_once(" = ") else {
                continue;
            };
            let value = serde_json::Deserializer::from_str(value)
                .into_iter::<Value>()
                .next()
                .and_then(Result::ok)
                .unwrap_or(Value::Null);
            heads.insert(
                predicate.to_owned(),
                (entity.clone(), label.to_owned(), value),
            );
        } else if let Some(rest) = line.strip_prefix('[') {
            let Some((head, text)) = rest.split_once("] ") else {
                continue;
            };
            let turn = head.split(' ').next().unwrap();
            for predicate in said.get(text).into_iter().flatten() {
                let listed = heads.get(predicate);
                let Some(subject) = listed
                    .map(|(entity, _, _)| entity.clone())
                    .or_else(|| entities.first().cloned())
                else {
                    continue;
                };
                let mut refs = vec![json!({"source": turn, "quote": text})];
                if let Some((_, claim, value)) = listed
                    && value == text
                {
                    refs.push(json!({"claim": claim}));
                }
                candidates.push(
                    json!({
                        "subject": subject,
                        "predicate": predicate,
                        "value": text,
                        "confidence": 0.9,
                        "evidence_refs": refs,
                    })
                    .to_string(),
                );
            }
        }
    }
    if candidates.is_empty() {
        return "{\"candidates\": []}".to_owned();
    }
    format!("{{\"candidates\": [\n{}\n]}}", candidates.join(",\n"))
}

/// The reader's rule: per field of the first tool, the option the context
/// names last (case-folded), else the first option.
fn act(question: &str, context: &str) -> String {
    let context = context.to_lowercase();
    let mut lines = question
        .split("\n\nTools:")
        .nth(1)
        .unwrap()
        .lines()
        .skip_while(|line| !line.starts_with("- "));
    let tool = lines.next().unwrap();
    let action = tool[2..].split(':').next().unwrap();
    let mut fields = Map::new();
    for line in lines.take_while(|line| line.starts_with("  ")) {
        let (field, options) = line.trim().split_once(": ").unwrap();
        let options: Vec<&str> = options.split(" | ").collect();
        let chosen = options
            .iter()
            .filter_map(|option| Some((context.rfind(&option.to_lowercase())?, *option)))
            .max()
            .map_or(options[0], |(_, option)| option);
        fields.insert(field.to_owned(), Value::from(chosen));
    }
    json!({"action": action, "fields": fields}).to_string()
}

fn write_plan(dir: &Path, endpoint: &str, tasks: &Path) -> PathBuf {
    write_plan_with(dir, endpoint, tasks, &ARMS, false)
}

/// A plan over `arms`; `extraction` adds the extraction pin, on the
/// loopback at `own_server`.
fn write_plan_with(
    dir: &Path,
    endpoint: &str,
    tasks: &Path,
    arms: &[&str],
    extraction: bool,
) -> PathBuf {
    let sha256: String = Sha256::digest(READER_PROMPT.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut models = Map::new();
    models.insert(
        READER_MODEL.to_owned(),
        json!({
            "input_per_million": 1.0,
            "output_per_million": 2.0,
            "cache_read_per_million": 0.5,
            "cache_write_per_million": 1.0,
        }),
    );
    models.insert(
        EXTRACTION_MODEL.to_owned(),
        json!({
            "input_per_million": 0.5,
            "output_per_million": 1.5,
            "cache_read_per_million": 0.25,
            "cache_write_per_million": 0.5,
        }),
    );
    let mut plan = json!({
        "tasks": tasks,
        "host": {
            "endpoint": endpoint,
            "api_key_env": null,
            "token_budget": 10_000_000,
            "prices": {"revision": "test", "source": "fixture://action-bench-test", "models": models},
        },
        "reader": {
            "model_id": READER_MODEL,
            "provider_model": PROVIDER_MODEL,
            "max_tokens": 64,
            "temperature": 0.0,
        },
        "reader_prompt": {"content": READER_PROMPT, "sha256": sha256},
        "arms": arms,
        "recall_limit": 10,
    });
    if extraction {
        plan["extraction"] = json!({
            "model_id": EXTRACTION_MODEL,
            "provider_model": EXTRACTION_PROVIDER_MODEL,
            "locality": "own_server",
            "pass_budget_units": 1_000_000,
        });
    }
    let path = dir.join("plan.json");
    std::fs::write(&path, plan.to_string()).unwrap();
    path
}

fn run_bench(plan: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_oneiron-bench"))
        .args(["beam", "action-bench"])
        .arg(plan)
        .output()
        .expect("the bench binary runs")
}

/// One run over the shipped tasks: its report, the requests the reader was
/// sent and the Dreamer calls the extraction arms made.
struct Run {
    report: Value,
    requests: Vec<Value>,
    dreamer: Vec<DreamerCall>,
}

fn run(forced: BTreeMap<String, String>) -> Run {
    run_arms(forced, &ARMS, false)
}

fn run_arms(forced: BTreeMap<String, String>, arms: &[&str], extraction: bool) -> Run {
    let reader = start_reader(forced);
    let dir = tempfile::tempdir().unwrap();
    let output = run_bench(&write_plan_with(
        dir.path(),
        &reader.endpoint,
        &shipped_tasks_path(),
        arms,
        extraction,
    ));
    assert!(
        output.status.success(),
        "the bench run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = serde_json::from_slice(&output.stdout).unwrap();
    let requests = reader.requests.lock().unwrap().clone();
    let dreamer = reader.dreamer.lock().unwrap().clone();
    Run {
        report,
        requests,
        dreamer,
    }
}

fn shipped_run() -> &'static Run {
    static RUN: OnceLock<Run> = OnceLock::new();
    RUN.get_or_init(|| run(BTreeMap::new()))
}

/// One run of the three extraction arms beside no memory.
fn extraction_run() -> &'static Run {
    static RUN: OnceLock<Run> = OnceLock::new();
    RUN.get_or_init(|| run_arms(BTreeMap::new(), &EXTRACTION_ARMS, true))
}

/// One extraction arm's row for one follow-up at one probe.
fn probe_row<'a>(run: &'a Run, arm: &str, probe: &str, follow_up: &str) -> &'a Value {
    rows(run, arm)
        .into_iter()
        .find(|row| row["follow_up"] == follow_up && row["probe"] == probe)
        .unwrap_or_else(|| panic!("no {arm} row at {probe} for {follow_up}"))
}

/// One history's extraction row under one arm.
fn extraction_row<'a>(run: &'a Run, history: &str, arm: &str) -> &'a Value {
    run.report["extraction"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["history"] == history && row["arm"] == arm)
        .unwrap_or_else(|| panic!("no extraction row for {history} {arm}"))
}

/// What an extraction vault held by a probe, over every lane.
fn probe_tally<'a>(run: &'a Run, history: &str, arm: &str, probe: &str) -> &'a Value {
    extraction_row(run, history, arm)["probes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tally| tally["probe"] == probe)
        .unwrap()
}

fn rows<'a>(run: &'a Run, arm: &str) -> Vec<&'a Value> {
    run.report["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["arm"] == arm)
        .collect()
}

fn row<'a>(run: &'a Run, arm: &str, follow_up: &str) -> &'a Value {
    rows(run, arm)
        .into_iter()
        .find(|row| row["follow_up"] == follow_up)
        .unwrap()
}

fn follow_up(tasks: &Value, id: &str) -> Value {
    tasks["follow_ups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|follow_up| follow_up["id"] == id)
        .unwrap()
        .clone()
}

#[test]
fn the_no_memory_arm_never_reads_the_vault_and_the_gold_arm_acts_on_every_follow_up() {
    let run = shipped_run();
    let tasks = shipped_tasks();
    assert_eq!(rows(run, "none").len(), follow_up_count(&tasks));
    for row in rows(run, "none") {
        assert_eq!(row["context"], "", "{row}");
        assert_eq!(row["recall_elapsed_us"], 0);
        assert_eq!(row["score"]["action_correct"], false, "{row}");
    }
    for row in rows(run, "gold") {
        let gold: Vec<String> =
            follow_up(&tasks, row["follow_up"].as_str().unwrap())["gold_memory"]
                .as_array()
                .unwrap()
                .iter()
                .map(|line| format!("- {}", line.as_str().unwrap()))
                .collect();
        assert_eq!(row["context"], gold.join("\n"));
        assert_eq!(row["score"]["action_correct"], true, "{row}");
        assert_eq!(row["score"]["unsupported_change"], false, "{row}");
    }
    let summary = run.report["summary"].as_array().unwrap();
    let gold = summary.iter().find(|arm| arm["arm"] == "gold").unwrap();
    assert_eq!(gold["action_correct"], 1.0);
    assert_eq!(gold["correction_persisted"], 1.0);
    assert_eq!(gold["leaked"], 0.0);
    assert_eq!(gold["reappeared"], 0.0);
    let none = summary.iter().find(|arm| arm["arm"] == "none").unwrap();
    assert_eq!(none["action_correct"], 0.0);
    // The first option of each corrected field is its superseded value, of
    // each scoped field another world's value, of each deleted field the
    // deleted value.
    assert_eq!(none["correction_persisted"], 0.0);
    assert_eq!(none["leaked"], 1.0);
    assert_eq!(none["reappeared"], 1.0);
}

#[test]
fn the_derived_arm_acts_on_the_correction_not_the_superseded_claim() {
    let run = shipped_run();
    let tasks = shipped_tasks();
    for id in CORRECTIONS {
        let row = row(run, "derived", id);
        let task = follow_up(&tasks, id);
        let rubric = &task["rubric"];
        let context = row["context"].as_str().unwrap();
        for value in rubric["expect"].as_object().unwrap().values() {
            assert!(context.contains(value.as_str().unwrap()), "{row}");
        }
        for stale in rubric["stale"].as_object().unwrap().values() {
            for value in stale.as_array().unwrap() {
                assert!(!context.contains(value.as_str().unwrap()), "{row}");
            }
        }
        assert_eq!(row["score"]["correction_persisted"], true, "{row}");
        assert_eq!(row["score"]["action_correct"], true, "{row}");
    }
}

#[test]
fn the_raw_arm_reads_only_turns_the_derived_arm_only_claims_and_no_arm_reads_past_the_freeze() {
    let run = shipped_run();
    let line_kinds = |arm: &str| -> BTreeSet<String> {
        rows(run, arm)
            .iter()
            .flat_map(|row| row["context"].as_str().unwrap().lines())
            .map(|line| line[2..].split([' ', ':']).next().unwrap().to_owned())
            .collect()
    };
    let raw = line_kinds("raw");
    assert!(!raw.is_empty());
    assert!(
        raw.is_subset(&BTreeSet::from(["TURN".to_owned(), "MESSAGE".to_owned()])),
        "{raw:?}"
    );
    assert_eq!(line_kinds("derived"), BTreeSet::from(["CLAIM".to_owned()]));
    let both = line_kinds("raw_plus_derived");
    assert!(
        both.contains("CLAIM") && (both.contains("TURN") || both.contains("MESSAGE")),
        "{both:?}"
    );
    for arm in ["raw", "derived", "raw_plus_derived"] {
        for row in rows(run, arm) {
            assert!(
                !row["context"].as_str().unwrap().contains("FreshCo"),
                "{row}"
            );
        }
    }
    let tasks = shipped_tasks();
    for reported in run.report["histories"].as_array().unwrap() {
        let shipped = history(&tasks, reported["history"].as_str().unwrap());
        let frozen_at = shipped["frozen_at"].as_u64().unwrap();
        let items = |key: &str| shipped[key].as_array().unwrap();
        let before = |key: &str| {
            items(key)
                .iter()
                .filter(|item| item["at"].as_u64().unwrap() < frozen_at)
                .count()
        };
        let after_freeze =
            items("turns").len() + items("claims").len() - before("turns") - before("claims");
        assert_eq!(reported["items_after_freeze"], after_freeze, "{reported}");
        assert_eq!(reported["turns_witnessed"], before("turns"), "{reported}");
        assert_eq!(reported["claims_written"], before("claims"), "{reported}");
    }
    let mara = history(&tasks, "mara");
    assert!(
        mara["turns"]
            .as_array()
            .unwrap()
            .iter()
            .any(|turn| turn["at"].as_u64().unwrap() >= mara["frozen_at"].as_u64().unwrap()),
        "mara holds a turn after the freeze"
    );
}

#[test]
fn the_reader_sees_only_the_question_and_the_arms_context() {
    let run = shipped_run();
    assert_eq!(
        run.requests.len(),
        follow_up_count(&shipped_tasks()) * ARMS.len()
    );
    let sent: BTreeSet<(String, String)> = run
        .requests
        .iter()
        .map(|request| {
            assert_eq!(message(request, "system"), READER_PROMPT);
            let input: Value = serde_json::from_str(&message(request, "user")).unwrap();
            let keys: BTreeSet<&str> = input
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(keys, BTreeSet::from(["question", "context"]));
            (
                input["question"].as_str().unwrap().to_owned(),
                input["context"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let expected: BTreeSet<(String, String)> = run.report["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["question"].as_str().unwrap().to_owned(),
                row["context"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(sent, expected);
    // No follow-up id and no rubric word reaches the reader; the shipped
    // texts use none of these words.
    let tasks = shipped_tasks();
    let markers: Vec<String> = tasks["follow_ups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap().to_owned())
        .chain(
            [
                "rubric",
                "gold_memory",
                "expect",
                "stale",
                "keep",
                "other_scope",
                "deleted_at",
            ]
            .map(str::to_owned),
        )
        .collect();
    for request in &run.requests {
        let text = request.to_string();
        for marker in &markers {
            assert!(
                !text.contains(marker.as_str()),
                "a request carries {marker}: {text}"
            );
        }
    }
    for row in rows(run, "none") {
        let question = row["question"].as_str().unwrap();
        let prompt = follow_up(&tasks, row["follow_up"].as_str().unwrap())["prompt"].clone();
        assert!(question.starts_with(prompt.as_str().unwrap()));
    }
}

#[test]
fn forced_replies_score_as_their_rubric_says_and_pairs_add_up() {
    let tasks = shipped_tasks();
    let prompt = |id: &str| follow_up(&tasks, id)["prompt"].as_str().unwrap().to_owned();
    let forced = BTreeMap::from([
        (
            prompt("owen-dentist"),
            r#"{"action": "book_appointment", "fields": {"provider": "Okafor"}}"#.to_owned(),
        ),
        (
            prompt("yuki-rent"),
            "```json\n{\"action\": \"make_payment\", \"fields\": {\"account\": \"joint\", \"reference\": \"MONTHLY\"}}\n```"
                .to_owned(),
        ),
        (prompt("mara-board"), "I would email the garden club committee.".to_owned()),
    ]);
    let run = run(forced);
    for arm in ARMS {
        let stale = &row(&run, arm, "owen-dentist")["score"];
        assert_eq!(stale["correction_persisted"], false);
        assert_eq!(stale["action_correct"], false);
        assert_eq!(stale["invalid"], false);
        let changed = &row(&run, arm, "yuki-rent")["score"];
        assert_eq!(
            changed["action_correct"], true,
            "the expected field is right"
        );
        assert_eq!(
            changed["unsupported_change"], true,
            "the kept reference changed"
        );
        let prose = &row(&run, arm, "mara-board")["score"];
        assert_eq!(prose["invalid"], true);
        assert_eq!(prose["action_correct"], false);
    }
    // Pairing by history, recomputed from the rows.
    let metric_of = |row: &Value, metric: &str| -> Option<f64> {
        row["score"][metric]
            .as_bool()
            .map(|hit| if hit { 1.0 } else { 0.0 })
    };
    let paired = run.report["paired"].as_array().unwrap();
    for arm in &ARMS[1..] {
        for metric in [
            "action_correct",
            "correction_persisted",
            "unsupported_change",
            "leaked",
            "reappeared",
        ] {
            let mut differences = Vec::new();
            for history in ["owen", "yuki", "mara"] {
                let mut pairs = Vec::new();
                for row in rows(&run, arm)
                    .into_iter()
                    .filter(|row| row["history"] == history)
                {
                    let none = self::row(&run, "none", row["follow_up"].as_str().unwrap());
                    if let (Some(mine), Some(base)) =
                        (metric_of(row, metric), metric_of(none, metric))
                    {
                        pairs.push((mine, base));
                    }
                }
                if !pairs.is_empty() {
                    let count = pairs.len() as f64;
                    differences.push(
                        pairs.iter().map(|(mine, _)| mine).sum::<f64>() / count
                            - pairs.iter().map(|(_, base)| base).sum::<f64>() / count,
                    );
                }
            }
            let reported = paired
                .iter()
                .find(|row| row["arm"] == *arm && row["metric"] == metric)
                .unwrap();
            let count = differences.len() as f64;
            let mean = differences.iter().sum::<f64>() / count;
            let variance = differences
                .iter()
                .map(|value| (value - mean).powi(2))
                .sum::<f64>()
                / (count - 1.0);
            assert_eq!(reported["histories"], 3);
            assert!((reported["paired_difference"].as_f64().unwrap() - mean).abs() < 1e-9);
            let error = reported["standard_error"].as_f64().unwrap();
            assert!(
                (error - (variance / count).sqrt()).abs() < 1e-9,
                "{reported}"
            );
        }
    }
    // Stage totals are the sums of their rows.
    for summary in run.report["summary"].as_array().unwrap() {
        let arm = summary["arm"].as_str().unwrap();
        let mine = rows(&run, arm);
        let sum = |key: &str| {
            mine.iter()
                .map(|row| row[key].as_u64().unwrap())
                .sum::<u64>()
        };
        assert_eq!(summary["follow_ups"], follow_up_count(&tasks));
        assert_eq!(summary["context_lines"], sum("context_lines"));
        assert_eq!(summary["recall_elapsed_us"], sum("recall_elapsed_us"));
        let input: u64 = mine
            .iter()
            .map(|row| row["reader"]["inputTokens"].as_u64().unwrap())
            .sum();
        assert_eq!(summary["reader"]["inputTokens"], input);
    }
}

#[test]
fn a_follow_up_missing_a_trace_part_stops_the_run() {
    let reader = start_reader(BTreeMap::new());
    let dir = tempfile::tempdir().unwrap();
    // Each case breaks one part of the shipped tasks; the run names the
    // follow-up (or history) and the part.
    let cases: [(&str, fn(&mut Value), &str); 6] = [
        (
            "owen-usual",
            |tasks| follow_up_mut(tasks, "owen-usual")["rubric"]["expect"] = json!({}),
            "grader",
        ),
        (
            "yuki-close",
            |tasks| {
                follow_up_mut(tasks, "yuki-close")["prompt"] =
                    json!("Set a reminder for 17:30 tomorrow.");
            },
            "leak",
        ),
        (
            "mara-taxi",
            |tasks| follow_up_mut(tasks, "mara-taxi")["tools"] = json!([]),
            "tools",
        ),
        (
            "owen-playlist",
            |tasks| follow_up_mut(tasks, "owen-playlist")["world"] = json!("moon"),
            "world",
        ),
        (
            "yuki-delivery",
            |tasks| {
                // The deleted office address stays in a turn the vault holds.
                for turn in history_mut(tasks, "yuki")["turns"].as_array_mut().unwrap() {
                    turn.as_object_mut().unwrap().remove("deleted_at");
                }
            },
            "world",
        ),
        (
            "mara",
            |tasks| {
                let mara = history_mut(tasks, "mara");
                let frozen_at = mara["frozen_at"].clone();
                for claim in mara["claims"].as_array_mut().unwrap() {
                    if claim.get("deleted_at").is_some() {
                        claim["deleted_at"] = frozen_at.clone();
                    }
                }
            },
            "world",
        ),
    ];
    for (id, break_part, part) in cases {
        let mut tasks = shipped_tasks();
        break_part(&mut tasks);
        let path = dir.path().join(format!("{id}.tasks.json"));
        std::fs::write(&path, tasks.to_string()).unwrap();
        let output = run_bench(&write_plan(dir.path(), &reader.endpoint, &path));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{id}: the run went ahead");
        assert!(
            stderr.contains(id) && stderr.contains(&format!("trace check, {part}")),
            "{stderr}"
        );
    }
    assert!(
        reader.requests.lock().unwrap().is_empty(),
        "a reader call before the check"
    );
}

#[test]
fn the_derived_arm_reads_the_follow_ups_world_and_never_the_other() {
    let run = shipped_run();
    let tasks = shipped_tasks();
    for id in SCOPED {
        let task = follow_up(&tasks, id);
        let rubric = &task["rubric"];
        let other = listed(&rubric["other_scope"]);
        for arm in ["derived", "raw_plus_derived"] {
            let row = row(run, arm, id);
            let claims: Vec<&str> = row["context"]
                .as_str()
                .unwrap()
                .lines()
                .filter(|line| line.starts_with("- CLAIM"))
                .collect();
            for value in rubric["expect"].as_object().unwrap().values() {
                let value = value.as_str().unwrap();
                assert!(claims.iter().any(|line| line.contains(value)), "{row}");
            }
            for value in &other {
                assert!(
                    claims.iter().all(|line| !line.contains(value.as_str())),
                    "{row}"
                );
            }
        }
        let derived = &row(run, "derived", id)["score"];
        assert_eq!(derived["action_correct"], true, "{derived}");
        assert_eq!(derived["leaked"], false, "{derived}");
        assert_eq!(row(run, "gold", id)["score"]["leaked"], false);
        assert_eq!(row(run, "none", id)["score"]["leaked"], true);
    }
    // A follow-up with no world reads base reality: no world's claim.
    for row in rows(run, "derived") {
        let task = follow_up(&tasks, row["follow_up"].as_str().unwrap());
        if task.get("world").is_some() {
            continue;
        }
        let shipped = history(&tasks, row["history"].as_str().unwrap());
        for claim in shipped["claims"].as_array().unwrap() {
            if claim.get("world").is_some() {
                let value = claim["value"].as_str().unwrap();
                assert!(!row["context"].as_str().unwrap().contains(value), "{row}");
            }
        }
        assert_eq!(row["score"]["leaked"], Value::Null);
    }
    let worlds: BTreeMap<&str, usize> = run.report["histories"]
        .as_array()
        .unwrap()
        .iter()
        .map(|reported| {
            (
                reported["history"].as_str().unwrap(),
                reported["worlds_created"].as_u64().unwrap() as usize,
            )
        })
        .collect();
    for (id, created) in worlds {
        assert_eq!(
            created,
            history(&tasks, id)["worlds"].as_array().unwrap().len()
        );
    }
}

#[test]
fn a_deleted_claim_and_turn_reach_no_arm() {
    let run = shipped_run();
    let tasks = shipped_tasks();
    // Every deleted value of a history, from its deletion follow-ups.
    let mut deleted: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for id in DELETIONS {
        let task = follow_up(&tasks, id);
        deleted
            .entry(task["history"].as_str().unwrap().to_owned())
            .or_default()
            .extend(listed(&task["rubric"]["deleted"]));
    }
    for row in run.report["rows"].as_array().unwrap() {
        let context = row["context"].as_str().unwrap();
        for value in &deleted[row["history"].as_str().unwrap()] {
            assert!(!context.contains(value.as_str()), "{row}");
        }
    }
    for id in DELETIONS {
        for arm in &ARMS[1..] {
            assert_eq!(
                row(run, arm, id)["score"]["reappeared"],
                false,
                "{arm} {id}"
            );
        }
        assert_eq!(row(run, "none", id)["score"]["reappeared"], true);
        assert_eq!(row(run, "derived", id)["score"]["action_correct"], true);
    }
    for reported in run.report["histories"].as_array().unwrap() {
        let shipped = history(&tasks, reported["history"].as_str().unwrap());
        let marked = ["turns", "claims"]
            .iter()
            .flat_map(|key| shipped[*key].as_array().unwrap())
            .filter(|item| item.get("deleted_at").is_some())
            .count();
        assert!(marked > 0);
        assert_eq!(reported["items_deleted"], marked, "{reported}");
    }
}

/// Each expected value of a follow-up's rubric, lower-cased.
fn expected(task: &Value) -> Vec<String> {
    task["rubric"]["expect"]
        .as_object()
        .unwrap()
        .values()
        .map(|value| value.as_str().unwrap().to_lowercase())
        .collect()
}

#[test]
fn the_online_arm_reads_the_correction_first_and_the_background_arm_after_its_sitting() {
    let run = extraction_run();
    let tasks = shipped_tasks();
    for id in CORRECTIONS {
        let task = follow_up(&tasks, id);
        let history = task["history"].as_str().unwrap();
        let new = expected(&task);
        let context = |arm: &str, probe: &str| {
            probe_row(run, arm, probe, id)["context"]
                .as_str()
                .unwrap()
                .to_lowercase()
        };
        // The correcting turn sits in a sitting that has not ended, so no
        // lane of the background arm has read it; its first sitting's end
        // ran the Meso lane, so it reads that sitting's claims.
        let background = context("extract_background", "after_correction");
        assert!(!background.is_empty(), "{id}: the first sitting's claims");
        for value in &new {
            assert!(!background.contains(value.as_str()), "{id}: {background}");
        }
        // The Micro lane ran after the correcting turn: its correction is
        // served, or the engine kept it as Proposed (RULING
        // L9-34-EXTRACT-PENDED = A: measured as it runs, counted pended).
        for arm in ["extract_online", "extract_combined"] {
            for probe in ["after_correction", "after_consolidation"] {
                let read = context(arm, probe);
                let pended = probe_tally(run, history, arm, probe)["claims_pended"]
                    .as_u64()
                    .unwrap();
                assert!(!read.is_empty(), "{id} {arm} {probe}");
                assert!(
                    new.iter().all(|value| read.contains(value.as_str())) || pended > 0,
                    "{id} {arm} {probe}: {read} {}",
                    extraction_row(run, history, arm)
                );
            }
        }
        // At the freeze the background arm's lanes have read every sitting.
        let read = context("extract_background", "after_consolidation");
        let pended =
            probe_tally(run, history, "extract_background", "after_consolidation")["claims_pended"]
                .as_u64()
                .unwrap();
        assert!(
            new.iter().all(|value| read.contains(value.as_str())) || pended > 0,
            "{id}: {read} {}",
            extraction_row(run, history, "extract_background")
        );
    }
    // The first probe reads only corrected-source follow-ups; the second
    // reads every follow-up.
    for arm in &EXTRACTION_ARMS[1..] {
        let first: BTreeSet<&str> = rows(run, arm)
            .iter()
            .filter(|row| row["probe"] == "after_correction")
            .map(|row| row["follow_up"].as_str().unwrap())
            .collect();
        assert_eq!(first, BTreeSet::from(CORRECTIONS));
        let second = rows(run, arm)
            .iter()
            .filter(|row| row["probe"] == "after_consolidation")
            .count();
        assert_eq!(second, follow_up_count(&tasks));
    }
}

#[test]
fn the_extraction_arms_serve_only_claims_their_dreamer_extracted() {
    let run = extraction_run();
    let tasks = shipped_tasks();
    let said: Vec<String> = said_in_turns(&tasks)
        .into_iter()
        .filter(|(_, predicates)| !predicates.is_empty())
        .map(|(text, _)| text.to_lowercase())
        .collect();
    let authored: Vec<String> = tasks["histories"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|history| history["claims"].as_array().unwrap())
        .map(|claim| claim["value"].as_str().unwrap().to_lowercase())
        .collect();
    for arm in &EXTRACTION_ARMS[1..] {
        let mut lines = 0;
        for row in rows(run, arm) {
            for line in row["context"].as_str().unwrap().lines() {
                // Every line is a claim whose value is a user turn's own
                // words: the loopback extractor's, never an authored value.
                let line = line.to_lowercase();
                assert!(line.starts_with("- claim "), "{arm}: {line}");
                assert!(
                    said.iter().any(|text| line.contains(text.as_str())),
                    "{arm}: {line}"
                );
                assert!(
                    authored.iter().all(|value| !line.contains(value.as_str())),
                    "{arm}: {line}"
                );
                lines += 1;
            }
        }
        assert!(lines > 0, "{arm} served no claim");
    }
    // No listing the extractor saw held an authored claim: none entered an
    // extraction vault.
    assert!(!run.dreamer.is_empty());
    for call in &run.dreamer {
        let text = call.request.to_string().to_lowercase();
        for value in &authored {
            assert!(!text.contains(value.as_str()), "{value}: {text}");
        }
    }
    for history in ["owen", "yuki", "mara"] {
        for arm in &EXTRACTION_ARMS[1..] {
            let row = extraction_row(run, history, arm);
            let landed = row["probes"][1]["claims_landed"].as_u64().unwrap();
            assert!(landed > 0, "{row}");
        }
    }
}

#[test]
fn the_extractor_never_sees_a_rubric_or_a_follow_up() {
    let run = extraction_run();
    let tasks = shipped_tasks();
    let extraction_calls = run
        .dreamer
        .iter()
        .filter(|call| system_text(&call.request).starts_with(EXTRACTION_SYSTEM))
        .count();
    assert!(extraction_calls > 0);
    let mut markers: Vec<String> = Vec::new();
    for item in tasks["follow_ups"].as_array().unwrap() {
        markers.push(item["id"].as_str().unwrap().to_lowercase());
        markers.push(item["prompt"].as_str().unwrap().to_lowercase());
        for line in item["gold_memory"].as_array().unwrap() {
            markers.push(line.as_str().unwrap().to_lowercase());
        }
    }
    markers.extend(["rubric", "gold_memory", "other_scope", "deleted_at"].map(str::to_owned));
    for call in &run.dreamer {
        let texts: String = call.request["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(text_of)
            .collect::<Vec<_>>()
            .join("\n")
            .to_lowercase();
        for marker in &markers {
            assert!(!texts.contains(marker.as_str()), "a call carries {marker}");
        }
    }
    // The reader still sees only `{question, context}`.
    for request in &run.requests {
        assert_eq!(message(request, "system"), READER_PROMPT);
    }
}

#[test]
fn extraction_stage_costs_add_up() {
    let run = extraction_run();
    let tasks = shipped_tasks();
    let rows = run.report["extraction"].as_array().unwrap();
    assert_eq!(rows.len(), 3 * (EXTRACTION_ARMS.len() - 1));
    assert_eq!(run.report["extraction_model"], EXTRACTION_MODEL);
    assert_eq!(run.report["extraction_locality"], "own_server");
    assert!(
        run.report["extraction_arms_mapping"]
            .as_str()
            .unwrap()
            .contains("LightMem")
    );
    let sum = |key: &str| -> u64 {
        rows.iter()
            .map(|row| row["extraction"][key].as_u64().unwrap())
            .sum()
    };
    let calls: u64 = rows
        .iter()
        .map(|row| row["probes"][1]["model_calls"].as_u64().unwrap())
        .sum();
    assert_eq!(calls, run.dreamer.len() as u64);
    assert_eq!(
        sum("inputTokens"),
        run.dreamer
            .iter()
            .map(|call| call.prompt_tokens)
            .sum::<u64>()
    );
    assert_eq!(
        sum("outputTokens"),
        run.dreamer
            .iter()
            .map(|call| call.completion_tokens)
            .sum::<u64>()
    );
    let lanes_of = |arm: &str| -> BTreeSet<String> {
        match arm {
            "extract_online" => ["micro"].map(str::to_owned).into(),
            "extract_background" => ["meso", "macro"].map(str::to_owned).into(),
            _ => ["micro", "meso", "macro"].map(str::to_owned).into(),
        }
    };
    for row in rows {
        let arm = row["arm"].as_str().unwrap();
        let lanes = row["lanes"].as_array().unwrap();
        let named: BTreeSet<String> = lanes
            .iter()
            .map(|lane| lane["lane"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(named, lanes_of(arm), "{row}");
        let lane_calls: u64 = lanes
            .iter()
            .map(|lane| lane["model_calls"].as_u64().unwrap())
            .sum();
        assert_eq!(row["probes"][1]["model_calls"], lane_calls, "{row}");
        assert!(
            row["probes"][0]["model_calls"].as_u64().unwrap() <= lane_calls,
            "{row}"
        );
        assert_eq!(row["failed_calls"], 0, "{row}");
        let shipped = history(&tasks, row["history"].as_str().unwrap());
        let frozen_at = shipped["frozen_at"].as_u64().unwrap();
        let before: Vec<&Value> = shipped["turns"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|turn| turn["at"].as_u64().unwrap() < frozen_at)
            .collect();
        assert_eq!(row["turns_witnessed"], before.len(), "{row}");
        assert_eq!(
            row["items_deleted"],
            before
                .iter()
                .filter(|turn| turn.get("deleted_at").is_some())
                .count(),
            "{row}"
        );
        // The first sitting's turns, then the correction and the forget
        // turn more than 30 min later.
        assert_eq!(row["sittings"], 2, "{row}");
    }
}

#[test]
fn an_extraction_arm_needs_its_pin_and_a_history_with_a_correction() {
    let reader = start_reader(BTreeMap::new());
    let dir = tempfile::tempdir().unwrap();
    let unpinned = run_bench(&write_plan_with(
        dir.path(),
        &reader.endpoint,
        &shipped_tasks_path(),
        &EXTRACTION_ARMS,
        false,
    ));
    assert!(!unpinned.status.success());
    assert!(
        String::from_utf8_lossy(&unpinned.stderr).contains("extraction pin"),
        "{}",
        String::from_utf8_lossy(&unpinned.stderr)
    );
    // Owen's history without the dentist correction has no correction point.
    let mut tasks = shipped_tasks();
    let owen = history_mut(&mut tasks, "owen");
    owen["claims"]
        .as_array_mut()
        .unwrap()
        .retain(|claim| claim["at"] != 1_780_005_000_u64);
    for task in tasks["follow_ups"].as_array_mut().unwrap() {
        if task["id"] == "owen-dentist" {
            task["kind"] = json!("stable_definition");
            task["rubric"].as_object_mut().unwrap().remove("stale");
        }
    }
    let path = dir.path().join("uncorrected.tasks.json");
    std::fs::write(&path, tasks.to_string()).unwrap();
    let uncorrected = run_bench(&write_plan_with(
        dir.path(),
        &reader.endpoint,
        &path,
        &EXTRACTION_ARMS,
        true,
    ));
    let stderr = String::from_utf8_lossy(&uncorrected.stderr);
    assert!(!uncorrected.status.success());
    assert!(
        stderr.contains("owen") && stderr.contains("trace check, world"),
        "{stderr}"
    );
    assert!(reader.dreamer.lock().unwrap().is_empty());
    assert!(reader.requests.lock().unwrap().is_empty());
}
