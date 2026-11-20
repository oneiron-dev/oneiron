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

/// The loopback reader and every request body it was sent.
struct Reader {
    endpoint: String,
    requests: Arc<Mutex<Vec<Value>>>,
}

/// Starts the loopback reader. `forced` maps a follow-up prompt to the reply
/// the reader gives it, whatever the context.
fn start_reader(forced: BTreeMap<String, String>) -> Reader {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&requests);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            serve(stream, &forced, &kept);
        }
    });
    Reader { endpoint, requests }
}

fn serve(mut stream: TcpStream, forced: &BTreeMap<String, String>, kept: &Mutex<Vec<Value>>) {
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
    let input: Value = serde_json::from_str(&message(&request, "user")).unwrap();
    let question = input["question"].as_str().unwrap();
    let context = input["context"].as_str().unwrap();
    let prompt = question.split("\n\nTools:").next().unwrap();
    let reply = forced
        .get(prompt)
        .cloned()
        .unwrap_or_else(|| act(question, context));
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
            "prompt_tokens": body.len() / 4 + 1,
            "completion_tokens": reply.len() / 4 + 1,
            "total_tokens": body.len() / 4 + reply.len() / 4 + 2,
        },
    })
    .to_string();
    kept.lock().unwrap().push(request);
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
        response.len()
    )
    .unwrap();
}

/// A request message's text, by role.
fn message(request: &Value, role: &str) -> String {
    let message = request["messages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|message| message["role"] == role)
        .unwrap();
    match &message["content"] {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect(),
        other => panic!("unexpected content {other}"),
    }
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
    let plan = json!({
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
        "arms": ARMS,
        "recall_limit": 10,
    });
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

/// One run over the shipped tasks with no forced reply: its report and the
/// requests the reader was sent.
struct Run {
    report: Value,
    requests: Vec<Value>,
}

fn run(forced: BTreeMap<String, String>) -> Run {
    let reader = start_reader(forced);
    let dir = tempfile::tempdir().unwrap();
    let output = run_bench(&write_plan(
        dir.path(),
        &reader.endpoint,
        &shipped_tasks_path(),
    ));
    assert!(
        output.status.success(),
        "the bench run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = serde_json::from_slice(&output.stdout).unwrap();
    let requests = reader.requests.lock().unwrap().clone();
    Run { report, requests }
}

fn shipped_run() -> &'static Run {
    static RUN: OnceLock<Run> = OnceLock::new();
    RUN.get_or_init(|| run(BTreeMap::new()))
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
