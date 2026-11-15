//! `oneiron-bench load lives` (census L9-36; ARCH-0042 #lives-bench): the
//! synthetic-lives screen ingests the same lives into each system, asks the
//! same questions, and reports accuracy and latency on every row. These
//! tests drive the shipped bench binary with `--in-process`, so every request
//! goes through the real facade router (`oneiron_server::build_app`) over
//! loopback HTTP: `vault.witness` per turn, `vault.recall` per question.
//! On a tree without the subcommand, `load` prints its usage and exits 1.
//!
//! Other systems join through the adapter protocol (`--system <name>=<url>`);
//! the tests serve a stub adapter in their own process. The judged column
//! (`--reader`, `--judge`) calls OpenAI-compatible endpoints; the tests serve
//! a stub model there too.
//!
//! `cargo test --locked -p oneiron-bench --test lives_bench_cli`.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex, OnceLock};

use axum::Json;
use axum::extract::{Path as UrlPath, State};
use axum::http::HeaderMap;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

/// Two invented English lives (L90001 Rina Okafor, L90002 Tomasz Weller),
/// 28 turns in all, in the generation run's format.
fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/lives_screen.v1.jsonl")
}

/// One `load lives --in-process` run over `lives`; the report when it wrote one.
fn lives(dir: &Path, lives: &[&Path], extra: &[&str]) -> (Output, Option<Value>) {
    let out = dir.join("report.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_oneiron-bench"));
    command.args(["load", "lives", "--in-process", "--embedder", "none"]);
    for path in lives {
        command.arg("--lives").arg(path);
    }
    let output = command
        .arg("--work")
        .arg(dir.join("work"))
        .arg("--out")
        .arg(&out)
        .args(["--settle-max-seconds", "60"])
        .args(extra)
        .output()
        .expect("the bench binary runs");
    let report = std::fs::read_to_string(&out)
        .ok()
        .map(|text| serde_json::from_str(&text).expect("the report is JSON"));
    (output, report)
}

fn succeeded(output: &Output) {
    assert!(
        output.status.success(),
        "load lives exited {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The two-grade screen over the fixture, run once for the tests that read it.
fn screen() -> &'static (Output, Option<Value>) {
    static SCREEN: OnceLock<(Output, Option<Value>)> = OnceLock::new();
    SCREEN.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        lives(
            dir.path(),
            &[&fixture()],
            &["--grades", "light,medium", "--limit", "5"],
        )
    })
}

fn system(report: &Value) -> &Value {
    let systems = report["systems"].as_array().expect("systems");
    assert_eq!(systems.len(), 1, "one system: {systems:?}");
    assert_eq!(systems[0]["name"], "oneiron");
    &systems[0]
}

fn rows<'r>(system: &'r Value, grade: &str) -> Vec<&'r Value> {
    system["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .filter(|row| row["grade"] == grade)
        .collect()
}

fn row<'r>(rows: &[&'r Value], life: &str, qid: &str) -> &'r Value {
    let found = rows
        .iter()
        .filter(|row| row["life"] == life && row["qid"] == qid)
        .collect::<Vec<_>>();
    assert_eq!(found.len(), 1, "one row for {life} {qid}");
    *found[0]
}

#[test]
fn the_screen_asks_every_question_once_per_grade_and_scores_the_string_ones() {
    let (output, report) = screen();
    succeeded(output);
    let system = system(report.as_ref().expect("a report"));
    let summaries = system["summary"].as_array().expect("summary");
    assert_eq!(summaries.len(), 2);
    for (grade, summary) in ["light", "medium"].into_iter().zip(summaries) {
        let rows = rows(system, grade);
        // L90001: q01-q05 and j01; L90002: q01-q04.
        assert_eq!(rows.len(), 10, "{grade}: one row per question");
        let asked = rows
            .iter()
            .map(|r| {
                format!(
                    "{}/{}",
                    r["life"].as_str().unwrap(),
                    r["qid"].as_str().unwrap()
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(asked.len(), 10, "{grade}: no question asked twice");
        for life in ["L90001", "L90002"] {
            let unanswerable = row(&rows, life, "q03");
            assert_eq!(unanswerable["scored"], false);
            assert_eq!(unanswerable["unscored_reason"], "unanswerable");
            let unchecked = row(&rows, life, "q04");
            assert_eq!(unchecked["scored"], false);
            assert_eq!(unchecked["unscored_reason"], "unchecked_support");
        }
        let scored = rows.iter().filter(|r| r["scored"] == true).count();
        assert_eq!(scored, 6, "{grade}: L90001 q01 q02 q05 j01, L90002 q01 q02");
        for (life, qid) in [
            ("L90001", "q01"),
            ("L90001", "q02"),
            ("L90001", "q05"),
            ("L90002", "q01"),
            ("L90002", "q02"),
        ] {
            let r = row(&rows, life, qid);
            assert_eq!(r["answer_in_context"], true, "{grade} {life} {qid}: {r}");
            let rank = r["evidence_rank"].as_u64().unwrap_or(0);
            assert!((1..=5).contains(&rank), "{grade} {life} {qid}: {r}");
        }
        // A line of a tool turn names its turn as the evidence.
        assert_eq!(row(&rows, "L90001", "q05")["evidence_turn"], "d2s1t04");
        assert_eq!(row(&rows, "L90001", "j01")["set"], "ja_cross");
        // Each question asks at the end of its own life's last day (UTC).
        assert_eq!(row(&rows, "L90001", "q01")["as_of"], 1_741_651_200);
        assert_eq!(row(&rows, "L90002", "q01")["as_of"], 1_744_675_200);
        for r in &rows {
            assert!(r["ms"].as_f64().unwrap() > 0.0, "{r}");
            assert!(r["error"].is_null(), "{r}");
        }
        let count = |field: &str| rows.iter().filter(|r| r[field] == true).count();
        let hits = rows.iter().filter(|r| r["evidence_rank"].is_u64()).count();
        assert_eq!(summary["grade"], grade);
        assert_eq!(summary["rows"], 10);
        assert_eq!(summary["errors"], 0);
        assert_eq!(summary["scored"], scored);
        assert_eq!(summary["answer_in_context"], count("answer_in_context"));
        assert_eq!(summary["evidence_hit"], hits);
        assert_eq!(summary["by_set"]["ja_cross"]["scored"], 1);
        assert_eq!(summary["by_type"]["past_at_time"]["scored"], 1);
    }
}

#[test]
fn latency_below_the_corpus_floor_reads_not_applicable() {
    let (output, report) = screen();
    succeeded(output);
    let report = report.as_ref().expect("a report");
    let system = system(report);
    assert_eq!(report["corpus"]["documents"], 28);
    assert_eq!(system["documents"], 28);
    for summary in system["summary"].as_array().unwrap() {
        let latency = &summary["latency"];
        assert_eq!(latency["latency_status"], "not_measured", "{summary}");
        assert_eq!(latency["latency_reason"], "corpus_below_1000_documents");
        assert!(latency["p50_ms"].is_null() && latency["p95_ms"].is_null());
        assert_eq!(latency["completed"], 10);
    }
}

/// One life of `turns` generated turns over 50-turn days, with three string
/// questions.
fn long_life(path: &Path, turns: usize) {
    let syllables = ["ka", "zu", "ri", "mo", "te", "la", "pi", "no", "sa", "vu"];
    let word = |i: usize| {
        format!(
            "{}{}{}",
            syllables[i % 10],
            syllables[(i / 10) % 10],
            syllables[(i / 100) % 10]
        )
    };
    let days = (0..turns.div_ceil(50))
        .map(|d| {
            let turns = (d * 50..turns.min(d * 50 + 50))
                .map(|i| {
                    json!({
                        "id": format!("d{}s1t{:02}", d + 1, i - d * 50 + 1),
                        "role": if i % 2 == 0 { "user" } else { "assistant" },
                        "text": format!("note {i}: item {}", word(i)),
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "date": format!("2025-05-{:02}", d + 1),
                "sessions": [{"sid": format!("d{}s1", d + 1), "turns": turns}],
            })
        })
        .collect::<Vec<_>>();
    let questions = [7, 333, 1001]
        .map(|i| {
            json!({
                "qid": format!("q{i}"),
                "type": "current",
                "question": format!("Which item is in note {i}?"),
                "answer_span": word(i),
                "evidence": [format!("d{}s1t{:02}", i / 50 + 1, i % 50 + 1)],
                "support": "string",
            })
        })
        .to_vec();
    let life = json!({"life_id": "L9L0001", "lang": "en", "days": days, "questions": questions});
    std::fs::write(path, format!("{life}\n")).unwrap();
}

#[test]
fn a_store_past_the_floor_reports_p50_and_p95() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lives-long.jsonl");
    long_life(&path, 1_050);
    let (output, report) = lives(dir.path(), &[&path], &["--grades", "light"]);
    succeeded(&output);
    let report = report.expect("a report");
    let system = system(&report);
    assert_eq!(report["corpus"]["documents"], 1_050);
    assert_eq!(system["documents"], 1_050);
    let latency = &system["summary"][0]["latency"];
    assert_eq!(latency["latency_status"], "measured", "{latency}");
    let p50 = latency["p50_ms"].as_f64().expect("p50_ms");
    let p95 = latency["p95_ms"].as_f64().expect("p95_ms");
    assert!(0.0 < p50 && p50 <= p95, "{latency}");
    assert_eq!(system["ingest"]["latency_status"], "measured");
}

fn picked(report: &Value) -> Vec<String> {
    report["corpus"]["lives"]
        .as_array()
        .expect("corpus.lives")
        .iter()
        .map(|life| life["life"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn the_screen_pick_is_seeded_and_reported() {
    let fixture = fixture();
    let digest = Sha256::digest(std::fs::read(&fixture).unwrap())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let mut picks = Vec::new();
    for _ in 0..2 {
        let dir = tempfile::tempdir().unwrap();
        let (output, report) = lives(
            dir.path(),
            &[&fixture],
            &[
                "--sample",
                "1",
                "--seed",
                "7",
                "--min-turns",
                "1",
                "--grades",
                "light",
            ],
        );
        succeeded(&output);
        let report = report.expect("a report");
        let files = report["corpus"]["files"].as_array().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0]["sha256"], digest.as_str());
        picks.push(picked(&report));
    }
    assert_eq!(
        picks[0].len(),
        1,
        "one life when one already clears the floor"
    );
    assert_eq!(picks[0], picks[1], "the same seed picks the same life");
    // Under the default floor of 1,000 turns the pick grows until the corpus ends.
    let dir = tempfile::tempdir().unwrap();
    let (output, report) = lives(
        dir.path(),
        &[&fixture],
        &["--sample", "1", "--seed", "7", "--grades", "light"],
    );
    succeeded(&output);
    let mut grown = picked(&report.expect("a report"));
    assert_eq!(
        grown[0], picks[0][0],
        "the grown pick starts where the seed does"
    );
    grown.sort();
    assert_eq!(grown, ["L90001", "L90002"]);
}

#[test]
fn a_network_embedder_endpoint_is_refused_before_any_vault() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oneiron-bench"))
        .args(["load", "lives", "--server", "oneiron-server", "--embedder"])
        .arg("endpoint=http://192.0.2.10:8080/v1,bge-m3,bge-m3@r1,1024")
        .arg("--lives")
        .arg(fixture())
        .arg("--work")
        .arg(dir.path().join("work"))
        .arg("--out")
        .arg(dir.path().join("report.json"))
        .output()
        .expect("the bench binary runs");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("192.0.2.10") && stderr.contains("loopback"),
        "stderr names the url and the loopback rule: {stderr}"
    );
    assert!(!dir.path().join("work").exists(), "no vault was made");
}

#[test]
fn a_life_without_days_is_refused_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lives-broken.jsonl");
    std::fs::write(
        &path,
        format!(
            "{}\n",
            json!({"life_id": "L9X0001", "lang": "en", "questions": []})
        ),
    )
    .unwrap();
    let (output, report) = lives(dir.path(), &[&path], &[]);
    assert!(!output.status.success());
    assert!(report.is_none(), "no report for a refused corpus");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("L9X0001") && stderr.contains("days"),
        "stderr names the life and the missing field: {stderr}"
    );
}

/// Every request a stub adapter took: its operation and its body.
type Seen = Arc<Mutex<Vec<(String, Value)>>>;

#[derive(Clone)]
struct StubState {
    seen: Seen,
    ready: bool,
    /// Settle polls after this many never answer (an adapter that hangs).
    hang_after: Option<usize>,
}

/// A stub adapter on loopback, in this test's own runtime.
struct Stub {
    url: String,
    seen: Seen,
    _runtime: tokio::runtime::Runtime,
}

/// Lower-case words of three characters or more.
fn words(text: &str) -> BTreeSet<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.chars().count() >= 3)
        .map(str::to_owned)
        .collect()
}

/// It records every request, and ranks a search over the turns its store took
/// by how many words they share with the query (ties in ingest order; a turn
/// sharing none is not returned), each answer timed at `system_ms: 1.5`.
async fn stub_call(
    State(state): State<StubState>,
    UrlPath(op): UrlPath<String>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let polled = {
        let mut seen = state.seen.lock().unwrap();
        seen.push((op.clone(), body.clone()));
        seen.iter().filter(|(op, _)| op == "settle").count()
    };
    if op == "settle" && state.hang_after.is_some_and(|after| polled > after) {
        // Longer than the bench client's own 600 s bound.
        tokio::time::sleep(std::time::Duration::from_secs(3_600)).await;
    }
    let seen = state.seen.lock().unwrap();
    let answer = match op.as_str() {
        "settle" => json!({"ready": state.ready}),
        "ingest" => json!({"system_ms": 1.5}),
        "search" => {
            let query = words(body["query"].as_str().unwrap_or(""));
            let k = usize::try_from(body["k"].as_u64().unwrap_or(10)).unwrap();
            let mut ranked = seen
                .iter()
                .filter(|(op, turn)| op == "ingest" && turn["store"] == body["store"])
                .enumerate()
                .map(|(order, (_, turn))| {
                    let text = turn["turn"]["text"].as_str().unwrap_or("").to_owned();
                    (query.intersection(&words(&text)).count(), order, text)
                })
                .filter(|(shared, _, _)| *shared > 0)
                .collect::<Vec<_>>();
            ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
            let items = ranked
                .into_iter()
                .take(k)
                .map(|(_, _, text)| json!({"text": text}))
                .collect::<Vec<_>>();
            json!({"items": items, "system_ms": 1.5})
        }
        _ => json!({}),
    };
    Json(answer)
}

fn stub(ready: bool) -> Stub {
    stub_hanging(ready, None)
}

/// A stub whose settle polls after `hang_after` of them never answer.
fn stub_hanging(ready: bool, hang_after: Option<usize>) -> Stub {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let seen = Seen::default();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let app = axum::Router::new()
        .route("/v1/lives/{op}", axum::routing::post(stub_call))
        .with_state(StubState {
            seen: Arc::clone(&seen),
            ready,
            hang_after,
        });
    runtime.spawn(async move { axum::serve(listener, app).await });
    Stub {
        url,
        seen,
        _runtime: runtime,
    }
}

/// The fixture's turns in file order: (life, turn id, text as ingested).
fn fixture_turns() -> Vec<(String, String, String)> {
    let mut turns = Vec::new();
    for line in std::fs::read_to_string(fixture()).unwrap().lines() {
        let life: Value = serde_json::from_str(line).unwrap();
        for day in life["days"].as_array().unwrap() {
            for session in day["sessions"].as_array().unwrap() {
                for turn in session["turns"].as_array().unwrap() {
                    let text = turn["text"].as_str().map_or_else(
                        || {
                            let lines = turn["lines"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|l| l.as_str().unwrap())
                                .collect::<Vec<_>>();
                            format!("{}\n{}", turn["tool"].as_str().unwrap(), lines.join("\n"))
                        },
                        str::to_owned,
                    );
                    turns.push((
                        life["life_id"].as_str().unwrap().to_owned(),
                        turn["id"].as_str().unwrap().to_owned(),
                        text,
                    ));
                }
            }
        }
    }
    turns
}

#[test]
fn an_external_system_gets_the_same_lives_and_questions() {
    let stub = stub(true);
    let dir = tempfile::tempdir().unwrap();
    let system = format!("stub={}", stub.url);
    let (output, report) = lives(
        dir.path(),
        &[&fixture()],
        &[
            "--grades",
            "light,medium",
            "--limit",
            "5",
            "--system",
            &system,
        ],
    );
    succeeded(&output);
    let report = report.expect("a report");
    let systems = report["systems"].as_array().expect("systems");
    assert_eq!(systems.len(), 2);
    let (oneiron, stubbed) = (&systems[0], &systems[1]);
    assert_eq!(oneiron["name"], "oneiron");
    assert_eq!(stubbed["name"], "stub");
    assert_eq!(stubbed["status"], "measured", "{stubbed}");
    let seen = stub.seen.lock().unwrap().clone();
    // The same input: every fixture turn once, in fixture order, with its text.
    let ingested = seen
        .iter()
        .filter(|(op, _)| op == "ingest")
        .map(|(_, body)| body)
        .collect::<Vec<_>>();
    let expected = fixture_turns();
    assert_eq!(ingested.len(), expected.len());
    assert_eq!(report["corpus"]["documents"], ingested.len());
    assert_eq!(stubbed["documents"], ingested.len());
    for (body, (_, id, text)) in ingested.iter().zip(&expected) {
        assert_eq!(body["turn"]["id"], id.as_str());
        assert_eq!(body["turn"]["text"], text.as_str());
    }
    // The times every system is given: a day's 09:00 UTC plus 20 s a turn.
    assert_eq!(ingested[0]["at"], 1_740_992_400, "L90001 d1s1t01");
    assert_eq!(ingested[11]["turn"]["role"], "tool");
    assert_eq!(ingested[11]["at"], 1_741_597_260, "L90001 d2s1t04");
    let conversations = ingested
        .iter()
        .map(|body| body["conversation"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(conversations.len(), 4, "one conversation per session");
    // The same questions at the same grades, each at its life's end.
    let keys = |system: &Value| {
        system["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| format!("{}/{}/{}/{}", r["life"], r["qid"], r["grade"], r["as_of"]))
            .collect::<BTreeSet<_>>()
    };
    assert_eq!(keys(stubbed).len(), 20);
    assert_eq!(keys(oneiron), keys(stubbed));
    // One untimed search per grade first (the first question, as Oneiron's
    // warm-up recall), then one search per question per grade.
    let searches = seen
        .iter()
        .filter(|(op, _)| op == "search")
        .map(|(_, body)| body)
        .collect::<Vec<_>>();
    assert_eq!(
        searches.len(),
        2 + 20,
        "a warm-up and one search per question, per grade"
    );
    for warm in [searches[0], searches[11]] {
        assert_eq!(warm["query"], searches[1]["query"], "{warm}");
        assert_eq!(warm["as_of"], searches[1]["as_of"], "{warm}");
    }
    for grade in ["light", "medium"] {
        let rows = rows(stubbed, grade);
        for r in &rows {
            assert!(r["ms"].as_f64().unwrap() > 0.0, "{r}");
            assert_eq!(r["system_ms"], 1.5, "{r}");
        }
        // The stub's key puts each English string question's evidence first.
        for (life, qid) in [
            ("L90001", "q01"),
            ("L90001", "q02"),
            ("L90001", "q05"),
            ("L90002", "q01"),
            ("L90002", "q02"),
        ] {
            let r = row(&rows, life, qid);
            assert_eq!(r["answer_in_context"], true, "{grade} {life} {qid}: {r}");
            assert_eq!(r["evidence_rank"], 1, "{grade} {life} {qid}: {r}");
        }
        // The Japanese question shares no word with an English turn.
        let japanese = row(&rows, "L90001", "j01");
        assert_eq!(japanese["items"], 0);
        assert_eq!(japanese["answer_in_context"], false);
        let summary = stubbed["summary"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["grade"] == grade)
            .unwrap();
        assert_eq!(summary["answer_in_context"], 5);
        assert_eq!(summary["system_latency"]["completed"], 10, "{summary}");
    }
}

#[test]
fn a_plain_http_adapter_off_loopback_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (output, report) = lives(
        dir.path(),
        &[&fixture()],
        &["--system", "x=http://10.0.0.1:9"],
    );
    assert!(!output.status.success());
    assert!(report.is_none(), "refused before any store is opened");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("https") && stderr.contains("loopback"),
        "stderr names the rule: {stderr}"
    );
}

/// The adapter answers its first settle poll `ready: false` and never
/// answers the next: the wait still ends at `--settle-max-seconds`.
#[test]
fn an_adapter_that_never_settles_is_not_ready_and_the_rest_still_run() {
    let stub = stub_hanging(false, Some(1));
    let dir = tempfile::tempdir().unwrap();
    let system = format!("stub={}", stub.url);
    let (output, report) = lives(
        dir.path(),
        &[&fixture()],
        &[
            "--grades",
            "light",
            "--system",
            &system,
            "--settle-max-seconds",
            "2",
        ],
    );
    succeeded(&output);
    let report = report.expect("a report");
    let systems = report["systems"].as_array().expect("systems");
    assert_eq!(systems.len(), 2);
    assert_eq!(systems[0]["name"], "oneiron");
    assert_eq!(systems[0]["status"], "measured");
    assert_eq!(systems[0]["rows"].as_array().unwrap().len(), 10);
    let stubbed = &systems[1];
    assert_eq!(stubbed["status"], "not_ready", "{stubbed}");
    assert_eq!(
        stubbed["reason"], "not ready after 2 s: the settle poll did not answer",
        "{stubbed}"
    );
    assert_eq!(stubbed["rows"].as_array().unwrap().len(), 0);
    let settles = stub
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|(op, _)| op == "settle")
        .count();
    assert!(settles >= 2, "settle was polled: {settles}");
}

/// The key the judged run's endpoints take; it must reach them and nothing else.
const MODEL_KEY: &str = "stub-model-key-7f3a91";

/// Every call a stub model took: (model, Authorization header, reply).
type Calls = Arc<Mutex<Vec<(String, String, String)>>>;

#[derive(Clone)]
struct ModelState {
    /// The fixture's questions by text, each with its gold answer span.
    spans: Arc<BTreeMap<String, Option<String>>>,
    calls: Calls,
}

/// A stub OpenAI-compatible endpoint on loopback, in this test's own runtime.
struct ModelStub {
    /// Ends where `/chat/completions` follows.
    base_url: String,
    calls: Calls,
    _runtime: tokio::runtime::Runtime,
}

/// Lower case with whitespace runs made one space, as the bench scores.
fn normal(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// The rest of the first line of `text` that starts with `label`.
fn line_after<'t>(text: &'t str, label: &str) -> Option<&'t str> {
    text.lines().find_map(|line| line.strip_prefix(label))
}

/// The preflight (a call with no system message) gets `OK`. The reader
/// (`stub-reader`) answers a fixture question's gold span when the memories it
/// was given hold it, and `unknown` otherwise. The judge answers `correct` when
/// the answer equals the gold answer, case aside, and `incorrect` otherwise.
/// Every reply names the model it was asked for.
async fn model_call(
    State(state): State<ModelState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Json<Value> {
    let model = body["model"].as_str().unwrap_or("").to_owned();
    let messages = body["messages"].as_array().cloned().unwrap_or_default();
    let content = |role: &str| {
        messages
            .iter()
            .find(|m| m["role"] == role)
            .and_then(|m| m["content"].as_str())
            .map(str::to_owned)
    };
    let user = content("user").unwrap_or_default();
    let reply = if content("system").is_none() {
        "OK".to_owned()
    } else if model == "stub-reader" {
        let question = line_after(&user, "Question: ").unwrap_or("");
        let memories = user.split("\nQuestion: ").next().unwrap_or("");
        match state.spans.get(question) {
            Some(Some(span)) if normal(memories).contains(&normal(span)) => span.clone(),
            _ => "unknown".to_owned(),
        }
    } else {
        let gold = line_after(&user, "Gold answer: ").unwrap_or("");
        let answer = line_after(&user, "Answer: ").unwrap_or("");
        if !gold.is_empty() && gold.eq_ignore_ascii_case(answer) {
            "correct".to_owned()
        } else {
            "incorrect".to_owned()
        }
    };
    let authorization = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    state
        .calls
        .lock()
        .unwrap()
        .push((model.clone(), authorization, reply.clone()));
    Json(json!({
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}],
    }))
}

fn model_stub() -> ModelStub {
    let mut spans = BTreeMap::new();
    for line in std::fs::read_to_string(fixture()).unwrap().lines() {
        let life: Value = serde_json::from_str(line).unwrap();
        for list in ["questions", "questions_ja"] {
            for question in life[list].as_array().into_iter().flatten() {
                spans.insert(
                    question["question"].as_str().unwrap().to_owned(),
                    question["answer_span"].as_str().map(str::to_owned),
                );
            }
        }
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let calls = Calls::default();
    let listener = runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let base_url = format!("http://{}/v1", listener.local_addr().unwrap());
    let app = axum::Router::new()
        .route("/v1/chat/completions", axum::routing::post(model_call))
        .with_state(ModelState {
            spans: Arc::new(spans),
            calls: Arc::clone(&calls),
        });
    runtime.spawn(async move { axum::serve(listener, app).await });
    ModelStub {
        base_url,
        calls,
        _runtime: runtime,
    }
}

#[test]
fn judged_rows_score_every_type() {
    let stub = model_stub();
    let dir = tempfile::tempdir().unwrap();
    let key_file = dir.path().join("model.key");
    std::fs::write(&key_file, format!("{MODEL_KEY}\n")).unwrap();
    let reader = format!("{},stub-reader", stub.base_url);
    let judge = format!("{},stub-judge", stub.base_url);
    let (output, report) = lives(
        dir.path(),
        &[&fixture()],
        &[
            "--grades",
            "light",
            "--limit",
            "5",
            "--reader",
            &reader,
            "--judge",
            &judge,
            "--model-key-file",
            key_file.to_str().unwrap(),
        ],
    );
    succeeded(&output);
    let report = report.expect("a report");
    // The key reaches the endpoints, on every call, and nothing else.
    assert!(
        !report.to_string().contains(MODEL_KEY),
        "the report never holds the key"
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains(MODEL_KEY));
    let calls = stub.calls.lock().unwrap().clone();
    let bearer = format!("Bearer {MODEL_KEY}");
    assert!(
        calls
            .iter()
            .all(|(_, authorization, _)| *authorization == bearer),
        "every model call carries the key"
    );
    // Both models are pinned: id, the id the endpoint answered as, and the
    // instruction's digest.
    for (role, model) in [("reader", "stub-reader"), ("judge", "stub-judge")] {
        let pin = &report["judged"][role];
        assert_eq!(pin["model"], model, "{pin}");
        assert_eq!(pin["reply_model"], model, "{pin}");
        let digest = pin["instruction_sha256"]
            .as_str()
            .expect("instruction pinned");
        assert!(
            digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
            "{pin}"
        );
    }
    assert_ne!(
        report["judged"]["reader"]["instruction_sha256"],
        report["judged"]["judge"]["instruction_sha256"]
    );
    let oneiron = system(&report);
    let rows = rows(oneiron, "light");
    assert_eq!(rows.len(), 10);
    for r in &rows {
        assert!(
            r["answer_correct"].is_boolean(),
            "every type is judged: {r}"
        );
        assert!(r["answer_error"].is_null(), "{r}");
    }
    for life in ["L90001", "L90002"] {
        let unanswerable = row(&rows, life, "q03");
        assert_eq!(unanswerable["reader_answer"], "unknown", "{unanswerable}");
        assert_eq!(
            unanswerable["answer_correct"], true,
            "an abstention answers an unanswerable question: {unanswerable}"
        );
        let unchecked = row(&rows, life, "q04");
        assert_eq!(unchecked["answer_correct"], false, "{unchecked}");
    }
    // The reader reads exactly the texts the context column scored.
    for r in rows.iter().filter(|r| r["scored"] == true) {
        assert_eq!(r["answer_correct"], r["answer_in_context"], "{r}");
    }
    let in_context = rows
        .iter()
        .filter(|r| r["answer_in_context"] == true)
        .count();
    let correct = rows.iter().filter(|r| r["answer_correct"] == true).count();
    assert_eq!(
        correct,
        in_context + 2,
        "the string hits and the two abstentions"
    );
    // The judge grades only answers given to answerable questions.
    let judged_answers = rows
        .iter()
        .filter(|r| r["type"] != "unanswerable" && r["reader_answer"] != "unknown")
        .count();
    let verdicts = calls
        .iter()
        .filter(|(model, _, reply)| model == "stub-judge" && reply != "OK")
        .count();
    assert!(
        judged_answers >= 5,
        "the five English string hits: {judged_answers}"
    );
    assert_eq!(verdicts, judged_answers);
    // The judged column is the headline.
    let summary = &oneiron["summary"][0];
    assert_eq!(summary["headline"], "answer_correct", "{summary}");
    assert_eq!(summary["judged"]["judged"], 10, "{summary}");
    assert_eq!(summary["judged"]["correct"], correct, "{summary}");
    assert_eq!(summary["judged"]["by_type"]["unanswerable"]["correct"], 2);
    assert_eq!(
        summary["headline_rate"].as_f64(),
        Some(correct as f64 / 10.0)
    );
    // A run without models leads with the context column.
    let (screen_output, screen_report) = screen();
    succeeded(screen_output);
    let plain = &system(screen_report.as_ref().unwrap())["summary"][0];
    assert_eq!(plain["headline"], "answer_in_context", "{plain}");
    assert!(plain["judged"].is_null(), "{plain}");
}

#[test]
fn a_reader_without_a_key_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let models = [
        "--reader",
        "http://127.0.0.1:9/v1,stub-reader",
        "--judge",
        "http://127.0.0.1:9/v1,stub-judge",
    ];
    let (output, report) = lives(dir.path(), &[&fixture()], &models);
    assert!(!output.status.success());
    assert!(report.is_none(), "refused before any store is opened");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--model-key-file"),
        "stderr names the missing flag: {stderr}"
    );
    // An empty key file is refused before any model is called or store opened.
    let key_file = dir.path().join("empty.key");
    std::fs::write(&key_file, "\n").unwrap();
    let mut args = models.to_vec();
    args.extend(["--model-key-file", key_file.to_str().unwrap()]);
    let (output, report) = lives(dir.path(), &[&fixture()], &args);
    assert!(!output.status.success());
    assert!(report.is_none());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--model-key-file") && stderr.contains("empty"),
        "stderr names the empty key file: {stderr}"
    );
    // A reader needs a judge.
    let (output, _) = lives(dir.path(), &[&fixture()], &models[..2]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--judge"),
        "a reader alone is refused by naming --judge"
    );
}
