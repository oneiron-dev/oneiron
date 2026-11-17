//! Drive the shipped `scorecard` CLI end to end: fixtures in, JSON out.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// A 40-hex engine commit for the fixtures.
const ENGINE_COMMIT: &str = "0123456789012345678901234567890123456789";

/// The fixture rows: six records, then two queries, each four floats.
const ROWS: [[f32; 4]; 8] = [
    [1.0, 0.0, 0.0, 0.0],
    [0.0, 1.0, 0.0, 0.0],
    [0.0, 0.0, 1.0, 0.0],
    [0.0, 0.0, 0.0, 1.0],
    [1.0, 0.0, 0.0, 0.0],
    [0.0, 1.0, 0.0, 0.0],
    [1.0, 0.0, 0.0, 0.0],
    [0.0, 0.0, 0.0, 1.0],
];

/// sha256 of bytes as lowercase hex.
fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Run `oneiron-bench scorecard` with the given arguments.
fn scorecard(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_oneiron-bench"))
        .arg("scorecard")
        .args(args)
        .output()
        .expect("scorecard CLI fixture")
}

/// Read a JSON file into a value.
fn read_json(path: &Path) -> Value {
    let bytes = std::fs::read(path).expect("fixture file reads");
    serde_json::from_slice(&bytes).expect("fixture file is JSON")
}

/// Write the hand-built `search` slice: two corpora of three records at the
/// same time, one query per corpus graded 2 on one record, each query vector
/// equal to its graded record's vector.
fn write_search_slice(dir: &Path, pinned: bool) {
    let mut bytes = Vec::with_capacity(ROWS.len() * 16);
    for row in ROWS {
        for value in row {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
    let vectors_sha256 = sha256_hex(&bytes);
    let embedding = if pinned {
        json!({
            "model_id": "test/fixture-embed@v1",
            "dims": 4,
            "transform": "fixture",
            "vectors_sha256": vectors_sha256,
        })
    } else {
        Value::Null
    };
    let manifest = json!({
        "contract": "oneiron.retrieval_pack.v1",
        "pack_id": "fixture-pack",
        "revision": "r1",
        "slice": "search",
        "source": {
            "dataset": "LongMemEval-S",
            "dataset_sha256": sha256_hex(b"fixture-dataset"),
            "license": "MIT",
            "split_sha256": sha256_hex(b"fixture-split"),
        },
        "embedding": embedding,
        "records": [
            {"record_id": "fixture-a0", "kind": "turn", "speaker": "user", "text": "harbour crossing at dawn", "source_ref": "sess-owen#0"},
            {"record_id": "fixture-a1", "kind": "turn", "speaker": "assistant", "text": "grocery list for market day", "source_ref": "sess-owen#1"},
            {"record_id": "fixture-a2", "kind": "turn", "speaker": "user", "text": "quiet evening reading nook", "source_ref": "sess-owen#2"},
            {"record_id": "fixture-b0", "kind": "turn", "speaker": "user", "text": "mountain trail snowfall", "source_ref": "sess-yuki#0"},
            {"record_id": "fixture-b1", "kind": "turn", "speaker": "assistant", "text": "city bus schedule", "source_ref": "sess-yuki#1"},
            {"record_id": "fixture-b2", "kind": "turn", "speaker": "user", "text": "evening lantern festival", "source_ref": "sess-yuki#2"},
        ],
        "corpora": [
            {"corpus_id": "corpus-owen", "sessions": [
                {"session_id": "sess-owen", "time": "2026-01-01T00:00:00Z", "record_ids": ["fixture-a0", "fixture-a1", "fixture-a2"]},
            ]},
            {"corpus_id": "corpus-yuki", "sessions": [
                {"session_id": "sess-yuki", "time": "2026-01-01T00:00:00Z", "record_ids": ["fixture-b0", "fixture-b1", "fixture-b2"]},
            ]},
        ],
        "queries": [
            {"query_id": "query-owen", "slice": "search", "corpus_id": "corpus-owen", "category": "single-session-user", "text": "harbour crossing", "now": "2026-01-02T00:00:00Z", "qrels": {"fixture-a0": 2}, "expect_empty": false},
            {"query_id": "query-yuki", "slice": "search", "corpus_id": "corpus-yuki", "category": "single-session-user", "text": "mountain snowfall", "now": "2026-01-02T00:00:00Z", "qrels": {"fixture-b0": 2}, "expect_empty": false},
        ],
    });
    let mut pretty = serde_json::to_vec_pretty(&manifest).expect("manifest JSON");
    pretty.push(b'\n');
    std::fs::write(dir.join("search.json"), pretty).expect("manifest write");
    if pinned {
        std::fs::write(dir.join("search.vectors.f32"), bytes).expect("vectors write");
    }
}

#[test]
fn scorecard_run_writes_a_v1_scorecard() {
    let dir = tempfile::tempdir().expect("scorecard fixture dir");
    write_search_slice(dir.path(), true);
    let pack_dir = dir.path().to_str().expect("fixture dir").to_owned();
    let out = dir.path().join("scorecard.json");
    let out_arg = out.to_str().expect("scorecard path").to_owned();
    let result = scorecard(&[
        "run",
        "--pack-dir",
        &pack_dir,
        "--slice",
        "search",
        "--engine-commit",
        ENGINE_COMMIT,
        "--out",
        &out_arg,
    ]);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "run failed: {stderr}");
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert_eq!(stdout.lines().count(), 1);
    assert!(stdout.ends_with('\n'));
    let summary: Value = serde_json::from_slice(&result.stdout).expect("run prints JSON");
    assert_eq!(summary["repeats"], json!(2));
    assert_eq!(summary["query_count"], json!(2));
    assert_eq!(summary["repeat_digest_equal"], json!(true));
    assert_eq!(summary["metrics"]["ndcg_at_10"], json!(1.0));
    assert_eq!(summary["metrics"]["mrr"], json!(1.0));
    let first_digest = summary["params_digest"]
        .as_str()
        .expect("params digest")
        .to_owned();
    let file = read_json(&out);
    assert_eq!(file["contract"], json!("oneiron.retrieval_scorecard.v1"));

    let params_path = dir.path().join("params.json");
    let params = json!({
        "contract": "oneiron.retrieval_eval_params.v1",
        "blend_weights": {"recency": 0.2, "salience": 0.1, "confidence": 0.1, "gravity": 0.1, "relevance": 0.5},
    });
    std::fs::write(
        &params_path,
        serde_json::to_vec(&params).expect("params JSON"),
    )
    .expect("params write");
    let params_arg = params_path.to_str().expect("params path").to_owned();
    let out_two = dir.path().join("scorecard-two.json");
    let out_two_arg = out_two.to_str().expect("second scorecard path").to_owned();
    let again = scorecard(&[
        "run",
        "--pack-dir",
        &pack_dir,
        "--slice",
        "search",
        "--engine-commit",
        ENGINE_COMMIT,
        "--out",
        &out_two_arg,
        "--params",
        &params_arg,
    ]);
    let again_stderr = String::from_utf8_lossy(&again.stderr);
    assert!(again.status.success(), "pinned run failed: {again_stderr}");
    let second: Value = serde_json::from_slice(&again.stdout).expect("second run prints JSON");
    let second_digest = second["params_digest"]
        .as_str()
        .expect("second params digest");
    assert_ne!(first_digest.as_str(), second_digest);
}

#[test]
fn scorecard_run_refuses_sealed_without_a_ledger() {
    let dir = tempfile::tempdir().expect("sealed fixture dir");
    let pack_dir = dir.path().to_str().expect("fixture dir").to_owned();
    let out = dir.path().join("x.json");
    let out_arg = out.to_str().expect("refused path").to_owned();
    let result = scorecard(&[
        "run",
        "--pack-dir",
        &pack_dir,
        "--slice",
        "sealed",
        "--engine-commit",
        ENGINE_COMMIT,
        "--out",
        &out_arg,
    ]);
    assert_eq!(result.status.code(), Some(2));
    let body: Value = serde_json::from_slice(&result.stdout).expect("refusal prints JSON");
    assert!(
        body.get("error").is_some_and(serde_json::Value::is_string),
        "refusal names its error"
    );
    assert!(!out.exists());
}

/// What the stub saw and how it answers.
struct StubState {
    /// The input types the stub saw, in request order.
    input_types: Mutex<Vec<String>>,
    /// The first request (0-based) whose answer names another transform than
    /// the listing; `None` keeps every answer on the listed one.
    transform_changes_at: Option<usize>,
}

/// The stub embedder: `/v1/models` plus `/v1/embeddings` on a live port.
struct Stub {
    endpoint: String,
    state: Arc<StubState>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl Drop for Stub {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

impl Stub {
    /// Start the stub on 127.0.0.1 with an ephemeral port.
    fn start(transform_changes_at: Option<usize>) -> Self {
        let state = Arc::new(StubState {
            input_types: Mutex::new(Vec::new()),
            transform_changes_at,
        });
        let app = Router::new()
            .route("/v1/models", get(stub_models))
            .route("/v1/embeddings", post(stub_embeddings))
            .with_state(Arc::clone(&state));
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("stub runtime");
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .expect("stub listener");
        let addr = listener.local_addr().expect("stub addr");
        runtime.spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            endpoint: format!("http://{addr}"),
            state,
            runtime: Some(runtime),
        }
    }
}

/// The run profile the stub lists and names in every answer.
fn stub_profile() -> Value {
    json!({"model_dir": false, "max_input_tokens": 512})
}

/// One served row shaped like the real listing.
async fn stub_models() -> Json<Value> {
    Json(json!({
        "object": "list",
        "data": [{
            "id": "stub-embed",
            "object": "model",
            "created": 0,
            "owned_by": "oneiron",
            "dimensions": 4,
            "model_id": "test/stub-embed@v1",
            "transform": "stub",
            "profile": stub_profile(),
            "oneiron_wire": 1,
        }],
    }))
}

/// Every input answers `[3, 4, 0, 0]`; every request's side is recorded.
/// From `transform_changes_at` on, answers name the transform `stub-bidirectional`.
async fn stub_embeddings(
    State(state): State<Arc<StubState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let input_type = body
        .get("input_type")
        .and_then(Value::as_str)
        .unwrap_or("missing")
        .to_owned();
    let request = {
        let mut seen = state.input_types.lock().expect("stub lock");
        seen.push(input_type);
        seen.len() - 1
    };
    let transform = match state.transform_changes_at {
        Some(first) if request >= first => "stub-bidirectional",
        _ => "stub",
    };
    let inputs = body
        .get("input")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rows: Vec<Value> = (0..inputs.len())
        .map(|index| {
            json!({
                "object": "embedding",
                "index": index,
                "embedding": [3.0, 4.0, 0.0, 0.0],
                "input_tokens": 4,
            })
        })
        .collect();
    Json(json!({
        "object": "list",
        "data": rows,
        "model": body.get("model").cloned().unwrap_or(Value::Null),
        "usage": {"prompt_tokens": 8, "total_tokens": 8},
        "model_id": "test/stub-embed@v1",
        "transform": transform,
        "profile": stub_profile(),
        "provenance": {},
    }))
}

#[test]
fn scorecard_pack_embed_pins_finished_vectors() {
    let stub = Stub::start(None);
    let dir = tempfile::tempdir().expect("embed fixture dir");
    write_search_slice(dir.path(), false);
    let pack_dir = dir.path().to_str().expect("fixture dir").to_owned();
    let result = scorecard(&[
        "pack-embed",
        "--pack-dir",
        &pack_dir,
        "--slice",
        "search",
        "--endpoint",
        &stub.endpoint,
    ]);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "pack-embed failed: {stderr}");
    let summary: Value = serde_json::from_slice(&result.stdout).expect("embed prints JSON");
    assert_eq!(summary["model_id"], json!("test/stub-embed@v1"));
    let manifest = read_json(&dir.path().join("search.json"));
    assert_eq!(
        manifest["embedding"]["model_id"],
        json!("test/stub-embed@v1")
    );
    assert_eq!(manifest["embedding"]["transform"], json!("stub"));
    assert_eq!(manifest["embedding"]["dims"], json!(4));
    let raw = std::fs::read(dir.path().join("search.vectors.f32")).expect("vectors file");
    assert_eq!(raw.len(), 8 * 4 * 4);
    let mut floats = Vec::new();
    for chunk in raw.chunks_exact(4) {
        floats.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    assert_eq!(floats.len(), 8 * 4);
    // [3, 4, 0, 0] / 5 rounded through f16: 0.6 -> 1229 * 2^-11, 0.8 -> 1638 * 2^-11.
    // Written as exact f32 quotients so this file needs no `half` and compiles on main.
    let want = [1229.0_f32 / 2048.0, 1638.0_f32 / 2048.0, 0.0, 0.0];
    for row in floats.chunks_exact(4) {
        assert_eq!(row, want.as_slice());
    }
    let seen = stub.state.input_types.lock().expect("stub lock").clone();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0], "document");
    assert_eq!(seen[1], "query");
}

#[test]
fn scorecard_pack_embed_refuses_an_answer_under_another_transform() {
    // Documents embed under the listed transform, then the query answer names
    // another one: no vector of the slice may be pinned as the listed transform.
    let stub = Stub::start(Some(1));
    let dir = tempfile::tempdir().expect("embed fixture dir");
    write_search_slice(dir.path(), false);
    let manifest_before = std::fs::read(dir.path().join("search.json")).expect("manifest");
    let pack_dir = dir.path().to_str().expect("fixture dir").to_owned();
    let result = scorecard(&[
        "pack-embed",
        "--pack-dir",
        &pack_dir,
        "--slice",
        "search",
        "--endpoint",
        &stub.endpoint,
    ]);
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert_eq!(
        result.status.code(),
        Some(1),
        "pack-embed answered: {stdout}"
    );
    let body: Value = serde_json::from_slice(&result.stdout).expect("refusal prints JSON");
    let error = body["error"].as_str().unwrap_or_default();
    assert!(
        error.contains("transform"),
        "refusal names the transform: {error}"
    );
    let manifest_after = std::fs::read(dir.path().join("search.json")).expect("manifest");
    assert_eq!(
        manifest_before, manifest_after,
        "a refused embed pins nothing"
    );
    assert!(!dir.path().join("search.vectors.f32").exists());
    let seen = stub.state.input_types.lock().expect("stub lock").clone();
    assert_eq!(seen, ["document", "query"]);
}

#[test]
fn scorecard_convert_writes_the_split_and_the_slices() {
    let dataset = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../oneiron-ruler/tests/fixtures/longmemeval_mini.json"
    );
    let dir = tempfile::tempdir().expect("convert fixture dir");
    let out_dir = dir.path().join("packs");
    let out_arg = out_dir.to_str().expect("convert out dir").to_owned();
    let result = scorecard(&[
        "convert",
        "--dataset",
        dataset,
        "--out-dir",
        &out_arg,
        "--seed",
        "7",
        "--search",
        "1",
        "--held-out",
        "1",
        "--sealed",
        "1",
    ]);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "convert failed: {stderr}");
    let summary: Value = serde_json::from_slice(&result.stdout).expect("convert prints JSON");
    assert_eq!(summary["slices"].as_array().expect("slices").len(), 3);
    let split = read_json(&out_dir.join("split.json"));
    assert_eq!(split["contract"], json!("oneiron.retrieval_split.v1"));
    for (file, name) in [
        ("search.json", "search"),
        ("held_out.json", "held_out"),
        ("sealed.json", "sealed"),
    ] {
        let slice = read_json(&out_dir.join(file));
        assert_eq!(slice["slice"], json!(name));
        assert!(slice["embedding"].is_null(), "{file} stays unpinned");
    }
}
