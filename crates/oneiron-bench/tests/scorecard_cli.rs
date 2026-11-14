//! Drive the shipped `scorecard` CLI end to end: fixtures in, JSON out.
#![allow(
    clippy::disallowed_methods,
    reason = "a test process starts its own subprocesses; the rule covers the server's crates"
)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use oneiron_ruler::pack::{Slice, load_slice};
use oneiron_ruler::proposal::{HeldOutProposal, PROPOSAL_CONTRACT, ProposalStore, proposal_id};
use oneiron_ruler::sealed::ExperimentIdentity;
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

/// Write the hand-built `slice` slice: two corpora of three records at the
/// same time, one query per corpus graded 2 on one record, each query vector
/// equal to its graded record's vector.
fn write_slice(dir: &Path, slice: &str, pinned: bool) {
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
        "slice": slice,
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
            {"query_id": "query-owen", "slice": slice, "corpus_id": "corpus-owen", "category": "single-session-user", "text": "harbour crossing", "now": "2026-01-02T00:00:00Z", "qrels": {"fixture-a0": 2}, "expect_empty": false},
            {"query_id": "query-yuki", "slice": slice, "corpus_id": "corpus-yuki", "category": "single-session-user", "text": "mountain snowfall", "now": "2026-01-02T00:00:00Z", "qrels": {"fixture-b0": 2}, "expect_empty": false},
        ],
    });
    let mut pretty = serde_json::to_vec_pretty(&manifest).expect("manifest JSON");
    pretty.push(b'\n');
    std::fs::write(dir.join(format!("{slice}.json")), pretty).expect("manifest write");
    if pinned {
        std::fs::write(dir.join(format!("{slice}.vectors.f32")), bytes).expect("vectors write");
    }
}

#[test]
fn scorecard_run_writes_a_v1_scorecard() {
    let dir = tempfile::tempdir().expect("scorecard fixture dir");
    write_slice(dir.path(), "search", true);
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

/// The input types the stub saw, in request order.
struct StubState {
    input_types: Mutex<Vec<String>>,
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
    fn start() -> Self {
        let state = Arc::new(StubState {
            input_types: Mutex::new(Vec::new()),
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
            "profile": {"model_dir": false, "max_input_tokens": 512},
            "oneiron_wire": 1,
        }],
    }))
}

/// Every input answers `[3, 4, 0, 0]`; every request's side is recorded.
async fn stub_embeddings(
    State(state): State<Arc<StubState>>,
    Json(body): Json<Value>,
) -> Json<Value> {
    let input_type = body
        .get("input_type")
        .and_then(Value::as_str)
        .unwrap_or("missing")
        .to_owned();
    state
        .input_types
        .lock()
        .expect("stub lock")
        .push(input_type);
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
        "transform": "stub",
        "profile": {},
        "provenance": {},
    }))
}

#[test]
fn scorecard_pack_embed_pins_finished_vectors() {
    let stub = Stub::start();
    let dir = tempfile::tempdir().expect("embed fixture dir");
    write_slice(dir.path(), "search", false);
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
    // Written as literals so this file needs no `half` and compiles on main.
    let want = [0.600_097_656_25_f32, 0.799_804_687_5_f32, 0.0, 0.0];
    for row in floats.chunks_exact(4) {
        assert_eq!(row, want.as_slice());
    }
    let seen = stub.state.input_types.lock().expect("stub lock").clone();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0], "document");
    assert_eq!(seen[1], "query");
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

/// Write a dominance campaign whose sealed ref is (`fixture-pack`, `sealed_revision`).
fn write_run_campaign(dir: &Path, sealed_revision: &str) -> PathBuf {
    let body = json!({
        "campaign_id": "fixture-campaign",
        "search_axes": [{"name": "fanout", "values": ["4", "8"]}],
        "metric_set": {"set_id": "retrieval-scorecard", "revision": "r1", "axes": [
            {"name": "ndcg_at_10", "direction": "higher", "role": "primary"},
            {"name": "recall_at_5", "direction": "higher", "role": "floor", "tolerance": 0.001},
            {"name": "search_p95_us", "direction": "lower", "role": "cost", "tolerance": 50.0},
        ]},
        "splits": {
            "search": {"dataset_id": "fixture-pack", "revision": "search-1"},
            "held_out": {"dataset_id": "fixture-pack", "revision": "held-out-1"},
            "sealed": {"dataset_id": "fixture-pack", "revision": sealed_revision},
        },
        "budget": {"budget_id": "lease-1", "max_units": 10, "exploration_units": 2},
        "decide": {"kind": "dominance"},
    });
    let path = dir.join("campaign.json");
    std::fs::write(&path, serde_json::to_vec(&body).expect("campaign JSON"))
        .expect("campaign write");
    path
}

#[test]
fn scorecard_run_sealed_spends_its_claim_before_reading() {
    let dir = tempfile::tempdir().expect("sealed fixture dir");
    write_slice(dir.path(), "sealed", true);
    let digest = load_slice(dir.path(), Slice::Sealed)
        .expect("sealed slice loads")
        .pack_digest;
    let campaign = write_run_campaign(dir.path(), &digest);
    let pack_dir = dir.path().to_str().expect("fixture dir").to_owned();
    let campaign_arg = campaign.to_str().expect("campaign path").to_owned();
    let ledger = dir.path().join("ledger");
    let ledger_arg = ledger.to_str().expect("ledger path").to_owned();
    let out = dir.path().join("sealed.json");
    let out_arg = out.to_str().expect("sealed path").to_owned();
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
        "--sealed-ledger",
        &ledger_arg,
        "--campaign",
        &campaign_arg,
        "--incumbent",
        "true",
    ]);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "sealed run failed: {stderr}");
    let summary: Value = serde_json::from_slice(&result.stdout).expect("run prints JSON");
    assert_eq!(summary["slice"], json!("sealed"));
    let claim = summary["sealed_claim"].as_str().expect("sealed claim");
    assert!(Path::new(claim).is_file(), "claim marker exists");
    assert!(out.is_file(), "sealed scorecard exists");
    let out_two = dir.path().join("sealed-two.json");
    let out_two_arg = out_two.to_str().expect("second path").to_owned();
    let again = scorecard(&[
        "run",
        "--pack-dir",
        &pack_dir,
        "--slice",
        "sealed",
        "--engine-commit",
        ENGINE_COMMIT,
        "--out",
        &out_two_arg,
        "--sealed-ledger",
        &ledger_arg,
        "--campaign",
        &campaign_arg,
        "--incumbent",
        "true",
    ]);
    assert_eq!(again.status.code(), Some(2));
    assert!(!out_two.exists(), "writes no second scorecard");
}

#[test]
fn scorecard_run_sealed_for_a_proposal_checks_its_record_first() {
    let dir = tempfile::tempdir().expect("proposal run fixture dir");
    write_slice(dir.path(), "sealed", true);
    let digest = load_slice(dir.path(), Slice::Sealed)
        .expect("sealed slice loads")
        .pack_digest;
    let campaign = write_run_campaign(dir.path(), &digest);
    let pack_dir = dir.path().to_str().expect("fixture dir").to_owned();
    let campaign_arg = campaign.to_str().expect("campaign path").to_owned();
    let ledger = dir.path().join("ledger");
    let ledger_arg = ledger.to_str().expect("ledger path").to_owned();
    let proposals = dir.path().join("proposals");
    let proposals_arg = proposals.to_str().expect("proposals path").to_owned();
    let out = dir.path().join("sealed.json");
    let out_arg = out.to_str().expect("sealed path").to_owned();
    let unknown = "ab".repeat(32);
    let missing = scorecard(&[
        "run",
        "--pack-dir",
        &pack_dir,
        "--slice",
        "sealed",
        "--engine-commit",
        ENGINE_COMMIT,
        "--out",
        &out_arg,
        "--sealed-ledger",
        &ledger_arg,
        "--campaign",
        &campaign_arg,
        "--proposal",
        &unknown,
        "--proposals",
        &proposals_arg,
    ]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(
        !ledger.join("sealed-once").exists(),
        "no sealed-once marker without a record"
    );
    let incumbent = ExperimentIdentity {
        engine_commit: ENGINE_COMMIT.to_owned(),
        params_digest: "dd".repeat(32),
        pack_digest: digest,
    };
    let candidate = ExperimentIdentity {
        engine_commit: ENGINE_COMMIT.to_owned(),
        params_digest: "cc".repeat(32),
        pack_digest: incumbent.pack_digest.clone(),
    };
    let id = proposal_id("fixture-campaign", &incumbent, &candidate).expect("proposal id");
    let store = ProposalStore::open(&proposals).expect("proposals open");
    let record = HeldOutProposal {
        contract: PROPOSAL_CONTRACT.to_owned(),
        proposal_id: id.clone(),
        campaign_id: "fixture-campaign".to_owned(),
        incumbent,
        candidate,
        candidate_params: json!({"contract": "oneiron.retrieval_eval_params.v1"}),
        incumbent_scorecard_sha256: "ee".repeat(32),
        candidate_scorecard_sha256: "ff".repeat(32),
        axes: Vec::new(),
        bootstrap: Vec::new(),
        decided_at: 1_700_000_000,
    };
    store.put_held_out(&record).expect("record writes");
    let mismatch = scorecard(&[
        "run",
        "--pack-dir",
        &pack_dir,
        "--slice",
        "sealed",
        "--engine-commit",
        ENGINE_COMMIT,
        "--out",
        &out_arg,
        "--sealed-ledger",
        &ledger_arg,
        "--campaign",
        &campaign_arg,
        "--proposal",
        &id,
        "--proposals",
        &proposals_arg,
    ]);
    assert_eq!(mismatch.status.code(), Some(2));
    assert!(
        !ledger.join("sealed-once").exists(),
        "no sealed-once marker on a params mismatch"
    );
}

#[test]
fn scorecard_run_sealed_on_the_wrong_pack_spends_the_run() {
    let dir = tempfile::tempdir().expect("wrong pack fixture dir");
    write_slice(dir.path(), "sealed", true);
    let digest = load_slice(dir.path(), Slice::Sealed)
        .expect("sealed slice loads")
        .pack_digest;
    let mut wrong = digest.clone();
    let first = if digest.starts_with('a') { "b" } else { "a" };
    wrong.replace_range(0..1, first);
    let campaign = write_run_campaign(dir.path(), &wrong);
    let pack_dir = dir.path().to_str().expect("fixture dir").to_owned();
    let campaign_arg = campaign.to_str().expect("campaign path").to_owned();
    let ledger = dir.path().join("ledger");
    let ledger_arg = ledger.to_str().expect("ledger path").to_owned();
    let out = dir.path().join("sealed.json");
    let out_arg = out.to_str().expect("sealed path").to_owned();
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
        "--sealed-ledger",
        &ledger_arg,
        "--campaign",
        &campaign_arg,
        "--incumbent",
        "true",
    ]);
    assert_eq!(result.status.code(), Some(1));
    let body: Value = serde_json::from_slice(&result.stdout).expect("spent prints JSON");
    let error = body["error"].as_str().expect("spent names its error");
    assert!(
        error.contains("spent"),
        "the error says the run was spent: {error}"
    );
    assert!(ledger.join("sealed-once").is_dir(), "claim marker spent");
    assert!(ledger.join("incumbent-once").is_dir(), "incumbent spent");
}
