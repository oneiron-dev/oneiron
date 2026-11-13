//! L9-15 (RULING L9-15-TRANSPORT = B): a managed llama.cpp worker row with
//! `listen = "unix"` serves the reranker on a Unix socket of its launch's
//! own, and the reranker reaches it there alone, each connection checked
//! against the launch's supervised child (I2-LOCAL), so the reranker seat
//! gets an on-device view.
//!
//! - The seat's on-device view exists and sends only over supervised
//!   channels; a rerank call on it reaches the stub on its socket with the
//!   documents' words, and its scores come back in document order.
//! - A socket whose peer is not the launch's supervised child gets no
//!   request: the call fails before any byte of it leaves. The same socket,
//!   recorded with its own child, is answered.
//! - A loopback HTTP reranker has no on-device view.
//! - Config refuses `listen = "unix"` on a provider any other role names,
//!   on a reranker model no such row serves, on an EXL3 row and on an
//!   external row.
//!
//! The stub (`tests/fixtures/stub_rerank_uds.py`, standard-library Python)
//! stands in for llama-server: it is started in a supervisor's custody by
//! the test door, as a launch's child is, and recorded as the hosted row's
//! current launch.
#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart,
    HostingPrivacyPosture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmResult, ModelId,
    ModelLocality, ModelTierRef, ResponseFormat, TierPrecedence,
};
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::models::{ModelRuntime, OfferLadder};
use oneiron_server::test_doors::supervised_rerank::{
    SocketStub, permit_worker_launch, record_socket_launch, reranker_on_device_view,
};
use serde_json::Value as JsonValue;

/// The `listen = "unix"` worker row's id.
const WORKER: &str = "rerank-socket";
const QUERY: &str = "ferry leaves seven";
const DOCUMENTS: [&str; 2] = ["a grocery list for monday", "the ferry leaves at seven"];
/// The stub's scores for [`DOCUMENTS`], in document order: how many of the
/// query's words each holds.
const SCORES: [f32; 2] = [0.0, 3.0];

/// The worker host is one per process: the tests that build a runtime take
/// turns, so none replaces another's hosted rows.
static HOST_TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A `[models]` section whose `house-rerank` provider is served by a
/// managed llama.cpp worker on its own socket, for the reranker alone.
/// Nothing is installed: the row's artifacts are paths under `dir` that do
/// not exist, so its supervisor never launches, and the test door records
/// the stub as its launch instead.
fn socket_config(dir: &Path) -> String {
    format!(
        r#"
[providers.house-rerank]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:18431"
revision = "v1"
timeout_secs = 20

[roles.reranker]
rungs = [{{ model = "house-rerank:stub-reranker" }}]

[workers.{WORKER}]
model = "house-rerank:stub-reranker"
kind = "llama_cpp"
mode = "managed"
listen = "unix"
weights_manifest = "{weights}"
server = "{server}"
server_sha256 = "{sha}"
runtime_root = "{runtime}"
"#,
        weights = dir.join("absent-weights.json").display(),
        server = dir.join("absent-llama-server").display(),
        sha = "0".repeat(64),
        runtime = dir.join("rt").display(),
    )
}

fn stub_program() -> (PathBuf, PathBuf) {
    (
        PathBuf::from("python3"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/stub_rerank_uds.py"),
    )
}

/// A stub on `socket`, logging to `log`, in custody; it is listening when
/// this returns.
async fn start_stub(socket: &Path, log: &Path) -> SocketStub {
    let (python, script) = stub_program();
    let stub = SocketStub::start(
        &python,
        &[
            script.display().to_string(),
            socket.display().to_string(),
            log.display().to_string(),
        ],
    )
    .expect("FIXTURE: the stub starts");
    let started = Instant::now();
    while !socket.exists() {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "FIXTURE: the stub bound {} within 20 s",
            socket.display()
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    stub
}

/// The requests the stub at `log` was sent, one JSON line each.
fn logged(log: &Path) -> Vec<JsonValue> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).expect("a JSON log line"))
        .collect()
}

fn rerank_posts(log: &Path) -> Vec<JsonValue> {
    logged(log)
        .into_iter()
        .filter(|line| line["method"] == "POST" && line["path"] == "/v1/rerank")
        .collect()
}

fn rerank_request(model: ModelId) -> LlmRequest {
    let purpose = CallPurpose::Other {
        name: "rerank".to_owned(),
    };
    let text = |text: &str| ContentPart::Text {
        text: text.to_owned(),
        signature: None,
    };
    LlmRequest {
        model,
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            tier: TierPrecedence::for_purpose(&purpose, ModelTierRef("rerank".into())),
            purpose,
            class: CallClass::BestEffort,
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OnDevice,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![
            LlmMessage {
                role: LlmMessageRole::User,
                content: vec![text(QUERY)],
            },
            LlmMessage {
                role: LlmMessageRole::User,
                content: DOCUMENTS.iter().copied().map(text).collect(),
            },
        ],
        tools: Vec::new(),
        params: Default::default(),
        provider_options: Default::default(),
        host_segments: None,
    }
}

/// One rerank call of [`QUERY`] over [`DOCUMENTS`] on `ladder`, under its
/// own undeclared run named `name`.
async fn rerank_on(
    runtime: &ModelRuntime,
    ladder: &OfferLadder,
    name: &str,
) -> LlmResult<LlmResponse> {
    let run = runtime.undeclared_run(
        name,
        BudgetGuard::with_reserve_units(name, 1_000_000, 1_000, BudgetExhaustionPolicy::Suspend),
    );
    let call = ladder.generate_within(
        &run,
        rerank_request(ladder.model().clone()),
        None,
        &|| true,
        Duration::ZERO,
    );
    tokio::time::timeout(Duration::from_secs(60), call)
        .await
        .expect("the rerank call ended within a minute")
}

/// The scores a rerank answer carries, in document order.
fn scores(answer: &LlmResponse) -> Vec<f32> {
    let text: String = answer
        .message
        .content
        .iter()
        .filter_map(|part| match part {
            ContentPart::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    serde_json::from_str(&text).expect("the answer is the scores, in document order")
}

/// The runtime of [`socket_config`] in a process that launches workers.
fn socket_runtime(dir: &Path) -> ModelRuntime {
    permit_worker_launch();
    let config = ModelsConfig::from_toml(&socket_config(dir), None)
        .expect("a listen = \"unix\" reranker row is valid config");
    ModelRuntime::build(Some(&config), HostingPrivacyPosture::SelfHostLocal)
}

#[tokio::test]
async fn a_socket_reranker_has_an_on_device_view_that_scores_on_its_socket() {
    let _turn = HOST_TURN.lock().await;
    let dir = tempfile::tempdir().expect("dir");
    let runtime = socket_runtime(dir.path());
    let socket = dir.path().join("stub.sock");
    let log = dir.path().join("stub.log");
    let stub = start_stub(&socket, &log).await;
    assert!(
        record_socket_launch(WORKER, &socket, &stub),
        "FIXTURE: the hosted listen = \"unix\" row takes the stub as its launch"
    );

    let (view, native_local) = reranker_on_device_view(&runtime)
        .expect("the reranker seat has an on-device view over its socket worker");
    assert!(
        native_local,
        "every rung of the reranker's on-device view is a supervised worker's, on this device"
    );
    let answer = rerank_on(&runtime, &view, "socket-rerank")
        .await
        .expect("the rerank call is answered on the worker's socket");
    assert_eq!(
        scores(&answer),
        SCORES,
        "the stub's scores, in document order"
    );

    let posts = rerank_posts(&log);
    assert_eq!(posts.len(), 1, "one batch went to /v1/rerank: {posts:?}");
    assert_eq!(posts[0]["body"]["model"], "stub-reranker");
    assert_eq!(posts[0]["body"]["query"], QUERY);
    assert_eq!(
        posts[0]["body"]["documents"],
        serde_json::json!(DOCUMENTS),
        "the documents' words reach the on-device worker"
    );
    stub.stop().await;
}

#[tokio::test]
async fn a_socket_whose_peer_is_not_the_launch_child_is_sent_nothing() {
    let _turn = HOST_TURN.lock().await;
    let dir = tempfile::tempdir().expect("dir");
    let runtime = socket_runtime(dir.path());
    let child_socket = dir.path().join("child.sock");
    let child = start_stub(&child_socket, &dir.path().join("child.log")).await;
    let other_socket = dir.path().join("other.sock");
    let other_log = dir.path().join("other.log");
    let other = start_stub(&other_socket, &other_log).await;
    let (view, _) = reranker_on_device_view(&runtime).expect("the on-device view");

    // The launch names `other`'s socket, but its supervised child is
    // `child`: the process answering on that socket is not the launch's.
    assert!(record_socket_launch(WORKER, &other_socket, &child));
    let refused = rerank_on(&runtime, &view, "foreign-peer").await;
    assert!(
        refused.is_err(),
        "a socket whose peer is not the launch's child is refused: {refused:?}"
    );
    assert!(
        rerank_posts(&other_log).is_empty(),
        "no rerank request reached the foreign peer"
    );

    // Control: the same socket, recorded with its own child, is answered.
    assert!(record_socket_launch(WORKER, &other_socket, &other));
    let answer = rerank_on(&runtime, &view, "own-peer")
        .await
        .expect("the socket's own child answers");
    assert_eq!(scores(&answer), SCORES);
    assert_eq!(rerank_posts(&other_log).len(), 1);
    child.stop().await;
    other.stop().await;
}

#[tokio::test]
async fn a_loopback_http_reranker_has_no_on_device_view() {
    let _turn = HOST_TURN.lock().await;
    permit_worker_launch();
    let config = ModelsConfig::from_toml(
        r#"
[providers.loopback]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:18432"
revision = "v1"

[roles.reranker]
rungs = [{ model = "loopback:stub-reranker" }]
"#,
        None,
    )
    .expect("a loopback reranker is valid config");
    let runtime = ModelRuntime::build(Some(&config), HostingPrivacyPosture::SelfHostLocal);
    assert!(
        runtime
            .seat(oneiron::llm::manifest::ModelRole::Reranker)
            .is_some()
    );
    assert!(
        reranker_on_device_view(&runtime).is_none(),
        "a loopback address alone is not the trust contract: no on-device view"
    );
}

#[test]
fn listen_unix_is_refused_off_a_reranker_only_llama_row() {
    let dir = tempfile::tempdir().expect("dir");
    let base = socket_config(dir.path());
    let refused = |text: String, needle: &str| {
        let error = ModelsConfig::from_toml(&text, None)
            .expect_err(needle)
            .to_string();
        assert!(error.contains(needle), "{needle:?} not in {error:?}");
    };
    refused(
        base.replace(
            "[roles.reranker]",
            "[roles.generative_reasoner]\nrungs = [{ model = \"house-rerank:stub-reranker\" }]\n\n[roles.reranker]",
        ),
        "serves the reranker alone",
    );
    refused(
        base.replace(
            "rungs = [{ model = \"house-rerank:stub-reranker\" }]",
            "rungs = [{ model = \"house-rerank:stub-reranker\" }, { model = \"house-rerank:other-reranker\" }]",
        ),
        "serves each reranker model from a listen = \"unix\" row",
    );
    refused(
        base.replace("kind = \"llama_cpp\"", "kind = \"exl3\""),
        "only a llama_cpp worker listens on a Unix socket",
    );
    refused(
        format!(
            r#"
[providers.house-rerank]
kind = "local-openai-compat"
base_url = "http://127.0.0.1:18431"
revision = "v1"

[roles.reranker]
rungs = [{{ model = "house-rerank:stub-reranker" }}]

[workers.{WORKER}]
model = "house-rerank:stub-reranker"
kind = "llama_cpp"
mode = "external"
listen = "unix"
"#
        ),
        ".listen: an external worker is the operator's",
    );
}
