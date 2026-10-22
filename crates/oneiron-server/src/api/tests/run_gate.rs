//! A chat turn and the raw `/v1/llm` routes admit each model call through a
//! run's gate: every provider call that went out has its `Dispatched` row,
//! and a rung the run's line cannot cover is denied and never sent.
use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use oneiron::llm::manifest::ModelRole;
use oneiron::llm::run_admission::{MemoryReceipts, RunEvent, RunReceipt};
use oneiron::{
    CallClass, CallEnvelope, CallPurpose, ContentPart, LlmMessage, LlmMessageRole, LlmRequest,
    ModelTierRef, ResponseFormat, TierPrecedence,
};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::ai_host::AiHost;
use crate::ai_host::test_support::{TEST_SECRET, models_toml, rooted_vault};
use crate::config::models::ModelsConfig;
use crate::fake_llm::{FakeLlm, Reply};
use crate::models::ModelRuntime;
use crate::server::SyncServer;

/// The generative seat on two rungs, the first failing and the second
/// answering. `units` is the raw routes' line and each chat turn's.
fn two_rungs(failing: &FakeLlm, answering: &FakeLlm, units: u64) -> ModelsConfig {
    models_toml(&format!(
        r#"
raw_budget_units = {units}
[providers.first]
kind = "local-openai-compat"
base_url = "{}"
[providers.second]
kind = "local-openai-compat"
base_url = "{}"
[roles.generative_reasoner]
rungs = [{{ model = "first:small" }}, {{ model = "second:big" }}]
[dreamer]
enabled = false
[chat]
turn_budget_units = {units}
"#,
        failing.base_url, answering.base_url
    ))
}

async fn gated_server(
    config: &ModelsConfig,
) -> (
    tempfile::TempDir,
    Arc<SyncServer>,
    AiHost,
    Arc<MemoryReceipts>,
) {
    let (dir, vault) = rooted_vault();
    let receipts = Arc::new(MemoryReceipts::default());
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some(TEST_SECRET.into()),
            ..Default::default()
        },
    )
    .unwrap()
    .with_run_receipts(receipts.clone());
    let (server, host) = AiHost::attach(server, Some(config)).await;
    (dir, Arc::new(server), host, receipts)
}

async fn send(server: &Arc<SyncServer>, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let request = slip_credentials::bind_request(server, request);
    let response = api_routes(Arc::clone(server))
        .oneshot(request)
        .await
        .expect("route response");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, body.to_vec())
}

/// A raw call to the generative seat by its id.
fn raw(verb: &str, config: &ModelsConfig) -> Request<Body> {
    let runtime = ModelRuntime::build(Some(config));
    let seat = runtime.seat(ModelRole::GenerativeReasoner).expect("seat");
    let request = LlmRequest {
        model: seat.model.clone(),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Default::default(),
            purpose: CallPurpose::AnswerGen,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::AnswerGen,
                ModelTierRef("answer".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: seat.locality,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text { text: "hi".into() }],
        }],
        tools: Vec::new(),
        params: BTreeMap::new(),
        provider_options: BTreeMap::new(),
        host_segments: None,
    };
    let body = serde_json::to_value(&request).unwrap();
    core_request_with_authz(
        "POST",
        &format!("/v1/llm/{verb}"),
        owner_bearer(),
        Some(&body),
    )
}

fn chat() -> Request<Body> {
    let body = json!({
        "conversation_ref": oneiron::EntityId::now().to_hex(),
        "text": "say hello",
    });
    core_request_with_authz("POST", "/v1/ai/chat", owner_bearer(), Some(&body))
}

fn lines(body: &[u8]) -> Vec<Value> {
    body.split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("NDJSON line"))
        .collect()
}

fn events(rows: &[RunReceipt]) -> Vec<&'static str> {
    rows.iter()
        .map(|row| match row.event {
            RunEvent::Admitted(_) => "admitted",
            RunEvent::Denied { .. } => "denied",
            RunEvent::Dispatched { .. } => "dispatched",
            RunEvent::Settled { .. } => "settled",
            RunEvent::Revised { .. } => "revised",
        })
        .collect()
}

fn dispatched(receipts: &MemoryReceipts) -> usize {
    events(&receipts.rows())
        .iter()
        .filter(|event| **event == "dispatched")
        .count()
}

/// Each path's call falls through a failing rung to an answering one: two
/// provider calls, two `Dispatched` rows, each settled.
#[tokio::test]
async fn every_server_call_writes_one_dispatched_row_per_provider_call() {
    let failing = FakeLlm::start(vec![], Some(Reply::Status(500))).await;
    let answering = FakeLlm::start(vec![], Some(Reply::text("Hello"))).await;
    let config = two_rungs(&failing, &answering, 1_000_000);
    let (_dir, server, host, receipts) = gated_server(&config).await;
    let sent = || failing.seen().len() + answering.seen().len();

    let (status, body) = send(&server, raw("generate", &config)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!((sent(), dispatched(&receipts)), (2, 2));

    let (status, body) = send(&server, raw("stream", &config)).await;
    assert_eq!(status, StatusCode::OK);
    let streamed = lines(&body);
    assert!(
        streamed
            .last()
            .is_some_and(|line| line["event"] == json!("done")),
        "{streamed:?}"
    );
    assert_eq!((sent(), dispatched(&receipts)), (4, 4));

    let (status, body) = send(&server, chat()).await;
    assert_eq!(status, StatusCode::OK);
    let turn = lines(&body);
    assert!(
        turn.iter().any(|line| line["type"] == json!("done")),
        "{turn:?}"
    );
    assert_eq!((sent(), dispatched(&receipts)), (6, 6));

    let call = ["admitted", "dispatched", "settled"];
    assert_eq!(events(&receipts.rows()), [call; 6].concat());
    host.shutdown().await;
}

/// A line of one reservation: the failing rung spends it, so the answering
/// rung has no permit. Its admission is denied with a row, and it is never
/// sent, through each path.
#[tokio::test]
async fn a_rung_its_line_cannot_cover_is_denied_and_never_sent() {
    let failing = FakeLlm::start(vec![], Some(Reply::Status(500))).await;
    let answering = FakeLlm::start(vec![], Some(Reply::text("Hello"))).await;
    let config = two_rungs(
        &failing,
        &answering,
        oneiron::llm::DEFAULT_BUDGET_RESERVE_UNITS,
    );
    for (path, sent) in [("generate", 1), ("stream", 2), ("chat", 3)] {
        // A fresh server each time: the raw routes' line lives as long as
        // the server.
        let (_dir, server, host, receipts) = gated_server(&config).await;
        let request = if path == "chat" {
            chat()
        } else {
            raw(path, &config)
        };
        let (status, body) = send(&server, request).await;
        if path == "generate" {
            assert_eq!(status, StatusCode::PAYMENT_REQUIRED);
        } else {
            // A stream already started: it ends on an error, with no answer.
            let lines = lines(&body);
            assert!(
                !lines
                    .iter()
                    .any(|line| line["event"] == json!("done") || line["type"] == json!("done")),
                "{path}: {lines:?}"
            );
        }
        assert_eq!(failing.seen().len(), sent, "{path}");
        assert!(
            answering.seen().is_empty(),
            "{path}: the second rung went out"
        );
        assert_eq!(
            events(&receipts.rows()),
            ["admitted", "dispatched", "settled", "denied"],
            "{path}"
        );
        host.shutdown().await;
    }
}
