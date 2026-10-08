//! `/v1/ai`: a chat turn streams through the bus and the socket fanout and
//! saves its terminal once; status and session hints over HTTP.
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::ai_host::AiHost;
use crate::ai_host::test_support::{TEST_SECRET, models, rooted_vault};
use crate::fake_llm::{FakeLlm, Reply};
use crate::server::{BroadcastPayload, SyncServer};

async fn ai_server(base_url: Option<&str>) -> (tempfile::TempDir, Arc<SyncServer>, AiHost) {
    let (dir, vault) = rooted_vault();
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some(TEST_SECRET.into()),
            ..Default::default()
        },
    )
    .unwrap();
    let config = base_url.map(|url| models(url, ""));
    let (server, host) = AiHost::attach(server, config.as_ref()).await;
    (dir, Arc::new(server), host)
}

async fn send(server: &Arc<SyncServer>, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let request = slip_credentials::bind_request(server, request);
    let response = api_routes(Arc::clone(server))
        .oneshot(request)
        .await
        .expect("route response");
    let status = response.status();
    (
        status,
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
}

fn chat(body: Value) -> Request<Body> {
    core_request_with_authz("POST", "/v1/ai/chat", owner_bearer(), Some(&body))
}

fn lines(body: &[u8]) -> Vec<Value> {
    body.split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).expect("NDJSON line"))
        .collect()
}

#[tokio::test]
async fn a_chat_turn_streams_deltas_to_subscribers_and_saves_its_terminal_once() {
    let fake = FakeLlm::start(
        vec![Reply::Deltas {
            deltas: vec!["Hel".into(), "lo ".into(), "there".into()],
            model: "served-under-another-name".into(),
        }],
        None,
    )
    .await;
    let (_dir, server, host) = ai_server(Some(&fake.base_url)).await;
    // The socket plane: every owner connection reads this fanout.
    let mut socket = server.broadcast_tx.subscribe();
    let conversation = oneiron::EntityId::now().to_hex();
    let (status, body) = send(
        &server,
        chat(json!({
            "conversation_ref": conversation,
            "text": "say hello",
            "history": [{"role": "user", "text": "earlier"}, {"role": "assistant", "text": "noted"}],
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let lines = lines(&body);
    assert_eq!(lines[0]["type"], json!("accepted"));
    let deltas: Vec<_> = lines
        .iter()
        .filter(|line| line["type"] == json!("delta"))
        .map(|line| line["text"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(deltas, ["Hel", "lo ", "there"]);
    let done = lines
        .iter()
        .find(|line| line["type"] == json!("done"))
        .unwrap();
    assert_eq!(done["text"], json!("Hello there"));
    assert_eq!(
        done["usage"]["raw_provider"]["reported_model"],
        json!("served-under-another-name")
    );
    let saved = lines.last().unwrap();
    assert_eq!(saved["type"], json!("saved"), "{lines:?}");
    assert_eq!(saved["receipt"]["finality"], json!("final"));
    assert_eq!(saved["receipt"]["bytes"], json!("Hello there".len()));

    // The one durable write: the assistant MESSAGE, its text the whole reply.
    let message = oneiron::EntityId::from_hex(lines[0]["message_id"].as_str().unwrap()).unwrap();
    let raw = server
        .vault()
        .get(&message)
        .unwrap()
        .expect("assistant message");
    assert!(String::from_utf8_lossy(&raw).contains("Hello there"));
    // Deltas rode the existing socket fanout as transient frames.
    let mut frames = 0;
    while let Ok(payload) = socket.try_recv() {
        if matches!(payload, BroadcastPayload::Frame(0, _)) {
            frames += 1;
        }
    }
    assert!(frames >= 1, "no transient frame reached the socket fanout");
    // History and the user's text reached the model, in order.
    let sent = &fake.seen()[0].body["messages"];
    let texts: Vec<_> = sent
        .as_array()
        .unwrap()
        .iter()
        .map(|message| message["content"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(texts[texts.len() - 3..], ["earlier", "noted", "say hello"]);
    host.shutdown().await;
}

#[tokio::test]
async fn a_failed_model_call_cancels_the_message_and_reports_why() {
    let fake = FakeLlm::start(vec![], Some(Reply::Status(500))).await;
    let (_dir, server, host) = ai_server(Some(&fake.base_url)).await;
    let (status, body) = send(
        &server,
        chat(json!({"conversation_ref": oneiron::EntityId::now().to_hex(), "text": "hi"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let lines = lines(&body);
    let last = lines.last().unwrap();
    assert_eq!(last["type"], json!("error"), "{lines:?}");
    assert!(!lines.iter().any(|line| line["type"] == json!("saved")));
    host.shutdown().await;
}

#[tokio::test]
async fn without_a_model_chat_refuses_and_status_says_why() {
    let (_dir, server, host) = ai_server(None).await;
    let (status, body) = send(
        &server,
        chat(json!({"conversation_ref": oneiron::EntityId::now().to_hex(), "text": "hi"})),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], json!("no_model_configured"));
    let (status, body) = send(
        &server,
        core_request_with_authz("GET", "/v1/ai/status", owner_bearer(), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["ai"]["dreamer"]["state"], json!("idle"));
    assert_eq!(
        body["ai"]["dreamer"]["reason"],
        json!("no_model_configured")
    );
    assert_eq!(body["models"]["configured"], json!(false));
    // A session hint without a Dreamer is accepted and changes nothing.
    let (status, _) = send(
        &server,
        core_request_with_authz(
            "POST",
            "/v1/ai/session",
            owner_bearer(),
            Some(&json!({"event": "end"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    host.shutdown().await;
}

/// Done means 1: a fresh vault and no `[models]` at all — capture, find and
/// export all work, and the Dreamer reports idle for want of a model.
#[tokio::test]
async fn a_fresh_vault_without_models_captures_finds_exports_and_reports_the_dreamer_idle() {
    let (_dir, server, host) = ai_server(None).await;
    let note = oneiron::EntityId::now();
    let (status, body) = route_json(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/memory/verbs/remember",
            owner_bearer(),
            Some(&json!({
                "entity": {
                    "id": note.to_hex(),
                    "entity_type": oneiron::registry::ENTITY_TYPE_TURN,
                    "body": {"txt": "buy saffron for the risotto", "spkr": "user"},
                    "text": [{"field": "body", "value": "buy saffron for the risotto"}]
                }
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body:#}");

    let (status, found) = route_json(
        server.clone(),
        core_request_with_authz(
            "GET",
            "/api/search/text?query=saffron",
            owner_bearer(),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{found:#}");
    assert!(
        found["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["id"] == json!(note.to_hex())),
        "{found:#}"
    );

    let (status, exported) = route_json(
        server.clone(),
        core_request_with_authz(
            "POST",
            "/v1/core/facade/export",
            owner_bearer(),
            Some(&json!({"format": "json"})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{exported:#}");
    assert!(exported["rendered"].as_str().unwrap().contains("saffron"));

    let (status, health) = route_json(
        server.clone(),
        Request::builder()
            .uri("/api/health")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        health["ai"],
        json!({"dreamer": "idle", "dreamer_reason": "no_model_configured"})
    );
    host.shutdown().await;
}
