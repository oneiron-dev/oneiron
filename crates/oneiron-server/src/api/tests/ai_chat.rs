//! `/v1/ai`: a chat turn streams through the bus and the socket fanout and
//! saves its terminal once; status and session hints over HTTP.
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::*;
use crate::ai_host::AiHost;
use crate::ai_host::test_support::{
    TEST_SECRET, eventually, models, models_toml, rooted_vault, saved_agent,
};
use crate::fake_llm::{FakeLlm, Reply};
use crate::server::{BroadcastPayload, SyncServer};

async fn ai_server(base_url: Option<&str>) -> (tempfile::TempDir, Arc<SyncServer>, AiHost) {
    ai_server_with(base_url.map(|url| models(url, ""))).await
}

async fn ai_server_with(
    config: Option<crate::config::models::ModelsConfig>,
) -> (tempfile::TempDir, Arc<SyncServer>, AiHost) {
    let (dir, vault) = rooted_vault();
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some(TEST_SECRET.into()),
            ..Default::default()
        },
    )
    .unwrap();
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

/// Astra #1304 P1: a credential revoked while its turn waits on the model
/// kept receiving the reply, and the reply still landed as a normal answer.
#[tokio::test]
async fn a_credential_revoked_mid_turn_sees_no_more_of_the_reply_and_it_is_not_finalized() {
    let fake = FakeLlm::start(
        vec![Reply::Hold {
            text: "the held answer".into(),
        }],
        None,
    )
    .await;
    let (_dir, server, host) = ai_server(Some(&fake.base_url)).await;
    let recipe = "jti=chat-revoked-mid-turn";
    let turn = tokio::spawn({
        let server = Arc::clone(&server);
        let request = core_request_with_authz(
            "POST",
            "/v1/ai/chat",
            test_bearer(recipe),
            Some(&json!({"conversation_ref": oneiron::EntityId::now().to_hex(), "text": "hi"})),
        );
        async move { send(&server, request).await }
    });
    fake.wait_holding().await;
    slip_credentials::revoke(&server, recipe);
    fake.release();
    let (status, body) = turn.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    let lines = lines(&body);
    assert_eq!(lines[0]["type"], json!("accepted"));
    assert!(
        !String::from_utf8_lossy(&body).contains("held answer"),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .all(|line| !["delta", "done", "saved"].contains(&line["type"].as_str().unwrap())),
        "{lines:?}"
    );
    // The model's words are not the vault's answer either.
    let message = oneiron::EntityId::from_hex(lines[0]["message_id"].as_str().unwrap()).unwrap();
    let stored = server.vault().get(&message).unwrap().unwrap_or_default();
    assert!(!String::from_utf8_lossy(&stored).contains("held answer"));
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
async fn a_named_agent_must_be_dispatchable_and_no_model_is_called() {
    let fake = FakeLlm::start(vec![], Some(Reply::Status(500))).await;
    let (_dir, server, host) = ai_server(Some(&fake.base_url)).await;
    let (status, body) = send(
        &server,
        chat(json!({
            "conversation_ref": oneiron::EntityId::now().to_hex(),
            "text": "hi",
            "agent_ref": oneiron::EntityId::now().to_hex(),
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], json!("agent_not_dispatchable"));
    assert!(fake.seen().is_empty());
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

/// A manifest whose every role sits on the LLM slot, pinned to `cloud/big`
/// at the widest route with narrower models for the vault to narrow to.
fn install_route_manifest(vault: &oneiron::Vault) {
    use oneiron::llm::manifest::{
        MODEL_ROLES, ModelBinding, ModelManifest, ModelRole, ModelSlot, TeacherProbeApproval,
    };
    use oneiron::{ModelId, ModelLocality, ModelTierRef};
    let model = |id: &str| ModelId::new(id).unwrap();
    let manifest = ModelManifest {
        version: 2,
        roles: MODEL_ROLES
            .into_iter()
            .map(|role| {
                (
                    role,
                    ModelBinding {
                        model: model("cloud/big@live"),
                        slot: ModelSlot::Llm,
                        tier: ModelTierRef("chat".into()),
                        // The teacher's pin is probe-approved as one model.
                        route_models: if role == ModelRole::ExtractionTeacher {
                            std::collections::BTreeMap::new()
                        } else {
                            std::collections::BTreeMap::from([
                                (ModelLocality::OwnServer, model("local/small@live")),
                                (ModelLocality::OnDevice, model("device/tiny@live")),
                            ])
                        },
                    },
                )
            })
            .collect(),
        routes: [
            (ModelSlot::Llm, ModelLocality::ThirdParty),
            (ModelSlot::Embedder, ModelLocality::OnDevice),
            (ModelSlot::Oneironer, ModelLocality::OnDevice),
        ]
        .into_iter()
        .collect(),
        verdict: None,
        seat_policy: None,
    };
    let approval = TeacherProbeApproval::for_scored_checkpoint(
        &manifest,
        &vault.teacher_probe_policy(None).unwrap(),
        1_000_000,
    )
    .unwrap();
    vault
        .set_model_manifest_with_teacher_approval(&manifest, &approval)
        .unwrap();
}

/// Astra #1304 P1: chat and workflow steps took the raw-call exception, so a
/// vault that narrowed its model route still sent them to a third party.
#[tokio::test]
async fn a_narrowed_vault_route_keeps_chat_and_workflow_steps_off_the_cloud() {
    use oneiron::agent_dispatch::{AgentDispatchTarget, AgentDispatcher, DispatchAgent};
    use oneiron::llm::manifest::ModelSlot;
    use oneiron::{EntityId, ModelLocality};
    let cloud = FakeLlm::start(vec![], Some(Reply::text("from the cloud"))).await;
    let local = FakeLlm::start(vec![], Some(Reply::text("from this server"))).await;
    let (_dir, server, host) = ai_server_with(Some(models_toml(&format!(
        "cloud = \"cloud:big\"\nlocal = \"local:small\"\nprefer_local = false\n[dreamer]\nenabled = false\n[providers.cloud]\nkind = \"openai-compat\"\nbase_url = \"{}\"\n[providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{}\"\n",
        cloud.base_url, local.base_url
    ))))
    .await;
    let vault = Arc::clone(server.vault());
    install_route_manifest(&vault);
    let turn = || chat(json!({"conversation_ref": EntityId::now().to_hex(), "text": "hi"}));

    // At the pin's widest route the manifest's cloud model answers.
    let (status, body) = send(&server, turn()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(lines(&body).last().unwrap()["type"], json!("saved"));
    assert_eq!((cloud.seen().len(), local.seen().len()), (1, 0));

    // The vault narrows its LLM route to its own server: chat and a saved
    // workflow's step both stay there.
    vault
        .set_model_route(ModelSlot::Llm, ModelLocality::OwnServer)
        .unwrap();
    let (status, body) = send(&server, turn()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(lines(&body).last().unwrap()["type"], json!("saved"));
    let agent = saved_agent(&vault, "narrowed", "Say one word.");
    let workflow = EntityId::now();
    vault
        .save_workflow(
            &workflow,
            &oneiron::agent_def::workflow::WorkflowDefinition::new("narrowed", vec![agent])
                .unwrap(),
            2,
        )
        .unwrap();
    let dispatcher = AgentDispatcher::new(&vault);
    dispatcher
        .dispatch(DispatchAgent {
            target: AgentDispatchTarget::Workflow(workflow),
            parent_attempt: None,
            dedupe_key: Some("narrowed".into()),
            run_id: Some("narrowed".into()),
            now: 10,
        })
        .unwrap();
    assert!(
        eventually(std::time::Duration::from_secs(20), || dispatcher
            .open_workflow_roots()
            .is_ok_and(|roots| roots.is_empty()))
        .await
    );
    assert_eq!((cloud.seen().len(), local.seen().len()), (1, 2));

    // Narrowed to the device, which this server cannot serve: refused before
    // any call leaves.
    vault
        .set_model_route(ModelSlot::Llm, ModelLocality::OnDevice)
        .unwrap();
    let (status, body) = send(&server, turn()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], json!("model_route_not_served"));
    assert_eq!((cloud.seen().len(), local.seen().len()), (1, 2));
    host.shutdown().await;
}
