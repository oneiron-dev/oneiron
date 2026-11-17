#![cfg(oneiron_test_support)]
//! A saved chat reply names the model call that answered it (UNBUILT3-41,
//! FIX [TURN-MODEL-LINK]). Canon ARCH-0026 #model-call-record: "One
//! model-call record sits beside the messages for every call. It references
//! input and output bodies, source rows and produced rows".
//!
//! The owner chats at `POST /v1/ai/chat` with a scripted local model. The
//! reply's saved MESSAGE (`message_id`) is linked to the one kept call record
//! that answered it, and that record names the model the call ran. Two turns
//! in two conversations each name only their own call. On main no call names
//! its reply: the record carries no conversation, TURN or MESSAGE (the chat
//! capture in `api/llm.rs` sets `thread_id: None` and keeps no reply ref), so
//! the door reads no link.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test chat_model_call_turn_link`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge};
use oneiron::code_run::model_call::{ModelCallKind, ModelCallRecord};
use oneiron::test_doors::model_call_turn_link::calls_linked_to_reply;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

use fake_llm::{FakeLlm, Reply as ModelReply};

/// The model every role of the test server runs, as its config names it.
const MODEL: &str = "test-model";
/// That model's engine id, as the answering rung records it: provider, the
/// configured name and the default revision.
const ENGINE_MODEL: &str = "local/test-model@live";

/// One served vault with a scripted local model: the owner on the host root
/// of a profiled install.
struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    ai: AiHost,
}

/// The saved reply of one chat turn: its assistant TURN and MESSAGE.
struct SavedReply {
    turn: EntityId,
    message: EntityId,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The models config of a server whose every role is the local model at
/// `base_url`, with no background model work.
fn models(base_url: &str) -> ModelsConfig {
    let toml = format!(
        "default = \"local:{MODEL}\"\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n"
    );
    ModelsConfig::from_toml(&toml, None).expect("models config")
}

impl Host {
    async fn start(fake: &FakeLlm) -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let mut config = VaultConfig::device();
        config.embedding_model = None;
        config.dimensions = 4;
        let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("chat-model-call-turn-link".into()),
                ..Default::default()
            },
        )
        .expect("create server");
        let (server, ai) = AiHost::attach(server, Some(&models(&fake.base_url))).await;
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let owner_slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("owner root slip");
        let owner_token = owner_slip.to_token().expect("owner slip token");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        vault.ensure_embedded_owner_actor().expect("embedded owner");
        Self {
            _dir: dir,
            vault,
            app: build_app(Arc::new(server)),
            issuer,
            owner_slip,
            owner_token,
            ai,
        }
    }

    /// The owner's chat turn `text` in `conversation`, answered whole, from
    /// the owner's app on this device; its saved reply.
    async fn chat(&self, conversation: EntityId, text: &str) -> SavedReply {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = hex(&self
            .issuer
            .binding_proof(&self.owner_slip, &challenge)
            .expect("owner holder proof"));
        let binding =
            json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string();
        let input = json!({"conversation_ref": conversation.to_hex(), "text": text});
        let mut request = Request::post("/v1/ai/chat")
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", binding)
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("chat request");
        // A session key is admitted only for a caller the listener saw on
        // loopback: the owner's app on this device.
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((Ipv4Addr::LOCALHOST, 40_000))));
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("the app's response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the response body");
        let body: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "the chat turn answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        assert_eq!(status, StatusCode::OK, "the chat turn answered {body}");
        let id = |field: &str| {
            body[field]
                .as_str()
                .and_then(|hex| EntityId::from_hex(hex).ok())
                .unwrap_or_else(|| panic!("the chat reply names no {field}: {body}"))
        };
        SavedReply {
            turn: id("turn_id"),
            message: id("message_id"),
        }
    }

    /// The call records the saved MESSAGE `reply` is linked to.
    fn calls(&self, reply: EntityId) -> Vec<ModelCallRecord> {
        calls_linked_to_reply(&self.vault, reply).expect("the reply's linked calls")
    }
}

/// The one call `records` holds, which generated the reply with
/// `ENGINE_MODEL` under the wire model the scripted model was sent.
fn answering_call(
    records: Vec<ModelCallRecord>,
    wire_model: &Value,
    what: &str,
) -> ModelCallRecord {
    assert_eq!(
        records.len(),
        1,
        "{what}: the saved reply names exactly the one call that answered it: {records:?}"
    );
    let record = records.into_iter().next().expect("one record");
    assert!(
        matches!(record.kind, ModelCallKind::Generate { .. }),
        "{what}: the answering call generated the reply: {:?}",
        record.kind
    );
    assert_eq!(
        record.rung.model.as_str(),
        ENGINE_MODEL,
        "{what}: the answering call names the model it ran"
    );
    let route = record
        .route
        .as_ref()
        .unwrap_or_else(|| panic!("{what}: the answering call names its route"));
    assert_eq!(
        Some(route.wire_model.as_str()),
        wire_model.as_str(),
        "{what}: the call's route names the model the provider was sent"
    );
    record
}

/// FIX [TURN-MODEL-LINK]: one chat turn's saved reply names the call that
/// answered it, and the model that call ran. Red on main: no call names its
/// reply.
#[test]
fn a_saved_reply_names_the_call_that_answered_it() {
    run_on_engine_stack("a-saved-reply-names-its-call", || async {
        let fake = FakeLlm::start(
            vec![ModelReply::Text {
                text: "the harbor light turns at nine".into(),
                model: MODEL.into(),
            }],
            None,
        )
        .await;
        let host = Host::start(&fake).await;

        let reply = host
            .chat(EntityId::now(), "when does the harbor light turn")
            .await;

        let seen = fake.seen();
        assert_eq!(seen.len(), 1, "one turn made one model call");
        answering_call(
            host.calls(reply.message),
            &seen[0].body["model"],
            "the reply",
        );
        // The link names the reply MESSAGE, never the TURN that holds it.
        assert!(
            host.calls(reply.turn).is_empty(),
            "a TURN id names no call; its saved MESSAGE does"
        );
        host.ai.shutdown().await;
    });
}

/// FIX [TURN-MODEL-LINK] "unrelated parallel threads do not join": two
/// turns in two conversations each name only their own call. Red on main: no
/// call names its reply.
#[test]
fn two_replies_in_two_conversations_each_name_only_their_own_call() {
    run_on_engine_stack("two-replies-name-their-own-calls", || async {
        let fake = FakeLlm::start(
            Vec::new(),
            Some(ModelReply::Text {
                text: "noted".into(),
                model: MODEL.into(),
            }),
        )
        .await;
        let host = Host::start(&fake).await;

        let first = host.chat(EntityId::now(), "the first conversation").await;
        let second = host.chat(EntityId::now(), "the second conversation").await;

        let seen = fake.seen();
        assert_eq!(seen.len(), 2, "two turns made two model calls");
        let first_call = answering_call(host.calls(first.message), &seen[0].body["model"], "first");
        let second_call =
            answering_call(host.calls(second.message), &seen[1].body["model"], "second");
        assert_ne!(
            first_call.key(),
            second_call.key(),
            "each reply names its own call, never the other conversation's"
        );
        host.ai.shutdown().await;
    });
}
