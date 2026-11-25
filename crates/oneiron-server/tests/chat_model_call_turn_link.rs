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
//! A thread whose model changed lists each turn's answering model through
//! `vault.conversations.turns.models` (FIX [THREAD-PROVENANCE-READ]).
//!
//! Each listed call names what its request was assembled from (FIX
//! [HANDOFF-CONTEXT]): this host's default agent keeps no retained log, so a
//! turn the caller sends no earlier line with is a first (cold) turn, and one
//! with lines names how many rode and how many were past the history bound.
//! A self agent's turn names the summaries and raw turns of its retained log,
//! a reply cut at the token limit among them; a Retry the turn-action worker answers names its action; a row that names
//! no form reads unknown.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test chat_model_call_turn_link`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::attempt_queue::{AttemptQueue, AttemptState};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof, holder_proof_challenge,
};
use oneiron::code_run::model_call::{ModelCallKind, ModelCallRecord};
use oneiron::compaction::read_chat_log;
use oneiron::conversation::TURN_ACTION_ATTEMPT_KIND;
use oneiron::test_doors::model_call_turn_link::calls_linked_to_reply;
use oneiron::{EdgeActorClass, EdgeKind, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::test_doors::build_server::bind_turn_actions;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

use fake_llm::{FakeLlm, Reply as ModelReply};

/// The model every role of the test server runs, as its config names it.
const MODEL: &str = "test-model";
/// That model's engine id, as the answering rung records it: provider, the
/// configured name and the default revision.
const ENGINE_MODEL: &str = "local/test-model@live";
/// The model the thread changes to, as the second config names it.
const OTHER_MODEL: &str = "other-model";
/// The most caller lines one chat turn sends on, as the config sets it.
const HISTORY_BOUND: usize = 4;
/// That model's engine id.
const OTHER_ENGINE_MODEL: &str = "local/other-model@live";
/// A self agent's compaction window, in tokens: its threshold.
const WINDOW_TOKENS: u64 = 2_000;
/// What the owner says on each turn of a self agent's thread, about a
/// spoken paragraph long.
const TRANSCRIPT: &str = "I am walking back from the allotment now. Remember that the new \
    garden gate code is four four one seven, that the tomato beds by the shed need water \
    on Thursday, that Mira borrowed the long ladder and will bring it back after the \
    weekend, and that the compost order from the cooperative arrives on the twelfth. \
    Can you keep all of that for me and remind me of the ladder on Sunday evening?";
/// What the self agent answers each turn.
const ANSWER: &str = "Got it. The gate code is four four one seven, the tomato beds by the \
    shed need water on Thursday, Mira has the long ladder until after the weekend, and \
    the compost arrives on the twelfth. I will remind you about the ladder on Sunday \
    evening.";
/// How long a background flight or a queued turn action may take to land.
const PATIENCE: Duration = Duration::from_secs(60);

/// One served vault with a scripted local model: the owner on the host root
/// of a profiled install.
struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
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
    models_running(base_url, MODEL)
}

/// [`models`] with every role on the local model `model`.
fn models_running(base_url: &str, model: &str) -> ModelsConfig {
    let toml = format!(
        "default = \"local:{model}\"\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [chat]\nhistory_turns = {HISTORY_BOUND}\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n"
    );
    ModelsConfig::from_toml(&toml, None).expect("models config")
}

/// The models config of a self agent's host: every role on the local model
/// at `base_url`, the engine prompt package, and a small compaction window,
/// so the seeded default agent answers from its own retained log and
/// compacts it as itself (FIX 7744), as `tests/voice_self_epoch.rs` sets it.
fn self_models(base_url: &str) -> ModelsConfig {
    let prompts = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../oneiron/tests/fixtures/prompts")
        .canonicalize()
        .expect("the fixture prompt package");
    let toml = format!(
        "default = \"local:{MODEL}\"\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [code_mode]\nprompt_package = {prompts:?}\n\
         [code_mode.compaction]\nwindow_tokens = {WINDOW_TOKENS}\nhot_steps = 1\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n\
         context_tokens = 500000\n",
        prompts = prompts.display().to_string(),
    );
    ModelsConfig::from_toml(&toml, None).expect("the self agent's models config")
}

/// A chat message's text, whether a string or an array of text parts.
fn content(message: &Value) -> String {
    match &message["content"] {
        Value::String(text) => text.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// The self agent's scripted model: a compaction pass gets a summary of its
/// span, with every pin copied word for word; any other call is the turn's
/// answer.
fn self_reply(body: &Value) -> String {
    let messages = body["messages"].as_array().cloned().unwrap_or_default();
    let texts: Vec<String> = messages.iter().map(content).collect();
    if texts.iter().any(|text| text.contains("You compact")) {
        let input = texts
            .iter()
            .rev()
            .find_map(|text| {
                serde_json::from_str::<Value>(text)
                    .ok()
                    .filter(|input| input.get("from").is_some())
            })
            .unwrap_or_default();
        let mut summary =
            String::from("The person listed their garden errands; I kept every one of them.");
        for pin in input["pins"].as_array().cloned().unwrap_or_default() {
            summary.push('\n');
            summary.push_str(pin.as_str().unwrap_or_default());
        }
        return json!({"from": input["from"], "through": input["through"], "summary": summary})
            .to_string();
    }
    ANSWER.to_owned()
}

impl Host {
    async fn start(fake: &FakeLlm) -> Self {
        Self::start_with(&models(&fake.base_url)).await
    }

    /// [`Host::start`] on the models config `models`.
    async fn start_with(models: &ModelsConfig) -> Self {
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
        let (server, ai) = AiHost::attach(server, Some(models)).await;
        let server = Arc::new(server);
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
            app: build_app(Arc::clone(&server)),
            server,
            issuer,
            owner_slip,
            owner_token,
            ai,
        }
    }

    /// The owner's chat turn `text` in `conversation`, answered whole, from
    /// the owner's app on this device; its saved reply.
    async fn chat(&self, conversation: EntityId, text: &str) -> SavedReply {
        self.chat_after(conversation, text, &[]).await
    }

    /// [`Host::chat`] with the caller's earlier lines `history`, oldest first.
    async fn chat_after(
        &self,
        conversation: EntityId,
        text: &str,
        history: &[Value],
    ) -> SavedReply {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = hex(&self
            .issuer
            .binding_proof(&self.owner_slip, &challenge)
            .expect("owner holder proof"));
        let binding =
            json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string();
        let input = json!({
            "conversation_ref": conversation.to_hex(),
            "text": text,
            "history": history,
        });
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

    /// This host serving the same vault again with every role on `model`:
    /// the AI host stops, and a new server and AI host start on the vault,
    /// so the thread's next turn runs the other model.
    async fn serve_model(self, fake: &FakeLlm, model: &str) -> Self {
        let Self {
            _dir,
            vault,
            server,
            app,
            issuer,
            owner_slip,
            owner_token,
            ai,
        } = self;
        ai.shutdown().await;
        drop(app);
        drop(server);
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("chat-model-call-turn-link".into()),
                ..Default::default()
            },
        )
        .expect("create the second server");
        let (server, ai) =
            AiHost::attach(server, Some(&models_running(&fake.base_url, model))).await;
        let server = Arc::new(server);
        Self {
            _dir,
            vault,
            app: build_app(Arc::clone(&server)),
            server,
            issuer,
            owner_slip,
            owner_token,
            ai,
        }
    }

    /// The owner's facade call of `verb` with `input`: its status and body.
    async fn facade(&self, verb: &str, input: &Value) -> (StatusCode, Value) {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = hex(&self
            .issuer
            .binding_proof(&self.owner_slip, &challenge)
            .expect("owner holder proof"));
        let binding =
            json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string();
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", binding)
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("facade request");
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
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The call records the saved MESSAGE `reply` is linked to.
    fn calls(&self, reply: EntityId) -> Vec<ModelCallRecord> {
        calls_linked_to_reply(&self.vault, reply).expect("the reply's linked calls")
    }

    /// Starts this host's turn-action worker, as `serve` does once its
    /// server is built, so a queued Continue or Retry is answered.
    fn answer_turn_actions(&self) {
        bind_turn_actions(&self.ai, &self.server);
    }

    /// The owner's own slip, held by the owner PERSON on a key of this
    /// app's: a turn action keeps the slip it was asked with and stands only
    /// while that slip names its requester, which the host-held root slip
    /// never does (`standing_lost`).
    fn owner_person_slip(&self) -> (CapabilitySlip, SigningKey) {
        let owner = self
            .vault
            .ensure_embedded_owner_actor()
            .expect("embedded owner");
        let key = SigningKey::from_bytes(&[0x41; 32]);
        let mut claims = self.owner_slip.claims.clone();
        claims.slip_id = [0x41; 32];
        claims.parent_id = None;
        claims.holder_ref = owner.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = key.verifying_key().to_bytes();
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the owner's own slip");
        (slip, key)
    }

    /// Queues the owner's Retry of the assistant TURN `reply_turn` through
    /// `vault.conversations.turn.retry`, from this device, on the owner's
    /// own slip; the queue's receipt.
    async fn retry(&self, reply_turn: EntityId) -> Value {
        let (slip, key) = self.owner_person_slip();
        let binding =
            holder_proof(&slip, &key, self.vault.now_recorded_at()).expect("holder proof");
        let mut request = Request::post("/v1/core/facade/vault.conversations.turn.retry")
            .header(
                "authorization",
                format!("Bearer {}", slip.to_token().expect("slip token")),
            )
            .header("x-oneiron-binding", binding.to_string())
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"turn_id": reply_turn.to_hex()}).to_string(),
            ))
            .expect("retry request");
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
        let receipt: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        assert_eq!(status, StatusCode::OK, "the Retry was queued: {receipt}");
        receipt
    }

    /// The reply the worker saved for a queued Retry of `replaced` in
    /// `conversation`, once it completed the action: the MESSAGE that
    /// regenerates the replaced one, and the conversation's TURN that holds
    /// it.
    async fn retried_reply(&self, conversation: EntityId, replaced: &SavedReply) -> SavedReply {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let attempts = AttemptQueue::new(&self.vault)
                .list()
                .expect("the attempt queue");
            let settled: Vec<AttemptState> = attempts
                .iter()
                .filter(|row| row.kind == TURN_ACTION_ATTEMPT_KIND)
                .map(|row| row.state)
                .filter(|state| {
                    matches!(
                        state,
                        AttemptState::Completed | AttemptState::Failed | AttemptState::Cancelled
                    )
                })
                .collect();
            if !settled.is_empty() {
                assert_eq!(
                    settled,
                    vec![AttemptState::Completed],
                    "the worker answers the Retry: {attempts:?}"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the worker settles the Retry within {PATIENCE:?}: {attempts:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let messages = self
            .vault
            .sources(&replaced.message, EdgeKind::Regenerates, None)
            .expect("the MESSAGEs that regenerate the reply");
        assert_eq!(
            messages.len(),
            1,
            "one saved MESSAGE regenerates the replaced reply"
        );
        let message = messages[0];
        // A TURN is a child of its conversation; a MESSAGE is part of its
        // TURN.
        let thread_turns = self
            .vault
            .sources(&conversation, EdgeKind::ChildOf, None)
            .expect("the conversation's TURNs");
        let turn = self
            .vault
            .targets(&message, EdgeKind::PartOf, None)
            .expect("the MESSAGE's TURNs")
            .into_iter()
            .find(|turn| thread_turns.contains(turn))
            .expect("the Retry's MESSAGE sits in a TURN of the conversation");
        assert_ne!(turn, replaced.turn, "the Retry saves a TURN of its own");
        SavedReply { turn, message }
    }

    /// `vault.conversations.turns.models` on `replies`' TURNs, as the owner
    /// reads it: the listed turns.
    async fn turn_models(&self, replies: &[&SavedReply]) -> Vec<Value> {
        let refs: Vec<String> = replies.iter().map(|reply| reply.turn.to_hex()).collect();
        let (status, body) = self
            .facade(
                "vault.conversations.turns.models",
                &json!({"turn_refs": refs}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the read answered {body}");
        body["value"]["turns"]
            .as_array()
            .cloned()
            .unwrap_or_else(|| panic!("the read lists turns: {body}"))
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

/// FIX [THREAD-PROVENANCE-READ] (RULED THREAD-PROVENANCE-READER = C): a
/// thread whose model changed between two turns lists, for its turns in the
/// order asked, each turn's answering model id and provider, so a reader can
/// mark the change; a TURN the caller reads no such turn of is withheld while
/// the rest answer. Red on PR 1's head dc76605393: no verb reads a turn's
/// models.
#[test]
fn two_models_in_one_thread_list_in_turn_order() {
    run_on_engine_stack("two-models-in-one-thread", || async {
        let fake = FakeLlm::start(
            Vec::new(),
            Some(ModelReply::Text {
                text: "noted".into(),
                model: MODEL.into(),
            }),
        )
        .await;
        let host = Host::start(&fake).await;
        let conversation = EntityId::now();

        let first = host.chat(conversation, "the first model's turn").await;
        let host = host.serve_model(&fake, OTHER_MODEL).await;
        let second = host.chat(conversation, "the second model's turn").await;
        let seen = fake.seen();
        assert_eq!(seen.len(), 2, "two turns made two model calls");
        assert_eq!(
            seen[1].body["model"].as_str(),
            Some(OTHER_MODEL),
            "the second turn ran the other model"
        );

        let withheld = EntityId::now();
        let (status, body) = host
            .facade(
                "vault.conversations.turns.models",
                &json!({"turn_refs": [
                    first.turn.to_hex(),
                    second.turn.to_hex(),
                    withheld.to_hex(),
                ]}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the read answered {body}");
        let turns = body["value"]["turns"]
            .as_array()
            .unwrap_or_else(|| panic!("the read lists turns: {body}"));
        assert_eq!(turns.len(), 3, "one entry per asked turn, in order: {body}");
        for (turn, (reply, model)) in turns
            .iter()
            .zip([(&first, ENGINE_MODEL), (&second, OTHER_ENGINE_MODEL)])
        {
            assert_eq!(
                turn["turn_ref"].as_str(),
                Some(reply.turn.to_hex().as_str())
            );
            assert_eq!(turn["state"].as_str(), Some("answered"), "{turn}");
            let calls = turn["calls"]
                .as_array()
                .unwrap_or_else(|| panic!("the turn lists its calls: {turn}"));
            assert_eq!(
                calls.len(),
                1,
                "the turn names the one call that answered it: {turn}"
            );
            let mut call = calls[0].clone();
            let context = call
                .as_object_mut()
                .and_then(|call| call.remove("context"))
                .unwrap_or_else(|| panic!("the call names its context form: {turn}"));
            assert_eq!(
                call,
                json!({
                    "message_ref": reply.message.to_hex(),
                    "model": model,
                    "provider": "local",
                }),
                "the call names its model and provider, and no route, login or seat"
            );
            // FIX [HANDOFF-CONTEXT]: the caller sent no earlier line, so the
            // other model's first turn on this thread got none either.
            assert_eq!(context["form"].as_str(), Some("turn"), "{turn}");
            assert_eq!(context["history"], json!({"kind": "cold"}), "{turn}");
        }
        assert_eq!(turns[2]["state"].as_str(), Some("withheld"), "{body}");
        assert_eq!(turns[2]["calls"], json!([]), "{body}");
        host.ai.shutdown().await;
    });
}

/// The one call the read lists for the turn that saved `reply`.
fn listed_call(turns: &[Value], reply: &SavedReply) -> Value {
    let turn = turns
        .iter()
        .find(|turn| turn["turn_ref"].as_str() == Some(reply.turn.to_hex().as_str()))
        .unwrap_or_else(|| panic!("the read lists the turn {}: {turns:?}", reply.turn.to_hex()));
    assert_eq!(turn["state"].as_str(), Some("answered"), "{turn}");
    let calls = turn["calls"]
        .as_array()
        .unwrap_or_else(|| panic!("the turn lists its calls: {turn}"));
    assert_eq!(
        calls.len(),
        1,
        "the turn names the one call that answered it: {turn}"
    );
    calls[0].clone()
}

/// The context form the read lists for the one call that answered `reply`,
/// with its board's place checked against the forms a board takes.
fn listed_context(turns: &[Value], reply: &SavedReply) -> Value {
    let context = listed_call(turns, reply)["context"].clone();
    assert_eq!(
        context["form"].as_str(),
        Some("turn"),
        "a chat turn's form: {context}"
    );
    assert!(
        matches!(
            context["board"].as_str(),
            Some("rode" | "omitted" | "absent")
        ),
        "the form names its board's place: {context}"
    );
    context["history"].clone()
}

/// FIX [HANDOFF-CONTEXT] "bounded caller history", "first/cold input",
/// "absent board" and "a hash difference alone never labels a context form":
/// each turn's call names the earlier lines its request carried. A turn with
/// none is cold, whatever its words; one past the bound names the lines that
/// rode and the ones it dropped. This vault holds nothing a board would
/// carry, so no turn had a board. Red on PR 2's head 6d0ca27e05: no call
/// names a context.
#[test]
fn each_turn_names_the_earlier_lines_its_call_was_sent() {
    run_on_engine_stack("each-turn-names-its-earlier-lines", || async {
        let fake = FakeLlm::start(
            Vec::new(),
            Some(ModelReply::Text {
                text: "noted".into(),
                model: MODEL.into(),
            }),
        )
        .await;
        let host = Host::start(&fake).await;
        let conversation = EntityId::now();
        let line = |index: usize| {
            let role = if index % 2 == 0 { "user" } else { "assistant" };
            json!({"role": role, "text": format!("earlier line {index}")})
        };
        let past_bound: Vec<Value> = (0..HISTORY_BOUND + 2).map(line).collect();
        let within_bound: Vec<Value> = (0..2).map(line).collect();

        let cold = host.chat(conversation, "the thread opens").await;
        let capped = host
            .chat_after(conversation, "six lines came before", &past_bound)
            .await;
        let kept = host
            .chat_after(conversation, "two lines came before", &within_bound)
            .await;
        let other_words = host
            .chat(EntityId::now(), "another thread opens in other words")
            .await;
        assert_eq!(fake.seen().len(), 4, "four turns made four model calls");

        let replies = [&cold, &capped, &kept, &other_words];
        let turns = host.turn_models(&replies).await;
        assert_eq!(
            listed_context(&turns, &cold),
            json!({"kind": "cold"}),
            "a turn sent no earlier line is cold"
        );
        assert_eq!(
            listed_context(&turns, &capped),
            json!({"kind": "caller_lines", "kept": HISTORY_BOUND, "dropped": 2}),
            "a turn past the bound names the lines that rode and the ones dropped"
        );
        assert_eq!(
            listed_context(&turns, &kept),
            json!({"kind": "caller_lines", "kept": 2, "dropped": 0}),
            "a turn within the bound sends every line"
        );
        assert_eq!(
            listed_context(&turns, &other_words),
            json!({"kind": "cold"}),
            "a first turn in other words is cold too: its request bytes differ, its form does not"
        );
        for reply in replies {
            assert_eq!(
                listed_call(&turns, reply)["context"]["board"].as_str(),
                Some("absent"),
                "no board rode or was left out: the vault holds nothing a board carries"
            );
        }
        host.ai.shutdown().await;
    });
}

/// FIX [HANDOFF-CONTEXT] "same-rung Retry": the owner's Retry of a saved
/// reply, answered by the turn-action worker on the model that answered the
/// first time, names its action: its history was rebuilt from the ledger,
/// not sent as a chat turn's lines. The replaced reply keeps its own form.
/// Red on PR 2's head 6d0ca27e05: no call names a context.
#[test]
fn a_retried_reply_names_its_turn_action() {
    run_on_engine_stack("a-retried-reply-names-its-action", || async {
        let fake = FakeLlm::start(
            Vec::new(),
            Some(ModelReply::Text {
                text: "noted".into(),
                model: MODEL.into(),
            }),
        )
        .await;
        let host = Host::start(&fake).await;
        host.answer_turn_actions();
        let conversation = EntityId::now();

        let first = host.chat(conversation, "when does the ferry leave").await;
        let receipt = host.retry(first.turn).await;
        let retried = host.retried_reply(conversation, &first).await;

        let turns = host.turn_models(&[&first, &retried]).await;
        assert_eq!(
            listed_context(&turns, &first),
            json!({"kind": "cold"}),
            "the replaced reply keeps its chat turn's form"
        );
        assert_eq!(
            listed_call(&turns, &retried),
            json!({
                "message_ref": retried.message.to_hex(),
                "model": ENGINE_MODEL,
                "provider": "local",
                "context": {"form": "turn_action", "action": "retry"},
            }),
            "the Retry ran on the same model and names its action (queued as {receipt})"
        );
        host.ai.shutdown().await;
    });
}

/// FIX [HANDOFF-CONTEXT] "summary+raw": a self agent's turn, once a
/// compaction summary stands in its thread, names the summaries its retained
/// log carried and the raw turns after them: the summaries fold this
/// thread's earlier turns, and the raw turns are the thread's turns no
/// summary folds. Red on PR 2's head 6d0ca27e05: no call names a context.
#[test]
fn a_self_agents_turn_names_its_summaries_and_raw_turns() {
    run_on_engine_stack("a-self-turn-names-summaries-and-raw", || async {
        let fake =
            FakeLlm::start(Vec::new(), Some(ModelReply::Computed(Arc::new(self_reply)))).await;
        let host = Host::start_with(&self_models(&fake.base_url)).await;
        let conversation = EntityId::now();

        // Enough turns that the raw ones outgrow the window, the last one
        // still hot.
        let per_turn = u64::try_from(
            oneiron::count_context_pack_tokens(TRANSCRIPT)
                + oneiron::count_context_pack_tokens(ANSWER),
        )
        .unwrap_or(u64::MAX);
        let turns = WINDOW_TOKENS / per_turn.max(1) + 2;
        for _ in 0..turns {
            host.chat(conversation, TRANSCRIPT).await;
        }
        // The flight runs off the turn's path: wait for its summary to stand.
        let owner = host
            .vault
            .ensure_embedded_owner_actor()
            .expect("embedded owner");
        let reader = host.vault.memory(owner, EdgeActorClass::Human);
        let deadline = Instant::now() + PATIENCE;
        loop {
            let log = read_chat_log(&reader, conversation, 1, usize::MAX)
                .expect("the thread's retained log");
            if !log.summaries.is_empty() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "a summary stands in the thread after {turns} turns ({per_turn} tokens each, window {WINDOW_TOKENS})"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let next = host.chat(conversation, TRANSCRIPT).await;
        let listed = host.turn_models(&[&next]).await;
        let history = listed_context(&listed, &next);
        assert_eq!(
            history["kind"].as_str(),
            Some("retained_log"),
            "a self agent's turn names its retained log: {history}"
        );
        let refs = |field: &str| -> Vec<EntityId> {
            history[field]
                .as_array()
                .unwrap_or_else(|| panic!("the form lists {field}: {history}"))
                .iter()
                .map(|id| {
                    id.as_str()
                        .and_then(|hex| EntityId::from_hex(hex).ok())
                        .unwrap_or_else(|| panic!("{field} holds ids: {history}"))
                })
                .collect()
        };
        let summaries = refs("summary_refs");
        let raw_turns = refs("raw_turn_refs");
        assert!(
            !summaries.is_empty(),
            "the log carried a summary: {history}"
        );
        assert!(
            !raw_turns.is_empty(),
            "the log carried raw turns after it: {history}"
        );
        let thread_turns = host
            .vault
            .sources(&conversation, EdgeKind::ChildOf, None)
            .expect("the conversation's TURNs");
        let mut folded = Vec::new();
        for summary in &summaries {
            let spans = host
                .vault
                .summary_folded_spans(summary)
                .expect("the summary's receipt")
                .unwrap_or_else(|| {
                    panic!("{} is a landed summary of the thread", summary.to_hex())
                });
            folded.extend(spans.into_iter().map(|span| span.turn));
        }
        assert!(
            !folded.is_empty() && folded.iter().all(|turn| thread_turns.contains(turn)),
            "each listed summary folds this thread's earlier turns"
        );
        assert!(
            raw_turns
                .iter()
                .all(|turn| thread_turns.contains(turn) && !folded.contains(turn)),
            "each raw turn is a turn of the thread no listed summary folds"
        );
        assert!(
            !raw_turns.contains(&next.turn),
            "a turn's history holds no line of its own reply"
        );
        host.ai.shutdown().await;
    });
}

/// What a self agent's reply had said when the model stopped at its token
/// limit: the saved, incomplete text the next turn's request carries.
const CUT_ANSWER: &str = "Got it. The gate code is four four one seven, and the tomato beds";

/// An OpenAI-compatible reply stream that says `text` as `model` and ends at
/// the token limit (`finish_reason` "length").
fn cut_stream(text: &str, model: &str) -> String {
    let events = [
        json!({"id": "chatcmpl-cut", "object": "chat.completion.chunk", "model": model,
            "choices": [{"index": 0, "delta": {"role": "assistant", "content": text}, "finish_reason": null}]}),
        json!({"id": "chatcmpl-cut", "object": "chat.completion.chunk", "model": model,
            "choices": [{"index": 0, "delta": {}, "finish_reason": "length"}]}),
        json!({"id": "chatcmpl-cut", "object": "chat.completion.chunk", "model": model,
            "choices": [], "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}}),
    ];
    let mut body: String = events
        .iter()
        .map(|event| format!("data: {event}\n\n"))
        .collect();
    body.push_str("data: [DONE]\n\n");
    body
}

/// FIX [HANDOFF-CONTEXT], review round 1 of #9382 (26 Nov): a self agent's
/// reply cut at the token limit is saved incomplete with the text it had
/// said, and the next turn's request carries that text, so the next turn's
/// retained log names the cut TURN among its raw turns, although no
/// projection pins an incomplete turn. Red on #9382's head bd941757d2: the
/// form lists only the turns a projection pinned.
#[test]
fn a_self_agents_turn_names_a_raw_turn_cut_at_the_token_limit() {
    run_on_engine_stack("a-self-turn-names-a-cut-raw-turn", || async {
        let fake = FakeLlm::start(
            vec![ModelReply::Raw(cut_stream(CUT_ANSWER, MODEL))],
            Some(ModelReply::Computed(Arc::new(self_reply))),
        )
        .await;
        let host = Host::start_with(&self_models(&fake.base_url)).await;
        let conversation = EntityId::now();

        let cut = host.chat(conversation, TRANSCRIPT).await;
        let next = host.chat(conversation, TRANSCRIPT).await;
        // Only a request made after the cut reply can hold its words.
        assert!(
            fake.seen()
                .iter()
                .any(|seen| seen.body.to_string().contains(CUT_ANSWER)),
            "the next turn's request carries the cut reply's saved text"
        );

        let listed = host.turn_models(&[&next]).await;
        let history = listed_context(&listed, &next);
        assert_eq!(
            history["kind"].as_str(),
            Some("retained_log"),
            "a self agent's turn names its retained log: {history}"
        );
        let raw_turns: Vec<EntityId> = history["raw_turn_refs"]
            .as_array()
            .unwrap_or_else(|| panic!("the form lists raw_turn_refs: {history}"))
            .iter()
            .map(|id| {
                id.as_str()
                    .and_then(|hex| EntityId::from_hex(hex).ok())
                    .unwrap_or_else(|| panic!("raw_turn_refs holds ids: {history}"))
            })
            .collect();
        assert!(
            raw_turns.contains(&cut.turn),
            "the cut reply's TURN is a raw turn of the next turn's log: {history}"
        );
        assert!(
            !raw_turns.contains(&next.turn),
            "a turn's history holds no line of its own reply"
        );
        host.ai.shutdown().await;
    });
}

/// FIX [HANDOFF-CONTEXT] "foreign unknown": a stored call row that names no
/// form, as every row recorded before the form existed and every capture
/// that keeps none (workflow steps, native reads, a foreign harness), decodes
/// and writes back with no form: unknown is never filled in. The rows go
/// through the codec of the call table (`Named`: MessagePack with field
/// names). Red on PR 2's head 6d0ca27e05: a chat call's row names no form.
#[test]
fn a_call_row_with_no_form_stays_unknown() {
    run_on_engine_stack("a-call-row-with-no-form", || async {
        let fake = FakeLlm::start(
            Vec::new(),
            Some(ModelReply::Text {
                text: "noted".into(),
                model: MODEL.into(),
            }),
        )
        .await;
        let host = Host::start(&fake).await;
        let reply = host
            .chat(EntityId::now(), "when does the market open")
            .await;
        let seen = fake.seen();
        let record = answering_call(
            host.calls(reply.message),
            &seen[0].body["model"],
            "the reply",
        );

        let fields = |record: &ModelCallRecord| -> Vec<(rmpv::Value, rmpv::Value)> {
            let bytes = rmp_serde::to_vec_named(record).expect("the call row encodes");
            match rmpv::decode::read_value(&mut bytes.as_slice()).expect("MessagePack") {
                rmpv::Value::Map(fields) => fields,
                other => panic!("a call row is a map of named fields: {other}"),
            }
        };
        let context = |fields: &[(rmpv::Value, rmpv::Value)]| {
            fields
                .iter()
                .find(|(name, _)| name.as_str() == Some("context"))
                .map(|(_, value)| value.clone())
        };
        let stored = fields(&record);
        assert!(
            context(&stored).is_some(),
            "a chat call's row names the form it was assembled from"
        );

        // The same row as a capture that kept no form writes it.
        let unknown: Vec<(rmpv::Value, rmpv::Value)> = stored
            .into_iter()
            .filter(|(name, _)| name.as_str() != Some("context"))
            .collect();
        let mut bytes = Vec::new();
        rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(unknown.clone()))
            .expect("the row without a form encodes");
        let decoded: ModelCallRecord =
            rmp_serde::from_slice(&bytes).expect("a row without a form decodes");
        let written = fields(&decoded);
        assert_eq!(
            context(&written),
            None,
            "a row read with no form is written back with none"
        );
        assert_eq!(
            written, unknown,
            "every other field of the row reads as it was stored"
        );
        host.ai.shutdown().await;
    });
}
