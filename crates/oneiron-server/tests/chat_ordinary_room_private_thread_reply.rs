//! Path 1 of the ruling (CHAT-THREAD-REPLY-REFUSAL-SCOPE = B): a chat
//! turn whose `reply_to` names a TURN of one of an ordinary room's private
//! threads is refused by the room's witness, and `POST /v1/ai/chat` answers
//! 409 `turn_refused` before any model is called. A `reply_to` naming a
//! room-wide thread's root is answered as today.
//!
//! Fixture: owen, the vault's owner, in an ordinary group room he holds
//! alone, served over the public app with every seat on a fake model. A
//! trunk witness turn anchors each thread: owen's DAG reply opens a private
//! thread (audience owen) and, on a second anchor, a room-wide thread.
//!
//! * `a_chat_reply_to_a_private_threads_root_is_refused_before_any_model_call`:
//!   `reply_to` the private root answers 409 with error code `turn_refused`,
//!   the fake model received no request, and owen's room history gained no
//!   turn. Red on main by assertion: there the witness lands the turn, so
//!   the route answers 2xx after calling the model.
//! * `a_chat_reply_to_a_room_wide_threads_root_is_answered`: `reply_to` the
//!   room-wide root is answered 2xx with the model's text, the model was
//!   called, and the room's history grew. Green on main too: a control.
//!
//! Public paths only, through the coach harness (`support/engine_stack.rs`,
//! `support/fake_llm.rs`, an owner root slip); the vault is rooted on a
//! `MemoryKeystore`, which needs the test-support cfg.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! chat_ordinary_room_private_thread_reply`.
#![cfg(oneiron_test_support)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use engine_stack::run_on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::core_write::ConversationCreateInput;
use oneiron::federation::Scope;
use oneiron::memory::{Memory, MemoryResult, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow, policy_manifests_as_owner,
    put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::{build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct ChatFixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    host: AiHost,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    model: FakeLlm,
}

/// owen's ordinary room on the vault the server holds.
struct Room {
    vault: Arc<Vault>,
    owen: EntityId,
    room: EntityId,
}

impl Room {
    fn owen(&self) -> Memory<'_> {
        self.vault.memory(self.owen, EdgeActorClass::Human)
    }
}

/// The models config: every seat on the fake model, keyless, with the
/// Dreamer and the workflows off, so no background pass calls the model.
fn models_text(base_url: &str) -> String {
    format!(
        "default = \"local:test-model\"\nextraction_egress = true\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n"
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// owen reads the vault's records: a row added to the default policy
/// manifest, the shipped rows kept.
fn grant_reads(vault: &Vault, owen: EntityId) -> TestResult {
    let proof = vault
        .memory(owen, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    let view =
        policy_manifests_as_owner(vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    rows.push(PolicyScopedGrantRow {
        // Bare census keys carry no actor class.
        actor_class: None,
        actor_ref: Some(owen.to_hex()),
        effector: "core:read".into(),
        scope: Scope::top(),
        selectors: None,
        budget: None,
        receipt_required: false,
    });
    manifest.scoped_grants = Some(rows);
    put_policy_manifest_as_owner(
        vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )?;
    Ok(())
}

/// An ordinary group room owen creates, and so hosts, holding owen alone.
fn ordinary_room(vault: &Vault, owen: EntityId) -> TestResult<EntityId> {
    let receipt = vault
        .memory(owen, EdgeActorClass::Human)
        .conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: serde_json::json!({
                "v": 1,
                "kind": "group",
                "member_ids": [owen.to_hex()],
                "title": "ordinary room",
            }),
            text: None,
        })?;
    Ok(EntityId::from_hex(&receipt.id)?)
}

/// owen's one-message witness turn in the room through the room speech
/// door, its message carrying `metadata`. Returns the TURN it names and the
/// door's answer.
fn speak(place: &Room, metadata: serde_json::Value) -> (EntityId, MemoryResult<()>) {
    let turn = EntityId::now();
    let spoken = place
        .owen()
        .rooms_speak(&WitnessTurn {
            conversation_ref: place.room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "owen".into(),
                parts: None,
                metadata: Some(metadata),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: place.vault.now_recorded_at(),
            assertions: Default::default(),
        })
        .map(|_| ());
    (turn, spoken)
}

/// owen's plain TURN for the DAG's thread reply door, read by `audience`
/// alone when it names one.
fn plain_turn(place: &Room, audience: Option<BTreeSet<EntityId>>) -> TestResult<AppendRecord> {
    let now = place.vault.now_recorded_at();
    Ok(AppendRecord {
        conversation: place.room,
        parent: None,
        reply_to: None,
        quote: None,
        address: AddressMode::Broadcast,
        recipients: vec![],
        advance: false,
        kind: ENTITY_TYPE_TURN,
        containing_turn: None,
        occurred: TimeRange {
            start: now,
            end: now,
        },
        learned_at: now,
        body: rmp_serde::to_vec_named(&serde_json::json!({"txt": "owen"}))?,
        text: vec![],
        session: None,
        actor: WriteActor::new(place.owen, EdgeActorClass::Human),
        thread_audience: audience,
    })
}

/// owen's reply on `anchor` through the DAG's thread reply door. Returns the
/// TURN.
fn thread_reply(
    place: &Room,
    anchor: EntityId,
    audience: Option<BTreeSet<EntityId>>,
) -> TestResult<EntityId> {
    let input = plain_turn(place, audience)?;
    Ok(place
        .vault
        .reply_in_thread(&place.owen(), anchor, &input)?
        .id)
}

/// A trunk witness turn, the anchor the threads hang from.
fn anchor(place: &Room) -> TestResult<EntityId> {
    let (turn, spoken) = speak(place, serde_json::json!({}));
    spoken?;
    Ok(turn)
}

impl ChatFixture {
    /// A rooted vault served over the app, its seats on a fake model
    /// answering `reply`, with owen's ordinary room and one private and one
    /// room-wide thread hanging from their own trunk anchors.
    async fn open(reply: Reply) -> (Self, Room, EntityId, EntityId) {
        let model = FakeLlm::start(vec![], Some(reply)).await;
        let dir = tempfile::tempdir().expect("temporary vault directory");
        // `open_owned` holds the writer lease the owner's doors ask for.
        let vault =
            Arc::new(Vault::open_owned(dir.path(), VaultConfig::device()).expect("open vault"));
        // The keystore goes in BEFORE the server: construction roots the vault.
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("chat-thread-reply".into()),
                ..Default::default()
            },
        )
        .expect("create server");
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let owner_slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("owner root slip");
        let owner_token = owner_slip.to_token().expect("owner slip token");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let models =
            ModelsConfig::from_toml(&models_text(&model.base_url), None).expect("models config");
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        let app = build_app(Arc::new(server));
        let owen = vault.ensure_embedded_owner_actor().expect("embedded owner");
        grant_reads(&vault, owen).expect("owen reads the vault");
        let room = ordinary_room(&vault, owen).expect("ordinary room");
        let place = Room {
            vault: Arc::clone(&vault),
            owen,
            room,
        };
        let private = thread_reply(
            &place,
            anchor(&place).expect("trunk anchor"),
            Some(BTreeSet::from([owen])),
        )
        .expect("private thread");
        let room_wide = thread_reply(&place, anchor(&place).expect("trunk anchor"), None)
            .expect("room-wide thread");
        (
            Self {
                _dir: dir,
                vault,
                host,
                app,
                issuer,
                owner_slip,
                owner_token,
                model,
            },
            place,
            private,
            room_wide,
        )
    }

    async fn finish(self) {
        self.host.shutdown().await;
    }

    fn owner_binding(&self) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = hex(&self
            .issuer
            .binding_proof(&self.owner_slip, challenge.as_bytes())
            .expect("owner holder proof"));
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    /// One chat turn as the owner, over the loopback the session key is
    /// admitted on. Answers the status and the JSON body.
    async fn post_chat(&self, body: Value) -> (StatusCode, Value) {
        let mut request = Request::post("/v1/ai/chat")
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", self.owner_binding())
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("chat request");
        // The owner's app on this device: a session key is admitted only for
        // a caller the listener saw on loopback.
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                std::net::Ipv4Addr::LOCALHOST,
                40_000,
            ))));
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("chat response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("chat body");
        let body: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!("chat answered no JSON: {}", String::from_utf8_lossy(&bytes))
        });
        (status, body)
    }
}

/// A chat turn answering in a private thread is refused before any model
/// call: `reply_to` the private root answers 409 `turn_refused`, the fake
/// model received no request, and owen's room history gained no turn.
///
/// Red on main by assertion: there the witness lands the turn on the trunk,
/// so the route answers 2xx after calling the model.
#[test]
fn a_chat_reply_to_a_private_threads_root_is_refused_before_any_model_call() {
    run_on_engine_stack("chat-private-thread-refused", || async {
        let (fixture, place, private, _) = ChatFixture::open(Reply::text("unspoken")).await;
        let before = place
            .owen()
            .rooms_messages(place.room)
            .expect("room history")
            .len();
        let (status, body) = fixture
            .post_chat(json!({
                "conversation_ref": place.room.to_hex(),
                "reply_to": private.to_hex(),
                "text": "answer in the private thread",
            }))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "refused: {body}");
        assert_eq!(body["error"]["code"], json!("turn_refused"), "{body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("reply door")),
            "{body}"
        );
        assert!(fixture.model.seen().is_empty(), "the model was called");
        let after = place
            .owen()
            .rooms_messages(place.room)
            .expect("room history")
            .len();
        assert_eq!(before, after, "a refused turn landed");
        fixture.finish().await;
    });
}

/// Control, green on main too: a chat turn answering in a room-wide thread
/// is answered as today, 2xx with the model's text, the model was called,
/// and the room's history grew.
#[test]
fn a_chat_reply_to_a_room_wide_threads_root_is_answered() {
    run_on_engine_stack("chat-room-wide-thread-answered", || async {
        let (fixture, place, _, room_wide) =
            ChatFixture::open(Reply::text("the room-wide answer")).await;
        let before = place
            .owen()
            .rooms_messages(place.room)
            .expect("room history")
            .len();
        let (status, body) = fixture
            .post_chat(json!({
                "conversation_ref": place.room.to_hex(),
                "reply_to": room_wide.to_hex(),
                "text": "answer in the room-wide thread",
            }))
            .await;
        assert_eq!(status, StatusCode::OK, "answered: {body}");
        assert_eq!(body["text"], json!("the room-wide answer"), "{body}");
        assert!(
            !fixture.model.seen().is_empty(),
            "the model was never called"
        );
        let after = place
            .owen()
            .rooms_messages(place.room)
            .expect("room history")
            .len();
        assert!(after > before, "an answered turn landed nothing");
        fixture.finish().await;
    });
}
