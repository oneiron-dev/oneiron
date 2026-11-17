//! Row `OFF-RECORD-SOURCED-PATHS-ANON-ONLY` (census L5-25): a caller verified
//! in an off-record session that keeps no model-call record gets model runs
//! that name no source rows.
//!
//! Each test drives one family's door twice over real HTTP: once with no
//! session (the control, whose run must name its source rows, so the second
//! half cannot pass vacuously) and once with a creator-bound off-record
//! session on `x-oneiron-session` (every `Admitted` receipt of the call must
//! name no rows and no worlds). The six families are `ai.verdict`,
//! `vault.graph.ask`, `vault.skills.convert`, `ai.speech` with a banked voice,
//! `vault.voices.targets.provision`, and `/v1/companion/memory/reason` at
//! `depth: "high"`, the last in the non-anonymous off-record mode (anonymous
//! mode suppresses its durable receipts, so a test there passes on the base
//! too).
//!
//! Red on 0686d1af2cf9 (the runs name their rows), green on 52999b0be1c9.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support,oneiron/test-hooks,
//! oneiron-broker/test-support,tokio/test-util --test off_record_sourced_doors`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;
#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;

use axum::{
    Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{Path, State},
    http::{Request, StatusCode},
    routing::post,
};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::authority::{CapabilitySlip, MachineRole, holder_proof};
use oneiron::llm::run_admission::{MemoryReceipts, RunEvent, RunReceiptSink};
use oneiron::memory::{WitnessAssertions, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::off_record::{OffRecordBackendClass, OffRecordCreator};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::voice_identity::ref_bank::{
    VoiceRefOrigin, VoiceRefPack, VoiceRefSubjectKind, VoiceRegisterClip, VoiceRenderDecision,
};
use oneiron::voice_identity::{VoiceConsentBasis, VoiceConsentState};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    ModelLocality, TimeRange, Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::{build_app, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The Big rung's yes/no answer, as `reply = "json"` reads it.
const DECISION_JSON: &str = r#"{"answer": "yes", "probability": 0.9}"#;

/// `skills.conversion_prompt`: conversion is unavailable without it, never on
/// a fallback prompt.
const CONVERSION_PROMPT: &str = concat!(
    "Preserve the selected words, invent no authority, and diff ",
    "against the supplied neighbors. Answer JSON.",
);

/// The typed JSON a refiner must return: one `SKILL.md` tree, minted.
fn refiner_json() -> String {
    let skill = "---\nname: morning-routine-checklist\n---\n\n## When to use\n\n";
    json!({
        "skill_id": "morning-routine-checklist",
        "desc": "Run the morning routine checklist when the day starts",
        "files": [{"path": "SKILL.md", "content": format!("{skill}Every morning.\n")}],
        "verdict": {
            "kind": "mint",
            "justification": "nothing in the library covers this checklist",
        },
    })
    .to_string()
}

/// Seats for the verdict and graph families: the default chat seat on the
/// fake plus the Big rung bound to it, answering `reply = "json"`.
fn decision_models(base_url: &str) -> String {
    format!(
        "default = \"local:test-model\"\nextraction_egress = true\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n\
         [decisions.big]\nversion = \"1\"\nwording = \"Answer the question.\"\n\
         reply = \"json\"\n"
    )
}

/// Seats for the convert family: the default chat seat on the fake.
fn chat_models(base_url: &str) -> String {
    format!(
        "default = \"local:test-model\"\nextraction_egress = true\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n"
    )
}

/// Seats for the memory-reason family: the default chat seat on the fake for
/// the generative role plus a reranker seat on the rerank fake.
fn reason_models(base_url: &str, rerank_url: &str) -> String {
    format!(
        "default = \"local:test-model\"\nextraction_egress = true\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n\
         [providers.rerank]\nkind = \"local-openai-compat\"\nbase_url = \"{rerank_url}\"\n\
         [roles.reranker]\nmodel = \"rerank:fake-reranker\"\n"
    )
}

/// Seats for the speech and provision families: one elevenlabs provider on
/// the fake vendor, serving the speech seat and the `eleven` clone target.
fn media_models(vendor_url: &str) -> String {
    format!(
        "[dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [providers.eleven]\nkind = \"elevenlabs\"\nbase_url = \"{vendor_url}\"\n\
         [media.speech]\nrungs = [\"eleven:flash-v2\"]\n"
    )
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    host: AiHost,
    owner: EntityId,
    slip: CapabilitySlip,
    key: SigningKey,
    receipts: Arc<MemoryReceipts>,
}

impl Host {
    /// A served vault on `models_text`'s seats, its run receipts kept in
    /// memory, driven by the owner's own full human slip: owner-grade and
    /// principal-bearing, so every door below admits it and the off-record
    /// rule can bind it.
    async fn serve(models_text: &str, conversion_prompt: Option<&str>, secret: &str) -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let receipts = Arc::new(MemoryReceipts::default());
        let sink: Arc<dyn RunReceiptSink> = receipts.clone();
        let mut config = SyncServerConfig {
            auth_secret: Some(secret.to_owned()),
            ..Default::default()
        };
        config.skills.conversion_prompt = conversion_prompt.map(str::to_owned);
        let server = SyncServer::new(Arc::clone(&vault), config)
            .expect("create server")
            .with_run_receipts(sink);
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let root = vault
            .ensure_host_root_slip(&issuer)
            .expect("host root slip");
        let key = SigningKey::from_bytes(&[0x5B; 32]);
        let mut claims = root.claims.clone();
        claims.slip_id = next_slip_id();
        claims.parent_id = None;
        claims.holder_ref = owner.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = key.verifying_key().to_bytes();
        let slip = vault
            .mint_capability_slip(&issuer, claims)
            .expect("owner slip");
        let models = ModelsConfig::from_toml(models_text, None).expect("models");
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        let app = build_app(Arc::new(server));
        Self {
            _dir: dir,
            vault,
            app,
            host,
            owner,
            slip,
            key,
            receipts,
        }
    }

    /// `body` to `route` over real HTTP as the owner, in `session` when one
    /// is named: its status and its JSON body.
    async fn post(&self, route: &str, body: Value, session: Option<&str>) -> (StatusCode, Value) {
        let token = self.slip.to_token().expect("slip token");
        let proof = holder_proof(&self.slip, &self.key, self.vault.now_recorded_at())
            .expect("holder proof");
        let mut request = Request::post(route)
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", proof.to_string())
            .header("content-type", "application/json");
        if let Some(session) = session {
            request = request.header("x-oneiron-session", session);
        }
        let response = tokio::time::timeout(
            Duration::from_secs(120),
            self.app
                .clone()
                .oneshot(request.body(Body::from(body.to_string())).expect("request")),
        )
        .await
        .expect("the door answers within two minutes")
        .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("response body");
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, body)
    }

    async fn finish(self) {
        self.host.shutdown().await;
    }
}

/// A creator-bound off-record session for `owner`: the rule
/// `model_call_keeps_no_record_for` reads true for. Its handle, for
/// `x-oneiron-session`.
fn off_record_session(vault: &Vault, name: &str, owner: EntityId) -> String {
    vault
        .off_record_session_vault()
        .enter_as_creator(
            name,
            OffRecordBackendClass::Local,
            OffRecordCreator {
                actor: owner,
                class: EdgeActorClass::Human,
            },
        )
        .expect("enter the off-record session")
        .session_ref()
        .to_owned()
}

/// Each `Admitted` receipt's source rows and their worlds, in order.
type Sourced = (Option<Vec<EntityId>>, Option<Vec<EntityId>>);

fn sourced(row: &oneiron::llm::run_admission::RunReceipt) -> Option<Sourced> {
    match &row.event {
        RunEvent::Admitted(facts) => Some((facts.source_rows.clone(), facts.source_worlds.clone())),
        _ => None,
    }
}

/// Every `Admitted` receipt recorded from `from` on.
fn admitted_from(receipts: &MemoryReceipts, from: usize) -> Vec<Sourced> {
    receipts
        .rows()
        .iter()
        .skip(from)
        .filter_map(sourced)
        .collect()
}

/// [`admitted_from`], for the memory-reason family's own runs alone.
fn admitted_memory_reason(receipts: &MemoryReceipts, from: usize) -> Vec<Sourced> {
    receipts
        .rows()
        .iter()
        .skip(from)
        .filter(|row| row.run.starts_with("memory-reason:"))
        .filter_map(sourced)
        .collect()
}

/// One claim saying `text`, text-indexed; its id. The index runs when
/// [`index_now`] runs.
fn seed_claim(vault: &Vault, text: &str) -> EntityId {
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"off-record sourced doors subject",
        )
        .expect("seed subject row");
    let body = ClaimBody::new(
        "test.sourced_doors_seed",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(text),
        0.8,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("seed claim body");
    let id = EntityId::now();
    vault
        .put_claim(
            &id,
            &body,
            TimeRange {
                start: 100,
                end: 100,
            },
            101,
        )
        .expect("seed claim");
    vault
        .batch()
        .text(&id, &[("body", text)])
        .commit()
        .expect("seed text index");
    id
}

/// Runs the staged text index now.
fn index_now(vault: &Vault) {
    vault.set_indexed_idle_delay_ms(0).expect("index delay");
    let published = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("index refresh");
    assert!(
        published.failed.is_empty(),
        "index publish failed: {:?}",
        published.failed
    );
}

/// One witnessed turn per line, spoken by `actor`; the TURN ids.
fn seed_turns(vault: &Vault, actor: EntityId, lines: &[&str]) -> Vec<EntityId> {
    let memory = vault.memory(actor, EdgeActorClass::Human);
    let conversation = EntityId::now().to_hex();
    lines
        .iter()
        .map(|line| {
            let turn = EntityId::now();
            memory
                .witness(&WitnessTurn {
                    conversation_ref: conversation.clone(),
                    turn_ref: Some(turn.to_hex()),
                    thread_audience: None,
                    project: None,
                    messages: vec![WitnessMessage {
                        id: None,
                        author: WitnessAuthor::User,
                        message_type: "text".to_owned(),
                        content: (*line).to_owned(),
                        parts: None,
                        metadata: None,
                        is_visible: true,
                        order: 0,
                        quote: None,
                    }],
                    occurred_at: vault.now_recorded_at(),
                    assertions: WitnessAssertions::default(),
                })
                .expect("witness the turn");
            turn
        })
        .collect()
}

/// Banks `voice_id`'s first pack for `owner` under their current render
/// grant, which reaches third-party clone targets.
fn bank_voice(vault: &Vault, owner: EntityId, voice_id: &str, pack_id: &str) {
    vault
        .record_voice_render_consent(&VoiceRenderDecision {
            event_id: format!("grant-{pack_id}"),
            voice_id: voice_id.to_owned(),
            subject: owner,
            subject_kind: VoiceRefSubjectKind::Person,
            recorded_by: owner,
            occurred_at: vault.now_recorded_at(),
            reach: ModelLocality::ThirdParty,
            basis: Some(VoiceConsentBasis::ConversationalNotice {
                notice: "grant".to_owned(),
            }),
            state: VoiceConsentState::Granted,
        })
        .expect("render consent");
    vault
        .store_voice_ref_pack(&VoiceRefPack {
            version: 1,
            id: pack_id.to_owned(),
            voice_id: voice_id.to_owned(),
            owner,
            origin: VoiceRefOrigin::Captured {
                consent_event_ref: format!("grant-{pack_id}"),
            },
            clips: vec![VoiceRegisterClip {
                register: "neutral".to_owned(),
                media_type: "audio/wav".to_owned(),
                audio: vec![1, 2, 3, 4],
                transcript: "a reference line".to_owned(),
            }],
        })
        .expect("bank the voice pack");
}

/// A loopback `/v1/rerank` server answering every document `0.7`.
#[derive(Clone)]
struct RerankState {
    calls: Arc<AtomicUsize>,
}

struct FakeReranker {
    base_url: String,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeReranker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeReranker {
    async fn start() -> Self {
        let calls = Arc::new(AtomicUsize::new(0));
        let state = RerankState {
            calls: Arc::clone(&calls),
        };
        let app = Router::new()
            .route("/v1/rerank", post(rerank))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            base_url: format!("http://{addr}"),
            calls,
            task,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

async fn rerank(State(state): State<RerankState>, Json(body): Json<Value>) -> Json<Value> {
    state.calls.fetch_add(1, Ordering::SeqCst);
    let results: Vec<Value> = body["documents"]
        .as_array()
        .map_or_else(Vec::new, |documents| {
            documents
                .iter()
                .enumerate()
                .map(|(index, _)| json!({"index": index, "relevance_score": 0.7}))
                .collect()
        });
    Json(json!({
        "model": "fake-reranker-v1",
        "results": results,
        "usage": {"total_tokens": 12},
    }))
}

/// A loopback elevenlabs vendor: `POST /v1/voices/add` mints a vendor voice,
/// `POST /v1/text-to-speech/{voice}` answers raw PCM16.
#[derive(Clone)]
struct VendorState {
    clones: Arc<AtomicUsize>,
    speeches: Arc<AtomicUsize>,
}

struct FakeSpeechVendor {
    base_url: String,
    state: VendorState,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeSpeechVendor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeSpeechVendor {
    async fn start() -> Self {
        let state = VendorState {
            clones: Arc::default(),
            speeches: Arc::default(),
        };
        let app = Router::new()
            .route("/v1/voices/add", post(clone_voice))
            .route("/v1/text-to-speech/{voice}", post(speak))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            base_url: format!("http://{addr}"),
            state,
            task,
        }
    }

    fn clones(&self) -> usize {
        self.state.clones.load(Ordering::SeqCst)
    }

    fn speeches(&self) -> usize {
        self.state.speeches.load(Ordering::SeqCst)
    }
}

async fn clone_voice(State(state): State<VendorState>, _body: Bytes) -> Json<Value> {
    let call = state.clones.fetch_add(1, Ordering::SeqCst) + 1;
    Json(json!({"voice_id": format!("vendor-voice-{call}")}))
}

async fn speak(
    State(state): State<VendorState>,
    Path(_voice): Path<String>,
    _body: Bytes,
) -> Vec<u8> {
    state.speeches.fetch_add(1, Ordering::SeqCst);
    vec![0u8; 480]
}

/// A memory-reason composition citing the first short id the request's
/// evidence carries, so the draft is usable.
fn compose_reply(body: &Value) -> String {
    let mut cited = String::new();
    if let Some(messages) = body.get("messages").and_then(Value::as_array) {
        for message in messages {
            let text = message.get("content").and_then(Value::as_str).unwrap_or("");
            let data: Value = serde_json::from_str(text).unwrap_or(Value::Null);
            if let Some(rows) = data.get("evidence").and_then(Value::as_array) {
                for row in rows {
                    if let Some(id) = row.get("shortId").and_then(Value::as_str) {
                        cited = id.to_owned();
                        break;
                    }
                }
            }
            if !cited.is_empty() {
                break;
            }
        }
    }
    let sources = (!cited.is_empty()).then(|| vec![cited.clone()]);
    json!({
        "answer": format!("the harbor keeps a lantern for night crossings [{cited}]"),
        "sourceShortIds": sources.unwrap_or_default(),
        "confidence": 0.8,
        "gaps": Vec::<String>::new(),
        "declined": false,
    })
    .to_string()
}

#[test]
fn ai_verdict_off_record_run_names_no_source_rows() {
    run_on_engine_stack("offrec-verdict", || async {
        let model = FakeLlm::start(Vec::new(), Some(Reply::text(DECISION_JSON))).await;
        let host = Host::serve(&decision_models(&model.base_url), None, "offrec-verdict").await;
        let claim = seed_claim(&host.vault, "the harbor lantern burns brass oil at night");
        index_now(&host.vault);
        let body = json!({
            "question": "Does the harbor lantern burn brass oil?",
            "evidence": [claim.to_hex()],
        });
        let before = host.receipts.rows().len();
        let seen = model.seen().len();
        let (status, answer) = host
            .post("/v1/core/facade/ai.verdict", body.clone(), None)
            .await;
        assert_eq!(status, StatusCode::OK, "control verdict: {answer}");
        assert_eq!(
            answer["rung"].as_str(),
            Some("big"),
            "the Big rung answers: {answer}"
        );
        assert!(
            model.seen().len() > seen,
            "the fake model answered the control"
        );
        let control = admitted_from(&host.receipts, before);
        assert!(!control.is_empty(), "the control admitted a run");
        assert!(
            control
                .iter()
                .any(|(rows, _)| rows.as_ref().is_some_and(|rows| !rows.is_empty())),
            "the control run names its evidence rows: {control:?}"
        );
        let session = off_record_session(&host.vault, "verdict-stretch", host.owner);
        let before = host.receipts.rows().len();
        let seen = model.seen().len();
        let (status, answer) = host
            .post("/v1/core/facade/ai.verdict", body, Some(&session))
            .await;
        assert_eq!(status, StatusCode::OK, "off-record verdict: {answer}");
        assert!(
            model.seen().len() > seen,
            "the fake model answered off record"
        );
        let hidden = admitted_from(&host.receipts, before);
        assert!(!hidden.is_empty(), "the off-record call admitted a run");
        for (rows, worlds) in &hidden {
            assert!(
                rows.as_ref().map_or(true, |rows| rows.is_empty()),
                "an off-record run names no source rows: {hidden:?}"
            );
            assert!(
                worlds.is_none(),
                "an off-record run names no worlds: {hidden:?}"
            );
        }
        host.finish().await;
    });
}

#[test]
fn graph_ask_off_record_run_names_no_source_rows() {
    run_on_engine_stack("offrec-graph-ask", || async {
        let model = FakeLlm::start(Vec::new(), Some(Reply::text(DECISION_JSON))).await;
        let host = Host::serve(&decision_models(&model.base_url), None, "offrec-graph-ask").await;
        let unit = seed_claim(&host.vault, "the brass lantern passed its inspection");
        index_now(&host.vault);
        let body = json!({
            "question": {
                "id": EntityId::now().to_hex(),
                "version": 1,
                "text": "Did the brass lantern pass its inspection?",
                "class": "judgment",
                "contract": {"kind": "noul"},
                "accept_type": false,
            },
            "units": [unit.to_hex()],
        });
        let before = host.receipts.rows().len();
        let seen = model.seen().len();
        let (status, answer) = host
            .post("/v1/core/facade/vault.graph.ask", body.clone(), None)
            .await;
        assert_eq!(status, StatusCode::OK, "control ask: {answer}");
        assert_eq!(
            answer["state"].as_str(),
            Some("done"),
            "the ask ran: {answer}"
        );
        assert_eq!(
            answer["answers"].as_array().map_or(0, Vec::len),
            1,
            "the unit answered: {answer}"
        );
        assert!(
            model.seen().len() > seen,
            "the fake model answered the control"
        );
        let control = admitted_from(&host.receipts, before);
        assert!(!control.is_empty(), "the control admitted a run");
        assert!(
            control
                .iter()
                .any(|(rows, _)| rows.as_ref().is_some_and(|rows| !rows.is_empty())),
            "the control run names its unit rows: {control:?}"
        );
        let session = off_record_session(&host.vault, "graph-ask-stretch", host.owner);
        let before = host.receipts.rows().len();
        let seen = model.seen().len();
        let (status, answer) = host
            .post("/v1/core/facade/vault.graph.ask", body, Some(&session))
            .await;
        assert_eq!(status, StatusCode::OK, "off-record ask: {answer}");
        assert!(
            model.seen().len() > seen,
            "the fake model answered off record"
        );
        let hidden = admitted_from(&host.receipts, before);
        assert!(!hidden.is_empty(), "the off-record call admitted a run");
        for (rows, worlds) in &hidden {
            assert!(
                rows.as_ref().map_or(true, |rows| rows.is_empty()),
                "an off-record run names no source rows: {hidden:?}"
            );
            assert!(
                worlds.is_none(),
                "an off-record run names no worlds: {hidden:?}"
            );
        }
        host.finish().await;
    });
}

#[test]
fn skills_convert_off_record_run_names_no_source_rows() {
    run_on_engine_stack("offrec-skills-convert", || async {
        let model = FakeLlm::start(Vec::new(), Some(Reply::text(refiner_json()))).await;
        let host = Host::serve(
            &chat_models(&model.base_url),
            Some(CONVERSION_PROMPT),
            "offrec-convert",
        )
        .await;
        let turns = seed_turns(
            &host.vault,
            host.owner,
            &[
                "first I open the blinds and put the kettle on",
                "then I write the three things that matter today",
                "then I walk around the harbor before the standup",
                "then I read the lantern keeper's log for the night",
            ],
        );
        let first = json!({"message_refs": [turns[0].to_hex(), turns[1].to_hex()]});
        let before = host.receipts.rows().len();
        let seen = model.seen().len();
        let (status, answer) = host
            .post("/v1/core/facade/vault.skills.convert", first, None)
            .await;
        assert_eq!(status, StatusCode::OK, "control convert: {answer}");
        assert_eq!(
            answer["outcome"].as_str(),
            Some("created"),
            "the skill minted: {answer}"
        );
        assert!(
            model.seen().len() > seen,
            "the fake model refined the control"
        );
        let control = admitted_from(&host.receipts, before);
        assert!(!control.is_empty(), "the control admitted a run");
        assert!(
            control
                .iter()
                .any(|(rows, _)| rows.as_ref().is_some_and(|rows| !rows.is_empty())),
            "the control run names its message rows: {control:?}"
        );
        let session = off_record_session(&host.vault, "convert-stretch", host.owner);
        let second = json!({"message_refs": [turns[2].to_hex(), turns[3].to_hex()]});
        let before = host.receipts.rows().len();
        let seen = model.seen().len();
        let (status, answer) = host
            .post(
                "/v1/core/facade/vault.skills.convert",
                second,
                Some(&session),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "off-record convert: {answer}");
        assert!(
            model.seen().len() > seen,
            "the fake model refined off record"
        );
        let hidden = admitted_from(&host.receipts, before);
        assert!(!hidden.is_empty(), "the off-record call admitted a run");
        for (rows, worlds) in &hidden {
            assert!(
                rows.as_ref().map_or(true, |rows| rows.is_empty()),
                "an off-record run names no source rows: {hidden:?}"
            );
            assert!(
                worlds.is_none(),
                "an off-record run names no worlds: {hidden:?}"
            );
        }
        host.finish().await;
    });
}

#[test]
fn speech_banked_voice_off_record_run_names_no_source_rows() {
    run_on_engine_stack("offrec-speech", || async {
        let vendor = FakeSpeechVendor::start().await;
        let host = Host::serve(&media_models(&vendor.base_url), None, "offrec-speech").await;
        bank_voice(&host.vault, host.owner, "speech-voice", "speech-pack");
        let (status, receipt) = host
            .post(
                "/v1/core/facade/vault.voices.targets.provision",
                json!({"voice_id": "speech-voice", "target": "eleven"}),
                None,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "provision the speech voice: {receipt}"
        );
        assert_eq!(vendor.clones(), 1, "the vendor made the clone");
        let body = json!({
            "prompt": "the harbor lantern burns at night",
            "voice": {"kind": "bank", "voice_id": "speech-voice"},
        });
        let before = host.receipts.rows().len();
        let (status, answer) = host
            .post("/v1/core/facade/ai.speech", body.clone(), None)
            .await;
        assert_eq!(status, StatusCode::OK, "control speech: {answer}");
        assert!(
            answer["parts"]
                .as_array()
                .is_some_and(|parts| !parts.is_empty()),
            "the control spoke audio: {answer}"
        );
        assert_eq!(vendor.speeches(), 1, "the vendor spoke the control");
        let control = admitted_from(&host.receipts, before);
        assert!(!control.is_empty(), "the control admitted a run");
        assert!(
            control
                .iter()
                .any(|(rows, _)| rows.as_ref().is_some_and(|rows| !rows.is_empty())),
            "the control run names the voice person row: {control:?}"
        );
        let session = off_record_session(&host.vault, "speech-stretch", host.owner);
        let before = host.receipts.rows().len();
        let (status, answer) = host
            .post("/v1/core/facade/ai.speech", body, Some(&session))
            .await;
        assert_eq!(status, StatusCode::OK, "off-record speech: {answer}");
        assert_eq!(vendor.speeches(), 2, "the vendor spoke off record too");
        let hidden = admitted_from(&host.receipts, before);
        assert!(!hidden.is_empty(), "the off-record call admitted a run");
        for (rows, worlds) in &hidden {
            assert!(
                rows.as_ref().map_or(true, |rows| rows.is_empty()),
                "an off-record run names no source rows: {hidden:?}"
            );
            assert!(
                worlds.is_none(),
                "an off-record run names no worlds: {hidden:?}"
            );
        }
        host.finish().await;
    });
}

#[test]
fn voice_clone_provision_off_record_run_names_no_source_rows() {
    run_on_engine_stack("offrec-provision", || async {
        let vendor = FakeSpeechVendor::start().await;
        let host = Host::serve(&media_models(&vendor.base_url), None, "offrec-provision").await;
        bank_voice(&host.vault, host.owner, "clone-voice-a", "clone-pack-a");
        bank_voice(&host.vault, host.owner, "clone-voice-b", "clone-pack-b");
        let before = host.receipts.rows().len();
        let (status, receipt) = host
            .post(
                "/v1/core/facade/vault.voices.targets.provision",
                json!({"voice_id": "clone-voice-a", "target": "eleven"}),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "control provision: {receipt}");
        assert_eq!(vendor.clones(), 1, "the vendor cloned the control voice");
        let control = admitted_from(&host.receipts, before);
        assert!(!control.is_empty(), "the control admitted a run");
        assert!(
            control
                .iter()
                .any(|(rows, _)| rows.as_ref().is_some_and(|rows| !rows.is_empty())),
            "the control run names the voice person row: {control:?}"
        );
        let session = off_record_session(&host.vault, "provision-stretch", host.owner);
        let before = host.receipts.rows().len();
        let (status, receipt) = host
            .post(
                "/v1/core/facade/vault.voices.targets.provision",
                json!({"voice_id": "clone-voice-b", "target": "eleven"}),
                Some(&session),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "off-record provision: {receipt}");
        assert_eq!(vendor.clones(), 2, "the vendor cloned off record too");
        let hidden = admitted_from(&host.receipts, before);
        assert!(!hidden.is_empty(), "the off-record call admitted a run");
        for (rows, worlds) in &hidden {
            assert!(
                rows.as_ref().map_or(true, |rows| rows.is_empty()),
                "an off-record run names no source rows: {hidden:?}"
            );
            assert!(
                worlds.is_none(),
                "an off-record run names no worlds: {hidden:?}"
            );
        }
        host.finish().await;
    });
}

#[test]
fn memory_reason_high_off_record_run_names_no_source_rows() {
    run_on_engine_stack("offrec-memory-reason", || async {
        let reranker = FakeReranker::start().await;
        let compose: fake_llm::Compute = Arc::new(compose_reply);
        let model = FakeLlm::start(Vec::new(), Some(Reply::Computed(compose))).await;
        let host = Host::serve(
            &reason_models(&model.base_url, &reranker.base_url),
            None,
            "offrec-memory-reason",
        )
        .await;
        seed_claim(
            &host.vault,
            "the harbor lantern burns brass oil for night crossings",
        );
        seed_claim(
            &host.vault,
            "brass fittings keep the lantern lit through the crossing",
        );
        seed_claim(
            &host.vault,
            "night crossings need a lit lantern at the harbor mouth",
        );
        index_now(&host.vault);
        let body = json!({"query": "harbor lantern brass night crossings", "depth": "high"});
        let before = host.receipts.rows().len();
        let (status, answer) = host
            .post("/v1/companion/memory/reason", body.clone(), None)
            .await;
        assert_eq!(status, StatusCode::OK, "control reason: {answer}");
        assert!(reranker.calls() > 0, "the reranker ran for the control");
        assert!(!model.seen().is_empty(), "the composer ran for the control");
        let control = admitted_memory_reason(&host.receipts, before);
        assert!(
            !control.is_empty(),
            "the control admitted a memory-reason run"
        );
        assert!(
            control
                .iter()
                .any(|(rows, _)| rows.as_ref().is_some_and(|rows| !rows.is_empty())),
            "the control run names its pinned rows: {control:?}"
        );
        let session = off_record_session(&host.vault, "reason-stretch", host.owner);
        let before = host.receipts.rows().len();
        let reranked = reranker.calls();
        let seen = model.seen().len();
        let (status, answer) = host
            .post("/v1/companion/memory/reason", body, Some(&session))
            .await;
        assert_eq!(status, StatusCode::OK, "off-record reason: {answer}");
        assert!(reranker.calls() > reranked, "the reranker ran off record");
        assert!(model.seen().len() > seen, "the composer ran off record");
        let hidden = admitted_memory_reason(&host.receipts, before);
        assert!(
            !hidden.is_empty(),
            "the off-record call admitted a memory-reason run"
        );
        for (rows, worlds) in &hidden {
            assert!(
                rows.as_ref().map_or(true, |rows| rows.is_empty()),
                "an off-record run names no source rows: {hidden:?}"
            );
            assert!(
                worlds.is_none(),
                "an off-record run names no worlds: {hidden:?}"
            );
        }
        host.finish().await;
    });
}
