//! Restriction wave 11, PR 1: the owner's Setting keys that let an agent plan
//! waves (`ai.waves.agent_may_plan`) and answer quota questions
//! (`models.quota.agent_may_answer`).
//!
//! Red/green HTTP tests: they drive the real routes `POST /v1/ai/waves`,
//! `GET /v1/ai/waves/{attempt}` and `POST /v1/ai/quota/{question}` with real
//! paired agent credentials (the `model_binding_proposer_grant` fixture
//! style: a registered agent principal redeemed over the real pairing
//! route, every request proving its holder key afresh). The owner acts on
//! its host-root credential and sets the Setting rows through the engine's
//! own owner door. Each case owns its vault.
//!
//! The wave-enqueue cases attach the AI host over a fake model with the
//! workflow pump enabled (the `coach_offer_run` fixture style), because
//! the route only enqueues while that worker runs; the refusal cases do
//! not, which also shows the closed key refuses before the worker check.
//! Quota questions are planted as the rows the runtime keeps, which `GET
//! /v1/ai/status` lists and `POST /v1/ai/quota/{id}` answers.
//!
//! Deterministic: in-process vault and router (`oneshot`, no sleeps, no
//! real models). The pump may claim a wave attempt while a case reads it;
//! every assertion reads the attempt's frozen payload or its status, which
//! no worker state changes.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test restriction_wave11_ai_gates`.
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
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use fake_llm::{FakeLlm, Reply};
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::attempt_queue::{AttemptId, AttemptQueue};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::SpentKind;
use oneiron::setting::{SetSetting, SetSettingOutcome, SettingCaller, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::models::{
    QuotaAnswerRecord, QuotaAnswerer, QuotaChoice, QuotaFallback, QuotaQuestion,
};
use oneiron_server::{build_app, server::SyncServer};
use rmpv::Value as RmpValue;
use serde_json::{Value, json};
use tower::ServiceExt;

/// The wave key under test.
const WAVE_KEY: &str = "ai.waves.agent_may_plan";
/// The quota key under test.
const QUOTA_KEY: &str = "models.quota.agent_may_answer";

/// One paired agent credential: its registered principal, its holder
/// signing key, its redeemed slip and the token it presents.
struct Agent {
    principal: EntityId,
    holder: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner: AuthenticatedOwner,
    host: Option<AiHost>,
    _model: Option<FakeLlm>,
}

impl Fixture {
    /// Stops the attached AI host, when one runs, so its pump ends with
    /// the case.
    async fn finish(self) {
        if let Some(host) = self.host {
            host.shutdown().await;
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The models config: every seat on the fake model at `base_url`, the
/// Dreamer off, and the workflow pump on, so the wave route enqueues.
fn models_text(base_url: &str) -> String {
    format!(
        "default = \"local:test-model\"\nextraction_egress = true\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = true\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n\
         key_env = \"HOME\"\n"
    )
}

async fn setup() -> (Fixture, Agent, Agent) {
    setup_inner(false).await
}

async fn setup_ai() -> (Fixture, Agent, Agent) {
    setup_inner(true).await
}

async fn setup_inner(with_workflows: bool) -> (Fixture, Agent, Agent) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("restriction-wave11-ai-gates".into()),
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
    let owner_id = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let owner = vault
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .expect("authenticated owner");
    let (server, host, model) = if with_workflows {
        let model = FakeLlm::start(vec![], Some(Reply::text("{}"))).await;
        let models =
            ModelsConfig::from_toml(&models_text(&model.base_url), None).expect("models config");
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        (server, Some(host), Some(model))
    } else {
        (server, None, None)
    };
    let app = build_app(Arc::new(server));
    let a = pair_agent(&vault, &app, &issuer, "wave11-agent-a", [0xA1; 32]).await;
    let b = pair_agent(&vault, &app, &issuer, "wave11-agent-b", [0xB2; 32]).await;
    (
        Fixture {
            _dir: dir,
            vault,
            app,
            issuer,
            owner_slip,
            owner_token,
            owner,
            host,
            _model: model,
        },
        a,
        b,
    )
}

/// Pairs one agent the way `token agent` does: a registered named PERSON
/// principal, a principal-bound link narrowed to `core:read` and
/// `core:write`, redeemed over the real pairing route with the
/// holder-signed binding transcript.
async fn pair_agent(
    vault: &Vault,
    app: &Router,
    issuer: &HostSlipIssuer,
    name: &str,
    seed: [u8; 32],
) -> Agent {
    pair_agent_with_verbs(vault, app, issuer, name, seed, &["core:read", "core:write"]).await
}

/// [`pair_agent`] with the link narrowed to `verbs`.
async fn pair_agent_with_verbs(
    vault: &Vault,
    app: &Router,
    issuer: &HostSlipIssuer,
    name: &str,
    seed: [u8; 32],
    verbs: &[&str],
) -> Agent {
    let principal = vault.ensure_agent_principal(name).expect("agent principal");
    let holder = SigningKey::from_bytes(&seed);
    let binding_key = holder.verifying_key().to_bytes();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(
        verbs
            .iter()
            .map(|verb| (*verb).to_owned())
            .collect::<BTreeSet<_>>(),
    );
    let link = vault
        .issue_pairing_link_for_principal(
            issuer,
            scope,
            3600,
            PairingPrincipal {
                holder_ref: Some(principal.to_hex()),
                actor_class: Some("agent".to_owned()),
                org_ref: None,
                write_facet: None,
                ..Default::default()
            },
        )
        .expect("pairing link");
    assert!(
        link.pin.is_none(),
        "fresh vault keeps no checkpoint pin on its links"
    );
    let transcript = pairing_binding_transcript(&link.code, &binding_key, &principal.to_hex())
        .expect("pairing transcript");
    let signature: String = hex(&holder.sign(&transcript).to_bytes());
    let request = Request::post("/v1/core/pairing/redeem")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "code": link.code,
                "holder_ref": principal.to_hex(),
                "binding_key": hex(&binding_key),
                "signature": signature,
            })
            .to_string(),
        ))
        .expect("pairing redeem request");
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("pairing redeem response");
    assert_eq!(response.status(), StatusCode::OK, "pairing redeem status");
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("pairing redeem body");
    let body: Value = serde_json::from_slice(&bytes).expect("pairing redeem JSON");
    let token = body["token"].as_str().expect("paired token").to_owned();
    let slip = CapabilitySlip::from_token(&token).expect("paired slip");
    assert_eq!(
        slip.claims.holder_ref,
        principal.to_hex(),
        "redeemed slip binds its agent"
    );
    assert_eq!(
        slip.claims.actor_class.as_deref(),
        Some("agent"),
        "redeemed slip binds its class"
    );
    Agent {
        principal,
        holder,
        slip,
        token,
    }
}

fn owner_binding(fixture: &Fixture) -> String {
    let timestamp = fixture.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = hex(&fixture
        .issuer
        .binding_proof(&fixture.owner_slip, challenge.as_bytes())
        .expect("owner holder proof"));
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

fn agent_binding(fixture: &Fixture, agent: &Agent) -> String {
    let timestamp = fixture.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let transcript = agent
        .slip
        .binding_transcript(challenge.as_bytes())
        .expect("agent binding transcript");
    let signature: String = hex(&agent.holder.sign(&transcript).to_bytes());
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

async fn request(
    fixture: &Fixture,
    method: &str,
    path: &str,
    token: &str,
    binding: String,
    body: Option<Value>,
) -> (StatusCode, Vec<u8>) {
    let builder = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding);
    let request = match body {
        Some(body) => builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("test request"),
        None => builder.body(Body::empty()).expect("test request"),
    };
    let response = fixture
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("test response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("test response body")
        .to_vec();
    (status, bytes)
}

async fn post(
    fixture: &Fixture,
    path: &str,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    let (status, bytes) = request(fixture, "POST", path, token, binding, Some(body)).await;
    let body: Value = serde_json::from_slice(&bytes).expect("JSON response");
    (status, body)
}

/// A POST whose answer may carry no body (204): the raw bytes.
async fn post_bytes(
    fixture: &Fixture,
    path: &str,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Vec<u8>) {
    request(fixture, "POST", path, token, binding, Some(body)).await
}

async fn get(fixture: &Fixture, path: &str, token: &str, binding: String) -> (StatusCode, Value) {
    let (status, bytes) = request(fixture, "GET", path, token, binding, None).await;
    let body: Value = serde_json::from_slice(&bytes).expect("JSON response");
    (status, body)
}

/// The owner creates the wave's epic TASK over the facade.
async fn create_epic_as_owner(fixture: &Fixture, title: &str) -> EntityId {
    let (status, body) = post(
        fixture,
        "/v1/core/facade/tasks.create",
        &fixture.owner_token,
        owner_binding(fixture),
        json!({
            "spec": {"title": title, "description": "a wave gate's epic", "lane": "wave-gates"},
            "label": title,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "owner creates the epic: {body}");
    let task = body["task_ref"].as_str().expect("the epic's ref");
    EntityId::from_hex(task).expect("the epic parses")
}

/// A dispatchable planner definition: approved, active and enabled.
fn planner_definition() -> AgentDefinition {
    AgentDefinition::new(
        "wave11.planner",
        "restriction wave 11 fixture planner",
        "1",
        Some("Cut carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        RmpValue::Map(vec![("definedVia".into(), "define_agent".into())]),
        None,
        true,
        None,
    )
}

/// The owner creates the wave's planner agent definition.
fn create_planner_as_owner(fixture: &Fixture) -> EntityId {
    let planner = EntityId::now();
    let now = fixture.vault.now_recorded_at();
    fixture
        .vault
        .create_agent_definition_as(
            &fixture.owner,
            &planner,
            &planner_definition(),
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .expect("owner creates the dispatchable planner");
    planner
}

/// The owner sets one wave-key row.
fn set_wave_row(fixture: &Fixture, scope: SettingScope, value: bool) {
    set_row(fixture, WAVE_KEY, None, scope, value);
}

/// The owner sets one quota-key row for one answer.
fn set_quota_row(fixture: &Fixture, item: &str, scope: SettingScope, value: bool) {
    set_row(fixture, QUOTA_KEY, Some(item), scope, value);
}

/// The owner sets one Setting row through the engine's owner door.
fn set_row(fixture: &Fixture, key: &str, item: Option<&str>, scope: SettingScope, value: bool) {
    let request = SetSetting {
        item: item.map(str::to_owned),
        scope,
        ..SetSetting::vault_value(key, json!(value))
    };
    match fixture
        .vault
        .set_setting(SettingCaller::Owner(&fixture.owner), request)
        .expect("owner sets the row")
    {
        SetSettingOutcome::Applied { .. } => {}
        outcome => panic!("the owner's row applies: {outcome:?}"),
    }
}

/// Plants one open quota question row, as the runtime keeps one: what `GET
/// /v1/ai/status` lists and `POST /v1/ai/quota/{id}` answers.
fn plant_question(fixture: &Fixture, id: &str, choices: Vec<QuotaChoice>) {
    let question = QuotaQuestion {
        id: id.to_owned(),
        asked_at: fixture.vault.now_recorded_at(),
        provider: "fixture".to_owned(),
        model: "fixture/model".to_owned(),
        route: "fixture".to_owned(),
        spent: SpentKind::Window,
        resets_at: None,
        choices,
        fallbacks: Vec::new(),
        account: None,
    };
    let bytes = rmp_serde::to_vec_named(&question).expect("encode the question");
    fixture
        .vault
        .sync_state_put(&format!("models:offer-cooldown:v1:ask:{id}"), &bytes)
        .expect("plant the question");
}

fn wave_body(epic: &EntityId, planner: &EntityId) -> Value {
    json!({
        "epic_task_ref": epic.to_hex(),
        "planner_ref": planner.to_hex(),
        "objective": "cut the epic into a wave",
        "constraints": {},
    })
}

/// An agent the owner lets plan enqueues a wave: the attempt's planning
/// context names it with the agent class, and it reads the attempt back.
#[test]
fn an_agent_the_owner_lets_plan_enqueues_a_wave() {
    run_on_engine_stack("wave11-agent-enqueues", || async {
        let (fixture, a, _b) = setup_ai().await;
        let epic = create_epic_as_owner(&fixture, "the epic").await;
        let planner = create_planner_as_owner(&fixture);
        set_wave_row(&fixture, SettingScope::Agent(a.principal), true);

        let (status, body) = post(
            &fixture,
            "/v1/ai/waves",
            &a.token,
            agent_binding(&fixture, &a),
            wave_body(&epic, &planner),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "agent enqueue: {body}");
        let attempt_ref = body["attempt_ref"]
            .as_str()
            .expect("attempt ref")
            .to_owned();

        let id = AttemptId::from_bytes(
            EntityId::from_hex(&attempt_ref)
                .expect("attempt id")
                .as_bytes(),
        )
        .expect("attempt id bytes");
        let attempt = AttemptQueue::new(&fixture.vault)
            .get(id)
            .expect("read the attempt")
            .expect("the attempt is kept");
        let payload: Value = serde_json::from_slice(&attempt.payload).expect("wave payload");
        assert_eq!(
            payload["constraints"]["actor_ref"]
                .as_str()
                .expect("actor ref"),
            a.principal.to_hex(),
            "the attempt names its agent: {payload}"
        );
        assert_eq!(
            payload["constraints"]["actor_class"]
                .as_u64()
                .expect("actor class"),
            EdgeActorClass::Agent as u64,
            "the attempt names the agent class: {payload}"
        );

        let (status, body) = get(
            &fixture,
            &format!("/v1/ai/waves/{attempt_ref}"),
            &a.token,
            agent_binding(&fixture, &a),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "agent reads its wave: {body}");
        assert_eq!(
            body["epic_task_ref"].as_str().expect("epic ref"),
            epic.to_hex(),
            "the status names the epic: {body}"
        );

        fixture.finish().await;
    });
}

/// While the key is off a wave stays the owner's: the agent's enqueue and
/// its status read are refused with today's answer.
#[test]
fn a_wave_stays_the_owners_while_the_key_is_off() {
    run_on_engine_stack("wave11-key-off", || async {
        let (fixture, a, _b) = setup().await;
        let (status, body) = post(
            &fixture,
            "/v1/ai/waves",
            &a.token,
            agent_binding(&fixture, &a),
            wave_body(&EntityId::now(), &EntityId::now()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "agent enqueue: {body}");
        assert_eq!(
            body["error"]["code"].as_str(),
            Some("owner_required"),
            "today's code: {body}"
        );
        assert_eq!(
            body["error"]["message"].as_str(),
            Some("wave planning requires the owner"),
            "today's message: {body}"
        );

        let (status, body) = get(
            &fixture,
            &format!("/v1/ai/waves/{}", EntityId::now().to_hex()),
            &a.token,
            agent_binding(&fixture, &a),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "agent status: {body}");
        assert_eq!(
            body["error"]["code"].as_str(),
            Some("owner_required"),
            "today's code: {body}"
        );
        assert_eq!(
            body["error"]["message"].as_str(),
            Some("wave status requires the owner"),
            "today's message: {body}"
        );

        fixture.finish().await;
    });
}

/// An agent's row lets only its agent plan: the named agent enqueues and
/// another agent is refused.
#[test]
fn an_agent_row_lets_only_its_agent_plan() {
    run_on_engine_stack("wave11-agent-row", || async {
        let (fixture, a, b) = setup_ai().await;
        let epic = create_epic_as_owner(&fixture, "the epic").await;
        let planner = create_planner_as_owner(&fixture);
        set_wave_row(&fixture, SettingScope::Agent(a.principal), true);

        let (status, body) = post(
            &fixture,
            "/v1/ai/waves",
            &a.token,
            agent_binding(&fixture, &a),
            wave_body(&epic, &planner),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "named agent enqueue: {body}");

        let (status, body) = post(
            &fixture,
            "/v1/ai/waves",
            &b.token,
            agent_binding(&fixture, &b),
            wave_body(&epic, &planner),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "other agent enqueue: {body}");
        assert_eq!(
            body["error"]["code"].as_str(),
            Some("owner_required"),
            "today's code: {body}"
        );
        assert_eq!(
            body["error"]["message"].as_str(),
            Some("wave planning requires the owner"),
            "today's message: {body}"
        );

        fixture.finish().await;
    });
}

/// The vault row lets every agent plan: an agent with no row of its own
/// enqueues.
#[test]
fn the_vault_row_lets_every_agent_plan() {
    run_on_engine_stack("wave11-vault-row", || async {
        let (fixture, _a, b) = setup_ai().await;
        let epic = create_epic_as_owner(&fixture, "the epic").await;
        let planner = create_planner_as_owner(&fixture);
        set_wave_row(&fixture, SettingScope::Vault, true);

        let (status, body) = post(
            &fixture,
            "/v1/ai/waves",
            &b.token,
            agent_binding(&fixture, &b),
            wave_body(&epic, &planner),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED, "agent enqueue: {body}");

        fixture.finish().await;
    });
}

/// An agent the owner lets wait answers `wait` on a quota question: the
/// question closes.
#[test]
fn an_agent_the_owner_lets_answer_waits_out_a_quota_question() {
    run_on_engine_stack("wave11-quota-wait", || async {
        let (fixture, a, _b) = setup().await;
        set_quota_row(&fixture, "wait", SettingScope::Agent(a.principal), true);
        plant_question(&fixture, "q1", vec![QuotaChoice::Wait, QuotaChoice::TopUp]);

        let (status, bytes) = post_bytes(
            &fixture,
            "/v1/ai/quota/q1",
            &a.token,
            agent_binding(&fixture, &a),
            json!({"choice": "wait"}),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "agent waits: {bytes:?}");
        assert!(bytes.is_empty(), "204 carries no body: {bytes:?}");

        let (status, body) = post(
            &fixture,
            "/v1/ai/quota/q1",
            &a.token,
            agent_binding(&fixture, &a),
            json!({"choice": "wait"}),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "the question closed: {body}");
        assert_eq!(
            body["error"]["code"].as_str(),
            Some("no_such_question"),
            "{body}"
        );

        fixture.finish().await;
    });
}

/// An agent paired with `core:read` only answers no quota question, even
/// with its item on: the answer is a write. The question stays open.
#[test]
fn a_read_only_agent_the_owner_lets_answer_is_refused() {
    run_on_engine_stack("wave11-quota-read-only", || async {
        let (fixture, a, _b) = setup().await;
        let reader = pair_agent_with_verbs(
            &fixture.vault,
            &fixture.app,
            &fixture.issuer,
            "wave11-agent-reader",
            [0xC3; 32],
            &["core:read"],
        )
        .await;
        set_quota_row(
            &fixture,
            "wait",
            SettingScope::Agent(reader.principal),
            true,
        );
        plant_question(&fixture, "q1", vec![QuotaChoice::Wait]);

        let (status, body) = post(
            &fixture,
            "/v1/ai/quota/q1",
            &reader.token,
            agent_binding(&fixture, &reader),
            json!({"choice": "wait"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "read-only agent: {body}");
        assert_eq!(body["error"]["code"].as_str(), Some("FORBIDDEN"), "{body}");
        assert!(
            body.to_string().contains("core:write"),
            "the refusal names the write scope: {body}"
        );

        set_quota_row(&fixture, "wait", SettingScope::Agent(a.principal), true);
        let (status, bytes) = post_bytes(
            &fixture,
            "/v1/ai/quota/q1",
            &a.token,
            agent_binding(&fixture, &a),
            json!({"choice": "wait"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "the question stayed open: {bytes:?}"
        );

        fixture.finish().await;
    });
}

/// A quota answer the owner did not let stays refused: with `wait` on and
/// `top_up` off, `top_up` is refused and `wait` still answers.
#[test]
fn a_quota_answer_the_owner_did_not_let_stays_refused() {
    run_on_engine_stack("wave11-quota-item", || async {
        let (fixture, a, _b) = setup().await;
        set_quota_row(&fixture, "wait", SettingScope::Agent(a.principal), true);
        plant_question(&fixture, "q1", vec![QuotaChoice::Wait, QuotaChoice::TopUp]);

        let (status, body) = post(
            &fixture,
            "/v1/ai/quota/q1",
            &a.token,
            agent_binding(&fixture, &a),
            json!({"choice": "top_up"}),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "agent top-up: {body}");
        assert_eq!(
            body["error"]["code"].as_str(),
            Some("owner_required"),
            "today's code: {body}"
        );
        assert_eq!(
            body["error"]["message"].as_str(),
            Some("quota questions are the owner's"),
            "today's message: {body}"
        );

        let (status, bytes) = post_bytes(
            &fixture,
            "/v1/ai/quota/q1",
            &a.token,
            agent_binding(&fixture, &a),
            json!({"choice": "wait"}),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "agent waits: {bytes:?}");

        fixture.finish().await;
    });
}

/// The fallback model a planted `use_fallback` question offers.
const FALLBACK_MODEL: &str = "other/fallback-model@1";

/// A question id in the form the runtime keeps: an offer's hex64 key.
fn offer_question_id(seed: u8) -> String {
    hex(&[seed; 32])
}

/// Plants one open quota question that offers `use_fallback` to
/// [`FALLBACK_MODEL`] (and `wait`).
fn plant_fallback_question(fixture: &Fixture, id: &str) {
    let question = QuotaQuestion {
        id: id.to_owned(),
        asked_at: fixture.vault.now_recorded_at(),
        provider: "fixture".to_owned(),
        model: "fixture/model".to_owned(),
        route: "fixture".to_owned(),
        spent: SpentKind::Window,
        resets_at: None,
        choices: vec![QuotaChoice::Wait, QuotaChoice::UseFallback],
        fallbacks: vec![QuotaFallback {
            provider: "other".to_owned(),
            model: FALLBACK_MODEL.to_owned(),
        }],
        account: None,
    };
    let bytes = rmp_serde::to_vec_named(&question).expect("encode the question");
    fixture
        .vault
        .sync_state_put(&format!("models:offer-cooldown:v1:ask:{id}"), &bytes)
        .expect("plant the question");
}

/// The answer body that names [`FALLBACK_MODEL`].
fn use_fallback_body() -> Value {
    json!({"choice": "use_fallback", "fallback": FALLBACK_MODEL})
}

/// The `use_fallback` item on at an agent's row lets that agent set the
/// standing fallback (a payment loosening the owner turned on), and the
/// question's answer row reads back that agent as the answerer
/// (WAVE11-QUOTA-CANON).
#[test]
fn an_agent_the_owner_lets_use_a_fallback_is_recorded_as_the_answerer() {
    run_on_engine_stack("wave11-quota-fallback-agent", || async {
        let (fixture, a, _b) = setup().await;
        set_quota_row(
            &fixture,
            "use_fallback",
            SettingScope::Agent(a.principal),
            true,
        );
        let id = offer_question_id(0xa1);
        plant_fallback_question(&fixture, &id);

        let (status, bytes) = post_bytes(
            &fixture,
            &format!("/v1/ai/quota/{id}"),
            &a.token,
            agent_binding(&fixture, &a),
            use_fallback_body(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "agent uses the fallback: {bytes:?}"
        );
        assert_eq!(
            fixture
                .vault
                .model_fallback(&id)
                .expect("read the fallback")
                .as_deref(),
            Some(FALLBACK_MODEL),
            "the standing fallback is set"
        );

        let record = QuotaAnswerRecord::read(&fixture.vault, &id)
            .expect("read the answer row")
            .expect("the answer row is kept");
        assert_eq!(record.question, id);
        assert_eq!(record.choice, QuotaChoice::UseFallback);
        assert_eq!(record.fallback.as_deref(), Some(FALLBACK_MODEL));
        assert_eq!(record.answered_by, QuotaAnswerer::Agent(a.principal));

        fixture.finish().await;
    });
}

/// With the `use_fallback` item at its default (off), the agent's answer is
/// refused exactly as today and leaves no trace; the owner's answer then
/// stands and its row reads back the owner as the answerer.
#[test]
fn a_fallback_the_owner_did_not_let_stays_his_and_records_him() {
    run_on_engine_stack("wave11-quota-fallback-default", || async {
        let (fixture, a, _b) = setup().await;
        let id = offer_question_id(0xb2);
        plant_fallback_question(&fixture, &id);

        let (status, body) = post(
            &fixture,
            &format!("/v1/ai/quota/{id}"),
            &a.token,
            agent_binding(&fixture, &a),
            use_fallback_body(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "agent fallback: {body}");
        assert_eq!(
            body["error"]["code"].as_str(),
            Some("owner_required"),
            "today's code: {body}"
        );
        assert_eq!(
            fixture
                .vault
                .model_fallback(&id)
                .expect("read the fallback"),
            None,
            "no fallback is set"
        );
        assert_eq!(
            QuotaAnswerRecord::read(&fixture.vault, &id).expect("read the answer row"),
            None,
            "a refused answer keeps no row"
        );

        let (status, bytes) = post_bytes(
            &fixture,
            &format!("/v1/ai/quota/{id}"),
            &fixture.owner_token,
            owner_binding(&fixture),
            use_fallback_body(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "owner uses the fallback: {bytes:?}"
        );
        let record = QuotaAnswerRecord::read(&fixture.vault, &id)
            .expect("read the answer row")
            .expect("the answer row is kept");
        assert_eq!(record.choice, QuotaChoice::UseFallback);
        assert_eq!(record.answered_by, QuotaAnswerer::Owner);

        fixture.finish().await;
    });
}

/// Plants one open quota question for spent prepaid credit on `account`,
/// as the runtime keeps one when a spent account parks all its offers.
fn plant_account_question(fixture: &Fixture, id: &str, account: &str) {
    let question = QuotaQuestion {
        id: id.to_owned(),
        asked_at: fixture.vault.now_recorded_at(),
        provider: "fixture".to_owned(),
        model: "fixture/model".to_owned(),
        route: "fixture".to_owned(),
        spent: SpentKind::Credit,
        resets_at: None,
        choices: vec![QuotaChoice::TopUp, QuotaChoice::AddAccount],
        fallbacks: Vec::new(),
        account: Some(account.to_owned()),
    };
    let bytes = rmp_serde::to_vec_named(&question).expect("encode the question");
    fixture
        .vault
        .sync_state_put(&format!("models:offer-cooldown:v1:ask:{id}"), &bytes)
        .expect("plant the question");
}

/// Whether the question `id` is still open.
fn question_open(fixture: &Fixture, id: &str) -> bool {
    fixture
        .vault
        .sync_state_get(&format!("models:offer-cooldown:v1:ask:{id}"))
        .expect("read the question")
        .is_some()
}

/// One top-up serves every offer billed to the account: the owner's answer
/// to one question closes each question open under that account, and each
/// one's answer row reads back the owner and the top-up. A question on
/// another account stays open with no answer row.
#[test]
fn a_top_up_records_its_answerer_on_every_question_it_closes() {
    run_on_engine_stack("wave11-quota-top-up-account", || async {
        let (fixture, _a, _b) = setup().await;
        let answered = offer_question_id(0xc3);
        let sibling = offer_question_id(0xc4);
        let other = offer_question_id(0xc5);
        plant_account_question(&fixture, &answered, "account-one");
        plant_account_question(&fixture, &sibling, "account-one");
        plant_account_question(&fixture, &other, "account-two");

        let (status, bytes) = post_bytes(
            &fixture,
            &format!("/v1/ai/quota/{answered}"),
            &fixture.owner_token,
            owner_binding(&fixture),
            json!({"choice": "top_up"}),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "owner tops up: {bytes:?}");

        for id in [&answered, &sibling] {
            assert!(!question_open(&fixture, id), "the top-up closes {id}");
            let record = QuotaAnswerRecord::read(&fixture.vault, id)
                .expect("read the answer row")
                .expect("the answer row is kept");
            assert_eq!(record.question, *id);
            assert_eq!(record.choice, QuotaChoice::TopUp);
            assert_eq!(record.fallback, None);
            assert_eq!(record.answered_by, QuotaAnswerer::Owner);
        }
        assert!(
            question_open(&fixture, &other),
            "another account's question stays open"
        );
        assert_eq!(
            QuotaAnswerRecord::read(&fixture.vault, &other).expect("read the answer row"),
            None,
            "an unanswered question keeps no row"
        );

        fixture.finish().await;
    });
}
