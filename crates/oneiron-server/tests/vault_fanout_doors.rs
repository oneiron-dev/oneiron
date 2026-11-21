#![cfg(oneiron_test_support)]
//! The vault fan-out doors (OF-393), entered as the SDK enters them: HTTP
//! `POST /v1/core/facade/<verb>` through the in-process router (`oneshot`,
//! no TCP ports, no sleeps). The family is `vault.fanout.spawn` (admit a
//! batch under the attached live run), `.launch` and `.slots` (read one
//! launch), `.resume` (the owner rules on a held launch), `.resume_as` (a
//! live lead or board holder rules), and `.ack` (the owner answers the width
//! check of a launch that went out).
//!
//! The promises this file proves:
//! - P1 (canon `planning/workbench-engine-asks.md:102`, mirror
//!   `llms-full.txt:372914`): "In `FULL` access, the fan-out just goes."
//! - P2 (canon `planning/workbench-engine-asks.md:104`, mirror
//!   `llms-full.txt:372916`): "manual pauses each fan-out at any width".
//! - P4 (canon `oneiron-arch-0079-agent-coordination-v1.md:114`, mirror
//!   `llms-full.txt:351217`): "An agent cannot approve its own held fan-out.
//!   Only an Owner approval whose digest matches the held fan-out launches it."
//! P3 ("reverse a runaway run in one action") stays unproven: no verb in this
//! family reverses launched work (FIX-LIST row FANOUT-REVERSE-RUNAWAY-NO-VERB);
//! the nearest proven behaviour is that deny keeps the hold visible.
//!
//! Each run test owns a fresh vault with a leased run of the seeded default
//! agent, registered live and attached over
//! `POST /v1/core/live-runs/{run}/attach`, plus the fan-out policy the test
//! names (FULL/MANUAL, threshold). The refusal table owns a fresh vault with
//! no run at all.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test vault_fanout_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::agent_def::AgentDefinition;
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, SpendScopeId, agent_dispatch_actor,
};
use oneiron::attempt_queue::{AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::check_in::CheckInMode;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::ScopeAxis;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::{ConsultFanOutPolicy, TaskCreateRateLimit};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::test_support::provision_engine_machines;
use oneiron::{AttemptQueue, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::test_doors::live_run_step::register_live_run;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The run's budget: roomy enough that no call here meets its cap.
const RUN_UNITS: u64 = 1_000_000;
/// The lease owner the tests claim the run's try as, as a pump holds it.
const WORKER: &str = "vault-fanout-doors";
/// The model string the live run is registered under. FULL/MANUAL admission
/// asks no model, so no provider stands behind it.
const MODEL: &str = "test/fanout-model@r1";
/// The shipped create rate the policy writes keep (limit, window seconds).
const CREATE_LIMIT: usize = 2000;
const CREATE_WINDOW: u64 = 60;
/// The default threshold the tests keep when they do not cross the check.
const WIDE_OPEN: u32 = 1000;

/// A handle with none of the guard's `lr1.<run>.<issued>` syntax.
const MALFORMED_HANDLE: &str = "not-a-live-run-handle";
/// A well-formed handle that names no registered run and no attachment.
const UNKNOWN_HANDLE: &str =
    "lr1.11111111111111111111111111111111.22222222222222222222222222222222";
/// A session header that is no 32-hex id.
const BAD_SESSION: &str = "not-a-session";
/// The record bound that narrows the record-narrowed slip.
const NARROW_RECORD: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// A 64-hex digest that names no frozen plan (fresh-vault refusal rows).
const DUMMY_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// `LiveRunRefusal::Invalid`'s fixed text.
const INVALID_MESSAGE: &str = "the live-run handle is malformed";
/// `LiveRunRefusal::Unavailable`'s fixed text.
const UNAVAILABLE_MESSAGE: &str = "no live run this credential may act for";
/// `facade_actor`'s refusal for a slip that names no principal.
const PRINCIPAL_MESSAGE: &str = "facade routes bind writes to an authenticated principal";
/// `ApiError::forbidden_scope`'s fixed text, for scope and record scope alike.
const SCOPE_MESSAGE: &str = "request does not have the required scope";
/// `hold_live_run`'s refusal for any call made inside a session.
const OFF_RECORD_MESSAGE: &str =
    "live child admission requires the attached run's canonical storage";
/// `FacadeCall::session`'s refusal for a malformed session header.
const SESSION_MESSAGE: &str = "invalid session header";
/// `validate_input`'s decode refusal, before the path it names.
const DECODE_PREFIX: &str = "invalid SDK request: ";
/// The facade's malformed-JSON refusal.
const BAD_JSON_MESSAGE: &str = "invalid JSON request body";
/// `plan_digest`'s fixed shape refusal.
const DIGEST_MESSAGE: &str = "plan_digest must be 64 lowercase hex digits";
/// The engine's unknown-launch refusal.
const UNKNOWN_LAUNCH_MESSAGE: &str = "fan-out launch not found";
/// The engine's launched-deny refusal.
const LAUNCHED_DENY_MESSAGE: &str = "a launched fan-out cannot be denied retroactively";
/// The engine's ack-without-check refusal.
const NO_CHECK_MESSAGE: &str = "fan-out launch has no width check to acknowledge";
/// The engine's holder-role refusal.
const ROLE_MESSAGE: &str = "actor does not hold this launch's approval role";

/// One minted slip with its holder key and presented token.
struct Credential {
    slip: CapabilitySlip,
    key: SigningKey,
    token: String,
}

/// A device vault, its server and app, the owner, and the seeded agent def.
struct Base {
    dir: tempfile::TempDir,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    owner_id: EntityId,
    root_slip: CapabilitySlip,
    root_token: String,
    server: Arc<SyncServer>,
    agent_def: EntityId,
}

/// A vault with a leased run registered live and attached, ready to spawn.
struct Fixture {
    vault: Arc<Vault>,
    _dir: tempfile::TempDir,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner_person: Credential,
    person_credential: Credential,
    agent_credential: Credential,
    other_agent_credential: Credential,
    handle: String,
    agent_def: EntityId,
}

/// A fresh vault with no run, for the refusal table.
struct FreshFixture {
    vault: Arc<Vault>,
    _dir: tempfile::TempDir,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    person_credential: Credential,
    agent_credential: Credential,
    agent_def: EntityId,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key one credential binds; its holder proves it per request.
fn holder_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// A live PERSON entity, as the house tests place one.
fn seed_person(vault: &Vault) -> EntityId {
    let who = EntityId::now();
    vault
        .put_entity(
            &who,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    who
}

/// The verbs every full credential here holds (both vocabularies).
fn full_verbs() -> BTreeSet<String> {
    BTreeSet::from([
        "read".to_owned(),
        "write".to_owned(),
        "core:read".to_owned(),
        "core:write".to_owned(),
    ])
}

/// A credential this host mints: the root's claims narrowed to `holder_ref`,
/// `actor_class` and `verbs`, proved by the key `seed` names.
fn mint_credential(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    root: &CapabilitySlip,
    holder_ref: &str,
    actor_class: &str,
    verbs: BTreeSet<String>,
    seed: u8,
) -> Credential {
    let key = holder_key(seed);
    let mut claims = root.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder_ref.to_owned();
    claims.actor_class = Some(actor_class.to_owned());
    claims.binding_key = key.verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(verbs);
    let slip = vault
        .mint_capability_slip(issuer, claims)
        .expect("a credential");
    let token = slip.to_token().expect("a credential token");
    Credential { slip, key, token }
}

/// The leased try of a root run of the seeded default agent, dispatched with
/// a budget: the try, the run's actor, its frozen definition and its scope.
fn leased_run(vault: &Vault) -> (AttemptRecord, WriteActor, AgentDefinition, SpendScopeId) {
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)
        .expect("the default agent is seeded")
        .expect("the default agent row exists");
    let dispatcher = AgentDispatcher::new(vault);
    let AgentDispatchOutcome::Dispatched(status) = dispatcher
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some(WORKER.to_owned()),
                now: 1,
            },
            AgentSpawnContext::default()
                .with_depth_remaining(1)
                .with_budget(RUN_UNITS),
        )
        .expect("one fresh root run")
    else {
        panic!("expected one fresh root run");
    };
    let actor = agent_dispatch_actor(&status.input).expect("the run's actor");
    let queue = AttemptQueue::new(vault);
    let mut leased = None;
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue
            .claim_kind(
                DREAMER_RUNNER_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: WORKER.to_owned(),
                    now: u64::MAX,
                },
            )
            .expect("claim the run's try")
        else {
            break;
        };
        if row.id == status.attempt.id {
            leased = queue.get(row.id).expect("the leased try");
            break;
        }
    }
    let leased = leased.expect("the run's try is ready to claim");
    let scope = dispatcher
        .spend_scope_for_attempt(leased.id)
        .expect("the run's scope")
        .expect("the budgeted run spends under a scope");
    (leased, actor, status.input.definition, scope)
}

/// A fresh vault with its server: keystore, engine machines, serving profile,
/// embedded owner, host root slip, and the seeded agent def id.
fn base_vault(auth_secret: &str) -> Base {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let issuer = provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let (owner_id, _) = embedded_owner(&vault).expect("the embedded owner");
    let root_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let root_token = root_slip.to_token().expect("owner slip token");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some(auth_secret.into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let (agent_def, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)
        .expect("the default agent is seeded")
        .expect("the default agent row exists");
    Base {
        dir,
        vault,
        issuer,
        owner_id,
        root_slip,
        root_token,
        server,
        agent_def,
    }
}

async fn setup() -> Fixture {
    let base = base_vault("vault-fanout-doors");
    let (leased, actor, definition, scope) = leased_run(&base.vault);
    let run = EntityId::now();
    register_live_run(
        &base.server,
        run,
        actor,
        &leased,
        MODEL,
        definition,
        Some(scope),
    )
    .expect("register the live run");
    let app = build_app(Arc::clone(&base.server));
    let owner_hex = base.owner_id.to_hex();
    let owner_person = mint_credential(
        &base.vault,
        &base.issuer,
        &base.root_slip,
        &owner_hex,
        "human",
        full_verbs(),
        0x1A,
    );
    let who = seed_person(&base.vault);
    let person_credential = mint_credential(
        &base.vault,
        &base.issuer,
        &base.root_slip,
        &who.to_hex(),
        "human",
        full_verbs(),
        0x5B,
    );
    let agent_credential = mint_credential(
        &base.vault,
        &base.issuer,
        &base.root_slip,
        &actor.entity_ref().to_hex(),
        "agent",
        full_verbs(),
        0xA6,
    );
    let other = base
        .vault
        .ensure_agent_principal("vault-fanout-doors-other")
        .expect("another agent principal");
    let other_agent_credential = mint_credential(
        &base.vault,
        &base.issuer,
        &base.root_slip,
        &other.to_hex(),
        "agent",
        full_verbs(),
        0xB7,
    );
    let mut fixture = Fixture {
        vault: base.vault,
        _dir: base.dir,
        app,
        issuer: base.issuer,
        owner_slip: base.root_slip,
        owner_token: base.root_token,
        owner_person,
        person_credential,
        agent_credential,
        other_agent_credential,
        handle: String::new(),
        agent_def: base.agent_def,
    };
    let attach_path = format!("/v1/core/live-runs/{}/attach", run.to_hex());
    let (status, body) =
        post_as_credential(&fixture, &attach_path, json!({}), &fixture.agent_credential).await;
    assert_eq!(status, StatusCode::OK, "the run's agent attaches: {body}");
    let handle = body["liveRun"]
        .as_str()
        .expect("the attach answers a handle")
        .to_owned();
    fixture.handle = handle;
    fixture
}

async fn setup_fresh() -> FreshFixture {
    let base = base_vault("vault-fanout-doors-fresh");
    let app = build_app(Arc::clone(&base.server));
    let who = seed_person(&base.vault);
    let person_credential = mint_credential(
        &base.vault,
        &base.issuer,
        &base.root_slip,
        &who.to_hex(),
        "human",
        full_verbs(),
        0x5B,
    );
    let agent_id = base
        .vault
        .ensure_agent_principal("vault-fanout-doors-agent")
        .expect("an agent principal");
    let agent_credential = mint_credential(
        &base.vault,
        &base.issuer,
        &base.root_slip,
        &agent_id.to_hex(),
        "agent",
        full_verbs(),
        0xA6,
    );
    FreshFixture {
        vault: base.vault,
        _dir: base.dir,
        app,
        issuer: base.issuer,
        owner_slip: base.root_slip,
        owner_token: base.root_token,
        person_credential,
        agent_credential,
        agent_def: base.agent_def,
    }
}

/// The fan-out policy `mode` with `threshold`, keeping the shipped rates.
fn set_policy(fixture: &Fixture, mode: CheckInMode, threshold: u32) {
    let (owner_id, proof) = embedded_owner(&fixture.vault).expect("the embedded owner");
    let policy = ConsultFanOutPolicy {
        approval_threshold: threshold,
        mode,
        peer_rate: None,
        create_rate: TaskCreateRateLimit {
            limit: CREATE_LIMIT,
            window_seconds: CREATE_WINDOW,
        },
    };
    fixture
        .vault
        .memory(owner_id, EdgeActorClass::Human)
        .set_consult_fanout_policy(&proof, &policy)
        .expect("set the fan-out policy");
}

fn owner_binding(vault: &Vault, issuer: &HostSlipIssuer, slip: &CapabilitySlip) -> String {
    let timestamp = vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = hex(&issuer
        .binding_proof(slip, challenge.as_bytes())
        .expect("owner holder proof"));
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

fn slip_binding(vault: &Vault, credential: &Credential) -> String {
    holder_proof(&credential.slip, &credential.key, vault.now_recorded_at())
        .expect("holder proof")
        .to_string()
}

async fn post(
    app: &Router,
    path: &str,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    post_raw(app, path, token, binding, &body.to_string()).await
}

async fn post_raw(
    app: &Router,
    path: &str,
    token: &str,
    binding: String,
    raw: &str,
) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
        .header("content-type", "application/json")
        .body(Body::from(raw.to_owned()))
        .expect("facade request");
    let response = app.clone().oneshot(request).await.expect("facade response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    let answer: Value = serde_json::from_slice(&bytes).expect("response JSON");
    (status, answer)
}

async fn post_with_session(
    app: &Router,
    path: &str,
    token: &str,
    binding: String,
    body: Value,
    session: &str,
) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
        .header("x-oneiron-session", session)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("facade request");
    let response = app.clone().oneshot(request).await.expect("facade response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    let answer: Value = serde_json::from_slice(&bytes).expect("response JSON");
    (status, answer)
}

async fn post_as_owner(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let binding = owner_binding(&fixture.vault, &fixture.issuer, &fixture.owner_slip);
    let token = fixture.owner_token.clone();
    post(&fixture.app, path, &token, binding, body).await
}

async fn post_as_credential(
    fixture: &Fixture,
    path: &str,
    body: Value,
    credential: &Credential,
) -> (StatusCode, Value) {
    let binding = slip_binding(&fixture.vault, credential);
    post(&fixture.app, path, &credential.token, binding, body).await
}

async fn fresh_post_as_owner(
    fixture: &FreshFixture,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let binding = owner_binding(&fixture.vault, &fixture.issuer, &fixture.owner_slip);
    let token = fixture.owner_token.clone();
    post(&fixture.app, path, &token, binding, body).await
}

async fn fresh_post_as_credential(
    fixture: &FreshFixture,
    path: &str,
    body: Value,
    credential: &Credential,
) -> (StatusCode, Value) {
    let binding = slip_binding(&fixture.vault, credential);
    post(&fixture.app, path, &credential.token, binding, body).await
}

/// `width` children on the seeded agent def, with distinct labels.
fn children_json(agent_def: &EntityId, width: usize) -> Value {
    let kids: Vec<Value> = (0..width)
        .map(|index| {
            json!({
                "agent_ref": agent_def.to_hex(),
                "label": format!("child-{index}"),
                "prompt": format!("do part {index} of the batch"),
            })
        })
        .collect();
    Value::Array(kids)
}

/// A spawn body for `intent_key` at `width` on the attached run.
fn spawn_body(fixture: &Fixture, intent_key: &str, width: usize) -> Value {
    json!({
        "live_run": fixture.handle.clone(),
        "spec": {
            "intent_key": intent_key,
            "children": children_json(&fixture.agent_def, width),
        },
    })
}

async fn spawn(fixture: &Fixture, intent_key: &str, width: usize) -> (StatusCode, Value) {
    let body = spawn_body(fixture, intent_key, width);
    let path = "/v1/core/facade/vault.fanout.spawn";
    post_as_credential(fixture, path, body, &fixture.agent_credential).await
}

async fn launch_as(
    fixture: &Fixture,
    launch_ref: &str,
    credential: &Credential,
) -> (StatusCode, Value) {
    post_as_credential(
        fixture,
        "/v1/core/facade/vault.fanout.launch",
        json!({"launch_ref": launch_ref}),
        credential,
    )
    .await
}

async fn slots_as(
    fixture: &Fixture,
    launch_ref: &str,
    credential: &Credential,
) -> (StatusCode, Value) {
    post_as_credential(
        fixture,
        "/v1/core/facade/vault.fanout.slots",
        json!({"launch_ref": launch_ref}),
        credential,
    )
    .await
}

async fn resume_as_owner(
    fixture: &Fixture,
    launch_ref: &str,
    digest: &str,
    ruling: &str,
) -> (StatusCode, Value) {
    post_as_owner(
        fixture,
        "/v1/core/facade/vault.fanout.resume",
        json!({"launch_ref": launch_ref, "plan_digest": digest, "ruling": ruling}),
    )
    .await
}

async fn ack_as_owner(
    fixture: &Fixture,
    launch_ref: &str,
    digest: &str,
    answer: &str,
) -> (StatusCode, Value) {
    post_as_owner(
        fixture,
        "/v1/core/facade/vault.fanout.ack",
        json!({"launch_ref": launch_ref, "plan_digest": digest, "answer": answer}),
    )
    .await
}

/// The launch hex, digest and view of a spawn answer.
fn spawn_launch(answer: &Value) -> (String, String, Value) {
    let launch = &answer["launch"];
    let launch_ref = launch["launch_ref"]
        .as_str()
        .expect("the spawn mints a launch")
        .to_owned();
    let digest = launch["plan_digest"]
        .as_str()
        .expect("the spawn freezes a digest")
        .to_owned();
    (launch_ref, digest, launch.clone())
}

fn assert_digest_shape(digest: &str, what: &str) {
    assert_eq!(
        digest.len(),
        64,
        "{what}: the digest is 64 hex digits: {digest}"
    );
    assert!(
        digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{what}: the digest is lowercase hex: {digest}"
    );
}

fn assert_refusal(
    status: StatusCode,
    answer: &Value,
    expected_status: StatusCode,
    expected_code: &str,
    expected_message: &str,
    what: &str,
) {
    assert_eq!(status, expected_status, "{what}: {answer}");
    assert_eq!(
        answer["error"]["code"].as_str(),
        Some(expected_code),
        "{what}: {answer}"
    );
    assert_eq!(
        answer["error"]["message"].as_str(),
        Some(expected_message),
        "{what}: {answer}"
    );
}

fn assert_decode_refusal(status: StatusCode, answer: &Value, field: &str, what: &str) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {answer}");
    assert_eq!(
        answer["error"]["code"].as_str(),
        Some("BAD_REQUEST"),
        "{what}: {answer}"
    );
    let message = answer["error"]["message"]
        .as_str()
        .expect("a decode refusal names its shape");
    assert!(message.starts_with(DECODE_PREFIX), "{what}: {answer}");
    assert!(message.contains(field), "{what}: {answer}");
}

fn owner_message(verb: &str) -> String {
    format!("{verb} is the vault owner's")
}

/// In FULL access the fan-out just goes: a width-2 spawn mints both TASKs,
/// holds nothing, and reads back whole.
///
/// Canon `planning/workbench-engine-asks.md:102` "In FULL access, the fan-out
/// just goes." (mirror `llms-full.txt:372914`).
#[test]
fn full_access_spawn_just_goes() {
    run_on_engine_stack("fanout-full-goes", || async {
        let fixture = setup().await;
        set_policy(&fixture, CheckInMode::NeverAsk, WIDE_OPEN);
        let (status, answer) = spawn(&fixture, "p1-full-goes", 2).await;
        assert_eq!(status, StatusCode::OK, "FULL spawn lands: {answer}");
        let (launch_ref, digest, launch) = spawn_launch(&answer);
        assert_digest_shape(&digest, "the FULL launch");
        assert!(launch["held"].is_null(), "FULL holds nothing: {launch}");
        assert!(
            launch["check_row_ref"].is_null(),
            "below the threshold there is no width check: {launch}"
        );
        let task_refs = launch["task_refs"]
            .as_array()
            .expect("FULL mints TASK refs");
        assert_eq!(task_refs.len(), 2, "FULL mints both children: {launch}");
        assert_eq!(
            launch["statement"]["task_count"].as_u64(),
            Some(2),
            "the statement states the width: {launch}"
        );
        let slots = answer["slots"].as_array().expect("the spawn answers slots");
        assert_eq!(slots.len(), 2, "one slot per child: {answer}");
        for (index, slot) in slots.iter().enumerate() {
            assert_eq!(
                slot["state"].as_str(),
                Some("pending"),
                "slot {index} goes: {slot}"
            );
            assert!(
                slot["task_ref"].is_string(),
                "slot {index} mints its TASK: {slot}"
            );
        }
        let (status, reread) = launch_as(&fixture, &launch_ref, &fixture.owner_person).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner reads the launch: {reread}"
        );
        assert!(
            reread["held"].is_null(),
            "the reread holds nothing: {reread}"
        );
        assert_eq!(
            reread["task_refs"]
                .as_array()
                .expect("reread TASK refs")
                .len(),
            2,
            "the reread keeps both children: {reread}"
        );
        let (status, observed) = slots_as(&fixture, &launch_ref, &fixture.owner_person).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner reads the slots: {observed}"
        );
        let observed_slots = observed["slots"]
            .as_array()
            .expect("the slots answer slots");
        assert_eq!(
            observed_slots.len(),
            2,
            "the slots keep both children: {observed}"
        );
        for (index, slot) in observed_slots.iter().enumerate() {
            assert_eq!(
                slot["state"].as_str(),
                Some("pending"),
                "reread slot {index} goes: {slot}"
            );
        }
    });
}

/// Manual pauses each fan-out at any width: width 1 and width 3 both hold,
/// with no TASK minted.
///
/// Canon `planning/workbench-engine-asks.md:104` "manual pauses each fan-out
/// at any width" (mirror `llms-full.txt:372916`).
#[test]
fn manual_spawn_holds_at_any_width() {
    run_on_engine_stack("fanout-manual-holds", || async {
        let fixture = setup().await;
        set_policy(&fixture, CheckInMode::AlwaysAsk, WIDE_OPEN);
        for (intent_key, width) in [("p2-manual-1", 1_usize), ("p2-manual-3", 3_usize)] {
            let (status, answer) = spawn(&fixture, intent_key, width).await;
            assert_eq!(status, StatusCode::OK, "MANUAL spawn lands held: {answer}");
            let (launch_ref, digest, launch) = spawn_launch(&answer);
            assert_digest_shape(&digest, "the MANUAL hold");
            let held = &launch["held"];
            assert!(held.is_object(), "width {width} holds: {launch}");
            assert!(
                held["surface_ref"]
                    .as_str()
                    .is_some_and(|surface| !surface.is_empty()),
                "the hold surfaces its row: {launch}"
            );
            assert_eq!(
                held["denied"].as_bool(),
                Some(false),
                "the hold is fresh: {launch}"
            );
            assert!(
                launch["task_refs"]
                    .as_array()
                    .expect("held TASK refs")
                    .is_empty(),
                "a held launch mints nothing: {launch}"
            );
            let slots = answer["slots"].as_array().expect("the spawn answers slots");
            assert_eq!(slots.len(), width, "one slot per child: {answer}");
            for (index, slot) in slots.iter().enumerate() {
                assert_eq!(
                    slot["state"].as_str(),
                    Some("held"),
                    "width-{width} slot {index} holds: {slot}"
                );
                assert!(
                    slot["task_ref"].is_null(),
                    "a held slot mints nothing: {slot}"
                );
            }
            let (status, reread) = launch_as(&fixture, &launch_ref, &fixture.owner_person).await;
            assert_eq!(status, StatusCode::OK, "the owner reads the hold: {reread}");
            assert!(
                reread["held"].is_object(),
                "the reread still holds: {reread}"
            );
        }
    });
}

/// The owner approves a held launch once: the frozen TASKs mint, the hold
/// clears, and a replay answers the same TASKs without minting again.
///
/// Canon `planning/workbench-engine-asks.md:104` "manual pauses each fan-out
/// at any width" (mirror `llms-full.txt:372916`): the completion half.
#[test]
fn owner_resume_approves_once_and_mints_children() {
    run_on_engine_stack("fanout-resume-mints", || async {
        let fixture = setup().await;
        set_policy(&fixture, CheckInMode::AlwaysAsk, WIDE_OPEN);
        let (status, answer) = spawn(&fixture, "p3-resume-mints", 3).await;
        assert_eq!(status, StatusCode::OK, "MANUAL spawn lands held: {answer}");
        let (launch_ref, digest, launch) = spawn_launch(&answer);
        assert!(
            launch["held"].is_object(),
            "the launch holds first: {launch}"
        );
        let (status, ruled) = resume_as_owner(&fixture, &launch_ref, &digest, "approve_once").await;
        assert_eq!(status, StatusCode::OK, "the owner approves once: {ruled}");
        assert!(
            ruled["held"].is_null(),
            "the approval clears the hold: {ruled}"
        );
        let minted = ruled["task_refs"]
            .as_array()
            .expect("the approval mints TASK refs");
        assert_eq!(
            minted.len(),
            3,
            "the approval mints all three children: {ruled}"
        );
        assert!(
            ruled["choice_receipt_ref"].is_string(),
            "the approval is receipted: {ruled}"
        );
        let (status, observed) = slots_as(&fixture, &launch_ref, &fixture.owner_person).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the slots flip to pending: {observed}"
        );
        for (index, slot) in observed["slots"]
            .as_array()
            .expect("slots")
            .iter()
            .enumerate()
        {
            assert_eq!(
                slot["state"].as_str(),
                Some("pending"),
                "slot {index} goes after the ruling: {slot}"
            );
        }
        let (status, replayed) =
            resume_as_owner(&fixture, &launch_ref, &digest, "approve_once").await;
        assert_eq!(status, StatusCode::OK, "a replay answers: {replayed}");
        assert_eq!(
            replayed["task_refs"], ruled["task_refs"],
            "a replay mints nothing new: {replayed}"
        );
    });
}

/// Deny keeps the hold visible: denied stays true, nothing mints, and the
/// slots stay held. Denying a launch that already went out is refused.
///
/// Nearest door-visible behaviour to P3 ("reverse a runaway run in one
/// action"); P3 itself stays unproven — no verb here reverses launched work.
#[test]
fn deny_keeps_the_hold_visible() {
    run_on_engine_stack("fanout-deny-holds", || async {
        let fixture = setup().await;
        set_policy(&fixture, CheckInMode::AlwaysAsk, WIDE_OPEN);
        let (status, answer) = spawn(&fixture, "p4-deny-hold", 3).await;
        assert_eq!(status, StatusCode::OK, "MANUAL spawn lands held: {answer}");
        let (launch_ref, digest, _) = spawn_launch(&answer);
        let (status, denied) = resume_as_owner(&fixture, &launch_ref, &digest, "deny").await;
        assert_eq!(status, StatusCode::OK, "the owner denies: {denied}");
        assert_eq!(
            denied["held"]["denied"].as_bool(),
            Some(true),
            "the denial is recorded on the hold: {denied}"
        );
        assert!(
            denied["task_refs"]
                .as_array()
                .expect("denied TASK refs")
                .is_empty(),
            "a denial mints nothing: {denied}"
        );
        let (status, observed) = slots_as(&fixture, &launch_ref, &fixture.owner_person).await;
        assert_eq!(status, StatusCode::OK, "the slots stay held: {observed}");
        for (index, slot) in observed["slots"]
            .as_array()
            .expect("slots")
            .iter()
            .enumerate()
        {
            assert_eq!(
                slot["state"].as_str(),
                Some("held"),
                "slot {index} stays held after the denial: {slot}"
            );
        }
        set_policy(&fixture, CheckInMode::NeverAsk, WIDE_OPEN);
        let (status, gone) = spawn(&fixture, "p4-deny-launched", 3).await;
        assert_eq!(status, StatusCode::OK, "FULL spawn goes: {gone}");
        let (launched_ref, launched_digest, _) = spawn_launch(&gone);
        let (status, refused) =
            resume_as_owner(&fixture, &launched_ref, &launched_digest, "deny").await;
        assert_refusal(
            status,
            &refused,
            StatusCode::CONFLICT,
            "INVALID_STATE",
            LAUNCHED_DENY_MESSAGE,
            "the engine refuses a deny on a launched fan-out",
        );
    });
}

/// An agent cannot approve its own held fan-out: the run's agent is refused
/// on resume, on ack, and on resume_as, and only the owner's approval with
/// the surfaced digest launches it.
///
/// Canon `oneiron-arch-0079-agent-coordination-v1.md:114` "An agent cannot
/// approve its own held fan-out." (mirror `llms-full.txt:351217`).
#[test]
fn agent_cannot_rule_on_its_own_hold() {
    run_on_engine_stack("fanout-agent-cannot-rule", || async {
        let fixture = setup().await;
        set_policy(&fixture, CheckInMode::AlwaysAsk, WIDE_OPEN);
        let (status, answer) = spawn(&fixture, "p5-agent-hold", 3).await;
        assert_eq!(status, StatusCode::OK, "MANUAL spawn lands held: {answer}");
        let (launch_ref, digest, launch) = spawn_launch(&answer);
        assert!(
            launch["held"].is_object(),
            "the launch holds first: {launch}"
        );
        let agent_body = json!({
            "launch_ref": launch_ref.clone(),
            "plan_digest": digest.clone(),
            "ruling": "approve_once",
        });
        let (status, refused) = post_as_credential(
            &fixture,
            "/v1/core/facade/vault.fanout.resume",
            agent_body,
            &fixture.agent_credential,
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            &owner_message("vault.fanout.resume"),
            "the owner precheck refuses the run's agent on resume",
        );
        let agent_ack = json!({
            "launch_ref": launch_ref.clone(),
            "plan_digest": digest.clone(),
            "answer": "ack",
        });
        let (status, refused) = post_as_credential(
            &fixture,
            "/v1/core/facade/vault.fanout.ack",
            agent_ack,
            &fixture.agent_credential,
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            &owner_message("vault.fanout.ack"),
            "the owner precheck refuses the run's agent on ack",
        );
        let agent_holder = json!({
            "launch_ref": launch_ref.clone(),
            "plan_digest": digest.clone(),
            "ruling": "approve_once",
        });
        let (status, refused) = post_as_credential(
            &fixture,
            "/v1/core/facade/vault.fanout.resume_as",
            agent_holder,
            &fixture.agent_credential,
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            ROLE_MESSAGE,
            "the engine refuses the run's agent as a holder",
        );
        let (status, ruled) = resume_as_owner(&fixture, &launch_ref, &digest, "approve_once").await;
        assert_eq!(status, StatusCode::OK, "the owner approves once: {ruled}");
        assert_eq!(
            ruled["task_refs"]
                .as_array()
                .expect("minted TASK refs")
                .len(),
            3,
            "only the owner's approval launches it: {ruled}"
        );
    });
}

/// A FULL launch above the threshold carries a width check the owner acks:
/// the ack lands, a replay answers the same receipt, and acking a held
/// launch (no check) is refused.
#[test]
fn ack_answers_a_launched_width_check() {
    run_on_engine_stack("fanout-ack-check", || async {
        let fixture = setup().await;
        set_policy(&fixture, CheckInMode::NeverAsk, 1);
        let (status, answer) = spawn(&fixture, "p6-ack-check", 3).await;
        assert_eq!(status, StatusCode::OK, "FULL spawn goes: {answer}");
        let (launch_ref, digest, launch) = spawn_launch(&answer);
        assert!(
            launch["held"].is_null(),
            "a FULL launch holds nothing: {launch}"
        );
        assert!(
            launch["check_row_ref"].is_string(),
            "above the threshold the launch carries its check: {launch}"
        );
        let (status, acked) = ack_as_owner(&fixture, &launch_ref, &digest, "ack").await;
        assert_eq!(status, StatusCode::OK, "the owner acks the check: {acked}");
        let receipt = acked["choice_receipt_ref"]
            .as_str()
            .expect("the ack is receipted")
            .to_owned();
        assert!(
            !receipt.is_empty(),
            "the ack receipt names its row: {acked}"
        );
        assert_eq!(
            acked["task_refs"]
                .as_array()
                .expect("acked TASK refs")
                .len(),
            3,
            "the ack touches no TASK: {acked}"
        );
        let (status, replayed) = ack_as_owner(&fixture, &launch_ref, &digest, "ack").await;
        assert_eq!(status, StatusCode::OK, "a repeated ack replays: {replayed}");
        assert_eq!(
            replayed["choice_receipt_ref"].as_str(),
            Some(receipt.as_str()),
            "the replay answers the recorded receipt: {replayed}"
        );
        set_policy(&fixture, CheckInMode::AlwaysAsk, 1);
        let (status, held) = spawn(&fixture, "p6-ack-held", 3).await;
        assert_eq!(status, StatusCode::OK, "MANUAL spawn lands held: {held}");
        let (held_ref, held_digest, _) = spawn_launch(&held);
        let (status, refused) = ack_as_owner(&fixture, &held_ref, &held_digest, "ack").await;
        assert_refusal(
            status,
            &refused,
            StatusCode::CONFLICT,
            "INVALID_STATE",
            NO_CHECK_MESSAGE,
            "the engine refuses an ack with no width check",
        );
    });
}

/// Launch and slots hide foreign and unknown launches: a stranger reads null,
/// and only the owner reads the row whole.
#[test]
fn launch_and_slots_hide_foreign_and_unknown() {
    run_on_engine_stack("fanout-visibility", || async {
        let fixture = setup().await;
        set_policy(&fixture, CheckInMode::AlwaysAsk, WIDE_OPEN);
        let (status, answer) = spawn(&fixture, "p7-visibility", 3).await;
        assert_eq!(status, StatusCode::OK, "MANUAL spawn lands held: {answer}");
        let (launch_ref, _, _) = spawn_launch(&answer);
        let unknown = EntityId::now().to_hex();
        let (status, body) = launch_as(&fixture, &unknown, &fixture.person_credential).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an unknown launch reads null: {body}"
        );
        assert!(body.is_null(), "unknown launch via launch: {body}");
        let (status, body) = slots_as(&fixture, &unknown, &fixture.person_credential).await;
        assert_eq!(status, StatusCode::OK, "unknown slots read null: {body}");
        assert!(body.is_null(), "unknown launch via slots: {body}");
        let (status, body) =
            launch_as(&fixture, &launch_ref, &fixture.other_agent_credential).await;
        assert_eq!(status, StatusCode::OK, "another agent reads null: {body}");
        assert!(body.is_null(), "another agent via launch: {body}");
        let (status, body) = slots_as(&fixture, &launch_ref, &fixture.other_agent_credential).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "another agent slots read null: {body}"
        );
        assert!(body.is_null(), "another agent via slots: {body}");
        let (status, body) = launch_as(&fixture, &launch_ref, &fixture.person_credential).await;
        assert_eq!(status, StatusCode::OK, "a stranger reads null: {body}");
        assert!(body.is_null(), "a stranger via launch: {body}");
        let (status, body) = slots_as(&fixture, &launch_ref, &fixture.person_credential).await;
        assert_eq!(status, StatusCode::OK, "a stranger slots read null: {body}");
        assert!(body.is_null(), "a stranger via slots: {body}");
        let (status, whole) = launch_as(&fixture, &launch_ref, &fixture.owner_person).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner reads the launch: {whole}"
        );
        assert_eq!(
            whole["launch_ref"].as_str(),
            Some(launch_ref.as_str()),
            "the owner reads it whole: {whole}"
        );
        let (status, whole) = slots_as(&fixture, &launch_ref, &fixture.owner_person).await;
        assert_eq!(status, StatusCode::OK, "the owner reads the slots: {whole}");
        assert_eq!(
            whole["slots"].as_array().expect("owner slots").len(),
            3,
            "the owner reads every slot: {whole}"
        );
    });
}

/// The fresh-vault refusal table: malformed bodies, wrong callers, unknown
/// ids and narrowed credentials, each refused by its own layer with the
/// source's own status, code and message.
#[test]
fn table_refusals_fresh_vault_no_run() {
    run_on_engine_stack("fanout-refusals", || async {
        let fixture = setup_fresh().await;
        let unknown = EntityId::now().to_hex();
        // Row 1: malformed JSON on an owner door.
        let binding = owner_binding(&fixture.vault, &fixture.issuer, &fixture.owner_slip);
        let token = fixture.owner_token.clone();
        let (status, refused) = post_raw(
            &fixture.app,
            "/v1/core/facade/vault.fanout.resume",
            &token,
            binding,
            "{not json",
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            BAD_JSON_MESSAGE,
            "the facade refuses malformed JSON",
        );
        // Row 2: bodies that do not decode (bound caller where the row needs one).
        let (status, refused) = fresh_post_as_credential(
            &fixture,
            "/v1/core/facade/vault.fanout.launch",
            json!({}),
            &fixture.person_credential,
        )
        .await;
        assert_decode_refusal(
            status,
            &refused,
            "launch_ref",
            "validate_input refuses a launch without its ref",
        );
        let (status, refused) = fresh_post_as_owner(
            &fixture,
            "/v1/core/facade/vault.fanout.resume",
            json!({"launch_ref": unknown.clone()}),
        )
        .await;
        assert_decode_refusal(
            status,
            &refused,
            "plan_digest",
            "validate_input refuses a resume without its digest",
        );
        let (status, refused) = fresh_post_as_owner(
            &fixture,
            "/v1/core/facade/vault.fanout.resume",
            json!({
                "launch_ref": unknown.clone(),
                "plan_digest": DUMMY_DIGEST,
                "ruling": "maybe",
            }),
        )
        .await;
        assert_decode_refusal(
            status,
            &refused,
            "ruling",
            "validate_input refuses a resume with a mistyped ruling",
        );
        // Row 3: resume/ack as a person, an agent and a stranger are the owner's.
        let resume_body = json!({
            "launch_ref": unknown.clone(),
            "plan_digest": DUMMY_DIGEST,
            "ruling": "approve_once",
        });
        let ack_body = json!({
            "launch_ref": unknown.clone(),
            "plan_digest": DUMMY_DIGEST,
            "answer": "ack",
        });
        for (verb, body) in [
            ("vault.fanout.resume", resume_body.clone()),
            ("vault.fanout.ack", ack_body.clone()),
        ] {
            let path = format!("/v1/core/facade/{verb}");
            for (who, credential) in [
                ("person", &fixture.person_credential),
                ("agent", &fixture.agent_credential),
            ] {
                let (status, refused) =
                    fresh_post_as_credential(&fixture, &path, body.clone(), credential).await;
                let what = format!("the owner precheck refuses {who} on {verb}");
                assert_refusal(
                    status,
                    &refused,
                    StatusCode::FORBIDDEN,
                    "FORBIDDEN",
                    &owner_message(verb),
                    &what,
                );
            }
        }
        // Row 4: resume_as with an owner-grade credential names no holder.
        let (status, refused) = fresh_post_as_owner(
            &fixture,
            "/v1/core/facade/vault.fanout.resume_as",
            resume_body.clone(),
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "vault.fanout.resume_as acts for a person or a bound agent that holds a role",
            "the holder precheck refuses resume_as on an owner-grade credential",
        );
        // Row 6: launch/slots on a slip with no principal bind no actor. The
        // host root itself acts as the owner through the host action, so only
        // a narrowed host-holder slip reaches this refusal.
        let without_principal = mint_credential(
            &fixture.vault,
            &fixture.issuer,
            &fixture.owner_slip,
            "host",
            "human",
            full_verbs(),
            0x1D,
        );
        for verb in ["vault.fanout.launch", "vault.fanout.slots"] {
            let path = format!("/v1/core/facade/{verb}");
            let body = json!({"launch_ref": unknown.clone()});
            let (status, refused) =
                fresh_post_as_credential(&fixture, &path, body, &without_principal).await;
            let what = format!("facade_actor refuses {verb} on a slip with no principal");
            assert_refusal(
                status,
                &refused,
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                PRINCIPAL_MESSAGE,
                &what,
            );
        }
        // Row 7: launch/slots as a stranger name no actor.
        let stranger_hex = EntityId::now().to_hex();
        let stranger = mint_credential(
            &fixture.vault,
            &fixture.issuer,
            &fixture.owner_slip,
            &stranger_hex,
            "human",
            full_verbs(),
            0xE5,
        );
        let stranger_message = format!("bound actor {stranger_hex} does not exist in this vault");
        for verb in ["vault.fanout.launch", "vault.fanout.slots"] {
            let path = format!("/v1/core/facade/{verb}");
            let body = json!({"launch_ref": unknown.clone()});
            let (status, refused) =
                fresh_post_as_credential(&fixture, &path, body, &stranger).await;
            let what = format!("the engine binds no stranger on {verb}");
            assert_refusal(
                status,
                &refused,
                StatusCode::FORBIDDEN,
                "FORBIDDEN",
                &stranger_message,
                &what,
            );
        }
        // Row 9: resume/ack on an unknown launch.
        for (verb, body) in [
            ("vault.fanout.resume", resume_body.clone()),
            ("vault.fanout.ack", ack_body.clone()),
        ] {
            let path = format!("/v1/core/facade/{verb}");
            let (status, refused) = fresh_post_as_owner(&fixture, &path, body).await;
            let what = format!("the engine finds no launch for {verb}");
            assert_refusal(
                status,
                &refused,
                StatusCode::NOT_FOUND,
                "NOT_FOUND",
                UNKNOWN_LAUNCH_MESSAGE,
                &what,
            );
        }
        // Row 10: a malformed digest never reaches the engine's frozen check.
        let (status, refused) = fresh_post_as_owner(
            &fixture,
            "/v1/core/facade/vault.fanout.resume",
            json!({"launch_ref": unknown.clone(), "plan_digest": "zzz", "ruling": "approve_once"}),
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            DIGEST_MESSAGE,
            "the digest check refuses a malformed plan_digest",
        );
        // Row 11: spawn bodies that do not decode.
        let valid_spec = json!({
            "intent_key": "table-valid",
            "children": children_json(&fixture.agent_def, 1),
        });
        let (status, refused) = fresh_post_as_owner(
            &fixture,
            "/v1/core/facade/vault.fanout.spawn",
            json!({"spec": valid_spec.clone()}),
        )
        .await;
        assert_decode_refusal(
            status,
            &refused,
            "live_run",
            "validate_input refuses a spawn without its live run",
        );
        // Row 12: malformed vs unknown live-run handles.
        for (handle, expected_status, expected_code, expected_message) in [
            (
                MALFORMED_HANDLE,
                StatusCode::BAD_REQUEST,
                "live_run_invalid",
                INVALID_MESSAGE,
            ),
            (
                UNKNOWN_HANDLE,
                StatusCode::FORBIDDEN,
                "live_run_unavailable",
                UNAVAILABLE_MESSAGE,
            ),
        ] {
            let body = json!({"live_run": handle, "spec": valid_spec.clone()});
            let path = "/v1/core/facade/vault.fanout.spawn";
            let (status, refused) = fresh_post_as_owner(&fixture, path, body).await;
            let what = format!("the live-run guard refuses a spawn with {handle}");
            assert_refusal(
                status,
                &refused,
                expected_status,
                expected_code,
                expected_message,
                &what,
            );
        }
        // Row 13: a session turns the spawn off-record; a ragged one is refused.
        let session = EntityId::now().to_hex();
        let seated_body = json!({"live_run": UNKNOWN_HANDLE, "spec": valid_spec.clone()});
        let binding = owner_binding(&fixture.vault, &fixture.issuer, &fixture.owner_slip);
        let token = fixture.owner_token.clone();
        let (status, refused) = post_with_session(
            &fixture.app,
            "/v1/core/facade/vault.fanout.spawn",
            &token,
            binding,
            seated_body.clone(),
            &session,
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::CONFLICT,
            "OFF_RECORD_SESSION_DOOR",
            OFF_RECORD_MESSAGE,
            "the live-run guard refuses a spawn inside a session",
        );
        let binding = owner_binding(&fixture.vault, &fixture.issuer, &fixture.owner_slip);
        let (status, refused) = post_with_session(
            &fixture.app,
            "/v1/core/facade/vault.fanout.spawn",
            &token,
            binding,
            seated_body,
            BAD_SESSION,
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            SESSION_MESSAGE,
            "the session check refuses a malformed session header",
        );
        // Row 14: a Write verb on a read-only slip, and any verb narrowed.
        let read_only = mint_credential(
            &fixture.vault,
            &fixture.issuer,
            &fixture.owner_slip,
            &fixture.person_credential.slip.claims.holder_ref.clone(),
            "human",
            BTreeSet::from(["read".to_owned()]),
            0x5C,
        );
        let (status, refused) = fresh_post_as_credential(
            &fixture,
            "/v1/core/facade/vault.fanout.spawn",
            json!({"live_run": UNKNOWN_HANDLE, "spec": valid_spec.clone()}),
            &read_only,
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            SCOPE_MESSAGE,
            "the scope guard refuses a spawn on a read-only slip",
        );
        let mut narrowed_claims = fixture.person_credential.slip.claims.clone();
        narrowed_claims.slip_id = next_slip_id();
        narrowed_claims.records = BTreeSet::from([NARROW_RECORD.to_owned()]);
        let narrowed_slip = fixture
            .vault
            .mint_capability_slip(&fixture.issuer, narrowed_claims)
            .expect("a narrowed credential");
        let narrowed_token = narrowed_slip.to_token().expect("a narrowed token");
        let narrowed = Credential {
            slip: narrowed_slip,
            key: holder_key(0x5B),
            token: narrowed_token,
        };
        let (status, refused) = fresh_post_as_credential(
            &fixture,
            "/v1/core/facade/vault.fanout.launch",
            json!({"launch_ref": unknown.clone()}),
            &narrowed,
        )
        .await;
        assert_refusal(
            status,
            &refused,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            SCOPE_MESSAGE,
            "the record-scope guard refuses a launch on a narrowed slip",
        );
    });
}
