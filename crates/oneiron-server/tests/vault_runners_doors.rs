//! The owner's runner seat doors, entered as the SDK enters them: HTTP
//! `POST /v1/core/facade/<verb>` through the in-process router (`oneshot`, no
//! TCP ports, no sleeps). The doors are `vault.runners.seats.quotas`,
//! `vault.runners.seats.top_up` and `vault.runners.seats.resume`: the named
//! seats' quotas as their captures last recorded them, the owner's word that a
//! seat's spent credit is topped up, and the owner's resume of a bound runner
//! work a spend parked.
//!
//! The promises (canon `oneiron/runtime.md:29`, `llms-full.txt:374869`):
//! "The router skips spent seats." (through the door: the resume re-search
//! names the skipped spent seat); "When all seats are spent or skipped, the
//! job parks with a typed wait naming the reset time" (through the door:
//! `quotas[].back_at` and resume `exhausted{back_at}`); "units of different
//! kinds never mix" (kind discipline only: a window spend comes back on its
//! own, a credit spend waits for the owner and only `top_up` clears it).
//! Unproven here: the park itself (engine-side, not a door answer), the live
//! automatic router hand-off during capture, cross-kind unit mixing itself,
//! and `InternalModels` routing.
//!
//! Each test owns a fresh vault. Spent quotas and parked work are seeded
//! through public engine API only (`dispatch_runner` / `bind_runner_work_in_txn`
//! + queue claim + `route_runner_terminal` with an explicit `SeatSpent`); no
//! model, runner, live run, or test door is used.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test vault_runners_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{ActSurface, CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::checkout::CheckoutId;
use oneiron::consent::AuthenticatedOwner;
use oneiron::dispatch_byoa::{
    BYOA_ATTEMPT_KIND, BindRunnerWork, ByoEndpointBackendFactory, ByoEndpointSpec, ByoaDispatcher,
    ByoaEgressLease, ByoaEgressPort, ByoaError, ByoaExhaust, ByoaResult, ByoaStream,
    ByoaTerminalDisposition, CaptureByoaExhaust, OnSeatSpent, ProviderAdapterRegistry, RunnerSeat,
    RunnerSeatChoice, RunnerSeatPolicy, RunnerWork, RunnerWorkBound, SeatAuth, SeatRoute,
    SeatSpent,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::{LlmBackend, SpentKind};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const QUOTAS_PATH: &str = "/v1/core/facade/vault.runners.seats.quotas";
const TOP_UP_PATH: &str = "/v1/core/facade/vault.runners.seats.top_up";
const RESUME_PATH: &str = "/v1/core/facade/vault.runners.seats.resume";

/// The endpoint seam the seeding path never reaches: every seeded seat is a
/// CLI runner, whose dispatch resolves no backend.
struct StubEndpoints;

impl ByoEndpointBackendFactory for StubEndpoints {
    fn resolve_backend(&self, _spec: &ByoEndpointSpec) -> ByoaResult<Arc<dyn LlmBackend>> {
        Err(ByoaError::Backend(
            "runner door tests run CLI seats only".to_owned(),
        ))
    }
}

/// The default-deny egress port: seeding mints rows, and no traffic moves.
struct DenyEgress;

impl ByoaEgressPort for DenyEgress {
    fn open(&mut self, profile_ref: &str, _intent_ref: &str) -> ByoaResult<ByoaEgressLease> {
        Err(ByoaError::EgressDenied {
            profile_ref: profile_ref.to_owned(),
            reason: "runner door tests lease no egress".to_owned(),
        })
    }
}

struct Fixture {
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    person: EntityId,
    person_slip: CapabilitySlip,
    person_token: String,
    agent_slip: CapabilitySlip,
    agent_token: String,
    _dir: tempfile::TempDir,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every member credential here binds; the holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x52; 32])
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

/// A live PERSON entity, as `graduation_demote_holder_door.rs` places one.
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

/// A credential this host mints `holder` at `class`, holding `verbs`: a
/// member's own slip, not owner-grade.
fn mint_bound_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
    holder: String,
    class: Option<&str>,
    verbs: &[&str],
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder;
    claims.actor_class = class.map(str::to_owned);
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a credential")
}

/// A host-holder slip narrowed to read and write: no principal, and, cut from
/// the root, not owner-grade.
fn mint_narrowed_host_slip(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a narrowed host slip")
}

fn owner_proof_for(vault: &Vault) -> AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("an owner proof")
}

/// An enabled agent the owner creates and gives one Grant naming `verbs`.
fn agent_with_grant(
    vault: &Vault,
    proof: &AuthenticatedOwner,
    agent_id: &str,
    verbs: &[&str],
) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Runner seat door test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled agent definition");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    let minted = mint_agent_grant_as(
        vault,
        proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the agent a Grant");
    assert!(minted.grant.confers, "{agent_id}: the Grant confers");
    agent
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-runners-doors".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let who = seed_person(&vault);
    let person_slip = mint_bound_credential(
        &owner_slip,
        &vault,
        &issuer,
        who.to_hex(),
        Some("human"),
        &["read", "write"],
    );
    let person_token = person_slip.to_token().expect("person slip token");
    let proof = owner_proof_for(&vault);
    let agent = agent_with_grant(
        &vault,
        &proof,
        "runner-door-agent",
        &[
            "read",
            "vault.runners.seats.quotas",
            "vault.runners.seats.top_up",
            "vault.runners.seats.resume",
        ],
    );
    let agent_slip = mint_bound_credential(
        &owner_slip,
        &vault,
        &issuer,
        agent.to_hex(),
        Some("agent"),
        &["read", "write"],
    );
    let agent_token = agent_slip.to_token().expect("agent slip token");
    let app = build_app(server);
    Fixture {
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
        person: who,
        person_slip,
        person_token,
        agent_slip,
        agent_token,
        _dir: dir,
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

/// A member credential's holder proof under the member key.
fn member_binding(fixture: &Fixture, slip: &CapabilitySlip) -> String {
    holder_proof(slip, &holder_key(), fixture.vault.now_recorded_at())
        .expect("holder proof")
        .to_string()
}

/// A host-holder slip's proof through the host secret.
fn host_binding(fixture: &Fixture, slip: &CapabilitySlip) -> String {
    let timestamp = fixture.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = hex(&fixture
        .issuer
        .binding_proof(slip, challenge.as_bytes())
        .expect("host holder proof"));
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

async fn post(
    fixture: &Fixture,
    path: &str,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("facade request");
    let response = fixture
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("facade response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("facade response body");
    let body: Value = serde_json::from_slice(&bytes).expect("facade response JSON");
    (status, body)
}

async fn post_as_owner(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.owner_token.clone();
    post(fixture, path, &token, owner_binding(fixture), body).await
}

async fn post_as_person(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.person_token.clone();
    post(
        fixture,
        path,
        &token,
        member_binding(fixture, &fixture.person_slip),
        body,
    )
    .await
}

async fn post_as_agent(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.agent_token.clone();
    post(
        fixture,
        path,
        &token,
        member_binding(fixture, &fixture.agent_slip),
        body,
    )
    .await
}

async fn post_bearer(
    fixture: &Fixture,
    path: &str,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    post(fixture, path, token, binding, body).await
}

async fn post_without_credential(
    fixture: &Fixture,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("facade request");
    let response = fixture
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("facade response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("facade response body");
    let body: Value = serde_json::from_slice(&bytes).expect("facade response JSON");
    (status, body)
}

async fn post_in_room_turn(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header("authorization", format!("Bearer {}", fixture.owner_token))
        .header("x-oneiron-binding", owner_binding(fixture))
        .header("x-oneiron-room-turn", EntityId::now().to_hex())
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("facade request");
    let response = fixture
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("facade response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("facade response body");
    let body: Value = serde_json::from_slice(&bytes).expect("facade response JSON");
    (status, body)
}

/// A vendor-login seat on the standard registry's runner.
fn login_seat(runner: &str) -> RunnerSeat {
    RunnerSeat {
        runner: runner.to_owned(),
        auth: SeatAuth::VendorLogin,
        egress_profile_ref: "egress/runner-door-test".to_owned(),
        credential_handles: Vec::new(),
    }
}

/// Two login seats under a Stop policy: a spend parks the work.
fn seat_policy() -> RunnerSeatPolicy {
    RunnerSeatPolicy {
        seats: vec![login_seat("claude-code"), login_seat("codex")],
        on_spent: OnSeatSpent::Stop,
    }
}

fn seat_json(runner: &str) -> Value {
    json!({
        "runner": runner,
        "auth": "vendor_login",
        "egress_profile_ref": "egress/runner-door-test",
    })
}

fn policy_json() -> Value {
    json!({"seats": [seat_json("claude-code"), seat_json("codex")]})
}

/// A non-empty terminal exhaust: an entirely empty one is refused at capture.
fn seed_exhaust() -> ByoaExhaust {
    let mut writer = ByoaStream::writer(None, None);
    writer
        .append(b"runner door test output")
        .expect("exhaust bytes");
    let stdout = writer.finish().expect("exhaust stream");
    ByoaExhaust {
        stdout,
        ..Default::default()
    }
}

/// Claims the oldest queued BYOA attempt: each seed dispatches exactly one
/// before it claims, so the claim takes that attempt.
fn claim_runner_attempt(vault: &Vault, now: u64) -> AttemptRecord {
    let outcome = AttemptQueue::new(vault)
        .claim_kind(
            BYOA_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: "runner-door-test".to_owned(),
                now,
            },
        )
        .expect("the queued runner attempt claims");
    match outcome {
        ClaimOutcome::Claimed(record) => record,
        _ => panic!("a runner attempt is queued to claim"),
    }
}

/// Spends `seat`'s quota without binding a work: dispatch, claim, then route
/// the terminal exhaust with the explicit spend. Answers the spent attempt.
fn spend_unbound_seat(
    vault: &Vault,
    registry: &ProviderAdapterRegistry,
    policy: &RunnerSeatPolicy,
    seat: usize,
    spent: SeatSpent,
    now: u64,
) -> AttemptId {
    let mut dispatcher = ByoaDispatcher::new(vault, StubEndpoints, DenyEgress);
    let checkout = CheckoutId::from_bytes([7_u8; 16]).expect("checkout id");
    let outcome = dispatcher
        .dispatch_runner(
            registry,
            policy,
            seat,
            RunnerWork {
                task: "runner door quota probe".to_owned(),
                checkout_id: checkout,
                task_ref: None,
                parent_attempt_id: None,
                run_id: None,
                dedupe_key: None,
                now,
            },
        )
        .expect("the runner dispatches");
    let attempt = outcome.status().attempt.id;
    let claimed = claim_runner_attempt(vault, now);
    assert_eq!(
        claimed.id, attempt,
        "the claim takes the dispatched attempt"
    );
    let capture = CaptureByoaExhaust {
        attempt_id: attempt,
        lease_owner: "runner-door-test".to_owned(),
        attempt_count: claimed.attempt_count,
        disposition: ByoaTerminalDisposition::Completed,
        exhaust: seed_exhaust(),
        reason: None,
        now,
    };
    let route = dispatcher
        .route_runner_terminal(registry, policy, seat, capture, Some(spent))
        .expect("the spent route lands");
    match route {
        SeatRoute::Park { .. } => {}
        _ => panic!("a Stop policy parks the spent work"),
    }
    attempt
}

/// Binds a fresh work on `seat` and parks it on the explicit spend. Answers
/// the binding hex and the spent attempt hex.
fn bind_parked_work(
    vault: &Vault,
    registry: &ProviderAdapterRegistry,
    policy: &RunnerSeatPolicy,
    seat: usize,
    step_key: &str,
    spent: SeatSpent,
    now: u64,
) -> (String, String) {
    let dispatcher = ByoaDispatcher::new(vault, StubEndpoints, DenyEgress);
    let checkout = CheckoutId::from_bytes([7_u8; 16]).expect("checkout id");
    let bound = vault
        .try_with_write_txn_grouped(|wtxn| {
            dispatcher.bind_runner_work_in_txn(
                wtxn,
                registry,
                policy,
                BindRunnerWork {
                    parent_attempt_id: AttemptId::now(),
                    step_key: step_key.to_owned(),
                    task: "runner door test task".to_owned(),
                    staged_input: None,
                    checkout_id: checkout,
                    task_ref: None,
                    run_id: None,
                    choice: RunnerSeatChoice::Seat(seat),
                    now,
                },
            )
        })
        .expect("the bind lands");
    let (binding, attempt) = match bound {
        RunnerWorkBound::Bound {
            binding,
            attempt,
            existing,
            ..
        } => {
            assert!(!existing, "a fresh step binds new");
            (binding, attempt)
        }
        _ => panic!("a fresh step binds on its seat"),
    };
    let claimed = claim_runner_attempt(vault, now);
    assert_eq!(claimed.id, attempt, "the claim takes the bound attempt");
    let mut router = ByoaDispatcher::new(vault, StubEndpoints, DenyEgress);
    let capture = CaptureByoaExhaust {
        attempt_id: attempt,
        lease_owner: "runner-door-test".to_owned(),
        attempt_count: claimed.attempt_count,
        disposition: ByoaTerminalDisposition::Completed,
        exhaust: seed_exhaust(),
        reason: None,
        now,
    };
    let route = router
        .route_runner_terminal(registry, policy, seat, capture, Some(spent))
        .expect("the spent route lands");
    match route {
        SeatRoute::Park { .. } => {}
        _ => panic!("a Stop policy parks the spent work"),
    }
    (binding.to_hex(), hex(attempt.as_bytes()))
}

/// Binds a fresh work on `seat` whose head attempt completes with no spend.
/// Answers the binding hex and the settled attempt hex.
fn bind_settled_work(
    vault: &Vault,
    registry: &ProviderAdapterRegistry,
    policy: &RunnerSeatPolicy,
    seat: usize,
    step_key: &str,
    now: u64,
) -> (String, String) {
    let dispatcher = ByoaDispatcher::new(vault, StubEndpoints, DenyEgress);
    let checkout = CheckoutId::from_bytes([7_u8; 16]).expect("checkout id");
    let bound = vault
        .try_with_write_txn_grouped(|wtxn| {
            dispatcher.bind_runner_work_in_txn(
                wtxn,
                registry,
                policy,
                BindRunnerWork {
                    parent_attempt_id: AttemptId::now(),
                    step_key: step_key.to_owned(),
                    task: "runner door test task".to_owned(),
                    staged_input: None,
                    checkout_id: checkout,
                    task_ref: None,
                    run_id: None,
                    choice: RunnerSeatChoice::Seat(seat),
                    now,
                },
            )
        })
        .expect("the bind lands");
    let (binding, attempt) = match bound {
        RunnerWorkBound::Bound {
            binding,
            attempt,
            existing,
            ..
        } => {
            assert!(!existing, "a fresh step binds new");
            (binding, attempt)
        }
        _ => panic!("a fresh step binds on its seat"),
    };
    let claimed = claim_runner_attempt(vault, now);
    assert_eq!(claimed.id, attempt, "the claim takes the bound attempt");
    let mut router = ByoaDispatcher::new(vault, StubEndpoints, DenyEgress);
    let capture = CaptureByoaExhaust {
        attempt_id: attempt,
        lease_owner: "runner-door-test".to_owned(),
        attempt_count: claimed.attempt_count,
        disposition: ByoaTerminalDisposition::Completed,
        exhaust: seed_exhaust(),
        reason: None,
        now,
    };
    let route = router
        .route_runner_terminal(registry, policy, seat, capture, None)
        .expect("the unspent route lands");
    match route {
        SeatRoute::Settled(_) => {}
        _ => panic!("an unspent capture settles"),
    }
    (binding.to_hex(), hex(attempt.as_bytes()))
}
/// A spent seat reads spent with its reset time, per seat: an empty read
/// answers no quotas, an unknown runner reads available, and the spent seat
/// names its kind, its reset, its reading time and its capture.
///
/// Canon `oneiron/runtime.md:29` (`llms-full.txt:374869`) "The router skips
/// spent seats." (the router's inputs) and "the job parks with a typed wait
/// naming the reset time" (the reset naming).
#[test]
fn quotas_reports_spent_and_back_at_per_seat() {
    run_on_engine_stack("runners-quotas", || async {
        let fixture = setup().await;
        let registry = ProviderAdapterRegistry::standard();
        let policy = seat_policy();

        let (status, empty) = post_as_owner(&fixture, QUOTAS_PATH, json!({"seats": []})).await;
        assert_eq!(status, StatusCode::OK, "owner reads no seats: {empty}");
        assert_eq!(
            empty["quotas"],
            json!([]),
            "no seats read no quotas: {empty}"
        );

        let (status, fresh) = post_as_owner(
            &fixture,
            QUOTAS_PATH,
            json!({"seats": [seat_json("nope-runner")]}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads an unknown runner: {fresh}"
        );
        assert_eq!(
            fresh["quotas"][0]["available"].as_bool(),
            Some(true),
            "a seat no capture recorded is available: {fresh}"
        );
        assert!(
            fresh["quotas"][0]["spent"].is_null(),
            "no spend read: {fresh}"
        );
        assert!(
            fresh["quotas"][0]["back_at"].is_null(),
            "no reset named: {fresh}"
        );

        let now = now_secs();
        let reset = now + 3600;
        let spent = SeatSpent {
            kind: Some(SpentKind::Window),
            retry_after: None,
            resets_at: vec![reset],
        };
        let attempt = spend_unbound_seat(&fixture.vault, &registry, &policy, 0, spent, now);
        let spent_hex = hex(attempt.as_bytes());

        let (status, quotas) = post_as_owner(
            &fixture,
            QUOTAS_PATH,
            json!({"seats": [seat_json("claude-code"), seat_json("codex")]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads both quotas: {quotas}");
        assert_eq!(
            quotas["quotas"].as_array().expect("quotas list").len(),
            2,
            "one quota per seat: {quotas}"
        );
        assert_eq!(
            quotas["quotas"][0]["seat"].as_u64(),
            Some(0),
            "the first quota is seat 0: {quotas}"
        );
        assert_eq!(
            quotas["quotas"][0]["runner"].as_str(),
            Some("claude-code"),
            "the first quota names its runner: {quotas}"
        );
        assert_eq!(
            quotas["quotas"][0]["available"].as_bool(),
            Some(false),
            "the spent seat is not available: {quotas}"
        );
        assert_eq!(
            quotas["quotas"][0]["spent"]["kind"].as_str(),
            Some("window"),
            "the spend names its kind: {quotas}"
        );
        assert_eq!(
            quotas["quotas"][0]["back_at"].as_u64(),
            Some(reset),
            "the spend names its reset: {quotas}"
        );
        assert_eq!(
            quotas["quotas"][0]["last_capture"].as_str(),
            Some(spent_hex.as_str()),
            "the quota names its capture: {quotas}"
        );
        let observed = quotas["quotas"][0]["observed_at"]
            .as_u64()
            .expect("reading time");
        assert!(
            observed >= now && observed <= now + 60,
            "the quota names its reading time: {quotas}"
        );
        assert_eq!(
            quotas["quotas"][1]["seat"].as_u64(),
            Some(1),
            "the second quota is seat 1: {quotas}"
        );
        assert_eq!(
            quotas["quotas"][1]["available"].as_bool(),
            Some(true),
            "the unspent seat is available: {quotas}"
        );
        assert!(
            quotas["quotas"][1]["spent"].is_null(),
            "no spend read: {quotas}"
        );
        assert!(
            quotas["quotas"][1]["back_at"].is_null(),
            "no reset named: {quotas}"
        );
    });
}

/// A credit spend waits for the owner: its quota names no reset until the
/// owner tops it up, the top-up clears it, and a second top-up is already
/// clear.
///
/// Canon `oneiron/runtime.md:29` (`llms-full.txt:374869`) "the job parks with
/// a typed wait naming the reset time" (a credit names no reset) and "units
/// of different kinds never mix" (only a credit clears by top-up).
#[test]
fn spent_credit_waits_for_owner_until_top_up() {
    run_on_engine_stack("runners-credit-top-up", || async {
        let fixture = setup().await;
        let registry = ProviderAdapterRegistry::standard();
        let policy = seat_policy();
        let now = now_secs();
        let spent = SeatSpent {
            kind: Some(SpentKind::Credit),
            retry_after: None,
            resets_at: Vec::new(),
        };
        let attempt = spend_unbound_seat(&fixture.vault, &registry, &policy, 0, spent, now);
        let spent_hex = hex(attempt.as_bytes());

        let (status, quotas) = post_as_owner(
            &fixture,
            QUOTAS_PATH,
            json!({"seats": [seat_json("claude-code")]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads the quota: {quotas}");
        assert_eq!(
            quotas["quotas"][0]["available"].as_bool(),
            Some(false),
            "the credit-spent seat is not available: {quotas}"
        );
        assert_eq!(
            quotas["quotas"][0]["spent"]["kind"].as_str(),
            Some("credit"),
            "the spend names its kind: {quotas}"
        );
        assert!(
            quotas["quotas"][0]["back_at"].is_null(),
            "a credit spend names no reset: it waits for the owner: {quotas}"
        );

        let top_up = json!({
            "seat": seat_json("claude-code"),
            "expected_spent_attempt": spent_hex.clone(),
        });
        let (status, cleared) = post_as_owner(&fixture, TOP_UP_PATH, top_up).await;
        assert_eq!(status, StatusCode::OK, "owner tops up the seat: {cleared}");
        assert_eq!(
            cleared["effect"].as_str(),
            Some("cleared"),
            "the top-up clears the credit spend: {cleared}"
        );
        assert_eq!(
            cleared["quota"]["available"].as_bool(),
            Some(true),
            "the seat is available again: {cleared}"
        );
        assert!(
            cleared["quota"]["spent"].is_null(),
            "no spend left: {cleared}"
        );
        assert_eq!(
            cleared["quota"]["last_capture"].as_str(),
            Some(spent_hex.as_str()),
            "the clearing keeps its capture: {cleared}"
        );
        let topped_up = cleared["quota"]["topped_up_at"]
            .as_u64()
            .expect("top-up time");
        assert!(topped_up >= now, "the top-up names its time: {cleared}");

        let (status, quotas) = post_as_owner(
            &fixture,
            QUOTAS_PATH,
            json!({"seats": [seat_json("claude-code")]}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the quota back: {quotas}"
        );
        assert_eq!(
            quotas["quotas"][0]["available"].as_bool(),
            Some(true),
            "the seat stays available: {quotas}"
        );

        let (status, again) = post_as_owner(
            &fixture,
            TOP_UP_PATH,
            json!({
                "seat": seat_json("claude-code"),
                "expected_spent_attempt": spent_hex,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner tops up again: {again}");
        assert_eq!(
            again["effect"].as_str(),
            Some("already_clear"),
            "a second top-up changes nothing: {again}"
        );
    });
}

/// A top-up of a non-credit spend, or of a capture that is no longer the
/// last reading, answers so and writes nothing: the quota reads identical
/// before and after.
///
/// Canon `oneiron/runtime.md:29` (`llms-full.txt:374869`) "units of different
/// kinds never mix" (a window spend comes back on its own; only a credit
/// clears by top-up).
#[test]
fn top_up_answers_stale_and_non_credit_without_writes() {
    run_on_engine_stack("runners-top-up-stale", || async {
        let fixture = setup().await;
        let registry = ProviderAdapterRegistry::standard();
        let policy = seat_policy();
        let now = now_secs();
        let reset = now + 3600;
        let spent = SeatSpent {
            kind: Some(SpentKind::Window),
            retry_after: None,
            resets_at: vec![reset],
        };
        let attempt = spend_unbound_seat(&fixture.vault, &registry, &policy, 0, spent, now);
        let spent_hex = hex(attempt.as_bytes());
        let seats = json!({"seats": [seat_json("claude-code")]});

        let (status, quotas) = post_as_owner(&fixture, QUOTAS_PATH, seats.clone()).await;
        assert_eq!(status, StatusCode::OK, "owner reads the quota: {quotas}");
        let before = quotas["quotas"][0].clone();
        assert_eq!(
            before["spent"]["kind"].as_str(),
            Some("window"),
            "the spend is a window spend: {quotas}"
        );

        let (status, kept) = post_as_owner(
            &fixture,
            TOP_UP_PATH,
            json!({
                "seat": seat_json("claude-code"),
                "expected_spent_attempt": spent_hex,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner tops up a window spend: {kept}"
        );
        assert_eq!(
            kept["effect"].as_str(),
            Some("not_credit"),
            "a window spend is not the owner's to clear: {kept}"
        );
        let (status, quotas) = post_as_owner(&fixture, QUOTAS_PATH, seats.clone()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the quota back: {quotas}"
        );
        assert_eq!(
            quotas["quotas"][0], before,
            "the refusal writes nothing: {quotas}"
        );

        let (status, stale) = post_as_owner(
            &fixture,
            TOP_UP_PATH,
            json!({
                "seat": seat_json("claude-code"),
                "expected_spent_attempt": EntityId::now().to_hex(),
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner tops up a stale capture: {stale}"
        );
        assert_eq!(
            stale["effect"].as_str(),
            Some("observation_changed"),
            "a capture that is no longer last changes nothing: {stale}"
        );
        let (status, quotas) = post_as_owner(&fixture, QUOTAS_PATH, seats).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the quota back: {quotas}"
        );
        assert_eq!(
            quotas["quotas"][0], before,
            "the refusal writes nothing: {quotas}"
        );
    });
}

/// A parked work resumes on the next seat, naming the spent seat it skipped:
/// the skip of P1 through the door.
///
/// Canon `oneiron/runtime.md:29` (`llms-full.txt:374869`) "The router skips
/// spent seats." The reason carries the reset time, so the test asserts its
/// prefix only.
#[test]
fn resume_moves_parked_work_to_next_seat_naming_skips() {
    run_on_engine_stack("runners-resume-next", || async {
        let fixture = setup().await;
        let registry = ProviderAdapterRegistry::standard();
        let policy = seat_policy();
        let now = now_secs();
        let spent = SeatSpent {
            kind: Some(SpentKind::Window),
            retry_after: Some(1800),
            resets_at: Vec::new(),
        };
        let (binding_hex, spent_hex) = bind_parked_work(
            &fixture.vault,
            &registry,
            &policy,
            0,
            "resume-next",
            spent,
            now,
        );

        let (status, quotas) = post_as_owner(
            &fixture,
            QUOTAS_PATH,
            json!({"seats": [seat_json("claude-code"), seat_json("codex")]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads the quotas: {quotas}");
        assert_eq!(
            quotas["quotas"][0]["available"].as_bool(),
            Some(false),
            "the spent seat is not available: {quotas}"
        );

        let (status, resumed) = post_as_owner(
            &fixture,
            RESUME_PATH,
            json!({
                "binding": binding_hex,
                "expected_attempt": spent_hex.clone(),
                "policy": policy_json(),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner resumes the work: {resumed}");
        assert_eq!(
            resumed["resumed"]["seat"].as_u64(),
            Some(1),
            "the work moves to the next seat: {resumed}"
        );
        let next = resumed["resumed"]["attempt"]
            .as_str()
            .expect("successor attempt");
        assert_eq!(
            next.len(),
            32,
            "the successor is a fresh attempt id: {resumed}"
        );
        assert_ne!(
            next,
            spent_hex.as_str(),
            "the successor is not the spent attempt: {resumed}"
        );
        assert_eq!(
            resumed["resumed"]["existing"].as_bool(),
            Some(false),
            "the successor is newly dispatched: {resumed}"
        );
        let skipped = resumed["resumed"]["skipped"]
            .as_array()
            .expect("skipped seats");
        assert_eq!(skipped.len(), 1, "one seat is skipped: {resumed}");
        assert_eq!(
            skipped[0]["seat"].as_u64(),
            Some(0),
            "seat 0 is skipped: {resumed}"
        );
        assert_eq!(
            skipped[0]["runner"].as_str(),
            Some("claude-code"),
            "the skip names its runner: {resumed}"
        );
        let reason = skipped[0]["reason"].as_str().unwrap_or_default();
        assert!(
            reason.starts_with("its quota is spent until "),
            "the skip names the spent quota: {resumed}"
        );
    });
}

/// When every seat is spent, the resume names the earliest reset: the typed
/// wait of P2 through the door, with every seat named.
///
/// Canon `oneiron/runtime.md:29` (`llms-full.txt:374869`) "When all seats are
/// spent or skipped, the job parks with a typed wait naming the reset time".
/// The test asserts the reset and the seat indices only, never the reason
/// strings.
#[test]
fn resume_exhausted_names_earliest_reset() {
    run_on_engine_stack("runners-resume-exhausted", || async {
        let fixture = setup().await;
        let registry = ProviderAdapterRegistry::standard();
        let policy = seat_policy();
        let now = now_secs();
        let first = now + 100_000;
        let later = now + 200_000;
        let first_spent = SeatSpent {
            kind: Some(SpentKind::Window),
            retry_after: None,
            resets_at: vec![first],
        };
        let (binding_hex, _) = bind_parked_work(
            &fixture.vault,
            &registry,
            &policy,
            0,
            "resume-exhausted-a",
            first_spent,
            now,
        );
        let later_spent = SeatSpent {
            kind: Some(SpentKind::Window),
            retry_after: None,
            resets_at: vec![later],
        };
        bind_parked_work(
            &fixture.vault,
            &registry,
            &policy,
            1,
            "resume-exhausted-b",
            later_spent,
            now,
        );

        let (status, quotas) = post_as_owner(
            &fixture,
            QUOTAS_PATH,
            json!({"seats": [seat_json("claude-code"), seat_json("codex")]}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads the quotas: {quotas}");
        assert_eq!(
            quotas["quotas"][0]["back_at"].as_u64(),
            Some(first),
            "seat 0 names its reset: {quotas}"
        );
        assert_eq!(
            quotas["quotas"][1]["back_at"].as_u64(),
            Some(later),
            "seat 1 names its reset: {quotas}"
        );

        let resume = json!({
            "binding": binding_hex,
            "expected_attempt": quotas["quotas"][0]["last_capture"].clone(),
            "policy": policy_json(),
        });
        let (status, exhausted) = post_as_owner(&fixture, RESUME_PATH, resume).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner resumes the parked work: {exhausted}"
        );
        assert_eq!(
            exhausted["exhausted"]["back_at"].as_u64(),
            Some(first),
            "the wait names the earliest reset: {exhausted}"
        );
        let skipped = exhausted["exhausted"]["skipped"]
            .as_array()
            .expect("skipped seats");
        assert_eq!(skipped.len(), 2, "both seats are named: {exhausted}");
        assert_eq!(
            skipped[0]["seat"].as_u64(),
            Some(0),
            "seat 0 is named: {exhausted}"
        );
        assert_eq!(
            skipped[1]["seat"].as_u64(),
            Some(1),
            "seat 1 is named: {exhausted}"
        );
    });
}

/// A resume answers where the work stands and writes nothing there: gone for
/// a work never bound, unchanged for an attempt that ended without a spend,
/// current for a work that moved past the named attempt. Each answer repeats
/// byte-identical.
///
/// Canon `oneiron/runtime.md:29` (`llms-full.txt:374869`) "The router skips
/// spent seats." (the resume re-search answers; every arm but `resumed` wrote
/// nothing).
#[test]
fn resume_answers_current_unchanged_and_gone_without_writes() {
    run_on_engine_stack("runners-resume-stands", || async {
        let fixture = setup().await;
        let registry = ProviderAdapterRegistry::standard();
        let policy = seat_policy();
        let now = now_secs();
        let (settled_binding, settled_hex) =
            bind_settled_work(&fixture.vault, &registry, &policy, 0, "resume-settled", now);
        let parked = SeatSpent {
            kind: Some(SpentKind::Window),
            retry_after: Some(1800),
            resets_at: Vec::new(),
        };
        let (moved_binding, spent_hex) = bind_parked_work(
            &fixture.vault,
            &registry,
            &policy,
            0,
            "resume-moved",
            parked,
            now,
        );
        let (status, moved) = post_as_owner(
            &fixture,
            RESUME_PATH,
            json!({
                "binding": moved_binding.clone(),
                "expected_attempt": spent_hex.clone(),
                "policy": policy_json(),
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner resumes the parked work: {moved}"
        );
        assert_eq!(
            moved["resumed"]["seat"].as_u64(),
            Some(1),
            "the work moves to the next seat: {moved}"
        );
        let successor = moved["resumed"]["attempt"]
            .as_str()
            .expect("successor attempt");

        let gone_body = json!({
            "binding": EntityId::now().to_hex(),
            "expected_attempt": spent_hex.clone(),
            "policy": policy_json(),
        });
        let (status, gone) = post_as_owner(&fixture, RESUME_PATH, gone_body.clone()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an unbound work answers gone: {gone}"
        );
        assert_eq!(gone, json!("gone"), "nothing holds the work: {gone}");
        let (status, gone_again) = post_as_owner(&fixture, RESUME_PATH, gone_body).await;
        assert_eq!(status, StatusCode::OK, "gone repeats: {gone_again}");
        assert_eq!(gone_again, gone, "gone writes nothing: {gone_again}");

        let unchanged_body = json!({
            "binding": settled_binding,
            "expected_attempt": settled_hex.clone(),
            "policy": policy_json(),
        });
        let (status, unchanged) =
            post_as_owner(&fixture, RESUME_PATH, unchanged_body.clone()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a spend-free end answers unchanged: {unchanged}"
        );
        assert_eq!(
            unchanged["unchanged"]["seat"].as_u64(),
            Some(0),
            "the work stands on its seat: {unchanged}"
        );
        assert_eq!(
            unchanged["unchanged"]["attempt"].as_str(),
            Some(settled_hex.as_str()),
            "the work stands at its attempt: {unchanged}"
        );
        let (status, unchanged_again) = post_as_owner(&fixture, RESUME_PATH, unchanged_body).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "unchanged repeats: {unchanged_again}"
        );
        assert_eq!(
            unchanged_again, unchanged,
            "unchanged writes nothing: {unchanged_again}"
        );

        let current_body = json!({
            "binding": moved_binding,
            "expected_attempt": spent_hex,
            "policy": policy_json(),
        });
        let (status, current) = post_as_owner(&fixture, RESUME_PATH, current_body.clone()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a moved work answers current: {current}"
        );
        assert_eq!(
            current["current"]["seat"].as_u64(),
            Some(1),
            "the work stands on the next seat: {current}"
        );
        assert_eq!(
            current["current"]["attempt"].as_str(),
            Some(successor),
            "the work stands at the successor: {current}"
        );
        let (status, current_again) = post_as_owner(&fixture, RESUME_PATH, current_body).await;
        assert_eq!(status, StatusCode::OK, "current repeats: {current_again}");
        assert_eq!(
            current_again, current,
            "current writes nothing: {current_again}"
        );
    });
}
/// The three doors refuse every non-owner caller class and demand their
/// scope: one table test over quotas, top_up and resume, each with a body
/// that decodes (these rows refuse after the body decodes). `actor_class:
/// "host"` has no served row: `SlipClaims::validate` refuses the class at
/// mint, so its 401 is unreachable and the test asserts the mint refusal.
///
/// Canon `oneiron/runtime.md:29` (`llms-full.txt:374869`) "The router skips
/// spent seats." (owner-only admission for this family, as for the host
/// triggers).
#[test]
fn runners_doors_refuse_non_owner_and_require_scope() {
    run_on_engine_stack("runners-refusals", || async {
        let fixture = setup().await;
        assert_eq!(
            fixture.person_slip.claims.holder_ref,
            fixture.person.to_hex(),
            "the person's credential binds the person"
        );
        let narrowed =
            mint_narrowed_host_slip(&fixture.owner_slip, &fixture.vault, &fixture.issuer);
        let narrowed_token = narrowed.to_token().expect("narrowed slip token");
        let read_only = mint_bound_credential(
            &fixture.owner_slip,
            &fixture.vault,
            &fixture.issuer,
            fixture.person.to_hex(),
            Some("human"),
            &["read"],
        );
        let read_only_token = read_only.to_token().expect("read-only slip token");
        let mut host_class_claims = fixture.owner_slip.claims.clone();
        host_class_claims.slip_id = next_slip_id();
        host_class_claims.parent_id = None;
        host_class_claims.holder_ref = fixture.person.to_hex();
        host_class_claims.actor_class = Some("host".to_owned());
        host_class_claims.binding_key = holder_key().verifying_key().to_bytes();
        host_class_claims.scope.verbs =
            ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        assert!(
            fixture
                .vault
                .mint_capability_slip(&fixture.issuer, host_class_claims)
                .is_err(),
            "the mint refuses actor_class host: a served host-class 401 is unreachable"
        );

        let attempt_hex = EntityId::now().to_hex();
        let binding_hex = EntityId::now().to_hex();
        let rows: Vec<(&str, &str, Value)> = vec![
            (
                "vault.runners.seats.quotas",
                QUOTAS_PATH,
                json!({"seats": []}),
            ),
            (
                "vault.runners.seats.top_up",
                TOP_UP_PATH,
                json!({
                    "seat": seat_json("claude-code"),
                    "expected_spent_attempt": attempt_hex.clone(),
                }),
            ),
            (
                "vault.runners.seats.resume",
                RESUME_PATH,
                json!({
                    "binding": binding_hex,
                    "expected_attempt": attempt_hex,
                    "policy": policy_json(),
                }),
            ),
        ];
        for (verb, path, input) in rows {
            let (status, denied) = post_without_credential(&fixture, path, input.clone()).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{verb} needs a credential: {denied}"
            );
            assert_eq!(
                denied["error"]["code"].as_str(),
                Some("UNAUTHORIZED"),
                "the refusal names its code: {denied}"
            );
            assert_eq!(
                denied["error"]["message"].as_str(),
                Some("request is not authorized"),
                "the extractor refuses before any door: {denied}"
            );

            // No served actor_class-host row: the mint above refuses the class, so no
            // host-class credential exists to serve a 401 to.
            let (status, denied) = post_in_room_turn(&fixture, path, input.clone()).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{verb} is not served inside a room turn: {denied}"
            );
            assert_eq!(
                denied["error"]["code"].as_str(),
                Some("BAD_REQUEST"),
                "the refusal names its code: {denied}"
            );
            assert_eq!(
                denied["error"]["message"].as_str(),
                Some(format!("{verb} is not served inside a room turn")).as_deref(),
                "the room-turn guard refuses before decode: {denied}"
            );

            let (status, denied) = post_as_person(&fixture, path, input.clone()).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{verb} refuses a person: {denied}"
            );
            assert_eq!(
                denied["error"]["code"].as_str(),
                Some("FORBIDDEN"),
                "the refusal names its code: {denied}"
            );
            assert_eq!(
                denied["error"]["message"].as_str(),
                Some(format!("{verb} is the vault owner's")).as_deref(),
                "the owner proof refuses a person: {denied}"
            );

            let (status, denied) = post_as_agent(&fixture, path, input.clone()).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{verb} refuses an agent with a Grant: {denied}"
            );
            assert_eq!(
                denied["error"]["code"].as_str(),
                Some("FORBIDDEN"),
                "the refusal names its code: {denied}"
            );
            assert_eq!(
                denied["error"]["message"].as_str(),
                Some(format!("{verb} is the vault owner's")).as_deref(),
                "no Grant is consulted on the owner proof: {denied}"
            );

            let (status, denied) = post_bearer(
                &fixture,
                path,
                &narrowed_token,
                host_binding(&fixture, &narrowed),
                input.clone(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{verb} refuses a narrowed host slip: {denied}"
            );
            assert_eq!(
                denied["error"]["code"].as_str(),
                Some("FORBIDDEN"),
                "the refusal names its code: {denied}"
            );
            assert_eq!(
                denied["error"]["message"].as_str(),
                Some(format!("{verb} is the vault owner's")).as_deref(),
                "a narrowed host slip is no owner proof: {denied}"
            );

            let (status, denied) = post_bearer(
                &fixture,
                path,
                &read_only_token,
                member_binding(&fixture, &read_only),
                input,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{verb} refuses a read-only slip: {denied}"
            );
            assert_eq!(
                denied["error"]["code"].as_str(),
                Some("FORBIDDEN"),
                "the refusal names its code: {denied}"
            );
            if verb == "vault.runners.seats.quotas" {
                assert_eq!(
                    denied["error"]["message"].as_str(),
                    Some(format!("{verb} is the vault owner's")).as_deref(),
                    "read passes the Read guard and dies at the owner proof: {denied}"
                );
            } else {
                assert_eq!(
                    denied["error"]["message"].as_str(),
                    Some("request does not have the required scope"),
                    "the scope guard refuses before decode: {denied}"
                );
            }
        }
    });
}

/// The three doors reject malformed bodies at decode and invalid ids and
/// seat orders at validation: every row below is a 400.
///
/// Canon `oneiron/runtime.md:29` (`llms-full.txt:374869`) "The router skips
/// spent seats." (the doors' input contract).
#[test]
fn runners_doors_reject_malformed_and_invalid_ids() {
    run_on_engine_stack("runners-malformed", || async {
        let fixture = setup().await;
        let attempt_hex = EntityId::now().to_hex();
        let binding_hex = EntityId::now().to_hex();

        for (verb, path) in [
            ("vault.runners.seats.quotas", QUOTAS_PATH),
            ("vault.runners.seats.top_up", TOP_UP_PATH),
            ("vault.runners.seats.resume", RESUME_PATH),
        ] {
            let (status, denied) = post_as_owner(&fixture, path, json!({})).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{verb} rejects an empty body: {denied}"
            );
            assert_eq!(
                denied["error"]["code"].as_str(),
                Some("BAD_REQUEST"),
                "the refusal names its code: {denied}"
            );
            let message = denied["error"]["message"].as_str().unwrap_or_default();
            assert!(
                message.starts_with("invalid SDK request: "),
                "the typed decode refuses first: {denied}"
            );
        }

        let (status, denied) =
            post_as_owner(&fixture, QUOTAS_PATH, json!({"seats": [], "bogus": 1})).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "quotas rejects an unknown field: {denied}"
        );
        assert_eq!(
            denied["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {denied}"
        );
        let message = denied["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.starts_with("invalid SDK request: "),
            "the typed decode refuses: {denied}"
        );

        let (status, denied) = post_as_owner(
            &fixture,
            RESUME_PATH,
            json!({
                "binding": binding_hex.clone(),
                "expected_attempt": attempt_hex.clone(),
                "policy": policy_json(),
                "bogus": 1,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "resume rejects an unknown field: {denied}"
        );
        let message = denied["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.starts_with("invalid SDK request: "),
            "the typed decode refuses: {denied}"
        );

        let (status, denied) = post_as_owner(
            &fixture,
            TOP_UP_PATH,
            json!({
                "seat": seat_json("claude-code"),
                "expected_spent_attempt": attempt_hex.clone(),
                "bogus": 1,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "top_up rejects an unknown field: {denied}"
        );
        let message = denied["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.starts_with("invalid SDK request: "),
            "the typed decode refuses: {denied}"
        );

        let (status, denied) = post_as_owner(
            &fixture,
            QUOTAS_PATH,
            json!({"seats": [{
                "runner": "claude-code",
                "auth": "oauth",
                "egress_profile_ref": "egress/runner-door-test",
            }]}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "quotas rejects auth oauth: {denied}"
        );
        let message = denied["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.starts_with("invalid SDK request: "),
            "the typed decode refuses: {denied}"
        );

        let (status, denied) = post_as_owner(
            &fixture,
            RESUME_PATH,
            json!({
                "binding": binding_hex.clone(),
                "expected_attempt": attempt_hex.clone(),
                "choice": 3,
                "policy": policy_json(),
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "resume rejects choice 3: {denied}"
        );
        let message = denied["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.starts_with("invalid SDK request: "),
            "the typed decode refuses: {denied}"
        );

        let (status, denied) = post_as_owner(
            &fixture,
            TOP_UP_PATH,
            json!({
                "seat": seat_json("claude-code"),
                "expected_spent_attempt": "zz",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "top_up rejects a non-hex capture: {denied}"
        );
        assert_eq!(
            denied["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {denied}"
        );
        assert_eq!(
            denied["error"]["message"].as_str(),
            Some("invalid key or value bytes"),
            "a capture id that is not an id: {denied}"
        );

        for (field, input) in [
            (
                "binding",
                json!({
                    "binding": "zz",
                    "expected_attempt": attempt_hex.clone(),
                    "policy": policy_json(),
                }),
            ),
            (
                "expected_attempt",
                json!({
                    "binding": binding_hex.clone(),
                    "expected_attempt": "zz",
                    "policy": policy_json(),
                }),
            ),
        ] {
            let (status, denied) = post_as_owner(&fixture, RESUME_PATH, input).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "resume rejects a non-hex {field}: {denied}"
            );
            assert_eq!(
                denied["error"]["message"].as_str(),
                Some("invalid key or value bytes"),
                "an id that is not an id: {denied}"
            );
        }

        let (status, denied) = post_as_owner(
            &fixture,
            RESUME_PATH,
            json!({
                "binding": binding_hex.clone(),
                "expected_attempt": attempt_hex.clone(),
                "policy": {"seats": []},
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "resume rejects an empty seat order: {denied}"
        );
        assert_eq!(
            denied["error"]["message"].as_str(),
            Some("invalid agent dispatch input: runner seat policy must order at least one seat"),
            "the policy validation refuses: {denied}"
        );

        let (status, denied) = post_as_owner(
            &fixture,
            RESUME_PATH,
            json!({
                "binding": binding_hex.clone(),
                "expected_attempt": attempt_hex.clone(),
                "policy": {"seats": [seat_json("nope")]},
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "resume rejects an unknown runner: {denied}"
        );
        assert_eq!(
            denied["error"]["message"].as_str(),
            Some("unknown Dreamer provider adapter: nope"),
            "the registry refuses: {denied}"
        );

        let (status, denied) = post_as_owner(
            &fixture,
            RESUME_PATH,
            json!({
                "binding": binding_hex.clone(),
                "expected_attempt": attempt_hex.clone(),
                "policy": {"seats": [{
                    "runner": "claude-code",
                    "auth": "vendor_login",
                    "egress_profile_ref": "egress/runner-door-test",
                    "credential_handles": ["custody://w/test"],
                }]},
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "resume refuses a login seat naming a credential: {denied}"
        );
        assert_eq!(
            denied["error"]["message"].as_str(),
            Some(
                "invalid agent dispatch input: a vendor-login seat names no credential: \
                  the login stays with the runtime's CLI"
            ),
            "the seat validation refuses: {denied}"
        );

        let (status, denied) = post_as_owner(
            &fixture,
            RESUME_PATH,
            json!({
                "binding": binding_hex,
                "expected_attempt": attempt_hex,
                "policy": {"seats": [{
                    "runner": "codex",
                    "auth": "api_key",
                    "egress_profile_ref": "egress/runner-door-test",
                }]},
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "resume refuses a key seat naming no custody handle: {denied}"
        );
        assert_eq!(
            denied["error"]["message"].as_str(),
            Some("invalid agent dispatch input: an API-key seat must name a custody handle"),
            "the seat validation refuses: {denied}"
        );

        let registry = ProviderAdapterRegistry::standard();
        let policy = seat_policy();
        let now = now_secs();
        let parked = SeatSpent {
            kind: Some(SpentKind::Window),
            retry_after: Some(1800),
            resets_at: Vec::new(),
        };
        let (parked_binding, parked_spent) = bind_parked_work(
            &fixture.vault,
            &registry,
            &policy,
            0,
            "resume-past-policy",
            parked,
            now,
        );
        let (status, denied) = post_as_owner(
            &fixture,
            RESUME_PATH,
            json!({
                "binding": parked_binding,
                "expected_attempt": parked_spent,
                "choice": {"seat": 9},
                "policy": policy_json(),
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "resume refuses a seat past the policy's order: {denied}"
        );
        assert_eq!(
            denied["error"]["message"].as_str(),
            Some("invalid agent dispatch input: runner seat index is past the policy's order"),
            "the seat index validation refuses: {denied}"
        );
    });
}
