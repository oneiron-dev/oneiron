//! The owner's typed host triggers (ARCH-0080), entered as the SDK enters them:
//! HTTP `POST /v1/core/facade/<verb>` through the in-process router
//! (`oneshot`, no TCP ports, no sleeps). The doors are `host.wake`,
//! `host.budget.hit`, and `host.compact` (which has no cheap backend on a
//! fresh vault, so it answers 503 once owner admission passes).
//!
//! The promises: `host` is a verb family, never an actor class (P1, proven as
//! the owner-only verb family plus the mint refusing the class: no served 401,
//! because the mint refuses `host` first); a spent budget seat keeps its
//! original accounting across hits (P3, accounting half only). P2 ("a
//! `host.compact` pre-hook may not Skip") is unproven here: no public door
//! installs a pre-hook, so nothing can serve one. Its refusing lines are
//! `crates/oneiron/src/runtime_hooks/verb/chain.rs:42,790-792,528-535` and the
//! twin gate at `crates/oneiron/src/runtime_hooks/verb/golden.rs:215-216`.
//!
//! Canon `oneiron/agents/oneiron-arch-0080-runtime-hooks-v1.md:291`
//! "`host` is a verb family, never an actor class."
//! (`generated/llms-full.txt:351740`).
//! Canon `oneiron/agents/oneiron-arch-0080-runtime-hooks-v1.md:293`
//! "a `host.compact` pre-hook may not Skip, because a skipped compaction
//! overflows the next turn" (`generated/llms-full.txt:351742`; unproven).
//! Canon `oneiron/agents/oneiron-arch-0080-runtime-hooks-v1.md:304`
//! "Enqueue, with the original budget accounting kept."
//! (`generated/llms-full.txt:351753`; accounting half only).
//!
//! Each test owns a fresh vault on a `MemoryKeystore`. Owner posts use the
//! host-root slip; person, agent, narrowed host-holder, and read-only posts
//! use holder-bound slips. Wake dedupe rides `x-oneiron-invocation`: one attempt
//! per invocation, where a repeat answers the first reply again (the facade's
//! invocation claim replays it before the door runs) and a fresh invocation
//! enqueues a fresh attempt.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test host_trigger_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::authority::{ActSurface, CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
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
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tower::ServiceExt;

struct Fixture {
    vault: Arc<Vault>,
    _dir: tempfile::TempDir,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    person: EntityId,
    person_slip: CapabilitySlip,
    person_token: String,
    agent: EntityId,
    agent_slip: CapabilitySlip,
    agent_token: String,
    narrowed_host_slip: CapabilitySlip,
    narrowed_host_token: String,
    readonly_slip: CapabilitySlip,
    readonly_token: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every holder-bound credential here binds; each holder proves it.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5B; 32])
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

/// A human credential this host mints `who`, holding `read` and `write`:
/// a person's own slip, not owner-grade.
fn mint_person_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
    who: EntityId,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = who.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a credential")
}

/// An agent credential this host mints `agent`, holding `read` and `write`.
fn mint_agent_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
    agent: EntityId,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = agent.to_hex();
    claims.actor_class = Some("agent".to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("an agent credential")
}

/// A narrowed host-holder slip: holder `host`, verbs `read` + `write`, no
/// principal and no actor class. The owner root is the full host slip; this
/// narrowed child names no person, so `facade_actor` refuses it.
fn mint_narrowed_host_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = "host".to_owned();
    claims.actor_class = None;
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a narrowed host credential")
}

/// A read-only human credential holding `read` only: the host verbs need
/// `Write`, so the scope guard refuses it before the body decodes.
fn mint_readonly_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
    who: EntityId,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = who.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a read-only credential")
}

/// An enabled agent the owner creates and gives one Grant naming the host
/// verbs, as `delete_authority_served_door.rs` mints its grants.
fn agent_with_grant(vault: &Vault, owner_actor: EntityId, agent_id: &str) -> EntityId {
    let agent = EntityId::now();
    let real_proof = vault
        .authenticate_owner(
            owner_actor,
            &owner_actor.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("an owner proof");
    create_agent_definition_as(
        vault,
        &real_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Host trigger door test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled agent definition");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        "host.wake".to_owned(),
        "host.compact".to_owned(),
        "host.budget.hit".to_owned(),
    ]));
    let minted = mint_agent_grant_as(
        vault,
        &real_proof,
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
                auth_secret: Some("host-trigger-doors".into()),
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
    let person_slip = mint_person_credential(&owner_slip, &vault, &issuer, who);
    let person_token = person_slip.to_token().expect("person slip token");
    let owner_actor = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let agent = agent_with_grant(&vault, owner_actor, "host_door_agent");
    let agent_slip = mint_agent_credential(&owner_slip, &vault, &issuer, agent);
    let agent_token = agent_slip.to_token().expect("agent slip token");
    let narrowed_host_slip = mint_narrowed_host_credential(&owner_slip, &vault, &issuer);
    let narrowed_host_token = narrowed_host_slip.to_token().expect("narrowed host token");
    let readonly_slip = mint_readonly_credential(&owner_slip, &vault, &issuer, who);
    let readonly_token = readonly_slip.to_token().expect("read-only token");
    let app = build_app(server);
    Fixture {
        vault,
        _dir: dir,
        app,
        issuer,
        owner_slip,
        owner_token,
        person: who,
        person_slip,
        person_token,
        agent,
        agent_slip,
        agent_token,
        narrowed_host_slip,
        narrowed_host_token,
        readonly_slip,
        readonly_token,
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

fn person_binding(fixture: &Fixture) -> String {
    holder_proof(
        &fixture.person_slip,
        &holder_key(),
        fixture.vault.now_recorded_at(),
    )
    .expect("holder proof")
    .to_string()
}

fn agent_binding(fixture: &Fixture) -> String {
    holder_proof(
        &fixture.agent_slip,
        &holder_key(),
        fixture.vault.now_recorded_at(),
    )
    .expect("agent holder proof")
    .to_string()
}

fn narrowed_host_binding(fixture: &Fixture) -> String {
    holder_proof(
        &fixture.narrowed_host_slip,
        &holder_key(),
        fixture.vault.now_recorded_at(),
    )
    .expect("narrowed host proof")
    .to_string()
}

fn readonly_binding(fixture: &Fixture) -> String {
    holder_proof(
        &fixture.readonly_slip,
        &holder_key(),
        fixture.vault.now_recorded_at(),
    )
    .expect("read-only holder proof")
    .to_string()
}

#[allow(clippy::too_many_arguments)]
async fn post_full(
    fixture: &Fixture,
    path: &str,
    token: Option<&str>,
    binding: Option<String>,
    invocation: Option<&str>,
    room_turn: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut request = Request::post(path).header("content-type", "application/json");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    if let Some(binding) = binding {
        request = request.header("x-oneiron-binding", binding);
    }
    if let Some(invocation) = invocation {
        request = request.header("x-oneiron-invocation", invocation);
    }
    if let Some(room_turn) = room_turn {
        request = request.header("x-oneiron-room-turn", room_turn);
    }
    let request = request
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
    post_full(
        fixture,
        path,
        Some(&token),
        Some(owner_binding(fixture)),
        None,
        None,
        body,
    )
    .await
}

async fn post_as_owner_with_invocation(
    fixture: &Fixture,
    path: &str,
    body: Value,
    invocation: &str,
) -> (StatusCode, Value) {
    let token = fixture.owner_token.clone();
    post_full(
        fixture,
        path,
        Some(&token),
        Some(owner_binding(fixture)),
        Some(invocation),
        None,
        body,
    )
    .await
}

async fn post_as_person(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.person_token.clone();
    post_full(
        fixture,
        path,
        Some(&token),
        Some(person_binding(fixture)),
        None,
        None,
        body,
    )
    .await
}

async fn post_as_agent(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.agent_token.clone();
    post_full(
        fixture,
        path,
        Some(&token),
        Some(agent_binding(fixture)),
        None,
        None,
        body,
    )
    .await
}

async fn post_as_narrowed_host(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.narrowed_host_token.clone();
    post_full(
        fixture,
        path,
        Some(&token),
        Some(narrowed_host_binding(fixture)),
        None,
        None,
        body,
    )
    .await
}

async fn post_as_readonly(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.readonly_token.clone();
    post_full(
        fixture,
        path,
        Some(&token),
        Some(readonly_binding(fixture)),
        None,
        None,
        body,
    )
    .await
}

async fn post_without_credential(
    fixture: &Fixture,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    post_full(fixture, path, None, None, None, None, body).await
}

async fn post_as_owner_with_room_turn(
    fixture: &Fixture,
    path: &str,
    body: Value,
    room_turn: &str,
) -> (StatusCode, Value) {
    let token = fixture.owner_token.clone();
    post_full(
        fixture,
        path,
        Some(&token),
        Some(owner_binding(fixture)),
        None,
        Some(room_turn),
        body,
    )
    .await
}

/// A root spend scope with `units` fully spent: the budget.hit happy path.
fn seed_spent_root(vault: &Vault, seat: &str, units: u64) -> SpendScopeId {
    let dispatcher = AgentDispatcher::new(vault);
    let scope_id = SpendScopeId::launch(seat).expect("a launch scope id");
    let opened = dispatcher
        .open_root_spend_scope(
            scope_id.clone(),
            DeclaredMaximum {
                units,
                unit: LeaseUnit::tokens(),
            },
            Some(MaximumShown { at_ms: 12_000 }),
            12,
        )
        .expect("a root spend scope");
    assert!(opened.hard, "the root is a hard cap");
    dispatcher
        .charge(&scope_id, units)
        .expect("the full cap is spent");
    scope_id
}

/// A root spend scope with `charged` of `cap` spent: the unspent control.
fn seed_unspent_root(vault: &Vault, seat: &str, cap: u64, charged: u64) -> SpendScopeId {
    let dispatcher = AgentDispatcher::new(vault);
    let scope_id = SpendScopeId::launch(seat).expect("a launch scope id");
    dispatcher
        .open_root_spend_scope(
            scope_id.clone(),
            DeclaredMaximum {
                units: cap,
                unit: LeaseUnit::tokens(),
            },
            Some(MaximumShown { at_ms: 12_000 }),
            12,
        )
        .expect("a root spend scope");
    dispatcher
        .charge(&scope_id, charged)
        .expect("a partial charge lands");
    scope_id
}

/// A compact body that decodes field by field (see REPORT.md section 1).
fn compact_body(session_hex: &str, message_hex: &str, turn_hex: &str) -> Value {
    json!({
        "session_ref": session_hex,
        "window": [{
            "message_id": message_hex,
            "turn_id": turn_hex,
            "content": "hello",
            "turn": 1,
            "tokens": 5,
        }],
        "keep_list": [],
        "token_ceiling": 1000,
    })
}

/// An owner wake enqueues one attempt per invocation: repeating the same
/// invocation answers the first reply again (the facade's invocation claim
/// replays it, so the repeat never reaches the door), and a fresh invocation
/// enqueues a fresh attempt.
#[test]
fn owner_wake_enqueues_once_per_invocation() {
    run_on_engine_stack("host-wake-dedupe", || async {
        let fixture = setup().await;
        let invocation_hex = "0123456789abcdef0123456789abcdef";
        let wake_input = json!({"wake_kind": "compaction", "queue_head": []});
        let (status_first, first) = post_as_owner_with_invocation(
            &fixture,
            "/v1/core/facade/host.wake",
            wake_input.clone(),
            invocation_hex,
        )
        .await;
        assert_eq!(status_first, StatusCode::OK, "owner wake enqueues: {first}");
        assert_eq!(
            first["wake_kind"].as_str(),
            Some("compaction"),
            "the wake echoes its kind: {first}"
        );
        assert_eq!(
            first["queue_head"],
            json!([]),
            "the wake echoes its head: {first}"
        );
        let attempt_first = first["attempt"].as_str().expect("an attempt id").to_owned();
        assert_eq!(attempt_first.len(), 32, "the attempt is 32 hex: {first}");
        assert!(
            attempt_first.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "the attempt is hex: {first}"
        );
        assert_eq!(
            first["already_queued"].as_bool(),
            Some(false),
            "the first wake is fresh: {first}"
        );
        assert!(
            first["request_id"].is_null(),
            "compaction names no request: {first}"
        );

        let (status_second, second) = post_as_owner_with_invocation(
            &fixture,
            "/v1/core/facade/host.wake",
            wake_input.clone(),
            invocation_hex,
        )
        .await;
        assert_eq!(
            status_second,
            StatusCode::OK,
            "the repeat answers: {second}"
        );
        assert_eq!(
            second, first,
            "the repeat answers the first reply again: {second}"
        );

        let fresh_invocation = "2123456789abcdef0123456789abcdef";
        let (status_fresh, fresh) = post_as_owner_with_invocation(
            &fixture,
            "/v1/core/facade/host.wake",
            wake_input,
            fresh_invocation,
        )
        .await;
        assert_eq!(
            status_fresh,
            StatusCode::OK,
            "a fresh invocation enqueues: {fresh}"
        );
        assert_eq!(
            fresh["already_queued"].as_bool(),
            Some(false),
            "the fresh wake is fresh: {fresh}"
        );
        assert_ne!(
            fresh["attempt"].as_str(),
            Some(attempt_first.as_str()),
            "the fresh wake names a fresh attempt: {fresh}"
        );
    });
}

/// A timer wake carries its invocation as the typed night-step request id;
/// any other kind carries none. Queue sizes are never asserted.
#[test]
fn timer_wake_carries_request_id() {
    run_on_engine_stack("host-wake-timer", || async {
        let fixture = setup().await;
        let timer_invocation = "abcdef0123456789abcdef0123456789";
        let timer_head = EntityId::now().to_hex();
        // No `already_queued` or `queue_head` assert here: those fields
        // belong to the dedupe and opacity tests and their faults.
        let (status_timer, timer) = post_as_owner_with_invocation(
            &fixture,
            "/v1/core/facade/host.wake",
            json!({"wake_kind": "timer", "queue_head": [timer_head]}),
            timer_invocation,
        )
        .await;
        assert_eq!(
            status_timer,
            StatusCode::OK,
            "owner timer wake lands: {timer}"
        );
        assert_eq!(
            timer["wake_kind"].as_str(),
            Some("timer"),
            "the wake echoes timer: {timer}"
        );
        assert_eq!(
            timer["request_id"].as_str(),
            Some(timer_invocation),
            "timer carries its invocation as the request id: {timer}"
        );

        let end_invocation = "00112233445566778899aabbccddeeff";
        let (status_end, ended) = post_as_owner_with_invocation(
            &fixture,
            "/v1/core/facade/host.wake",
            json!({"wake_kind": "session_end", "queue_head": []}),
            end_invocation,
        )
        .await;
        assert_eq!(status_end, StatusCode::OK, "a session end lands: {ended}");
        assert!(
            ended["request_id"].is_null(),
            "a session end names no request: {ended}"
        );
    });
}

/// A budget hit keeps the original accounting: the same line, root, cap,
/// spend, and zero available, before and after, across two hits.
///
/// Canon `oneiron/agents/oneiron-arch-0080-runtime-hooks-v1.md:304`
/// "Enqueue, with the original budget accounting kept."
#[test]
fn owner_budget_hit_keeps_original_accounting() {
    run_on_engine_stack("host-budget-hit", || async {
        let fixture = setup().await;
        let seat_name = "seat-1";
        let scope_id = seed_spent_root(&fixture.vault, seat_name, 100);
        let dispatcher = AgentDispatcher::new(&fixture.vault);
        let spend_before = dispatcher.spend_read(&scope_id).expect("a spend read");
        assert_eq!(
            spend_before.available_units, 0,
            "the seeded seat is fully spent"
        );
        let scope_before = dispatcher
            .read_spend_scope(&scope_id)
            .expect("a scope read")
            .expect("the seeded scope");
        assert_eq!(scope_before.cap_units, 100, "the seeded cap stands");
        assert_eq!(scope_before.spent_units, 100, "the seeded spend stands");

        let budget_input = json!({"seat": seat_name, "policy": {"kind": "suspend"}});
        let (status_first, first) = post_as_owner(
            &fixture,
            "/v1/core/facade/host.budget.hit",
            budget_input.clone(),
        )
        .await;
        assert_eq!(status_first, StatusCode::OK, "a spent seat hits: {first}");
        assert_eq!(
            first["seat"].as_str(),
            Some(seat_name),
            "the hit echoes its seat: {first}"
        );
        assert_eq!(
            first["policy"]["kind"].as_str(),
            Some("suspend"),
            "the hit echoes suspend: {first}"
        );
        assert_eq!(
            first["accounting"]["line"]["scope"].as_str(),
            Some(seat_name),
            "the line is the original seat: {first}"
        );
        assert_eq!(
            first["accounting"]["line"]["cap_units"].as_u64(),
            Some(100),
            "the line keeps its cap: {first}"
        );
        assert_eq!(
            first["accounting"]["line"]["spent_units"].as_u64(),
            Some(100),
            "the line keeps its spend: {first}"
        );
        assert_eq!(
            first["accounting"]["spend"]["available_units"].as_u64(),
            Some(0),
            "nothing is left to spend: {first}"
        );
        assert_eq!(
            first["accounting"]["root"]["scope"].as_str(),
            Some(seat_name),
            "the root is the same seat: {first}"
        );

        let (status_second, second) =
            post_as_owner(&fixture, "/v1/core/facade/host.budget.hit", budget_input).await;
        assert_eq!(status_second, StatusCode::OK, "the hit repeats: {second}");
        assert_eq!(
            second["accounting"], first["accounting"],
            "the repeat keeps identical accounting: {second}"
        );

        let spend_after = dispatcher.spend_read(&scope_id).expect("a spend re-read");
        assert_eq!(
            spend_after.available_units, spend_before.available_units,
            "the hits move no spend"
        );
        let scope_after = dispatcher
            .read_spend_scope(&scope_id)
            .expect("a scope re-read")
            .expect("the scope still stands");
        assert_eq!(
            scope_after.spent_units, scope_before.spent_units,
            "the hits move nothing"
        );
    });
}

/// A budget hit refuses what is not a spent suspend seat: an unspent line,
/// a non-suspend policy, an unknown seat, and a malformed seat id.
#[test]
fn budget_hit_refuses_unspent_wrong_policy_and_unknown_seat() {
    run_on_engine_stack("host-budget-refusals", || async {
        let fixture = setup().await;
        seed_spent_root(&fixture.vault, "seat-spent", 100);
        seed_unspent_root(&fixture.vault, "seat-unspent", 100, 10);

        let (status_unspent, unspent) = post_as_owner(
            &fixture,
            "/v1/core/facade/host.budget.hit",
            json!({"seat": "seat-unspent", "policy": {"kind": "suspend"}}),
        )
        .await;
        assert_eq!(
            status_unspent,
            StatusCode::BAD_REQUEST,
            "an unspent seat is refused: {unspent}"
        );
        assert_eq!(
            unspent["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {unspent}"
        );
        assert_eq!(
            unspent["error"]["message"].as_str(),
            Some("the budget seat has not hit its cap"),
            "the refusal names the unspent line: {unspent}"
        );

        let (status_policy, policy) = post_as_owner(
            &fixture,
            "/v1/core/facade/host.budget.hit",
            json!({"seat": "seat-spent", "policy": {"kind": "continue_on_local"}}),
        )
        .await;
        assert_eq!(
            status_policy,
            StatusCode::BAD_REQUEST,
            "a non-suspend policy is refused: {policy}"
        );
        assert_eq!(
            policy["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {policy}"
        );
        assert_eq!(
            policy["error"]["message"].as_str(),
            Some("a durable spend scope's policy is Suspend"),
            "the refusal names the suspend law: {policy}"
        );

        let (status_unknown, unknown) = post_as_owner(
            &fixture,
            "/v1/core/facade/host.budget.hit",
            json!({"seat": "no-such-seat", "policy": {"kind": "suspend"}}),
        )
        .await;
        assert_eq!(
            status_unknown,
            StatusCode::BAD_REQUEST,
            "an unknown seat is refused: {unknown}"
        );
        assert_eq!(
            unknown["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {unknown}"
        );
        assert_eq!(
            unknown["error"]["message"].as_str(),
            Some("budget seat has no spend scope"),
            "the refusal names the missing scope: {unknown}"
        );

        let (status_empty, empty) = post_as_owner(
            &fixture,
            "/v1/core/facade/host.budget.hit",
            json!({"seat": "", "policy": {"kind": "suspend"}}),
        )
        .await;
        assert_eq!(
            status_empty,
            StatusCode::BAD_REQUEST,
            "an empty seat is refused: {empty}"
        );
        assert_eq!(
            empty["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {empty}"
        );
        assert_eq!(
            empty["error"]["message"].as_str(),
            Some(
                "invalid agent dispatch input: a launch id is 1..=128 printable bytes, \
                 not an attempt id"
            ),
            "the refusal names the launch law: {empty}"
        );
    });
}

/// Only the owner reaches the host verbs: a person and an agent (even under
/// a Grant naming the verbs) are refused as non-owners; a narrowed
/// host-holder slip binds no principal; a read-only slip lacks the scope; a
/// room turn is not served; no credential is unauthorized. The owner's
/// compact answers 503, proving admission passed before the backend check.
/// P1 is proven as the owner-only verb family plus the mint refusing `host`
/// as an actor class (no served 401: an unmintable class is never served).

/// Canon `oneiron/agents/oneiron-arch-0080-runtime-hooks-v1.md:291`
/// "`host` is a verb family, never an actor class."
#[test]
fn host_rows_refuse_non_owner_and_bind_actor() {
    run_on_engine_stack("host-owner-matrix", || async {
        let fixture = setup().await;
        assert_eq!(
            fixture.person_slip.claims.holder_ref,
            fixture.person.to_hex(),
            "the person's credential binds the person"
        );
        assert_eq!(
            fixture.agent_slip.claims.holder_ref,
            fixture.agent.to_hex(),
            "the agent's credential binds the agent"
        );
        let session_hex = EntityId::now().to_hex();
        let message_hex = EntityId::now().to_hex();
        let turn_hex = EntityId::now().to_hex();
        let compact_input = compact_body(&session_hex, &message_hex, &turn_hex);
        let rows: Vec<(&str, Value)> = vec![
            (
                "host.wake",
                json!({"wake_kind": "compaction", "queue_head": []}),
            ),
            (
                "host.budget.hit",
                json!({"seat": "seat-1", "policy": {"kind": "suspend"}}),
            ),
            ("host.compact", compact_input.clone()),
        ];
        for (verb, valid_body) in &rows {
            let path = format!("/v1/core/facade/{verb}");
            let (status_person, refused_person) =
                post_as_person(&fixture, &path, (*valid_body).clone()).await;
            assert_eq!(
                status_person,
                StatusCode::FORBIDDEN,
                "a person is refused {verb}: {refused_person}"
            );
            assert_eq!(
                refused_person["error"]["code"].as_str(),
                Some("FORBIDDEN"),
                "the refusal names its code: {refused_person}"
            );
            assert_eq!(
                refused_person["error"]["message"].as_str(),
                Some(format!("{verb} is the vault owner's")).as_deref(),
                "the refusal names the owner: {refused_person}"
            );

            let (status_agent, refused_agent) =
                post_as_agent(&fixture, &path, (*valid_body).clone()).await;
            assert_eq!(
                status_agent,
                StatusCode::FORBIDDEN,
                "an agent is refused {verb}: {refused_agent}"
            );
            assert_eq!(
                refused_agent["error"]["code"].as_str(),
                Some("FORBIDDEN"),
                "the refusal names its code: {refused_agent}"
            );
            assert_eq!(
                refused_agent["error"]["message"].as_str(),
                Some(format!("{verb} is the vault owner's")).as_deref(),
                "a Grant names no owner path: {refused_agent}"
            );
        }

        for (verb, _) in &rows {
            let path = format!("/v1/core/facade/{verb}");
            let (status_narrowed, narrowed) =
                post_as_narrowed_host(&fixture, &path, json!({})).await;
            assert_eq!(
                status_narrowed,
                StatusCode::FORBIDDEN,
                "a narrowed host slip binds no principal on {verb}: {narrowed}"
            );
            assert_eq!(
                narrowed["error"]["code"].as_str(),
                Some("FORBIDDEN"),
                "the refusal names its code: {narrowed}"
            );
            assert_eq!(
                narrowed["error"]["message"].as_str(),
                Some("facade routes bind writes to an authenticated principal"),
                "the refusal names the missing principal: {narrowed}"
            );

            let (status_readonly, readonly) = post_as_readonly(&fixture, &path, json!({})).await;
            assert_eq!(
                status_readonly,
                StatusCode::FORBIDDEN,
                "a read-only slip is refused {verb}: {readonly}"
            );
            assert_eq!(
                readonly["error"]["code"].as_str(),
                Some("FORBIDDEN"),
                "the refusal names its code: {readonly}"
            );
            assert_eq!(
                readonly["error"]["message"].as_str(),
                Some("request does not have the required scope"),
                "the refusal names the missing scope: {readonly}"
            );

            let room_hex = EntityId::now().to_hex();
            let (status_room, room) =
                post_as_owner_with_room_turn(&fixture, &path, json!({}), &room_hex).await;
            assert_eq!(
                status_room,
                StatusCode::BAD_REQUEST,
                "a room turn is not served {verb}: {room}"
            );
            assert_eq!(
                room["error"]["code"].as_str(),
                Some("BAD_REQUEST"),
                "the refusal names its code: {room}"
            );
            assert_eq!(
                room["error"]["message"].as_str(),
                Some(format!("{verb} is not served inside a room turn")).as_deref(),
                "the refusal names the room turn: {room}"
            );

            let (status_bare, bare) = post_without_credential(&fixture, &path, json!({})).await;
            assert_eq!(
                status_bare,
                StatusCode::UNAUTHORIZED,
                "no credential is unauthorized on {verb}: {bare}"
            );
            assert_eq!(
                bare["error"]["code"].as_str(),
                Some("UNAUTHORIZED"),
                "the refusal names its code: {bare}"
            );
            assert_eq!(
                bare["error"]["message"].as_str(),
                Some("request is not authorized"),
                "the refusal names its reason: {bare}"
            );
        }

        let (status_compact, compact) =
            post_as_owner(&fixture, "/v1/core/facade/host.compact", compact_input).await;
        assert_eq!(
            status_compact,
            StatusCode::SERVICE_UNAVAILABLE,
            "the owner's compact passes admission: {compact}"
        );
        assert_eq!(
            compact["error"]["code"].as_str(),
            Some("MODEL_UNAVAILABLE"),
            "the refusal names its code: {compact}"
        );
        assert_eq!(
            compact["error"]["message"].as_str(),
            Some("no configured cheap compaction backend serves this host"),
            "the refusal names the missing backend: {compact}"
        );

        let mut host_claims = fixture.owner_slip.claims.clone();
        host_claims.slip_id = next_slip_id();
        host_claims.parent_id = None;
        host_claims.holder_ref = fixture.person.to_hex();
        host_claims.actor_class = Some("host".to_owned());
        host_claims.binding_key = holder_key().verifying_key().to_bytes();
        let host_mint = fixture
            .vault
            .mint_capability_slip(&fixture.issuer, host_claims);
        assert!(host_mint.is_err(), "no slip mints `host` as an actor class");
    });
}

/// Malformed host bodies are refused before any hook runs: `{}` everywhere,
/// an unknown field everywhere, and each verb's mistyped field.
#[test]
fn host_rows_reject_malformed_bodies() {
    run_on_engine_stack("host-malformed", || async {
        let fixture = setup().await;
        let session_hex = EntityId::now().to_hex();
        let message_hex = EntityId::now().to_hex();
        let turn_hex = EntityId::now().to_hex();
        let compact_valid = compact_body(&session_hex, &message_hex, &turn_hex);
        let mut compact_unknown = compact_valid.clone();
        compact_unknown["extra"] = json!(1);
        let mut compact_mistyped = compact_valid.clone();
        compact_mistyped["token_ceiling"] = json!("lots");
        let rows: Vec<(&str, Value)> = vec![
            ("host.wake", json!({})),
            (
                "host.wake",
                json!({"wake_kind": "compaction", "queue_head": [], "extra": 1}),
            ),
            (
                "host.wake",
                json!({"wake_kind": "nonsense", "queue_head": []}),
            ),
            ("host.budget.hit", json!({})),
            (
                "host.budget.hit",
                json!({"seat": "seat-1", "policy": {"kind": "suspend"}, "extra": 1}),
            ),
            (
                "host.budget.hit",
                json!({"seat": "seat-1", "policy": "suspend"}),
            ),
            ("host.compact", json!({})),
            ("host.compact", compact_unknown),
            ("host.compact", compact_mistyped),
        ];
        for (verb, bad_body) in rows {
            let path = format!("/v1/core/facade/{verb}");
            let (status, refused) = post_as_owner(&fixture, &path, bad_body).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "a malformed {verb} body is refused: {refused}"
            );
            assert_eq!(
                refused["error"]["code"].as_str(),
                Some("BAD_REQUEST"),
                "the refusal names its code: {refused}"
            );
            let message = refused["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            assert!(
                message.starts_with("invalid SDK request: "),
                "the refusal names the decode path: {refused}"
            );
        }
    });
}

/// A wake carries its queue head opaquely: unknown ids are echoed, never
/// resolved. No `already_queued` assert here: that field is the dedupe
/// test's, and its fault must not fail this test first.
#[test]
fn wake_queue_head_is_opaque_and_echoed() {
    run_on_engine_stack("host-queue-head", || async {
        let fixture = setup().await;
        let first_head = EntityId::now().to_hex();
        let second_head = EntityId::now().to_hex();
        let invocation_hex = "102030405060708090a0b0c0d0e0f000";
        let (status, echoed) = post_as_owner_with_invocation(
            &fixture,
            "/v1/core/facade/host.wake",
            json!({
                "wake_kind": "compaction",
                "queue_head": [first_head.clone(), second_head.clone()],
            }),
            invocation_hex,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "an opaque head lands: {echoed}");
        assert_eq!(
            echoed["wake_kind"].as_str(),
            Some("compaction"),
            "the wake echoes its kind: {echoed}"
        );
        assert_eq!(
            echoed["queue_head"],
            json!([first_head, second_head]),
            "the wake echoes its unknown head: {echoed}"
        );
    });
}
