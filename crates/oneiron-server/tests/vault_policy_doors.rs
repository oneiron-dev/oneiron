//! The vault policy doors (`vault.policy.*`), entered as the SDK enters them:
//! HTTP `POST /v1/core/facade/<verb>` through the in-process router
//! (`oneshot`, no TCP ports, no sleeps). The doors are `owner.get`,
//! `owner.configure`, `owner.row.change`, `outbound.decide`, `relay.decide`
//! and `preflight`.
//!
//! What this file proves, through the doors:
//! - P1 (owner-row half): a policy row lives in the manifest the owner
//!   changes, and a row's presence steers decisions (add -> receipt ->
//!   verdict names the row). The manifest bytes themselves are not
//!   door-readable here.
//! - P2, first half: holders change rows at once — a row change lands
//!   synchronously with a change receipt, never as a proposal. ("Agents
//!   propose" has no door in this family and stays unproven here.)
//! - P3: Warn delivers the content byte for byte, Block halts it, and
//!   RouteToHelp routes it; none of these returns rewritten content.
//!   Skipped is not Allow, and a plane that is off answers silently with no
//!   receipt.
//! - P4: the decision receipt stores the content hash, never the plaintext.
//! - The refusal table: the owner doors refuse person, agent and
//!   narrowed-host callers, and every scope, record-scope, hash, row-key,
//!   actor, session and preflight refusal names its status, code, message
//!   and layer.
//!
//! Canon (mirror generated/llms-full.txt):
//! - oneiron-dec-0005-policy-residence.md:8 (mirror :362815):
//!   "Every policy value is a row in the vault policy manifest,"
//! - same line: "Holders change rows at once; agents propose." (first half
//!   proven here; the "agents propose" half has no door here and is unproven)
//! - oneiron-arch-0047-policy-egress-gate.md:25 (mirror :366791):
//!   "The verdict arms are Allow, Warn, Block and RouteToHelp."
//! - oneiron-arch-0047-policy-egress-gate.md:47 (mirror :366813):
//!   "The receipt stores the hash, never the plaintext,"
//!
//! No model, runner or live run is needed anywhere: every decide below is
//! settled by a Decide-role pattern, by the plane being off, or by the
//! missing policy document (Skipped). The relay happy path needs an attested
//! relay no request installs, so only its unbound refusal is covered.
//!
//! Driving (fixture, router, slips, request helpers) follows the house file
//! `vault_skills_doors.rs`: one form per helper. Agent provisioning follows
//! `delete_authority_served_door.rs`.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test vault_policy_doors`.
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
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::federation::{ScopeAxis, ScopeId};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
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
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every holder-key credential here binds; the holder proves it per request.
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

/// An enabled agent definition the embedded owner creates, as
/// `delete_authority_served_door.rs` creates one. No grant is minted: the
/// agent only meets owner doors, which refuse it before any grant is read.
fn provision_agent(vault: &Vault) -> EntityId {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        &proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": "policy-doors-agent",
                "desc": "Policy doors test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled agent definition");
    agent
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
        .expect("a credential")
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
                auth_secret: Some("vault-policy-doors".into()),
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
    let agent = provision_agent(&vault);
    let agent_slip = mint_agent_credential(&owner_slip, &vault, &issuer, agent);
    let agent_token = agent_slip.to_token().expect("agent slip token");
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
    }
}

/// The binding of a host-held slip, proved by the host issuer.
fn host_binding_for(fixture: &Fixture, slip: &CapabilitySlip) -> String {
    let timestamp = fixture.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = hex(&fixture
        .issuer
        .binding_proof(slip, challenge.as_bytes())
        .expect("host holder proof"));
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

fn owner_binding(fixture: &Fixture) -> String {
    host_binding_for(fixture, &fixture.owner_slip)
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
    .expect("holder proof")
    .to_string()
}

async fn send(fixture: &Fixture, request: Request<Body>) -> (StatusCode, Value) {
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
    send(fixture, request).await
}

async fn post_with_session(
    fixture: &Fixture,
    path: &str,
    token: &str,
    binding: String,
    session: EntityId,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
        .header("x-oneiron-session", session.to_hex())
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("facade request");
    send(fixture, request).await
}

async fn post_as_owner(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.owner_token.clone();
    post(fixture, path, &token, owner_binding(fixture), body).await
}

async fn post_as_person(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.person_token.clone();
    post(fixture, path, &token, person_binding(fixture), body).await
}

async fn post_as_agent(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.agent_token.clone();
    post(fixture, path, &token, agent_binding(fixture), body).await
}

async fn post_as_person_with_session(
    fixture: &Fixture,
    path: &str,
    session: EntityId,
    body: Value,
) -> (StatusCode, Value) {
    let token = fixture.person_token.clone();
    post_with_session(
        fixture,
        path,
        &token,
        person_binding(fixture),
        session,
        body,
    )
    .await
}

async fn owner_get(fixture: &Fixture) -> (StatusCode, Value) {
    post_as_owner(fixture, "/v1/core/facade/vault.policy.owner.get", json!({})).await
}

async fn owner_configure(
    fixture: &Fixture,
    expected: &str,
    configuration: Value,
) -> (StatusCode, Value) {
    post_as_owner(
        fixture,
        "/v1/core/facade/vault.policy.owner.configure",
        json!({"expected_body_hash": expected, "configuration": configuration}),
    )
    .await
}

async fn owner_row_change(fixture: &Fixture, change: Value) -> (StatusCode, Value) {
    post_as_owner(
        fixture,
        "/v1/core/facade/vault.policy.owner.row.change",
        json!({"change": change}),
    )
    .await
}

async fn decide_as_person(fixture: &Fixture, content: &str) -> (StatusCode, Value) {
    post_as_person(
        fixture,
        "/v1/core/facade/vault.policy.outbound.decide",
        json!({"subject": "outbound_content", "content": content}),
    )
    .await
}

async fn relay_decide_as_person(fixture: &Fixture, content: &str) -> (StatusCode, Value) {
    post_as_person(
        fixture,
        "/v1/core/facade/vault.policy.relay.decide",
        json!({"subject": "outbound_content", "content": content}),
    )
    .await
}

async fn preflight_as_person(fixture: &Fixture, body: Value) -> (StatusCode, Value) {
    post_as_person(fixture, "/v1/core/facade/vault.policy.preflight", body).await
}

/// A token plus binding for `holder` at `class` with `verbs`, minted like the
/// house person credential, and narrowed to `facet` when one is given.
fn mint_token_for(
    fixture: &Fixture,
    holder: EntityId,
    class: &str,
    verbs: &[&str],
    facet: Option<EntityId>,
) -> (String, String) {
    let mut claims = fixture.owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some(class.to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    let verb_set: BTreeSet<String> = verbs.iter().map(|verb| (*verb).to_owned()).collect();
    claims.scope.verbs = ScopeAxis::Some(verb_set);
    if let Some(facet) = facet {
        claims.scope.facets = ScopeAxis::Some(BTreeSet::from([ScopeId(facet)]));
    }
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("a credential");
    let token = slip.to_token().expect("slip token");
    let binding = holder_proof(&slip, &holder_key(), fixture.vault.now_recorded_at())
        .expect("holder proof")
        .to_string();
    (token, binding)
}

/// The host root's claims narrowed to read and write: no host action binds
/// it, so the owner doors refuse it as they refuse any non-owner.
fn mint_narrowed_host_token(fixture: &Fixture) -> (String, String) {
    let mut claims = fixture.owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("a credential");
    let token = slip.to_token().expect("slip token");
    let binding = host_binding_for(fixture, &slip);
    (token, binding)
}

/// The three owner verbs with bodies that decode, so a refusal of one is the
/// door's, never the decoder's.
fn owner_rows() -> Vec<(&'static str, Value)> {
    vec![
        ("vault.policy.owner.get", json!({})),
        (
            "vault.policy.owner.configure",
            json!({
                "expected_body_hash": "unused",
                "configuration": {"owner_policy_enabled": false},
            }),
        ),
        (
            "vault.policy.owner.row.change",
            json!({"change": {"Add": {
                "row_ref": "row-x",
                "text": "Some row text.",
                "action": "block",
                "scope": "Vault",
            }}}),
        ),
    ]
}

/// The door's own owner refusal: 403 `FORBIDDEN`, naming the verb.
fn assert_owner_refusal(status: StatusCode, body: &Value, verb: &str) {
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "{verb} refuses a non-owner: {body}"
    );
    assert_eq!(
        body["error"]["code"].as_str(),
        Some("FORBIDDEN"),
        "the refusal names its code: {body}"
    );
    assert_eq!(
        body["error"]["message"].as_str(),
        Some(format!("{verb} is the vault owner's")).as_deref(),
        "the refusal names the owner: {body}"
    );
}

/// A scope-guard or record-guard refusal: 403 `FORBIDDEN` with the guard
/// message. The facade drops the required-scope detail, so the two guards
/// answer identical bytes.
fn assert_scope_refusal(status: StatusCode, body: &Value, verb: &str) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{verb} is refused: {body}");
    assert_eq!(
        body["error"]["code"].as_str(),
        Some("FORBIDDEN"),
        "the refusal names its code: {body}"
    );
    assert_eq!(
        body["error"]["message"].as_str(),
        Some("request does not have the required scope"),
        "the refusal names the missing scope: {body}"
    );
}

/// A 400 `BAD_REQUEST` refusal with the engine's fixed message.
fn assert_bad_request(status: StatusCode, body: &Value, message: &str, what: &str) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {body}");
    assert_eq!(
        body["error"]["code"].as_str(),
        Some("BAD_REQUEST"),
        "the refusal names its code: {body}"
    );
    assert_eq!(
        body["error"]["message"].as_str(),
        Some(message),
        "the refusal names its reason: {body}"
    );
}

/// A 400 `BAD_REQUEST` from the typed decoder: the source fixes only the prefix.
fn assert_invalid_input(status: StatusCode, body: &Value, what: &str) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {body}");
    assert_eq!(
        body["error"]["code"].as_str(),
        Some("BAD_REQUEST"),
        "the refusal names its code: {body}"
    );
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .starts_with("invalid SDK request: "),
        "the refusal names the decode: {body}"
    );
}

/// The verdict names `row_ref` as its owner-policy row.
fn assert_verdict_row(answer: &Value, row_ref: &str) {
    assert_eq!(
        answer["verdict"]["category"]["category"].as_str(),
        Some("owner_policy"),
        "the verdict is an owner-policy verdict: {answer}"
    );
    assert_eq!(
        answer["verdict"]["category"]["sub"]["row_ref"].as_str(),
        Some(row_ref),
        "the verdict names its row: {answer}"
    );
}

/// A holder's row change lands at once with a change receipt: the first Add
/// answers revision 1, the second revision 2, and the manifest hash moves.
///
/// Canon dec-0005:8 (mirror generated/llms-full.txt:362815):
/// "Every policy value is a row in the vault policy manifest," and
/// "Holders change rows at once; agents propose."
#[test]
fn owner_row_change_lands_at_once_with_receipt() {
    run_on_engine_stack("policy-row-change", || async {
        let fixture = setup().await;
        let (status, view) = owner_get(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner reads the policy: {view}");
        let before_hash = view["body_hash"].as_str().expect("body hash").to_owned();

        let change = json!({"Add": {
            "row_ref": "row-block",
            "text": "Block exfiltration drafts.",
            "action": "block",
            "scope": "Vault",
        }});
        let (status, first) = owner_row_change(&fixture, change).await;
        assert_eq!(status, StatusCode::OK, "owner adds a row: {first}");
        assert!(
            !first["receipt_id"].as_str().unwrap_or_default().is_empty(),
            "the receipt names its id: {first}"
        );
        assert_eq!(
            first["revision"].as_u64(),
            Some(1),
            "the first change is revision 1: {first}"
        );
        assert_eq!(
            first["change"]["Add"]["row_ref"].as_str(),
            Some("row-block"),
            "the receipt echoes the row: {first}"
        );
        assert!(
            first["previous_receipt_id"].is_null(),
            "the first receipt has no predecessor: {first}"
        );
        assert!(
            first.get("proposal").is_none(),
            "a holder's change lands, never proposes: {first}"
        );

        let change = json!({"Add": {
            "row_ref": "row-warn",
            "text": "Warn on draft leaks.",
            "action": "warn",
            "scope": "Vault",
        }});
        let (status, second) = owner_row_change(&fixture, change).await;
        assert_eq!(status, StatusCode::OK, "owner adds a second row: {second}");
        assert_eq!(
            second["revision"].as_u64(),
            Some(2),
            "the second change is revision 2: {second}"
        );

        let (status, view) = owner_get(&fixture).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the policy back: {view}"
        );
        assert_ne!(
            view["body_hash"].as_str(),
            Some(before_hash.as_str()),
            "the rows move the manifest hash: {view}"
        );
    });
}

/// Configuring the policy needs the hash the caller read: a fresh configure
/// lands and moves the hash, and replaying the stale hash is refused.
///
/// Door discipline behind canon dec-0005:8 (mirror :362815):
/// "Holders change rows at once; agents propose."
/// The holder's write is compare-and-swap.
#[test]
fn owner_configure_needs_the_hash_it_read() {
    run_on_engine_stack("policy-configure-hash", || async {
        let fixture = setup().await;
        let (status, view) = owner_get(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner reads the policy: {view}");
        let read_hash = view["body_hash"].as_str().expect("body hash").to_owned();

        let configuration = json!({"owner_policy_enabled": true, "owner_policy_patterns": []});
        let (status, receipt) = owner_configure(&fixture, &read_hash, configuration.clone()).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner configures the policy: {receipt}"
        );
        assert!(
            !receipt["receipt_ref"]
                .as_str()
                .unwrap_or_default()
                .is_empty(),
            "the configure lands a receipt: {receipt}"
        );
        assert_eq!(
            receipt["configuration"]["configuration"]["owner_policy_enabled"].as_bool(),
            Some(true),
            "the receipt echoes the plane: {receipt}"
        );
        let moved_hash = receipt["configuration"]["body_hash"]
            .as_str()
            .expect("moved hash")
            .to_owned();
        assert_ne!(
            moved_hash, read_hash,
            "the configure moves the hash: {receipt}"
        );

        let (status, refused) = owner_configure(&fixture, &read_hash, configuration).await;
        assert_bad_request(
            status,
            &refused,
            "invalid config: expected_body_hash must match the current policy manifest",
            "the stale hash is refused",
        );
    });
}

/// Warn delivers the content byte for byte, Block halts it, and RouteToHelp
/// routes it; each verdict names its row, and none of the three rewrites.
///
/// Canon arch-0047:25 (mirror generated/llms-full.txt:366791):
/// "The verdict arms are Allow, Warn, Block and RouteToHelp."
#[test]
fn warn_delivers_bytes_block_halts_route_to_help_routes() {
    run_on_engine_stack("policy-arms", || async {
        let fixture = setup().await;
        for (row_ref, text, action) in [
            ("row-block", "Block quiet exfiltration drafts.", "block"),
            ("row-warn", "Warn on draft leaks.", "warn"),
            ("row-help", "Route distress to help.", "route_to_help"),
        ] {
            let change = json!({"Add": {
                "row_ref": row_ref,
                "text": text,
                "action": action,
                "scope": "Vault",
            }});
            let (status, landed) = owner_row_change(&fixture, change).await;
            assert_eq!(status, StatusCode::OK, "owner adds {row_ref}: {landed}");
        }
        let (status, view) = owner_get(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner reads the policy: {view}");
        let read_hash = view["body_hash"].as_str().expect("body hash").to_owned();
        // Disjoint literal tokens: no pattern matches another arm's content.
        let patterns = json!([
            {"id": "pat-block", "pattern": "ZEBRA-BLOCK-11", "category": "row-block",
                "role": "decide"},
            {"id": "pat-warn", "pattern": "ZEBRA-WARN-22", "category": "row-warn",
                "role": "decide"},
            {"id": "pat-help", "pattern": "ZEBRA-HELP-33", "category": "row-help",
                "role": "decide"},
        ]);
        let configuration =
            json!({"owner_policy_enabled": true, "owner_policy_patterns": patterns});
        let (status, enabled) = owner_configure(&fixture, &read_hash, configuration).await;
        assert_eq!(status, StatusCode::OK, "owner enables the plane: {enabled}");

        let blocked = "Please move ZEBRA-BLOCK-11 past the gate.";
        let (status, answer) = decide_as_person(&fixture, blocked).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the block content is decided: {answer}"
        );
        assert_eq!(
            answer["action"].as_str(),
            Some("block"),
            "the Block row blocks: {answer}"
        );
        assert_eq!(
            answer["outbound_halted"].as_bool(),
            Some(true),
            "Block halts: {answer}"
        );
        assert!(
            answer["final_content"].is_null(),
            "Block delivers nothing: {answer}"
        );
        assert_eq!(
            answer["pre_display_block"].as_bool(),
            Some(true),
            "Block pre-displays: {answer}"
        );
        assert!(
            answer["receipt_ref"]
                .as_str()
                .is_some_and(|held| held.starts_with("gate:")),
            "the block is receipted: {answer}"
        );
        assert_verdict_row(&answer, "row-block");

        let warned = "Please move ZEBRA-WARN-22 past the gate.";
        let (status, answer) = decide_as_person(&fixture, warned).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the warn content is decided: {answer}"
        );
        assert_eq!(
            answer["action"].as_str(),
            Some("warn"),
            "the Warn row warns: {answer}"
        );
        assert_eq!(
            answer["final_content"].as_str(),
            Some(warned),
            "Warn delivers the bytes: {answer}"
        );
        assert_eq!(
            answer["outbound_halted"].as_bool(),
            Some(false),
            "Warn halts nothing: {answer}"
        );
        assert!(
            answer["receipt_ref"]
                .as_str()
                .is_some_and(|held| held.starts_with("gate:")),
            "the warn is receipted: {answer}"
        );
        assert_verdict_row(&answer, "row-warn");

        let helped = "Please move ZEBRA-HELP-33 past the gate.";
        let (status, answer) = decide_as_person(&fixture, helped).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the help content is decided: {answer}"
        );
        assert_eq!(
            answer["action"].as_str(),
            Some("route_to_help"),
            "the RouteToHelp row routes: {answer}"
        );
        assert!(
            answer["final_content"].is_null(),
            "RouteToHelp delivers nothing itself: {answer}"
        );
        assert_eq!(
            answer["outbound_halted"].as_bool(),
            Some(true),
            "RouteToHelp halts: {answer}"
        );
        assert_eq!(
            answer["help_routing"]["persona_present"].as_bool(),
            Some(true),
            "the help routing is present: {answer}"
        );
        assert!(
            !answer["help_routing"]["message"]
                .as_str()
                .unwrap_or_default()
                .is_empty(),
            "the help routing names its message: {answer}"
        );
        assert_eq!(
            answer["help_routing"]["category"]["category"].as_str(),
            Some("owner_policy"),
            "the help routing names the plane: {answer}"
        );
        assert_eq!(
            answer["help_routing"]["category"]["sub"]["row_ref"].as_str(),
            Some("row-help"),
            "the help routing names its row: {answer}"
        );
        assert_verdict_row(&answer, "row-help");
    });
}

/// Skipped is not Allow, and a plane that is off is silent: plane off
/// answers Allow with no receipt, while plane on with no rows and no
/// document answers Skipped with one.
///
/// Canon arch-0047:25 (mirror :366791):
/// "The verdict arms are Allow, Warn, Block and RouteToHelp."
/// Plus the engine's honest seventh arm.
#[test]
fn skipped_is_not_allow_and_plane_off_is_silent() {
    run_on_engine_stack("policy-skipped-silent", || async {
        let fixture = setup().await;
        let silent = "Nothing matches here and the plane is off.";
        let (status, answer) = decide_as_person(&fixture, silent).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the plane-off content is decided: {answer}"
        );
        assert_eq!(
            answer["action"].as_str(),
            Some("allow"),
            "plane off allows: {answer}"
        );
        assert_eq!(
            answer["verdict"]["decision"].as_str(),
            Some("allow"),
            "the verdict is Allow: {answer}"
        );
        assert!(
            answer["receipt_ref"].is_null(),
            "plane off writes no receipt: {answer}"
        );
        assert_eq!(
            answer["final_content"].as_str(),
            Some(silent),
            "plane off delivers the bytes: {answer}"
        );
        assert_eq!(
            answer["outbound_halted"].as_bool(),
            Some(false),
            "plane off halts nothing: {answer}"
        );

        let (status, view) = owner_get(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner reads the policy: {view}");
        let read_hash = view["body_hash"].as_str().expect("body hash").to_owned();
        let configuration = json!({"owner_policy_enabled": true, "owner_policy_patterns": []});
        let (status, enabled) = owner_configure(&fixture, &read_hash, configuration).await;
        assert_eq!(status, StatusCode::OK, "owner enables the plane: {enabled}");

        let unread = "Nothing matches here and the plane is on.";
        let (status, answer) = decide_as_person(&fixture, unread).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the unmatched content is decided: {answer}"
        );
        assert_eq!(
            answer["action"].as_str(),
            Some("skipped"),
            "no rows and no document skips: {answer}"
        );
        assert_eq!(
            answer["verdict"]["decision"],
            json!({"skipped": "no-document"}),
            "the verdict is Skipped for no document: {answer}"
        );
        assert!(
            answer["receipt_ref"]
                .as_str()
                .is_some_and(|held| held.starts_with("gate:")),
            "the skip is receipted: {answer}"
        );
        assert_eq!(
            answer["final_content"].as_str(),
            Some(unread),
            "Skipped delivers the bytes: {answer}"
        );
        assert_eq!(
            answer["custom_tier_skipped"].as_bool(),
            Some(true),
            "the skip is marked: {answer}"
        );
        assert_eq!(
            answer["outbound_halted"].as_bool(),
            Some(false),
            "Skipped halts nothing: {answer}"
        );
    });
}

/// The decision receipt stores the content hash, never the plaintext: the
/// stored row's bytes hold no canary, and its hash equals the verdict's.
///
/// Canon arch-0047:47 (mirror generated/llms-full.txt:366813):
/// "The receipt stores the hash, never the plaintext,"
#[test]
fn receipt_holds_hash_never_plaintext() {
    run_on_engine_stack("policy-receipt-hash", || async {
        let fixture = setup().await;
        let change = json!({"Add": {
            "row_ref": "row-warn",
            "text": "Warn on draft leaks.",
            "action": "warn",
            "scope": "Vault",
        }});
        let (status, landed) = owner_row_change(&fixture, change).await;
        assert_eq!(status, StatusCode::OK, "owner adds a row: {landed}");
        let (status, view) = owner_get(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner reads the policy: {view}");
        let read_hash = view["body_hash"].as_str().expect("body hash").to_owned();
        let patterns = json!([
            {"id": "pat-warn", "pattern": "CANARY-7F3A9D2E", "category": "row-warn",
                "role": "decide"},
        ]);
        let configuration =
            json!({"owner_policy_enabled": true, "owner_policy_patterns": patterns});
        let (status, enabled) = owner_configure(&fixture, &read_hash, configuration).await;
        assert_eq!(status, StatusCode::OK, "owner enables the plane: {enabled}");

        let canary = "CANARY-7F3A9D2E-THREADS-THE-LEDGER";
        let content = format!("A Warn row judges this line: {canary} flies at dawn.");
        let (status, answer) = decide_as_person(&fixture, &content).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the canary content is decided: {answer}"
        );
        assert_eq!(
            answer["action"].as_str(),
            Some("warn"),
            "the Warn row warns: {answer}"
        );
        assert_eq!(
            answer["final_content"].as_str(),
            Some(content.as_str()),
            "Warn delivers the bytes: {answer}"
        );
        let receipt_ref = answer["receipt_ref"]
            .as_str()
            .expect("receipt ref")
            .to_owned();
        let wanted = receipt_ref
            .strip_prefix("gate:")
            .expect("gate receipt")
            .to_owned();

        let rows = fixture.vault.gate_decisions(50).expect("gate rows");
        let found = rows
            .iter()
            .find(|row| row.decision_id.to_hex() == wanted)
            .expect("the decide receipt row");
        let stored = serde_json::to_value(found).expect("row json");
        let stored_bytes = serde_json::to_string(&stored).expect("row bytes");
        assert!(
            !stored_bytes.contains(canary),
            "the ledger holds no plaintext: {stored_bytes}"
        );
        // `diff_handle` is a plain `Vec<u8>`, so it serializes as a JSON
        // number array the string search above can never see: compare the
        // arrays directly, or F5 (content bytes in the row) would pass.
        let content_bytes = json!(content.as_bytes());
        assert_ne!(
            stored["diff_handle"], content_bytes,
            "the ledger holds no plaintext bytes: {stored_bytes}"
        );
        assert_ne!(
            stored["read_frontier_hash"], content_bytes,
            "the frontier holds no plaintext bytes: {stored_bytes}"
        );
        assert_eq!(
            stored["diff_handle"], answer["verdict"]["binding"]["content_hash"],
            "the ledger holds the verdict's hash: {stored_bytes}"
        );
    });
}

/// Every refusal names its status, code, message and layer: the owner doors
/// refuse person, agent and narrowed-host callers, and every scope,
/// record-scope, hash, row-key, actor, session and preflight refusal answers
/// its own row.
///
/// Canon dec-0005:8 (mirror :362815):
/// "Holders change rows at once; agents propose."
/// An agent at an owner door is refused, never proposed through.
#[test]
fn refusals_table() {
    run_on_engine_stack("policy-refusals", || async {
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

        for (verb, input) in owner_rows() {
            let path = format!("/v1/core/facade/{verb}");
            let (status, refused) = post_as_person(&fixture, &path, input).await;
            assert_owner_refusal(status, &refused, verb);
        }
        for (verb, input) in owner_rows() {
            let path = format!("/v1/core/facade/{verb}");
            let (status, refused) = post_as_agent(&fixture, &path, input).await;
            assert_owner_refusal(status, &refused, verb);
        }
        let (narrowed_token, narrowed_binding) = mint_narrowed_host_token(&fixture);
        for (verb, input) in owner_rows() {
            let path = format!("/v1/core/facade/{verb}");
            let (status, refused) = post(
                &fixture,
                &path,
                &narrowed_token,
                narrowed_binding.clone(),
                input,
            )
            .await;
            assert_owner_refusal(status, &refused, verb);
        }

        let (read_token, read_binding) =
            mint_token_for(&fixture, fixture.person, "human", &["read"], None);
        let (status, refused) = post(
            &fixture,
            "/v1/core/facade/vault.policy.owner.get",
            &read_token,
            read_binding.clone(),
            json!({}),
        )
        .await;
        assert_owner_refusal(status, &refused, "vault.policy.owner.get");
        for (verb, input) in owner_rows().into_iter().skip(1) {
            let path = format!("/v1/core/facade/{verb}");
            let (status, refused) =
                post(&fixture, &path, &read_token, read_binding.clone(), input).await;
            assert_scope_refusal(status, &refused, verb);
        }

        let facet = EntityId::now();
        fixture
            .vault
            .put_entity(
                &facet,
                ENTITY_TYPE_FACET,
                TimeRange { start: 1, end: 1 },
                1,
                b"facet",
            )
            .expect("a facet");
        let (facet_token, facet_binding) = mint_token_for(
            &fixture,
            fixture.person,
            "human",
            &["read", "write"],
            Some(facet),
        );
        let (status, refused) = post(
            &fixture,
            "/v1/core/facade/vault.policy.owner.get",
            &facet_token,
            facet_binding,
            json!({}),
        )
        .await;
        assert_scope_refusal(status, &refused, "vault.policy.owner.get");

        let (status, view) = owner_get(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner reads the policy: {view}");
        let read_hash = view["body_hash"].as_str().expect("body hash").to_owned();

        let (status, refused) =
            owner_configure(&fixture, "unused", json!({"owner_policy_enabled": false})).await;
        assert_bad_request(
            status,
            &refused,
            "invalid config: expected_body_hash must match the current policy manifest",
            "a stale hash is refused",
        );
        let (status, refused) = owner_configure(
            &fixture,
            &read_hash,
            json!({
                "owner_policy_enabled": true,
                "owner_policy_document": "A policy with no contract.",
            }),
        )
        .await;
        assert_bad_request(
            status,
            &refused,
            "invalid config: a policy document and output contract must be supplied together",
            "a document alone is refused",
        );

        let (status, refused) = owner_row_change(
            &fixture,
            json!({"Add": {
                "row_ref": "",
                "text": "Some text.",
                "action": "block",
                "scope": "Vault",
            }}),
        )
        .await;
        assert_bad_request(
            status,
            &refused,
            "invalid config: empty owner policy row key",
            "an empty key is refused",
        );

        let change = json!({"Add": {
            "row_ref": "dup-row",
            "text": "First write wins.",
            "action": "block",
            "scope": "Vault",
        }});
        let (status, landed) = owner_row_change(&fixture, change).await;
        assert_eq!(status, StatusCode::OK, "owner adds dup-row: {landed}");
        let change = json!({"Add": {
            "row_ref": "dup-row",
            "text": "Second write loses.",
            "action": "warn",
            "scope": "Vault",
        }});
        let (status, refused) = owner_row_change(&fixture, change).await;
        assert_bad_request(
            status,
            &refused,
            "invalid config: owner policy row already exists",
            "an occupied key is refused",
        );
        let (status, refused) = owner_row_change(
            &fixture,
            json!({"Add": {
                "row_ref": "empty-text-row",
                "text": "",
                "action": "warn",
                "scope": "Vault",
            }}),
        )
        .await;
        assert_bad_request(
            status,
            &refused,
            "invalid config: empty owner policy row text",
            "empty text is refused",
        );
        let (status, refused) = owner_row_change(
            &fixture,
            json!({"Edit": {
                "row_ref": "dup-row",
                "text": "",
                "action": "warn",
                "scope": "Vault",
            }}),
        )
        .await;
        assert_bad_request(
            status,
            &refused,
            "invalid config: empty owner policy row text",
            "an empty edit is refused",
        );
        let (status, refused) = owner_row_change(
            &fixture,
            json!({"Edit": {
                "row_ref": "no-such-row",
                "text": "Some text.",
                "action": "warn",
                "scope": "Vault",
            }}),
        )
        .await;
        assert_bad_request(
            status,
            &refused,
            "invalid config: owner policy row does not exist",
            "editing a missing row is refused",
        );
        let (status, refused) = owner_row_change(
            &fixture,
            json!({"Remove": {"row_ref": "no-such-row", "scope": "Vault"}}),
        )
        .await;
        assert_bad_request(
            status,
            &refused,
            "invalid config: owner policy row does not exist",
            "removing a missing row is refused",
        );

        let stranger = EntityId::now();
        let (stranger_token, stranger_binding) =
            mint_token_for(&fixture, stranger, "human", &["read", "write"], None);
        let (status, refused) = post(
            &fixture,
            "/v1/core/facade/vault.policy.outbound.decide",
            &stranger_token,
            stranger_binding,
            json!({"subject": "outbound_content", "content": "A stranger knocks."}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a stranger is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("FORBIDDEN"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some(format!(
                "bound actor {} does not exist in this vault",
                stranger.to_hex()
            ))
            .as_deref(),
            "the refusal names the missing actor: {refused}"
        );

        let (mismatch_token, mismatch_binding) =
            mint_token_for(&fixture, fixture.person, "agent", &["read", "write"], None);
        let (status, refused) = post(
            &fixture,
            "/v1/core/facade/vault.policy.outbound.decide",
            &mismatch_token,
            mismatch_binding,
            json!({"subject": "outbound_content", "content": "A person wearing an agent mask."}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a masked caller is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("FORBIDDEN"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some(format!(
                "bound actor {} is a PERSON entity and cannot act as class agent",
                fixture.person.to_hex()
            ))
            .as_deref(),
            "the refusal names the mismatch: {refused}"
        );

        for body in [
            json!({"subject": "outbound_content"}),
            json!({"subject": "nonsense", "content": "Some content."}),
            json!({"subject": "outbound_content", "content": "Some content.", "extra": 1}),
        ] {
            let (status, refused) = post_as_person(
                &fixture,
                "/v1/core/facade/vault.policy.outbound.decide",
                body,
            )
            .await;
            assert_invalid_input(status, &refused, "a malformed decide is refused");
        }

        let (status, refused) =
            relay_decide_as_person(&fixture, "A relay with nothing bound.").await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "the unbound relay is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("INVALID_STATE"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("no authenticated hosted relay is bound to this server"),
            "the refusal names the missing relay: {refused}"
        );

        let session = EntityId::now();
        for verb in ["vault.policy.outbound.decide", "vault.policy.relay.decide"] {
            let path = format!("/v1/core/facade/{verb}");
            let (status, refused) = post_as_person_with_session(
                &fixture,
                &path,
                session,
                json!({"subject": "outbound_content", "content": "Off the record."}),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::CONFLICT,
                "{verb} off record is refused: {refused}"
            );
            assert_eq!(
                refused["error"]["code"].as_str(),
                Some("OFF_RECORD_SESSION_DOOR"),
                "the refusal names its code: {refused}"
            );
            assert_eq!(
                refused["error"]["message"].as_str(),
                Some("policy decisions write canonical hash-only receipts"),
                "the refusal names its reason: {refused}"
            );
        }

        let (status, refused) =
            preflight_as_person(&fixture, json!({"refs": [], "act": "read"})).await;
        assert_bad_request(
            status,
            &refused,
            "a preflight names at least one ref",
            "an empty preflight is refused",
        );
        let many: Vec<Value> = (0..101).map(|_| json!(EntityId::now().to_hex())).collect();
        let (status, refused) =
            preflight_as_person(&fixture, json!({"refs": many, "act": "read"})).await;
        assert_bad_request(
            status,
            &refused,
            "at most 100 refs per preflight",
            "an oversize preflight is refused",
        );
        let (status, refused) = preflight_as_person(
            &fixture,
            json!({"refs": [EntityId::now().to_hex()], "act": "nonsense"}),
        )
        .await;
        assert_invalid_input(status, &refused, "a bad preflight act is refused");
        let (status, refused) = preflight_as_person(
            &fixture,
            json!({"refs": [EntityId::now().to_hex()], "act": "read", "extra": 1}),
        )
        .await;
        assert_invalid_input(
            status,
            &refused,
            "a preflight with an unknown key is refused",
        );

        let absent = EntityId::now().to_hex();
        let (status, answer) =
            preflight_as_person(&fixture, json!({"refs": [absent.clone()], "act": "read"})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an unreadable ref is answered, not refused: {answer}"
        );
        assert_eq!(
            answer["value"]["act"].as_str(),
            Some("read"),
            "the preflight echoes its act: {answer}"
        );
        assert_eq!(
            answer["value"]["refs"][0]["status"].as_str(),
            Some("withheld"),
            "the absent ref is withheld: {answer}"
        );
        assert_eq!(
            answer["value"]["refs"][0]["entity"].as_str(),
            Some(absent.as_str()),
            "the withheld ref echoes its id: {answer}"
        );
    });
}
