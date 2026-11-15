//! Restriction wave 7 over the real watch route (C32): an agent keeps its OWN memory watch
//! while the owner's setting `memory.watch.agent_may_watch` is on. With the key on and the
//! agent's grant naming `read`, the agent sets, reads and clears its watch on a claim it can
//! read; its watch is its own, never the owner's. With the key absent the agent keeps today's
//! refusal, and a claim its read cannot see answers today's not-found.
//!
//! Each case owns its vault: an in-process vault served over the real router (`oneshot`, no TCP
//! ports, no sleeps, no models), a paired agent credential, an owner grant minted over
//! `vault.agents.grants.mint`, the key set over `vault.settings.set` as the owner, and a claim
//! seeded in process. The owner acts on a person-bound owner-grade human slip minted from the
//! host root's claims, since the host root itself carries no human class.
//!
//! Red on the base by refusal: with the key on and the grant naming `read`, the agent's watch
//! answers 403 there (the route takes an owner-grade human alone), 200 here. The suite calls no
//! test door. It needs `oneiron/test-support` for `MemoryKeystore`, as its template does.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test restriction_wave7_watch`.
#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_PERSON, TypeByteFamily};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const WATCH_KEY: &str = "memory.watch.agent_may_watch";
/// A verb that is not `read`, for the grant that names no read.
const OTHER_VERB: &str = "vault.runs.review";
/// When the seeded claims and their subject were learned and hold.
const LEARNED_AT: u64 = 1_780_000_000;

/// One holder credential: its registered principal, its holder signing key,
/// its slip and the token it presents.
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
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn setup(auth_secret: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
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
    vault
        .prepare_install_signing()
        .expect("this install's signing keys");
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let app = build_app(server);
    Fixture {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
    }
}

/// Pairs one agent the way `token agent` does: a registered PERSON
/// principal, a principal-bound link narrowed to `core:read`/`core:write`,
/// redeemed over the real pairing route with the holder-signed binding
/// transcript.
async fn pair_agent(fixture: &Fixture, name: &str, seed: [u8; 32]) -> Agent {
    let principal = fixture
        .vault
        .ensure_agent_principal(name)
        .expect("agent principal");
    let holder = SigningKey::from_bytes(&seed);
    let binding_key = holder.verifying_key().to_bytes();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let link = fixture
        .vault
        .issue_pairing_link_for_principal(
            &fixture.issuer,
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
    let response = fixture
        .app
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

/// The vault owner's own watch credential: the embedded owner, on a human slip minted from
/// the host root's top-scope claims. The host root itself carries no human class, so it never
/// reaches the watch route; this slip keeps its full scope, which keeps it owner-grade.
fn owner_person(fixture: &Fixture, seed: u8) -> Agent {
    let owner = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("embedded owner");
    let holder = SigningKey::from_bytes(&[seed; 32]);
    let mut claims = fixture.owner_slip.claims.clone();
    claims.slip_id = [seed; 32];
    claims.parent_id = None;
    claims.holder_ref = owner.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = holder.verifying_key().to_bytes();
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("the owner's person slip");
    let token = slip.to_token().expect("owner person token");
    Agent {
        principal: owner,
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

async fn post(
    fixture: &Fixture,
    verb: &str,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::post(format!("/v1/core/facade/{verb}"))
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
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

async fn as_owner(fixture: &Fixture, verb: &str, body: Value) -> (StatusCode, Value) {
    post(
        fixture,
        verb,
        &fixture.owner_token,
        owner_binding(fixture),
        body,
    )
    .await
}

/// One watch-route call: GET, PUT or DELETE over `/v1/core/memory/{claim}/watch`.
async fn watch(
    fixture: &Fixture,
    method: &str,
    claim_hex: &str,
    token: &str,
    binding: String,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(format!("/v1/core/memory/{claim_hex}/watch"))
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
        .body(Body::empty())
        .expect("watch request");
    let response = fixture
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("watch response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("watch response body");
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
    (status, body)
}

async fn watch_as(
    fixture: &Fixture,
    method: &str,
    claim_hex: &str,
    agent: &Agent,
) -> (StatusCode, Value) {
    watch(
        fixture,
        method,
        claim_hex,
        &agent.token,
        agent_binding(fixture, agent),
    )
    .await
}

/// The owner mints `agent` a grant naming `read` and `verbs`; returns its grant ref.
async fn mint_grant(fixture: &Fixture, agent_hex: &str, verbs: &[&str]) -> String {
    let values: Vec<String> = std::iter::once("read".to_owned())
        .chain(verbs.iter().map(|verb| (*verb).to_owned()))
        .collect();
    let (status, body) = as_owner(
        fixture,
        "vault.agents.grants.mint",
        json!({
            "agent": agent_hex,
            "authority_scope": {
                "worlds": {"kind": "all"},
                "facets": {"kind": "all"},
                "bands": {"kind": "all"},
                "audience": {"kind": "all"},
                "verbs": {"kind": "some", "values": values},
                "sensitivity": {"kind": "at_most", "value": "restricted"},
            },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mint the grant: {body}");
    assert_eq!(body["grant"]["agent"].as_str(), Some(agent_hex), "{body}");
    assert_eq!(body["grant"]["confers"].as_bool(), Some(true), "{body}");
    body["grant"]["grant_ref"]
        .as_str()
        .expect("minted grant ref")
        .to_owned()
}

/// The owner mints `agent` a grant naming one verb that is not `read`: the narrowest grant
/// the mint admits whose read sees nothing. It confers no read.
async fn mint_grant_without_read(fixture: &Fixture, agent_hex: &str, verb: &str) -> String {
    let (status, body) = as_owner(
        fixture,
        "vault.agents.grants.mint",
        json!({
            "agent": agent_hex,
            "authority_scope": {
                "worlds": {"kind": "all"},
                "facets": {"kind": "all"},
                "bands": {"kind": "all"},
                "audience": {"kind": "all"},
                "verbs": {"kind": "some", "values": [verb]},
                "sensitivity": {"kind": "at_most", "value": "restricted"},
            },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mint the narrow grant: {body}");
    assert_eq!(body["grant"]["agent"].as_str(), Some(agent_hex), "{body}");
    assert_eq!(
        body["grant"]["confers"].as_bool(),
        Some(false),
        "a grant without read confers no read: {body}"
    );
    body["grant"]["grant_ref"]
        .as_str()
        .expect("minted grant ref")
        .to_owned()
}

/// The owner turns `key` on at the vault scope.
async fn turn_key_on(fixture: &Fixture, key: &str) {
    let (status, body) = as_owner(
        fixture,
        "vault.settings.set",
        json!({ "key": key, "scope": {"kind": "vault"}, "value": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "turn {key} on: {body}");
    assert_eq!(body["status"].as_str(), Some("applied"), "{body}");
    assert_eq!(body["value"], json!(true), "{body}");
}

/// One active claim about a seeded PERSON, written in process; returns its 32-hex id.
fn seed_claim(fixture: &Fixture) -> String {
    oneiron::campaign::register_crm_pack(&fixture.vault, 107, 108, TypeByteFamily::Productivity)
        .expect("register the CRM pack");
    let subject = EntityId::now();
    fixture
        .vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            b"watch claim subject",
        )
        .expect("claim subject");
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from("lanternwick"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    fixture
        .vault
        .put_claim(
            &id,
            &body,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
        )
        .expect("seed the claim");
    id.to_hex()
}

fn assert_forbidden(status: &StatusCode, body: &Value, what: &str) {
    assert_eq!(*status, StatusCode::FORBIDDEN, "{what}: {body}");
    assert_eq!(body["error"]["code"], "FORBIDDEN", "{what}: {body}");
}

fn assert_not_found(status: &StatusCode, body: &Value, what: &str) {
    assert_eq!(*status, StatusCode::NOT_FOUND, "{what}: {body}");
    assert_eq!(body["error"]["code"], "NOT_FOUND", "{what}: {body}");
}

/// C32 red: key on, the agent's grant names `read`, and the agent sets, reads and clears its
/// own watch. 403 on the base.
#[test]
fn c32_agent_sets_reads_and_clears_its_own_watch_when_key_on() {
    run_on_engine_stack("wave7-c32-own-watch", || async {
        let fixture = setup("wave7-c32-own-watch").await;
        let claim = seed_claim(&fixture);
        let agent = pair_agent(&fixture, "wave7-watch-keeper", [0xC1; 32]).await;
        turn_key_on(&fixture, WATCH_KEY).await;
        mint_grant(&fixture, &agent.principal.to_hex(), &[]).await;

        let (status, body) = watch_as(&fixture, "PUT", &claim, &agent).await;
        assert_eq!(status, StatusCode::OK, "agent sets its watch: {body}");
        assert_eq!(body["watched"], true, "{body}");
        let query_ref = body["query_ref"]
            .as_str()
            .expect("set watch ref")
            .to_owned();

        let (status, body) = watch_as(&fixture, "GET", &claim, &agent).await;
        assert_eq!(status, StatusCode::OK, "agent reads its watch: {body}");
        assert_eq!(body["watched"], true, "{body}");
        assert_eq!(
            body["query_ref"].as_str(),
            Some(query_ref.as_str()),
            "{body}"
        );

        let (status, body) = watch_as(&fixture, "DELETE", &claim, &agent).await;
        assert_eq!(status, StatusCode::OK, "agent clears its watch: {body}");
        assert_eq!(body["watched"], false, "{body}");

        let (status, body) = watch_as(&fixture, "GET", &claim, &agent).await;
        assert_eq!(status, StatusCode::OK, "cleared watch reads off: {body}");
        assert_eq!(body["watched"], false, "{body}");
    });
}

/// C32 guard: key absent, the agent's grant names `read`, and the agent keeps today's
/// refusal on set and read.
#[test]
fn c32_agent_refused_watch_when_key_absent() {
    run_on_engine_stack("wave7-c32-key-absent", || async {
        let fixture = setup("wave7-c32-key-absent").await;
        let claim = seed_claim(&fixture);
        let agent = pair_agent(&fixture, "wave7-watch-absent", [0xC2; 32]).await;
        mint_grant(&fixture, &agent.principal.to_hex(), &[]).await;

        let (status, body) = watch_as(&fixture, "PUT", &claim, &agent).await;
        assert_forbidden(&status, &body, "set with the key absent");
        let (status, body) = watch_as(&fixture, "GET", &claim, &agent).await;
        assert_forbidden(&status, &body, "read with the key absent");
    });
}

/// C32 guard and red: the owner's watch is the owner's. The owner sets one; the key goes on;
/// the agent reads no watch of its own, sets one under another ref, clears it, and the
/// owner's watch still stands. The agent's read is 403 on the base.
#[test]
fn c32_agent_watch_is_its_own_not_the_owners() {
    run_on_engine_stack("wave7-c32-not-owners", || async {
        let fixture = setup("wave7-c32-not-owners").await;
        let claim = seed_claim(&fixture);
        let owner = owner_person(&fixture, 0x0E);

        let (status, body) = watch_as(&fixture, "PUT", &claim, &owner).await;
        assert_eq!(status, StatusCode::OK, "owner sets its watch: {body}");
        assert_eq!(body["watched"], true, "{body}");
        let owner_ref = body["query_ref"].as_str().expect("owner ref").to_owned();

        turn_key_on(&fixture, WATCH_KEY).await;
        let agent = pair_agent(&fixture, "wave7-watch-other", [0xC3; 32]).await;
        mint_grant(&fixture, &agent.principal.to_hex(), &[]).await;

        let (status, body) = watch_as(&fixture, "GET", &claim, &agent).await;
        assert_eq!(status, StatusCode::OK, "agent reads its own watch: {body}");
        assert_eq!(
            body["watched"], false,
            "the owner's watch is not its own: {body}"
        );

        let (status, body) = watch_as(&fixture, "PUT", &claim, &agent).await;
        assert_eq!(status, StatusCode::OK, "agent sets its watch: {body}");
        assert_eq!(body["watched"], true, "{body}");
        let agent_ref = body["query_ref"].as_str().expect("agent ref").to_owned();
        assert_ne!(agent_ref, owner_ref, "each watcher holds its own ref");

        let (status, body) = watch_as(&fixture, "DELETE", &claim, &agent).await;
        assert_eq!(status, StatusCode::OK, "agent clears its watch: {body}");
        assert_eq!(body["watched"], false, "{body}");

        let (status, body) = watch_as(&fixture, "GET", &claim, &owner).await;
        assert_eq!(status, StatusCode::OK, "owner reads its watch: {body}");
        assert_eq!(body["watched"], true, "{body}");
        assert_eq!(
            body["query_ref"].as_str(),
            Some(owner_ref.as_str()),
            "{body}"
        );
    });
}

/// C32 guard: key on, the agent's grant names no `read`, and its set answers today's
/// not-found for a claim it cannot read.
#[test]
fn c32_agent_without_read_of_the_claim_is_refused() {
    run_on_engine_stack("wave7-c32-no-read", || async {
        let fixture = setup("wave7-c32-no-read").await;
        let claim = seed_claim(&fixture);
        let agent = pair_agent(&fixture, "wave7-watch-blind", [0xC4; 32]).await;
        turn_key_on(&fixture, WATCH_KEY).await;
        mint_grant_without_read(&fixture, &agent.principal.to_hex(), OTHER_VERB).await;

        let (status, body) = watch_as(&fixture, "PUT", &claim, &agent).await;
        assert_not_found(&status, &body, "set of a claim the read cannot see");
    });
}
