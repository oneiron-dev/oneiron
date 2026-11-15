//! Restriction wave 7 over the real facade routes (C24, C28, C41): an agent whose own live owner
//! grant names the verb reads a run's review, settlement and changes while the owner's setting
//! `memory.run_review.agent_may_read` is on, and reads hook regen due while
//! `memory.hook_regen.agent_may_adopt` is on. Settle, revert and the restore-group path stay
//! owner-only; a differing regen candidate still needs the owner's stamp (no served fixture
//! builds a regen candidate, so adopt is not exercised here). The creator of a stretch entered
//! alone puts it on record (`vault.off_record.save_from_here`) while
//! `off_record.flip_alone.by_holder` is on, and the saving stops at the next landing once it is
//! off; nobody else's stretch is reachable.
//!
//! Each case owns its vault: an in-process vault served over the real router (`oneshot`, no TCP
//! ports, no sleeps, no models), a paired agent credential, an owner grant minted over
//! `vault.agents.grants.mint`, the key set over `vault.settings.set` as the owner, and a claim
//! the agent proposed in process for the run review to read. The owner acts on its host-root
//! credential, the established self-hosted owner path.
//!
//! Red on the base by refusal: with the key on and the grant naming the verb, the agent's read
//! answers 403 there (the doors take the owner's proof alone), 200 here. The suite calls no
//! test door. It needs `oneiron/test-support` for `MemoryKeystore`, as its template does.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features oneiron/test-support --test restriction_wave7_served`.
#[path = "support/engine_stack.rs"]
mod engine_stack;

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
use oneiron::memory::run_review::{
    RunReviewChange, RunReviewRequest, RunSettleDecision, RunSettleRequest,
};
use oneiron::memory::{ClaimInput, resolve_entity_ref};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{AgentDefinitionCreateRequest, create_agent_definition_as};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use tower::ServiceExt;

const RUN_KEY: &str = "memory.run_review.agent_may_read";
const REGEN_KEY: &str = "memory.hook_regen.agent_may_adopt";
const REVIEW_VERB: &str = "vault.runs.review";
const SETTLEMENT_VERB: &str = "vault.runs.settlement";
const CHANGES_VERB: &str = "vault.runs.changes.get";
const SETTLE_VERB: &str = "vault.runs.settle";
const DUE_VERB: &str = "vault.hooks.regen.due";

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

async fn as_agent(
    fixture: &Fixture,
    agent: &Agent,
    verb: &str,
    body: Value,
) -> (StatusCode, Value) {
    post(
        fixture,
        verb,
        &agent.token,
        agent_binding(fixture, agent),
        body,
    )
    .await
}

/// The owner mints `agent` a grant naming `read` and `verbs`; returns its
/// grant ref.
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

/// The agent proposes one claim in process, for the run review to read;
/// returns its 32-hex id.
fn propose_claim(fixture: &Fixture, agent: &Agent) -> String {
    let owner = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("embedded owner");
    let proof = fixture
        .vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    fixture
        .vault
        .grant_foreign_principal(&proof, &agent.principal.to_hex())
        .expect("the owner grants the proposer read and propose");
    let subject = fixture
        .vault
        .ensure_agent_principal("wave7-claim-subject")
        .expect("claim subject");
    let facet = fixture.vault.default_facet().expect("default facet");
    let receipt = fixture
        .vault
        .memory(agent.principal, EdgeActorClass::Agent)
        .claim_propose(&ClaimInput {
            id: None,
            predicate: "profile.name".to_owned(),
            subject_ref: subject.to_hex(),
            value: json!("Wave Seven"),
            confidence: 1.0,
            confidence_details: None,
            source: "observed".to_owned(),
            world_ref: None,
            relationship_ref: None,
            scope: Some(json!({ "facet": facet.to_hex() })),
            valid_from: Some(100),
            valid_to: None,
            occurred_at: None,
            learned_at: None,
            salience: None,
        })
        .expect("agent proposal");
    assert_eq!(receipt.approval, "proposed");
    resolve_entity_ref(&fixture.vault, &receipt.claim_short_id)
        .expect("proposal id")
        .to_hex()
}

fn review_request(claim_hex: &str) -> Value {
    json!({
        "run_id": "run:wave7-c28",
        "changes": [{"kind": "claim", "claim_ref": claim_hex}],
    })
}

/// The owner reviews and settles the run in process; returns the review id.
fn owner_review_and_settle(fixture: &Fixture, claim_hex: &str) -> String {
    let owner = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("embedded owner");
    let proof = fixture
        .vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let memory = fixture.vault.memory(owner, EdgeActorClass::Human);
    let request = RunReviewRequest {
        run_id: "run:wave7-c28".to_owned(),
        changes: vec![RunReviewChange::Claim {
            claim_ref: claim_hex.to_owned(),
        }],
    };
    let review = memory
        .review_run_as_owner(&proof, &request)
        .expect("owner run review");
    assert_eq!(review.changes.len(), 1);
    memory
        .settle_run_as_owner(
            &proof,
            &RunSettleRequest {
                review: request,
                review_id: review.review_id.clone(),
                decision: RunSettleDecision::Approve,
            },
        )
        .expect("the owner's run approval lands");
    review.review_id
}

fn assert_forbidden(status: &StatusCode, body: &Value, what: &str) {
    assert_eq!(*status, StatusCode::FORBIDDEN, "{what}: {body}");
    assert_eq!(body["error"]["code"], "FORBIDDEN", "{what}: {body}");
}

/// C28 red: key on, the agent's grant names `vault.runs.review`, and the
/// agent reads the run's review. 403 on the base.
#[test]
fn c28_agent_with_grant_reads_run_review_when_key_on() {
    run_on_engine_stack("wave7-c28-review", || async {
        let fixture = setup("wave7-c28-review").await;
        let agent = pair_agent(&fixture, "wave7-review-reader", [0x31; 32]).await;
        let claim = propose_claim(&fixture, &agent);
        turn_key_on(&fixture, RUN_KEY).await;
        mint_grant(&fixture, &agent.principal.to_hex(), &[REVIEW_VERB]).await;

        // Positive control: the owner reads the review.
        let (status, owner_body) = as_owner(&fixture, REVIEW_VERB, review_request(&claim)).await;
        assert_eq!(status, StatusCode::OK, "owner review: {owner_body}");

        let (status, body) = as_agent(&fixture, &agent, REVIEW_VERB, review_request(&claim)).await;
        assert_eq!(status, StatusCode::OK, "granted agent review: {body}");
        assert_eq!(body["changes"].as_array().map(Vec::len), Some(1), "{body}");
        assert_eq!(
            body["review_id"].as_str(),
            owner_body["review_id"].as_str(),
            "the agent reads what the owner reads: {body}"
        );
    });
}

/// C28 red: key on, the agent's grant names `vault.runs.changes.get`, and
/// the agent lists the run's changes. 403 on the base.
#[test]
fn c28_agent_with_grant_reads_run_changes_when_key_on() {
    run_on_engine_stack("wave7-c28-changes", || async {
        let fixture = setup("wave7-c28-changes").await;
        let agent = pair_agent(&fixture, "wave7-changes-reader", [0x32; 32]).await;
        propose_claim(&fixture, &agent);
        turn_key_on(&fixture, RUN_KEY).await;
        mint_grant(&fixture, &agent.principal.to_hex(), &[CHANGES_VERB]).await;

        let (status, body) = as_agent(
            &fixture,
            &agent,
            CHANGES_VERB,
            json!({ "run_id": "run:wave7-c28" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "granted agent changes: {body}");
        assert!(body["changes"].is_array(), "{body}");
    });
}

/// C28 red: a settlement exists, the key is on, the agent's grant names
/// `vault.runs.settlement`, and the agent reads it. 403 on the base.
#[test]
fn c28_agent_with_grant_reads_run_settlement_when_key_on() {
    run_on_engine_stack("wave7-c28-settlement", || async {
        let fixture = setup("wave7-c28-settlement").await;
        let agent = pair_agent(&fixture, "wave7-settlement-reader", [0x33; 32]).await;
        let claim = propose_claim(&fixture, &agent);
        owner_review_and_settle(&fixture, &claim);
        turn_key_on(&fixture, RUN_KEY).await;
        mint_grant(&fixture, &agent.principal.to_hex(), &[SETTLEMENT_VERB]).await;

        let (status, body) = as_agent(
            &fixture,
            &agent,
            SETTLEMENT_VERB,
            json!({ "run_id": "run:wave7-c28" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "granted agent settlement: {body}");
        assert_eq!(body["changes"].as_array().map(Vec::len), Some(1), "{body}");
    });
}

/// C28 guard: key absent, the agent's grant names the verb, and the agent
/// keeps today's refusal.
#[test]
fn c28_agent_refused_run_review_when_key_absent() {
    run_on_engine_stack("wave7-c28-key-absent", || async {
        let fixture = setup("wave7-c28-key-absent").await;
        let agent = pair_agent(&fixture, "wave7-key-absent", [0x34; 32]).await;
        let claim = propose_claim(&fixture, &agent);
        mint_grant(&fixture, &agent.principal.to_hex(), &[REVIEW_VERB]).await;

        let (status, body) = as_agent(&fixture, &agent, REVIEW_VERB, review_request(&claim)).await;
        assert_forbidden(&status, &body, "review with the key absent");
    });
}

/// C28 guard: key on, the agent's grant names another verb, and the agent
/// is refused the review.
#[test]
fn c28_agent_refused_run_review_when_grant_lacks_verb() {
    run_on_engine_stack("wave7-c28-grant-lacks", || async {
        let fixture = setup("wave7-c28-grant-lacks").await;
        let agent = pair_agent(&fixture, "wave7-grant-lacks", [0x35; 32]).await;
        let claim = propose_claim(&fixture, &agent);
        turn_key_on(&fixture, RUN_KEY).await;
        mint_grant(&fixture, &agent.principal.to_hex(), &[CHANGES_VERB]).await;

        let (status, body) = as_agent(&fixture, &agent, REVIEW_VERB, review_request(&claim)).await;
        assert_forbidden(&status, &body, "review with a grant lacking the verb");
    });
}

/// C28 guard: key on, and the agent's settle is still refused.
#[test]
fn c28_agent_still_refused_run_settle_when_key_on() {
    run_on_engine_stack("wave7-c28-settle", || async {
        let fixture = setup("wave7-c28-settle").await;
        let agent = pair_agent(&fixture, "wave7-settler", [0x36; 32]).await;
        let claim = propose_claim(&fixture, &agent);
        let (status, owner_body) = as_owner(&fixture, REVIEW_VERB, review_request(&claim)).await;
        assert_eq!(status, StatusCode::OK, "owner review: {owner_body}");
        let review_id = owner_body["review_id"]
            .as_str()
            .expect("review id")
            .to_owned();
        turn_key_on(&fixture, RUN_KEY).await;
        mint_grant(&fixture, &agent.principal.to_hex(), &[SETTLE_VERB]).await;

        let (status, body) = as_agent(
            &fixture,
            &agent,
            SETTLE_VERB,
            json!({
                "review": review_request(&claim),
                "review_id": review_id,
                "decision": "approve",
            }),
        )
        .await;
        assert_forbidden(&status, &body, "settle by an agent with the key on");
    });
}

/// C41 red: key on, the agent's grant names `vault.hooks.regen.due`, and
/// the agent reads the due list. 403 on the base (and the key itself is
/// unknown there).
#[test]
fn c41_agent_with_grant_reads_regen_due_when_key_on() {
    run_on_engine_stack("wave7-c41-due", || async {
        let fixture = setup("wave7-c41-due").await;
        let agent = pair_agent(&fixture, "wave7-due-reader", [0x41; 32]).await;
        turn_key_on(&fixture, REGEN_KEY).await;
        mint_grant(&fixture, &agent.principal.to_hex(), &[DUE_VERB]).await;

        let (status, body) = as_agent(&fixture, &agent, DUE_VERB, json!({})).await;
        assert_eq!(status, StatusCode::OK, "granted agent due: {body}");
        assert!(body.is_array(), "the due list is a list: {body}");
    });
}

/// C41 guard: key absent, the agent's grant names the verb, and the agent
/// keeps today's refusal.
#[test]
fn c41_agent_refused_regen_due_when_key_absent() {
    run_on_engine_stack("wave7-c41-key-absent", || async {
        let fixture = setup("wave7-c41-key-absent").await;
        let agent = pair_agent(&fixture, "wave7-due-absent", [0x42; 32]).await;
        mint_grant(&fixture, &agent.principal.to_hex(), &[DUE_VERB]).await;

        let (status, body) = as_agent(&fixture, &agent, DUE_VERB, json!({})).await;
        assert_forbidden(&status, &body, "due with the key absent");
    });
}

const SOLO_KEY: &str = "off_record.flip_alone.by_holder";
const SOLO_SAVE_VERB: &str = "vault.off_record.save_from_here";

/// The owner turns `key` off at the vault scope.
async fn turn_key_off(fixture: &Fixture, key: &str) {
    let (status, body) = as_owner(
        fixture,
        "vault.settings.set",
        json!({ "key": key, "scope": {"kind": "vault"}, "value": false }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "turn {key} off: {body}");
    assert_eq!(body["status"].as_str(), Some("applied"), "{body}");
    assert_eq!(body["value"], json!(false), "{body}");
}

/// One of this vault's own agents (ARCH-0052 #d5-save-grant), as C24's
/// saver must be: an AGENT_DEF the owner creates, on a slip this vault mints
/// it from the root's claims, narrowed to `read`/`write`, unattenuated and
/// holder-bound. A paired principal is a PERSON row, not one of the vault's
/// agents, so it never holds the vault's write grant.
fn vault_agent(fixture: &Fixture, name: &str, seed: u8) -> Agent {
    let owner = fixture
        .vault
        .ensure_embedded_owner_actor()
        .expect("embedded owner");
    let proof = fixture
        .vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let principal = fixture.vault.new_entity_id().expect("agent id");
    create_agent_definition_as(
        &fixture.vault,
        &proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: principal,
            definition: serde_json::from_value(json!({
                "agent_id": name,
                "desc": "restriction wave 7 fixture",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("agent spec"),
        },
    )
    .expect("the owner creates the agent");
    let holder = SigningKey::from_bytes(&[seed; 32]);
    let mut claims = fixture.owner_slip.claims.clone();
    claims.slip_id = [seed; 32];
    claims.parent_id = None;
    claims.holder_ref = principal.to_hex();
    claims.actor_class = Some("agent".to_owned());
    claims.binding_key = holder.verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("the agent's slip");
    let token = slip.to_token().expect("agent token");
    Agent {
        principal,
        holder,
        slip,
        token,
    }
}

/// `agent` enters a stretch alone, off record, as its creator; returns the
/// handle `vault.off_record.start` answers as its `session_ref`.
async fn start_alone(fixture: &Fixture, agent: &Agent, name: &str) -> String {
    let (status, body) = as_agent(
        fixture,
        agent,
        "vault.off_record.start",
        json!({ "session_ref": name, "mode": "off_record", "backend": "local" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "start {name}: {body}");
    assert_eq!(body["mode"], "off_record", "{body}");
    body["session_ref"]
        .as_str()
        .expect("the stretch's handle")
        .to_owned()
}

/// The mode of the stretch `handle`, as the vault's owner reads it.
async fn owner_reads_mode(fixture: &Fixture, handle: &str) -> Value {
    let (status, body) = as_owner(
        fixture,
        "vault.off_record.status",
        json!({ "session_ref": handle }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "status {handle}: {body}");
    body["mode"].clone()
}

/// C24 red: key on, an agent puts the stretch it entered alone on record on
/// its own write slip. On the base no route lets it: the verb is absent.
#[test]
fn c24_creator_saves_its_stretch_from_here_when_key_on() {
    run_on_engine_stack("wave7-c24-save", || async {
        let fixture = setup("wave7-c24-save").await;
        let agent = vault_agent(&fixture, "wave7-solo-saver", 0x24);
        let handle = start_alone(&fixture, &agent, "solo").await;
        turn_key_on(&fixture, SOLO_KEY).await;

        let (status, body) = as_agent(
            &fixture,
            &agent,
            SOLO_SAVE_VERB,
            json!({ "session_ref": handle }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the creator saves from here: {body}"
        );
        assert_eq!(body["mode"], "on_record", "{body}");
        assert_eq!(owner_reads_mode(&fixture, &handle).await, "on_record");
    });
}

/// C24 guard: key absent, the creator's save from here is refused, and the
/// stretch stays off record.
#[test]
fn c24_creator_refused_save_from_here_when_key_absent() {
    run_on_engine_stack("wave7-c24-key-absent", || async {
        let fixture = setup("wave7-c24-key-absent").await;
        let agent = vault_agent(&fixture, "wave7-solo-absent", 0x25);
        let handle = start_alone(&fixture, &agent, "solo").await;

        let (status, body) = as_agent(
            &fixture,
            &agent,
            SOLO_SAVE_VERB,
            json!({ "session_ref": handle }),
        )
        .await;
        assert_forbidden(&status, &body, "save from here with the key absent");
        assert_eq!(owner_reads_mode(&fixture, &handle).await, "off_record");
    });
}

/// C24 guard: key on, an agent reaches neither another agent's stretch nor
/// the owner's: each answers as no stretch at all, and both stay off record.
#[test]
fn c24_agent_saves_neither_another_creators_stretch_nor_the_owners() {
    run_on_engine_stack("wave7-c24-strangers", || async {
        let fixture = setup("wave7-c24-strangers").await;
        let creator = vault_agent(&fixture, "wave7-solo-creator", 0x26);
        let stranger = vault_agent(&fixture, "wave7-solo-stranger", 0x27);
        let theirs = start_alone(&fixture, &creator, "solo").await;
        let (status, owners) = as_owner(
            &fixture,
            "vault.off_record.start",
            json!({ "session_ref": "owners-own", "mode": "off_record", "backend": "local" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the owner starts one: {owners}");
        let owners = owners["session_ref"]
            .as_str()
            .expect("the owner's stretch")
            .to_owned();
        turn_key_on(&fixture, SOLO_KEY).await;

        for handle in [&theirs, &owners] {
            let (status, body) = as_agent(
                &fixture,
                &stranger,
                SOLO_SAVE_VERB,
                json!({ "session_ref": handle }),
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{handle}: {body}");
            assert_eq!(owner_reads_mode(&fixture, handle).await, "off_record");
        }
    });
}

/// C24: every landing checks the key again. The creator saves from here
/// with the key on; the owner turns it off; the next turn that lands stops
/// the saving, and the stretch is off record again.
#[test]
fn c24_saving_alone_stops_at_the_next_landing_once_the_key_is_off() {
    run_on_engine_stack("wave7-c24-landing", || async {
        let fixture = setup("wave7-c24-landing").await;
        let agent = vault_agent(&fixture, "wave7-solo-lapse", 0x28);
        let handle = start_alone(&fixture, &agent, "solo").await;
        turn_key_on(&fixture, SOLO_KEY).await;
        let (status, body) = as_agent(
            &fixture,
            &agent,
            SOLO_SAVE_VERB,
            json!({ "session_ref": handle }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the creator saves from here: {body}"
        );
        assert_eq!(owner_reads_mode(&fixture, &handle).await, "on_record");

        turn_key_off(&fixture, SOLO_KEY).await;
        // The landing refuses or lands off record; either way it stops the
        // saving, so its own answer is not the claim.
        let _ = as_owner(
            &fixture,
            "vault.off_record.witness",
            json!({
                "session_ref": handle,
                "turn": {
                    "conversation_ref": "",
                    "turn_ref": null,
                    "messages": [{
                        "id": null,
                        "author": "user",
                        "message_type": "utterance",
                        "content": "said after the key went off",
                        "metadata": null,
                        "is_visible": true,
                        "order": 0,
                    }],
                    "occurred_at": 200,
                },
            }),
        )
        .await;
        assert_eq!(owner_reads_mode(&fixture, &handle).await, "off_record");
    });
}
