//! An agent whose Grant names `vault.models.bindings.propose` may propose a
//! binding; the owner still decides (OPUS-E2E-3 model-binding-proposer-grant).
//!
//! Red/green facade test: it drives the real route
//! `POST /v1/core/facade/vault.models.bindings.propose` with a real paired
//! agent credential. The agent is a vault-registered named PERSON
//! (`ensure_agent_principal`, as `token agent` mints), enrolled through an
//! actual pairing redemption: the owner issues a principal-bound link and
//! the agent redeems it over real `POST /v1/core/pairing/redeem` with its
//! holder-signed binding transcript. Every later request proves possession
//! afresh with that holder key. The owner acts on its host-root credential,
//! the established self-hosted owner path, on a profiled install (this
//! install's live machine profile, or owner acts fail "no carrier").
//!
//! The trial fixture (one completed held-out trial offer for the role) comes
//! from the cfg-only `oneiron::test_doors::model_binding_proposer` door,
//! which builds it through the engine's own public owner writers and never
//! writes a proposal. The HTTP trial runner selects the server's decision
//! host; the cfg door instead uses the engine runner's scripted callback.
//! Each case owns its vault.
//!
//! On unmodified main the agent's propose (case 1) answers 403, because the
//! verb is owner-only end to end. With the fix the Grant's agent lands a
//! `Proposed` binding under the owner's principal, and nothing activates it.
//! Cases 2 and 3 accept either refusal exactly: main's 403 owner-only text,
//! or the fix's 400 authority text (`no live Grant of this agent names this
//! act`), since the existing authority conversion maps to `BAD_REQUEST`
//! (never 500). Cases 4 and 5 pass on main and on the head.
//!
//! Deterministic: in-process vault and router (`oneshot`, no TCP ports, no
//! sleeps, no models).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test model_binding_proposer_grant`.
#![cfg(oneiron_test_support)]

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::test_doors::model_binding_proposer::{
    PROPOSE_ROLE, TrialFixture, ensure_completed_trial_offer, proposal_ids_for_trial,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use tower::ServiceExt;

/// The verb the agent's Grant must name.
const GRANT_VERB: &str = "vault.models.bindings.propose";
/// The fix's authority refusal when no live Grant names the act: the
/// existing `owner_act.rs` text, mapped to `BAD_REQUEST` (never 500).
const AUTHORITY_REFUSAL_MESSAGE: &str = "no live Grant of this agent names this act";

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
    trial: TrialFixture,
}

/// Runs `test` on an engine-sized stack and runtime, as the facade's
/// generated dispatch needs more than a test thread's default stack.
fn run_on_engine_stack(name: &str, test: impl std::future::Future<Output = ()> + Send + 'static) {
    let run = std::thread::Builder::new()
        .name(name.into())
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("engine-sized test runtime")
                .block_on(test)
        })
        .expect("spawn the engine-sized test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

async fn setup() -> (Fixture, Agent) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("model-binding-proposer-grant".into()),
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
    // The owner's agent-Grant act is carried by this install's live machine
    // profile, as a serving start or `init` enrols it; without one the mint
    // fails "no carrier".
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let trial = ensure_completed_trial_offer(&vault).expect("completed held-out trial offer");
    let app = build_app(server);
    let agent = pair_agent(&vault, &app, &issuer, "binding-proposer-agent", [0x51; 32]).await;
    (
        Fixture {
            _dir: dir,
            vault,
            app,
            issuer,
            owner_slip,
            owner_token,
            trial,
        },
        agent,
    )
}

/// Pairs one agent the way `token agent` does: a registered named PERSON
/// principal, a principal-bound link narrowed to the agent verb scope the
/// end-to-end suite pairs (`core:read`, `core:write`), redeemed over the
/// real pairing route with the holder-signed binding transcript.
async fn pair_agent(
    vault: &Vault,
    app: &Router,
    issuer: &HostSlipIssuer,
    name: &str,
    seed: [u8; 32],
) -> Agent {
    let principal = vault.ensure_agent_principal(name).expect("agent principal");
    let holder = SigningKey::from_bytes(&seed);
    let binding_key = holder.verifying_key().to_bytes();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
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

/// The scope the owner gives the agent's Grant: everything, with `read` (so
/// the Grant confers) and the propose verb among its explicit verbs.
fn propose_grant_scope() -> Value {
    json!({
        "worlds": {"kind": "all"},
        "facets": {"kind": "all"},
        "bands": {"kind": "all"},
        "audience": {"kind": "all"},
        "verbs": {"kind": "some", "values": ["read", GRANT_VERB]},
        "sensitivity": {"kind": "at_most", "value": "restricted"},
    })
}

/// The owner mints the agent a Grant naming the propose verb over actual
/// HTTP, reads it back from the mint answer (its agent, its verbs, that it
/// confers) and from the stored grant row itself (`vault.get`: kind
/// `FEDERATION_GRANT` under the grant ref), and returns its grant ref.
async fn mint_propose_grant(fixture: &Fixture, agent_hex: &str) -> String {
    let (status, body) = post(
        fixture,
        "/v1/core/facade/vault.agents.grants.mint",
        &fixture.owner_token,
        owner_binding(fixture),
        json!({
            "agent": agent_hex,
            "authority_scope": propose_grant_scope(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "mint propose grant: {body}");
    assert_eq!(
        body["grant"]["agent"].as_str(),
        Some(agent_hex),
        "minted grant binds its agent: {body}"
    );
    let verbs = body["grant"]["authority_scope"]["verbs"]["values"]
        .as_array()
        .expect("minted grant verbs");
    assert!(
        verbs.iter().any(|verb| verb.as_str() == Some(GRANT_VERB)),
        "minted grant names the propose verb: {body}"
    );
    assert_eq!(
        body["grant"]["confers"].as_bool(),
        Some(true),
        "minted grant confers: {body}"
    );
    let grant = body["grant"]["grant_ref"]
        .as_str()
        .expect("minted grant ref")
        .to_owned();
    // Persisted read-back: the grant row itself, not just the mint answer.
    let (status, body) = get_grant_as_owner(fixture, &grant).await;
    assert_eq!(status, StatusCode::OK, "read the minted grant back: {body}");
    assert_eq!(
        body["value"]["kind"].as_str(),
        Some("FEDERATION_GRANT"),
        "{body}"
    );
    assert_eq!(
        body["value"]["id_hex"].as_str(),
        Some(grant.as_str()),
        "{body}"
    );
    grant
}

/// The owner revokes the grant over actual HTTP and returns the answer.
async fn revoke_grant(fixture: &Fixture, grant: &str) -> (StatusCode, Value) {
    post(
        fixture,
        "/v1/core/facade/vault.agents.grants.revoke",
        &fixture.owner_token,
        owner_binding(fixture),
        json!({"grant_ref": grant}),
    )
    .await
}

/// The owner reads one entity row over actual HTTP: the persisted
/// read-back behind the mint and revoke answers.
async fn get_grant_as_owner(fixture: &Fixture, grant: &str) -> (StatusCode, Value) {
    post(
        fixture,
        "/v1/core/facade/vault.get",
        &fixture.owner_token,
        owner_binding(fixture),
        json!({"entity_ref": grant}),
    )
    .await
}

/// The propose input for the fixture trial: the role, with the manifest
/// incumbent's binding and only the measured model changed to the candidate.
fn propose_input(fixture: &Fixture) -> Value {
    json!({
        "question": fixture.trial.question.to_hex(),
        "trial": fixture.trial.trial.to_hex(),
        "role": PROPOSE_ROLE,
        "binding": {
            "model": fixture.trial.candidate,
            "slot": "llm",
            "tier": fixture.trial.tier,
        },
    })
}

async fn propose_as(
    fixture: &Fixture,
    token: &str,
    binding: String,
    input: Value,
) -> (StatusCode, Value) {
    post(
        fixture,
        "/v1/core/facade/vault.models.bindings.propose",
        token,
        binding,
        input,
    )
    .await
}

async fn get_as_owner(fixture: &Fixture, proposal: &str) -> (StatusCode, Value) {
    post(
        fixture,
        "/v1/core/facade/vault.models.bindings.get",
        &fixture.owner_token,
        owner_binding(fixture),
        json!({"proposal": proposal}),
    )
    .await
}

async fn read_as_owner(fixture: &Fixture) -> (StatusCode, Value) {
    post(
        fixture,
        "/v1/core/facade/vault.models.bindings.read",
        &fixture.owner_token,
        owner_binding(fixture),
        json!({"role": PROPOSE_ROLE}),
    )
    .await
}

async fn accept_as(
    fixture: &Fixture,
    token: &str,
    binding: String,
    proposal: &str,
) -> (StatusCode, Value) {
    post(
        fixture,
        "/v1/core/facade/vault.models.bindings.accept",
        token,
        binding,
        json!({"proposal": proposal}),
    )
    .await
}

/// There is no proposal list verb and `get` requires an id that a refusal
/// does not return. Scan the trial's rows read-only, then read the binding
/// through the owner's HTTP path to confirm nothing activated.
async fn assert_no_proposal(fixture: &Fixture) {
    let ids = proposal_ids_for_trial(&fixture.vault, fixture.trial.trial)
        .expect("scan the trial's proposals");
    assert!(ids.is_empty(), "refused propose left no proposal: {ids:?}");
    let (status, body) = read_as_owner(fixture).await;
    assert_eq!(status, StatusCode::OK, "owner reads the role: {body}");
    assert_eq!(
        body["model"].as_str(),
        Some(fixture.trial.incumbent.as_str()),
        "the refused proposal leaves the incumbent binding: {body}"
    );
}

/// The agent's propose without a standing Grant is refused, on main with the
/// 403 owner-only text, with the fix with the 400 authority text; both are
/// exact, and neither is a 500.
fn assert_agent_propose_refused(status: StatusCode, body: &Value) {
    let main = status == StatusCode::FORBIDDEN
        && body["error"]["code"].as_str() == Some("FORBIDDEN")
        && body["error"]["message"].as_str()
            == Some("vault.models.bindings.propose is the vault owner's");
    let head = status == StatusCode::BAD_REQUEST
        && body["error"]["code"].as_str() == Some("BAD_REQUEST")
        && body["error"]["message"].as_str() == Some(AUTHORITY_REFUSAL_MESSAGE);
    assert!(
        main || head,
        "agent propose refused as main-403 or head-400: status {status}, {body}"
    );
}

/// The agent's propose refused with main's exact 403 owner-only text. Only
/// the case-4 fallback uses this: there the Grant is valid, so the fix's
/// 400 would be a bug, not a fallback.
fn assert_main_propose_refused(status: StatusCode, body: &Value) {
    assert_eq!(
        (
            status,
            body["error"]["code"].as_str(),
            body["error"]["message"].as_str()
        ),
        (
            StatusCode::FORBIDDEN,
            Some("FORBIDDEN"),
            Some("vault.models.bindings.propose is the vault owner's"),
        ),
        "agent propose refused with main's exact owner-only text: {body}"
    );
}

/// Case 1: the agent whose Grant names the propose verb lands a `Proposed`
/// binding under the owner's principal; the role still reads the incumbent
/// model (nothing activated). Red on main (403), green with the fix.
#[test]
fn an_agent_whose_grant_names_propose_lands_a_proposed_binding() {
    run_on_engine_stack("binding-proposer-grant", async {
        let (fixture, agent) = setup().await;
        let agent_hex = agent.principal.to_hex();
        let _grant = mint_propose_grant(&fixture, &agent_hex).await;

        let binding = agent_binding(&fixture, &agent);
        let (status, body) =
            propose_as(&fixture, &agent.token, binding, propose_input(&fixture)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "agent propose with the Grant: {body}"
        );
        assert_eq!(body["status"].as_str(), Some("proposed"), "{body}");
        let proposal = body["id"].as_str().expect("proposal id").to_owned();

        let (status, body) = get_as_owner(&fixture, &proposal).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the proposal back: {body}"
        );
        assert_eq!(body["id"].as_str(), Some(proposal.as_str()), "{body}");
        assert_eq!(body["status"].as_str(), Some("proposed"), "{body}");
        assert_eq!(
            body["principal"].as_str(),
            Some(fixture.trial.owner.to_hex()).as_deref(),
            "proposal lands under the owner's principal: {body}"
        );
        assert_eq!(
            body["proposed"]["model"].as_str(),
            Some(fixture.trial.candidate.as_str()),
            "{body}"
        );

        let (status, body) = read_as_owner(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner reads the role: {body}");
        assert_eq!(
            body["model"].as_str(),
            Some(fixture.trial.incumbent.as_str()),
            "the role still reads the incumbent model: {body}"
        );
    });
}

/// Case 2: the same agent with no Grant is refused, and no proposal lands
/// for the trial. Green on main and on the head.
#[test]
fn an_agent_without_the_grant_is_refused() {
    run_on_engine_stack("binding-proposer-no-grant", async {
        let (fixture, agent) = setup().await;
        let binding = agent_binding(&fixture, &agent);
        let (status, body) =
            propose_as(&fixture, &agent.token, binding, propose_input(&fixture)).await;
        assert_agent_propose_refused(status, &body);

        assert_no_proposal(&fixture).await;
    });
}

/// Case 3: mint, revoke, read the deleted row back absent, then propose.
/// The next use is refused and leaves no proposal. Green on main and head.
#[test]
fn an_agent_whose_grant_is_revoked_is_refused_at_its_next_use() {
    run_on_engine_stack("binding-proposer-revoked", async {
        let (fixture, agent) = setup().await;
        let agent_hex = agent.principal.to_hex();
        let grant = mint_propose_grant(&fixture, &agent_hex).await;

        let (status, body) = revoke_grant(&fixture, &grant).await;
        assert_eq!(status, StatusCode::OK, "revoke the grant: {body}");
        assert_eq!(body["grant_ref"].as_str(), Some(grant.as_str()), "{body}");
        assert_eq!(body["changed"].as_bool(), Some(true), "{body}");
        assert_eq!(body["agent"].as_str(), Some(agent_hex.as_str()), "{body}");
        assert!(body["act_ref"].as_str().is_some(), "{body}");

        // Persisted read-back: revoke deletes the row, so the stored grant
        // reads back absent (200 with a null value, never 404).
        let (status, body) = get_grant_as_owner(&fixture, &grant).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "read the revoked grant back: {body}"
        );
        assert!(
            body["value"].is_null(),
            "revoke deleted the grant row: {body}"
        );

        let binding = agent_binding(&fixture, &agent);
        let (status, body) =
            propose_as(&fixture, &agent.token, binding, propose_input(&fixture)).await;
        assert_agent_propose_refused(status, &body);

        assert_no_proposal(&fixture).await;
    });
}

/// Case 4: the agent cannot accept its own proposal: accept stays
/// owner-only, so the agent's accept is refused and the proposal stays
/// `Proposed` with the role on the incumbent. With the fix the proposal is
/// the agent's own; on main the owner seeds it, since the agent's propose
/// is refused there with main's exact owner-only text. Green on main and
/// on the head.
#[test]
fn the_agent_cannot_accept_its_own_proposal() {
    run_on_engine_stack("binding-proposer-no-accept", async {
        let (fixture, agent) = setup().await;
        let agent_hex = agent.principal.to_hex();
        let _grant = mint_propose_grant(&fixture, &agent_hex).await;

        let binding = agent_binding(&fixture, &agent);
        let (status, body) =
            propose_as(&fixture, &agent.token, binding, propose_input(&fixture)).await;
        let proposal = if status == StatusCode::OK {
            assert_eq!(body["status"].as_str(), Some("proposed"), "{body}");
            body["id"].as_str().expect("proposal id").to_owned()
        } else {
            // Main only: the Grant is valid, so anything but main's exact
            // owner-only refusal (in particular the fix's 400) fails here.
            assert_main_propose_refused(status, &body);
            let owner_token = fixture.owner_token.clone();
            let (status, body) = propose_as(
                &fixture,
                &owner_token,
                owner_binding(&fixture),
                propose_input(&fixture),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "owner seeds the proposal: {body}");
            body["id"].as_str().expect("proposal id").to_owned()
        };

        let binding = agent_binding(&fixture, &agent);
        let (status, body) = accept_as(&fixture, &agent.token, binding, &proposal).await;
        assert_eq!(
            (
                status,
                body["error"]["code"].as_str(),
                body["error"]["message"].as_str()
            ),
            (
                StatusCode::FORBIDDEN,
                Some("FORBIDDEN"),
                Some("vault.models.bindings.accept is the vault owner's"),
            ),
            "agent accept of its own proposal: {body}"
        );

        let (status, body) = get_as_owner(&fixture, &proposal).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the proposal after the refused accept: {body}"
        );
        assert_eq!(body["id"].as_str(), Some(proposal.as_str()), "{body}");
        assert_eq!(body["status"].as_str(), Some("proposed"), "{body}");
        assert!(body["settled_at"].is_null(), "{body}");

        let (status, body) = read_as_owner(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner reads the role: {body}");
        assert_eq!(
            body["model"].as_str(),
            Some(fixture.trial.incumbent.as_str()),
            "the role still reads the incumbent model: {body}"
        );
    });
}

/// Case 5, control: the owner's propose lands `Proposed` and reads back,
/// with the role still on the incumbent. Green on main and on the head.
#[test]
fn the_owner_still_proposes() {
    run_on_engine_stack("binding-proposer-owner", async {
        let (fixture, _agent) = setup().await;
        let owner_token = fixture.owner_token.clone();
        let (status, body) = propose_as(
            &fixture,
            &owner_token,
            owner_binding(&fixture),
            propose_input(&fixture),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner propose: {body}");
        assert_eq!(body["status"].as_str(), Some("proposed"), "{body}");
        let proposal = body["id"].as_str().expect("proposal id").to_owned();

        let (status, body) = get_as_owner(&fixture, &proposal).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner reads the proposal back: {body}"
        );
        assert_eq!(body["id"].as_str(), Some(proposal.as_str()), "{body}");
        assert_eq!(body["status"].as_str(), Some("proposed"), "{body}");

        let (status, body) = read_as_owner(&fixture).await;
        assert_eq!(status, StatusCode::OK, "owner reads the role: {body}");
        assert_eq!(
            body["model"].as_str(),
            Some(fixture.trial.incumbent.as_str()),
            "the role still reads the incumbent model: {body}"
        );
    });
}
