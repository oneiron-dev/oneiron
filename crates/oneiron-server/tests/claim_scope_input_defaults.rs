//! The claim write door stamps an omitted scope axis (OF-464; canon
//! cross-arch-0002a §5.8; Engine RULING CLAIM-SCOPE-INPUT-DEFAULTS = A,
//! 15 Nov). Before a write lands, an omitted axis takes the base WORLD, the
//! vault's default FACET (only while it is a stored FACET), `all`
//! relationships and the root's default PROJECT. The stored claim carries all
//! four. Closes FIX [AGENT-CLAIM-WRITE-NO-FACET-DISCOVERY]: an agent that
//! holds a `core:write` slip writes its first claim with no FACET id, which
//! no verb it may call answers.
//!
//! Each case drives the real route `POST /v1/core/facade/vault.claims.upsert`
//! in process (`oneshot`, no TCP port, no sleep, no model). Each writer pairs
//! as `oneiron token agent` pairs an agent: a principal-bound link
//! (`core:read`, `core:write`) redeemed over `POST /v1/core/pairing/redeem`
//! with its holder-signed transcript. The agent is a named agent PERSON of
//! class `agent`; the owner pairs as its own PERSON, class `human` (the
//! host-root credential binds no read proof, so it cannot write a scoped
//! claim at all).
//!
//! On main the two omitted-axis cases are refused before the door runs: the
//! request body does not decode (400 `invalid SDK request: missing field`).
//! The control, which names all four axes, passes on main and on the head,
//! and tells a fixture failure from the change.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! --no-fail-fast -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test claim_scope_input_defaults`. The cfg flag exposes the vault's
//! `MemoryKeystore`; without it this file builds empty.
#![cfg(oneiron_test_support)]

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
use oneiron::claim::{base_world_id, default_project_id, substrate_facet_id};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use tower::ServiceExt;

const UPSERT: &str = "/v1/core/facade/vault.claims.upsert";

/// One paired credential: its principal, holder key, slip and token.
struct Paired {
    principal: EntityId,
    holder: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    agent: Paired,
    owner: Paired,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A fresh served vault, with one paired agent and the paired owner.
async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the vault's owner PERSON");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("claim-scope-input-defaults".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let app = build_app(server);
    let agent_principal = vault
        .ensure_agent_principal("claim-scope-agent")
        .expect("agent principal");
    let agent = pair(&vault, &app, &issuer, agent_principal, "agent", [0x5c; 32]).await;
    let owner = pair(&vault, &app, &issuer, owner, "human", [0x5d; 32]).await;
    Fixture {
        _dir: dir,
        vault,
        app,
        agent,
        owner,
    }
}

/// Pairs `principal` as `class`: a principal-bound link narrowed to
/// `core:read` and `core:write`, redeemed over the real pairing route with
/// the holder-signed binding transcript.
async fn pair(
    vault: &Vault,
    app: &Router,
    issuer: &HostSlipIssuer,
    principal: EntityId,
    class: &str,
    seed: [u8; 32],
) -> Paired {
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
                actor_class: Some(class.to_owned()),
                ..Default::default()
            },
        )
        .expect("pairing link");
    let transcript = pairing_binding_transcript(&link.code, &binding_key, &principal.to_hex())
        .expect("pairing transcript");
    let request = Request::post("/v1/core/pairing/redeem")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "code": link.code,
                "holder_ref": principal.to_hex(),
                "binding_key": hex(&binding_key),
                "signature": hex(&holder.sign(&transcript).to_bytes()),
            })
            .to_string(),
        ))
        .expect("pairing redeem request");
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("pairing redeem response");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "FIXTURE: {class} pairing redeem status"
    );
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("pairing redeem body");
    let body: Value = serde_json::from_slice(&bytes).expect("pairing redeem JSON");
    let token = body["token"].as_str().expect("paired token").to_owned();
    let slip = CapabilitySlip::from_token(&token).expect("paired slip");
    assert_eq!(
        slip.claims.holder_ref,
        principal.to_hex(),
        "FIXTURE: the slip binds its {class}"
    );
    assert_eq!(slip.claims.actor_class.as_deref(), Some(class));
    Paired {
        principal,
        holder,
        slip,
        token,
    }
}

/// A fresh holder proof for one request.
fn binding(fixture: &Fixture, paired: &Paired) -> String {
    let timestamp = fixture.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let transcript = paired
        .slip
        .binding_transcript(challenge.as_bytes())
        .expect("binding transcript");
    let signature = hex(&paired.holder.sign(&transcript).to_bytes());
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

/// One upsert over the facade by `paired`. A reply that is not JSON comes
/// back as a JSON string, so a red shows its status and text.
async fn upsert(fixture: &Fixture, paired: &Paired, body: Value) -> (StatusCode, Value) {
    let request = Request::post(UPSERT)
        .header("authorization", format!("Bearer {}", paired.token))
        .header("x-oneiron-binding", binding(fixture, paired))
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

/// The four stamps of the claim the receipt `body` names, as stored: world,
/// facet, whether the relationships are `all`, project.
fn stored_position(fixture: &Fixture, body: &Value) -> (EntityId, EntityId, bool, EntityId) {
    let short = body["claim_short_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the receipt names its claim: {body}"));
    let id = oneiron::memory::resolve_entity_ref(&fixture.vault, short)
        .unwrap_or_else(|error| panic!("claim ref {short} resolves: {error:?}"));
    let claim = fixture
        .vault
        .get_claim(&id)
        .expect("read the stored claim")
        .expect("the claim is stored");
    (
        claim.world.unwrap_or_else(base_world_id),
        claim.scope_facet,
        claim.rel.is_none(),
        claim.scope_project,
    )
}

/// A `profile.note` claim (a predicate the shipped policy declares normal)
/// about `subject`, with `scope` when given.
fn claim(subject: EntityId, scope: Option<Value>) -> Value {
    let mut claim = json!({
        "predicate": "profile.note",
        "subject_ref": subject.to_hex(),
        "value": "worth a second look",
        "confidence": 0.8,
        "source": "observed",
    });
    if let Some(scope) = scope {
        claim["scope"] = scope;
    }
    claim
}

/// The vault default facet, which a fresh vault stores (the owner PERSON's
/// substrate FACET, minted at open).
fn stored_default_facet(fixture: &Fixture) -> EntityId {
    let default = fixture.vault.default_facet().expect("vault default facet");
    assert_eq!(
        fixture
            .vault
            .get_entity_type(&default)
            .expect("default facet type"),
        Some(oneiron::registry::ENTITY_TYPE_FACET),
        "FIXTURE: the default facet is a stored FACET"
    );
    default
}

/// Case 1 (the named red): an agent names world, relationships and project
/// but no facet. The claim lands under the vault's default facet. Red on
/// main: 400, the body does not decode (`missing field scope_facet_id`).
#[test]
fn an_agent_claim_with_no_facet_lands_under_the_vault_default_facet() {
    run_on_engine_stack("claim-scope-agent-no-facet", || async {
        let fixture = setup().await;
        let default = stored_default_facet(&fixture);
        let body = claim(
            fixture.agent.principal,
            Some(json!({
                "world_id": base_world_id().to_hex(),
                "scope_relationship_id": "all",
                "scope_project_id": default_project_id().to_hex(),
            })),
        );
        let (status, body) = upsert(&fixture, &fixture.agent, body).await;
        assert_eq!(status, StatusCode::OK, "agent upsert with no facet: {body}");
        assert_eq!(
            stored_position(&fixture, &body),
            (base_world_id(), default, true, default_project_id()),
            "the omitted facet is the vault default: {body}"
        );
    });
}

/// Case 2: the owner sends no `scope` at all. All four axes are stamped:
/// base world, the vault default facet, all relationships, the default
/// project. Red on main: 400 (`missing field scope`).
#[test]
fn an_owner_claim_with_no_scope_lands_at_the_four_defaults() {
    run_on_engine_stack("claim-scope-owner-no-scope", || async {
        let fixture = setup().await;
        let default = stored_default_facet(&fixture);
        let body = claim(fixture.owner.principal, None);
        let (status, body) = upsert(&fixture, &fixture.owner, body).await;
        assert_eq!(status, StatusCode::OK, "owner upsert with no scope: {body}");
        assert_eq!(
            stored_position(&fixture, &body),
            (base_world_id(), default, true, default_project_id()),
            "every omitted axis is stamped: {body}"
        );
    });
}

/// Case 3 (control, green on main and on the head): an agent that names all
/// four axes lands where it says, under its own substrate facet, as an MCP
/// agent writes today.
#[test]
fn an_agent_claim_that_names_every_axis_lands_where_it_says() {
    run_on_engine_stack("claim-scope-agent-stated", || async {
        let fixture = setup().await;
        let own = substrate_facet_id(fixture.agent.principal).expect("agent substrate facet id");
        let body = claim(
            fixture.agent.principal,
            Some(json!({
                "world_id": base_world_id().to_hex(),
                "scope_facet_id": own.to_hex(),
                "scope_relationship_id": "all",
                "scope_project_id": default_project_id().to_hex(),
            })),
        );
        let (status, body) = upsert(&fixture, &fixture.agent, body).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "agent upsert naming four axes: {body}"
        );
        assert_eq!(
            stored_position(&fixture, &body),
            (base_world_id(), own, true, default_project_id()),
            "a stated facet is kept: {body}"
        );
    });
}
