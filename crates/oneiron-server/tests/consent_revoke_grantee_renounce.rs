//! A grantee may renounce its own standing consent grant (P-GATE-010, DEC-0006).
//!
//! Red/green facade test for [CONSENT-REVOKE-GRANTEE-RENOUNCE]: it drives the
//! real route `POST /v1/core/facade/vault.consent.revoke` with real paired
//! agent credentials. Each agent is a vault-registered PERSON
//! (`ensure_agent_principal`, as `token agent` mints), enrolled through an
//! actual pairing redemption: the owner issues a principal-bound link and
//! the agent redeems it over real `POST /v1/core/pairing/redeem` with its
//! holder-signed binding transcript. Every later request proves possession
//! afresh with that holder key. The owner acts on its host-root credential,
//! the established self-hosted owner path.
//!
//! On unmodified main the grantee's renounce (case a) answers 403, because
//! `vault_consent_revoke` runs `owner_proof` only. With the fix the Grant's
//! own grantee lands the same `gate.consent.revoked` receipt as the owner,
//! never a 202 ask; any other non-owner keeps a 403 `FORBIDDEN`. Cases b
//! and c pass on main and on the head.
//!
//! Deterministic: in-process vault and router (`oneshot`, no TCP ports, no
//! sleeps, no models). Each case owns its vault.
//!
//! Fleet command: `cargo test --locked -p oneiron-server --test
//! consent_revoke_grantee_renounce` (no test doors, no extra cfg).
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use tower::ServiceExt;

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

/// Runs `test` on an engine-sized stack and runtime, as the facade's
/// generated dispatch needs more than a test thread's default stack.
fn run_on_engine_stack(
    name: &str,
    test: impl std::future::Future<Output = ()> + Send + 'static,
) {
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

async fn setup() -> (Fixture, Agent, Agent) {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("consent-revoke-grantee-renounce".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault.ensure_host_root_slip(&issuer).expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    let app = build_app(server);
    let fixture = Fixture {
        _dir: dir,
        vault: Arc::clone(&vault),
        app,
        issuer,
        owner_slip,
        owner_token,
    };
    let agent = pair_agent(&fixture, "renounce-agent-a", [0x11; 32]).await;
    let other = pair_agent(&fixture, "renounce-agent-b", [0x22; 32]).await;
    (fixture, agent, other)
}

/// Pairs one agent the way `token agent` does: a registered PERSON
/// principal, a principal-bound link narrowed to the agent verb scope the
/// end-to-end suite pairs (`core:read`, `core:write`), redeemed over the
/// real pairing route with the holder-signed binding transcript.
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
    assert!(
        link.pin.is_none(),
        "fresh vault keeps no checkpoint pin on its links"
    );
    let transcript =
        pairing_binding_transcript(&link.code, &binding_key, &principal.to_hex())
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
    let signature: String = hex(
        &fixture
            .issuer
            .binding_proof(&fixture.owner_slip, challenge.as_bytes())
            .expect("owner holder proof"),
    );
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

/// The owner mints one action grant bound to `actor_hex` over a fresh
/// project, and returns its 64-hex grant ref.
async fn create_action_grant(fixture: &Fixture, actor_hex: &str) -> String {
    let (status, body) = post(
        fixture,
        "/v1/core/facade/vault.consent.create_standing_grant",
        &fixture.owner_token,
        owner_binding(fixture),
        json!({
            "bound": {
                "actor": actor_hex,
                "class": "channel_send",
                "envelope": {
                    "project": EntityId::now().to_hex(),
                    "audience": [EntityId::now().to_hex()],
                },
            },
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create standing grant: {body}");
    assert_eq!(
        body["outcome"].as_str(),
        Some("approved"),
        "create standing grant: {body}"
    );
    let grant = body["grant_ref"]
        .as_str()
        .expect("created grant ref")
        .to_owned();
    assert_eq!(grant.len(), 64, "grant ref is a bound digest: {grant}");
    grant
}

async fn revoke_as(
    fixture: &Fixture,
    token: &str,
    binding: String,
    grant: &str,
) -> (StatusCode, Value) {
    post(
        fixture,
        "/v1/core/facade/vault.consent.revoke",
        token,
        binding,
        json!({"grant": grant}),
    )
    .await
}

async fn registry(fixture: &Fixture, include_revoked: bool) -> Value {
    let (status, body) = post(
        fixture,
        "/v1/core/facade/vault.consent.registry",
        &fixture.owner_token,
        owner_binding(fixture),
        json!({"limit": 100, "include_revoked": include_revoked}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "consent registry: {body}");
    body
}

fn registry_row<'body>(registry: &'body Value, grant: &str) -> Option<&'body Value> {
    registry["rows"]
        .as_array()
        .expect("registry rows")
        .iter()
        .find(|row| row["grant_ref"].as_str() == Some(grant))
}

/// Case a: the grantee renounces its own standing grant. 200 with the
/// revoked receipt, gone from the owner's active registry, and a second
/// renounce returns that same receipt with `already_revoked` (no new act).
/// Red on main (403), green with the fix.
#[test]
fn grantee_renounce_of_own_standing_grant_lands_revoked_receipt() {
    run_on_engine_stack("consent-renounce-own", async {
        let (fixture, agent, _other) = setup().await;
        let grantee = agent.principal.to_hex();
        let grant = create_action_grant(&fixture, &grantee).await;

        let binding = agent_binding(&fixture, &agent);
        let (status, body) = revoke_as(&fixture, &agent.token, binding, &grant).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "grantee renounce of its own grant: {body}"
        );
        assert_eq!(body["outcome"].as_str(), Some("revoked"), "{body}");
        assert_eq!(
            body["reason_code"].as_str(),
            Some(oneiron::consent::CONSENT_REASON_REVOKED),
            "{body}"
        );
        assert_eq!(body["grant_ref"].as_str(), Some(grant.as_str()), "{body}");
        assert_eq!(body["revoked_by"].as_str(), Some(grantee.as_str()), "{body}");
        let decision = body["decision_ref"]
            .as_str()
            .expect("revoke decision ref")
            .to_owned();
        let already = body
            .get("already_revoked")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        assert!(!already, "first renounce writes: {body}");

        let active = registry(&fixture, false).await;
        assert!(
            registry_row(&active, &grant).is_none(),
            "renounced grant leaves the active registry: {active}"
        );
        let audit = registry(&fixture, true).await;
        let row = registry_row(&audit, &grant).expect("revoked row kept in audit view");
        assert_eq!(row["status"].as_str(), Some("revoked"), "{row}");

        let binding = agent_binding(&fixture, &agent);
        let (status, again) = revoke_as(&fixture, &agent.token, binding, &grant).await;
        assert_eq!(status, StatusCode::OK, "second renounce: {again}");
        assert_eq!(
            again["decision_ref"].as_str(),
            Some(decision.as_str()),
            "second renounce returns the original receipt: {again}"
        );
        assert_eq!(again["outcome"].as_str(), Some("revoked"), "{again}");
        assert_eq!(
            again["reason_code"].as_str(),
            Some(oneiron::consent::CONSENT_REASON_REVOKED),
            "{again}"
        );
        assert_eq!(
            again["revoked_by"].as_str(),
            Some(grantee.as_str()),
            "{again}"
        );
        assert_eq!(again["already_revoked"].as_bool(), Some(true), "{again}");
    });
}

/// Case b: the same agent names a grant whose grantee is a different agent.
/// 403 with the owner path's error code, on main and on the head; an
/// unknown grant ref answers the same refusal (no existence leak); the
/// named grant stays active.
#[test]
fn non_grantee_revoke_of_anothers_grant_keeps_owner_refusal_and_grant_active() {
    run_on_engine_stack("consent-renounce-other", async {
        let (fixture, agent, other) = setup().await;
        let grant = create_action_grant(&fixture, &other.principal.to_hex()).await;

        let binding = agent_binding(&fixture, &agent);
        let (status, body) = revoke_as(&fixture, &agent.token, binding, &grant).await;
        assert_eq!(
            (status, body["error"]["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("FORBIDDEN")),
            "non-grantee revoke: {body}"
        );

        let unknown = "f".repeat(64);
        let binding = agent_binding(&fixture, &agent);
        let (status, veiled) = revoke_as(&fixture, &agent.token, binding, &unknown).await;
        assert_eq!(
            (status, veiled["error"]["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("FORBIDDEN")),
            "unknown grant revoke: {veiled}"
        );
        // The two refusals match field for field (beside the per-request
        // id), so neither wording nor shape leaks the grant's existence.
        for field in ["code", "message", "suggestions"] {
            assert_eq!(
                body["error"][field], veiled["error"][field],
                "refusal field {field} matches: {body} vs {veiled}"
            );
        }

        let active = registry(&fixture, false).await;
        let row = registry_row(&active, &grant).expect("refused grant stays listed");
        assert_eq!(row["status"].as_str(), Some("active"), "{row}");
    });
}

/// Case c, control: the owner's revoke of a standing grant still works as
/// today (200, receipt). Passes on main and on the head.
#[test]
fn owner_revoke_of_standing_grant_control() {
    run_on_engine_stack("consent-renounce-owner", async {
        let (fixture, agent, _other) = setup().await;
        let grant = create_action_grant(&fixture, &agent.principal.to_hex()).await;

        let owner_token = fixture.owner_token.clone();
        let binding = owner_binding(&fixture);
        let (status, body) = revoke_as(&fixture, &owner_token, binding, &grant).await;
        assert_eq!(status, StatusCode::OK, "owner revoke: {body}");
        assert_eq!(body["outcome"].as_str(), Some("revoked"), "{body}");
        assert_eq!(
            body["reason_code"].as_str(),
            Some(oneiron::consent::CONSENT_REASON_REVOKED),
            "{body}"
        );
    });
}
