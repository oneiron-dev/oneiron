//! The audit_read power on the served facade ([AUDIT-READ-POWER]; RULING
//! AUDIT-READ-POWER-LIST = B, Engine RULINGs AUDITREAD-GRANT-HOME = A and
//! AUDITREAD-DOOR-LIST = A, 15 Nov 22:00).
//!
//! `vault.authority.audit` is a host door whose verb row names the
//! `audit_reader` proof: the owner's own proof, or a credential bound to an
//! actor that holds a live audit_read power. `vault.receipts.get` reads a
//! call receipt for a live holder too. Only the owner grants and revokes the
//! power (`vault.audit_read.grant`, `vault.audit_read.revoke`).
//!
//! It drives the real routes `POST /v1/core/facade/<verb>` with real paired
//! agent credentials. Each agent is a vault-registered PERSON
//! (`ensure_agent_principal`, as `token agent` mints), enrolled through an
//! actual pairing redemption; every later request proves possession afresh
//! with its holder key. The owner acts on its host-root credential.
//!
//! On main the owner verbs do not exist and a holder is refused, so each case
//! fails there.
//!
//! Deterministic: in-process vault and router (`oneshot`, no TCP ports, no
//! sleeps, no models). Each case owns its vault.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test audit_read_host_door`. The test calls no test door.
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
    CapabilitySlip, HostSlipIssuer, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::receipt::{CallOutcome, CallReceiptInput, CallTransport};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
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
                auth_secret: Some("audit-read-host-door".into()),
                ..Default::default()
            },
        )
        .expect("create server")
        .with_usage_metering("billing-owner")
        .expect("bind the usage meter"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
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
    let auditor = pair_agent(&fixture, "audit-read-agent-a", [0x31; 32]).await;
    let other = pair_agent(&fixture, "audit-read-agent-b", [0x32; 32]).await;
    (fixture, auditor, other)
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
    let body: Value = serde_json::from_slice(&bytes).expect("facade response JSON");
    (status, body)
}

async fn as_owner(fixture: &Fixture, verb: &str, body: Value) -> (StatusCode, Value) {
    let binding = owner_binding(fixture);
    post(fixture, verb, &fixture.owner_token, binding, body).await
}

async fn as_agent(
    fixture: &Fixture,
    agent: &Agent,
    verb: &str,
    body: Value,
) -> (StatusCode, Value) {
    let binding = agent_binding(fixture, agent);
    post(fixture, verb, &agent.token, binding, body).await
}

/// The owner changes `holder`'s power through `verb` and answers its body.
async fn owner_changes(fixture: &Fixture, verb: &str, holder: &Agent) -> Value {
    let (status, body) =
        as_owner(fixture, verb, json!({"holder": holder.principal.to_hex()})).await;
    assert_eq!(status, StatusCode::OK, "{verb}: {body}");
    assert_eq!(
        body["changed"],
        json!(true),
        "{verb} changes the power: {body}"
    );
    body
}

fn assert_forbidden(status: StatusCode, body: &Value, what: &str) {
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("FORBIDDEN")),
        "{what}: {body}"
    );
}

/// The `audit_reader` proof: an agent reads the authority audit on its own
/// credential while it holds a live audit_read power, sees the owner's grant
/// listed there, and is refused once the owner revokes it. Another agent is
/// refused throughout, and the holder cannot grant the power on.
#[test]
fn an_audit_read_holder_reads_the_authority_audit_on_its_own_credential() {
    run_on_engine_stack("audit-read-authority-audit", || async {
        let (fixture, auditor, other) = setup().await;
        let (status, body) = as_agent(&fixture, &auditor, "vault.authority.audit", json!({})).await;
        assert_forbidden(status, &body, "the audit before any grant");

        let granted = owner_changes(&fixture, "vault.audit_read.grant", &auditor).await;
        assert_eq!(
            granted["holders"][0]["holder"],
            json!(auditor.principal.to_hex()),
            "the grant lists its holder: {granted}"
        );
        let (status, page) = as_agent(&fixture, &auditor, "vault.authority.audit", json!({})).await;
        assert_eq!(status, StatusCode::OK, "the holder reads the audit: {page}");
        assert!(page["rows"].is_array(), "{page}");
        let acts = page["audit_read_acts"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            acts.iter()
                .any(|act| act["holder"] == json!(auditor.principal.to_hex())
                    && act["change"] == json!("grant")),
            "the page lists the owner's grant: {page}"
        );
        let (status, body) = as_agent(&fixture, &other, "vault.authority.audit", json!({})).await;
        assert_forbidden(status, &body, "the audit for an agent without the power");
        let (status, body) = as_agent(
            &fixture,
            &auditor,
            "vault.audit_read.grant",
            json!({"holder": other.principal.to_hex()}),
        )
        .await;
        assert_forbidden(status, &body, "a holder's grant to another agent");

        owner_changes(&fixture, "vault.audit_read.revoke", &auditor).await;
        let (status, body) = as_agent(&fixture, &auditor, "vault.authority.audit", json!({})).await;
        assert_forbidden(status, &body, "the audit after the revoke");
    });
}

/// `vault.receipts.get` on the served facade: the owner's call receipt reads
/// for a live holder on its own credential, and as none before the grant,
/// for another agent, and after the revoke.
#[test]
fn an_audit_read_holder_reads_the_owners_call_receipt() {
    run_on_engine_stack("audit-read-call-receipt", || async {
        let (fixture, auditor, other) = setup().await;
        let receipt_ref = fixture
            .vault
            .record_call_receipt(CallReceiptInput {
                transport: CallTransport::HttpFacade,
                verb: "vault.claims.list".to_owned(),
                actor_ref: fixture
                    .vault
                    .ensure_embedded_owner_actor()
                    .expect("owner")
                    .to_hex(),
                actor_class: "human".to_owned(),
                credential_ref: None,
                carrier_machine: None,
                outcome: CallOutcome::Ok,
                request_digest: "ab".repeat(32),
                result_digest: Some("cd".repeat(32)),
                inputs: None,
                attempt: None,
                served: Vec::new(),
            })
            .expect("the owner's call receipt");
        let get = json!({"receipt_ref": receipt_ref});
        let read = |agent: &'static str, status: StatusCode, body: Value| {
            assert_eq!(status, StatusCode::OK, "{agent}'s receipts.get: {body}");
            body
        };

        let (status, body) = as_agent(&fixture, &auditor, "vault.receipts.get", get.clone()).await;
        assert_eq!(
            read("the auditor", status, body),
            Value::Null,
            "before any grant"
        );

        owner_changes(&fixture, "vault.audit_read.grant", &auditor).await;
        let (status, body) = as_agent(&fixture, &auditor, "vault.receipts.get", get.clone()).await;
        let body = read("the auditor", status, body);
        assert_eq!(
            body["receipt_ref"],
            json!(receipt_ref),
            "the holder reads it: {body}"
        );
        let (status, body) = as_agent(&fixture, &other, "vault.receipts.get", get.clone()).await;
        assert_eq!(read("the other agent", status, body), Value::Null);

        owner_changes(&fixture, "vault.audit_read.revoke", &auditor).await;
        let (status, body) = as_agent(&fixture, &auditor, "vault.receipts.get", get).await;
        assert_eq!(
            read("the auditor", status, body),
            Value::Null,
            "after the revoke"
        );
    });
}

/// `vault.usage.repair.receipts` on the served facade: every receipt a
/// removal kept reads for a live audit_read holder on its own credential,
/// and is refused before the grant, for another agent, and after the revoke.
/// The metering scope holds no removal yet, so the holder reads an empty
/// list.
#[test]
fn an_audit_read_holder_reads_the_usage_repair_receipts() {
    run_on_engine_stack("audit-read-usage-repair-receipts", || async {
        let (fixture, auditor, other) = setup().await;
        let (status, body) =
            as_agent(&fixture, &auditor, "vault.usage.repair.receipts", json!({})).await;
        assert_forbidden(status, &body, "the receipts before any grant");

        owner_changes(&fixture, "vault.audit_read.grant", &auditor).await;
        let (status, body) =
            as_agent(&fixture, &auditor, "vault.usage.repair.receipts", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the holder reads the receipts: {body}"
        );
        assert!(
            body["receipts"].is_array(),
            "the holder reads a list: {body}"
        );
        let (status, body) =
            as_agent(&fixture, &other, "vault.usage.repair.receipts", json!({})).await;
        assert_forbidden(status, &body, "the receipts for an agent without the power");

        owner_changes(&fixture, "vault.audit_read.revoke", &auditor).await;
        let (status, body) =
            as_agent(&fixture, &auditor, "vault.usage.repair.receipts", json!({})).await;
        assert_forbidden(status, &body, "the receipts after the revoke");
    });
}
