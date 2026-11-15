//! Public-door promise tests for the `vault.secrets` family (ruling L4-23 =
//! A: each test proves a promise at the door; DOOR-FAMILIES Part 2, row 2).
//!
//! Every case drives the real route `POST /v1/core/facade/<verb>` in process
//! (`build_app` + `oneshot`): the owner on the host root credential, the
//! established self-hosted owner path, and an agent on its own paired
//! credential, enrolled through a real pairing redemption and proving its
//! holder key on every request. Each case owns its vault. No sockets, no
//! sleeps, no models.
//!
//! The promises, with their canon lines (oneiron-docs `generated/`,
//! `oneiron/gate/oneiron-arch-0069-secret-custody-v1.md`):
//! - a register or rotate reply never carries the value: `:380` "The reply
//!   never carries the value." and "The reply carries metadata and the
//!   manifest copy, never the value.";
//! - a rotation moves the generation by one and nothing rotates on its own:
//!   `:380` "The reply is the receipt: its id, the name, the old and new
//!   generation, and the time." and "Rotation stays owner-initiated";
//! - a revoke ends the record: the `vault.secrets.revoke` row, "the record
//!   goes terminal and every lease over it is revoked";
//! - custody is the owner's: `:380` "The engine rechecks the owner's proof in
//!   the transaction that replaces the value", so an agent is refused at
//!   every door of the family and writes nothing.
//!
//! These promises hold on main. Their red proof is a seeded fault (Test rules
//! v2, rule 5), named in the PR.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! vault_secrets_doors`. The test calls no test door; it needs
//! `oneiron/test-support` for `MemoryKeystore`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The name every case registers its secret under.
const NAME: &str = "doors-custody-secret";

/// One paired agent credential: its registered principal, its holder
/// signing key, its redeemed slip and the token it presents.
struct Agent {
    holder: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

/// A served vault with its owner's host root credential and one paired
/// agent.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    agent: Agent,
}

/// Who posts a request.
#[derive(Clone, Copy)]
enum Caller {
    Owner,
    Agent,
}

/// One secret value: its bytes as text and the standard base64 the doors
/// take.
struct SecretValue {
    raw: String,
    base64: String,
}

impl SecretValue {
    /// A fresh value no other case or fixture spells.
    fn fresh() -> Self {
        let raw = format!("doors_custody_{}", EntityId::now().to_hex());
        let base64 = STANDARD.encode(raw.as_bytes());
        Self { raw, base64 }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn error_code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

/// Neither the value nor its base64 appears anywhere in `body`.
fn assert_value_free(what: &str, body: &Value, values: &[&SecretValue]) {
    let text = body.to_string();
    for value in values {
        assert!(
            !text.contains(&value.raw),
            "{what} carries a secret value: {text}"
        );
        assert!(
            !text.contains(&value.base64),
            "{what} carries a secret value's base64: {text}"
        );
    }
}

async fn served() -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-secrets-doors".into()),
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
    let app = build_app(server);
    let agent = pair_agent(&vault, &app, &issuer, "secrets-doors-agent", [0x41; 32]).await;
    Served {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
        agent,
    }
}

/// Pairs one agent the way `token agent` does: a registered PERSON
/// principal, a principal-bound link narrowed to `core:read` and
/// `core:write`, redeemed over the real pairing route with the
/// holder-signed binding transcript.
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
    let transcript = pairing_binding_transcript(&link.code, &binding_key, &principal.to_hex())
        .expect("pairing transcript");
    let signature = hex(&holder.sign(&transcript).to_bytes());
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
        slip.claims.actor_class.as_deref(),
        Some("agent"),
        "the redeemed slip binds an agent"
    );
    Agent {
        holder,
        slip,
        token,
    }
}

impl Served {
    /// The request binding `caller` signs afresh for one request.
    fn binding(&self, caller: Caller) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = match caller {
            Caller::Owner => hex(&self
                .issuer
                .binding_proof(&self.owner_slip, challenge.as_bytes())
                .expect("owner holder proof")),
            Caller::Agent => {
                let transcript = self
                    .agent
                    .slip
                    .binding_transcript(challenge.as_bytes())
                    .expect("agent binding transcript");
                hex(&self.agent.holder.sign(&transcript).to_bytes())
            }
        };
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    /// `caller` posts `verb` with `input` to its facade door: the status and
    /// the body.
    async fn post(&self, caller: Caller, verb: &str, input: Value) -> (StatusCode, Value) {
        let token = match caller {
            Caller::Owner => self.owner_token.as_str(),
            Caller::Agent => self.agent.token.as_str(),
        };
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", self.binding(caller))
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("facade request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("facade response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .expect("facade response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The owner registers `name` with `value`: a portable record at rung
    /// 0 with no binding. Asserts the 200 and answers the reply.
    async fn register(&self, name: &str, value: &SecretValue) -> Value {
        let (status, body) = self
            .post(Caller::Owner, "vault.secrets.register", register_input(name, value))
            .await;
        assert_eq!(status, StatusCode::OK, "the owner registers {name}: {body}");
        body
    }

    /// The owner's value-free custody view of `name`.
    async fn custody(&self, name: &str) -> Value {
        let (status, body) = self
            .post(
                Caller::Owner,
                "vault.secrets.custody.get",
                json!({"name": name}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner reads {name}'s custody: {body}"
        );
        body
    }
}

/// A register input for `name` with `value`: portable, rung 0, no binding.
fn register_input(name: &str, value: &SecretValue) -> Value {
    json!({
        "name": name,
        "class": "custody-portable",
        "device_only": false,
        "rung": 0,
        "value_base64": value.base64,
        "bindings": [],
    })
}

/// The owner registers a secret and rotates it twice: each reply is 200,
/// value-free, and moves the generation by exactly one (0, then 0 to 1,
/// then 1 to 2), and the custody view reads each new generation back,
/// value-free. A rotate with no value is refused 400 and moves nothing.
/// "The reply never carries the value" (arch-0069:380).
#[test]
fn register_and_rotate_replies_never_carry_the_value() {
    run_on_engine_stack("secrets-doors-replies", || async {
        let served = served().await;
        let values = [
            SecretValue::fresh(),
            SecretValue::fresh(),
            SecretValue::fresh(),
        ];
        let all: Vec<&SecretValue> = values.iter().collect();

        let registered = served.register(NAME, &values[0]).await;
        assert_value_free("the register reply", &registered, &all);
        assert_eq!(registered["name"].as_str(), Some(NAME), "{registered}");
        assert_eq!(
            registered["rotation_generation"].as_u64(),
            Some(0),
            "a register starts at generation 0: {registered}"
        );
        let view = served.custody(NAME).await;
        assert_value_free("the custody view", &view, &all);
        assert_eq!(view["known"].as_bool(), Some(true), "{view}");
        assert_eq!(view["generation"].as_u64(), Some(0), "{view}");

        for (from, value) in [(0_u64, &values[1]), (1, &values[2])] {
            let (status, rotated) = served
                .post(
                    Caller::Owner,
                    "vault.secrets.rotate",
                    json!({"name": NAME, "value_base64": value.base64}),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "the owner rotates: {rotated}");
            assert_value_free("the rotate reply", &rotated, &all);
            assert_eq!(
                (
                    rotated["kind"].as_str(),
                    rotated["from_generation"].as_u64(),
                    rotated["to_generation"].as_u64(),
                ),
                (Some("rotated"), Some(from), Some(from + 1)),
                "a rotation moves the generation by one: {rotated}"
            );
            let view = served.custody(NAME).await;
            assert_value_free("the custody view after a rotation", &view, &all);
            assert_eq!(view["generation"].as_u64(), Some(from + 1), "{view}");
        }

        let (status, empty) = served
            .post(
                Caller::Owner,
                "vault.secrets.rotate",
                json!({"name": NAME, "value_base64": ""}),
            )
            .await;
        assert_eq!(
            (status, error_code(&empty)),
            (StatusCode::BAD_REQUEST, Some("BAD_REQUEST")),
            "a rotate with no value is refused: {empty}"
        );
        let view = served.custody(NAME).await;
        assert_eq!(
            view["generation"].as_u64(),
            Some(2),
            "a refused rotate moves nothing: {view}"
        );
    });
}

/// The owner revokes a registered secret: 200, a value-free reply that
/// reads as a rotation's with kind `revoked` and the generation unmoved,
/// and the record is no longer active. A rotate of the revoked name is
/// refused with a client error and revives nothing ("the record goes
/// terminal", the `vault.secrets.revoke` row).
#[test]
fn a_revoke_ends_the_record_and_no_rotate_revives_it() {
    run_on_engine_stack("secrets-doors-revoke", || async {
        let served = served().await;
        let first = SecretValue::fresh();
        let later = SecretValue::fresh();
        let all = [&first, &later];
        served.register(NAME, &first).await;

        let (status, revoked) = served
            .post(Caller::Owner, "vault.secrets.revoke", json!({"name": NAME}))
            .await;
        assert_eq!(status, StatusCode::OK, "the owner revokes: {revoked}");
        assert_value_free("the revoke reply", &revoked, &all);
        assert_eq!(
            (
                revoked["kind"].as_str(),
                revoked["from_generation"].as_u64(),
                revoked["to_generation"].as_u64(),
            ),
            (Some("revoked"), Some(0), Some(0)),
            "a revoke reads as a rotation that moves no generation: {revoked}"
        );
        let view = served.custody(NAME).await;
        assert_value_free("the custody view after a revoke", &view, &all);
        let active = |view: &Value| {
            view["known"].as_bool() == Some(true) && view["status"].as_str() == Some("active")
        };
        assert!(!active(&view), "a revoked record is not active: {view}");

        let (status, rotated) = served
            .post(
                Caller::Owner,
                "vault.secrets.rotate",
                json!({"name": NAME, "value_base64": later.base64}),
            )
            .await;
        assert!(
            status.is_client_error(),
            "a rotate of a revoked record is refused: {status} {rotated}"
        );
        assert_value_free("the refused rotate's reply", &rotated, &all);
        let view = served.custody(NAME).await;
        assert!(
            !active(&view),
            "a refused rotate revives no record: {view}"
        );
    });
}
