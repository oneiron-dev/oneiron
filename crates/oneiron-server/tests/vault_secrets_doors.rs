//! Public-door promise tests for the `vault.secrets` family (ruling L4-23 =
//! A: each test proves a promise at the door; DOOR-FAMILIES Part 2, row 2).
//!
//! Every case drives the real routes `POST /v1/core/facade/<verb>` and
//! `POST /v1/core/query` in process (`build_app` + `oneshot`): the owner on
//! the host root credential, the established self-hosted owner path, and an
//! agent on its own paired credential, enrolled through a real pairing
//! redemption and proving its holder key on every request. Each case owns
//! its vault. No sockets, no sleeps, no models.
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
//!   every door of the family and writes nothing;
//! - a secret is not knowledge: `:8` "Secrets are not knowledge, and the
//!   repo is not their sync plane." and "never as retrievable claims", so no
//!   recall or query names the record, and an export with secrets left out
//!   carries no value.
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
use std::io::{Cursor, Read};
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

/// The name the agent's refused register asks for.
const AGENT_NAME: &str = "doors-custody-agent-secret";

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
        self.request(caller, &format!("/v1/core/facade/{verb}"), input)
            .await
    }

    /// `caller` posts `input` to the route at `path`: the status and the
    /// body.
    async fn request(&self, caller: Caller, path: &str, input: Value) -> (StatusCode, Value) {
        let token = match caller {
            Caller::Owner => self.owner_token.as_str(),
            Caller::Agent => self.agent.token.as_str(),
        };
        let request = Request::post(path)
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", self.binding(caller))
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("route request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("route response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 64 * 1024 * 1024)
            .await
            .expect("route response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The owner registers `name` with `value`: a portable record at rung
    /// 0 with no binding. Asserts the 200 and answers the reply.
    async fn register(&self, name: &str, value: &SecretValue) -> Value {
        let (status, body) = self
            .post(
                Caller::Owner,
                "vault.secrets.register",
                register_input(name, value),
            )
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
        assert!(!active(&view), "a refused rotate revives no record: {view}");
    });
}

/// The agent, on its own verified credential, posts each of the nine
/// `vault.secrets` doors with a well-formed input. Each answers 403
/// `FORBIDDEN` with no value in its body, and none writes: the owner's
/// record keeps its id, status, generation and custody revision, and the
/// name the agent asked to register stays unknown. Custody is the owner's
/// (arch-0069:380). Red with the seeded fault that lets the host doors'
/// owner proof fall back to the embedded owner.
#[test]
fn an_agent_is_refused_at_every_door_of_the_family() {
    run_on_engine_stack("secrets-doors-agent", || async {
        let served = served().await;
        let kept = SecretValue::fresh();
        let offered = SecretValue::fresh();
        let all = [&kept, &offered];
        served.register(NAME, &kept).await;
        let before = served.custody(NAME).await;
        let record = |view: &Value| {
            [
                view["secret_id"].clone(),
                view["known"].clone(),
                view["status"].clone(),
                view["generation"].clone(),
                view["seen"].clone(),
            ]
        };
        let rows: [(&str, Value); 9] = [
            (
                "vault.secrets.register",
                register_input(AGENT_NAME, &offered),
            ),
            (
                "vault.secrets.rotate",
                json!({"name": NAME, "value_base64": offered.base64}),
            ),
            (
                "vault.secrets.rewrap",
                json!({"name": NAME, "recipients": []}),
            ),
            ("vault.secrets.revoke", json!({"name": NAME})),
            ("vault.secrets.custody.get", json!({"name": NAME})),
            (
                "vault.secrets.custody.submit",
                json!({
                    "change": "rotate",
                    "secret_id": before["secret_id"],
                    "generation": 1,
                    "seen": before["seen"],
                    "holder": EntityId::now().to_hex(),
                    "recipients": [],
                    "input_base64": offered.base64,
                }),
            ),
            ("vault.secrets.code_run_lifts", json!({})),
            (
                "vault.secrets.code_run_room_lifts",
                json!({"room_ref": EntityId::now().to_hex(), "session_ref": "doors-custody"}),
            ),
            ("vault.secrets.lift_history", json!({})),
        ];
        for (verb, input) in rows {
            let (status, body) = served.post(Caller::Agent, verb, input).await;
            assert_eq!(
                (status, error_code(&body)),
                (StatusCode::FORBIDDEN, Some("FORBIDDEN")),
                "the agent is refused at {verb}: {body}"
            );
            assert_value_free(verb, &body, &all);
        }

        let after = served.custody(NAME).await;
        assert_eq!(
            record(&after),
            record(&before),
            "no refused agent call moves the owner's record: {after}"
        );
        let asked = served.custody(AGENT_NAME).await;
        assert_eq!(
            asked["known"].as_bool(),
            Some(false),
            "the agent's refused register holds nothing: {asked}"
        );
    });
}

/// A registered secret is not knowledge (arch-0069:8). The owner's and the
/// agent's recall and query of its name answer 200 and name neither the
/// record nor its value. The owner's JSON export and archive with secrets
/// left out carry no value: the archive keeps the record as a handle with
/// no body, and no member of it holds the value or its base64. Red with the
/// seeded fault that opens custody values into an archive whose secrets
/// were left out.
#[test]
fn a_secret_is_not_knowledge_and_no_read_carries_its_value() {
    run_on_engine_stack("secrets-doors-knowledge", || async {
        let served = served().await;
        let value = SecretValue::fresh();
        let all = [&value];
        let registered = served.register(NAME, &value).await;
        let secret_id = registered["secret_id"]
            .as_str()
            .expect("the register reply names the record")
            .to_owned();

        for caller in [Caller::Owner, Caller::Agent] {
            for (path, input) in [
                ("/v1/core/facade/vault.recall", json!({"query": NAME})),
                ("/v1/core/query", json!({"query": NAME, "limit": 10})),
            ] {
                let (status, body) = served.request(caller, path, input).await;
                assert_eq!(status, StatusCode::OK, "{path}: {body}");
                assert_value_free(path, &body, &all);
                assert!(
                    !body.to_string().contains(&secret_id),
                    "{path} names the custody record: {body}"
                );
            }
        }

        let (status, document) = served
            .post(Caller::Owner, "vault.export", json!({"format": "json"}))
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner's JSON export: {document}"
        );
        assert_value_free("the JSON export", &document, &all);

        let (status, export) = served
            .post(
                Caller::Owner,
                "vault.export",
                json!({"format": "archive", "include_secrets": false, "delivery": "inline"}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner's archive: {export}");
        assert_value_free("the archive reply", &export, &all);
        let bytes = STANDARD
            .decode(export["archive"].as_str().expect("an inline archive"))
            .expect("the archive is standard base64");
        let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).expect("the archive is a ZIP");
        let mut custody_rows = Vec::new();
        for index in 0..archive.len() {
            let mut member = archive.by_index(index).expect("an archive member");
            let name = member.name().to_owned();
            let mut content = Vec::new();
            member
                .read_to_end(&mut content)
                .expect("the archive member reads");
            let text = String::from_utf8_lossy(&content);
            assert!(
                !text.contains(&value.raw) && !text.contains(&value.base64),
                "archive member {name} carries the secret value"
            );
            if name == "records/secret_custody.jsonl" {
                custody_rows.extend(
                    text.lines()
                        .filter(|line| !line.trim().is_empty())
                        .map(|line| serde_json::from_str::<Value>(line).expect("a custody row")),
                );
            }
        }
        let row = custody_rows
            .iter()
            .find(|row| row["name"].as_str() == Some(NAME))
            .expect("the owner's archive keeps the record as a handle");
        assert!(
            row["body"].is_null(),
            "an archive with secrets left out carries no custody body: {row}"
        );
    });
}
