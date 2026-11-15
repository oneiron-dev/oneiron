//! The owner's machine list and his name for each machine at their served
//! doors (FIX [DEVICE-DISPLAY-NAME]): `GET /v1/owner/machines`, `POST
//! /v1/owner/machines/name` and their facade rows `vault.machines.list` and
//! `vault.machines.name.set`.
//!
//! Every case drives the real routes in process (`build_app` + `oneshot`):
//! the owner on the host root credential, and an agent on its own paired
//! credential, enrolled through a real pairing redemption and proving its
//! holder key on every request. This install's machine profile is enrolled
//! as a serving start enrols it. Each case owns its vault. No sleeps, no
//! models.
//!
//! The promises:
//! - the list names this install by the name its host reports, with its
//!   class, role, standing and the revision `/machines/answer` reads; the
//!   route and the row answer the same machines;
//! - with no report, the machine is named by its class;
//! - the owner's own name wins over the report, and clearing it falls back
//!   to the report; neither moves the machine's revision;
//! - a name past one line, and a machine the vault does not know, are
//!   refused;
//! - both doors are the owner's: an agent is refused at the rows and the
//!   routes, and its attempt changes no name.
//!
//! Red on main: neither the rows nor the routes exist there (404).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! machine_name_doors`. It calls no test door; the cfg flag builds
//! `MemoryKeystore`.
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
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The name and model the host of the reporting fixture declares.
const REPORTED_NAME: &str = "Kitchen laptop";
const REPORTED_MODEL: &str = "MacBook Air";

/// One paired agent credential: its holder signing key, its redeemed slip
/// and the token it presents.
struct Agent {
    holder: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

/// A served vault with its owner's host root credential, this install's
/// machine and one paired agent.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    machine: String,
    agent: Agent,
}

/// Who posts a request.
#[derive(Clone, Copy)]
enum Caller {
    Owner,
    Agent,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn error_code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

/// A vault whose host declares `name` and `model` for this install, served,
/// with this install's machine profile enrolled.
async fn served(name: Option<&str>, model: Option<&str>) -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let mut config = VaultConfig::device();
    config.machine_reported_name = name.map(str::to_owned);
    config.machine_reported_model = model.map(str::to_owned);
    let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("machine-name-doors".into()),
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
    // This install's own machine, as a serving start enrols it.
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let machine = vault
        .local_machine()
        .expect("this install's machine")
        .expect("this install has a machine id")
        .id
        .to_hex();
    let app = build_app(server);
    let agent = pair_agent(&vault, &app, &issuer, "machine-name-agent", [0x4d; 32]).await;
    Served {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
        machine,
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

    fn token(&self, caller: Caller) -> &str {
        match caller {
            Caller::Owner => self.owner_token.as_str(),
            Caller::Agent => self.agent.token.as_str(),
        }
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
        let request = Request::post(path)
            .header("authorization", format!("Bearer {}", self.token(caller)))
            .header("x-oneiron-binding", self.binding(caller))
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("route request");
        self.send(request).await
    }

    /// `caller` gets the route at `path`: the status and the body.
    async fn get(&self, caller: Caller, path: &str) -> (StatusCode, Value) {
        let request = Request::get(path)
            .header("authorization", format!("Bearer {}", self.token(caller)))
            .header("x-oneiron-binding", self.binding(caller))
            .body(Body::empty())
            .expect("route request");
        self.send(request).await
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, Value) {
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("route response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("route response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The owner's list at its route, asserted 200: its machines.
    async fn list(&self) -> Vec<Value> {
        let (status, body) = self.get(Caller::Owner, "/v1/owner/machines").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner lists the machines: {body}"
        );
        body["machines"]
            .as_array()
            .expect("the list answers machines")
            .clone()
    }

    /// This install's machine as the owner's list shows it: the first
    /// machine, the one marked as this install.
    async fn this_install(&self) -> Value {
        let machines = self.list().await;
        let first = machines
            .first()
            .expect("the list names this install")
            .clone();
        assert_eq!(
            first["this_install"], true,
            "this install comes first: {machines:?}"
        );
        assert_eq!(first["machine"], self.machine.as_str(), "{first}");
        assert_eq!(
            machines
                .iter()
                .filter(|machine| machine["this_install"] == true)
                .count(),
            1,
            "one machine is this install: {machines:?}"
        );
        first
    }

    /// This install's revision as `GET /v1/owner/machines/answer` reads it.
    async fn answer_revision(&self) -> String {
        let (status, body) = self
            .get(
                Caller::Owner,
                &format!("/v1/owner/machines/answer?machine={}", self.machine),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner reads the answer: {body}");
        body["revision"]
            .as_str()
            .expect("the answer names a revision")
            .to_owned()
    }
}

/// The list names this install by the name its host reports, with its
/// class, role, standing and revision; the facade row answers the same.
#[test]
fn the_owner_lists_this_install_by_the_name_its_host_reports() {
    run_on_engine_stack("machine-name-reported", || async {
        let served = served(Some(REPORTED_NAME), Some(REPORTED_MODEL)).await;
        let mine = served.this_install().await;
        assert_eq!(mine["name"], REPORTED_NAME, "{mine}");
        assert_eq!(mine["name_source"], "reported", "{mine}");
        assert_eq!(mine["reported_name"], REPORTED_NAME, "{mine}");
        assert_eq!(mine["reported_model"], REPORTED_MODEL, "{mine}");
        assert_eq!(mine["owner_name"], Value::Null, "{mine}");
        assert_eq!(mine["class"], "computer", "{mine}");
        assert_eq!(mine["role"], "unanswered", "{mine}");
        assert_eq!(mine["live"], true, "{mine}");
        assert_eq!(
            mine["revision"],
            served.answer_revision().await.as_str(),
            "the list's revision is the one /machines/answer reads: {mine}"
        );

        let (status, route) = served.get(Caller::Owner, "/v1/owner/machines").await;
        assert_eq!(status, StatusCode::OK, "the owner's route: {route}");
        let (status, row) = served
            .post(Caller::Owner, "vault.machines.list", json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "the owner's facade row: {row}");
        assert_eq!(
            row["machines"], route["machines"],
            "the row answers the route's machines"
        );
    });
}

/// With no report, the machine is named by its class.
#[test]
fn a_machine_that_reports_no_name_is_named_by_its_class() {
    run_on_engine_stack("machine-name-class", || async {
        let served = served(None, None).await;
        let mine = served.this_install().await;
        assert_eq!(mine["name"], "Computer", "{mine}");
        assert_eq!(mine["name_source"], "class", "{mine}");
        assert_eq!(mine["reported_name"], Value::Null, "{mine}");
        assert_eq!(mine["reported_model"], Value::Null, "{mine}");
    });
}

/// The owner's own name wins over the report, at the route; clearing it at
/// the row falls back to the report. Each act answers a Gate receipt, and
/// neither moves the machine's revision.
#[test]
fn the_owners_name_wins_over_the_report_and_clearing_it_falls_back() {
    run_on_engine_stack("machine-name-owner", || async {
        let served = served(Some(REPORTED_NAME), None).await;
        let revision = served.answer_revision().await;

        let (status, set) = served
            .request(
                Caller::Owner,
                "/v1/owner/machines/name",
                json!({"machine": served.machine, "name": "  Office Mac  "}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner names the machine: {set}");
        assert_eq!(set["machine"]["machine"], served.machine.as_str(), "{set}");
        assert_eq!(set["machine"]["name"], "Office Mac", "trimmed: {set}");
        assert_eq!(set["machine"]["name_source"], "owner", "{set}");
        assert_eq!(set["machine"]["owner_name"], "Office Mac", "{set}");
        assert!(
            set["receipt"]
                .as_str()
                .is_some_and(|receipt| receipt.starts_with("gate:")),
            "the act answers its Gate receipt: {set}"
        );
        let mine = served.this_install().await;
        assert_eq!(
            mine["name"], "Office Mac",
            "the list shows the owner's name: {mine}"
        );
        assert_eq!(mine["name_source"], "owner", "{mine}");
        assert_eq!(
            mine["reported_name"], REPORTED_NAME,
            "the report stays: {mine}"
        );
        assert_eq!(
            served.answer_revision().await,
            revision,
            "a name moves no revision"
        );

        let (status, cleared) = served
            .post(
                Caller::Owner,
                "vault.machines.name.set",
                json!({"machine": served.machine, "name": null}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner clears the name: {cleared}"
        );
        assert_eq!(cleared["machine"]["name"], REPORTED_NAME, "{cleared}");
        assert_eq!(cleared["machine"]["name_source"], "reported", "{cleared}");
        assert_eq!(cleared["machine"]["owner_name"], Value::Null, "{cleared}");
        assert!(
            cleared["receipt"]
                .as_str()
                .is_some_and(|receipt| receipt.starts_with("gate:") && receipt != set["receipt"]),
            "the clear answers its own Gate receipt: {cleared}"
        );
        let mine = served.this_install().await;
        assert_eq!(
            mine["name"], REPORTED_NAME,
            "the report names it again: {mine}"
        );
        assert_eq!(mine["name_source"], "reported", "{mine}");
        assert_eq!(
            served.answer_revision().await,
            revision,
            "a clear moves no revision"
        );
    });
}

/// A name past one line or past the cap is refused (400), as is a machine
/// id that is not 32 hex (400) and a machine the vault does not know (404),
/// at the route and the row. The name stays as it was.
#[test]
fn a_bad_name_or_an_unknown_machine_is_refused() {
    run_on_engine_stack("machine-name-refused", || async {
        let served = served(Some(REPORTED_NAME), None).await;
        let unknown = EntityId::now().to_hex();
        let too_long = "n".repeat(129);
        for (input, expected, why) in [
            (
                json!({"machine": served.machine, "name": "Office\nMac"}),
                StatusCode::BAD_REQUEST,
                "a two-line name",
            ),
            (
                json!({"machine": served.machine, "name": too_long}),
                StatusCode::BAD_REQUEST,
                "a name past 128 bytes",
            ),
            (
                json!({"machine": "not-an-id", "name": "Office Mac"}),
                StatusCode::BAD_REQUEST,
                "a malformed machine id",
            ),
            (
                json!({"machine": unknown, "name": "Office Mac"}),
                StatusCode::NOT_FOUND,
                "a machine the vault does not know",
            ),
        ] {
            let (status, body) = served
                .request(Caller::Owner, "/v1/owner/machines/name", input.clone())
                .await;
            assert_eq!(status, expected, "the route refuses {why}: {body}");
            let (status, body) = served
                .post(Caller::Owner, "vault.machines.name.set", input)
                .await;
            assert_eq!(status, expected, "the row refuses {why}: {body}");
        }
        let mine = served.this_install().await;
        assert_eq!(mine["name"], REPORTED_NAME, "nothing was named: {mine}");
        assert_eq!(mine["owner_name"], Value::Null, "{mine}");
    });
}

/// Both doors are the owner's: an agent is refused at the rows and the
/// routes, and its attempt changes no name.
#[test]
fn an_agent_reaches_neither_the_list_nor_the_name() {
    run_on_engine_stack("machine-name-agent", || async {
        let served = served(Some(REPORTED_NAME), None).await;
        let input = json!({"machine": served.machine, "name": "Agent's name"});
        for (verb, input) in [
            ("vault.machines.list", json!({})),
            ("vault.machines.name.set", input.clone()),
        ] {
            let (status, body) = served.post(Caller::Agent, verb, input).await;
            assert_eq!(
                (status, error_code(&body)),
                (StatusCode::FORBIDDEN, Some("FORBIDDEN")),
                "the agent is refused at {verb}: {body}"
            );
        }
        let (status, body) = served.get(Caller::Agent, "/v1/owner/machines").await;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
            "the agent is refused at GET /v1/owner/machines: {status} {body}"
        );
        let (status, body) = served
            .request(Caller::Agent, "/v1/owner/machines/name", input)
            .await;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
            "the agent is refused at POST /v1/owner/machines/name: {status} {body}"
        );
        let mine = served.this_install().await;
        assert_eq!(
            mine["name"], REPORTED_NAME,
            "the agent named nothing: {mine}"
        );
        assert_eq!(mine["owner_name"], Value::Null, "{mine}");
    });
}
