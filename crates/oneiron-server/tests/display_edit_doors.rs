//! Display-edit proposals at their served doors (FIX
//! [SECRETS-LABEL-PURPOSE-VERBS], [DEVICE-DISPLAY-NAME]; Engine RULING
//! DISPLAY-EDIT-PROPOSAL-SCOPE = A): the agent row `self.display_edits.propose`,
//! the owner's rows `vault.display_edits.list`, `.accept` and `.decline`, and
//! their routes `GET /v1/owner/display-edits`, `POST
//! /v1/owner/display-edits/accept` and `/decline`.
//!
//! Every case drives the real routes in process (`build_app` + `oneshot`):
//! the owner on the host root credential, and an agent on its own paired
//! credential, enrolled through a real pairing redemption and proving its
//! holder key on every request. Each case owns its vault. No sleeps, no
//! models.
//!
//! The promises:
//! - an agent's proposal changes nothing until the owner accepts it; the
//!   accept runs the owner's own door (a Gate receipt) and closes it, for a
//!   secret's label, a secret's purpose and a machine's name;
//! - a decline closes it and changes nothing;
//! - a proposal raises one inbox Ask for the owner, settled by the answer;
//! - a newer proposal of the agent's for the same edit replaces the open one;
//! - text with a credential, a subject the vault does not know, and a
//!   proposal past the agent's open cap (32) are refused;
//! - an agent never answers, and the owner never proposes.
//!
//! Red on the base (#8635's head): none of the rows or routes exists there
//! (404).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! display_edit_doors`. It calls no test door; the cfg flag builds
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
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The custody name every secret of a case starts with.
const NAME: &str = "display-edit-secret";

/// The producer of a proposal's inbox Ask.
const PRODUCER: &str = "display_edit.proposal";

/// One paired agent credential: its holder signing key, its redeemed slip
/// and the token it presents.
struct Agent {
    id: String,
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

/// A served vault with this install's machine profile enrolled and one
/// paired agent.
async fn served() -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("display-edit-doors".into()),
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
    let agent = pair_agent(&vault, &app, &issuer, "display-edit-agent", [0x5e; 32]).await;
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
        id: principal.to_hex(),
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

    /// The owner registers a secret named `name` (a portable record at rung
    /// 1 with one binding, as the register route's own test does): its bare
    /// handle, as an agent names it.
    async fn register(&self, name: &str) -> String {
        let value = STANDARD.encode(format!("display_edit_{}", EntityId::now().to_hex()));
        let (status, body) = self
            .post(
                Caller::Owner,
                "vault.secrets.register",
                json!({
                    "name": name,
                    "class": "custody-portable",
                    "device_only": false,
                    "rung": 1,
                    "value_base64": value,
                    "bindings": [{"effector": "deploy", "scopes": ["read"]}],
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner registers {name}: {body}");
        let id = self
            .vault
            .resolve_secret_ref(name)
            .expect("the custody name resolves")
            .expect("the registered secret is in custody");
        let reference = oneiron::retrieval_depth::short_ref_or_hex(&self.vault, &id)
            .expect("the record's short reference");
        let handle = reference
            .split(':')
            .next()
            .expect("a short reference")
            .to_owned();
        assert!(handle.starts_with("sc"), "a secret handle: {reference}");
        handle
    }

    /// The name the agent's handle card gives the secret `handle`: the
    /// owner's label, else the custody name.
    async fn card_label(&self, handle: &str) -> String {
        let (status, card) = self
            .post(Caller::Agent, "reveal.describe", json!({"handle": handle}))
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the agent describes {handle}: {card}"
        );
        card["label"]
            .as_str()
            .expect("the card names the secret")
            .to_owned()
    }

    /// The owner's proof as the engine's own doors take it.
    fn owner_proof(&self) -> AuthenticatedOwner {
        let owner = self
            .vault
            .ensure_embedded_owner_actor()
            .expect("the vault's owner");
        self.vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("the owner's proof")
    }

    /// The purpose the engine holds for `handle`, read at its own door.
    fn stored_purpose(&self, handle: &str) -> Option<String> {
        self.vault
            .secret_handle_purpose(&self.owner_proof(), handle)
            .expect("the owner reads the purpose")
            .and_then(|set| set.purpose)
    }

    /// The agent proposes `input` at its row: the status and the body.
    async fn propose(&self, input: Value) -> (StatusCode, Value) {
        self.post(Caller::Agent, "self.display_edits.propose", input)
            .await
    }

    /// The agent proposes `input`, asserted 200: the proposal's id.
    async fn proposed(&self, input: Value) -> String {
        let (status, body) = self.propose(input.clone()).await;
        assert_eq!(status, StatusCode::OK, "the agent proposes {input}: {body}");
        assert_eq!(body["target"], input["target"], "{body}");
        assert_eq!(body["value"], input["value"], "{body}");
        assert_eq!(body["proposer"], self.agent.id.as_str(), "{body}");
        body["id"]
            .as_str()
            .expect("the proposal names its id")
            .to_owned()
    }

    /// The owner's open proposals at the route, asserted 200.
    async fn proposals(&self) -> Vec<Value> {
        let (status, body) = self.get(Caller::Owner, "/v1/owner/display-edits").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner lists the proposals: {body}"
        );
        body["proposals"]
            .as_array()
            .expect("the list answers proposals")
            .clone()
    }

    /// This install's machine as the owner's machine list shows it.
    async fn this_install(&self) -> Value {
        let (status, body) = self.get(Caller::Owner, "/v1/owner/machines").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner lists the machines: {body}"
        );
        body["machines"]
            .as_array()
            .expect("the list answers machines")
            .iter()
            .find(|machine| machine["machine"] == self.machine.as_str())
            .expect("the list names this install")
            .clone()
    }

    /// The owner's inbox rows a proposal's Ask raised.
    async fn asks_for(&self, proposal: &str) -> Vec<Value> {
        let (status, body) = self
            .post(Caller::Owner, "self.inbox.list", json!({"limit": 500}))
            .await;
        assert_eq!(status, StatusCode::OK, "the owner lists the inbox: {body}");
        body["rows"]
            .as_array()
            .expect("the inbox answers rows")
            .iter()
            .filter(|row| {
                row["source"]["producer"] == PRODUCER && row["source"]["result"] == proposal
            })
            .cloned()
            .collect()
    }
}

/// A label proposal changes nothing until the owner accepts it; the accept
/// runs his label door (a Gate receipt), the label lands, and the proposal
/// closes.
#[test]
fn an_accepted_label_proposal_labels_the_secret_as_the_owners_act() {
    run_on_engine_stack("display-edit-label", || async {
        let served = served().await;
        let handle = served.register(NAME).await;
        assert_eq!(served.card_label(&handle).await, NAME);
        let id = served
            .proposed(json!({
                "target": "secret_label",
                "subject": handle,
                "value": "Billing key",
                "why": "the invoices call it the billing key",
            }))
            .await;
        assert_eq!(
            served.card_label(&handle).await,
            NAME,
            "a proposal labels nothing"
        );
        let open = served.proposals().await;
        assert_eq!(open.len(), 1, "{open:?}");
        assert_eq!(open[0]["id"], id.as_str(), "{open:?}");
        assert_eq!(open[0]["subject"], handle.as_str(), "{open:?}");
        assert_eq!(open[0]["why"], "the invoices call it the billing key");

        let (status, body) = served
            .request(
                Caller::Owner,
                "/v1/owner/display-edits/accept",
                json!({"id": id}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner accepts: {body}");
        assert_eq!(body["proposal"]["id"], id.as_str(), "{body}");
        assert!(
            body["receipt"]
                .as_str()
                .is_some_and(|receipt| receipt.starts_with("gate:")),
            "the accept answers the label act's Gate receipt: {body}"
        );
        assert_eq!(served.card_label(&handle).await, "Billing key");
        assert!(served.proposals().await.is_empty(), "the proposal closed");
        let (status, body) = served
            .request(
                Caller::Owner,
                "/v1/owner/display-edits/accept",
                json!({"id": id}),
            )
            .await;
        assert!(
            status.is_client_error(),
            "a closed proposal is no longer answered: {status} {body}"
        );
    });
}

/// A declined purpose proposal closes and changes nothing; the owner answers
/// at his facade rows as at the routes.
#[test]
fn a_declined_purpose_proposal_changes_nothing() {
    run_on_engine_stack("display-edit-decline", || async {
        let served = served().await;
        let handle = served.register(NAME).await;
        let id = served
            .proposed(json!({
                "target": "secret_purpose",
                "subject": handle,
                "value": "Pays the hosting bill",
                "why": "the owner said it pays for hosting",
            }))
            .await;
        let (status, body) = served
            .post(Caller::Owner, "vault.display_edits.list", json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "the owner lists at the row: {body}");
        assert_eq!(body["proposals"][0]["id"], id.as_str(), "{body}");
        let (status, body) = served
            .post(
                Caller::Owner,
                "vault.display_edits.decline",
                json!({"id": id}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner declines: {body}");
        assert_eq!(body["proposal"]["id"], id.as_str(), "{body}");
        assert_eq!(served.stored_purpose(&handle), None, "nothing changed");
        assert!(served.proposals().await.is_empty(), "the proposal closed");
        let (status, body) = served
            .post(
                Caller::Owner,
                "vault.display_edits.accept",
                json!({"id": id}),
            )
            .await;
        assert!(
            status.is_client_error(),
            "a declined proposal is no longer answered: {status} {body}"
        );
        assert_eq!(
            served.stored_purpose(&handle),
            None,
            "still nothing changed"
        );
    });
}

/// A machine-name proposal, accepted, names the machine as the owner's own
/// name for it.
#[test]
fn an_accepted_machine_name_proposal_names_the_machine() {
    run_on_engine_stack("display-edit-machine", || async {
        let served = served().await;
        let id = served
            .proposed(json!({
                "target": "machine_name",
                "subject": served.machine,
                "value": "Office server",
                "why": "this is the server in the office",
            }))
            .await;
        let mine = served.this_install().await;
        assert_eq!(
            mine["owner_name"],
            Value::Null,
            "a proposal names nothing: {mine}"
        );
        let (status, body) = served
            .post(
                Caller::Owner,
                "vault.display_edits.accept",
                json!({"id": id}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner accepts: {body}");
        let mine = served.this_install().await;
        assert_eq!(mine["name"], "Office server", "{mine}");
        assert_eq!(mine["name_source"], "owner", "{mine}");
        assert_eq!(mine["owner_name"], "Office server", "{mine}");
    });
}

/// A proposal raises one inbox Ask for the owner, and his answer settles it.
#[test]
fn a_proposal_raises_one_inbox_ask_that_the_answer_settles() {
    run_on_engine_stack("display-edit-ask", || async {
        let served = served().await;
        let handle = served.register(NAME).await;
        let id = served
            .proposed(json!({
                "target": "secret_label",
                "subject": handle,
                "value": "Deploy key",
                "why": "it deploys the site",
            }))
            .await;
        let asks = served.asks_for(&id).await;
        assert_eq!(asks.len(), 1, "one Ask for the one owner: {asks:?}");
        assert_eq!(asks[0]["acked"], false, "{asks:?}");
        let (status, body) = served
            .request(
                Caller::Owner,
                "/v1/owner/display-edits/decline",
                json!({"id": id}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner declines: {body}");
        let asks = served.asks_for(&id).await;
        assert_eq!(asks.len(), 1, "{asks:?}");
        assert_eq!(
            asks[0]["acked"], true,
            "the answer settles the Ask: {asks:?}"
        );
    });
}

/// A newer proposal of the agent's for the same edit on the same subject
/// replaces its open one; another edit on that subject stands beside it.
#[test]
fn a_newer_proposal_replaces_the_agents_open_one_for_the_same_edit() {
    run_on_engine_stack("display-edit-replace", || async {
        let served = served().await;
        let handle = served.register(NAME).await;
        let first = served
            .proposed(json!({
                "target": "secret_label",
                "subject": handle,
                "value": "Old name",
                "why": "first guess",
            }))
            .await;
        let second = served
            .proposed(json!({
                "target": "secret_label",
                "subject": handle,
                "value": "New name",
                "why": "second guess",
            }))
            .await;
        let open = served.proposals().await;
        assert_eq!(open.len(), 1, "the newer one replaced the older: {open:?}");
        assert_eq!(open[0]["id"], second.as_str(), "{open:?}");
        assert_eq!(open[0]["value"], "New name", "{open:?}");
        let (status, body) = served
            .request(
                Caller::Owner,
                "/v1/owner/display-edits/accept",
                json!({"id": first}),
            )
            .await;
        assert!(
            status.is_client_error(),
            "the replaced proposal is closed: {status} {body}"
        );
        served
            .proposed(json!({
                "target": "secret_purpose",
                "subject": handle,
                "value": null,
                "why": "clear what it is for",
            }))
            .await;
        assert_eq!(
            served.proposals().await.len(),
            2,
            "another edit stands beside it"
        );
        assert_eq!(served.card_label(&handle).await, NAME, "nothing changed");
    });
}

/// Text with a credential, a subject the vault does not know, and an agent
/// past its open cap are refused, and a refused proposal files nothing.
#[test]
fn a_credential_an_unknown_subject_or_the_open_cap_is_refused() {
    run_on_engine_stack("display-edit-refusals", || async {
        let served = served().await;
        let handle = served.register(NAME).await;
        let credential = "token=ghp_0123456789abcdefghijklmnopqrstuvwxyz";
        for (why, input) in [
            (
                "a credential in the value",
                json!({"target": "secret_label", "subject": handle, "value": credential, "why": "a name"}),
            ),
            (
                "a credential in the why",
                json!({"target": "secret_label", "subject": handle, "value": "Name", "why": credential}),
            ),
            (
                "an empty why",
                json!({"target": "secret_label", "subject": handle, "value": "Name", "why": " "}),
            ),
            (
                "a two-line value",
                json!({"target": "machine_name", "subject": served.machine, "value": "a\nb", "why": "a name"}),
            ),
            (
                "an unknown secret",
                json!({"target": "secret_purpose", "subject": "sc999999", "value": "x", "why": "a purpose"}),
            ),
            (
                "an unknown machine",
                json!({"target": "machine_name", "subject": EntityId::now().to_hex(), "value": "x", "why": "a name"}),
            ),
            (
                "a machine that is no id",
                json!({"target": "machine_name", "subject": "kitchen", "value": "x", "why": "a name"}),
            ),
        ] {
            let (status, body) = served.propose(input).await;
            assert!(
                status.is_client_error(),
                "{why} is refused: {status} {body}"
            );
        }
        assert!(served.proposals().await.is_empty(), "nothing was filed");

        // The cap: 32 open proposals over 16 secrets' labels and purposes.
        let mut handles = vec![handle];
        for index in 1..16 {
            handles.push(served.register(&format!("{NAME}-{index}")).await);
        }
        for handle in &handles {
            for target in ["secret_label", "secret_purpose"] {
                served
                    .proposed(json!({"target": target, "subject": handle, "value": "Name", "why": "a name"}))
                    .await;
            }
        }
        assert_eq!(served.proposals().await.len(), 32);
        let (status, body) = served
            .propose(json!({"target": "machine_name", "subject": served.machine, "value": "Server", "why": "a name"}))
            .await;
        assert!(
            status.is_client_error(),
            "a 33rd open proposal is refused: {status} {body}"
        );
        let (status, body) = served
            .propose(json!({"target": "secret_label", "subject": handles[0], "value": "Other", "why": "a name"}))
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "replacing an open proposal at the cap is no new one: {body}"
        );
        assert_eq!(served.proposals().await.len(), 32);
    });
}

/// An agent never answers a proposal, and the owner never proposes.
#[test]
fn the_agent_never_answers_and_the_owner_never_proposes() {
    run_on_engine_stack("display-edit-roles", || async {
        let served = served().await;
        let handle = served.register(NAME).await;
        let id = served
            .proposed(json!({
                "target": "secret_label",
                "subject": handle,
                "value": "Agent's name",
                "why": "a name",
            }))
            .await;
        for (verb, input) in [
            ("vault.display_edits.list", json!({})),
            ("vault.display_edits.accept", json!({"id": id})),
            ("vault.display_edits.decline", json!({"id": id})),
        ] {
            let (status, body) = served.post(Caller::Agent, verb, input).await;
            assert_eq!(
                (status, error_code(&body)),
                (StatusCode::FORBIDDEN, Some("FORBIDDEN")),
                "the agent is refused at {verb}: {body}"
            );
        }
        let (status, body) = served.get(Caller::Agent, "/v1/owner/display-edits").await;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
            "the agent is refused at GET /v1/owner/display-edits: {status} {body}"
        );
        let (status, body) = served
            .request(
                Caller::Agent,
                "/v1/owner/display-edits/accept",
                json!({"id": id}),
            )
            .await;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
            "the agent is refused at POST /v1/owner/display-edits/accept: {status} {body}"
        );
        assert_eq!(
            served.card_label(&handle).await,
            NAME,
            "the agent labelled nothing"
        );
        assert_eq!(
            served.proposals().await.len(),
            1,
            "the proposal is still open"
        );
        let (status, body) = served
            .post(
                Caller::Owner,
                "self.display_edits.propose",
                json!({"target": "secret_label", "subject": handle, "value": "Mine", "why": "a name"}),
            )
            .await;
        assert!(
            status.is_client_error(),
            "the owner does not propose to himself: {status} {body}"
        );
        assert_eq!(served.proposals().await.len(), 1, "the owner filed nothing");
    });
}
