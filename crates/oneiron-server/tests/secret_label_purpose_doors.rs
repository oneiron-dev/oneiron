//! The owner's display edits on one secret at their served doors (FIX
//! [SECRETS-LABEL-PURPOSE-VERBS]): `POST /v1/owner/secrets/label` and
//! `/secrets/purpose`, and their facade rows `vault.secrets.label.set` and
//! `vault.secrets.purpose.set`.
//!
//! Every case drives the real routes in process (`build_app` + `oneshot`):
//! the owner on the host root credential, and an agent on its own paired
//! credential, enrolled through a real pairing redemption and proving its
//! holder key on every request. Each case owns its vault. No sleeps, no
//! models.
//!
//! The promises:
//! - the owner sets a secret's label, and the agent's handle card
//!   (`reveal.describe`) names the secret by it; a clear names it by its
//!   record name again;
//! - the owner sets what a secret is for, its line breaks kept, and clears
//!   it;
//! - the edits are owner acts: an agent is refused at both rows and both
//!   routes, and nothing moves;
//! - an id that names no secret is refused.
//!
//! Red on main: neither row nor route exists there (404).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! secret_label_purpose_doors`. It calls no test door; the cfg flag builds
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
    CapabilitySlip, HostSlipIssuer, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The custody name every case registers its secret under.
const NAME: &str = "label-purpose-secret";

/// One paired agent credential: its holder signing key, its redeemed slip
/// and the token it presents.
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn error_code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

async fn served() -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("secret-label-purpose-doors".into()),
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
    let agent = pair_agent(&vault, &app, &issuer, "label-purpose-agent", [0x4C; 32]).await;
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
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("route response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The owner registers [`NAME`]: a portable record at rung 0 with no
    /// binding. Answers its `secret_id`.
    async fn register(&self) -> String {
        let value = STANDARD.encode(format!("label_purpose_{}", EntityId::now().to_hex()));
        let (status, body) = self
            .post(
                Caller::Owner,
                "vault.secrets.register",
                json!({
                    "name": NAME,
                    "class": "custody-portable",
                    "device_only": false,
                    "rung": 0,
                    "value_base64": value,
                    "bindings": [],
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner registers {NAME}: {body}");
        body["secret_id"]
            .as_str()
            .expect("the register reply names the record")
            .to_owned()
    }

    /// The name the agent's handle card gives the secret `handle`.
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
}

/// The handle a display edit's reply names.
fn handle_of(reply: &Value) -> String {
    let handle = reply["handle"]
        .as_str()
        .expect("the reply names the handle")
        .to_owned();
    assert!(handle.starts_with("sc"), "a secret handle: {reply}");
    handle
}

/// The owner labels a secret at its route: the reply holds the trimmed
/// label and a Gate receipt, and the agent's handle card names the secret
/// by it. A clear at the facade row answers no label, and the card names
/// the secret by its record name again.
#[test]
fn the_owner_labels_a_secret_and_the_agents_card_names_it_by_the_label() {
    run_on_engine_stack("label-purpose-label", || async {
        let served = served().await;
        let secret_id = served.register().await;

        let (status, set) = served
            .request(
                Caller::Owner,
                "/v1/owner/secrets/label",
                json!({"secret_id": secret_id, "label": "  Billing key  "}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner labels the secret: {set}");
        assert_eq!(set["label"].as_str(), Some("Billing key"), "{set}");
        assert!(
            set["receipt"]
                .as_str()
                .is_some_and(|receipt| receipt.starts_with("gate:")),
            "the act's Gate receipt: {set}"
        );
        let handle = handle_of(&set);
        assert_eq!(served.card_label(&handle).await, "Billing key");

        let (status, cleared) = served
            .post(
                Caller::Owner,
                "vault.secrets.label.set",
                json!({"secret_id": secret_id, "label": null}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner clears the label: {cleared}"
        );
        assert!(cleared["label"].is_null(), "{cleared}");
        assert_eq!(handle_of(&cleared), handle);
        assert_eq!(served.card_label(&handle).await, NAME);
    });
}

/// The owner says what a secret is for at its facade row: the reply and
/// the engine's own read hold the text, line break kept. A blank purpose
/// at the route clears it, and the engine holds none.
#[test]
fn the_owner_sets_and_clears_what_a_secret_is_for() {
    run_on_engine_stack("label-purpose-purpose", || async {
        let served = served().await;
        let secret_id = served.register().await;
        let purpose = "Pays the hosting bill.\nRotate it every spring.";

        let (status, set) = served
            .post(
                Caller::Owner,
                "vault.secrets.purpose.set",
                json!({"secret_id": secret_id, "purpose": purpose}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner sets the purpose: {set}");
        assert_eq!(set["purpose"].as_str(), Some(purpose), "{set}");
        assert!(
            set["receipt"]
                .as_str()
                .is_some_and(|receipt| receipt.starts_with("gate:")),
            "the act's Gate receipt: {set}"
        );
        let handle = handle_of(&set);
        assert_eq!(served.stored_purpose(&handle).as_deref(), Some(purpose));

        let (status, cleared) = served
            .request(
                Caller::Owner,
                "/v1/owner/secrets/purpose",
                json!({"secret_id": secret_id, "purpose": "   "}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner clears the purpose: {cleared}"
        );
        assert!(cleared["purpose"].is_null(), "{cleared}");
        assert_eq!(served.stored_purpose(&handle), None);
    });
}

/// The edits are owner acts: an agent is refused at both facade rows
/// (403) and at both owner routes, and the owner's label and purpose stand
/// as they were.
#[test]
fn an_agent_is_refused_at_both_display_edits_and_moves_nothing() {
    run_on_engine_stack("label-purpose-agent", || async {
        let served = served().await;
        let secret_id = served.register().await;
        let (status, set) = served
            .post(
                Caller::Owner,
                "vault.secrets.label.set",
                json!({"secret_id": secret_id, "label": "Owner's name"}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner labels the secret: {set}");
        let handle = handle_of(&set);
        let (status, set) = served
            .post(
                Caller::Owner,
                "vault.secrets.purpose.set",
                json!({"secret_id": secret_id, "purpose": "The owner's purpose."}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner sets the purpose: {set}");

        for (verb, input) in [
            (
                "vault.secrets.label.set",
                json!({"secret_id": secret_id, "label": "Agent's name"}),
            ),
            (
                "vault.secrets.label.set",
                json!({"secret_id": secret_id, "label": null}),
            ),
            (
                "vault.secrets.purpose.set",
                json!({"secret_id": secret_id, "purpose": "The agent's purpose."}),
            ),
        ] {
            let (status, body) = served.post(Caller::Agent, verb, input).await;
            assert_eq!(
                (status, error_code(&body)),
                (StatusCode::FORBIDDEN, Some("FORBIDDEN")),
                "the agent is refused at {verb}: {body}"
            );
        }
        for (path, input) in [
            (
                "/v1/owner/secrets/label",
                json!({"secret_id": secret_id, "label": "Agent's name"}),
            ),
            (
                "/v1/owner/secrets/purpose",
                json!({"secret_id": secret_id, "purpose": "The agent's purpose."}),
            ),
        ] {
            let (status, body) = served.request(Caller::Agent, path, input).await;
            assert!(
                status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
                "the agent is refused at {path}: {status} {body}"
            );
        }

        assert_eq!(served.card_label(&handle).await, "Owner's name");
        assert_eq!(
            served.stored_purpose(&handle).as_deref(),
            Some("The owner's purpose.")
        );
    });
}

/// An edit naming no secret is refused: a `secret_id` that is not 32 hex
/// (400) and one that names no record (404), at both rows.
#[test]
fn a_display_edit_naming_no_secret_is_refused() {
    run_on_engine_stack("label-purpose-unknown", || async {
        let served = served().await;
        let unknown = EntityId::now().to_hex();
        for (verb, field) in [
            ("vault.secrets.label.set", "label"),
            ("vault.secrets.purpose.set", "purpose"),
        ] {
            let (status, body) = served
                .post(
                    Caller::Owner,
                    verb,
                    json!({"secret_id": "not-an-id", field: "text"}),
                )
                .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{verb} on a malformed id: {body}"
            );
            let (status, body) = served
                .post(
                    Caller::Owner,
                    verb,
                    json!({"secret_id": unknown, field: "text"}),
                )
                .await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{verb} on an unknown id: {body}"
            );
        }
    });
}
