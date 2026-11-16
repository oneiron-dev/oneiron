//! The owner's list of every secret in custody at its served doors (FIX
//! [SECRETS-OWNER-LIST-READ], [SECRETS-HOLDER-LIST-READ]): `GET
//! /v1/owner/secrets` and its facade row `vault.secrets.list`.
//!
//! Every case drives the real routes in process (`build_app` + `oneshot`):
//! the owner on the host root credential, and an agent on its own paired
//! credential, enrolled through a real pairing redemption and proving its
//! holder key on every request. Each case owns its vault. No sleeps, no
//! models.
//!
//! The promises:
//! - the list names every live secret once, value-free, with the machine
//!   that holds it, and leaves a revoked one out; the route and the row
//!   answer the same items;
//! - the owner's label names the item, and its purpose and payment mark
//!   show on it;
//! - two records of one value are one item (RULING
//!   SECRETS-LIST-DUP-GROUPING = A: this install proves they hold one value),
//!   the second marked as its machine's own copy; a different value is its
//!   own item;
//! - the list is the owner's: an agent is refused at the row and the route.
//!
//! Red on main: neither row nor route exists there (404).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! secret_list_doors`. It calls no test door; the cfg flag builds
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
                auth_secret: Some("secret-list-doors".into()),
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
    let agent = pair_agent(&vault, &app, &issuer, "secret-list-agent", [0x53; 32]).await;
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

    /// `caller` gets the route at `path`: the status and the body.
    async fn get(&self, caller: Caller, path: &str) -> (StatusCode, Value) {
        let token = match caller {
            Caller::Owner => self.owner_token.as_str(),
            Caller::Agent => self.agent.token.as_str(),
        };
        let request = Request::get(path)
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", self.binding(caller))
            .body(Body::empty())
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

    /// The owner registers `name` holding `value`: a portable record at
    /// rung 0 with no binding. Answers its `secret_id`.
    async fn register(&self, name: &str, value: &str) -> String {
        let (status, body) = self
            .post(
                Caller::Owner,
                "vault.secrets.register",
                json!({
                    "name": name,
                    "class": "custody-portable",
                    "device_only": false,
                    "rung": 0,
                    "value_base64": STANDARD.encode(value),
                    "bindings": [],
                }),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner registers {name}: {body}");
        body["secret_id"]
            .as_str()
            .expect("the register reply names the record")
            .to_owned()
    }

    /// The owner's list at its route, asserted 200: its items.
    async fn list(&self) -> Vec<Value> {
        let (status, body) = self.get(Caller::Owner, "/v1/owner/secrets").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner lists the secrets: {body}"
        );
        body["items"]
            .as_array()
            .expect("the list answers items")
            .clone()
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
}

/// A fresh value no other case or fixture spells.
fn fresh_value() -> String {
    format!("secret_list_{}", EntityId::now().to_hex())
}

/// The item one of whose records is `secret_id`.
fn item_of<'a>(items: &'a [Value], secret_id: &str) -> Option<&'a Value> {
    items.iter().find(|item| {
        item["records"].as_array().is_some_and(|records| {
            records
                .iter()
                .any(|record| record["secret_id"] == secret_id)
        })
    })
}

/// Neither a value nor its base64 appears anywhere in `body`.
fn assert_value_free(what: &str, body: &Value, values: &[&str]) {
    let text = body.to_string();
    for value in values {
        assert!(
            !text.contains(value),
            "{what} carries a secret value: {text}"
        );
        assert!(
            !text.contains(&STANDARD.encode(value)),
            "{what} carries a secret value's base64: {text}"
        );
    }
}

/// The machine `item` says this install is.
fn this_install(item: &Value) -> String {
    let holders = item["holders"].as_array().expect("the item's holders");
    let mine: Vec<&Value> = holders
        .iter()
        .filter(|holder| holder["this_install"] == true)
        .collect();
    assert_eq!(mine.len(), 1, "this install holds the item once: {item}");
    mine[0]["machine"]
        .as_str()
        .expect("a holder names its machine")
        .to_owned()
}

/// The owner lists two registered secrets: one item each, value-free,
/// named by its custody name, held here, with this install as its holder;
/// a revoked one is left out. The facade row answers the same items.
#[test]
fn the_owner_lists_every_secret_value_free_with_the_machine_that_holds_it() {
    run_on_engine_stack("secret-list-each", || async {
        let served = served().await;
        let (first, second, ended) = (fresh_value(), fresh_value(), fresh_value());
        let first_id = served.register("secret-list-first", &first).await;
        let second_id = served.register("secret-list-second", &second).await;
        let ended_id = served.register("secret-list-ended", &ended).await;
        let (status, revoked) = served
            .post(
                Caller::Owner,
                "vault.secrets.revoke",
                json!({"name": "secret-list-ended"}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner revokes one: {revoked}");

        let items = served.list().await;
        let body = json!({"items": items});
        assert_value_free("the list", &body, &[&first, &second, &ended]);
        assert!(
            item_of(&items, &ended_id).is_none(),
            "a revoked secret is left out: {body}"
        );
        for (secret_id, name) in [
            (&first_id, "secret-list-first"),
            (&second_id, "secret-list-second"),
        ] {
            let item = item_of(&items, secret_id).expect("the list names the secret");
            assert_eq!(item["secret_id"], *secret_id, "{item}");
            assert_eq!(item["display_name"], name, "{item}");
            assert_eq!(item["display_name_source"], "name", "{item}");
            assert!(
                item["handle"]
                    .as_str()
                    .is_some_and(|handle| handle.starts_with("sc")),
                "{item}"
            );
            assert_eq!(
                item["payment"],
                json!({"marked": null, "suggested": false, "payment": false}),
                "{item}"
            );
            assert_eq!(item["maybe_same_as"], Value::Null, "{item}");
            let records = item["records"].as_array().expect("the item's records");
            assert_eq!(records.len(), 1, "one record of its value: {item}");
            assert_eq!(records[0]["name"], name, "{item}");
            assert_eq!(records[0]["held_here"], true, "{item}");
            assert_eq!(records[0]["generation"], 0, "{item}");
            let machine = this_install(item);
            assert_eq!(records[0]["holders"], json!([machine]), "{item}");
        }
        assert_ne!(
            item_of(&items, &first_id).map(|item| &item["secret_id"]),
            item_of(&items, &second_id).map(|item| &item["secret_id"]),
            "two values are two items: {body}"
        );

        let (status, row) = served
            .post(Caller::Owner, "vault.secrets.list", json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "the owner's facade row: {row}");
        assert_eq!(
            row["items"], body["items"],
            "the row answers the route's items"
        );
    });
}

/// The owner's label names the item (source `label`), and the purpose and
/// payment mark the owner set show on it.
#[test]
fn the_owners_label_purpose_and_payment_mark_show_on_the_item() {
    run_on_engine_stack("secret-list-owner-facts", || async {
        let served = served().await;
        let secret_id = served
            .register("secret-list-labelled", &fresh_value())
            .await;
        let items = served.list().await;
        let item = item_of(&items, &secret_id).expect("the list names the secret");
        let handle = item["handle"]
            .as_str()
            .expect("the item's handle")
            .to_owned();
        let owner = served.owner_proof();
        served
            .vault
            .set_secret_handle_label(&owner, &handle, Some("Billing key"))
            .expect("the owner labels it");
        served
            .vault
            .set_secret_handle_purpose(&owner, &handle, Some("Pays the hosting bill."))
            .expect("the owner says what it is for");
        served
            .vault
            .set_secret_payment_mark(
                &owner,
                &EntityId::from_hex(&secret_id).expect("a 32-hex id"),
                Some(true),
            )
            .expect("the owner marks it as paying");

        let items = served.list().await;
        let item = item_of(&items, &secret_id).expect("the list names the secret");
        assert_eq!(item["display_name"], "Billing key", "{item}");
        assert_eq!(item["display_name_source"], "label", "{item}");
        assert_eq!(item["purpose"], "Pays the hosting bill.", "{item}");
        assert_eq!(
            item["payment"],
            json!({"marked": true, "suggested": false, "payment": true}),
            "{item}"
        );
        assert_eq!(item["records"][0]["label"], "Billing key", "{item}");
    });
}

/// Two records of one value (registered under two names) are one item
/// with both records, the second marked as this machine's own copy; a
/// record of a different value is its own item, with no hint between them.
#[test]
fn two_records_of_one_value_are_one_item_and_a_different_value_is_its_own() {
    run_on_engine_stack("secret-list-same-value", || async {
        let served = served().await;
        let (shared, other) = (fresh_value(), fresh_value());
        let first_id = served.register("secret-list-copy-one", &shared).await;
        let second_id = served.register("secret-list-copy-two", &shared).await;
        let other_id = served.register("secret-list-other", &other).await;

        let items = served.list().await;
        let body = json!({"items": items});
        assert_value_free("the list", &body, &[&shared, &other]);
        let item = item_of(&items, &first_id).expect("the list names the first copy");
        let records = item["records"].as_array().expect("the item's records");
        let ids: BTreeSet<&str> = records
            .iter()
            .filter_map(|record| record["secret_id"].as_str())
            .collect();
        assert_eq!(
            ids,
            BTreeSet::from([first_id.as_str(), second_id.as_str()]),
            "one item holds both records of the value: {item}"
        );
        assert_eq!(
            item["secret_id"], records[0]["secret_id"],
            "the primary comes first: {item}"
        );
        let machine = this_install(item);
        assert_eq!(records[0]["own_copy"], Value::Null, "{item}");
        assert_eq!(
            records[1]["own_copy"], machine,
            "the second is this machine's own copy: {item}"
        );

        let lone = item_of(&items, &other_id).expect("the list names the other value");
        assert_ne!(
            lone["secret_id"], item["secret_id"],
            "a different value is its own item: {body}"
        );
        assert_eq!(lone["records"].as_array().map(Vec::len), Some(1), "{lone}");
        assert_eq!(lone["maybe_same_as"], Value::Null, "{lone}");
        assert_eq!(item["maybe_same_as"], Value::Null, "{item}");
        let counted = items
            .iter()
            .filter(|listed| {
                [&first_id, &second_id, &other_id]
                    .iter()
                    .any(|id| item_of(std::slice::from_ref(*listed), id).is_some())
            })
            .count();
        assert_eq!(
            counted, 2,
            "three records of two values are two items: {body}"
        );
    });
}

/// The list is the owner's: an agent is refused at the facade row (403)
/// and at the route, and neither refusal carries a value.
#[test]
fn an_agent_is_refused_at_the_secrets_list() {
    run_on_engine_stack("secret-list-agent", || async {
        let served = served().await;
        let value = fresh_value();
        served.register("secret-list-agent-refused", &value).await;
        let (status, body) = served
            .post(Caller::Agent, "vault.secrets.list", json!({}))
            .await;
        assert_eq!(
            (status, error_code(&body)),
            (StatusCode::FORBIDDEN, Some("FORBIDDEN")),
            "the agent is refused at vault.secrets.list: {body}"
        );
        assert_value_free("the row's refusal", &body, &[&value]);
        assert!(
            !body.to_string().contains("secret-list-agent-refused"),
            "the refusal names no secret: {body}"
        );
        let (status, body) = served.get(Caller::Agent, "/v1/owner/secrets").await;
        assert!(
            status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED,
            "the agent is refused at GET /v1/owner/secrets: {status} {body}"
        );
        assert_value_free("the route's refusal", &body, &[&value]);
    });
}
