//! Promise tests for the `vault.guests.*` doors, entered at
//! `POST /v1/core/facade/<verb>`. Canon: ARCH-0043
//! (oneiron/sync/oneiron-arch-0043-federation-membership-v1.md) and
//! oneiron/surfaces.md.
//!
//! A Connect guest is a key pair and a slip. It acts on the host's own
//! server and holds no vault here. Its grant confers only while the host's
//! Connect pact with the peer vault is Active, so two vaults live in one
//! process, and the test carries every signed half between their doors, as
//! tests/vault_federation_doors.rs does.
//!
//! - :12, :38 and `federation:F-NOLEAK` (:237): the guest fetches the
//!   owner's filtered envelope under its own credential, signed by the host
//!   and bound to the pact and its epoch, with no roster, topology or count.
//! - :12 ("non-reshareable"), :58 and :142 ("host-owner revocable"): only
//!   the owner shares, re-shares, mints and revokes; only the guest fetches
//!   and proposes.
//! - :38 ("Named foreign WORLD copies, never base") and :58 (a guest
//!   "Cannot ... re-share the host's foreign WORLD"): a share stays inside
//!   the grant's own local named world.
//! - :38 ("attributed to a guest actor") and :146: a guest's proposal lands
//!   in the owner's review inbox under the guest actor and writes nothing.
//! - surfaces.md:12 (OF-232, "un-revocable-copy disclosure") and
//!   `federation:G` (:238): a revoke says the guest keeps what it copied,
//!   ends the pact, and stops every later fetch.

#![cfg(unix)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    AgentTier, CapabilitySlip, GuestDocumentContext, HostSlipIssuer, MachineRole,
    holder_proof_challenge,
};
use oneiron::federation::{
    GuestShareEnvelope, Scope, ScopeAxis, encode_guest_share_envelope,
    encode_guest_share_envelope_body,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// When the claims were said and learned: 17 Oct 2026, so each claim's
/// window is that month's (`2026-10@<world>`), as FEDERATION-04 has it.
const LEARNED_AT: u64 = 1_792_238_400;

const PREDICATE: &str = "guests.doors.document";

const SHARED_WORDS: &str = "The host's observatory opens at dusk.";

const UNSHARED_WORDS: &str = "The host's cellar keeps the spare lenses.";

const PEER_WORDS: &str = "The peer's workshop keeps its own lenses.";

/// Base reality's world id.
const BASE_WORLD: &str = "00000000000000000000000000000001";

/// The refusal of every caller but the guest at the guest's own doors
/// (src/api/facade/guest_document_doors.rs).
const GUEST_REFUSAL: &str =
    "guest document export requires the recipient's own live grant-bound credential";

/// One served vault, called by its owner on the host root.
struct Side {
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
    owner: EntityId,
}

/// A caller other than the owner, on its own slip, signed by its own key.
struct Principal {
    token: String,
    slip: CapabilitySlip,
    key: SigningKey,
}

/// Who sends a request.
#[derive(Clone, Copy)]
enum Caller<'a> {
    Owner,
    As(&'a Principal),
}

/// One reply: its status and its JSON.
struct Reply {
    status: StatusCode,
    body: Value,
}

impl Reply {
    /// The body of a 200, or a failure naming the call and the reply.
    fn ok(self, call: &str) -> Value {
        assert_eq!(self.status, StatusCode::OK, "{call} answered {}", self.body);
        self.body
    }

    /// Asserts the refusal `status` with the error `code`.
    fn refused(&self, call: &str, status: StatusCode, code: &str) {
        assert_eq!(self.status, status, "{call} answered {}", self.body);
        assert_eq!(
            self.body["error"]["code"], code,
            "{call} answered {}",
            self.body
        );
    }

    /// Asserts some refusal of the caller's request: a 4xx with an error code.
    fn refused_as_a_request(&self, call: &str) {
        assert!(
            self.status.is_client_error(),
            "{call} answered {}",
            self.body
        );
        assert!(
            self.body["error"]["code"].is_string(),
            "{call} answered {}",
            self.body
        );
    }

    /// Asserts the error message holds `words`.
    fn says(&self, call: &str, words: &str) {
        let message = self.body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains(words),
            "{call} answered {}, which does not say {words:?}",
            self.body
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The 32 bytes a 64-hex string spells.
fn unhex32(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64, "{text} is no 32-byte hex string");
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .unwrap_or_else(|_| panic!("{text} is no hex string"));
    }
    bytes
}

/// The names of `value`'s fields.
fn keys(value: &Value) -> BTreeSet<String> {
    value
        .as_object()
        .unwrap_or_else(|| panic!("{value} is no object"))
        .keys()
        .cloned()
        .collect()
}

fn names(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

impl Side {
    fn new(path: &Path, secret: &str) -> Self {
        let vault = Arc::new(Vault::open(path, VaultConfig::device()).expect("open fresh vault"));
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some(secret.into()),
                    ..Default::default()
                },
            )
            .expect("create the vault's server"),
        );
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("owner root slip");
        let token = slip.to_token().expect("owner slip token");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
        Self {
            vault,
            app: build_app(server),
            issuer,
            slip,
            token,
            owner,
        }
    }

    /// `caller`'s `method` request to `uri`, with `input` as its JSON body.
    async fn request(
        &self,
        caller: Caller<'_>,
        method: Method,
        uri: &str,
        input: Option<&Value>,
    ) -> Reply {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let (token, signature) = match caller {
            Caller::Owner => (
                self.token.clone(),
                hex(&self
                    .issuer
                    .binding_proof(&self.slip, &challenge)
                    .expect("owner holder proof")),
            ),
            Caller::As(principal) => (
                principal.token.clone(),
                hex(&principal
                    .key
                    .sign(
                        &principal
                            .slip
                            .binding_transcript(&challenge)
                            .expect("caller binding transcript"),
                    )
                    .to_bytes()),
            ),
        };
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .header(
                "x-oneiron-binding",
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
            );
        let request = match input {
            Some(input) => builder
                .header("content-type", "application/json")
                .body(Body::from(input.to_string())),
            None => builder.body(Body::empty()),
        }
        .expect("the request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("the app's response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("the response body");
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Reply { status, body }
    }

    /// `caller`'s call to `verb` at its facade route.
    async fn send(&self, caller: Caller<'_>, verb: &str, input: &Value) -> Reply {
        self.request(
            caller,
            Method::POST,
            &format!("/v1/core/facade/{verb}"),
            Some(input),
        )
        .await
    }

    /// The owner's call to `verb`.
    async fn call(&self, verb: &str, input: Value) -> Reply {
        self.send(Caller::Owner, verb, &input).await
    }

    /// The owner's call to `verb`, which must answer 200.
    async fn ok(&self, verb: &str, input: Value) -> Value {
        self.call(verb, input).await.ok(verb)
    }

    /// The owner's review inbox of Connect guests' proposals
    /// (`GET /v1/owner/federation/connect/proposals`).
    async fn proposals(&self) -> Vec<Value> {
        let inbox = self
            .request(
                Caller::Owner,
                Method::GET,
                "/v1/owner/federation/connect/proposals",
                None,
            )
            .await
            .ok("the owner's proposal inbox");
        inbox
            .as_array()
            .unwrap_or_else(|| panic!("the inbox is no list: {inbox}"))
            .clone()
    }

    /// A new named world of this vault.
    async fn world(&self, name: &str) -> String {
        let body = self
            .ok(
                "vault.structural.put",
                json!({
                    "kind": "WORLD",
                    "body": {"name": name, "kind": "fictional"},
                    "occurred_at": LEARNED_AT,
                    "text_fields": [{"field": "name", "value": name}]
                }),
            )
            .await;
        body["id_hex"].as_str().expect("new world id").to_owned()
    }

    /// The `vault.federation.status` row of `pact`, if this vault holds one.
    async fn pact_row(&self, pact: &str) -> Option<Value> {
        let status = self.ok("vault.federation.status", json!({})).await;
        status["pacts"]
            .as_array()
            .expect("status lists pacts")
            .iter()
            .find(|row| row["pact"] == pact)
            .cloned()
    }

    /// Asserts this vault holds `pact` at `status` and `epoch`.
    async fn holds(&self, pact: &str, status: &str, epoch: u64, side: &str) {
        let row = self.pact_row(pact).await;
        assert_eq!(
            row,
            Some(json!({"pact": pact, "status": status, "epoch": epoch, "inactive_reason": null})),
            "{side}'s status row of the pact"
        );
    }

    /// The scope a fresh vault's own claims take: base reality, the owner's
    /// substrate facet, every relationship and the default project
    /// (tests/e2e/support/fixtures.ts `ownerBaseClaimScope`).
    async fn base_claim_scope(&self) -> Value {
        let facets = self
            .ok(
                "vault.neighbors",
                json!({
                    "entity_ref": self.owner.to_hex(),
                    "opts": {"edge_kind": "has_facet", "limit": 100}
                }),
            )
            .await;
        for facet in facets["value"].as_array().expect("the owner's facets") {
            let read = self
                .ok("vault.get", json!({"entity_ref": facet["short_id"]}))
                .await;
            let row = &read["value"];
            if row["kind"] == "FACET" && row["body"]["kind"] == "substrate" {
                return json!({
                    "world_id": BASE_WORLD,
                    "scope_facet_id": row["id_hex"],
                    "scope_relationship_id": "all",
                    "scope_project_id": "00000000000000000000000000000002"
                });
            }
        }
        panic!("a fresh vault has no readable owner substrate facet: {facets}");
    }

    /// Lets claims of source `imported` land without a gate hold, as
    /// FEDERATION-03's `fed03PermitImported` does.
    async fn permit_imported(&self) {
        let policy = self.ok("vault.gate.policy.get", json!({})).await;
        let row = policy["manifests"]
            .as_array()
            .expect("policy manifests")
            .iter()
            .find(|row| row["manifest_ref"] == policy["default_manifest_ref"])
            .cloned()
            .expect("the default policy manifest");
        let mut manifest = row["manifest"].clone();
        if !manifest["source_trust"].is_object() {
            manifest["source_trust"] = json!({});
        }
        manifest["source_trust"]["imported"] =
            json!({"max_auto_sensitivity": 1, "receipted": true, "warned": true});
        self.ok(
            "vault.gate.policy.put",
            json!({
                "manifest_ref": row["manifest_ref"],
                "expected_body_hash": row["body_hash"],
                "manifest": manifest
            }),
        )
        .await;
    }

    /// The owner says `words` in `world` (sensitivity 1, inside a guest
    /// grant's at-most-private ceiling); the claim's 32-hex id.
    async fn say(&self, world: &str, words: &str) -> String {
        let mut scope = self.base_claim_scope().await;
        scope["world_id"] = json!(world);
        self.ok(
            "vault.claims.upsert",
            json!({
                "predicate": PREDICATE, "subject_ref": self.owner.to_hex(), "value": words,
                "confidence": 0.9, "source": "user_stated", "sensitivity": 1, "scope": scope,
                "occurred_at": LEARNED_AT, "learned_at": LEARNED_AT
            }),
        )
        .await;
        for _ in 0..50 {
            if let Some(claim) = self.listed(world, words).await {
                return claim;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the owner's claim {words:?} in {world} is not listed");
    }

    /// The id of the claim under [`PREDICATE`] this vault lists in `world`
    /// saying `words`.
    async fn listed(&self, world: &str, words: &str) -> Option<String> {
        let page = self
            .ok(
                "vault.claims.list",
                json!({"predicate": PREDICATE, "limit": 20}),
            )
            .await;
        page["value"]
            .as_array()
            .expect("a claims page")
            .iter()
            .find(|row| row["world_ref"] == world && row["value"] == words)
            .map(|row| {
                row["claim_ref"]
                    .as_str()
                    .unwrap_or_else(|| panic!("a claim row with no id: {row}"))
                    .to_owned()
            })
    }

    /// Says `words` in `world`, then exports that world's October window
    /// over `pact`: the delivery the owner carries to the peer.
    async fn deliver(&self, pact: &str, world: &str, words: &str) -> Value {
        self.say(world, words).await;
        self.ok(
            "vault.federation.connect.export",
            json!({"pact": pact, "window_key": window(world), "world_ref": world}),
        )
        .await
    }

    /// A PERSON this vault knows, with no vault here.
    fn person(&self, name: &str) -> EntityId {
        let id = EntityId::now();
        let now = self.vault.now_recorded_at();
        let mut body = Vec::new();
        rmpv::encode::write_value(
            &mut body,
            &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
        )
        .expect("the person's PERSON body");
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &body,
            )
            .expect("the person's PERSON row");
        id
    }

    /// `holder`'s own read-and-write slip as a `class` caller, signed by the
    /// key `seed` makes.
    fn principal(&self, holder: EntityId, class: &str, seed: u8) -> Principal {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let mut claims = self.slip.claims.clone();
        claims.parent_id = None;
        claims.holder_ref = holder.to_hex();
        claims.binding_key = key.verifying_key().to_bytes();
        claims.actor_class = Some(class.to_owned());
        claims.scope = Scope::top();
        claims.scope.verbs = ScopeAxis::Some(
            ["core:read", "core:write"]
                .iter()
                .map(|verb| (*verb).to_owned())
                .collect(),
        );
        claims.slip_id = [seed; 32];
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("mint the caller's slip");
        let token = slip.to_token().expect("the caller's slip token");
        Principal { token, slip, key }
    }

    /// The vault's own agent `name`, bound with full access, on its own slip.
    fn agent(&self, name: &str, seed: u8) -> Principal {
        let agent = self
            .vault
            .ensure_agent_principal(name)
            .expect("the vault's own agent");
        let owner = self
            .vault
            .authenticate_owner(
                self.owner,
                &self.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("the owner's proof");
        self.vault
            .bind_and_grant_agent_principal(
                &self.issuer,
                &owner,
                agent,
                AgentTier::FullAccess.ceiling(),
            )
            .expect("bind the vault's own agent");
        self.principal(agent, "agent", seed)
    }

    /// The `vault.guests.mint_slip` input for `grant`, binding the public
    /// half of `key` until `expires_at`.
    fn mint_input(grant: &str, key: &SigningKey, expires_at: u64) -> Value {
        json!({
            "grant_ref": grant,
            "holder_key": hex(&key.verifying_key().to_bytes()),
            "expires_at": expires_at
        })
    }

    /// The guest `seed` names: the key pair it made on its own device, and
    /// the slip the owner mints through the door for the public half. The
    /// slip and its id.
    async fn guest(&self, grant: &str, seed: u8) -> (Principal, String) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let expires_at = self.vault.now_recorded_at() + 3600;
        let minted = self
            .ok(
                "vault.guests.mint_slip",
                Self::mint_input(grant, &key, expires_at),
            )
            .await;
        let token = minted["slip"]
            .as_str()
            .expect("the guest's slip")
            .to_owned();
        assert!(token.starts_with("v2.slip."), "{minted}");
        assert_eq!(minted["expires_at"], expires_at, "{minted}");
        let slip_id = minted["slip_id"].as_str().expect("the slip id").to_owned();
        let slip = CapabilitySlip::from_token(&token).expect("the guest's slip parses");
        (Principal { token, slip, key }, slip_id)
    }
}

/// The October window of `world`, where its claims live.
fn window(world: &str) -> String {
    format!("2026-10@{world}")
}

/// One direction of a pact: these worlds, every facet and band.
fn direction(worlds: &[&str]) -> Value {
    json!({
        "worlds": {"kind": "some", "values": worlds},
        "facets": {"kind": "all"}, "bands": {"kind": "all"}
    })
}

/// A Connect guest grant's authority, as FEDERATION-04 mints it: read and
/// propose over `world`, at most private. The verbs are sorted, as the wire
/// carries the set.
fn guest_scope(world: &str) -> Value {
    json!({
        "worlds": {"kind": "some", "values": [world]},
        "facets": {"kind": "all"}, "bands": {"kind": "all"},
        "audience": {"kind": "all"}, "verbs": {"kind": "some", "values": ["propose", "read"]},
        "sensitivity": {"kind": "at_most", "value": "private"}
    })
}

/// The peer's grant back: read `world`, at most private.
fn peer_scope(world: &str) -> Value {
    json!({
        "worlds": {"kind": "some", "values": [world]},
        "facets": {"kind": "all"}, "bands": {"kind": "all"},
        "audience": {"kind": "all"}, "verbs": {"kind": "some", "values": ["read"]},
        "sensitivity": {"kind": "at_most", "value": "private"}
    })
}

/// The host A and the peer B, each with a named world and a Connect grant
/// naming the other; A's grant is the guest's. No pact yet.
struct Guests {
    _dir: tempfile::TempDir,
    a: Side,
    b: Side,
    b_vault: String,
    a_key: String,
    a_world: String,
    a_unshared: String,
    b_world: String,
    a_grant: Value,
    b_grant: Value,
}

async fn guests() -> Guests {
    let dir = tempfile::tempdir().expect("fresh guest vaults");
    let a = Side::new(&dir.path().join("a"), "vault-guests-doors-a");
    let b = Side::new(&dir.path().join("b"), "vault-guests-doors-b");
    let a_id = a.ok("vault.federation.connect.identity", json!({})).await;
    let b_id = b.ok("vault.federation.connect.identity", json!({})).await;
    assert_ne!(a_id["vault"], b_id["vault"], "two vaults");
    let a_world = a.world("guests-doors-shared").await;
    let a_unshared = a.world("guests-doors-unshared").await;
    let b_world = b.world("guests-doors-peer").await;
    let a_grant = a
        .ok(
            "vault.federation.connect.grants.mint",
            json!({"peer_vault": b_id["vault"], "authority_scope": guest_scope(&a_world)}),
        )
        .await;
    let b_grant = b
        .ok(
            "vault.federation.connect.grants.mint",
            json!({"peer_vault": a_id["vault"], "authority_scope": peer_scope(&b_world)}),
        )
        .await;
    assert_eq!(
        a_grant["resolved_scope"],
        guest_scope(&a_world),
        "{a_grant}"
    );
    assert!(
        a_grant["guest_actor"]
            .as_str()
            .is_some_and(|actor| actor.len() == 32),
        "{a_grant}"
    );
    let text = |value: &Value| value.as_str().expect("a hex string").to_owned();
    Guests {
        _dir: dir,
        b_vault: text(&b_id["vault"]),
        a_key: text(&a_id["host_key"]),
        a,
        b,
        a_world,
        a_unshared,
        b_world,
        a_grant,
        b_grant,
    }
}

impl Guests {
    /// The guest's grant at A.
    fn grant(&self) -> &str {
        self.a_grant["grant"].as_str().expect("the grant id")
    }

    /// The vault-resident guest actor A's grant confers on.
    fn guest_actor(&self) -> &str {
        self.a_grant["guest_actor"]
            .as_str()
            .expect("the guest actor")
    }

    /// The share and fetch input for `world` through the window `window_key`.
    fn share_input(&self, world: &str, window_key: &str) -> Value {
        json!({
            "grant_ref": self.grant(), "world_ref": world, "window_key": window_key,
            "facets": [], "bands": []
        })
    }

    /// A offers, B accepts, A accepts B's counter: the pact, Active on both
    /// sides at epoch 1.
    async fn activate(&self) -> String {
        let offer = self
            .a
            .ok(
                "vault.federation.connect.offer",
                json!({
                    "peer_vault": self.b_vault, "grant": self.a_grant["grant"],
                    "outbound": direction(&[&self.a_world]),
                    "inbound": direction(&[&self.b_world])
                }),
            )
            .await;
        let b_accept = self
            .b
            .ok(
                "vault.federation.connect.accept",
                json!({"offer": offer, "grant": self.b_grant["grant"]}),
            )
            .await;
        assert_eq!(b_accept["status"], "Active", "{b_accept}");
        let a_accept = self
            .a
            .ok(
                "vault.federation.connect.accept",
                json!({"offer": b_accept["counter"], "grant": self.a_grant["grant"]}),
            )
            .await;
        assert_eq!(a_accept["status"], "Active", "{a_accept}");
        let pact = offer["pact"].as_str().expect("the pact id").to_owned();
        self.a.holds(&pact, "Active", 1, "A").await;
        self.b.holds(&pact, "Active", 1, "B").await;
        pact
    }

    /// Asserts `answer` is A's guest envelope for `a_world` over `pact`: its
    /// pinned fields only, the guest's actor and window, and both host
    /// signatures, the outer one over the pact context.
    fn holds_envelope(&self, who: &str, answer: &Value, pact: &str) {
        assert_eq!(
            keys(answer),
            names(&[
                "context",
                "envelope",
                "signer",
                "signature",
                "travel_receipt"
            ]),
            "{who}: {answer}"
        );
        assert_eq!(
            keys(&answer["context"]),
            names(&["pact", "epoch", "ceiling", "effective_scope"]),
            "{who}: {answer}"
        );
        assert_eq!(
            keys(&answer["envelope"]),
            names(&["body", "signature"]),
            "{who}: {answer}"
        );
        assert_eq!(
            keys(&answer["envelope"]["body"]),
            names(&["scope", "member_ref", "selector", "window_key", "update"]),
            "{who}: no roster, topology or count rides in the body: {answer}"
        );
        assert_eq!(answer["context"]["pact"], pact, "{who}");
        assert_eq!(answer["context"]["epoch"], 1, "{who}");
        assert_eq!(
            answer["context"]["ceiling"],
            guest_scope(&self.a_world),
            "{who}"
        );
        assert_eq!(
            answer["context"]["effective_scope"],
            direction(&[&self.a_world]),
            "{who}"
        );
        let body = &answer["envelope"]["body"];
        assert_eq!(body["member_ref"], self.guest_actor(), "{who}");
        assert_eq!(body["window_key"], window(&self.a_world), "{who}");
        assert!(
            body["update"]
                .as_array()
                .is_some_and(|update| !update.is_empty()),
            "{who}: an empty update"
        );
        assert_eq!(
            answer["signer"], self.a_key,
            "{who}: signed by A's host key"
        );

        let signer = VerifyingKey::from_bytes(&unhex32(&self.a_key)).expect("A's host key");
        let envelope: GuestShareEnvelope =
            serde_json::from_value(answer["envelope"].clone()).expect("the signed envelope");
        let context: GuestDocumentContext =
            serde_json::from_value(answer["context"].clone()).expect("the pact context");
        let inner = Signature::from_slice(&envelope.signature).expect("a 64-byte body signature");
        signer
            .verify(
                &encode_guest_share_envelope_body(&envelope.body).expect("the canonical body"),
                &inner,
            )
            .unwrap_or_else(|error| panic!("{who}: the body signature fails: {error}"));
        let outer: Vec<u8> =
            serde_json::from_value(answer["signature"].clone()).expect("the outer signature");
        let outer = Signature::from_slice(&outer).expect("a 64-byte outer signature");
        let transcript = context
            .transcript(&encode_guest_share_envelope(&envelope).expect("the canonical envelope"))
            .expect("the context transcript");
        signer.verify(&transcript, &outer).unwrap_or_else(|error| {
            panic!("{who}: the signature does not bind the pact context: {error}")
        });
    }
}

/// :12 and :38: the guest fetches the owner's own filtered document under
/// its own grant-bound credential. `federation:F-NOLEAK` (:237): "Guest-share
/// envelopes strip originating-vault membership, roster, topology, and
/// counts." The envelope is the host's, signed over its pact and epoch.
#[test]
fn a_guest_fetches_the_owners_signed_envelope_bound_to_the_pact_and_nothing_more() {
    run_on_engine_stack("guests-doors-fetch", || async {
        let f = guests().await;
        let pact = f.activate().await;
        f.a.say(&f.a_world, SHARED_WORDS).await;
        let (guest, _) = f.a.guest(f.grant(), 0x71).await;
        let input = f.share_input(&f.a_world, &window(&f.a_world));

        let shared = f.a.ok("vault.guests.share", input.clone()).await;
        f.holds_envelope("the owner's share", &shared, &pact);
        let fetched =
            f.a.send(Caller::As(&guest), "vault.guests.export_envelope", &input)
                .await
                .ok("the guest's fetch");
        f.holds_envelope("the guest's fetch", &fetched, &pact);

        // The guest's slip proves nothing in another key's hands.
        let stolen = Principal {
            token: guest.token.clone(),
            slip: CapabilitySlip::from_token(&guest.token).expect("the guest's slip parses"),
            key: SigningKey::from_bytes(&[0x7f; 32]),
        };
        f.a.send(Caller::As(&stolen), "vault.guests.export_envelope", &input)
            .await
            .refused(
                "the guest's slip under another key",
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
            );
    });
}

/// :12 ("scoped read/propose, non-reshareable"), :58 (a guest "Cannot ...
/// re-share the host's foreign WORLD") and :142 ("host-owner revocable"):
/// the owner alone shares, re-shares, mints a guest slip and revokes, and
/// only on a live Active guest grant; the guest alone fetches and proposes.
#[test]
fn only_the_owner_shares_mints_and_revokes_and_only_the_guest_fetches_and_proposes() {
    run_on_engine_stack("guests-doors-who", || async {
        let f = guests().await;
        let mina = f.a.person("Mina");
        let mina = f.a.principal(mina, "human", 0x72);
        let agent = f.a.agent("guests-doors-agent", 0x73);
        let key = SigningKey::from_bytes(&[0x74; 32]);
        let later = f.a.vault.now_recorded_at() + 3600;

        // The grant confers nothing before its pact is Active: no slip.
        let early =
            f.a.call(
                "vault.guests.mint_slip",
                Side::mint_input(f.grant(), &key, later),
            )
            .await;
        early.refused_as_a_request("a mint before the pact");
        assert!(early.body.get("slip").is_none(), "{}", early.body);
        let pact = f.activate().await;
        f.a.call(
            "vault.guests.mint_slip",
            Side::mint_input(&EntityId::now().to_hex(), &key, later),
        )
        .await
        .refused("a mint on no grant", StatusCode::NOT_FOUND, "NOT_FOUND");
        let keyless =
            f.a.call(
                "vault.guests.mint_slip",
                json!({"grant_ref": f.grant(), "holder_key": "not-a-key", "expires_at": later}),
            )
            .await;
        keyless.refused("a mint for no key", StatusCode::BAD_REQUEST, "BAD_REQUEST");
        keyless.says("a mint for no key", "holder_key is not 32 bytes of hex");
        let over =
            f.a.call(
                "vault.guests.mint_slip",
                Side::mint_input(f.grant(), &key, f.a.vault.now_recorded_at() - 60),
            )
            .await;
        over.refused_as_a_request("a mint of a slip already over");
        assert!(over.body.get("slip").is_none(), "{}", over.body);
        let (guest, _) = f.a.guest(f.grant(), 0x71).await;

        let share = f.share_input(&f.a_world, &window(&f.a_world));
        let owner_doors = [
            ("vault.guests.share", share.clone()),
            ("vault.guests.reshare", share.clone()),
            (
                "vault.guests.mint_slip",
                Side::mint_input(f.grant(), &key, later),
            ),
            ("vault.guests.revoke", json!({"grant_ref": f.grant()})),
        ];
        for (verb, input) in &owner_doors {
            let call = format!("the guest at {verb}");
            let reply = f.a.send(Caller::As(&guest), verb, input).await;
            reply.refused(&call, StatusCode::FORBIDDEN, "FORBIDDEN");
            reply.says(&call, "required scope");
            for (who, caller) in [("Mina", &mina), ("the vault's agent", &agent)] {
                let call = format!("{who} at {verb}");
                let reply = f.a.send(Caller::As(caller), verb, input).await;
                reply.refused(&call, StatusCode::FORBIDDEN, "FORBIDDEN");
                reply.says(&call, &format!("{verb} is the vault owner's"));
            }
        }
        let propose = json!({
            "grant_ref": f.grant(), "world_ref": f.a_world, "entity_ref": f.a_world,
            "update": [1, 2, 3]
        });
        for (verb, input) in [
            ("vault.guests.export_envelope", &share),
            ("vault.guests.propose", &propose),
        ] {
            for (who, caller) in [
                ("the owner", Caller::Owner),
                ("Mina", Caller::As(&mina)),
                ("the vault's agent", Caller::As(&agent)),
            ] {
                let call = format!("{who} at {verb}");
                let reply = f.a.send(caller, verb, input).await;
                reply.refused(&call, StatusCode::FORBIDDEN, "FORBIDDEN");
                reply.says(&call, GUEST_REFUSAL);
            }
        }

        // The owner re-shares its own local world as it shares it, and the
        // guest's own fetch stands.
        let reshared = f.a.ok("vault.guests.reshare", share.clone()).await;
        assert_eq!(reshared["context"]["pact"], pact, "{reshared}");
        assert_eq!(
            reshared["envelope"]["body"]["member_ref"],
            f.guest_actor(),
            "{reshared}"
        );
        f.a.send(Caller::As(&guest), "vault.guests.export_envelope", &share)
            .await
            .ok("the guest's fetch");
    });
}

/// :38 ("Named foreign WORLD copies, never base"), :136 ("Base is never one
/// of those ids") and :58 (a guest "Cannot ... re-share the host's foreign
/// WORLD"): a share or a fetch stays inside the grant's own local named
/// world, read through that world's own window.
#[test]
fn a_share_stays_inside_the_grants_own_local_named_world() {
    run_on_engine_stack("guests-doors-where", || async {
        let f = guests().await;
        let pact = f.activate().await;
        f.a.say(&f.a_world, SHARED_WORDS).await;
        f.a.say(&f.a_unshared, UNSHARED_WORDS).await;
        // The peer's world reaches A as A's own foreign copy.
        f.a.permit_imported().await;
        let delivery = f.b.deliver(&pact, &f.b_world, PEER_WORDS).await;
        let joined = f.a.ok("vault.federation.connect.rejoin", delivery).await;
        assert_eq!(joined["status"], "imported", "{joined}");
        let foreign = joined["world_ref"]
            .as_str()
            .expect("A's copy of B's world")
            .to_owned();
        assert!(
            oneiron::entity_id::is_foreign_world_id_range(
                EntityId::from_hex(&foreign).expect("a world id")
            ),
            "A's copy of B's world is no foreign world: {foreign}"
        );
        let (guest, _) = f.a.guest(f.grant(), 0x71).await;

        let own = f.share_input(&f.a_world, &window(&f.a_world));
        f.a.ok("vault.guests.share", own.clone()).await;
        f.a.send(Caller::As(&guest), "vault.guests.export_envelope", &own)
            .await
            .ok("the guest's fetch of its world");
        let outside = [
            (
                "a world the grant does not name",
                f.share_input(&f.a_unshared, &window(&f.a_unshared)),
            ),
            ("base", f.share_input(BASE_WORLD, "2026-10")),
            (
                "the peer's world A received",
                f.share_input(&foreign, &window(&foreign)),
            ),
            (
                "the grant's world through another world's window",
                f.share_input(&f.a_world, &window(&f.a_unshared)),
            ),
        ];
        for (what, input) in &outside {
            for verb in ["vault.guests.share", "vault.guests.reshare"] {
                f.a.call(verb, input.clone()).await.refused(
                    &format!("the owner's {verb} of {what}"),
                    StatusCode::FORBIDDEN,
                    "FORBIDDEN",
                );
            }
            f.a.send(Caller::As(&guest), "vault.guests.export_envelope", input)
                .await
                .refused(
                    &format!("the guest's fetch of {what}"),
                    StatusCode::FORBIDDEN,
                    "FORBIDDEN",
                );
        }
    });
}

/// :38 ("attributed to a guest actor and not re-shareable") and :146
/// ("Actor = WHO ... a vault-resident guest actor entity"): a guest's
/// proposal lands in the owner's review inbox under the guest actor, writes
/// nothing, and goes with its grant (FIX 3684).
#[test]
fn a_guest_proposal_lands_in_the_owners_inbox_under_the_guest_actor_and_writes_nothing() {
    run_on_engine_stack("guests-doors-propose", || async {
        let f = guests().await;
        f.activate().await;
        let record = f.a.say(&f.a_world, SHARED_WORDS).await;
        let unshared = f.a.say(&f.a_unshared, UNSHARED_WORDS).await;
        let (guest, _) = f.a.guest(f.grant(), 0x71).await;

        let landed =
            f.a.send(
                Caller::As(&guest),
                "vault.guests.propose",
                &json!({
                    "grant_ref": f.grant(), "world_ref": f.a_world, "entity_ref": record,
                    "update": [16, 32, 48]
                }),
            )
            .await
            .ok("the guest's proposal");
        assert_eq!(landed["grant_ref"], f.grant(), "{landed}");
        assert_eq!(landed["entity_ref"], record.as_str(), "{landed}");
        let proposal = landed["proposal_ref"]
            .as_str()
            .expect("the proposal id")
            .to_owned();

        let inbox = f.a.proposals().await;
        assert_eq!(inbox.len(), 1, "the owner's inbox: {inbox:?}");
        let row = &inbox[0];
        assert_eq!(row["proposal_ref"], proposal.as_str(), "{row}");
        assert_eq!(
            row["proposer_ref"],
            f.guest_actor(),
            "the proposal is not the guest actor's: {row}"
        );
        assert_eq!(row["grant_ref"], f.grant(), "{row}");
        assert_eq!(row["world_ref"], f.a_world.as_str(), "{row}");
        assert_eq!(row["entity_ref"], record.as_str(), "{row}");
        assert_eq!(row["update_len"], 3, "{row}");
        assert!(row["decision"].is_null(), "{row}");
        assert_eq!(
            f.a.listed(&f.a_world, SHARED_WORDS).await.as_deref(),
            Some(record.as_str()),
            "the proposal wrote the owner's claim"
        );

        // A record outside the grant, and a grant the slip does not name.
        f.a.send(
            Caller::As(&guest),
            "vault.guests.propose",
            &json!({
                "grant_ref": f.grant(), "world_ref": f.a_unshared, "entity_ref": unshared,
                "update": [16]
            }),
        )
        .await
        .refused_as_a_request("a proposal outside the grant");
        f.a.send(
            Caller::As(&guest),
            "vault.guests.propose",
            &json!({
                "grant_ref": EntityId::now().to_hex(), "world_ref": f.a_world,
                "entity_ref": record, "update": [16]
            }),
        )
        .await
        .refused_as_a_request("a proposal under another grant");
        assert_eq!(f.a.proposals().await.len(), 1, "a refused proposal landed");

        f.a.ok("vault.guests.revoke", json!({"grant_ref": f.grant()}))
            .await;
        let inbox = f.a.proposals().await;
        assert!(
            inbox.is_empty(),
            "the revoked guest's proposal stayed: {inbox:?}"
        );
    });
}

/// surfaces.md:12 (OF-232, "Guest-revoke UI (un-revocable-copy
/// disclosure)") and `federation:G` (:238): "Revocation stops future sync
/// and sends an authenticated request, not a recall guarantee." A revoke
/// says the guest keeps what it already fetched, ends the grant's pact, and
/// stops every later fetch, proposal and share.
#[test]
fn a_revoke_says_the_guest_keeps_its_copy_ends_the_pact_and_stops_every_later_fetch() {
    run_on_engine_stack("guests-doors-revoke", || async {
        let f = guests().await;
        let pact = f.activate().await;
        f.a.say(&f.a_world, SHARED_WORDS).await;
        let (guest, slip_id) = f.a.guest(f.grant(), 0x71).await;
        let input = f.share_input(&f.a_world, &window(&f.a_world));
        f.a.send(Caller::As(&guest), "vault.guests.export_envelope", &input)
            .await
            .ok("the guest's fetch before the revoke");

        let revoked =
            f.a.ok("vault.guests.revoke", json!({"grant_ref": f.grant()}))
                .await;
        assert_eq!(revoked["grant_ref"], f.grant(), "{revoked}");
        assert_eq!(revoked["guest_ref"], f.guest_actor(), "{revoked}");
        assert_eq!(revoked["changed"], true, "{revoked}");
        assert!(
            revoked["revoked_slip_refs"]
                .as_array()
                .is_some_and(|slips| slips.iter().any(|slip| slip == slip_id.as_str())),
            "the guest's slip is not revoked: {revoked}"
        );
        assert_eq!(
            revoked["disclosure"],
            json!({
                "copied_bytes_recallable": false,
                "recipient_copy_state": "unknown",
                "deletion_request_status": "not_requested"
            }),
            "{revoked}"
        );
        assert_eq!(revoked["pact_standing"], "disconnected", "{revoked}");
        let targets = revoked["courtesy_targets"]
            .as_array()
            .unwrap_or_else(|| panic!("the revoke names no ended pact: {revoked}"));
        assert_eq!(targets.len(), 1, "{revoked}");
        assert_eq!(targets[0]["pact"], pact.as_str(), "{revoked}");
        assert_eq!(targets[0]["peer_vault_id"], f.b_vault.as_str(), "{revoked}");
        let row = f.a.pact_row(&pact).await.expect("A's row of the pact");
        assert_eq!(row["status"], "Disconnected", "{row}");
        assert_eq!(row["epoch"], 1, "{row}");

        // A repeat changes nothing and says so.
        let again =
            f.a.ok("vault.guests.revoke", json!({"grant_ref": f.grant()}))
                .await;
        assert_eq!(again["changed"], false, "{again}");
        assert_eq!(again["revoked_at"], revoked["revoked_at"], "{again}");
        assert!(
            again["revoked_slip_refs"]
                .as_array()
                .is_none_or(Vec::is_empty),
            "{again}"
        );

        // Every later act through the grant stops.
        f.a.send(Caller::As(&guest), "vault.guests.export_envelope", &input)
            .await
            .refused(
                "the guest's fetch after the revoke",
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
            );
        f.a.send(
            Caller::As(&guest),
            "vault.guests.propose",
            &json!({
                "grant_ref": f.grant(), "world_ref": f.a_world, "entity_ref": f.a_world,
                "update": [16]
            }),
        )
        .await
        .refused(
            "the guest's proposal after the revoke",
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
        );
        f.a.call("vault.guests.share", input.clone()).await.refused(
            "the owner's share after the revoke",
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
        );
        let key = SigningKey::from_bytes(&[0x75; 32]);
        f.a.call(
            "vault.guests.mint_slip",
            Side::mint_input(f.grant(), &key, f.a.vault.now_recorded_at() + 3600),
        )
        .await
        .refused(
            "a new slip on the revoked grant",
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
        );
    });
}
