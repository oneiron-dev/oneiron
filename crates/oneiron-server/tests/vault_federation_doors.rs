//! Promise tests for the `vault.federation.*` doors, entered at
//! `POST /v1/core/facade/<verb>`. Canon: ARCH-0043
//! (oneiron/sync/oneiron-arch-0043-federation-membership-v1.md).
//!
//! Two vaults live in one process, each behind its own app. Neither sends
//! the other anything: as the Connect host says ("The owner carries each
//! half to the other host; this host sends nothing",
//! src/owner/federation_connect.rs), the test carries every signed half and
//! every delivery from one door's answer to the other door's input.
//!
//! - `federation:R1` (:219, with the Connect row :156): a pact activates only
//!   on both owners' signatures over the same disclosed scope.
//! - `federation:D1` / `D2` (:228-229): one owner's disconnect closes both
//!   directions on that side, with no help from the peer, and leaves a
//!   receipt.
//! - `federation:G` (:238, with :189): a delivery lands as the recipient's
//!   own copy in a foreign world, and the sharer's disconnect does not recall
//!   it.
//! - Re-scope row (:157): a narrow keeps the pact; a widen needs a fresh
//!   gesture from both owners at the next epoch.
//! - `federation:Rc` (:220, with :189): a coreference link is owner-confirmed,
//!   and unlinking retracts only the link's own claims.
//! - :22: connection acts are owner authority actions, so no other caller
//!   opens any of the 26 doors.

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
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    AgentTier, CapabilitySlip, HostSlipIssuer, MachineRole, WorldPrivacy, holder_proof_challenge,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// When the delivered claims were said and learned: 17 Oct 2026, so each
/// export window is that month's (`2026-10@<world>`), as FEDERATION-03 has it.
const LEARNED_AT: u64 = 1_792_238_400;
/// The predicate every delivered claim is written under.
const PREDICATE: &str = "federation.doors.delivery";
/// What the sharing vault says in its shared world.
const SHARED_WORDS: &str = "The sharer's observatory opens at dusk.";
/// What the peer says in its own shared world.
const PEER_WORDS: &str = "The peer's workshop keeps the spare lenses.";

/// Every `vault.federation.*` row (scripts/sdk/verbs/vault.federation.*.json).
const FEDERATION_VERBS: [&str; 26] = [
    "vault.federation.burst.baseline",
    "vault.federation.burst.disposition",
    "vault.federation.burst.ingress",
    "vault.federation.burst.policy",
    "vault.federation.burst.policy.set",
    "vault.federation.burst.replay",
    "vault.federation.burst.review",
    "vault.federation.burst.review.reject",
    "vault.federation.burst.review.release",
    "vault.federation.connect.accept",
    "vault.federation.connect.disconnect",
    "vault.federation.connect.export",
    "vault.federation.connect.grants.mint",
    "vault.federation.connect.identity",
    "vault.federation.connect.narrow",
    "vault.federation.connect.offer",
    "vault.federation.connect.rejoin",
    "vault.federation.connect.rescope.accept",
    "vault.federation.connect.rescope.offer",
    "vault.federation.connect.world_privacy.export",
    "vault.federation.connect.world_privacy.receive",
    "vault.federation.coreference.confirm",
    "vault.federation.coreference.link",
    "vault.federation.coreference.share_consent",
    "vault.federation.coreference.unlink",
    "vault.federation.status",
];

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

    /// Asserts a 400 `BAD_REQUEST`, the doors' answer to a refused input.
    fn bad_request(&self, call: &str) {
        assert_eq!(
            self.status,
            StatusCode::BAD_REQUEST,
            "{call} answered {}",
            self.body
        );
        assert_eq!(self.body["error"]["code"], "BAD_REQUEST", "{call}");
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

    /// `caller`'s call to `verb` at its facade route.
    async fn send(&self, caller: Caller<'_>, verb: &str, input: &Value) -> Reply {
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
                principal.slip.to_token().expect("caller slip token"),
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
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {token}"))
            .header(
                "x-oneiron-binding",
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
            )
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("facade request");
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
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{verb} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        Reply { status, body }
    }

    /// The owner's call to `verb`.
    async fn call(&self, verb: &str, input: Value) -> Reply {
        self.send(Caller::Owner, verb, &input).await
    }

    /// The owner's call to `verb`, which must answer 200.
    async fn ok(&self, verb: &str, input: Value) -> Value {
        self.call(verb, input).await.ok(verb)
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
                    "world_id": "00000000000000000000000000000001",
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
        let written = self
            .ok(
                "vault.gate.policy.put",
                json!({
                    "manifest_ref": row["manifest_ref"],
                    "expected_body_hash": row["body_hash"],
                    "manifest": manifest
                }),
            )
            .await;
        assert!(
            written["receipt_ref"]
                .as_str()
                .is_some_and(|receipt| !receipt.is_empty()),
            "the policy write's receipt: {written}"
        );
    }

    /// Says `words` in `world` as an owner claim, then exports that world's
    /// October window over `pact`: the delivery the owner carries.
    async fn deliver(&self, pact: &str, world: &str, words: &str) -> Value {
        let mut scope = self.base_claim_scope().await;
        scope["world_id"] = json!(world);
        let written = self
            .ok(
                "vault.claims.upsert",
                json!({
                    "predicate": PREDICATE, "subject_ref": self.owner.to_hex(), "value": words,
                    "confidence": 0.9, "source": "user_stated", "sensitivity": 1, "scope": scope,
                    "occurred_at": LEARNED_AT, "learned_at": LEARNED_AT
                }),
            )
            .await;
        assert_eq!(written["approval"], "proposed", "{written}");
        self.ok("vault.federation.connect.export", export_input(pact, world))
            .await
    }

    /// The claims under [`PREDICATE`] this vault lists in `world` saying `words`.
    async fn listed(&self, world: &str, words: &str) -> Vec<Value> {
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
            .filter(|row| row["world_ref"] == world && row["value"] == words)
            .cloned()
            .collect()
    }

    /// [`Self::listed`] once it lists one claim, read again for a while as
    /// FEDERATION-03's `awaitPublic` does.
    async fn listed_soon(&self, world: &str, words: &str) -> Vec<Value> {
        for _ in 0..50 {
            let rows = self.listed(world, words).await;
            if !rows.is_empty() {
                return rows;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        self.listed(world, words).await
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
        Principal { slip, key }
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
}

/// One direction of a pact: these worlds, every facet and band.
fn direction(worlds: &[&str]) -> Value {
    json!({
        "worlds": {"kind": "some", "values": worlds},
        "facets": {"kind": "all"}, "bands": {"kind": "all"}
    })
}

/// A Connect grant's authority: read `world`, at most private.
fn share_scope(world: &str) -> Value {
    json!({
        "worlds": {"kind": "some", "values": [world]},
        "facets": {"kind": "all"}, "bands": {"kind": "all"},
        "audience": {"kind": "all"}, "verbs": {"kind": "some", "values": ["read"]},
        "sensitivity": {"kind": "at_most", "value": "private"}
    })
}

/// `vault.federation.connect.export`'s input for `world`'s October window.
fn export_input(pact: &str, world: &str) -> Value {
    json!({"pact": pact, "window_key": format!("2026-10@{world}"), "world_ref": world})
}

/// Two vaults, each with a shared world and a Connect grant naming the other.
struct Connect {
    _dir: tempfile::TempDir,
    a: Side,
    b: Side,
    a_vault: String,
    b_vault: String,
    a_key: String,
    b_key: String,
    a_world: String,
    a_unshared: String,
    b_world: String,
    a_grant: Value,
    b_grant: Value,
}

async fn connect() -> Connect {
    let dir = tempfile::tempdir().expect("fresh Connect vaults");
    let a = Side::new(&dir.path().join("a"), "vault-federation-doors-a");
    let b = Side::new(&dir.path().join("b"), "vault-federation-doors-b");
    let a_id = a.ok("vault.federation.connect.identity", json!({})).await;
    let b_id = b.ok("vault.federation.connect.identity", json!({})).await;
    assert_ne!(a_id["vault"], b_id["vault"], "two vaults");
    let a_world = a.world("federation-doors-shared").await;
    let a_unshared = a.world("federation-doors-unshared").await;
    let b_world = b.world("federation-doors-peer").await;
    let a_grant = a
        .ok(
            "vault.federation.connect.grants.mint",
            json!({"peer_vault": b_id["vault"], "authority_scope": share_scope(&a_world)}),
        )
        .await;
    let b_grant = b
        .ok(
            "vault.federation.connect.grants.mint",
            json!({"peer_vault": a_id["vault"], "authority_scope": share_scope(&b_world)}),
        )
        .await;
    assert_eq!(a_grant["resolved_scope"], share_scope(&a_world));
    assert_eq!(b_grant["resolved_scope"], share_scope(&b_world));
    let text = |value: &Value| value.as_str().expect("a hex string").to_owned();
    Connect {
        _dir: dir,
        a_vault: text(&a_id["vault"]),
        b_vault: text(&b_id["vault"]),
        a_key: text(&a_id["host_key"]),
        b_key: text(&b_id["host_key"]),
        a,
        b,
        a_world,
        a_unshared,
        b_world,
        a_grant,
        b_grant,
    }
}

impl Connect {
    /// A's signed offer to B: A discloses its shared world and asks for B's.
    async fn a_offer(&self) -> Value {
        self.a
            .ok(
                "vault.federation.connect.offer",
                json!({
                    "peer_vault": self.b_vault, "grant": self.a_grant["grant"],
                    "outbound": direction(&[&self.a_world]),
                    "inbound": direction(&[&self.b_world])
                }),
            )
            .await
    }

    /// B accepts `offer`, then A accepts B's counter: the pact, Active on
    /// both sides at epoch 1.
    async fn activate(&self, offer: &Value) -> String {
        let b_accept = self
            .b
            .ok(
                "vault.federation.connect.accept",
                json!({"offer": offer, "grant": self.b_grant["grant"]}),
            )
            .await;
        assert_eq!(b_accept["pact"], offer["pact"], "{b_accept}");
        assert_eq!(b_accept["status"], "Active", "{b_accept}");
        assert_eq!(b_accept["peer_key"], self.a_key, "{b_accept}");
        let a_accept = self
            .a
            .ok(
                "vault.federation.connect.accept",
                json!({"offer": b_accept["counter"], "grant": self.a_grant["grant"]}),
            )
            .await;
        assert_eq!(a_accept["status"], "Active", "{a_accept}");
        assert_eq!(a_accept["peer_key"], self.b_key, "{a_accept}");
        let pact = offer["pact"].as_str().expect("the pact id").to_owned();
        self.a.holds(&pact, "Active", 1, "A").await;
        self.b.holds(&pact, "Active", 1, "B").await;
        pact
    }

    /// An Active pact between A and B, with A's offer that made it.
    async fn active(&self) -> (String, Value) {
        let offer = self.a_offer().await;
        let pact = self.activate(&offer).await;
        (pact, offer)
    }
}

/// `federation:R1` (canon :219): "Activation requires both owner signatures,
/// matching scope digests, and matching pact epoch." The Connect row (:156):
/// the grants "activate only after both owners sign the exact disclosed
/// scopes".
#[test]
fn a_pact_activates_only_on_both_owners_signatures_over_one_scope() {
    run_on_engine_stack("federation-doors-activation", || async {
        let f = connect().await;
        // B's real signed offer asks A to disclose its shared and its
        // unshared world; A's grant discloses only the shared one.
        let wider =
            f.b.ok(
                "vault.federation.connect.offer",
                json!({
                    "peer_vault": f.a_vault, "grant": f.b_grant["grant"],
                    "outbound": direction(&[&f.b_world]),
                    "inbound": direction(&[&f.a_world, &f.a_unshared])
                }),
            )
            .await;
        let refused =
            f.a.call(
                "vault.federation.connect.accept",
                json!({"offer": wider, "grant": f.a_grant["grant"]}),
            )
            .await;
        refused.bad_request("accepting an offer wider than the grant");
        assert!(
            refused.body["error"]["message"]
                .as_str()
                .is_some_and(|message| message
                    .contains("the pact's outbound scope is not the Connect grant's scope")),
            "{}",
            refused.body
        );
        for (side, name) in [(&f.a, "A"), (&f.b, "B")] {
            let pact = wider["pact"].as_str().expect("the wider pact id");
            assert_eq!(
                side.pact_row(pact).await,
                None,
                "{name} holds the wider pact"
            );
        }

        // A's own offer with a signature that is not A's.
        let offer = f.a_offer().await;
        let mut forged = offer.clone();
        forged["signature"] = json!("00".repeat(64));
        let refused =
            f.b.call(
                "vault.federation.connect.accept",
                json!({"offer": forged, "grant": f.b_grant["grant"]}),
            )
            .await;
        refused.bad_request("accepting an offer A did not sign");
        let pact = offer["pact"].as_str().expect("the pact id");
        assert_eq!(f.b.pact_row(pact).await, None, "B holds a forged pact");

        // The same offer as A signed it, accepted by B, and B's counter
        // accepted by A: Active on both sides at epoch 1.
        let activated = f.activate(&offer).await;
        assert_eq!(activated, pact);
    });
}

/// `federation:D1` (canon :228): "Disconnect defaults to both-direction revoke
/// access, stop sync, emit receipt"; `federation:D2` (:229): "host-enforced
/// with zero peer cooperation".
#[test]
fn a_disconnect_closes_both_directions_on_its_side_and_leaves_a_receipt() {
    run_on_engine_stack("federation-doors-disconnect", || async {
        let f = connect().await;
        let (pact, _) = f.active().await;
        f.a.permit_imported().await;
        // B's delivery to A, made while the pact was whole.
        let delivery = f.b.deliver(&pact, &f.b_world, PEER_WORDS).await;

        let closed =
            f.a.ok("vault.federation.connect.disconnect", json!({"pact": pact}))
                .await;
        assert_eq!(closed["receipt"]["pact"], pact, "{closed}");
        assert_eq!(closed["receipt"]["status"], "Disconnected", "{closed}");
        assert_eq!(closed["receipt"]["epoch"], 1, "{closed}");
        assert_eq!(closed["outbound_access"], false, "{closed}");
        assert_eq!(closed["inbound_access"], false, "{closed}");
        assert_eq!(closed["sync_stopped"], true, "{closed}");

        // The next use in each direction refuses on A, with nothing from B.
        f.a.call(
            "vault.federation.connect.export",
            export_input(&pact, &f.a_world),
        )
        .await
        .bad_request("exporting over a disconnected pact");
        f.a.call("vault.federation.connect.rejoin", delivery)
            .await
            .bad_request("taking a delivery over a disconnected pact");
        assert!(
            f.a.listed(&f.b_world, PEER_WORDS).await.is_empty(),
            "A took the peer's words"
        );
        f.a.holds(&pact, "Disconnected", 1, "A").await;
        f.b.holds(&pact, "Active", 1, "B").await;
    });
}

/// `federation:G` (canon :238): "Guest federation creates a separately
/// controlled recipient copy. ... Revocation stops future sync and sends an
/// authenticated request, not a recall guarantee." (:189): "Guest content
/// lands in a foreign WORLD."
#[test]
fn a_delivery_lands_as_the_recipients_own_copy_in_a_foreign_world() {
    run_on_engine_stack("federation-doors-delivery", || async {
        let f = connect().await;
        let (pact, _) = f.active().await;
        f.b.permit_imported().await;
        let delivery = f.a.deliver(&pact, &f.a_world, SHARED_WORDS).await;
        assert_eq!(delivery["body"]["pact"], pact, "{delivery}");
        assert_eq!(delivery["body"]["epoch"], 1, "{delivery}");
        assert_eq!(delivery["body"]["source_vault"], f.a_vault, "{delivery}");
        assert_eq!(delivery["body"]["recipient_vault"], f.b_vault, "{delivery}");
        assert_eq!(delivery["body"]["world_ref"], f.a_world, "{delivery}");
        assert!(
            delivery["signature"]
                .as_str()
                .is_some_and(|signature| !signature.is_empty()),
            "{delivery}"
        );

        let joined =
            f.b.ok("vault.federation.connect.rejoin", delivery.clone())
                .await;
        assert_eq!(joined["pact"], pact, "{joined}");
        assert_eq!(joined["epoch"], 1, "{joined}");
        assert_eq!(joined["status"], "imported", "{joined}");
        let foreign = joined["world_ref"].as_str().expect("the foreign world");
        assert_ne!(foreign, f.a_world, "B filed A's words under A's own world");
        let foreign_id = EntityId::from_hex(foreign).expect("a world id");
        assert!(
            oneiron::entity_id::is_foreign_world_id_range(foreign_id),
            "B's copy of A's world is no foreign world: {foreign}"
        );

        let copy = f.b.listed_soon(foreign, SHARED_WORDS).await;
        assert_eq!(copy.len(), 1, "B's copy of A's words: {copy:?}");
        assert_eq!(copy[0]["source"], "imported", "{}", copy[0]);
        assert_eq!(copy[0]["approval"], "proposed", "{}", copy[0]);
        assert_eq!(copy[0]["lifecycle"], "active", "{}", copy[0]);

        // A's disconnect promises no recall, and B's copy stays B's.
        let closed =
            f.a.ok("vault.federation.connect.disconnect", json!({"pact": pact}))
                .await;
        assert_eq!(closed["copied_bytes_recallable"], false, "{closed}");
        assert_eq!(closed["recipient_copy_state"], "unknown", "{closed}");
        assert_eq!(
            f.b.listed(foreign, SHARED_WORDS).await.len(),
            1,
            "A's disconnect took B's copy"
        );
    });
}

/// The Re-scope row (canon :157): "Any widen changes the pact epoch and
/// requires a fresh owner gesture. Narrowing is allowed without implying a
/// breakup."
#[test]
fn a_narrow_keeps_the_pact_and_a_widen_takes_both_owners_at_the_next_epoch() {
    run_on_engine_stack("federation-doors-rescope", || async {
        let f = connect().await;
        let (pact, _) = f.active().await;

        // B narrows what it sends to nothing: the pact stays Active at
        // epoch 1, and B's very next export of its world refuses.
        let narrowed = f
            .b
            .ok(
                "vault.federation.connect.narrow",
                json!({
                    "pact": pact, "epoch": 1,
                    "outbound": {"worlds": {"kind": "bottom"}, "facets": {"kind": "all"}, "bands": {"kind": "all"}}
                }),
            )
            .await;
        assert_eq!(narrowed["pact"], pact, "{narrowed}");
        assert_eq!(narrowed["status"], "Active", "{narrowed}");
        assert_eq!(narrowed["epoch"], 1, "{narrowed}");
        assert_eq!(
            narrowed["effective_scope"]["worlds"],
            json!({"kind": "bottom"}),
            "{narrowed}"
        );
        f.b.call(
            "vault.federation.connect.export",
            export_input(&pact, &f.b_world),
        )
        .await
        .bad_request("exporting a world the narrow excluded");
        f.b.holds(&pact, "Active", 1, "B").await;

        // A widen at the epoch the pact already has is no fresh gesture.
        let rescope = |epoch: u64| {
            json!({
                "pact": pact, "epoch": epoch,
                "outbound": direction(&[&f.a_world]), "inbound": direction(&[&f.b_world])
            })
        };
        f.a.call("vault.federation.connect.rescope.offer", rescope(1))
            .await
            .bad_request("re-scoping at the current epoch");
        f.a.holds(&pact, "Active", 1, "A").await;

        // At epoch 2 both owners sign: A offers, B accepts, A accepts B's
        // counter, and both sides hold the pact at epoch 2.
        let offer =
            f.a.ok("vault.federation.connect.rescope.offer", rescope(2))
                .await;
        assert_eq!(offer["pact"], pact, "{offer}");
        assert_eq!(offer["epoch"], 2, "{offer}");
        let b_accept =
            f.b.ok(
                "vault.federation.connect.rescope.accept",
                json!({"offer": offer}),
            )
            .await;
        assert_eq!(b_accept["receipt"]["epoch"], 2, "{b_accept}");
        f.a.ok(
            "vault.federation.connect.rescope.accept",
            json!({"offer": b_accept["counter"]}),
        )
        .await;
        f.a.holds(&pact, "Active", 2, "A").await;
        f.b.holds(&pact, "Active", 2, "B").await;
    });
}

/// `federation:Rc` (canon :220): "Cross-vault coreference links identity
/// without merging belief; local by default, owner-confirmed before confirmed
/// links". (:189): "a local same_as edge can say 'this Sarah may be the same
/// Sarah' while keeping claims attributed to their source world."
#[test]
fn a_coreference_link_is_owner_confirmed_and_unlinking_retracts_only_the_link() {
    run_on_engine_stack("federation-doors-coreference", || async {
        let f = connect().await;
        let local = f.a.person("Sarah of this vault").to_hex();
        let other = f.a.person("Sarah of the peer's vault").to_hex();
        let pair = json!({"local_person": local, "other_person": other});

        let mut link = pair.clone();
        link["status"] = json!("proposed");
        let proposed = f.a.ok("vault.federation.coreference.link", link).await;
        assert_eq!(proposed["status"], "proposed", "{proposed}");
        assert_eq!(proposed["local_person"], local, "{proposed}");
        assert_eq!(proposed["other_person"], other, "{proposed}");

        let confirmed =
            f.a.ok("vault.federation.coreference.confirm", pair.clone())
                .await;
        assert_eq!(confirmed["status"], "confirmed", "{confirmed}");

        let link_claims: BTreeSet<String> = [&proposed, &confirmed]
            .iter()
            .map(|receipt| {
                receipt["status_claim"]
                    .as_str()
                    .expect("the link's status claim")
                    .to_owned()
            })
            .collect();
        let unlinked =
            f.a.ok("vault.federation.coreference.unlink", pair.clone())
                .await;
        assert_eq!(unlinked["unlinked"], true, "{unlinked}");
        assert_eq!(unlinked["original_claims_retained"], true, "{unlinked}");
        let retracted = unlinked["retracted_claims"]
            .as_array()
            .expect("the retracted claims");
        assert!(!retracted.is_empty(), "{unlinked}");
        for claim in retracted {
            let claim = claim.as_str().expect("a claim id");
            assert!(
                link_claims.contains(claim),
                "unlink retracted {claim}, which is no claim of the link ({link_claims:?})"
            );
        }
        for person in [&local, &other] {
            let read = f.a.ok("vault.get", json!({"entity_ref": person})).await;
            assert_eq!(read["value"]["kind"], "PERSON", "{read}");
        }
    });
}

/// Canon :22: "Connection confirms and subtree revokes are owner authority
/// actions in AUTHORITY_LOG." Every `vault.federation.*` row is an owner host
/// door (`host_door_proof: owner`). A person known to the vault and the
/// vault's own full-access agent, each on a read-and-write slip of its own,
/// get the owner's refusal at all 26 doors, each with an input its row
/// decodes (the row's input check runs before the door's).
#[test]
fn no_federation_door_opens_for_anyone_but_the_owner() {
    run_on_engine_stack("federation-doors-owner-only", || async {
        let f = connect().await;
        let (pact, offer) = f.active().await;
        let delivery = f.b.deliver(&pact, &f.b_world, PEER_WORDS).await;
        let mut rescope_offer = offer.clone();
        rescope_offer["epoch"] = json!(2);
        let person = f.a.person("Ada").to_hex();
        let peer = json!({
            "principal": f.a_grant["guest_actor"], "grant": f.a_grant["grant"],
            "scope": {"kind": "connect", "peer_vault_id": f.b_vault},
            "world": {"kind": "all"}
        });
        let pair = json!({"local_person": person, "other_person": EntityId::now().to_hex()});
        let settings = serde_json::to_value(WorldPrivacy::default()).expect("world settings JSON");
        let input = |verb: &str| -> Value {
            match verb {
                "vault.federation.burst.baseline" | "vault.federation.burst.policy" => peer.clone(),
                "vault.federation.burst.disposition" | "vault.federation.burst.replay" => {
                    json!({"peer": peer, "batch_ref": "federation-doors-batch"})
                }
                "vault.federation.burst.ingress" | "vault.federation.connect.rejoin" => {
                    delivery.clone()
                }
                "vault.federation.burst.policy.set" => json!({
                    "peer": peer,
                    "policy": {"baseline": null, "unusual_rate": "defer", "unusual_streak": "isolate-and-propose"}
                }),
                "vault.federation.burst.review"
                | "vault.federation.connect.identity"
                | "vault.federation.status" => json!({}),
                "vault.federation.burst.review.reject"
                | "vault.federation.burst.review.release" => {
                    json!({"bundle_ref": "federation-doors-bundle"})
                }
                "vault.federation.connect.accept" => {
                    json!({"offer": offer, "grant": f.a_grant["grant"]})
                }
                "vault.federation.connect.disconnect" => json!({"pact": pact}),
                "vault.federation.connect.export" => export_input(&pact, &f.a_world),
                "vault.federation.connect.grants.mint" => {
                    json!({"peer_vault": f.b_vault, "authority_scope": share_scope(&f.a_world)})
                }
                "vault.federation.connect.narrow" => {
                    json!({"pact": pact, "epoch": 1, "outbound": direction(&[&f.a_world])})
                }
                "vault.federation.connect.offer" => json!({
                    "peer_vault": f.b_vault, "grant": f.a_grant["grant"],
                    "outbound": direction(&[&f.a_world]), "inbound": direction(&[&f.b_world])
                }),
                "vault.federation.connect.rescope.accept" => json!({"offer": rescope_offer}),
                "vault.federation.connect.rescope.offer" => json!({
                    "pact": pact, "epoch": 2,
                    "outbound": direction(&[&f.a_world]), "inbound": direction(&[&f.b_world])
                }),
                "vault.federation.connect.world_privacy.export" => {
                    json!({"request": EntityId::now().to_hex()})
                }
                "vault.federation.connect.world_privacy.receive" => json!({
                    "body": {
                        "leg": "ask", "pact": pact, "epoch": 1,
                        "source_vault": f.b_vault, "recipient_vault": f.a_vault,
                        "world": f.b_world, "ask": EntityId::now().to_hex(), "settings": settings
                    },
                    "signature": "00".repeat(64)
                }),
                "vault.federation.coreference.confirm" | "vault.federation.coreference.unlink" => {
                    pair.clone()
                }
                "vault.federation.coreference.link" => {
                    let mut link = pair.clone();
                    link["status"] = json!("confirmed");
                    link
                }
                "vault.federation.coreference.share_consent" => {
                    let mut consent = pair.clone();
                    consent["pact"] = json!(pact);
                    consent
                }
                other => panic!("no input for {other}"),
            }
        };
        let guest = f.a.principal(f.a.person("Olu"), "human", 0x61);
        let agent = f.a.agent("federation-doors-agent", 0x62);
        for (caller, name) in [(&guest, "a person"), (&agent, "the vault's own agent")] {
            for verb in FEDERATION_VERBS {
                let reply = f.a.send(Caller::As(caller), verb, &input(verb)).await;
                assert_eq!(
                    reply.status,
                    StatusCode::FORBIDDEN,
                    "{name} at {verb}: {}",
                    reply.body
                );
                assert_eq!(reply.body["error"]["code"], "FORBIDDEN", "{name} at {verb}");
                assert!(
                    reply.body["error"]["message"]
                        .as_str()
                        .is_some_and(|message| message.contains("owner")),
                    "{name} at {verb}: {}",
                    reply.body
                );
            }
        }
        // Nothing they sent moved the pact.
        f.a.holds(&pact, "Active", 1, "A").await;
        f.b.holds(&pact, "Active", 1, "B").await;
    });
}
