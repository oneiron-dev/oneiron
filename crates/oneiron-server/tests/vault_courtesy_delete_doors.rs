//! Public-door promise tests for the `vault.courtesy_delete` family (ruling
//! L4-23 = A: each test proves a promise at the door; DOOR-FAMILIES Part 2,
//! row 6).
//!
//! Every case drives the real routes in process (`build_app` + `oneshot`):
//! `POST /v1/core/facade/<verb>` for `vault.courtesy_delete.send`, `.sent`,
//! `.incoming` and `.answer`, and the former peer's keyless ingress
//! `POST /v1/federation/courtesy-delete`. Two served, rooted hosts hold a
//! Connect pact between their vaults (set up through the engine's owner
//! calls, as `transport_credential_release.rs` does); the asker ends it
//! with the `vault.federation.connect.disconnect` door. An ask reaches the
//! other host as the signed bytes the asker's host key signs, posted to its
//! ingress; no outbox worker runs. Callers: each owner on its host root
//! credential, and an agent on its own paired credential. No sleeps, no
//! models.
//!
//! The promises, with their canon lines (oneiron-docs `generated/`):
//! - no recall, a courtesy unsend only
//!   (`oneiron/planning/reversibility-review-v1.md:125`): a send queues an
//!   ask, deletes nothing on the asker's side, and its record claims no
//!   delivery or deletion;
//! - forget-me is normal sharing: an authenticated request, an optional
//!   courtesy unsend, no remote attestation or recall guarantee
//!   (`oneiron/sync/oneiron-arch-0043-federation-membership-v1.md:232`):
//!   an ask is only for a pact its owner ended, and only an ask signed by
//!   the key the recipient pinned for that pact is filed;
//! - the recipient reviews and answers (`reversibility-review-v1.md:125`):
//!   a filed ask deletes nothing until its owner answers, and an answer
//!   deletes the records it names and no other;
//! - the four doors are the owner's: an agent is refused and nothing is
//!   queued (`crates/oneiron-server/src/api/facade/courtesy_delete_doors.rs:1-9`).
//!
//! These promises hold on main. Their red proof is a seeded fault (Test rules
//! v2, rule 5), named in the PR.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! vault_courtesy_delete_doors`.
#![cfg(oneiron_test_support)]
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
    AuthorityVaultId, CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal,
    pairing_binding_transcript,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::deletion::encode_signed_cooperative_deletion_request;
use oneiron::federation::{
    FederationDirectionScope, Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling,
};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const SEND: &str = "vault.courtesy_delete.send";
const SENT: &str = "vault.courtesy_delete.sent";
const INCOMING: &str = "vault.courtesy_delete.incoming";
const ANSWER: &str = "vault.courtesy_delete.answer";
const DISCONNECT: &str = "vault.federation.connect.disconnect";
/// The former peer's keyless ingress for a signed ask.
const INGRESS: &str = "/v1/federation/courtesy-delete";
/// The former peer's host origin a send names; no test contacts it.
const PEER: &str = "https://former-peer.example";
const LEARNED_AT: u64 = 1;

/// The fields a sent ask's record carries: its ids, its pact, its
/// recipient, its delivery status and its times. None claims recall.
const SENT_FIELDS: [&str; 7] = [
    "request",
    "pages",
    "pact",
    "recipient",
    "status",
    "created",
    "updated",
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn error_code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

/// One credential a test holds: its slip, its holder key and its token.
struct Holder {
    key: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

/// One served, rooted vault: its router, its host's slip issuer and root
/// slip, its owner bound under that root, the owner's engine proof, and,
/// when asked, one paired agent.
struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    root_slip: CapabilitySlip,
    root_token: String,
    owner: EntityId,
    proof: AuthenticatedOwner,
    vault_id: AuthorityVaultId,
    agent: Option<Holder>,
}

/// Who sends a request.
#[derive(Clone, Copy)]
enum Caller {
    Owner,
    Agent,
}

impl Host {
    async fn open(name: &str, pair: bool) -> Self {
        let dir = tempfile::tempdir().expect("vault directory");
        let vault =
            Arc::new(Vault::open(&dir.path().join(name), VaultConfig::device()).expect("vault"));
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some(format!("courtesy-delete-doors-{name}")),
                    ..Default::default()
                },
            )
            .expect("server"),
        );
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let root_slip = vault.ensure_host_root_slip(&issuer).expect("host root");
        let root_token = root_slip.to_token().expect("root slip token");
        vault
            .provision_engine_machine_identities(&issuer)
            .expect("engine machine identities");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's machine profile");
        let owner = vault.ensure_embedded_owner_actor().expect("owner actor");
        oneiron::test_support::bind_host_owner(&vault, &issuer, owner).expect("owner bound");
        let proof = vault
            .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
            .expect("owner proof");
        let vault_id = vault
            .authority_fold()
            .expect("authority fold")
            .vault_id
            .expect("a rooted vault has an id");
        let app = build_app(server);
        let agent = if pair {
            Some(pair_agent(&vault, &app, &issuer, "courtesy-delete-agent", [0x43; 32]).await)
        } else {
            None
        };
        Self {
            _dir: dir,
            vault,
            app,
            issuer,
            root_slip,
            root_token,
            owner,
            proof,
            vault_id,
            agent,
        }
    }

    fn agent(&self) -> &Holder {
        self.agent.as_ref().expect("this host paired an agent")
    }

    /// The request binding `caller` signs afresh for one request.
    fn binding(&self, caller: Caller) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = match caller {
            Caller::Owner => hex(&self
                .issuer
                .binding_proof(&self.root_slip, challenge.as_bytes())
                .expect("owner holder proof")),
            Caller::Agent => {
                let agent = self.agent();
                let transcript = agent
                    .slip
                    .binding_transcript(challenge.as_bytes())
                    .expect("agent binding transcript");
                hex(&agent.key.sign(&transcript).to_bytes())
            }
        };
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    fn token(&self, caller: Caller) -> &str {
        match caller {
            Caller::Owner => self.root_token.as_str(),
            Caller::Agent => self.agent().token.as_str(),
        }
    }

    /// `caller` posts `verb` with `input` to its facade door: the status and
    /// the body.
    async fn post(&self, caller: Caller, verb: &str, input: Value) -> (StatusCode, Value) {
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {}", self.token(caller)))
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
        let bytes = to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .expect("facade response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The owner posts `verb`: asserts the 200 and answers the body.
    async fn owner_ok(&self, verb: &str, input: Value) -> Value {
        let (status, body) = self.post(Caller::Owner, verb, input).await;
        assert_eq!(status, StatusCode::OK, "the owner's {verb}: {body}");
        body
    }

    /// A former peer posts signed ask bytes to this host's keyless ingress:
    /// the status.
    async fn take_ask(&self, bytes: Vec<u8>) -> StatusCode {
        let request = Request::post(INGRESS)
            .header("content-type", "application/octet-stream")
            .body(Body::from(bytes))
            .expect("ingress request");
        self.app
            .clone()
            .oneshot(request)
            .await
            .expect("ingress response")
            .status()
    }

    /// The owner remembers one claim about himself: its id.
    async fn remember(&self, predicate: &str, text: &str) -> EntityId {
        let receipt = self
            .owner_ok(
                "vault.remember",
                json!({
                    "predicate": predicate,
                    "subject_ref": self.owner.to_hex(),
                    "value": {"text": text},
                    "confidence": 0.9,
                    "source": "user_stated",
                }),
            )
            .await;
        let id = receipt["claim"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("the receipt names the claim: {receipt}"));
        EntityId::from_hex(id).expect("claim id")
    }

    /// The record's stored bytes, if it is stored.
    fn stored(&self, id: &EntityId) -> Option<Vec<u8>> {
        self.vault.get_raw(id).expect("raw read")
    }

    /// The owner's own sent asks.
    async fn sent(&self) -> Vec<Value> {
        let sent = self.owner_ok(SENT, json!({})).await;
        sent.as_array().expect("a list of sent asks").clone()
    }

    /// The asks filed here for the owner's review.
    async fn incoming(&self) -> Vec<Value> {
        let incoming = self.owner_ok(INCOMING, json!({})).await;
        incoming.as_array().expect("a list of filed asks").clone()
    }

    /// The owner ends the pact with the disconnect door.
    async fn disconnect(&self, pact: &[u8; 32]) {
        self.owner_ok(DISCONNECT, json!({"pact": hex(pact)})).await;
    }

    /// One ask about `pact` signed by `issuer` over this vault's ended pact,
    /// in the bytes its ingress takes; with its nonce.
    fn signed_ask(&self, issuer: &HostSlipIssuer, pact: &[u8; 32]) -> (Vec<u8>, [u8; 16]) {
        let fold = self.vault.authority_fold().expect("authority fold");
        let state = fold.federation_pacts.get(pact).expect("the pact");
        let cutoff = state.terminal_epoch.unwrap_or(state.pact_epoch);
        let nonce = *EntityId::now().as_bytes();
        let pages = issuer
            .sign_cooperative_deletion_request(&self.vault, pact, Vec::new(), cutoff, nonce)
            .expect("a signed ask");
        assert_eq!(pages.len(), 1, "an ask naming no world is one page");
        let bytes = encode_signed_cooperative_deletion_request(&pages[0]).expect("ask bytes");
        (bytes, nonce)
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
) -> Holder {
    let principal = vault.ensure_agent_principal(name).expect("agent principal");
    let key = SigningKey::from_bytes(&seed);
    let binding_key = key.verifying_key().to_bytes();
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
    let signature = hex(&key.sign(&transcript).to_bytes());
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
    Holder { key, slip, token }
}

/// A Connect guest's bounds over one world: read and propose, private at
/// most (the seeded guest ceiling's sensitivity).
fn guest_scope(world: EntityId) -> Scope {
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some([ScopeId(world)].into());
    scope.verbs = ScopeAxis::Some(["read".to_owned(), "propose".to_owned()].into());
    scope.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Private);
    scope
}

fn guest_direction(world: EntityId) -> FederationDirectionScope {
    FederationDirectionScope {
        worlds: ScopeAxis::Some([ScopeId(world)].into()),
        facets: ScopeAxis::All,
        bands: ScopeAxis::All,
    }
}

/// A live Connect pact between `asker` and `peer`, each half signed by its
/// own host, each owner's grant over one world of its own: the pact id.
fn connect(asker: &Host, peer: &Host) -> [u8; 32] {
    let asker_world = asker
        .vault
        .create_world(&asker.proof, "courtesy-asker", LEARNED_AT)
        .expect("the asker's world");
    let peer_world = peer
        .vault
        .create_world(&peer.proof, "courtesy-peer", LEARNED_AT)
        .expect("the peer's world");
    let minted = asker
        .vault
        .mint_connect_grant(
            &asker.proof,
            peer.vault_id,
            guest_scope(asker_world),
            None,
            None,
        )
        .expect("the asker's Connect grant");
    let reciprocal = peer
        .vault
        .mint_connect_grant(
            &peer.proof,
            asker.vault_id,
            guest_scope(peer_world),
            None,
            None,
        )
        .expect("the peer's Connect grant");
    let offer = asker
        .vault
        .propose_connect_as(
            &asker.proof,
            &asker.issuer,
            minted.grant,
            peer.vault_id,
            guest_direction(asker_world),
            guest_direction(peer_world),
        )
        .expect("the asker's offer");
    let (_, counter) = peer
        .vault
        .accept_connect_as(&peer.proof, &peer.issuer, reciprocal.grant, &offer)
        .expect("the peer accepts");
    asker
        .vault
        .accept_connect_as(&asker.proof, &asker.issuer, minted.grant, &counter)
        .expect("the asker accepts the counter");
    offer.pact_id
}

/// A courtesy unsend queues one ask for the ended pact and deletes nothing
/// on the asker's side; its record says queued and carries no recall or
/// deletion claim, and the sent list shows the same ask. (P1.)
#[test]
fn a_courtesy_unsend_queues_an_ask_and_deletes_nothing_here() {
    run_on_engine_stack("courtesy-delete-send", || async {
        let asker = Host::open("asker", false).await;
        let peer = Host::open("peer", false).await;
        let pact = connect(&asker, &peer);
        let kept = asker
            .remember("courtesy.kept_fact", "the asker keeps what it shared")
            .await;
        let before = asker.stored(&kept).expect("the asker's claim is stored");
        asker.disconnect(&pact).await;

        let sent = asker
            .owner_ok(SEND, json!({"pact": hex(&pact), "peer": PEER}))
            .await;
        assert_eq!(sent["pact"], hex(&pact), "{sent}");
        assert_eq!(
            sent["status"], "queued",
            "a courtesy ask is only queued: {sent}"
        );
        let request = sent["request"].as_str().expect("the ask's id");
        assert_eq!(request.len(), 32, "{sent}");
        assert_eq!(sent["pages"], json!([request]), "one page: {sent}");
        let fields: BTreeSet<&str> = sent
            .as_object()
            .expect("a sent ask is an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            fields,
            BTreeSet::from(SENT_FIELDS),
            "the record carries no recall, proof or deletion field: {sent}"
        );

        assert_eq!(
            asker.stored(&kept),
            Some(before),
            "a courtesy unsend deletes nothing on the asker's side"
        );
        let listed = asker.sent().await;
        assert_eq!(listed.len(), 1, "{listed:?}");
        assert_eq!(listed[0]["request"], request, "{listed:?}");
        assert_eq!(listed[0]["status"], "queued", "{listed:?}");
    });
}

/// An ask is only for a pact its owner ended: a live pact is refused, an
/// unknown pact is not found, and nothing is queued until the disconnect.
/// (P2.)
#[test]
fn a_courtesy_unsend_needs_an_ended_pact() {
    run_on_engine_stack("courtesy-delete-ended-pact", || async {
        let asker = Host::open("asker", false).await;
        let peer = Host::open("peer", false).await;
        let pact = connect(&asker, &peer);

        let (status, body) = asker
            .post(
                Caller::Owner,
                SEND,
                json!({"pact": hex(&pact), "peer": PEER}),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "a live pact: {body}");
        let (status, body) = asker
            .post(
                Caller::Owner,
                SEND,
                json!({"pact": "00".repeat(32), "peer": PEER}),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "an unknown pact: {body}");
        assert!(asker.sent().await.is_empty(), "nothing is queued");

        asker.disconnect(&pact).await;
        asker
            .owner_ok(SEND, json!({"pact": hex(&pact), "peer": PEER}))
            .await;
        assert_eq!(
            asker.sent().await.len(),
            1,
            "the ended pact's ask is queued"
        );
    });
}

/// The former peer's host files an ask signed by the key it pinned for the
/// pact, for its owner's review, and deletes nothing; an ask another key
/// signed is refused, and the same ask again stays filed once. (P2, P3.)
#[test]
fn an_incoming_ask_lands_for_review_and_deletes_nothing() {
    run_on_engine_stack("courtesy-delete-incoming", || async {
        let asker = Host::open("asker", false).await;
        let peer = Host::open("peer", false).await;
        let pact = connect(&asker, &peer);
        let held = peer
            .remember("courtesy.held_fact", "the peer holds this")
            .await;
        let before = peer.stored(&held).expect("the peer's claim is stored");
        asker.disconnect(&pact).await;

        let stranger = HostSlipIssuer::from_secret(b"courtesy-delete-stranger").expect("issuer");
        let (forged, _) = asker.signed_ask(&stranger, &pact);
        assert_eq!(
            peer.take_ask(forged).await,
            StatusCode::FORBIDDEN,
            "an ask the pinned key did not sign is refused"
        );
        assert!(peer.incoming().await.is_empty(), "nothing is filed");

        let (bytes, nonce) = asker.signed_ask(&asker.issuer, &pact);
        assert_eq!(
            peer.take_ask(bytes.clone()).await,
            StatusCode::ACCEPTED,
            "the asker's signed ask is filed"
        );
        assert_eq!(
            peer.take_ask(bytes).await,
            StatusCode::OK,
            "the same ask again is filed once"
        );

        let incoming = peer.incoming().await;
        assert_eq!(incoming.len(), 1, "{incoming:?}");
        assert_eq!(incoming[0]["request"], hex(&nonce), "{incoming:?}");
        assert_eq!(incoming[0]["pact"], hex(&pact), "{incoming:?}");
        assert!(
            incoming[0]["answer"].is_null(),
            "the ask waits for its owner's answer: {incoming:?}"
        );
        assert_eq!(
            peer.stored(&held),
            Some(before),
            "nothing is deleted on receipt"
        );
    });
}

/// The recipient's owner answers a filed ask: the delete takes the record
/// it names and no other, and an answer to an ask never filed is refused
/// and deletes nothing. (P3.)
#[test]
fn the_answer_deletes_only_the_records_it_names() {
    run_on_engine_stack("courtesy-delete-answer", || async {
        let asker = Host::open("asker", false).await;
        let peer = Host::open("peer", false).await;
        let pact = connect(&asker, &peer);
        let named = peer
            .remember("courtesy.named_fact", "the answer deletes this")
            .await;
        let other = peer
            .remember("courtesy.other_fact", "the answer leaves this")
            .await;
        let other_before = peer.stored(&other).expect("the other claim is stored");
        asker.disconnect(&pact).await;
        let (bytes, nonce) = asker.signed_ask(&asker.issuer, &pact);
        assert_eq!(peer.take_ask(bytes).await, StatusCode::ACCEPTED);

        let (status, body) = peer
            .post(
                Caller::Owner,
                ANSWER,
                json!({
                    "pact": hex(&pact),
                    "request": hex(EntityId::now().as_bytes()),
                    "choice": "delete",
                    "delete": [named.to_hex()],
                }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an ask never filed: {body}"
        );
        assert!(
            peer.stored(&named).is_some(),
            "a refused answer deletes nothing"
        );

        let answered = peer
            .owner_ok(
                ANSWER,
                json!({
                    "pact": hex(&pact),
                    "request": hex(&nonce),
                    "choice": "delete",
                    "delete": [named.to_hex()],
                }),
            )
            .await;
        let answer = &answered["answer"];
        assert_eq!(answer["choice"], "delete", "{answered}");
        assert_eq!(answer["deleted"], json!([named.to_hex()]), "{answered}");
        assert!(
            peer.stored(&named).is_none(),
            "the record the answer names is deleted"
        );
        assert_eq!(
            peer.stored(&other),
            Some(other_before),
            "a record the answer does not name is kept"
        );
        let incoming = peer.incoming().await;
        assert_eq!(incoming.len(), 1, "{incoming:?}");
        assert_eq!(incoming[0]["answer"]["choice"], "delete", "{incoming:?}");
    });
}

/// The four doors are the owner's: a paired agent gets 403 at each, and
/// nothing is queued or answered. (Door.)
#[test]
fn the_courtesy_doors_are_the_owners() {
    run_on_engine_stack("courtesy-delete-owner-doors", || async {
        let host = Host::open("asker", true).await;
        let doors = [
            (SEND, json!({"pact": "00".repeat(32), "peer": PEER})),
            (SENT, json!({})),
            (INCOMING, json!({})),
            (
                ANSWER,
                json!({
                    "pact": "00".repeat(32),
                    "request": "00".repeat(16),
                    "choice": "delete",
                    "delete": [],
                }),
            ),
        ];
        for (verb, input) in doors {
            let (status, body) = host.post(Caller::Agent, verb, input).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "the agent at {verb}: {body}");
            assert_eq!(
                error_code(&body),
                Some("FORBIDDEN"),
                "the agent at {verb}: {body}"
            );
        }
        assert!(host.sent().await.is_empty(), "nothing is queued");
        assert!(host.incoming().await.is_empty(), "nothing is filed");
    });
}
