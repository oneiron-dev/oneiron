//! Public-door promise tests for the `vault.usage` repair family: the stored
//! usage rows of this server's metering scope that no longer decode, the
//! removal of one reviewed row by the hash of its bytes, the receipts those
//! removals kept, and the per-vault rollup those rows feed.
//!
//! Every case drives the real routes in process (`build_app` + `oneshot`):
//! `POST /v1/core/facade/<verb>` for `vault.usage.events.undecodable`,
//! `vault.usage.events.remove_undecodable` and `vault.usage.repair.receipts`,
//! and `GET /v1/usage/owners/{owner}/vaults/{vault_id}/rollup` for the
//! rollup. Callers: the vault's embedded owner on the host root credential;
//! a second live person on their own minted human credential; a live person
//! on their own minted agent-class credential; and an agent on its own
//! minted agent credential, given a definition and a Grant by the tests that
//! need one. Each case owns its wall-clock vault, metered except the
//! unmetered case, so no clock moves and no sleeps are needed.
//!
//! The promises:
//! - the list names every stored row that does not decode, by row ref,
//!   length and hash, and none of its bytes;
//! - a removal deletes exactly the reviewed row and keeps one receipt that
//!   reads back;
//! - a removal refuses a row whose bytes changed, a row that is gone, and
//!   a row that decodes now, and keeps nothing then;
//! - the receipts read every kept receipt of this metering scope and count
//!   the kept rows that no longer decode;
//! - an agent whose Grant names the verb removes, while the same agent
//!   without the verb, a grantless agent and a second person are refused
//!   at all three doors;
//! - the rollup sums the recorded calls, an undecodable row fails the read
//!   instead of joining the sum, and removing it restores the read;
//! - a server that meters nothing answers all three verbs unbound.
//!
//! These promises hold on main. Their red proof is a seeded fault (Test rules
//! v2, rule 5), named in `seed_usage_faults.py`.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --no-fail-fast --test vault_usage_doors`. The test calls no test door; it
//! needs `oneiron/test-support` for `MemoryKeystore`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::agent_dispatch::budget_doors::UsageEventOrigin;
use oneiron::authority::{ActSurface, CapabilitySlip, HostSlipIssuer, holder_proof};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::usage_repair::{
    UsageRepairAuthority, UsageRepairReason, UsageRepairReceipt, UsageRepairSurface,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::usage::{UsageEvent, UsageEventType, UsageLedger, UsageMode, UsageTokenCounts};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const UNDECODABLE: &str = "vault.usage.events.undecodable";
const REMOVE: &str = "vault.usage.events.remove_undecodable";
const RECEIPTS: &str = "vault.usage.repair.receipts";

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every minted credential here binds; the holder proves it per
/// request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x6D; 32])
}

/// A served vault on the wall clock: its embedded owner, a second live
/// person, a live person holding an agent-class credential, and an agent
/// holding its own agent credential (bare until a test gives it a
/// definition and a Grant). Metered unless the case asks otherwise.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_proof: AuthenticatedOwner,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner: EntityId,
    vault_id: String,
    person_slip: CapabilitySlip,
    person_token: String,
    stranger_slip: CapabilitySlip,
    stranger_token: String,
    agent: EntityId,
    agent_slip: CapabilitySlip,
    agent_token: String,
}

/// Who sends a request.
#[derive(Clone, Copy, Debug)]
enum Caller {
    /// The embedded owner on the host root credential.
    Owner,
    /// A second live person on their own human credential.
    Person,
    /// A live person on their own agent-class credential, grantless.
    StrangerAgent,
    /// The agent on its own agent credential.
    Agent,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn error_code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// A served vault, metered for `owner` unless `metered` is false.
fn serve(metered: bool) -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("vault-usage-doors".into()),
            ..Default::default()
        },
    )
    .expect("create server");
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    let owner_proof = proof(&vault, owner);
    let second = EntityId::now();
    let stranger = EntityId::now();
    for id in [second, stranger] {
        person(&vault, id);
    }
    let agent = EntityId::now();
    let server = if metered {
        server
            .with_usage_metering(owner.to_hex())
            .expect("bind usage metering")
    } else {
        server
    };
    let vault_id = server
        .vault_usage()
        .map(|usage| usage.vault_id().to_owned())
        .unwrap_or_default();
    let app = build_app(Arc::new(server));
    let (person_slip, person_token) = credential(&vault, &issuer, second, Some("human"));
    let (stranger_slip, stranger_token) = credential(&vault, &issuer, stranger, Some("agent"));
    let (agent_slip, agent_token) = credential(&vault, &issuer, agent, Some("agent"));
    Served {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_proof,
        owner_slip,
        owner_token,
        owner,
        vault_id,
        person_slip,
        person_token,
        stranger_slip,
        stranger_token,
        agent,
        agent_slip,
        agent_token,
    }
}

fn served() -> Served {
    serve(true)
}

fn served_unmetered() -> Served {
    serve(false)
}

/// A credential this host mints `who` at `class`, holding `read` and
/// `write`: a holder's own slip, not owner-grade. Answers the slip and its
/// token.
fn credential(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    who: EntityId,
    class: Option<&str>,
) -> (CapabilitySlip, String) {
    let mut claims = vault
        .ensure_host_root_slip(issuer)
        .expect("the host root slip")
        .claims;
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = who.to_hex();
    claims.actor_class = class.map(str::to_owned);
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    let slip = vault
        .mint_capability_slip(issuer, claims)
        .expect("a credential");
    let token = slip.to_token().expect("token");
    (slip, token)
}

/// An enabled agent definition for `agent` and one Grant naming `verbs`,
/// both from the owner: answers the Grant's row id.
fn grant_verbs(served: &Served, agent: EntityId, name: &str, verbs: &[&str]) -> EntityId {
    create_agent_definition_as(
        &served.vault,
        &served.owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": name,
                "desc": "Usage doors test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled agent definition");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    let minted = mint_agent_grant_as(
        &served.vault,
        &served.owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the agent a Grant");
    assert!(minted.grant.confers, "{name}: the Grant confers");
    minted.grant.grant_ref
}

/// A stored usage event key's part for `value`: the lowercase hex of its
/// UTF-8 bytes, as the meter builds its keys.
fn key_part(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = value.as_bytes();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// The stored key of the usage event billed to `owner` in `vault_id` under
/// `id`, as the meter builds it.
fn event_key(owner: &str, vault_id: &str, id: &str) -> String {
    format!(
        "usage:event:{}:{}:{}",
        key_part(owner),
        key_part(vault_id),
        key_part(id)
    )
}

/// The row ref the list gives an event row with the key parts `billed` and
/// `id`: unpadded base64url of `event:<billed>:<id>`.
fn row_ref_for(billed: &str, id: &str) -> String {
    URL_SAFE_NO_PAD.encode(format!("event:{billed}:{id}"))
}

/// BLAKE3 of `bytes` as 64 lowercase hex digits, as the list hashes a row.
fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Plants `bytes` that decode as nothing under the event key billed to
/// `owner` for `id`: answers the stored key.
fn plant(served: &Served, owner: &str, id: &str, bytes: &[u8]) -> String {
    let key = event_key(owner, &served.vault_id, id);
    served
        .vault
        .sync_state_put(&key, bytes)
        .expect("plant an undecodable row");
    key
}

/// A minimal valid usage event billed to `owner` in `vault_id` under `id`,
/// counting `input` in-tokens and `output` out-tokens, priced at nothing.
fn event(owner: &str, vault_id: &str, id: &str, input: u64, output: u64) -> UsageEvent {
    UsageEvent {
        owner: owner.to_owned(),
        vault_id: vault_id.to_owned(),
        idempotency_key: id.to_owned(),
        source: Some(UsageMode::Local),
        event_type: UsageEventType::Inference,
        role: None,
        occurred_at: None,
        agent_id: None,
        model: None,
        service: None,
        token_counts: UsageTokenCounts {
            input_tokens: input,
            output_tokens: output,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        },
        cost_rates: None,
        unpriced: None,
        service_amount: 0,
        run: None,
    }
}

/// Records `event` on the engine's path and expects it recorded.
fn record(served: &Served, event: UsageEvent) {
    let recorded = UsageLedger::new(Arc::clone(&served.vault))
        .record_event(event, UsageMode::Local, UsageEventOrigin::Engine)
        .expect("record a usage event");
    assert!(recorded.recorded, "the ledger records the event");
}

impl Served {
    fn slip(&self, caller: Caller) -> Option<&CapabilitySlip> {
        match caller {
            Caller::Owner => None,
            Caller::Person => Some(&self.person_slip),
            Caller::StrangerAgent => Some(&self.stranger_slip),
            Caller::Agent => Some(&self.agent_slip),
        }
    }

    /// The request binding `caller` signs afresh for one request: the owner
    /// on the host root, anyone else on their own holder key.
    fn binding(&self, caller: Caller) -> String {
        match self.slip(caller) {
            None => {
                let timestamp = self.vault.now_recorded_at();
                let nonce = EntityId::now().to_hex();
                let challenge = format!("oneiron-request:{timestamp}:{nonce}");
                let signature = hex(&self
                    .issuer
                    .binding_proof(&self.owner_slip, challenge.as_bytes())
                    .expect("owner holder proof"));
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
            }
            Some(slip) => holder_proof(slip, &holder_key(), self.vault.now_recorded_at())
                .expect("holder proof")
                .to_string(),
        }
    }

    fn token(&self, caller: Caller) -> &str {
        match caller {
            Caller::Owner => self.owner_token.as_str(),
            Caller::Person => self.person_token.as_str(),
            Caller::StrangerAgent => self.stranger_token.as_str(),
            Caller::Agent => self.agent_token.as_str(),
        }
    }

    /// `caller` sends `method` to `uri` with an optional JSON `body`: the
    /// status and the body.
    async fn send(
        &self,
        caller: Caller,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let builder = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", self.token(caller)))
            .header("x-oneiron-binding", self.binding(caller));
        let request = match body {
            Some(body) => builder
                .header("content-type", "application/json")
                .body(Body::from(body.to_string())),
            None => builder.body(Body::empty()),
        }
        .expect("request");
        let response = self.app.clone().oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .expect("response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// `caller` posts `verb` with `input` to its facade door.
    async fn post(&self, caller: Caller, verb: &str, input: Value) -> (StatusCode, Value) {
        self.send(
            caller,
            Method::POST,
            &format!("/v1/core/facade/{verb}"),
            Some(input),
        )
        .await
    }

    /// `caller` posts `verb` and expects a 200: the answer.
    async fn ok(&self, caller: Caller, verb: &str, input: Value) -> Value {
        let (status, body) = self.post(caller, verb, input).await;
        assert_eq!(status, StatusCode::OK, "{caller:?} at {verb}: {body}");
        body
    }

    /// `caller` reads the rollup of `owner` in this metering scope: the
    /// status and the body.
    async fn rollup(&self, caller: Caller, owner: &str) -> (StatusCode, Value) {
        self.send(
            caller,
            Method::GET,
            &format!("/v1/usage/owners/{}/vaults/{}/rollup", owner, self.vault_id),
            None,
        )
        .await
    }
}

/// The list names the one planted row by its hash and length, says why it
/// does not decode, leaves the decodable row out, and carries none of the
/// row's bytes. (List what does not decode, none of the bytes.)
#[test]
fn owner_lists_one_planted_row_by_hash_and_length() {
    run_on_engine_stack("usage-list", || async {
        let served = served();
        let owner = served.owner.to_hex();
        let bytes = b"\xc1doors-custody-not-an-event";
        plant(&served, &owner, "door-1", bytes);
        record(&served, event(&owner, &served.vault_id, "door-1-ok", 7, 3));

        let listed = served.ok(Caller::Owner, UNDECODABLE, json!({})).await;
        let events = listed["events"].as_array().expect("an events list");
        assert_eq!(events.len(), 1, "{listed}");
        assert_eq!(
            events[0]["byteLength"].as_u64().expect("byte length"),
            bytes.len() as u64,
            "{:?}",
            events[0]
        );
        assert_eq!(events[0]["hash"], blake3_hex(bytes), "{:?}", events[0]);
        assert_eq!(
            events[0]["decodeReason"], "stored_event_decode_failed",
            "{:?}",
            events[0]
        );
        assert!(
            events[0]["rowRef"]
                .as_str()
                .is_some_and(|row| !row.is_empty()),
            "{:?}",
            events[0]
        );
        assert_eq!(
            events[0].as_object().expect("a row").len(),
            4,
            "the row carries none of its bytes: {:?}",
            events[0]
        );
    });
}

/// A removal deletes exactly the reviewed row and keeps one receipt: the
/// receipt names the scope, the row and its hash, the owner authority and
/// the call, the list reads empty after, and the receipts read shows
/// exactly it. (Removal by hash keeps a receipt.)
#[test]
fn remove_deletes_the_row_and_keeps_one_receipt() {
    run_on_engine_stack("usage-remove", || async {
        let served = served();
        let owner = served.owner.to_hex();
        let bytes = b"\xc1doors-custody-remove-me";
        plant(&served, &owner, "door-2", bytes);

        let listed = served.ok(Caller::Owner, UNDECODABLE, json!({})).await;
        assert_eq!(
            listed["events"].as_array().expect("events").len(),
            1,
            "{listed}"
        );
        let row_ref = listed["events"][0]["rowRef"]
            .as_str()
            .expect("row ref")
            .to_owned();
        let hash = listed["events"][0]["hash"]
            .as_str()
            .expect("hash")
            .to_owned();

        let removed = served
            .ok(
                Caller::Owner,
                REMOVE,
                json!({"rowRef": row_ref.clone(), "expectedHash": hash.clone()}),
            )
            .await;
        assert_eq!(removed["owner"], owner, "{removed}");
        assert_eq!(removed["vaultId"], served.vault_id, "{removed}");
        assert_eq!(removed["rowRef"], row_ref, "{removed}");
        assert_eq!(removed["hash"], hash, "{removed}");
        assert_eq!(
            removed["byteLength"].as_u64().expect("byte length"),
            bytes.len() as u64,
            "{removed}"
        );
        assert_eq!(removed["reason"], "undecodable_event_removed", "{removed}");
        assert_eq!(removed["authority"]["kind"], "owner", "{removed}");
        assert!(removed["authority"]["ref"].is_string(), "{removed}");
        assert_eq!(removed["actorRef"], owner, "{removed}");
        assert_eq!(removed["actorClass"], "human", "{removed}");
        assert_eq!(
            removed["surface"],
            json!({"kind": "this_install"}),
            "{removed}"
        );
        assert!(removed["recordedAt"].is_u64(), "{removed}");
        assert_eq!(
            removed["receiptId"].as_str().expect("receipt id").len(),
            32,
            "{removed}"
        );

        let listed = served.ok(Caller::Owner, UNDECODABLE, json!({})).await;
        assert_eq!(
            listed["events"].as_array().expect("events").len(),
            0,
            "{listed}"
        );
        let receipts = served.ok(Caller::Owner, RECEIPTS, json!({})).await;
        assert_eq!(
            receipts["receipts"].as_array().expect("receipts").len(),
            1,
            "{receipts}"
        );
        assert_eq!(receipts["undecodable"], 0, "{receipts}");
        assert_eq!(receipts["receipts"][0], removed, "{receipts}");
    });
}

/// A removal refuses a row whose bytes changed since the review, a row that
/// is gone, and a row that decodes now, each with its typed reason, and
/// keeps no receipt for any of them. (The reviewed-bytes rule.)
#[test]
fn remove_refuses_a_changed_row_a_gone_row_and_a_decodable_row() {
    run_on_engine_stack("usage-remove-refusals", || async {
        let served = served();
        let owner = served.owner.to_hex();
        let key = plant(&served, &owner, "door-3-a", b"\xc1doors-custody-row-a");
        let listed = served.ok(Caller::Owner, UNDECODABLE, json!({})).await;
        assert_eq!(
            listed["events"].as_array().expect("events").len(),
            1,
            "{listed}"
        );
        let row_ref = listed["events"][0]["rowRef"]
            .as_str()
            .expect("row ref")
            .to_owned();
        let hash = listed["events"][0]["hash"]
            .as_str()
            .expect("hash")
            .to_owned();

        served
            .vault
            .sync_state_put(&key, b"\xc1doors-custody-row-a-changed")
            .expect("overwrite the row");
        let (status, body) = served
            .post(
                Caller::Owner,
                REMOVE,
                json!({"rowRef": row_ref.clone(), "expectedHash": hash.clone()}),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "a changed row: {body}");
        assert_eq!(error_code(&body), Some("INVALID_STATE"), "{body}");
        assert_eq!(
            body["error"]["reasonCodes"],
            json!(["usage_event_changed"]),
            "{body}"
        );

        served
            .vault
            .sync_state_delete(&key)
            .expect("delete the row directly");
        let (status, body) = served
            .post(
                Caller::Owner,
                REMOVE,
                json!({"rowRef": row_ref.clone(), "expectedHash": hash.clone()}),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "a gone row: {body}");
        assert_eq!(error_code(&body), Some("NOT_FOUND"), "{body}");

        record(&served, event(&owner, &served.vault_id, "door-3-b", 7, 3));
        let stored = served
            .vault
            .sync_state_get(&event_key(&owner, &served.vault_id, "door-3-b"))
            .expect("read the stored event")
            .expect("a stored event");
        let forged = json!({
            "rowRef": row_ref_for(&key_part(&owner), &key_part("door-3-b")),
            "expectedHash": blake3_hex(&stored),
        });
        let (status, body) = served.post(Caller::Owner, REMOVE, forged).await;
        assert_eq!(status, StatusCode::CONFLICT, "a decodable row: {body}");
        assert_eq!(error_code(&body), Some("INVALID_STATE"), "{body}");
        assert_eq!(
            body["error"]["reasonCodes"],
            json!(["usage_event_decodable"]),
            "{body}"
        );

        let receipts = served.ok(Caller::Owner, RECEIPTS, json!({})).await;
        assert_eq!(
            receipts["receipts"].as_array().expect("receipts").len(),
            0,
            "{receipts}"
        );
        assert_eq!(receipts["undecodable"], 0, "{receipts}");
    });
}

/// The receipts read every kept receipt of this metering scope, skips
/// another vault's receipt without counting it, and counts the kept row
/// that no longer decodes instead of reading it. (None capped or dropped;
/// undecodable counted.)
#[test]
fn receipts_lists_only_this_scopes_receipts_and_counts_undecodable() {
    run_on_engine_stack("usage-receipts", || async {
        let served = served();
        let owner = served.owner.to_hex();
        plant(&served, &owner, "door-4-a", b"\xc1doors-custody-row-a");
        plant(&served, &owner, "door-4-b", b"\xc1doors-custody-row-b");
        let listed = served.ok(Caller::Owner, UNDECODABLE, json!({})).await;
        assert_eq!(
            listed["events"].as_array().expect("events").len(),
            2,
            "{listed}"
        );
        let mut kept = Vec::new();
        for row in listed["events"].as_array().expect("events") {
            let removed = served
                .ok(
                    Caller::Owner,
                    REMOVE,
                    json!({
                        "rowRef": row["rowRef"].clone(),
                        "expectedHash": row["hash"].clone(),
                    }),
                )
                .await;
            kept.push(
                removed["receiptId"]
                    .as_str()
                    .expect("receipt id")
                    .to_owned(),
            );
        }

        let elsewhere = UsageRepairReceipt {
            receipt_id: "0123456789abcdef0123456789abcdef".to_owned(),
            owner: owner.clone(),
            vault_id: "another-vault".to_owned(),
            row_ref: "e30".to_owned(),
            hash: "0".repeat(64),
            byte_length: 1,
            reason: UsageRepairReason::UndecodableEventRemoved,
            actor_ref: owner.clone(),
            actor_class: "human".to_owned(),
            authority: UsageRepairAuthority::Owner("f".repeat(64)),
            surface: UsageRepairSurface::ThisInstall,
            recorded_at: 1,
        };
        served
            .vault
            .sync_state_put(
                "usage:repair:receipt:0123456789abcdef0123456789abcdef",
                &rmp_serde::to_vec_named(&elsewhere).expect("encode a receipt"),
            )
            .expect("plant another vault's receipt");

        served
            .vault
            .sync_state_put(
                &format!("usage:repair:receipt:{}", kept[0]),
                b"\xc1doors-custody-not-a-receipt",
            )
            .expect("corrupt one kept receipt");

        let receipts = served.ok(Caller::Owner, RECEIPTS, json!({})).await;
        let rows = receipts["receipts"].as_array().expect("receipts");
        assert_eq!(rows.len(), 1, "{receipts}");
        assert_eq!(receipts["undecodable"], 1, "{receipts}");
        assert_eq!(rows[0]["receiptId"], kept[1], "{receipts}");
    });
}

/// An agent whose Grant names the removal removes under the grant's
/// authority, while the same agent is refused the list and the receipts, a
/// grantless agent and a second person are refused at all three doors, the
/// other rows stay listed, and the receipts hold the one removal.
/// (The Grant names the verb; each verb is its own right.)
#[test]
fn agent_with_verb_grant_removes_person_and_grantless_agent_cannot() {
    run_on_engine_stack("usage-grant", || async {
        let served = served();
        let owner = served.owner.to_hex();
        plant(&served, &owner, "door-5-a", b"\xc1doors-custody-row-a");
        plant(&served, &owner, "door-5-b", b"\xc1doors-custody-row-b");
        plant(&served, &owner, "door-5-c", b"\xc1doors-custody-row-c");
        let grant = grant_verbs(
            &served,
            served.agent,
            "usage-doors-agent",
            &["read", REMOVE],
        );

        let listed = served.ok(Caller::Owner, UNDECODABLE, json!({})).await;
        assert_eq!(
            listed["events"].as_array().expect("events").len(),
            3,
            "{listed}"
        );
        let removed = served
            .ok(
                Caller::Agent,
                REMOVE,
                json!({
                    "rowRef": listed["events"][0]["rowRef"].clone(),
                    "expectedHash": listed["events"][0]["hash"].clone(),
                }),
            )
            .await;
        assert_eq!(
            removed["authority"],
            json!({"kind": "grant", "ref": grant.to_hex()}),
            "{removed}"
        );
        assert_eq!(removed["actorRef"], served.agent.to_hex(), "{removed}");
        assert_eq!(removed["actorClass"], "agent", "{removed}");

        let (status, body) = served.post(Caller::Agent, UNDECODABLE, json!({})).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "the agent lists: {body}");
        assert_eq!(error_code(&body), Some("FORBIDDEN"), "{body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .expect("a refusal message")
                .starts_with("vault.usage.events.undecodable takes the vault owner's own proof"),
            "{body}"
        );
        let (status, body) = served.post(Caller::Agent, RECEIPTS, json!({})).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "the agent reads receipts: {body}"
        );
        assert_eq!(error_code(&body), Some("FORBIDDEN"), "{body}");

        let stranger_remove = json!({
            "rowRef": listed["events"][1]["rowRef"].clone(),
            "expectedHash": listed["events"][1]["hash"].clone(),
        });
        for caller in [Caller::Person, Caller::StrangerAgent] {
            for (verb, input) in [
                (UNDECODABLE, json!({})),
                (REMOVE, stranger_remove.clone()),
                (RECEIPTS, json!({})),
            ] {
                let (status, body) = served.post(caller, verb, input).await;
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "{caller:?} at {verb}: {body}"
                );
                assert_eq!(error_code(&body), Some("FORBIDDEN"), "{body}");
            }
        }

        let listed = served.ok(Caller::Owner, UNDECODABLE, json!({})).await;
        assert_eq!(
            listed["events"].as_array().expect("events").len(),
            2,
            "{listed}"
        );
        let receipts = served.ok(Caller::Owner, RECEIPTS, json!({})).await;
        assert_eq!(
            receipts["receipts"].as_array().expect("receipts").len(),
            1,
            "{receipts}"
        );
        assert_eq!(
            receipts["receipts"][0]["authority"],
            json!({"kind": "grant", "ref": grant.to_hex()}),
            "{receipts}"
        );
    });
}

/// The rollup sums the recorded calls; a stored row that does not decode
/// fails the read instead of joining the sum; removing it restores the
/// read with the same counters. (Undecodable is never counted.)
#[test]
fn rollup_ignores_the_row_and_remove_restores_the_read() {
    run_on_engine_stack("usage-rollup", || async {
        let served = served();
        let owner = served.owner.to_hex();
        record(
            &served,
            event("room-payer", &served.vault_id, "door-6-p", 1, 1),
        );
        let (status, body) = served.rollup(Caller::Owner, "room-payer").await;
        assert_eq!(status, StatusCode::OK, "the payer's rollup: {body}");
        assert_eq!(body["counters"]["eventCount"], 1, "{body}");

        plant(&served, &owner, "door-6-a", b"\xc1doors-custody-row-a");
        record(&served, event(&owner, &served.vault_id, "door-6-ok", 7, 3));
        let (status, body) = served.rollup(Caller::Owner, &owner).await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "the failed read: {body}"
        );
        // `/v1/usage/*` answers the flat `ApiError` body, not the facade's
        // `{"error": ...}` envelope.
        assert_eq!(body["code"], "INTERNAL_SERVER_ERROR", "{body}");

        let listed = served.ok(Caller::Owner, UNDECODABLE, json!({})).await;
        let removed = served
            .ok(
                Caller::Owner,
                REMOVE,
                json!({
                    "rowRef": listed["events"][0]["rowRef"].clone(),
                    "expectedHash": listed["events"][0]["hash"].clone(),
                }),
            )
            .await;
        assert_eq!(removed["reason"], "undecodable_event_removed", "{removed}");

        let (status, body) = served.rollup(Caller::Owner, &owner).await;
        assert_eq!(status, StatusCode::OK, "the restored read: {body}");
        assert_eq!(body["owner"], owner, "{body}");
        assert_eq!(body["vaultId"], served.vault_id, "{body}");
        assert_eq!(body["status"], "current", "{body}");
        assert_eq!(body["counters"]["eventCount"], 1, "{body}");
        assert_eq!(body["counters"]["inputTokens"], 7, "{body}");
        assert_eq!(body["counters"]["outputTokens"], 3, "{body}");
        assert_eq!(body["counters"]["amountsByCurrency"], json!({}), "{body}");
    });
}

/// A server that meters nothing answers all three verbs unbound, and lists,
/// removes and receipts nothing. (The scope is this server's metering
/// vault.)
#[test]
fn unmetered_server_answers_unbound_on_all_three_verbs() {
    run_on_engine_stack("usage-unbound", || async {
        let served = served_unmetered();
        for (verb, input) in [
            (UNDECODABLE, json!({})),
            (
                REMOVE,
                json!({"rowRef": "e30", "expectedHash": "0".repeat(64)}),
            ),
            (RECEIPTS, json!({})),
        ] {
            let (status, body) = served.post(Caller::Owner, verb, input).await;
            assert_eq!(status, StatusCode::CONFLICT, "the owner at {verb}: {body}");
            assert_eq!(error_code(&body), Some("INVALID_STATE"), "{body}");
            assert_eq!(
                body["error"]["message"],
                "usage_metering_unbound: this server meters no usage, so it holds no usage event to repair",
                "{body}"
            );
        }
    });
}
