//! Public-door promise tests for the `vault.shared` family (ARCH-0043 =
//! A: each test proves a promise at the door).
//!
//! Every case drives the real routes in process (`build_app` + `oneshot`):
//! `POST /v1/core/facade/<verb>` for `vault.shared.propose_delete`,
//! `.propose_add_owner`, `.propose_remove_owner`, `.propose_transfer`,
//! `.object`, `.withdraw_objection`, `.started`, `.matured`, `.outcomes`,
//! `.receipt`, `.execute`, `.deletion` and `.owner_change_wait.set`/`.get`,
//! and `POST /v1/operator/shared/recover-owner` for owner recovery.
//! Callers: the vault's embedded owner on the host root credential; a second
//! Owner and a Member on their own minted human credentials; and an agent on
//! its own minted agent credential. Each case owns its vault on a manual
//! store clock, so veto windows mature deterministically with no sleeps.
//!
//! The promises, with their canon (oneiron-docs `generated/oneiron/sync/
//! oneiron-arch-0043-federation-membership-v1.md`):
//! - every Owner hears an act at once, and a live objection holds it past
//!   its window (the veto window);
//! - silence means go: an unopposed act matures by time and executes
//!   (the maturity pass);
//! - a deleted vault serves only its marker and its notices;
//! - owner changes are instant until a common wait is set;
//! - the last Owner cannot be removed, and recovery only fires when no
//!   Owner stands (handover keeps one live Owner);
//! - a Member reaches no act door and writes nothing (the `person()` door
//!   plus the engine's role checks);
//! - an agent is refused at the person doors but reads the deletion marker
//!   like anyone (`vault.shared.deletion` takes no proof);
//! - an export-first removal delivers its archive to the removed Owner
//!   alone, again on a re-run.
//!
//! These promises hold on main. Their red proof is a seeded fault (Test rules
//! v2, rule 5), named in `seed_shared_faults.py`.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! vault_shared_doors`. The test calls no test door; it needs
//! `oneiron/test-support` for `MemoryKeystore`.
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
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const SHARED: u64 = 43;
const VAULT_ID: &str = "43";
/// The manual clock's fixed start: every deadline is exact on it.
const T0: u64 = 1_800_000_000;
/// `delete_vault.wait_secs` on the shipped shared row: seven days.
const DELETE_WAIT_SECS: u64 = 604800;
/// Ninety days, the deleted-vault backup retention and the removal-export
/// term (`DELETED_VAULT_BACKUP_RETENTION_SECS`, `REMOVAL_EXPORT_RETAIN_SECS`).
const NINETY_DAYS: u64 = 90 * 24 * 60 * 60;

const PROPOSE_DELETE: &str = "vault.shared.propose_delete";
const PROPOSE_ADD_OWNER: &str = "vault.shared.propose_add_owner";
const PROPOSE_REMOVE_OWNER: &str = "vault.shared.propose_remove_owner";
const PROPOSE_TRANSFER: &str = "vault.shared.propose_transfer";
const OBJECT: &str = "vault.shared.object";
const WITHDRAW_OBJECTION: &str = "vault.shared.withdraw_objection";
const STARTED: &str = "vault.shared.started";
const MATURED: &str = "vault.shared.matured";
const OUTCOMES: &str = "vault.shared.outcomes";
const RECEIPT: &str = "vault.shared.receipt";
const EXECUTE: &str = "vault.shared.execute";
const DELETION: &str = "vault.shared.deletion";
const WAIT_SET: &str = "vault.shared.owner_change_wait.set";
const WAIT_GET: &str = "vault.shared.owner_change_wait.get";
const RECOVER_OWNER: &str = "/v1/operator/shared/recover-owner";

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

/// A served shared vault on a manual clock: its embedded owner A, a second
/// Owner B, a Member M, two plain live persons C and D, and an agent, each
/// caller on their own credential. B and M accepted their founding
/// invitations; every invitation, act and notice runs on the manual clock.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    clock: Arc<ManualClock>,
    owner_slip: CapabilitySlip,
    owner_token: String,
    a: EntityId,
    b: EntityId,
    m: EntityId,
    c: EntityId,
    d: EntityId,
    b_slip: CapabilitySlip,
    b_token: String,
    m_slip: CapabilitySlip,
    m_token: String,
    agent_slip: CapabilitySlip,
    agent_token: String,
}

/// Who sends a request.
#[derive(Clone, Copy, Debug)]
enum Caller {
    /// The embedded owner on the host root credential.
    Owner,
    /// The second Owner on their own human credential.
    SecondOwner,
    /// The Member on their own human credential.
    Member,
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

/// A self-hosted served vault on the manual clock, shared by A with B as a
/// second Owner and M as a Member.
fn served() -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-shared-doors".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    let a = vault.ensure_embedded_owner_actor().expect("owner A");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    let owner_proof = proof(&vault, a);
    let b = EntityId::now();
    let m = EntityId::now();
    let c = EntityId::now();
    let d = EntityId::now();
    for id in [b, m, c, d] {
        person(&vault, id);
    }
    let agent = vault
        .ensure_agent_principal("shared-doors-agent")
        .expect("agent principal");
    let founding = |member_ref, role| InitialSharedMember {
        member_ref,
        role: Some(role),
    };
    vault
        .initialize_shared_vault(
            &owner_proof,
            SHARED,
            None,
            &[
                founding(a, Role::Owner),
                founding(b, Role::Owner),
                founding(m, Role::Member),
            ],
            1,
        )
        .expect("a shared vault with a second Owner and a Member");
    for (id, role) in [(b, Role::Owner), (m, Role::Member)] {
        let own = proof(&vault, id);
        let invitation = vault
            .shared_invitations(&own, SHARED)
            .expect("invitations")
            .into_iter()
            .find(|open| open.role == role)
            .expect("the founding invitation");
        vault
            .accept_shared_invitation(&own, SHARED, &invitation.id)
            .expect("the person accepts");
    }
    let app = build_app(server);
    let (b_slip, b_token) = credential(&vault, &issuer, b, Some("human"));
    let (m_slip, m_token) = credential(&vault, &issuer, m, Some("human"));
    let (agent_slip, agent_token) = credential(&vault, &issuer, agent, Some("agent"));
    Served {
        _dir: dir,
        vault,
        app,
        issuer,
        clock,
        owner_slip,
        owner_token,
        a,
        b,
        m,
        c,
        d,
        b_slip,
        b_token,
        m_slip,
        m_token,
        agent_slip,
        agent_token,
    }
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

impl Served {
    fn slip(&self, caller: Caller) -> Option<&CapabilitySlip> {
        match caller {
            Caller::Owner => None,
            Caller::SecondOwner => Some(&self.b_slip),
            Caller::Member => Some(&self.m_slip),
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
            Caller::SecondOwner => self.b_token.as_str(),
            Caller::Member => self.m_token.as_str(),
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

    /// The act `id` A proposed to delete the vault: started, waiting its
    /// seven-day window.
    async fn proposed_delete(&self) -> Value {
        let act = self
            .ok(Caller::Owner, PROPOSE_DELETE, json!({"vault_id": VAULT_ID}))
            .await;
        assert_eq!(act["act"], "delete_vault", "{act}");
        assert_eq!(act["completed"], false, "{act}");
        assert_eq!(act["starter"], self.a.to_hex(), "{act}");
        assert_eq!(act["objector_roles"], json!(["owner"]), "{act}");
        assert_eq!(act["required_verb"], "admin", "{act}");
        assert_eq!(act["starter_may_object"], true, "{act}");
        assert_eq!(act["objections"], json!([]), "{act}");
        let started_at = act["started_at"].as_u64().expect("started_at");
        let deadline = act["deadline"].as_u64().expect("deadline");
        assert_eq!(deadline - started_at, DELETE_WAIT_SECS, "{act}");
        act
    }

    fn act_id(act: &Value) -> String {
        act["id"].as_str().expect("act id").to_owned()
    }

    fn deadline(act: &Value) -> u64 {
        act["deadline"].as_u64().expect("deadline")
    }
}

/// Owner B hears A's delete at once, and B's objection holds it past its
/// window: no maturity notice is written and executing is refused. (The veto
/// window: every Owner is told at the start, and a live objection blocks
/// maturity.)
#[test]
fn owner_b_sees_a_delete_at_once_and_an_objection_holds_it() {
    run_on_engine_stack("shared-delete-objected", || async {
        let served = served();
        let act = served.proposed_delete().await;
        let id = Served::act_id(&act);
        let deadline = Served::deadline(&act);

        let started = served
            .ok(Caller::SecondOwner, STARTED, json!({"vault_id": VAULT_ID}))
            .await;
        let started = started.as_array().expect("a started list");
        assert_eq!(started.len(), 1, "{started:?}");
        assert_eq!(started[0]["act_id"], id, "{:?}", started[0]);
        assert_eq!(started[0]["vault_id"], VAULT_ID, "{:?}", started[0]);
        assert_eq!(started[0]["act"], "delete_vault", "{:?}", started[0]);
        assert_eq!(
            started[0]["recipient"],
            served.b.to_hex(),
            "{:?}",
            started[0]
        );
        assert_eq!(
            started[0]["deadline"].as_u64().expect("deadline"),
            deadline,
            "{:?}",
            started[0]
        );

        let objected = served
            .ok(Caller::SecondOwner, OBJECT, json!({"act_id": id.clone()}))
            .await;
        assert_eq!(
            objected["objections"],
            json!([served.b.to_hex()]),
            "{objected}"
        );
        assert_eq!(objected["completed"], false, "{objected}");

        served.clock.set(deadline + 5);
        let written = served
            .vault
            .notify_matured_shared_acts()
            .expect("maturity pass");
        assert_eq!(written, 0, "the objection holds the act past its window");
        let matured = served
            .ok(Caller::SecondOwner, MATURED, json!({"vault_id": VAULT_ID}))
            .await;
        assert_eq!(
            matured.as_array().expect("a matured list").len(),
            0,
            "{matured}"
        );

        let (status, body) = served
            .post(Caller::SecondOwner, EXECUTE, json!({"act_id": id}))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "executing a held act: {body}");
        assert_eq!(error_code(&body), Some("INVALID_STATE"), "{body}");
    });
}

/// Silence means go: with no objection the delete matures by time and B
/// executes it; the marker and B's outcome notice read back. (The maturity
/// pass: the window passes on the store clock, the act completes, the
/// receipt lands.)
#[test]
fn silence_means_go_delete_matures_and_executes() {
    run_on_engine_stack("shared-delete-matures", || async {
        let served = served();
        let act = served.proposed_delete().await;
        let id = Served::act_id(&act);
        let deadline = Served::deadline(&act);

        let member_started = served
            .ok(Caller::Member, STARTED, json!({"vault_id": VAULT_ID}))
            .await;
        assert_eq!(
            member_started.as_array().expect("a started list").len(),
            0,
            "the Member is told nothing: {member_started}"
        );

        let (status, body) = served
            .post(Caller::SecondOwner, EXECUTE, json!({"act_id": id.clone()}))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "executing early: {body}");
        assert_eq!(error_code(&body), Some("INVALID_STATE"), "{body}");

        served.clock.set(deadline + 5);
        let written = served
            .vault
            .notify_matured_shared_acts()
            .expect("maturity pass");
        assert_eq!(written, 2, "both Owners are told it matured");
        let matured = served
            .ok(Caller::SecondOwner, MATURED, json!({"vault_id": VAULT_ID}))
            .await;
        let matured = matured.as_array().expect("a matured list");
        assert_eq!(matured.len(), 1, "{matured:?}");
        assert_eq!(matured[0]["act_id"], id, "{:?}", matured[0]);
        assert_eq!(
            matured[0]["recipient"],
            served.b.to_hex(),
            "{:?}",
            matured[0]
        );
        assert_eq!(
            matured[0]["noticed_at"].as_u64().expect("noticed_at"),
            deadline + 5,
            "{:?}",
            matured[0]
        );

        let executed = served
            .ok(Caller::SecondOwner, EXECUTE, json!({"act_id": id.clone()}))
            .await;
        let receipt = &executed["receipt"];
        assert_eq!(receipt["act_id"], id, "{executed}");
        assert_eq!(receipt["vault_id"], VAULT_ID, "{executed}");
        assert_eq!(
            receipt["change"]["vault_deleted"]["backup_retain_until"]
                .as_u64()
                .expect("backup_retain_until"),
            deadline + 5 + NINETY_DAYS,
            "{executed}"
        );
        assert!(
            executed.get("delivery").is_none() || executed["delivery"].is_null(),
            "{executed}"
        );

        let deletion = served.ok(Caller::SecondOwner, DELETION, json!({})).await;
        assert_eq!(deletion["vault_id"], VAULT_ID, "{deletion}");
        assert_eq!(deletion["act_id"], id, "{deletion}");
        assert_eq!(deletion["receipt_id"], receipt["id"], "{deletion}");
        assert_eq!(
            deletion["deleted_at"].as_u64().expect("deleted_at"),
            deadline + 5,
            "{deletion}"
        );
        assert_eq!(
            deletion["backup_retain_until"]
                .as_u64()
                .expect("backup_retain_until"),
            deadline + 5 + NINETY_DAYS,
            "{deletion}"
        );

        let outcomes = served
            .ok(Caller::SecondOwner, OUTCOMES, json!({"vault_id": VAULT_ID}))
            .await;
        let outcomes = outcomes.as_array().expect("an outcomes list");
        let deleted: Vec<&Value> = outcomes
            .iter()
            .filter(|outcome| outcome["act_id"] == id)
            .collect();
        assert_eq!(deleted.len(), 1, "the delete outcome: {outcomes:?}");
        assert_eq!(
            deleted[0]["recipient"],
            served.b.to_hex(),
            "{:?}",
            deleted[0]
        );
        assert!(
            deleted[0]["change"]["vault_deleted"].is_object(),
            "{:?}",
            deleted[0]
        );
    });
}

/// A deleted vault serves only its marker and its notices: any new act is
/// not found, while the deletion, the outcomes and the receipt still read.
/// (Deletion closes the vault's doors but keeps its record.)
#[test]
fn a_deleted_vault_serves_only_its_marker_and_notices() {
    run_on_engine_stack("shared-deleted-serves-marker", || async {
        let served = served();
        let act = served.proposed_delete().await;
        let id = Served::act_id(&act);
        served.clock.set(Served::deadline(&act) + 5);
        served
            .vault
            .notify_matured_shared_acts()
            .expect("maturity pass");
        let executed = served
            .ok(Caller::SecondOwner, EXECUTE, json!({"act_id": id.clone()}))
            .await;
        let receipt_id = executed["receipt"]["id"]
            .as_str()
            .expect("receipt id")
            .to_owned();

        let (status, body) = served
            .post(Caller::Owner, PROPOSE_DELETE, json!({"vault_id": VAULT_ID}))
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "proposing after delete: {body}"
        );
        assert_eq!(error_code(&body), Some("NOT_FOUND"), "{body}");

        let (status, body) = served
            .post(Caller::SecondOwner, STARTED, json!({"vault_id": VAULT_ID}))
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "started after delete: {body}"
        );
        assert_eq!(error_code(&body), Some("NOT_FOUND"), "{body}");

        let deletion = served.ok(Caller::SecondOwner, DELETION, json!({})).await;
        assert_eq!(deletion["act_id"], id, "{deletion}");

        let outcomes = served
            .ok(Caller::SecondOwner, OUTCOMES, json!({"vault_id": VAULT_ID}))
            .await;
        let outcomes = outcomes.as_array().expect("an outcomes list");
        let deleted: Vec<&Value> = outcomes
            .iter()
            .filter(|outcome| outcome["act_id"] == id)
            .collect();
        assert_eq!(deleted.len(), 1, "the delete outcome: {outcomes:?}");

        let receipt = served
            .ok(
                Caller::SecondOwner,
                RECEIPT,
                json!({"receipt_id": receipt_id.clone()}),
            )
            .await;
        assert_eq!(receipt["id"], receipt_id, "{receipt}");
        assert!(receipt["change"]["vault_deleted"].is_object(), "{receipt}");
    });
}

/// Owner changes are instant until a wait is set: adding an Owner lands at
/// once, then with a seven-day common wait a transfer waits, nobody can
/// object to it, and executing early is refused. (The common owner-change
/// wait overrides only the wait.)
#[test]
fn owner_changes_are_instant_until_a_wait_is_set() {
    run_on_engine_stack("shared-owner-change-wait", || async {
        let served = served();
        let added = served
            .ok(
                Caller::Owner,
                PROPOSE_ADD_OWNER,
                json!({"vault_id": VAULT_ID, "owner": served.c.to_hex()}),
            )
            .await;
        assert_eq!(added["act"], "add_owner", "{added}");
        assert_eq!(added["completed"], true, "{added}");
        let executed = served
            .ok(
                Caller::Owner,
                EXECUTE,
                json!({"act_id": Served::act_id(&added)}),
            )
            .await;
        assert_eq!(
            executed["receipt"]["change"]["owner_added"]["owner"],
            served.c.to_hex(),
            "{executed}"
        );

        let (status, body) = served
            .post(
                Caller::Owner,
                WAIT_SET,
                json!({"vault_id": VAULT_ID, "days": 7}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "setting the wait: {body}");
        assert_eq!(body.as_u64().expect("wait seconds"), 7 * 86400, "{body}");
        let wait = served.ok(Caller::Owner, WAIT_GET, json!({})).await;
        assert_eq!(wait.as_u64().expect("wait seconds"), 7 * 86400, "{wait}");

        let transfer = served
            .ok(
                Caller::Owner,
                PROPOSE_TRANSFER,
                json!({
                    "vault_id": VAULT_ID,
                    "to": served.d.to_hex(),
                    "from_keeps": "member",
                }),
            )
            .await;
        assert_eq!(transfer["act"], "transfer_ownership", "{transfer}");
        assert_eq!(transfer["completed"], false, "{transfer}");
        assert_eq!(transfer["objector_roles"], json!([]), "{transfer}");
        let started_at = transfer["started_at"].as_u64().expect("started_at");
        let deadline = transfer["deadline"].as_u64().expect("deadline");
        assert_eq!(deadline - started_at, 7 * 86400, "{transfer}");

        let (status, body) = served
            .post(
                Caller::SecondOwner,
                OBJECT,
                json!({"act_id": Served::act_id(&transfer)}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "nobody can object to a waiting owner change: {body}"
        );
        assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{body}");

        let (status, body) = served
            .post(
                Caller::Owner,
                EXECUTE,
                json!({"act_id": Served::act_id(&transfer)}),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "executing early: {body}");
        assert_eq!(error_code(&body), Some("INVALID_STATE"), "{body}");
    });
}

/// The last Owner cannot be removed, and recovery is refused while an Owner
/// stands: removing B lands and revokes B's slips, removing last-standing A
/// is refused at propose, and the recovery door refuses a caller that is not
/// owner-grade, a blank proof note, and a recovery with an Owner still
/// standing.
/// (Handover keeps one live Owner; recovery only fires when none stands.)
#[test]
fn the_last_owner_cannot_be_removed_and_recovery_is_refused_while_an_owner_stands() {
    run_on_engine_stack("shared-last-owner", || async {
        let served = served();
        let removed = served
            .ok(
                Caller::Owner,
                PROPOSE_REMOVE_OWNER,
                json!({
                    "vault_id": VAULT_ID,
                    "target": served.b.to_hex(),
                    "export_first": false,
                }),
            )
            .await;
        assert_eq!(removed["act"], "remove_owner", "{removed}");
        assert_eq!(removed["completed"], true, "{removed}");
        let executed = served
            .ok(
                Caller::Owner,
                EXECUTE,
                json!({"act_id": Served::act_id(&removed)}),
            )
            .await;
        assert_eq!(
            executed["receipt"]["change"]["owner_removed"]["target"],
            served.b.to_hex(),
            "{executed}"
        );
        let b_slip_hex = hex(&served.b_slip.claims.slip_id);
        let revoked = executed["receipt"]["revoked_slips"]
            .as_array()
            .expect("revoked slips");
        assert!(
            revoked
                .iter()
                .any(|slip| slip.as_str() == Some(b_slip_hex.as_str())),
            "B's slips are revoked: {executed}"
        );

        let (status, body) = served
            .post(
                Caller::Owner,
                PROPOSE_REMOVE_OWNER,
                json!({
                    "vault_id": VAULT_ID,
                    "target": served.a.to_hex(),
                    "export_first": false,
                }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "removing the last Owner: {body}"
        );
        assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{body}");

        let recovery = json!({
            "vault_id": SHARED,
            "from": served.a.to_hex(),
            "claimant": served.m.to_hex(),
            "proof_note": "the operator judged proof of control in person",
        });
        // A Member's own credential is not owner-grade, so the operator's
        // door (`require_owner_auth`) refuses it before any vault read.
        let (status, body) = served
            .send(
                Caller::Member,
                Method::POST,
                RECOVER_OWNER,
                Some(recovery.clone()),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a Member recovers: {body}"
        );
        assert_eq!(error_code(&body), Some("UNAUTHORIZED"), "{body}");

        let (status, body) = served
            .send(
                Caller::Owner,
                Method::POST,
                RECOVER_OWNER,
                Some(json!({
                    "vault_id": SHARED,
                    "from": served.a.to_hex(),
                    "claimant": served.m.to_hex(),
                    "proof_note": "   ",
                })),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a blank proof note: {body}"
        );
        assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{body}");

        let (status, body) = served
            .send(Caller::Owner, Method::POST, RECOVER_OWNER, Some(recovery))
            .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "recovering while an Owner stands: {body}"
        );
        assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{body}");
    });
}

/// A Member reaches no act door and writes nothing: proposing, objecting,
/// withdrawing, executing and setting the wait are refused, the owner's
/// wait read is forbidden, the Member's own notices are empty, and A's
/// reads are unchanged. (The `person()` door plus the engine's role
/// checks: only Owners start, object, execute and set.)
#[test]
fn a_member_reaches_no_act_door_and_writes_nothing() {
    run_on_engine_stack("shared-member-refused", || async {
        let served = served();
        let act = served.proposed_delete().await;
        let id = Served::act_id(&act);
        let member_outcomes_before = served
            .ok(Caller::Member, OUTCOMES, json!({"vault_id": VAULT_ID}))
            .await;
        let owner_outcomes_before = served
            .ok(Caller::Owner, OUTCOMES, json!({"vault_id": VAULT_ID}))
            .await;

        for (verb, input) in [
            (PROPOSE_DELETE, json!({"vault_id": VAULT_ID})),
            (OBJECT, json!({"act_id": id.clone()})),
            (WITHDRAW_OBJECTION, json!({"act_id": id.clone()})),
            (EXECUTE, json!({"act_id": id.clone()})),
            (WAIT_SET, json!({"vault_id": VAULT_ID, "days": 7})),
        ] {
            let (status, body) = served.post(Caller::Member, verb, input).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "Member at {verb}: {body}");
            assert_eq!(
                error_code(&body),
                Some("BAD_REQUEST"),
                "Member at {verb}: {body}"
            );
        }

        let (status, body) = served.post(Caller::Member, WAIT_GET, json!({})).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "Member at {WAIT_GET}: {body}"
        );
        assert_eq!(
            error_code(&body),
            Some("FORBIDDEN"),
            "Member at {WAIT_GET}: {body}"
        );

        for verb in [STARTED, MATURED] {
            let notices = served
                .ok(Caller::Member, verb, json!({"vault_id": VAULT_ID}))
                .await;
            assert_eq!(
                notices.as_array().expect("a notices list").len(),
                0,
                "Member at {verb}: {notices}"
            );
        }
        let member_outcomes = served
            .ok(Caller::Member, OUTCOMES, json!({"vault_id": VAULT_ID}))
            .await;
        assert_eq!(
            member_outcomes, member_outcomes_before,
            "the Member wrote no outcome: {member_outcomes}"
        );

        let started = served
            .ok(Caller::Owner, STARTED, json!({"vault_id": VAULT_ID}))
            .await;
        let started = started.as_array().expect("a started list");
        assert_eq!(started.len(), 1, "no new act: {started:?}");
        assert_eq!(started[0]["act_id"], id, "{:?}", started[0]);
        let outcomes = served
            .ok(Caller::Owner, OUTCOMES, json!({"vault_id": VAULT_ID}))
            .await;
        assert_eq!(
            outcomes, owner_outcomes_before,
            "no new outcome: {outcomes}"
        );
        let deletion = served.ok(Caller::Owner, DELETION, json!({})).await;
        assert!(deletion.is_null(), "{deletion}");
        let wait = served.ok(Caller::Owner, WAIT_GET, json!({})).await;
        assert!(wait.is_null(), "{wait}");
    });
}

/// An agent is refused at the person doors but reads the deletion marker
/// like anyone: all twelve person doors plus the owner's wait read refuse
/// its credential, the deletion reads, and A's reads are unchanged.
/// (Only a live person's own act passes `person()`; the marker is for
/// anyone.)
#[test]
fn an_agent_is_refused_at_the_person_doors_but_reads_the_deletion_marker() {
    run_on_engine_stack("shared-agent-refused", || async {
        let served = served();
        let act = served.proposed_delete().await;
        let id = Served::act_id(&act);
        let owner_outcomes_before = served
            .ok(Caller::Owner, OUTCOMES, json!({"vault_id": VAULT_ID}))
            .await;

        for (verb, input) in [
            (PROPOSE_DELETE, json!({"vault_id": VAULT_ID})),
            (
                PROPOSE_ADD_OWNER,
                json!({"vault_id": VAULT_ID, "owner": served.c.to_hex()}),
            ),
            (
                PROPOSE_REMOVE_OWNER,
                json!({
                    "vault_id": VAULT_ID,
                    "target": served.b.to_hex(),
                    "export_first": false,
                }),
            ),
            (
                PROPOSE_TRANSFER,
                json!({"vault_id": VAULT_ID, "to": served.c.to_hex()}),
            ),
            (OBJECT, json!({"act_id": id.clone()})),
            (WITHDRAW_OBJECTION, json!({"act_id": id.clone()})),
            (STARTED, json!({"vault_id": VAULT_ID})),
            (MATURED, json!({"vault_id": VAULT_ID})),
            (OUTCOMES, json!({"vault_id": VAULT_ID})),
            (RECEIPT, json!({"receipt_id": id.clone()})),
            (EXECUTE, json!({"act_id": id.clone()})),
            (WAIT_SET, json!({"vault_id": VAULT_ID, "days": 7})),
            (WAIT_GET, json!({})),
        ] {
            let (status, body) = served.post(Caller::Agent, verb, input).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "agent at {verb}: {body}");
            assert_eq!(
                error_code(&body),
                Some("FORBIDDEN"),
                "agent at {verb}: {body}"
            );
        }

        let deletion = served.ok(Caller::Agent, DELETION, json!({})).await;
        assert!(deletion.is_null(), "{deletion}");

        let started = served
            .ok(Caller::Owner, STARTED, json!({"vault_id": VAULT_ID}))
            .await;
        assert_eq!(started.as_array().expect("started").len(), 1, "{started}");
        let outcomes = served
            .ok(Caller::Owner, OUTCOMES, json!({"vault_id": VAULT_ID}))
            .await;
        assert_eq!(
            outcomes, owner_outcomes_before,
            "no new outcome: {outcomes}"
        );
        let wait = served.ok(Caller::Owner, WAIT_GET, json!({})).await;
        assert!(wait.is_null(), "{wait}");
    });
}

/// An export-first removal delivers its archive to the removed Owner alone:
/// executing answers the export summary and the delivery to B, B's outcome
/// names it, and a re-run re-delivers it for a fresh term. (The archive
/// goes to the removed Owner only, never to the Owner who runs the act.)
#[test]
fn export_first_delivers_the_archive_to_the_removed_owner_only() {
    run_on_engine_stack("shared-export-first", || async {
        let served = served();
        let removed = served
            .ok(
                Caller::Owner,
                PROPOSE_REMOVE_OWNER,
                json!({
                    "vault_id": VAULT_ID,
                    "target": served.b.to_hex(),
                    "export_first": true,
                }),
            )
            .await;
        assert_eq!(removed["completed"], true, "{removed}");
        let executed = served
            .ok(
                Caller::Owner,
                EXECUTE,
                json!({"act_id": Served::act_id(&removed)}),
            )
            .await;
        let receipt = &executed["receipt"];
        let export = &receipt["export"];
        assert_eq!(export["member"], served.b.to_hex(), "{executed}");
        assert!(export["records"].is_u64(), "{executed}");
        assert_eq!(
            export["digest"].as_str().expect("digest").len(),
            64,
            "{executed}"
        );
        let delivery = &executed["delivery"];
        assert_eq!(delivery["recipient"], served.b.to_hex(), "{executed}");
        assert_eq!(delivery["digest"], export["digest"], "{executed}");
        assert_eq!(delivery["receipt_id"], receipt["id"], "{executed}");
        let delivered_at = delivery["delivered_at"].as_u64().expect("delivered_at");
        let expires_at = delivery["expires_at"].as_u64().expect("expires_at");
        assert_eq!(delivered_at, T0, "{executed}");
        assert_eq!(expires_at, T0 + NINETY_DAYS, "{executed}");

        let outcomes = served
            .ok(Caller::Owner, OUTCOMES, json!({"vault_id": VAULT_ID}))
            .await;
        let outcomes = outcomes.as_array().expect("an outcomes list");
        let removal_id = Served::act_id(&removed);
        let named: Vec<&Value> = outcomes
            .iter()
            .filter(|outcome| outcome["act_id"] == removal_id)
            .collect();
        assert_eq!(named.len(), 1, "the removal outcome: {outcomes:?}");
        assert_eq!(
            named[0]["change"]["owner_removed"]["target"],
            served.b.to_hex(),
            "{:?}",
            named[0]
        );

        let rerun = served
            .ok(
                Caller::Owner,
                EXECUTE,
                json!({"act_id": Served::act_id(&removed)}),
            )
            .await;
        assert_eq!(rerun["receipt"]["id"], receipt["id"], "{rerun}");
        assert_eq!(rerun["delivery"]["recipient"], served.b.to_hex(), "{rerun}");

        served.clock.set(T0 + 3600);
        let redelivered = served
            .ok(
                Caller::Owner,
                EXECUTE,
                json!({"act_id": Served::act_id(&removed)}),
            )
            .await;
        assert_eq!(redelivered["receipt"]["id"], receipt["id"], "{redelivered}");
        assert_eq!(
            redelivered["delivery"]["expires_at"]
                .as_u64()
                .expect("expires_at"),
            expires_at + 3600,
            "{redelivered}"
        );
    });
}
