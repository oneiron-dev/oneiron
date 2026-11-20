//! Public-door promise tests for the `vault.notes` family (the server serves
//! all 27 verbs; editor.bind/close work only on the server).
//!
//! Every case drives the real routes in process (`build_app` + `oneshot`):
//! `POST /v1/core/facade/<verb>` for `vault.notes.create`, `.edit`, `.read`,
//! `.history`, `.history_purge`, `.history_purge_execute`, `.seal`, `.fork`,
//! `.proposals.open`, `.proposals.merge`, `.lifecycle`, `.version_tree`,
//! `.forks.read`, `.set_overrides`, `.defaults`, `.editor.bind` and
//! `.editor.close`. Callers: the vault's embedded owner on the host root
//! credential; a second live person on their own minted human credential; and
//! a live person on a minted agent-class credential. Each case owns its
//! vault; only the veto-window case runs on a manual store clock, so its
//! window matures deterministically with no sleeps.
//!
//! The promises:
//! - a personal purge erases history at once and keeps the live text
//!   byte-identical (removes vs keeps);
//! - a shared purge waits its veto window, refuses an early execute, then
//!   executes once and idempotently (the veto window);
//! - strangers are refused at the owner-only purge doors and write nothing;
//! - a seal freezes the document and later edits fork;
//! - an agent's proposal waits for the owner's merge;
//! - a session's pad seals at its own session close only;
//! - seal and overrides need the author or the owner;
//! - an editor binding belongs to its opener.
//!
//! These promises hold on main. Their red proof is a seeded fault (Test rules
//! v2, rule 5), named in `seed_notes_faults.py`.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --no-fail-fast --test vault_notes_doors`. The test calls no test door; it
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
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::session_lifecycle::{SessionClosePredicate, SessionMintOutcome};
use oneiron::store::GateDecisionId;
use oneiron::store::ports::ManualClock;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const SHARED: u64 = 43;
/// The manual clock's fixed start: every deadline is exact on it.
const T0: u64 = 1_800_000_000;
/// The shipped `erase` wait: seven days.
const ERASE_WAIT_SECS: u64 = 604800;

const CREATE: &str = "vault.notes.create";
const EDIT: &str = "vault.notes.edit";
const READ: &str = "vault.notes.read";
const HISTORY: &str = "vault.notes.history";
const HISTORY_PURGE: &str = "vault.notes.history_purge";
const HISTORY_PURGE_EXECUTE: &str = "vault.notes.history_purge_execute";
const SEAL: &str = "vault.notes.seal";
const FORK: &str = "vault.notes.fork";
const PROPOSALS_OPEN: &str = "vault.notes.proposals.open";
const PROPOSALS_MERGE: &str = "vault.notes.proposals.merge";
const LIFECYCLE: &str = "vault.notes.lifecycle";
const VERSION_TREE: &str = "vault.notes.version_tree";
const FORKS_READ: &str = "vault.notes.forks.read";
const SET_OVERRIDES: &str = "vault.notes.set_overrides";
const DEFAULTS: &str = "vault.notes.defaults";
const EDITOR_BIND: &str = "vault.notes.editor.bind";
const EDITOR_CLOSE: &str = "vault.notes.editor.close";

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

/// A served vault: its embedded owner A, a second live person B, and a live
/// person G on an agent-class credential, each caller on their own
/// credential. `served_shared` additionally shares the vault between A and B
/// as Owners on the manual clock.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    clock: Option<Arc<ManualClock>>,
    owner_slip: CapabilitySlip,
    owner_token: String,
    a: EntityId,
    b: EntityId,
    g: EntityId,
    b_slip: CapabilitySlip,
    b_token: String,
    g_slip: CapabilitySlip,
    g_token: String,
}

/// Who sends a request.
#[derive(Clone, Copy, Debug)]
enum Caller {
    /// The embedded owner on the host root credential.
    Owner,
    /// The second person on their own human credential.
    Person,
    /// A live person on a minted agent-class credential.
    Agent,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn error_code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

fn error_message(body: &Value) -> Option<&str> {
    body["error"]["message"].as_str()
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

/// A self-hosted served vault on the wall clock.
fn served() -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-notes-doors".into()),
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
    let b = EntityId::now();
    let g = EntityId::now();
    for id in [b, g] {
        person(&vault, id);
    }
    let app = build_app(server);
    let (b_slip, b_token) = credential(&vault, &issuer, b, Some("human"));
    let (g_slip, g_token) = credential(&vault, &issuer, g, Some("agent"));
    Served {
        _dir: dir,
        vault,
        app,
        issuer,
        clock: None,
        owner_slip,
        owner_token,
        a,
        b,
        g,
        b_slip,
        b_token,
        g_slip,
        g_token,
    }
}

/// [`served`] on the manual clock, shared by A with B as a second Owner; B
/// accepted the founding invitation.
fn served_shared() -> Served {
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
                auth_secret: Some("vault-notes-doors".into()),
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
    let g = EntityId::now();
    for id in [b, g] {
        person(&vault, id);
    }
    let founding = |member_ref, role| InitialSharedMember {
        member_ref,
        role: Some(role),
    };
    vault
        .initialize_shared_vault(
            &owner_proof,
            SHARED,
            None,
            &[founding(a, Role::Owner), founding(b, Role::Owner)],
            1,
        )
        .expect("a shared vault with a second Owner");
    let own = proof(&vault, b);
    let invitation = vault
        .shared_invitations(&own, SHARED)
        .expect("invitations")
        .into_iter()
        .find(|open| open.role == Role::Owner)
        .expect("the founding invitation");
    vault
        .accept_shared_invitation(&own, SHARED, &invitation.id)
        .expect("the person accepts");
    let app = build_app(server);
    let (b_slip, b_token) = credential(&vault, &issuer, b, Some("human"));
    let (g_slip, g_token) = credential(&vault, &issuer, g, Some("agent"));
    Served {
        _dir: dir,
        vault,
        app,
        issuer,
        clock: Some(clock),
        owner_slip,
        owner_token,
        a,
        b,
        g,
        b_slip,
        b_token,
        g_slip,
        g_token,
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
            Caller::Person => Some(&self.b_slip),
            Caller::Agent => Some(&self.g_slip),
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
            Caller::Person => self.b_token.as_str(),
            Caller::Agent => self.g_token.as_str(),
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
}

/// A personal purge erases history at once and keeps the live text
/// byte-identical: the receipt names the note and its hash matches the live
/// markdown, the read is unchanged, and history turns shallow with no
/// operations. (Removes vs keeps: ops below the floor go, the live text
/// stays.)
#[test]
fn owner_purges_personal_note_history_at_once() {
    run_on_engine_stack("notes-purge-personal", || async {
        let served = served();
        let m0 = "The lighthouse keeper logs the tide at dawn.";
        let created = served
            .ok(
                Caller::Owner,
                CREATE,
                json!({"kind": "research", "markdown": m0}),
            )
            .await;
        let note = created["id_hex"].as_str().expect("note id").to_owned();
        assert_eq!(note.len(), 32, "{created}");

        let m1 = format!("{m0} The gulls cry at noon.");
        let read = served
            .ok(Caller::Owner, READ, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(read["value"]["markdown"], m0, "{read}");
        let v0 = read["value"]["version"].clone();
        let edited = served
            .ok(
                Caller::Owner,
                EDIT,
                json!({"note_ref": note.clone(), "edit": {"kind": "whole_text", "text": m1.clone(), "timeout_ms": 100, "base": v0}}),
            )
            .await;
        assert_eq!(edited["outcome"], "edited", "{edited}");

        let m2 = format!("{m1} The foghorn sounds at dusk.");
        let read = served
            .ok(Caller::Owner, READ, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(read["value"]["markdown"], m1, "{read}");
        let v1 = read["value"]["version"].clone();
        let edited = served
            .ok(
                Caller::Owner,
                EDIT,
                json!({"note_ref": note.clone(), "edit": {"kind": "whole_text", "text": m2.clone(), "timeout_ms": 100, "base": v1}}),
            )
            .await;
        assert_eq!(edited["outcome"], "edited", "{edited}");

        let pre = served
            .ok(Caller::Owner, HISTORY, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(pre["value"]["complete"], true, "{pre}");
        assert!(
            pre["value"]["operations"]
                .as_array()
                .expect("operations")
                .len()
                > 0,
            "{pre}"
        );

        let purged = served
            .ok(
                Caller::Owner,
                HISTORY_PURGE,
                json!({"note_ref": note.clone()}),
            )
            .await;
        assert_eq!(purged["state"], "erased", "{purged}");
        let receipt = &purged["receipt"];
        assert_eq!(receipt["entity"], note, "{purged}");
        let hash = blake3::hash(m2.as_bytes());
        let expected = serde_json::to_value(hash.as_bytes().to_vec()).expect("hash json");
        assert_eq!(receipt["live_text_hash"], expected, "{purged}");

        let read = served
            .ok(Caller::Owner, READ, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(read["value"]["markdown"], m2, "{read}");

        let post = served
            .ok(Caller::Owner, HISTORY, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(post["value"]["complete"], false, "{post}");
        assert_eq!(
            post["value"]["operations"]
                .as_array()
                .expect("operations")
                .len(),
            0,
            "{post}"
        );
    });
}

/// A shared purge waits its veto window, refuses an early execute, then
/// executes once and idempotently: the retry returns the same receipt.
/// (The veto window: two live Owners, seven days on the store clock.)
#[test]
fn shared_purge_waits_veto_window_then_executes_once() {
    run_on_engine_stack("notes-purge-shared", || async {
        let served = served_shared();
        let m0 = "The lighthouse keeper logs the tide at dawn.";
        let created = served
            .ok(
                Caller::Owner,
                CREATE,
                json!({"kind": "research", "markdown": m0}),
            )
            .await;
        let note = created["id_hex"].as_str().expect("note id").to_owned();

        let purged = served
            .ok(
                Caller::Owner,
                HISTORY_PURGE,
                json!({"note_ref": note.clone()}),
            )
            .await;
        assert_eq!(purged["state"], "waiting", "{purged}");
        assert_eq!(purged["note_ref"], note, "{purged}");
        let act = purged["act_id"].as_str().expect("act id").to_owned();

        let (status, body) = served
            .post(
                Caller::Owner,
                HISTORY_PURGE_EXECUTE,
                json!({"act_id": act.clone()}),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "executing early: {body}");
        assert_eq!(error_code(&body), Some("INVALID_STATE"), "{body}");
        assert_eq!(
            error_message(&body),
            Some("this erase's veto window is open or an owner objects"),
            "{body}"
        );

        served
            .clock
            .as_ref()
            .expect("manual clock")
            .set(T0 + ERASE_WAIT_SECS + 1);
        let executed = served
            .ok(
                Caller::Owner,
                HISTORY_PURGE_EXECUTE,
                json!({"act_id": act.clone()}),
            )
            .await;
        assert_eq!(executed["entity"], note, "{executed}");

        let rerun = served
            .ok(
                Caller::Owner,
                HISTORY_PURGE_EXECUTE,
                json!({"act_id": act.clone()}),
            )
            .await;
        assert_eq!(
            rerun, executed,
            "the retry returns the same receipt: {rerun}"
        );
    });
}

/// Strangers are refused at the owner-only purge doors and write nothing:
/// the agent and the second person get 403 at purge and execute, and the
/// owner's history stays complete with its operations intact. (The owner
/// proof: purge and execute are the vault owner's.)
#[test]
fn purge_refuses_agent_and_second_person_with_nothing_written() {
    run_on_engine_stack("notes-purge-refused", || async {
        let served = served();
        let m0 = "The lighthouse keeper logs the tide at dawn.";
        let created = served
            .ok(
                Caller::Owner,
                CREATE,
                json!({"kind": "research", "markdown": m0}),
            )
            .await;
        let note = created["id_hex"].as_str().expect("note id").to_owned();

        let m1 = format!("{m0} The gulls cry at noon.");
        let read = served
            .ok(Caller::Owner, READ, json!({"note_ref": note.clone()}))
            .await;
        let v0 = read["value"]["version"].clone();
        let edited = served
            .ok(
                Caller::Owner,
                EDIT,
                json!({"note_ref": note.clone(), "edit": {"kind": "whole_text", "text": m1.clone(), "timeout_ms": 100, "base": v0}}),
            )
            .await;
        assert_eq!(edited["outcome"], "edited", "{edited}");

        let pre = served
            .ok(Caller::Owner, HISTORY, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(pre["value"]["complete"], true, "{pre}");
        let pre_ops = pre["value"]["operations"]
            .as_array()
            .expect("operations")
            .len();
        assert!(pre_ops > 0, "{pre}");

        for caller in [Caller::Agent, Caller::Person] {
            let (status, body) = served
                .post(caller, HISTORY_PURGE, json!({"note_ref": note.clone()}))
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{caller:?} at purge: {body}");
            assert_eq!(error_code(&body), Some("FORBIDDEN"), "{caller:?}: {body}");
            assert_eq!(
                error_message(&body),
                Some("vault.notes.history_purge is the vault owner's"),
                "{caller:?}: {body}"
            );
        }

        let fake = "00000000000000000000000000000000";
        for caller in [Caller::Agent, Caller::Person] {
            let (status, body) = served
                .post(caller, HISTORY_PURGE_EXECUTE, json!({"act_id": fake}))
                .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{caller:?} at execute: {body}"
            );
            assert_eq!(error_code(&body), Some("FORBIDDEN"), "{caller:?}: {body}");
            assert_eq!(
                error_message(&body),
                Some("vault.notes.history_purge_execute is the vault owner's"),
                "{caller:?}: {body}"
            );
        }

        let post = served
            .ok(Caller::Owner, HISTORY, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(post["value"]["complete"], true, "{post}");
        assert_eq!(
            post["value"]["operations"]
                .as_array()
                .expect("operations")
                .len(),
            pre_ops,
            "{post}"
        );
        let tree = served
            .ok(
                Caller::Owner,
                VERSION_TREE,
                json!({"note_ref": note.clone()}),
            )
            .await;
        assert_eq!(
            tree["value"]["receipts"]
                .as_array()
                .expect("receipts")
                .len(),
            0,
            "{tree}"
        );
    });
}

/// A seal freezes the document and later edits fork: after the seal each of
/// the five edit shapes opens a fork, the live read never moves, the fork
/// text reads back, lifecycle stays sealed, and the version tree lists the
/// forks. (The seal: in-place needs authorized and unsealed.)
#[test]
fn seal_freezes_document_later_edits_fork() {
    run_on_engine_stack("notes-seal-forks", || async {
        let served = served();
        let m0 = "The lighthouse keeper logs the tide at dawn.";
        let created = served
            .ok(
                Caller::Owner,
                CREATE,
                json!({"kind": "research", "markdown": m0}),
            )
            .await;
        let note = created["id_hex"].as_str().expect("note id").to_owned();

        let m1 = format!("{m0} The gulls cry at noon.");
        let read = served
            .ok(Caller::Owner, READ, json!({"note_ref": note.clone()}))
            .await;
        let v0 = read["value"]["version"].clone();
        let edited = served
            .ok(
                Caller::Owner,
                EDIT,
                json!({"note_ref": note.clone(), "edit": {"kind": "whole_text", "text": m1.clone(), "timeout_ms": 100, "base": v0}}),
            )
            .await;
        assert_eq!(edited["outcome"], "edited", "{edited}");

        let seal = served
            .ok(Caller::Owner, SEAL, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(seal["note"], note, "{seal}");

        let read = served
            .ok(Caller::Owner, READ, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(read["value"]["markdown"], m1, "{read}");
        assert_eq!(
            read["value"]["version"]["head"], seal["document"],
            "{read} vs {seal}"
        );

        let spanned = served
            .ok(
                Caller::Owner,
                READ,
                json!({"note_ref": note.clone(), "spans": [{"start": 0, "end": 0}]}),
            )
            .await;
        assert_eq!(
            spanned["value"]["spans"].as_array().expect("spans").len(),
            1,
            "{spanned}"
        );
        let start = spanned["value"]["spans"][0]["start"].clone();
        let end = spanned["value"]["spans"][0]["end"].clone();

        let out = served
            .ok(
                Caller::Owner,
                EDIT,
                json!({"note_ref": note.clone(), "edit": {"kind": "replace_span", "start": start, "end": end.clone(), "text": " [replace] "}}),
            )
            .await;
        assert_eq!(out["outcome"], "rewrite_fork", "{out}");

        let out = served
            .ok(
                Caller::Owner,
                EDIT,
                json!({"note_ref": note.clone(), "edit": {"kind": "insert_after", "anchor": end.clone(), "text": " [insert] "}}),
            )
            .await;
        assert_eq!(out["outcome"], "rewrite_fork", "{out}");

        let out = served
            .ok(
                Caller::Owner,
                EDIT,
                json!({"note_ref": note.clone(), "edit": {"kind": "append_to_section", "end": end.clone(), "text": " [append] "}}),
            )
            .await;
        assert_eq!(out["outcome"], "rewrite_fork", "{out}");

        let read = served
            .ok(Caller::Owner, READ, json!({"note_ref": note.clone()}))
            .await;
        let base = read["value"]["version"].clone();
        let m_whole = format!("{m1} [whole] ");
        let out = served
            .ok(
                Caller::Owner,
                EDIT,
                json!({"note_ref": note.clone(), "edit": {"kind": "whole_text", "text": m_whole.clone(), "timeout_ms": 100, "base": base}}),
            )
            .await;
        assert_eq!(out["outcome"], "rewrite_fork", "{out}");

        let m_rewrite = format!("{m1} [rewrite] ");
        let out = served
            .ok(
                Caller::Owner,
                EDIT,
                json!({"note_ref": note.clone(), "edit": {"kind": "rewrite", "text": m_rewrite.clone()}}),
            )
            .await;
        assert_eq!(out["outcome"], "rewrite_fork", "{out}");
        let fork_rewrite = out["fork"].as_str().expect("fork").to_owned();

        let read = served
            .ok(Caller::Owner, READ, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(read["value"]["markdown"], m1, "{read}");

        let forked = served
            .ok(
                Caller::Owner,
                FORKS_READ,
                json!({"note_ref": note.clone(), "fork_ref": fork_rewrite.clone()}),
            )
            .await;
        assert_eq!(forked["value"]["markdown"], m_rewrite, "{forked}");

        let life = served
            .ok(Caller::Owner, LIFECYCLE, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(life["status"], "sealed", "{life}");

        let tree = served
            .ok(
                Caller::Owner,
                VERSION_TREE,
                json!({"note_ref": note.clone()}),
            )
            .await;
        assert_eq!(
            tree["value"]["forks"].as_array().expect("forks").len(),
            5,
            "{tree}"
        );
    });
}

/// An agent's proposal waits for the owner's merge: the agent forks a
/// whole-text edit (a diff, not a declared rewrite, which only a switch
/// settles) and opens, the live text stays, the agent and the second person
/// are refused without a grant, and the owner's merge lands the text with a
/// receipt. (The grant: every waiting member needs it, the owner always lands.)
#[test]
fn agent_proposal_waits_for_owner_merge() {
    run_on_engine_stack("notes-proposal-merge", || async {
        let served = served();
        let m0 = "The lighthouse keeper logs the tide at dawn.";
        let created = served
            .ok(
                Caller::Owner,
                CREATE,
                json!({"kind": "research", "markdown": m0}),
            )
            .await;
        let note = created["id_hex"].as_str().expect("note id").to_owned();

        let agent_read = served
            .ok(Caller::Agent, READ, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(agent_read["value"]["markdown"], m0, "{agent_read}");
        let base = agent_read["value"]["version"].clone();

        let m1 = format!("{m0} Agent words added here for the proposal.");
        let forked = served
            .ok(
                Caller::Agent,
                FORK,
                json!({"note_ref": note.clone(), "base": base, "edit": {"kind": "whole_text", "text": m1.clone(), "timeout_ms": 100, "base": null}}),
            )
            .await;
        let fork_ref = forked["record"]["fork_ref"]
            .as_str()
            .expect("fork ref")
            .to_owned();
        assert_eq!(forked["markdown"], m1, "{forked}");

        let explainer = "Agent proposes its addition to the log.";
        let opened = served
            .ok(
                Caller::Agent,
                PROPOSALS_OPEN,
                json!({"forks": [{"note_ref": note.clone(), "fork_ref": fork_ref.clone()}], "explainer": explainer}),
            )
            .await;
        assert_eq!(
            opened["waiting"].as_array().expect("waiting").len(),
            1,
            "{opened}"
        );
        assert_eq!(
            opened["landed"].as_array().expect("landed").len(),
            0,
            "{opened}"
        );
        assert_eq!(opened["explainer"], explainer, "{opened}");
        let prop = opened["proposal_ref"]
            .as_str()
            .expect("proposal")
            .to_owned();

        let read = served
            .ok(Caller::Owner, READ, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(read["value"]["markdown"], m0, "{read}");

        for caller in [Caller::Agent, Caller::Person] {
            let (status, body) = served
                .post(
                    caller,
                    PROPOSALS_MERGE,
                    json!({"proposal_ref": prop.clone()}),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{caller:?} merges: {body}");
            assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{caller:?}: {body}");
            assert_eq!(
                error_message(&body),
                Some("no grant to accept this fork"),
                "{caller:?}: {body}"
            );
        }

        let merged = served
            .ok(
                Caller::Owner,
                PROPOSALS_MERGE,
                json!({"proposal_ref": prop.clone()}),
            )
            .await;
        assert_eq!(
            merged["waiting"].as_array().expect("waiting").len(),
            0,
            "{merged}"
        );
        assert_eq!(
            merged["landed"].as_array().expect("landed").len(),
            1,
            "{merged}"
        );

        let read = served
            .ok(Caller::Owner, READ, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(read["value"]["markdown"], m1, "{read}");

        let tree = served
            .ok(
                Caller::Owner,
                VERSION_TREE,
                json!({"note_ref": note.clone()}),
            )
            .await;
        let receipts = tree["value"]["receipts"].as_array().expect("receipts");
        assert_eq!(receipts.len(), 1, "{tree}");
        assert_eq!(receipts[0]["verdict"], "Merge", "{tree}");
    });
}

/// A session's pad seals at its own session close only: closing A's sitting
/// seals A's pad and leaves B's active, A's lines still read, and closing
/// B's seals B's. (The sitting close seals its session's pad in a
/// savepoint.)
#[test]
fn pad_seals_at_its_own_session_close() {
    run_on_engine_stack("notes-pad-close", || async {
        let served = served();
        let now = served.vault.now_recorded_at();
        let key_a = served.vault.local_session_key(served.a).expect("key A");
        let session_a = match served.vault.mint_session(key_a, now).expect("mint A") {
            SessionMintOutcome::Minted(id) | SessionMintOutcome::AlreadyOpen(id) => id,
        };
        let key_b = served.vault.local_session_key(served.b).expect("key B");
        let session_b = match served.vault.mint_session(key_b, now).expect("mint B") {
            SessionMintOutcome::Minted(id) | SessionMintOutcome::AlreadyOpen(id) => id,
        };
        assert_ne!(session_a, session_b, "two sittings");

        let sess_a = session_a.to_hex();
        let sess_b = session_b.to_hex();
        let pad_a = served
            .vault
            .memory(served.a, EdgeActorClass::Human)
            .scratchpad_append(sess_a.as_str(), "first line of A's run", None, false)
            .expect("A appends")
            .pad;
        let pad_b = served
            .vault
            .memory(served.b, EdgeActorClass::Human)
            .scratchpad_append(sess_b.as_str(), "first line of B's run", None, false)
            .expect("B appends")
            .pad;
        assert_ne!(pad_a, pad_b, "two pads");
        let pad_a_hex = pad_a.to_hex();
        let pad_b_hex = pad_b.to_hex();

        let life_a = served
            .ok(
                Caller::Owner,
                LIFECYCLE,
                json!({"note_ref": pad_a_hex.clone()}),
            )
            .await;
        assert_eq!(life_a["status"], "active", "{life_a}");
        let life_b = served
            .ok(
                Caller::Person,
                LIFECYCLE,
                json!({"note_ref": pad_b_hex.clone()}),
            )
            .await;
        assert_eq!(life_b["status"], "active", "{life_b}");

        let wake_a = served
            .vault
            .plan_session_end_wake(&session_a)
            .expect("plan A");
        let ended_a = served
            .vault
            .end_session_with_wake(
                &session_a,
                SessionClosePredicate::Explicit,
                served.vault.now_recorded_at(),
                &wake_a,
            )
            .expect("close A");
        assert!(ended_a.is_some(), "A's sitting closed");

        let life_a = served
            .ok(
                Caller::Owner,
                LIFECYCLE,
                json!({"note_ref": pad_a_hex.clone()}),
            )
            .await;
        assert_eq!(life_a["status"], "sealed", "{life_a}");
        let life_b = served
            .ok(
                Caller::Person,
                LIFECYCLE,
                json!({"note_ref": pad_b_hex.clone()}),
            )
            .await;
        assert_eq!(life_b["status"], "active", "{life_b}");

        let read_a = served
            .ok(
                Caller::Owner,
                READ,
                json!({"note_ref": pad_a_hex.clone(), "reason": "the close test reads its sealed pad"}),
            )
            .await;
        let markdown = read_a["value"]["markdown"]
            .as_str()
            .expect("markdown")
            .to_owned();
        assert!(markdown.contains("first line of A's run"), "{markdown}");

        let wake_b = served
            .vault
            .plan_session_end_wake(&session_b)
            .expect("plan B");
        let ended_b = served
            .vault
            .end_session_with_wake(
                &session_b,
                SessionClosePredicate::Explicit,
                served.vault.now_recorded_at(),
                &wake_b,
            )
            .expect("close B");
        assert!(ended_b.is_some(), "B's sitting closed");

        let life_b = served
            .ok(
                Caller::Person,
                LIFECYCLE,
                json!({"note_ref": pad_b_hex.clone()}),
            )
            .await;
        assert_eq!(life_b["status"], "sealed", "{life_b}");
    });
}

/// Seal and overrides need the author or the owner: the agent and the second
/// person are refused at both, the owner seals, the owner sets overrides on
/// the sealed note, and lifecycle plus defaults show both. (Author or
/// owner: a seal freezes text, not policy.)
#[test]
fn seal_and_overrides_need_author_or_owner() {
    run_on_engine_stack("notes-seal-owner", || async {
        let served = served();
        let m0 = "The lighthouse keeper logs the tide at dawn.";
        let created = served
            .ok(
                Caller::Owner,
                CREATE,
                json!({"kind": "research", "markdown": m0}),
            )
            .await;
        let note = created["id_hex"].as_str().expect("note id").to_owned();

        for caller in [Caller::Agent, Caller::Person] {
            let (status, body) = served
                .post(caller, SEAL, json!({"note_ref": note.clone()}))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{caller:?} seals: {body}");
            assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{caller:?}: {body}");
            assert_eq!(
                error_message(&body),
                Some("NOTE seal requires its author or the owner"),
                "{caller:?}: {body}"
            );
        }

        for caller in [Caller::Agent, Caller::Person] {
            let (status, body) = served
                .post(
                    caller,
                    SET_OVERRIDES,
                    json!({"note_ref": note.clone(), "overrides": {"extraction": "disabled"}}),
                )
                .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{caller:?} overrides: {body}"
            );
            assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{caller:?}: {body}");
            assert_eq!(
                error_message(&body),
                Some("NOTE overrides require its author or the owner"),
                "{caller:?}: {body}"
            );
        }

        let seal = served
            .ok(Caller::Owner, SEAL, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(seal["note"], note, "{seal}");

        let set = served
            .ok(
                Caller::Owner,
                SET_OVERRIDES,
                json!({"note_ref": note.clone(), "overrides": {"extraction": "disabled"}}),
            )
            .await;
        assert_eq!(set["overrides"]["extraction"], "disabled", "{set}");
        assert_eq!(set["defaults"]["extraction"], "disabled", "{set}");

        let life = served
            .ok(Caller::Owner, LIFECYCLE, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(life["status"], "sealed", "{life}");

        let view = served
            .ok(Caller::Owner, DEFAULTS, json!({"note_ref": note.clone()}))
            .await;
        assert_eq!(view["overrides"]["extraction"], "disabled", "{view}");
        assert_eq!(view["defaults"]["extraction"], "disabled", "{view}");
    });
}

/// An editor binding belongs to its opener: another caller closes nothing,
/// the opener closes, a re-close closes nothing, and binding a non-note is
/// refused. (The binding id carries no authority by itself.)
#[test]
fn editor_binding_belongs_to_its_opener() {
    run_on_engine_stack("notes-editor-bind", || async {
        let served = served();
        let m0 = "The lighthouse keeper logs the tide at dawn.";
        let created = served
            .ok(
                Caller::Owner,
                CREATE,
                json!({"kind": "research", "markdown": m0}),
            )
            .await;
        let note = created["id_hex"].as_str().expect("note id").to_owned();

        let bound = served
            .ok(
                Caller::Owner,
                EDITOR_BIND,
                json!({"note_ref": note.clone()}),
            )
            .await;
        assert_eq!(bound["value"]["note"]["markdown"], m0, "{bound}");
        let binding = bound["value"]["binding"]
            .as_str()
            .expect("binding")
            .to_owned();
        assert_eq!(binding.len(), 32, "{bound}");

        let closed = served
            .ok(
                Caller::Person,
                EDITOR_CLOSE,
                json!({"binding": binding.clone()}),
            )
            .await;
        assert_eq!(closed["closed"], false, "{closed}");

        let closed = served
            .ok(
                Caller::Owner,
                EDITOR_CLOSE,
                json!({"binding": binding.clone()}),
            )
            .await;
        assert_eq!(closed["closed"], true, "{closed}");

        let closed = served
            .ok(
                Caller::Owner,
                EDITOR_CLOSE,
                json!({"binding": binding.clone()}),
            )
            .await;
        assert_eq!(closed["closed"], false, "{closed}");

        let (status, body) = served
            .post(
                Caller::Owner,
                EDITOR_BIND,
                json!({"note_ref": served.b.to_hex()}),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "binding a person: {body}");
        assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{body}");
        assert_eq!(error_message(&body), Some("entity is not a NOTE"), "{body}");
    });
}
