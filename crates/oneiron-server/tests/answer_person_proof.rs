//! UC-05 PR 2a: a direct `tasks.answer` over the facade binds the answering
//! person's own person-tier proof.
//!
//! `direct_authorship` (`crates/oneiron-server/src/api/facade/identity.rs`)
//! binds, for `tasks.answer` only, the owner's own authorship as before, or
//! else the answering person's own person-tier proof (`answer_person_proof`:
//! `shared_act_doors::person`, then `Vault::bind_person_credential`, so the
//! proof stays person-tier even for an owner). No guard reads the person
//! tier yet, so nothing behaves differently: both tests below pass
//! identically on the base (main) and on this head. They are guards for the
//! PR that teaches a guard to read it:
//!
//! - `a_members_direct_answer_lands_under_their_person_proof`: a member's
//!   direct answer on their own slip still lands (200) and settles the ask.
//!   On the head this request carries a person-tier proof into admission
//!   and settlement; the test shows nothing downstream errors on it.
//! - `an_owners_narrowed_slip_answer_carries_no_owner_authority`: the
//!   owner's narrowed slip answering an attendee ask is refused 403 and the
//!   ask still waits. A narrowed owner slip never reaches the owner tier
//!   through the person path.
//!
//! Public paths only; no test door. Run:
//! `cargo test --locked -p oneiron-server --all-features --test answer_person_proof`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof};
use oneiron::disclosure::{ATTENDEE_UNKNOWN_OPTION, UnknownAttendeeAsk};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskQuestion, TaskAskSpec, TaskAskStatus, TaskAskTarget,
    TaskAssignee,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const VERB: &str = "tasks.answer";

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every credential here binds; the holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5B; 32])
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

fn turn_body(role: &str) -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("role"), rmpv::Value::from(role))]),
    )
    .expect("a turn body");
    body
}

/// A rooted server on its own device keystore, holding a plain vault whose
/// roster is its embedded owner and one non-owner person.
struct Served {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    owner: EntityId,
    person: EntityId,
}

fn served() -> Served {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("answer-person-proof".to_owned()),
                ..Default::default()
            },
        )
        .expect("a server"),
    );
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let member = EntityId::now();
    person(&vault, member);
    Served {
        _dir: dir,
        server,
        vault,
        issuer,
        owner,
        person: member,
    }
}

impl Served {
    /// A human credential this host mints `who`, holding `read` and `write`:
    /// a person's own slip, narrowed below the top scope, so never
    /// owner-grade (`VerifiedSlip::is_full_vault_owner_grade` needs
    /// `Scope::top()`). The assert pins that: no credential here may reach
    /// the owner tier through `owner_authorship`, whatever its holder owns.
    fn credential(&self, who: EntityId) -> CapabilitySlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root slip")
            .claims;
        claims.slip_id = next_slip_id();
        claims.parent_id = None;
        claims.holder_ref = who.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = holder_key().verifying_key().to_bytes();
        claims.scope.verbs =
            ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        let slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("a credential");
        assert!(
            slip.claims.scope != Scope::top(),
            "the fixture mints narrowed slips only: no owner tier through owner_authorship",
        );
        slip
    }

    /// A durable TURN row holding `role`, for an ask's question or a word's
    /// result.
    fn turn(&self, role: &str, at: u64) -> EntityId {
        let id = EntityId::now();
        self.vault
            .put_entity(
                &id,
                ENTITY_TYPE_TURN,
                TimeRange { start: at, end: at },
                at,
                &turn_body(role),
            )
            .expect("a turn row");
        id
    }

    /// `who` answers the ask `group` with `result` on their own slip: the
    /// status and the body. `option` is the offered choice, or `None` for an
    /// optionless ask.
    async fn answer_as(
        &self,
        who: EntityId,
        group: EntityId,
        result: EntityId,
        option: Option<&str>,
    ) -> (StatusCode, Value) {
        let slip = self.credential(who);
        let binding =
            holder_proof(&slip, &holder_key(), self.vault.now_recorded_at()).expect("holder proof");
        let input = json!({
            "handle": {"group_ref": group.to_hex()},
            "word": {"result_ref": result.to_hex(), "option": option,
                     "inform_for": null, "provenance_refs": []},
        });
        let response = build_app(Arc::clone(&self.server))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/core/facade/{VERB}"))
                    .header(
                        "Authorization",
                        format!("Bearer {}", slip.to_token().expect("token")),
                    )
                    .header("x-oneiron-binding", binding.to_string())
                    .header("Content-Type", "application/json")
                    .body(Body::from(input.to_string()))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_048_576)
            .await
            .expect("response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

/// Runs one served case on threads that have the engine's native stack, as
/// `oneiron serve` runs its doors: a generated dispatch frame is larger than
/// a libtest thread's stack in a dev build (FIX 16372).
fn on_engine_stack<F>(case: impl FnOnce() -> F + Send + 'static)
where
    F: std::future::Future<Output = ()>,
{
    let thread = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(case());
        })
        .expect("engine-stack thread");
    if let Err(panic) = thread.join() {
        std::panic::resume_unwind(panic);
    }
}

/// A non-owner person asked an ordinary ask answers it directly on their own
/// slip: 200, and the ask then reads Settled. On the head this request
/// carries a person-tier proof into admission and settlement; the test shows
/// nothing downstream errors on it. Passes on main too, where no proof is
/// bound: no guard reads the person tier yet.
#[test]
fn a_members_direct_answer_lands_under_their_person_proof() {
    on_engine_stack(|| async {
        let served = served();
        let question = served.turn("question", 2);
        let receipt = served
            .vault
            .memory(served.owner, EdgeActorClass::Human)
            .tasks_ask(&TaskAskSpec {
                intent_key: "answer-person-proof-member".into(),
                ..TaskAskSpec::shorthand(
                    Some(TaskAskTarget::Responder(TaskAssignee::Human {
                        actor_ref: served.person,
                    })),
                    TaskAskQuestion::new(
                        ConsultPayloadRef::parse(
                            &served.vault,
                            &format!("tn_{}", question.to_hex()),
                        )
                        .expect("the question ref"),
                    ),
                    Some(u64::MAX),
                    TaskAskDefault::AskMe,
                )
            })
            .expect("the owner asks the member");
        let result = served.turn("answer", 3);
        let (status, body) = served
            .answer_as(served.person, receipt.handle.group_ref, result, None)
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a member's direct answer lands: {body}"
        );
        assert_eq!(
            body["actor_ref"],
            served.person.to_hex(),
            "the word lands under the member's own actor: {body}"
        );
        let status = served
            .vault
            .memory(served.owner, EdgeActorClass::Human)
            .tasks_ask_status(receipt.handle)
            .expect("the ask reads");
        assert!(
            matches!(status, TaskAskStatus::Settled(_)),
            "the answered ask settles: {status:?}"
        );
    });
}

/// The vault owner answering an attendee ask on a narrowed slip of their own
/// (holder = owner, human, verbs {read, write}: not owner grade) is refused
/// 403 (`ConsentOwnerNotAuthenticated` renders `FORBIDDEN`), and the ask
/// still reads Pending. A narrowed owner slip never reaches the owner tier
/// through the person path: on the head its person-tier proof carries no
/// owner authority (FIX 4707); on main no proof is bound. The refusal is the
/// same either way.
#[test]
fn an_owners_narrowed_slip_answer_carries_no_owner_authority() {
    on_engine_stack(|| async {
        let served = served();
        let ask = UnknownAttendeeAsk {
            session_key: "room-narrowed-owner".to_owned(),
            speaker_key: "speaker-1".to_owned(),
            roster_revision: 1,
            trigger_turn: None,
            candidates: Vec::new(),
            until: served.vault.now_recorded_at() + 86_400,
        };
        let receipt = served
            .vault
            .memory(served.owner, EdgeActorClass::Human)
            .raise_unknown_attendee_ask(&ask)
            .expect("the owner raises the attendee ask");
        let result = served.turn("answer", 2);
        let (status, body) = served
            .answer_as(
                served.owner,
                receipt.handle.group_ref,
                result,
                Some(ATTENDEE_UNKNOWN_OPTION),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a narrowed owner slip carries no owner authority: {body}"
        );
        let status = served
            .vault
            .memory(served.owner, EdgeActorClass::Human)
            .tasks_ask_status(receipt.handle)
            .expect("the ask reads");
        assert!(
            matches!(status, TaskAskStatus::Pending { .. }),
            "the refused ask still waits: {status:?}"
        );
    });
}
