//! A waiting delete is finished on the route that asked it (FIX-LIST
//! CHECK-IN-CORE-DELETE-ROUTE-NO-CHECK-IN-REF; ROLES-CHECKIN 2k5, Engine
//! ruling STEWARD-DELETE-WAIT = B). `POST /v1/core/memory/verbs/delete`
//! judges a person's delete by role through `vault.delete`. A Steward's
//! delete of another person's NOTE waits: the route answers 202
//! `CHECK_IN_PENDING` naming the check-in and deletes nothing. Once the Owner
//! approves it, the same route call naming it as `check_in_ref` deletes the
//! NOTE, spends the check-in, and its receipt names it.
//!
//! Red on main 7b962d258336: the route sends `vault.delete` only the target
//! and the reason, so the approved call waits again and the NOTE stays. The
//! owner's delete naming a check-in deletes (the field is dropped), and a
//! retract naming one runs as if it named none.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! core_memory_delete_check_in_ref`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, SlipCaveat, holder_proof};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember, Scope, ScopeAxis};
use oneiron::note::TakeTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::invoke;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

use engine_stack::run_on_engine_stack;

const SHARED: u64 = 43;

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every credential here binds; the holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x6E; 32])
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

/// A rooted server on its own device keystore, holding a shared vault: its
/// owner, a Steward and a Member, each of whom accepted, and a subject PERSON
/// the NOTEs are about.
struct Served {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    owner: EntityId,
    steward: EntityId,
    member: EntityId,
    subject: EntityId,
}

impl Served {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        vault.prepare_install_signing().expect("install signing");
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some("core-memory-delete-check-in-ref".to_owned()),
                    ..Default::default()
                },
            )
            .expect("a server"),
        );
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let [steward, member, subject] = std::array::from_fn(|_| EntityId::now());
        for id in [steward, member, subject] {
            person(&vault, id);
        }
        let founding = |member_ref, role| InitialSharedMember {
            member_ref,
            role: Some(role),
        };
        vault
            .initialize_shared_vault(
                &proof(&vault, owner),
                SHARED,
                None,
                &[
                    founding(owner, Role::Owner),
                    founding(steward, Role::Steward),
                    founding(member, Role::Member),
                ],
                1,
            )
            .expect("a shared vault with a Steward and a Member");
        for (id, role) in [(steward, Role::Steward), (member, Role::Member)] {
            let person_proof = proof(&vault, id);
            let invitation = vault
                .shared_invitations(&person_proof, SHARED)
                .expect("invitations")
                .into_iter()
                .find(|open| open.role == role)
                .expect("the founding invitation");
            vault
                .accept_shared_invitation(&person_proof, SHARED, &invitation.id)
                .expect("the person accepts");
        }
        Self {
            _dir: dir,
            server,
            vault,
            issuer,
            owner,
            steward,
            member,
            subject,
        }
    }

    /// A NOTE the Member writes about the subject, by its full hex ref. A
    /// human binding is the owner's (H149), so the fixture binds the host key
    /// to the Member for this one write and then gives it back to the owner.
    fn member_note(&self) -> String {
        bind_host_actor(&self.vault, &self.issuer, self.member, "human")
            .expect("the host key bound to the Member for its write");
        let note = self
            .vault
            .memory(self.member, EdgeActorClass::Human)
            .author_take(
                TakeTarget::Subject(self.subject),
                "a take about the subject",
            )
            .expect("the Member writes a NOTE")
            .id_hex;
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        note
    }

    fn deleted(&self, note: &str) -> bool {
        self.vault
            .is_deleted_shell(&EntityId::from_hex(note).expect("note id"))
            .expect("shell read")
    }

    /// A `human` credential this host mints `who`, holding `read` and
    /// `write`: not owner-grade.
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
        self.vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("a credential")
    }

    /// The owner's own slip, narrowed by its holder to `read` and `write`:
    /// it deletes on the owner's path.
    fn owner_credential(&self) -> CapabilitySlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root slip")
            .claims;
        claims.slip_id = next_slip_id();
        claims.parent_id = None;
        claims.holder_ref = self.owner.to_hex();
        claims.actor_class = Some("human".to_owned());
        claims.binding_key = holder_key().verifying_key().to_bytes();
        let mut slip = self
            .vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("the owner's slip");
        let mut narrowed = Scope::top();
        narrowed.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        slip.attenuate(
            SlipCaveat {
                scope: Some(narrowed),
                ..Default::default()
            },
            &holder_key(),
        )
        .expect("the owner narrows its own slip");
        slip
    }

    /// `slip` posts `POST /v1/core/memory/verbs/{verb}` with `body`: the
    /// status and the answer.
    async fn post(&self, slip: &CapabilitySlip, verb: &str, body: Value) -> (StatusCode, Value) {
        let binding =
            holder_proof(slip, &holder_key(), self.vault.now_recorded_at()).expect("holder proof");
        let request = Request::builder()
            .method("POST")
            .uri(format!("/v1/core/memory/verbs/{verb}"))
            .header(
                "Authorization",
                format!("Bearer {}", slip.to_token().expect("token")),
            )
            .header("x-oneiron-binding", binding.to_string())
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request");
        let response = build_app(Arc::clone(&self.server))
            .oneshot(request)
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

    /// The Owner approves pending check-in `id` over the effect it waits on,
    /// through `vault.check_in.answer`.
    fn owner_approves(&self, id: &str) {
        let row = self
            .vault
            .pending_check_in(&EntityId::from_hex(id).expect("a check-in id"))
            .expect("read the check-in")
            .expect("the check-in is stored");
        let digest: String = row
            .effect_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let settled = invoke(
            &self.vault.memory(self.owner, EdgeActorClass::Human),
            "vault.check_in.answer",
            json!({ "handle": id, "answer": "approve", "effect_digest": digest }),
        )
        .expect("the Owner answers");
        assert_eq!(
            settled["eligible"].as_str(),
            Some("approved"),
            "the Owner's approval makes the delete eligible: {settled}"
        );
    }

    /// Whether check-in `id` is spent.
    fn spent(&self, id: &str) -> bool {
        self.vault
            .pending_check_in(&EntityId::from_hex(id).expect("a check-in id"))
            .expect("read the check-in")
            .expect("stored")
            .consumed_at
            .is_some()
    }
}

/// The check-in a 202 `CHECK_IN_PENDING` answer names in its pending block.
fn pending_check_in(status: StatusCode, body: &Value) -> String {
    assert_eq!(status, StatusCode::ACCEPTED, "the delete waits: {body}");
    assert_eq!(body["error"]["code"], "CHECK_IN_PENDING", "{body}");
    assert_eq!(body["error"]["pending"]["kind"], "check_in", "{body}");
    body["error"]["pending"]["check_in"]
        .as_str()
        .expect("the pending block names the check-in")
        .to_owned()
}

/// A 400 naming `check_in_ref`.
fn assert_check_in_ref_refused(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("check_in_ref"),
        "the refusal names check_in_ref: {body}"
    );
}

#[test]
fn a_stewards_waiting_delete_finishes_on_the_route_with_its_approved_check_in() {
    run_on_engine_stack("steward-delete-check-in", || async {
        let fx = Served::new();
        let note = fx.member_note();
        let steward = fx.credential(fx.steward);

        let (status, body) = fx.post(&steward, "delete", json!({ "id": note })).await;
        let check_in = pending_check_in(status, &body);
        assert!(!fx.deleted(&note), "a waiting delete deletes nothing");

        let (status, body) = fx
            .post(
                &steward,
                "delete",
                json!({ "id": note, "check_in_ref": check_in }),
            )
            .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "an unanswered check-in runs nothing: {body}"
        );
        assert!(!fx.deleted(&note), "the early recall deletes nothing");

        fx.owner_approves(&check_in);
        let (status, body) = fx
            .post(
                &steward,
                "delete",
                json!({ "id": note, "check_in_ref": check_in }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the approved recall deletes: {body}"
        );
        assert_eq!(body["delete"]["existed"], true, "{body}");
        assert!(fx.deleted(&note), "the Steward's delete applied");
        assert!(fx.spent(&check_in), "the delete spent its check-in");
        let decision = &body["delete"]["check_in"];
        assert_eq!(decision["role"], "steward", "{body}");
        assert_eq!(decision["basis"], "approved", "{body}");
        assert_eq!(
            decision["check_in"], check_in,
            "the receipt names the check-in the delete spent: {body}"
        );
    });
}

#[test]
fn the_owners_delete_naming_a_check_in_is_refused_and_deletes_nothing() {
    run_on_engine_stack("owner-delete-check-in", || async {
        let fx = Served::new();
        let note = fx.member_note();
        let owner = fx.owner_credential();
        let (status, body) = fx
            .post(
                &owner,
                "delete",
                json!({ "id": note, "check_in_ref": "0123456789abcdef0123456789abcdef" }),
            )
            .await;
        assert_check_in_ref_refused(status, &body);
        assert!(!fx.deleted(&note), "the refused delete deletes nothing");

        let (status, body) = fx.post(&owner, "delete", json!({ "id": note })).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner's plain delete goes: {body}"
        );
        assert!(fx.deleted(&note), "the owner's delete applied");
    });
}

#[test]
fn a_retract_naming_a_check_in_is_refused() {
    run_on_engine_stack("retract-check-in", || async {
        let fx = Served::new();
        let note = fx.member_note();
        let member = fx.credential(fx.member);
        let (status, body) = fx
            .post(
                &member,
                "retract",
                json!({ "id": note, "check_in_ref": "0123456789abcdef0123456789abcdef" }),
            )
            .await;
        assert_check_in_ref_refused(status, &body);
    });
}
