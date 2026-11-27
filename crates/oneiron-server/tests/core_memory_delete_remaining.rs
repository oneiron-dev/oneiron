//! The HTTP owner delete answers what remains, and `restricted` for a record
//! the owner chose to restrict (FIX
//! HARD-DELETE-ANSWER-SILENT-ON-OWED-SWEEP and
//! FIX HARD-DELETE-RESTRICTED-ANSWERS-NOT-FOUND, Engine ruling 27 Nov).
//!
//! - `http_owner_hard_delete_answer_lists_the_history_sweep`: the owner's
//!   `hard_delete` lists `history_sweep` then `backups_before_delete`, both
//!   in the ruling's words.
//! - `http_owner_delete_of_a_restricted_record_answers_409_restricted`: the
//!   owner's `hard_delete` of a restricted record answers 409 with the
//!   `restricted` state and the ruling's words.
//! - `facade_owner_delete_of_a_restricted_record_answers_409`: the owner's
//!   `vault.delete` through the facade answers that refusal 409 with the
//!   `restricted` code, not a server fault.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! core_memory_delete_remaining`.
#![cfg(oneiron_test_support)]
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
/// owner, a Member who accepted, and a subject PERSON the NOTEs are about.
struct Served {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    owner: EntityId,
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
                    auth_secret: Some("core-memory-delete-remaining".to_owned()),
                    ..Default::default()
                },
            )
            .expect("a server"),
        );
        let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
        let owner = vault.ensure_embedded_owner_actor().expect("owner");
        let [member, subject] = std::array::from_fn(|_| EntityId::now());
        for id in [member, subject] {
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
                &[founding(owner, Role::Owner), founding(member, Role::Member)],
                1,
            )
            .expect("a shared vault with a Member");
        for (id, role) in [(member, Role::Member)] {
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
            member,
            subject,
        }
    }

    /// A NOTE the Member writes about the subject, by its full hex ref. A
    /// human binding is the owner's (H149), so the fixture binds the host key
    /// to the author for this one write and then gives it back to the owner.
    fn member_note(&self) -> String {
        bind_host_actor(&self.vault, &self.issuer, self.member, "human")
            .expect("the host key bound to the author for its write");
        let note = self
            .vault
            .memory(self.member, EdgeActorClass::Human)
            .author_take(
                TakeTarget::Subject(self.subject),
                "a take about the subject",
            )
            .expect("the author writes a NOTE")
            .id_hex;
        bind_host_owner(&self.vault, &self.issuer, self.owner).expect("the owner's binding again");
        note
    }

    fn deleted(&self, note: &str) -> bool {
        self.vault
            .is_deleted_shell(&EntityId::from_hex(note).expect("note id"))
            .expect("shell read")
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
        self.post_to(slip, &format!("/v1/core/memory/verbs/{verb}"), body)
            .await
    }

    /// `slip` posts `POST /v1/core/facade/{verb}` with `body`: the status
    /// and the answer.
    async fn post_facade(
        &self,
        slip: &CapabilitySlip,
        verb: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        self.post_to(slip, &format!("/v1/core/facade/{verb}"), body)
            .await
    }

    /// `slip` posts `POST {uri}` with `body`, proving its holder key: the
    /// status and the answer.
    async fn post_to(&self, slip: &CapabilitySlip, uri: &str, body: Value) -> (StatusCode, Value) {
        let binding =
            holder_proof(slip, &holder_key(), self.vault.now_recorded_at()).expect("holder proof");
        let request = Request::builder()
            .method("POST")
            .uri(uri)
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
}

#[test]
fn http_owner_hard_delete_answer_lists_the_history_sweep() {
    run_on_engine_stack("owner-hard-delete-remaining", || async {
        let fx = Served::new();
        let note = fx.member_note();
        let owner = fx.owner_credential();
        let (status, body) = fx.post(&owner, "hard_delete", json!({ "id": note })).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(fx.deleted(&note), "the owner's hard delete applied");
        let remaining = &body["delete"]["remaining"];
        assert_eq!(
            remaining.as_array().map(Vec::len),
            Some(2),
            "two remainders: {body}"
        );
        assert_eq!(remaining[0]["code"], "history_sweep", "{body}");
        assert_eq!(
            remaining[0]["text"],
            "Removed now. Older copies in this vault's sync history are cleared by a background sweep, and the receipt shows when that is done.",
            "{body}"
        );
        assert_eq!(remaining[1]["code"], "backups_before_delete", "{body}");
        assert_eq!(
            remaining[1]["text"],
            "Backups made before this delete still hold it, and restoring one brings it back.",
            "{body}"
        );
    });
}

#[test]
fn http_owner_delete_of_a_restricted_record_answers_409_restricted() {
    run_on_engine_stack("owner-delete-restricted", || async {
        let fx = Served::new();
        let note = fx.member_note();
        oneiron::test_doors::campaign_member_index::restrict_record(
            &fx.vault,
            EntityId::from_hex(&note).expect("note id"),
        )
        .expect("FIXTURE: restrict the note");
        let owner = fx.owner_credential();
        let (status, body) = fx.post(&owner, "hard_delete", json!({ "id": note })).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"]["code"], "INVALID_STATE", "{body}");
        assert_eq!(body["error"]["details"]["state"], "restricted", "{body}");
        assert_eq!(
            body["error"]["message"],
            "This record is restricted: you chose to keep it stored and unused in answer to a deletion request. Lift the restriction to delete it.",
            "{body}"
        );
    });
}

#[test]
fn facade_owner_delete_of_a_restricted_record_answers_409() {
    run_on_engine_stack("facade-owner-delete-restricted", || async {
        let fx = Served::new();
        let note = fx.member_note();
        oneiron::test_doors::campaign_member_index::restrict_record(
            &fx.vault,
            EntityId::from_hex(&note).expect("note id"),
        )
        .expect("FIXTURE: restrict the note");
        let owner = fx.owner_credential();
        let (status, body) = fx
            .post_facade(
                &owner,
                "vault.delete",
                json!({ "entity_ref": note, "reason": "user_hard_delete" }),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["error"]["code"], "restricted", "{body}");
    });
}
