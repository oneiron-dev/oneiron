//! The core memory route's owner `retract` and `supersede` check the owner's
//! proof again in the writer that commits them (FIX-LIST
//! MEMORY-VERB-OWNER-PROOF-NOT-REVALIDATED-AT-COMMIT), and so do its owner
//! `delete` and `hard_delete`, in each writer of the delete before its
//! publication (FIX-LIST MEMORY-DELETE-OWNER-PROOF-NOT-REVALIDATED-AT-COMMIT).
//!
//! `POST /v1/core/memory/verbs/{retract,supersede}` admits the vault owner
//! (`owner_routes::owner`) and then ran the vault's lifecycle mechanics in a
//! writer of their own, with no second look at the owner. A request admitted
//! on the owner's live slip that waited on that writer behind the slip's
//! revocation committed after it, at the `at` it chose. Now the owner path
//! hands its proof to `Vault::retract_claim_as_owner` and
//! `Vault::supersede_claim_as_owner`, which revalidate it inside the
//! committing writer, and the stale proof gets the owner door's 403.
//!
//! Each case registers one act at the route's owner path
//! (`oneiron_server::test_doors::memory_owner_commit`), after the owner check
//! and before the lifecycle door opens its writer. The act starts a thread
//! that opens the vault's writer, revokes in it every slip one holder holds
//! (`oneiron::test_doors::holder_slip_revoke`), and keeps it open for
//! [`HOLD`]; the act returns once that writer is held, so the route's writer
//! waits on the lock behind the uncommitted revocation.
//!
//! On the base (the #8073 head, with the same act run before its
//! `retract_claim` / `supersede_claim` call) both `*_revoked_behind_the_writer_*`
//! cases are red: the route answers 200 and the claim closes. The control
//! `an_owner_retract_behind_a_held_writer_with_no_revocation_lands` passes on
//! both: holding the writer and revoking nothing refuses nothing.
//!
//! The delete cases: the owner path ran the ungated
//! `Vault::delete_entity_with_reason` with the owner's proof dropped, and
//! took any full-vault slip as the owner's (`is_owner_grade`). Now it takes
//! the owner's proof (OWNER-GRADE-IS-NOT-OWNERSHIP, census H3) and deletes
//! through `Vault::delete_entity_with_reason_as_owner`, which re-proves it in
//! each writer before publication. On the red pin (main with this file, and
//! the same act run before the route's `delete_entity_with_reason`) both
//! `*_delete_revoked_behind_the_writer_*` cases and
//! `a_non_owner_full_vault_slip_deletes_nothing_on_the_owner_path` are red:
//! the route answers 200 and the NOTE is deleted. The control
//! `an_owner_delete_behind_a_held_writer_with_no_revocation_lands` passes on
//! both.
//!
//! Deterministic: the revocation is staged before the route's writer opens,
//! so the route's writer always sees it committed, whichever thread reaches
//! the lock first. One in-process vault, server and router per case
//! (`oneshot`). No model is configured and none is called.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test memory_verb_owner_proof_at_commit`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::Scope;
use oneiron::memory::ClaimInput;
use oneiron::note::TakeTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{ClaimLifecycleStatus, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

/// A close time well before the vault's clock: the owner's own `at`.
const PAST: u64 = 1_700_000_000;

/// How long the revoking thread keeps its writer open after the route's act
/// returns: the route reaches its own writer in that time and waits on it.
const HOLD: Duration = Duration::from_millis(300);

/// A distinct slip id for each credential a case mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// A distinct holder key for each credential a case mints.
fn next_holder_key() -> SigningKey {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    SigningKey::from_bytes(&[NEXT.fetch_add(1, Ordering::Relaxed); 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One self-hosted vault with its embedded owner and its served router.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    owner: EntityId,
}

fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    // The keystore goes in before the server: construction roots the vault.
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("this install's signing key");
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("memory-verb-owner-proof-at-commit".into()),
            ..Default::default()
        },
    )
    .expect("create server");
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("the host root slip");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let app = build_app(Arc::new(server));
    Fixture {
        _dir: dir,
        vault,
        app,
        issuer,
        root,
        owner,
    }
}

fn owner_proof(fx: &Fixture) -> AuthenticatedOwner {
    fx.vault
        .authenticate_owner(fx.owner, &fx.owner.to_hex(), true, GateDecisionId::now())
        .expect("the embedded owner authenticates")
}

/// A credential a case presents: a slip and its holder's proof of
/// possession, fresh for each request.
struct Caller {
    slip: CapabilitySlip,
    key: SigningKey,
}

impl Caller {
    fn binding(&self, fx: &Fixture) -> String {
        let timestamp = fx.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let transcript = self
            .slip
            .binding_transcript(challenge.as_bytes())
            .expect("binding transcript");
        let signature = self.key.sign(&transcript).to_bytes();
        json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)}).to_string()
    }

    fn bearer(&self) -> String {
        format!("Bearer {}", self.slip.to_token().expect("slip token"))
    }
}

/// The owner's full slip on one of his devices, minted live by the host.
fn owner_device_slip(fx: &Fixture) -> Caller {
    full_vault_slip(fx, fx.owner, "human")
}

/// A full-vault slip `holder` holds as a `class`, minted live by the host.
fn full_vault_slip(fx: &Fixture, holder: EntityId, class: &str) -> Caller {
    let key = next_holder_key();
    let mut claims = fx.root.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some(class.to_owned());
    claims.binding_key = key.verifying_key().to_bytes();
    claims.scope = Scope::top();
    let slip = fx
        .vault
        .mint_capability_slip(&fx.issuer, claims)
        .expect("a live slip");
    Caller { slip, key }
}

fn claim_input(predicate: &str, subject: EntityId, value: &str) -> ClaimInput {
    serde_json::from_value(json!({
        "predicate": predicate,
        "subject_ref": subject.to_hex(),
        "value": value,
        "confidence": 0.9,
        "source": "user_stated",
    }))
    .expect("claim input")
}

/// An active claim the owner wrote about himself, on `predicate`.
fn owners_claim(fx: &Fixture, predicate: &str, value: &str) -> EntityId {
    let receipt = fx
        .vault
        .memory(fx.owner, EdgeActorClass::Human)
        .with_owner_authorship(&owner_proof(fx))
        .claim_upsert(&claim_input(predicate, fx.owner, value))
        .expect("the owner writes a claim");
    let id =
        oneiron::memory::resolve_entity_ref(&fx.vault, &receipt.claim_short_id).expect("claim id");
    assert_eq!(life(fx, id), ClaimLifecycleStatus::Active);
    id
}

fn life(fx: &Fixture, id: EntityId) -> ClaimLifecycleStatus {
    fx.vault
        .get_claim(&id)
        .expect("claim read")
        .expect("the claim is stored")
        .lifecycle
}

/// A live person the vault knows who is not its owner.
fn person(fx: &Fixture) -> EntityId {
    let person = EntityId::now();
    fx.vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    assert_ne!(person, fx.owner, "the person is not the owner");
    person
}

/// A NOTE the owner wrote about a person.
fn owners_note(fx: &Fixture) -> EntityId {
    let subject = person(fx);
    let note = fx
        .vault
        .memory(fx.owner, EdgeActorClass::Human)
        .author_take(TakeTarget::Subject(subject), "the owner's own take")
        .expect("the owner writes a NOTE")
        .id_hex;
    let note = EntityId::from_hex(&note).expect("note id");
    assert!(live(fx, note), "the owner's NOTE is live");
    note
}

/// Whether `id` is still a live record: no delete shell, a body kept.
fn live(fx: &Fixture, id: EntityId) -> bool {
    !fx.vault.is_deleted_shell(&id).expect("shell read")
        && fx
            .vault
            .get(&id)
            .expect("record read")
            .is_some_and(|body| !body.is_empty())
}

async fn send(fx: &Fixture, caller: &Caller, verb: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(format!("/v1/core/memory/verbs/{verb}"))
        .header("authorization", caller.bearer())
        .header("x-oneiron-binding", caller.binding(fx))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    let response = fx.app.clone().oneshot(request).await.expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Registers the act at the route's next owner retract, supersede, delete or
/// hard delete: a thread opens the vault's writer and revokes in it every
/// slip `holder` holds, and the act returns once that writer is held, so the
/// route's own writer waits behind the uncommitted revocation. The receiver
/// answers the slip ids the thread revoked, once it committed.
fn revoke_behind_the_writer(fx: &Fixture, holder: EntityId) -> mpsc::Receiver<Vec<[u8; 32]>> {
    let (revoked_tx, revoked_rx) = mpsc::channel();
    let vault = Arc::clone(&fx.vault);
    oneiron_server::test_doors::memory_owner_commit::before_next_owner_commit(
        &fx.vault,
        move || {
            let (held_tx, held_rx) = mpsc::channel();
            std::thread::Builder::new()
                .name("revoke-behind-the-writer".into())
                .stack_size(ENGINE_THREAD_STACK_BYTES)
                .spawn(move || {
                    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
                    let revoked =
                        oneiron::test_doors::holder_slip_revoke::revoke_holder_slips_holding_writer(
                            &vault,
                            &issuer,
                            &holder.to_hex(),
                            || {
                                held_tx.send(()).expect("the route waits for the held writer");
                                std::thread::sleep(HOLD);
                            },
                        )
                        .expect("the holder's slips are revoked");
                    revoked_tx
                        .send(revoked)
                        .expect("the case reads the revoked ids");
                })
                .expect("the revoking thread starts");
            held_rx
                .recv()
                .expect("the writer is held with the revocation in it");
        },
    );
    revoked_rx
}

fn revoked_ids(revoked: &mpsc::Receiver<Vec<[u8; 32]>>) -> Vec<[u8; 32]> {
    revoked
        .recv_timeout(Duration::from_secs(30))
        .expect("the revoking thread committed")
}

#[test]
fn an_owner_retract_revoked_behind_the_writer_commits_nothing() {
    run_on_engine_stack("memory-verb-owner-retract-revoked", || async {
        let fx = setup();
        let caller = owner_device_slip(&fx);
        let claim = owners_claim(&fx, "note.reviewed", "retract");
        let revoked = revoke_behind_the_writer(&fx, fx.owner);
        let (status, body) = send(
            &fx,
            &caller,
            "retract",
            json!({ "id": claim.to_hex(), "at": PAST }),
        )
        .await;
        assert_eq!(
            revoked_ids(&revoked),
            vec![caller.slip.claims.slip_id],
            "the owner's device slip is revoked behind the writer"
        );
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a retract admitted on a slip revoked before its writer opened lands: {body}"
        );
        assert_eq!(
            life(&fx, claim),
            ClaimLifecycleStatus::Active,
            "the revoked owner credential closed the claim"
        );
    });
}

#[test]
fn an_owner_supersede_revoked_behind_the_writer_commits_nothing() {
    run_on_engine_stack("memory-verb-owner-supersede-revoked", || async {
        let fx = setup();
        let caller = owner_device_slip(&fx);
        let old = owners_claim(&fx, "note.reviewed", "supersede");
        let new = owners_claim(&fx, "profile.preference", "supersede");
        let revoked = revoke_behind_the_writer(&fx, fx.owner);
        let (status, body) = send(
            &fx,
            &caller,
            "supersede",
            json!({ "new_id": new.to_hex(), "old_id": old.to_hex(), "at": PAST }),
        )
        .await;
        assert_eq!(
            revoked_ids(&revoked),
            vec![caller.slip.claims.slip_id],
            "the owner's device slip is revoked behind the writer"
        );
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a supersede admitted on a slip revoked before its writer opened lands: {body}"
        );
        assert_eq!(
            life(&fx, old),
            ClaimLifecycleStatus::Active,
            "the revoked owner credential closed the old claim"
        );
        assert_eq!(
            life(&fx, new),
            ClaimLifecycleStatus::Active,
            "the new claim stays as it was"
        );
    });
}

#[test]
fn an_owner_retract_behind_a_held_writer_with_no_revocation_lands() {
    run_on_engine_stack("memory-verb-owner-retract-held", || async {
        let fx = setup();
        let caller = owner_device_slip(&fx);
        let claim = owners_claim(&fx, "note.reviewed", "control");
        // A holder that holds no slip: the writer is held, nothing revoked.
        let revoked = revoke_behind_the_writer(&fx, EntityId::now());
        let (status, body) = send(
            &fx,
            &caller,
            "retract",
            json!({ "id": claim.to_hex(), "at": PAST }),
        )
        .await;
        assert!(revoked_ids(&revoked).is_empty(), "nothing is revoked");
        assert_eq!(status, StatusCode::OK, "the owner retracts: {body}");
        assert_eq!(body["at"], json!(PAST), "the owner's time: {body}");
        assert_eq!(
            life(&fx, claim),
            ClaimLifecycleStatus::Retracted,
            "the owner retracts his claim behind a held writer"
        );
    });
}

/// One owner delete `verb` of his NOTE, with the owner's device slip revoked
/// behind the writer the delete's first write waits on.
async fn owner_delete_revoked_behind_the_writer(fx: &Fixture, verb: &str) {
    let caller = owner_device_slip(fx);
    let note = owners_note(fx);
    let revoked = revoke_behind_the_writer(fx, fx.owner);
    let (status, body) = send(fx, &caller, verb, json!({ "id": note.to_hex() })).await;
    assert_eq!(
        revoked_ids(&revoked),
        vec![caller.slip.claims.slip_id],
        "the owner's device slip is revoked behind the writer"
    );
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a {verb} admitted on a slip revoked before its writer opened lands: {body}"
    );
    assert!(
        live(fx, note),
        "the revoked owner credential's {verb} removed the NOTE"
    );
}

#[test]
fn an_owner_delete_revoked_behind_the_writer_deletes_nothing() {
    run_on_engine_stack("memory-verb-owner-delete-revoked", || async {
        let fx = setup();
        owner_delete_revoked_behind_the_writer(&fx, "delete").await;
    });
}

#[test]
fn an_owner_hard_delete_revoked_behind_the_writer_purges_nothing() {
    run_on_engine_stack("memory-verb-owner-hard-delete-revoked", || async {
        let fx = setup();
        owner_delete_revoked_behind_the_writer(&fx, "hard_delete").await;
    });
}

#[test]
fn an_owner_delete_behind_a_held_writer_with_no_revocation_lands() {
    run_on_engine_stack("memory-verb-owner-delete-held", || async {
        let fx = setup();
        let caller = owner_device_slip(&fx);
        let note = owners_note(&fx);
        // A holder that holds no slip: the writer is held, nothing revoked.
        let revoked = revoke_behind_the_writer(&fx, EntityId::now());
        let (status, body) = send(&fx, &caller, "delete", json!({ "id": note.to_hex() })).await;
        assert!(revoked_ids(&revoked).is_empty(), "nothing is revoked");
        assert_eq!(status, StatusCode::OK, "the owner deletes: {body}");
        assert_eq!(body["delete"]["existed"], json!(true), "{body}");
        assert!(
            fx.vault.is_deleted_shell(&note).expect("shell read"),
            "the owner deletes his NOTE behind a held writer"
        );
    });
}

#[test]
fn a_non_owner_full_vault_slip_deletes_nothing_on_the_owner_path() {
    run_on_engine_stack("memory-verb-non-owner-delete", || async {
        for class in ["human", "agent"] {
            let fx = setup();
            let holder = if class == "human" {
                person(&fx)
            } else {
                fx.vault
                    .ensure_agent_principal("memory-verb-owner-proof-agent")
                    .expect("a registered agent principal")
            };
            let caller = full_vault_slip(&fx, holder, class);
            let note = owners_note(&fx);
            let (status, body) = send(&fx, &caller, "delete", json!({ "id": note.to_hex() })).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a non-owner {class}'s full-vault slip deletes the owner's NOTE as the owner: {body}"
            );
            assert!(
                live(&fx, note),
                "a non-owner {class} deleted the owner's NOTE"
            );
        }
    });
}
