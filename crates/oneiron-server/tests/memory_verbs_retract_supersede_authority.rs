//! The core memory route's `retract` and `supersede` judge their caller
//! (FIX-LIST LEGACY-MEMORY-VERB-RETRACT-SUPERSEDE-UNGUARDED).
//!
//! `POST /v1/core/memory/verbs/{retract,supersede}` ran the vault's lifecycle
//! mechanics for any credential whose slip allows the write verb: no actor,
//! no authorship check, and an operation time the caller chose. A scoped
//! agent, another agent or a member could close the owner's claim, or put
//! another claim in its place, and date the close in the past. Now:
//! - the vault owner (the owner's own slip, or the host root his CLI acts
//!   on) keeps the route's mechanics, `at` included;
//! - anyone else retracts as `vault.claims.retract` does, on its own resolved
//!   actor and at the vault's time: its own claim only, a request naming `at`
//!   refused;
//! - anyone else's supersede is refused: the route runs no gate and no
//!   deferred closure (ARCH-0040: a destructive supersede defers closure
//!   until approval), so they supersede through the gated claim doors.
//!
//! On main every `non_owner_*` case is red: the claim closes. The `owner_*`
//! and `agent_retracts_its_own_claim_at_the_vault_time` cases pass on both.
//!
//! The scoped agent is cut on verbs only. A slip cut on records, channels,
//! worlds or facets is refused before any verb runs, on main too
//! (`CoreAuth::require` asks an unrestricted record scope of a write), so
//! it never reaches these mechanics.
//!
//! Deterministic: one in-process vault, server and router per case
//! (`oneshot`). No model is configured and none is called.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --test memory_verbs_retract_supersede_authority`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::ClaimInput;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::{ClaimLifecycleStatus, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// A close time well before the vault's clock: a backdated retract.
const PAST: u64 = 1_700_000_000;

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
            auth_secret: Some("memory-verbs-retract-supersede".into()),
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

/// A live person of this vault who is not its owner.
fn person(vault: &Vault) -> EntityId {
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"member",
        )
        .expect("a live person");
    person
}

/// A credential a case presents: a slip and its holder's proof of
/// possession, fresh for each request.
struct Caller {
    slip: CapabilitySlip,
    /// The holder's key; `None` for the host root, which the host proves.
    key: Option<SigningKey>,
}

impl Caller {
    fn binding(&self, fx: &Fixture) -> String {
        let timestamp = fx.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = match &self.key {
            Some(key) => {
                let transcript = self
                    .slip
                    .binding_transcript(challenge.as_bytes())
                    .expect("binding transcript");
                key.sign(&transcript).to_bytes().to_vec()
            }
            None => fx
                .issuer
                .binding_proof(&self.slip, challenge.as_bytes())
                .expect("root holder proof"),
        };
        json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)}).to_string()
    }

    fn bearer(&self) -> String {
        format!("Bearer {}", self.slip.to_token().expect("slip token"))
    }
}

/// A live slip the host mints `holder` at `class` with `scope`.
fn slip(fx: &Fixture, holder: EntityId, class: &str, scope: Scope) -> Caller {
    let key = next_holder_key();
    let mut claims = fx.root.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some(class.to_owned());
    claims.binding_key = key.verifying_key().to_bytes();
    claims.scope = scope;
    let slip = fx
        .vault
        .mint_capability_slip(&fx.issuer, claims)
        .expect("a live slip");
    Caller {
        slip,
        key: Some(key),
    }
}

/// A registered agent of this vault on a full-vault slip, and its id.
fn full_agent(fx: &Fixture, name: &str) -> (EntityId, Caller) {
    let agent = fx
        .vault
        .ensure_agent_principal(name)
        .expect("a registered agent principal");
    assert_ne!(agent, fx.owner);
    (agent, slip(fx, agent, "agent", Scope::top()))
}

/// The callers that are not the owner, each named for its failure message:
/// a scoped agent (its slip names only the read and write verbs), an agent
/// on a full-vault slip, and a member on a full-vault slip.
fn non_owners(fx: &Fixture) -> Vec<(&'static str, Caller)> {
    let mut scoped = Scope::top();
    scoped.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let scoped_agent = fx
        .vault
        .ensure_agent_principal("memory-verbs-scoped-agent")
        .expect("a registered agent principal");
    vec![
        ("a scoped agent", slip(fx, scoped_agent, "agent", scoped)),
        (
            "an agent's full-vault slip",
            full_agent(fx, "memory-verbs-full-agent").1,
        ),
        (
            "a member's full-vault slip",
            slip(fx, person(&fx.vault), "human", Scope::top()),
        ),
    ]
}

/// The owner's credentials: his full slip on one of his devices, and the
/// host root his CLI acts on.
fn owner_callers(fx: &Fixture) -> [(&'static str, Caller); 2] {
    [
        (
            "the owner's device slip",
            slip(fx, fx.owner, "human", Scope::top()),
        ),
        (
            "the host root",
            Caller {
                slip: fx.root.clone(),
                key: None,
            },
        ),
    ]
}

fn claim_input(predicate: &str, subject: EntityId, value: &str, source: &str) -> ClaimInput {
    serde_json::from_value(json!({
        "predicate": predicate,
        "subject_ref": subject.to_hex(),
        "value": value,
        "confidence": 0.9,
        "source": source,
    }))
    .expect("claim input")
}

/// An active claim the owner wrote about himself, on `predicate`.
fn owners_claim(fx: &Fixture, predicate: &str, value: &str) -> EntityId {
    let receipt = fx
        .vault
        .memory(fx.owner, EdgeActorClass::Human)
        .with_owner_authorship(&owner_proof(fx))
        .claim_upsert(&claim_input(predicate, fx.owner, value, "user_stated"))
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

#[test]
fn non_owner_cannot_retract_the_owners_claim() {
    run_on_engine_stack("memory-verbs-retract-non-owner", || async {
        let fx = setup();
        for (name, caller) in non_owners(&fx) {
            let claim = owners_claim(&fx, "note.reviewed", name);
            let (status, body) =
                send(&fx, &caller, "retract", json!({ "id": claim.to_hex() })).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{name} retracts the owner's claim: {body}"
            );
            assert_eq!(
                life(&fx, claim),
                ClaimLifecycleStatus::Active,
                "{name} closed the owner's claim"
            );
        }
    });
}

#[test]
fn non_owner_cannot_supersede_the_owners_claim() {
    run_on_engine_stack("memory-verbs-supersede-non-owner", || async {
        let fx = setup();
        for (name, caller) in non_owners(&fx) {
            let old = owners_claim(&fx, "note.reviewed", name);
            let new = owners_claim(&fx, "profile.preference", name);
            let (status, body) = send(
                &fx,
                &caller,
                "supersede",
                json!({ "new_id": new.to_hex(), "old_id": old.to_hex() }),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{name} supersedes the owner's claim: {body}"
            );
            assert_eq!(
                life(&fx, old),
                ClaimLifecycleStatus::Active,
                "{name} closed the owner's claim"
            );
        }
    });
}

#[test]
fn non_owner_cannot_choose_the_retract_time() {
    run_on_engine_stack("memory-verbs-retract-at-non-owner", || async {
        let fx = setup();
        let (agent, caller) = full_agent(&fx, "memory-verbs-own-claim-agent");
        let receipt = fx
            .vault
            .memory(agent, EdgeActorClass::Agent)
            .claim_upsert(&claim_input("note.reviewed", fx.owner, "own", "observed"))
            .expect("the agent writes its own claim");
        let claim = oneiron::memory::resolve_entity_ref(&fx.vault, &receipt.claim_short_id)
            .expect("claim id");
        let (status, body) = send(
            &fx,
            &caller,
            "retract",
            json!({ "id": claim.to_hex(), "at": PAST }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an agent dates its retract in the past: {body}"
        );
        assert_eq!(
            life(&fx, claim),
            ClaimLifecycleStatus::Active,
            "the backdated retract closed the claim"
        );
    });
}

#[test]
fn agent_retracts_its_own_claim_at_the_vault_time() {
    run_on_engine_stack("memory-verbs-retract-own-claim", || async {
        let fx = setup();
        let (agent, caller) = full_agent(&fx, "memory-verbs-own-claim-agent");
        let receipt = fx
            .vault
            .memory(agent, EdgeActorClass::Agent)
            .claim_upsert(&claim_input("note.reviewed", fx.owner, "own", "observed"))
            .expect("the agent writes its own claim");
        let claim = oneiron::memory::resolve_entity_ref(&fx.vault, &receipt.claim_short_id)
            .expect("claim id");
        let before = fx.vault.now_recorded_at();
        let (status, body) = send(&fx, &caller, "retract", json!({ "id": claim.to_hex() })).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the agent retracts its own claim: {body}"
        );
        // The gate lands it, or parks it for the holder's consent (ARCH-0040
        // `mcp:5`); either way nothing closes before the vault's time.
        let stored = fx
            .vault
            .get_claim(&claim)
            .expect("claim read")
            .expect("stored");
        match stored.lifecycle {
            ClaimLifecycleStatus::Retracted => assert!(
                stored.valid_to.is_some_and(|to| to >= before),
                "the retract closed before the vault's time: {stored:?}"
            ),
            ClaimLifecycleStatus::Active => {}
            other => panic!("the agent's retract left the claim {other:?}: {body}"),
        }
    });
}

#[test]
fn owner_credentials_retract_and_supersede_on_the_owner_path() {
    run_on_engine_stack("memory-verbs-owner", || async {
        let fx = setup();
        for (name, caller) in owner_callers(&fx) {
            let retracted = owners_claim(&fx, "note.reviewed", name);
            let (status, body) = send(
                &fx,
                &caller,
                "retract",
                json!({ "id": retracted.to_hex(), "at": PAST }),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{name} retracts: {body}");
            assert_eq!(body["at"], json!(PAST), "{name}: {body}");
            assert_eq!(
                life(&fx, retracted),
                ClaimLifecycleStatus::Retracted,
                "{name} retracts the owner's claim"
            );

            let old = owners_claim(&fx, "note.reviewed", name);
            let new = owners_claim(&fx, "profile.preference", name);
            let (status, body) = send(
                &fx,
                &caller,
                "supersede",
                json!({ "new_id": new.to_hex(), "old_id": old.to_hex() }),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{name} supersedes: {body}");
            assert_eq!(
                life(&fx, old),
                ClaimLifecycleStatus::Superseded,
                "{name} supersedes the owner's claim"
            );
        }
    });
}
