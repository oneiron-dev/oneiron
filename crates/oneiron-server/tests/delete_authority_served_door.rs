//! DEL-2 at the core HTTP delete (ARCH-0043, owner DEL-2 = A; Engine ruling
//! 13 Nov 02:51 = A). `POST /v1/core/memory/verbs/delete` deleted for any
//! token holding `core:write`. Now a token that is not owner-grade is judged
//! by the engine's one delete authority on its own resolved actor: a Member's
//! own NOTE, an agent under a Grant that names `delete`; anything else is a
//! typed 403 naming its reason. Owner-grade tokens are unchanged, and the
//! owner's own caveated slip still deletes on the owner's path.
//!
//! Red at the door's base (the engine half of DEL-2, the door unchanged): a
//! Member's token on another Member's NOTE, an agent with no delete Grant and
//! a token that names no actor each delete (200). Guards (pass there too):
//! the Member's own NOTE, the owner's caveated slip and the agent under a
//! delete Grant.
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! delete_authority_served_door`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use oneiron::authority::{ActSurface, CapabilitySlip, HostSlipIssuer, SlipCaveat, holder_proof};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember, Scope, ScopeAxis};
use oneiron::note::TakeTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_support::{bind_host_actor, bind_host_owner};
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const SHARED: u64 = 43;

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every credential here binds; the holder proves it per request.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x6D; 32])
}

/// A rooted server on its own device keystore, its host issuer, and the
/// vault's owner with an owner proof.
struct Served {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    owner: EntityId,
    owner_proof: AuthenticatedOwner,
    subject: EntityId,
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
                auth_secret: Some("delete-authority-served-door".to_owned()),
                ..Default::default()
            },
        )
        .expect("a rooted server"),
    );
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let owner_proof = proof(&vault, owner);
    let subject = EntityId::now();
    person(&vault, subject);
    Served {
        _dir: dir,
        server,
        vault,
        issuer,
        owner,
        owner_proof,
        subject,
    }
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

impl Served {
    /// A NOTE `author` writes about the subject, by its full hex ref.
    fn note_by(&self, author: EntityId) -> String {
        self.vault
            .memory(author, EdgeActorClass::Human)
            .author_take(
                TakeTarget::Subject(self.subject),
                "a take about the subject",
            )
            .expect("author a NOTE")
            .id_hex
    }

    fn deleted(&self, note: &str) -> bool {
        self.vault
            .is_deleted_shell(&EntityId::from_hex(note).expect("note id"))
            .expect("shell read")
    }

    /// A credential this host mints `who` at `class`, holding `read` and
    /// `write`: not owner-grade, as a member's or an agent's is not.
    fn credential(&self, who: EntityId, class: Option<&str>) -> CapabilitySlip {
        let mut claims = self
            .vault
            .ensure_host_root_slip(&self.issuer)
            .expect("the host root slip")
            .claims;
        claims.slip_id = next_slip_id();
        claims.parent_id = None;
        claims.holder_ref = who.to_hex();
        claims.actor_class = class.map(str::to_owned);
        claims.binding_key = holder_key().verifying_key().to_bytes();
        claims.scope.verbs =
            ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
        self.vault
            .mint_capability_slip(&self.issuer, claims)
            .expect("a credential")
    }

    /// The owner's own slip, narrowed by its holder to `read` and `write`.
    fn owner_caveated_credential(&self) -> CapabilitySlip {
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
        assert!(!slip.caveats.is_empty(), "the owner's slip is caveated");
        slip
    }

    /// `slip` posts the core delete of `note`: the status and the body.
    async fn delete(&self, slip: &CapabilitySlip, note: &str) -> (StatusCode, Value) {
        let binding =
            holder_proof(slip, &holder_key(), self.vault.now_recorded_at()).expect("holder proof");
        let response = build_app(Arc::clone(&self.server))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/core/memory/verbs/delete")
                    .header(
                        "Authorization",
                        format!("Bearer {}", slip.to_token().expect("token")),
                    )
                    .header("x-oneiron-binding", binding.to_string())
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({ "id": note }).to_string()))
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

/// A shared vault on the served vault: its owner and two Members, each
/// Member's founding invitation accepted.
struct SharedServed {
    served: Served,
    member_a: EntityId,
    member_b: EntityId,
}

fn shared_served() -> SharedServed {
    let served = served();
    let [member_a, member_b] = std::array::from_fn(|_| EntityId::now());
    for id in [member_a, member_b] {
        person(&served.vault, id);
    }
    let member = |member_ref, role| InitialSharedMember {
        member_ref,
        role: Some(role),
    };
    served
        .vault
        .initialize_shared_vault(
            &served.owner_proof,
            SHARED,
            None,
            &[
                member(served.owner, Role::Owner),
                member(member_a, Role::Member),
                member(member_b, Role::Member),
            ],
            1,
        )
        .expect("a shared vault with two Members");
    for id in [member_a, member_b] {
        let member_proof = proof(&served.vault, id);
        let invitation = served
            .vault
            .shared_invitations(&member_proof, SHARED)
            .expect("invitations")
            .into_iter()
            .find(|open| open.role == Role::Member)
            .expect("the founding invitation");
        served
            .vault
            .accept_shared_invitation(&member_proof, SHARED, &invitation.id)
            .expect("the Member accepts");
    }
    SharedServed {
        served,
        member_a,
        member_b,
    }
}

impl SharedServed {
    /// A NOTE Member A authors. A human binding is the owner's (H149), so the
    /// fixture binds the host key to the Member for this one write and then
    /// gives it back to the owner: the Member acts by its credential alone.
    fn member_note(&self) -> String {
        let served = &self.served;
        bind_host_actor(&served.vault, &served.issuer, self.member_a, "human")
            .expect("the host key bound to Member A for its write");
        let note = served.note_by(self.member_a);
        bind_host_owner(&served.vault, &served.issuer, served.owner)
            .expect("the owner's binding again");
        note
    }
}

/// An enabled agent the owner creates and gives one Grant naming `verbs`.
fn agent_with_grant(served: &Served, agent_id: &str, verbs: &[&str]) -> EntityId {
    let agent = EntityId::now();
    create_agent_definition_as(
        &served.vault,
        &served.owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Delete authority door test agent",
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
    assert!(minted.grant.confers, "{agent_id}: the Grant confers");
    agent
}

/// The 403 the engine's delete authority answers: FORBIDDEN, its message
/// leading with `reason`.
fn assert_refused(status: StatusCode, body: &Value, reason: &str) {
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"]["code"], "FORBIDDEN", "{body}");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.starts_with(&format!("{reason}:")),
        "the refusal names {reason}: {body}"
    );
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

#[test]
fn a_member_token_deletes_its_own_note() {
    on_engine_stack(|| async {
        let fx = shared_served();
        let note = fx.member_note();
        let token = fx.served.credential(fx.member_a, Some("human"));
        let (status, body) = fx.served.delete(&token, &note).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["delete"]["existed"], true, "{body}");
        assert!(
            fx.served.deleted(&note),
            "the Member's NOTE is a deleted shell"
        );
    });
}

#[test]
fn a_member_token_is_refused_another_members_note() {
    on_engine_stack(|| async {
        let fx = shared_served();
        let note = fx.member_note();
        let token = fx.served.credential(fx.member_b, Some("human"));
        let (status, body) = fx.served.delete(&token, &note).await;
        assert_refused(status, &body, "not_owner_of_item");
        assert!(!fx.served.deleted(&note), "the refused NOTE is untouched");
    });
}

#[test]
fn the_owners_caveated_slip_still_deletes() {
    on_engine_stack(|| async {
        let fx = served();
        let note = fx.note_by(fx.owner);
        let token = fx.owner_caveated_credential();
        let (status, body) = fx.delete(&token, &note).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["delete"]["existed"], true, "{body}");
        assert!(fx.deleted(&note), "the owner's NOTE is a deleted shell");
    });
}

#[test]
fn an_agent_token_under_a_delete_grant_deletes() {
    on_engine_stack(|| async {
        let fx = served();
        let agent = agent_with_grant(&fx, "door_delete_granted_agent", &["read", "delete"]);
        let note = fx.note_by(fx.owner);
        let token = fx.credential(agent, Some("agent"));
        let (status, body) = fx.delete(&token, &note).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["delete"]["existed"], true, "{body}");
        assert!(fx.deleted(&note), "the NOTE is a deleted shell");
    });
}

#[test]
fn an_agent_token_without_a_delete_grant_is_refused() {
    on_engine_stack(|| async {
        let fx = served();
        let agent = agent_with_grant(&fx, "door_read_only_agent", &["read"]);
        let note = fx.note_by(fx.owner);
        let token = fx.credential(agent, Some("agent"));
        let (status, body) = fx.delete(&token, &note).await;
        assert_refused(status, &body, "no_delete_grant");
        assert!(!fx.deleted(&note), "the refused NOTE is untouched");
    });
}

#[test]
fn a_token_that_names_no_actor_is_refused() {
    on_engine_stack(|| async {
        let fx = served();
        let note = fx.note_by(fx.owner);
        let token = fx.credential(fx.subject, None);
        let (status, body) = fx.delete(&token, &note).await;
        assert_refused(status, &body, "unresolved_actor");
        assert!(!fx.deleted(&note), "the refused NOTE is untouched");
    });
}
