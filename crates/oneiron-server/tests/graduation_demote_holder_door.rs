//! A policy holder demotes a graduated ramp scope over the host door (census
//! L7-33; Engine RULING L7-33-HOLDER-ROUTE = A, Fri 13 Nov 18:23 JST).
//! `vault.consent.graduation.demote` took the owner's proof only. Its host
//! door now admits the owner under its proof, or a person on their own
//! verified slip who holds the ramp demotion policy power, as
//! `vault.gate.policy.put` admits a policy holder (FIX 8177). The engine's
//! demotion writer checks that power again in its own transaction.
//!
//! Red at the engine half's head (#7482), where the door's proof is the
//! owner's: the Admin holding the power is refused. Guard (passes there
//! too): a Member, and an Admin whose grant names no demotion target, are
//! refused and change nothing.
//!
//! The shipped grant rows give the `policy.change` verb to no role, so the
//! owner first lets the Admin role carry it through the hidden door
//! `oneiron::test_doors::consent_graduation_demotion`, built only under
//! `--cfg oneiron_test_support`. Run:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! graduation_demote_holder_door`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof};
use oneiron::consent::{ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, GrantBound};
use oneiron::consent_graduation::{RAMP_DEMOTE_GRANT_TARGET, RampScope};
use oneiron::federation::{FederationGrantRole as Role, InitialSharedMember, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::GateDecisionId;
use oneiron::test_doors::consent_graduation_demotion::admit_policy_verb;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const SHARED: u64 = 44;
const VERB: &str = "vault.consent.graduation.demote";

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

fn proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .expect("a person proof")
}

/// A rooted server on its own device keystore, holding a shared vault whose
/// roster is its embedded owner, an Admin and a Member, each of whom has
/// accepted a founding invitation. The owner's grant rows let the Admin role
/// carry the `policy.change` verb; with `power`, the owner also mints the
/// Admin the grant that names [`RAMP_DEMOTE_GRANT_TARGET`]. The owner has
/// graduated one agent's scope.
struct Served {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    admin: EntityId,
    member: EntityId,
    scope: RampScope,
}

fn served(power: bool) -> Served {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("vault"));
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("graduation-demote-holder-door".to_owned()),
                ..Default::default()
            },
        )
        .expect("a server"),
    );
    let issuer = vault.bootstrap_host_slip_issuer().expect("host issuer");
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let owner_proof = proof(&vault, owner);
    admit_policy_verb(&vault, &owner_proof, &[Role::Admin])
        .expect("the owner lets an Admin carry the policy verb");
    let admin = EntityId::now();
    let member = EntityId::now();
    person(&vault, admin);
    person(&vault, member);
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
                founding(owner, Role::Owner),
                founding(admin, Role::Admin),
                founding(member, Role::Member),
            ],
            1,
        )
        .expect("a shared vault with an Admin and a Member");
    for (id, role) in [(admin, Role::Admin), (member, Role::Member)] {
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
    if power {
        let bound = GrantBound::action(
            ActorBound::new(admin.to_hex())
                .and_then(|bound| bound.with_actor_class("human"))
                .expect("the Admin's bound"),
            ActionClass::new("policy.change").expect("the policy class"),
            ActionEnvelope::new(["owner_policy_rows".to_owned()])
                .and_then(|envelope| envelope.with_target(RAMP_DEMOTE_GRANT_TARGET))
                .expect("the demotion target"),
        )
        .expect("the policy grant bound");
        vault
            .create_standing_grant(&owner_proof, bound)
            .expect("the owner mints the Admin the demotion power");
    }
    let scope =
        RampScope::new("send_email", "client_followup", &EntityId::now().to_hex()).expect("scope");
    vault
        .create_standing_grant(&owner_proof, scope.to_grant_bound().expect("bound"))
        .expect("the owner graduates the agent's scope");
    Served {
        _dir: dir,
        server,
        vault,
        issuer,
        admin,
        member,
        scope,
    }
}

impl Served {
    /// A human credential this host mints `who`, holding `read` and `write`:
    /// a person's own slip, not owner-grade.
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

    fn grant_is_live(&self) -> bool {
        let grant_ref = self.scope.grant_ref().expect("grant ref");
        self.vault
            .consent_grant(&grant_ref)
            .expect("grant row")
            .is_some_and(|row| row.is_active())
    }

    /// `who` posts the demotion of the agent's scope to the host door: the
    /// status and the body.
    async fn demote_as(&self, who: EntityId) -> (StatusCode, Value) {
        let slip = self.credential(who);
        let binding =
            holder_proof(&slip, &holder_key(), self.vault.now_recorded_at()).expect("holder proof");
        let input = json!({
            "scope": {
                "op_kind": self.scope.op_kind,
                "target_class": self.scope.target_class,
                "actor": self.scope.actor,
            },
            "reason": "rejected",
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

/// An Admin whose Owner-minted grant names the demotion target demotes the
/// agent's graduated scope over the host door on its own slip: 200, and the
/// scope's standing grant is revoked. Red at #7482's head: the door's proof
/// was the owner's, so the Admin was refused 403.
#[test]
fn a_policy_holder_demotes_over_the_host_door() {
    on_engine_stack(|| async {
        let served = served(true);
        assert!(served.grant_is_live());
        let (status, body) = served.demote_as(served.admin).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a policy holder demotes over the host door: {body}"
        );
        assert!(
            !served.grant_is_live(),
            "the demotion revokes the scope's standing grant: {body}"
        );
    });
}

/// A Member, and an Admin that carries the policy verb but holds no grant
/// naming the demotion target, are each refused 403 at the host door, and
/// the scope's grant stays live.
#[test]
fn a_person_without_the_power_is_refused_at_the_host_door() {
    on_engine_stack(|| async {
        let served = served(false);
        for (who, person) in [
            ("a Member", served.member),
            ("an Admin with no grant naming the target", served.admin),
        ] {
            let (status, body) = served.demote_as(person).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{who} must not demote: {body}"
            );
            assert!(served.grant_is_live(), "{who}'s refusal leaves the grant");
        }
    });
}
