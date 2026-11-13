//! An owner-agent grant's end is wall time (census L7-18). DEC-0006's
//! duration amendment: an owner-set expiry on an owner-agent grant "ends on
//! wall time", and the house now.max(recording) rule judges it no earlier
//! than the recording clock. identity.md #slip-clocks keeps a credential's
//! own lifetime on the authority clock, which stops while the vault is
//! closed or its host sleeps. On main an agent grant's end was judged on
//! that authority clock at the owner's act door and at the vault.delete
//! agent arm, so a host that slept past the deadline still admitted the
//! agent. Now each is judged no earlier than the recording clock, as the
//! support grant is (`support_admission.rs`).
//!
//! Each test moves only the recording clock (a `ManualClock`, same handle,
//! no authority write after the move) and asserts the authority clock still
//! sits before the deadline. Red on main: the two refusal asserts. Guards
//! (pass on main too): each door admits before the wall deadline.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test agent_grant_expiry_wall_clock`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole, OwnerActKind};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError};
use oneiron::note::TakeTarget;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::ports::ManualClock;
use oneiron::task_verb::sdk::invoke;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use serde_json::json;

const T0: u64 = 1_800_000_000;
const GRANT_END: u64 = T0 + 100;

/// One personal vault on its own recording clock (the `personal()` shape of
/// `delete_authority.rs:324-353`, on a `ManualClock`): the owner, one agent
/// per test, and the subject PERSON the NOTEs are about. The vault drops
/// first.
struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    owner: EntityId,
    proof: AuthenticatedOwner,
    subject: EntityId,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let clock = ManualClock::new(T0);
        let dir = tempfile::tempdir().expect("vault directory");
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let vault = Vault::open(dir.path(), config).expect("vault on its manual clock");
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        // The owner's agent Grant act is carried by this install's live machine
        // profile (FIX 4648).
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let (owner, proof) = embedded_owner(&vault).expect("authenticated embedded owner");
        let subject = EntityId::now();
        vault
            .put_entity(
                &subject,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"human",
            )
            .expect("a live subject PERSON");
        Self {
            vault,
            clock,
            owner,
            proof,
            subject,
            _dir: dir,
        }
    }
}

/// An enabled agent the owner creates and gives one Grant naming `verbs`,
/// expiring at `expires_at` (`delete_authority.rs:355-398`, plus the expiry;
/// returns the agent and its Grant).
fn agent_with_grant(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    agent_id: &str,
    verbs: &[&str],
    expires_at: Option<u64>,
) -> (EntityId, EntityId) {
    let agent = EntityId::now();
    create_agent_definition_as(
        vault,
        owner_proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Agent grant expiry test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled, active agent definition");
    let grant = grant_agent(vault, owner_proof, agent, agent_id, verbs, expires_at);
    (agent, grant)
}

/// The owner gives `agent` one more Grant naming `verbs`, expiring at
/// `expires_at`; returns the Grant.
fn grant_agent(
    vault: &Vault,
    owner_proof: &AuthenticatedOwner,
    agent: EntityId,
    agent_id: &str,
    verbs: &[&str],
    expires_at: Option<u64>,
) -> EntityId {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    let minted = mint_agent_grant_as(
        vault,
        owner_proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent,
            authority_scope,
            expires_at,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the agent a Grant");
    assert!(
        minted.grant.confers,
        "{agent_id}: the Grant confers at its mint"
    );
    minted.grant.grant_ref
}

/// A NOTE `author` writes about `subject`, by its full hex ref.
fn note_by(vault: &Vault, author: EntityId, class: EdgeActorClass, subject: EntityId) -> String {
    vault
        .memory(author, class)
        .author_take(TakeTarget::Subject(subject), "a take about the subject")
        .expect("author a NOTE")
        .id_hex
}

fn deleted(vault: &Vault, note: &str) -> bool {
    vault
        .is_deleted_shell(&EntityId::from_hex(note).expect("note id"))
        .expect("shell read")
}

/// `agent` calls the `vault.delete` verb on `note`.
fn agent_deletes(
    vault: &Vault,
    agent: EntityId,
    note: &str,
) -> Result<serde_json::Value, MemoryError> {
    invoke(
        &vault.memory(agent, EdgeActorClass::Agent),
        "vault.delete",
        json!({ "entity_ref": note, "reason": "user_delete" }),
    )
}

/// An owner-agent grant's end is wall time at an owner act (DEC-0006
/// duration): the TopologySeal act the grant names is admitted before the
/// wall deadline and refused after it, even though the authority clock
/// still precedes the deadline.
#[test]
fn an_agent_grant_ends_on_wall_time_at_an_owner_act() {
    let fixture = Fixture::open();
    let (agent, grant) = agent_with_grant(
        &fixture.vault,
        &fixture.proof,
        "expiry_owner_act_agent",
        &["read", "topology_seal"],
        Some(GRANT_END),
    );

    fixture.clock.set(T0 + 10);
    let admitted = fixture
        .vault
        .granted_act(agent, grant, OwnerActKind::TopologySeal);
    assert!(
        admitted.is_ok(),
        "guard: the live owner-agent grant names TopologySeal before its wall deadline: {admitted:?}"
    );

    // Same handle, no reopen or authority write: only recording time moves.
    fixture.clock.set(T0 + 10_000);
    assert!(
        fixture
            .vault
            .capability_slip_now()
            .expect("authority clock")
            < GRANT_END,
        "the authority clock must still precede the grant's deadline"
    );
    let refused = fixture
        .vault
        .granted_act(agent, grant, OwnerActKind::TopologySeal);
    assert!(
        refused.is_err(),
        "the owner-agent grant ends on wall time at its owner act, even though the authority clock has not reached its end: {refused:?}"
    );
}

/// An owner-agent grant's end is wall time at vault.delete (DEC-0006
/// duration): the agent deletes under its grant before the wall deadline,
/// and its delete is refused after, the NOTE untouched, even though the
/// authority clock still precedes the deadline.
///
/// The `delete` Grant expires; a separate `read` Grant has no end, so the
/// NOTE still resolves for the agent after the deadline and the refusal
/// comes from the delete arm itself. One expiring Grant naming both verbs
/// would be refused earlier, at `entity_ref` resolution, once its `read`
/// ends (INVENTED_REFERENCE).
#[test]
fn an_agent_grant_ends_on_wall_time_at_vault_delete() {
    let fixture = Fixture::open();
    let (agent, _) = agent_with_grant(
        &fixture.vault,
        &fixture.proof,
        "expiry_delete_agent",
        &["read"],
        None,
    );
    grant_agent(
        &fixture.vault,
        &fixture.proof,
        agent,
        "expiry_delete_agent",
        &["delete"],
        Some(GRANT_END),
    );
    // A `user_delete` may write: both NOTEs exist before the clock moves,
    // so nothing writes after the move except the judged call.
    let first = note_by(
        &fixture.vault,
        fixture.owner,
        EdgeActorClass::Human,
        fixture.subject,
    );
    let second = note_by(
        &fixture.vault,
        fixture.owner,
        EdgeActorClass::Human,
        fixture.subject,
    );

    fixture.clock.set(T0 + 10);
    agent_deletes(&fixture.vault, agent, &first).unwrap_or_else(|error| {
        panic!("guard: the agent deletes under its live Grant before the wall deadline: {error:?}")
    });
    assert!(
        deleted(&fixture.vault, &first),
        "the guard delete scrubs its NOTE"
    );

    // Same handle, no reopen or authority write: only recording time moves.
    fixture.clock.set(T0 + 10_000);
    assert!(
        fixture
            .vault
            .capability_slip_now()
            .expect("authority clock")
            < GRANT_END,
        "the authority clock must still precede the grant's deadline"
    );
    let error = agent_deletes(&fixture.vault, agent, &second).expect_err(
        "the owner-agent grant ends on wall time at vault.delete, even though the authority clock has not reached its end",
    );
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN, "{error:?}");
    assert!(
        error.message.starts_with("no_delete_grant:"),
        "the refusal names its reason: {error:?}"
    );
    assert!(
        !deleted(&fixture.vault, &second),
        "the refused NOTE is untouched"
    );
}
