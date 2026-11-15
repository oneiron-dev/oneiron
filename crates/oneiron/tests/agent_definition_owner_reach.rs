//! What the owner's agent definition edit answers about his other installs (Fable pass 28
//! R2d; Engine RULING R2D-NO-CARRIER-POLICY = B, 16 Nov 06:59). His door states the switches
//! a turn-on writes on the vault's authority log, so his other installs land it. On an install
//! that cannot carry that statement the edit still lands here, no act is written, and his
//! answer says the change is saved on this device only; another install holds the synced row
//! waiting.
#![cfg(all(feature = "sync", feature = "test-support"))]
#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use oneiron::agent_def::encode_agent_definition;
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope, AgentSwitchesReach};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_AUTHORITY_LOG};
use oneiron::store::GateDecisionId;
use oneiron::sync::FederationAdmissionRole;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::temporal::TimeRange;
use oneiron::test_support::provision_act_carrier;
use oneiron::{EntityId, ErrorKind, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;

const T0: u64 = 1_773_532_800;

fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn running_definition() -> AgentDefinition {
    AgentDefinition::new(
        "custom.revocable",
        "Revocation fixture",
        "1.0.0",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![(
            rmpv::Value::from("definedVia"),
            rmpv::Value::from("owner reach fixture"),
        )]),
        None,
        true,
        None,
    )
}

fn next(
    definition: &AgentDefinition,
    version: &str,
    edit: impl FnOnce(&mut AgentDefinition),
) -> AgentDefinition {
    let mut next = definition.clone();
    next.version = version.to_owned();
    edit(&mut next);
    next
}

fn replay(
    vault: &Vault,
    id: &EntityId,
    definition: &AgentDefinition,
    tier: ImportTier,
) -> oneiron::Result<()> {
    let body = encode_agent_definition(definition).unwrap();
    replay_entity(
        vault,
        ReplicatedEntity {
            id: *id,
            entity_type: ENTITY_TYPE_AGENT_DEF,
            occurred: at(T0),
            learned_at: T0,
            row_version: 0,
            body: &body,
        },
        tier,
    )
}

/// An install of a fresh vault with its keystore and signing loaded, and no machine profile
/// in the vault's roster: it carries no act.
fn plain_install(dir: &std::path::Path) -> Vault {
    let vault = Vault::open(dir, VaultConfig::device()).unwrap();
    vault.install_device_keystore(Arc::new(MemoryKeystore::default()));
    vault.prepare_install_signing().unwrap();
    vault
}

fn owner_proof(vault: &Vault, person: EntityId) -> AuthenticatedOwner {
    vault
        .authenticate_owner(person, &person.to_hex(), true, GateDecisionId::now())
        .unwrap()
}

/// The definition seeded running at `id`, then turned off by a federation member (a peer's
/// restrictive move lands).
fn revoked_at(vault: &Vault, id: EntityId) -> AgentDefinition {
    let running = running_definition();
    vault
        .put_agent_definition(&id, &running, at(T0), T0)
        .unwrap();
    let revoked = next(&running, "1.0.1", |def| {
        def.enabled = false;
        def.approval_status = ClaimApprovalStatus::Rejected;
        def.lifecycle_status = ClaimLifecycleStatus::Retracted;
    });
    replay(
        vault,
        &id,
        &revoked,
        ImportTier::Federated(FederationAdmissionRole::Member),
    )
    .expect("a peer turns a definition off");
    revoked
}

fn turned_on(revoked: &AgentDefinition) -> AgentDefinition {
    next(revoked, "1.0.2", |def| {
        def.enabled = true;
        def.approval_status = ClaimApprovalStatus::Approved;
        def.lifecycle_status = ClaimLifecycleStatus::Active;
    })
}

fn authority_entries(vault: &Vault) -> u64 {
    vault
        .count_entities_by_type(ENTITY_TYPE_AUTHORITY_LOG)
        .unwrap()
}

/// Catches the owner's door refusing his turn-on on an install that cannot carry its
/// statement, writing an act it could not count, or answering as if every install had it.
#[test]
fn an_owner_turn_on_with_no_carrier_lands_here_alone() {
    let dir = tempfile::tempdir().unwrap();
    let vault = plain_install(dir.path());
    let person = vault.ensure_embedded_owner_actor().unwrap();
    let owner = owner_proof(&vault, person);
    let id = EntityId::now();
    let on = turned_on(&revoked_at(&vault, id));
    let entries = authority_entries(&vault);
    let reach = vault
        .update_agent_definition_as(&owner, &id, &on, at(T0), T0)
        .expect("the owner's turn-on lands here");
    assert_eq!(reach, AgentSwitchesReach::ThisInstallOnly);
    assert!(
        reach
            .notice()
            .is_some_and(|notice| notice.contains("this device only")),
        "the owner's answer says so: {:?}",
        reach.notice()
    );
    assert_eq!(authority_entries(&vault), entries, "no act is written");
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(on.clone()));

    let second_dir = tempfile::tempdir().unwrap();
    let second = plain_install(second_dir.path());
    let held = revoked_at(&second, id);
    let replayed = replay(&second, &id, &on, ImportTier::OwnDevice);
    assert_eq!(
        replayed.as_ref().err().map(oneiron::Error::kind),
        Some(ErrorKind::InvalidAgentDefBody),
        "the second install holds the synced turn-on waiting: {replayed:?}"
    );
    assert_eq!(second.get_agent_definition(&id).unwrap(), Some(held));
}

/// Catches a notice on an edit that reached every install: on an install that carries acts
/// the turn-on is stated, and the answer carries none.
#[test]
fn an_owner_turn_on_on_a_carrying_install_reaches_every_install() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let (_issuer, person) = provision_act_carrier(&vault);
    let owner = owner_proof(&vault, person);
    let id = EntityId::now();
    let on = turned_on(&revoked_at(&vault, id));
    let entries = authority_entries(&vault);
    let reach = vault
        .update_agent_definition_as(&owner, &id, &on, at(T0), T0)
        .expect("the owner's turn-on");
    assert_eq!(reach, AgentSwitchesReach::EveryInstall);
    assert_eq!(reach.notice(), None);
    assert!(
        authority_entries(&vault) > entries,
        "the turn-on is stated on the authority log"
    );
    let reworded = next(&on, "1.0.3", |def| {
        def.desc = "Revocation fixture, reworded".to_owned();
    });
    assert_eq!(
        vault
            .update_agent_definition_as(&owner, &id, &reworded, at(T0), T0)
            .expect("the owner rewords it"),
        AgentSwitchesReach::EveryInstall,
        "an edit that moves no switch needs no statement"
    );
}

/// Catches the no-carrier save-again recovery writing no statement: the owner's turn-on lands
/// here alone with no carrier, the install gains one, and saving the same switches again
/// appends nothing, so the other install waits forever.
#[test]
fn a_save_again_after_a_carrier_arrives_states_the_switches() {
    let dir = tempfile::tempdir().unwrap();
    let vault = plain_install(dir.path());
    let person = vault.ensure_embedded_owner_actor().unwrap();
    let owner = owner_proof(&vault, person);
    let id = EntityId::now();
    let on = turned_on(&revoked_at(&vault, id));
    let reach = vault
        .update_agent_definition_as(&owner, &id, &on, at(T0), T0)
        .expect("the owner's turn-on lands here");
    assert_eq!(reach, AgentSwitchesReach::ThisInstallOnly);
    let entries = authority_entries(&vault);
    // The install gains a carrier without a second keystore: the engine's machines, its live
    // profile and the owner's binding under the host root.
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault
        .ensure_serving_install_profile(&issuer, oneiron::authority::MachineRole::Unanswered)
        .expect("this install's live machine profile, to carry acts");
    oneiron::test_support::bind_host_owner(&vault, &issuer, person).expect("owner binding");
    let owner = owner_proof(&vault, person);
    let again = next(&on, "1.0.3", |_| {});
    vault
        .update_agent_definition_as(&owner, &id, &again, at(T0), T0)
        .expect("the owner saves the same switches again");
    assert!(
        authority_entries(&vault) > entries,
        "the save again states the switches on the authority log"
    );
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(again));
}
