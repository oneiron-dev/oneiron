//! An owner-grade generic batch states the agent definition switches it puts (R2d review
//! finding 4).
//!
//! The served owner `vault.batch` route commits at owner grade through the core lane. A batch
//! that turns a revoked definition back on states its switches in the vault's recorded owner's
//! name before it applies, as the owner's update door does, so the row reaches his other
//! installs.
#![cfg(all(feature = "sync", feature = "test-support"))]
#![allow(clippy::unwrap_used)]

use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope, encode_agent_definition};
use oneiron::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use oneiron::consent::AuthenticatedOwner;
use oneiron::core_write::{CoreBatchCommit, CoreWriteLane};
use oneiron::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_AUTHORITY_LOG};
use oneiron::store::GateDecisionId;
use oneiron::sync::FederationAdmissionRole;
use oneiron::sync::client::ImportTier;
use oneiron::sync::replay::{ReplicatedEntity, replay_entity};
use oneiron::temporal::TimeRange;
use oneiron::test_support::provision_act_carrier;
use oneiron::{EntityId, Vault, VaultConfig};

const T0: u64 = 1_773_532_800;

fn at(ts: u64) -> TimeRange {
    TimeRange { start: ts, end: ts }
}

fn running_definition() -> AgentDefinition {
    AgentDefinition::new(
        "custom.revocable",
        "Owner batch fixture",
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
            rmpv::Value::from("owner batch fixture"),
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

/// Catches an owner-grade generic batch turning a definition back on without stating its
/// switches: the batch lands here, no act is written, and the replicated row never reaches
/// the owner's other installs.
#[test]
fn an_owner_batch_turn_on_states_its_switches() {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::device()).unwrap();
    let (_issuer, person) = provision_act_carrier(&vault);
    let _owner = owner_proof(&vault, person);
    let id = EntityId::now();
    let on = turned_on(&revoked_at(&vault, id));
    let entries = authority_entries(&vault);
    let body = encode_agent_definition(&on).unwrap();
    vault
        .batch()
        .put(&id, ENTITY_TYPE_AGENT_DEF, at(T0), T0, &body)
        .commit_in_core_lane(&CoreWriteLane::Unbound, CoreBatchCommit::Owner, |_| Ok(()))
        .expect("the owner batch turns the definition back on");
    assert!(
        authority_entries(&vault) > entries,
        "the batch states the switches on the authority log"
    );
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(on.clone()));

    let off = next(&on, "1.0.3", |def| def.enabled = false);
    replay(
        &vault,
        &id,
        &off,
        ImportTier::Federated(FederationAdmissionRole::Member),
    )
    .expect("a peer turns the definition off again");
    replay(&vault, &id, &on, ImportTier::OwnDevice).expect("the stated row lands on replay");
    assert_eq!(vault.get_agent_definition(&id).unwrap(), Some(on));
}
