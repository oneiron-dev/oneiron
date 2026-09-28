use super::{AgentWakeSignals, WakeTurnSubject};
use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope, AgentWakeCadence, DreamingMode};
use crate::attempt_queue::AttemptQueue;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::config::VaultConfig;
use crate::dreamer_runner::{DreamerAttemptPayload, DreamerRunnerStore};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::temporal::TimeRange;
use rmpv::Value;

use super::{WakeGrain, request_turn_wake};

fn tick(vault: &crate::Vault, ordinal: u64, projection: Option<[u8; 32]>) -> Result<bool> {
    let outcome = request_turn_wake(
        &DreamerRunnerStore::new(vault),
        WakeTurnSubject::Vault,
        ordinal,
        projection,
        DreamerAttemptPayload {
            attempt_type: "micro".into(),
            input: Value::from("turn"),
            parent_attempt: None,
        },
        Some(format!("turn:{ordinal}")),
        None,
        ordinal,
    )?;
    Ok(outcome.is_some())
}

#[test]
fn two_vaults_have_independent_turn_grains_and_surprise_is_write_free() -> Result<()> {
    let (_first_dir, first) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let (_second_dir, second) = crate::test_util::open_test_vault_with(VaultConfig::device());
    assert_eq!(first.wake_grain()?, WakeGrain::new(1)?);
    second.set_wake_grain(&owner(&second)?, WakeGrain::new(3)?)?;
    assert_eq!(first.wake_grain()?.turns_per_wake, 1);
    assert_eq!(second.wake_grain()?.turns_per_wake, 3);
    let image = [1; 32];
    assert!(!tick(&first, 1, None)?);
    assert!(AttemptQueue::new(&first).list()?.is_empty());
    assert!(tick(&first, 1, Some(image))?);
    assert!(!tick(&second, 1, Some(image))?);
    assert!(!tick(&second, 2, Some(image))?);
    assert!(tick(&second, 3, Some(image))?);
    // No material is a no-op even on a due turn; repeated projection is too.
    let first_count = AttemptQueue::new(&first).list()?.len();
    let second_count = AttemptQueue::new(&second).list()?.len();
    assert!(!tick(&first, 2, None)?);
    assert!(!tick(&second, 6, Some(image))?);
    assert_eq!(AttemptQueue::new(&first).list()?.len(), first_count);
    assert_eq!(AttemptQueue::new(&second).list()?.len(), second_count);
    assert!(tick(&first, 3, Some([2; 32]))?);
    assert!(tick(&second, 9, Some([2; 32]))?);
    assert!(WakeGrain::new(0).is_err());
    Ok(())
}

#[test]
fn new_image_on_same_turn_cannot_be_swallowed_by_advisory_dedupe() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    assert!(tick(&vault, 1, Some([1; 32]))?);
    assert!(tick(&vault, 1, Some([2; 32]))?);
    assert_eq!(AttemptQueue::new(&vault).list()?.len(), 2);
    assert!(!tick(&vault, 1, Some([2; 32]))?);
    assert_eq!(AttemptQueue::new(&vault).list()?.len(), 2);
    Ok(())
}

fn owner(vault: &crate::Vault) -> Result<crate::consent::AuthenticatedOwner> {
    let actor = EntityId::now();
    vault.put_entity(
        &actor,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    vault.authenticate_owner(
        actor,
        &actor.to_hex(),
        true,
        crate::store::GateDecisionId::now(),
    )
}

fn agent(
    vault: &crate::Vault,
    dial: Option<AgentWakeCadence>,
    enabled: bool,
    off: bool,
) -> Result<EntityId> {
    let id = EntityId::now();
    let mut definition = AgentDefinition::new(
        format!("agent-{}", id.to_hex()),
        "Resident fixture",
        "1",
        None,
        vec![],
        vec![],
        vec![],
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
        Value::Map(vec![(Value::from("definedVia"), Value::from("test"))]),
        None,
        enabled,
        None,
    );
    definition.wake_cadence = dial;
    if off {
        definition.dreaming = Some(DreamingMode::Off);
    }
    vault.put_agent_definition(&id, &definition, TimeRange { start: 2, end: 2 }, 2)?;
    Ok(id)
}

fn agent_tick(
    vault: &crate::Vault,
    id: EntityId,
    ordinal: u64,
    signals: AgentWakeSignals,
    digest: u8,
) -> Result<bool> {
    let result = request_turn_wake(
        &DreamerRunnerStore::new(vault),
        WakeTurnSubject::Agent { id, signals },
        ordinal,
        Some([digest; 32]),
        DreamerAttemptPayload {
            attempt_type: "micro".into(),
            input: Value::from("agent-turn"),
            parent_attempt: None,
        },
        Some(format!("agent:{}:{ordinal}", id.to_hex())),
        None,
        ordinal,
    )?;
    Ok(result.is_some())
}

#[test]
fn stored_agent_dials_resolve_in_the_same_enqueue_as_the_vault_policy() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let proof = owner(&vault)?;
    vault.set_wake_grain(&proof, WakeGrain::new(3)?)?;
    let inherited = agent(
        &vault,
        Some(AgentWakeCadence::Companion { every_turns: None }),
        true,
        false,
    )?;
    let leader = agent(
        &vault,
        Some(AgentWakeCadence::Leader {
            every_turns: Some(2),
        }),
        true,
        false,
    )?;
    let slower = agent(
        &vault,
        Some(AgentWakeCadence::Leader {
            every_turns: Some(4),
        }),
        true,
        false,
    )?;
    let worker = agent(&vault, Some(AgentWakeCadence::Worker), true, false)?;
    let absent = agent(&vault, None, true, false)?;
    let disabled = agent(
        &vault,
        Some(AgentWakeCadence::Companion { every_turns: None }),
        false,
        false,
    )?;
    let off = agent(
        &vault,
        Some(AgentWakeCadence::Companion { every_turns: None }),
        true,
        true,
    )?;
    let none = AgentWakeSignals::default();
    assert!(!agent_tick(&vault, inherited, 2, none, 1)?);
    assert!(agent_tick(&vault, inherited, 3, none, 1)?);
    assert!(
        !agent_tick(&vault, leader, 2, none, 2)?,
        "vault floor narrows a faster agent dial"
    );
    assert!(agent_tick(&vault, leader, 3, none, 2)?);
    assert!(!agent_tick(&vault, slower, 3, none, 3)?);
    assert!(
        agent_tick(&vault, slower, 4, none, 3)?,
        "slower dial must not be gated again by vault modulo"
    );
    assert!(agent_tick(
        &vault,
        inherited,
        2,
        AgentWakeSignals {
            surprise: true,
            ..none
        },
        4
    )?);
    assert!(agent_tick(
        &vault,
        leader,
        2,
        AgentWakeSignals {
            agency: true,
            ..none
        },
        5
    )?);
    assert!(!agent_tick(
        &vault,
        leader,
        2,
        AgentWakeSignals {
            surprise: true,
            ..none
        },
        6
    )?);
    assert!(!agent_tick(
        &vault,
        worker,
        3,
        AgentWakeSignals {
            agency: true,
            surprise: true,
            ..none
        },
        6
    )?);
    assert!(agent_tick(
        &vault,
        worker,
        2,
        AgentWakeSignals {
            event: true,
            ..none
        },
        6
    )?);
    assert!(!agent_tick(&vault, absent, 3, none, 7)?);
    assert!(!agent_tick(
        &vault,
        disabled,
        3,
        AgentWakeSignals {
            event: true,
            ..none
        },
        7
    )?);
    assert!(!agent_tick(
        &vault,
        off,
        3,
        AgentWakeSignals {
            event: true,
            ..none
        },
        7
    )?);
    let mut policy = vault.dreamer_wake_policy()?;
    policy.agent_cadence.absent_role = super::AgentWakeRole::Companion;
    policy.agent_cadence.leader.agency = false;
    policy.agent_cadence.precedence = super::CadencePrecedence::AgentOverride;
    vault.set_dreamer_wake_policy(&proof, policy)?;
    assert!(
        agent_tick(&vault, absent, 3, none, 7)?,
        "absent role follows edited policy"
    );
    assert!(
        !agent_tick(
            &vault,
            leader,
            1,
            AgentWakeSignals {
                agency: true,
                ..none
            },
            8
        )?,
        "role trigger follows edited policy"
    );
    assert!(
        agent_tick(&vault, leader, 2, none, 8)?,
        "holder precedence edit may lift the vault floor"
    );
    Ok(())
}
