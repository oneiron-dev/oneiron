//! Census cases for what a task, an ask and an agent may do.
use super::Case;
use crate::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use crate::agent_dispatch::{ResidentAgentSpec, ResidentGoalRecord, ResidentWakeMode};
use crate::channel_identity::{ChannelIdentityBinding, ChannelIdentityState, SelfHeldShape};
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSource};
use crate::consent::{ActionClass, ActionEnvelope, ActorBound, GrantBound};
use crate::deletion::DeleteEntityOptions;
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::habit::{TaskRole, task_body_for_test};
use crate::memory::{MemoryError, WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TASK, ENTITY_TYPE_TURN};
use crate::store::GateDecisionId;
use crate::task_authority::{
    TaskAuthorityFact, TaskAuthorityFactKind, put_task_authority_fact_in_txn,
};
use crate::task_verb::{
    ConsultPayloadRef, TaskAskDefault, TaskAskQuestion, TaskAskSpec, TaskAskTarget,
};
use crate::test_util::entity;
use crate::{EntityId, Error, Result, TimeRange, Vault, VaultConfig};
use rmpv::Value;
use std::collections::BTreeSet;

/// A vault as the engine opens one, its shipped policy manifest in force.
fn open_vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default()).expect("open vault");
    (dir, vault)
}

/// The engine error for a refusal a memory door gives.
fn memory(error: MemoryError) -> Error {
    Error::InvalidConfig(error.message)
}

fn put_person(vault: &Vault, id: EntityId) -> Result<()> {
    vault.put_entity(
        &id,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"person",
    )
}

/// A turn saying `role`, as of `at`.
fn put_turn(vault: &Vault, id: EntityId, role: &str, at: u64) -> Result<()> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("role"), Value::from(role))]),
    )
    .expect("encode a turn body");
    vault.put_entity(
        &id,
        ENTITY_TYPE_TURN,
        TimeRange { start: at, end: at },
        at,
        &body,
    )
}

/// Mints one authority fact about `task`, with the `ScopedTo` edge it is
/// read through.
fn mint(
    vault: &Vault,
    task: EntityId,
    kind: TaskAuthorityFactKind,
    actor: EntityId,
) -> Result<EntityId> {
    vault.with_write_txn(|txn| {
        put_task_authority_fact_in_txn(
            vault,
            txn,
            TaskAuthorityFact {
                task_ref: task,
                kind,
                actor_ref: actor,
                assigned_ref: None,
                occurred_at: 10,
            },
        )
    })
}

/// A task, with the fact that proves `owner` owns it.
fn put_task(vault: &Vault, task: EntityId, owner: EntityId) -> Result<()> {
    vault.put_entity(
        &task,
        ENTITY_TYPE_TASK,
        TimeRange { start: 10, end: 10 },
        10,
        &task_body_for_test(TaskRole::Task),
    )?;
    mint(vault, task, TaskAuthorityFactKind::Owner, owner).map(drop)
}

/// An approved, active definition whose own ceiling lets its agent act
/// without asking, forked from `parent` when one is named.
fn put_agent(vault: &Vault, id: EntityId, parent: Option<EntityId>, enabled: bool) -> Result<()> {
    let definition = AgentDefinition::new(
        format!("census-{}", id.to_hex()),
        "census fixture",
        "1",
        None,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::All,
        AgentCeiling::Auto,
        parent,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::Imported,
        1.0,
        false,
        true,
        Value::Map(vec![(Value::from("fixture"), Value::from("census"))]),
        None,
        enabled,
        None,
    );
    vault.put_agent_definition(&id, &definition, TimeRange { start: 10, end: 10 }, 10)
}

/// A task's cancellation is read through the `ScopedTo` edge that reaches
/// its fact. A cancellation whose edge reached the task only since the
/// backup, its body unchanged, is one a restore would lift; a task made
/// since changes nothing.
pub(super) fn task_authority() -> Result<Case> {
    let (dir, vault) = open_vault();
    let (owner, task) = (entity(0xC1), entity(0xC2));
    put_person(&vault, owner)?;
    put_task(&vault, task, owner)?;
    let cancelled = mint(&vault, task, TaskAuthorityFactKind::Cancelled, owner)?;
    vault.delete_edge(&cancelled, EdgeKind::ScopedTo, &task)?;
    Case::after_backup(
        "task owners and cancellations",
        (dir, vault),
        move |vault| put_task(vault, entity(0xC3), owner),
        move |vault| vault.put_edge(&cancelled, EdgeKind::ScopedTo, &task, 0.7),
    )
}

/// An ask whose question was edited since the backup is stale. A restore
/// would bring the question's old bytes back, and the ask with them.
pub(super) fn stale_asks() -> Result<Case> {
    let (dir, vault) = open_vault();
    let owner = vault.ensure_embedded_owner_actor().map_err(memory)?;
    let (person, question) = (entity(0x61), entity(0x62));
    put_person(&vault, person)?;
    put_turn(&vault, question, "question", 10)?;
    vault
        .memory(owner, EdgeActorClass::Human)
        .tasks_ask(&TaskAskSpec::shorthand(
            Some(TaskAskTarget::People(BTreeSet::from([person]))),
            TaskAskQuestion::new(ConsultPayloadRef::Turn(question)),
            Some(crate::unix_seconds_now() + 3_600),
            TaskAskDefault::AskMe,
        ))
        .map_err(memory)?;
    Case::after_backup(
        "stale task asks",
        (dir, vault),
        |vault| put_turn(vault, entity(0x63), "aside", 20),
        move |vault| put_turn(vault, question, "revised question", 30),
    )
}

/// A definition deleted since the backup keeps its shell, and the
/// dispatcher no longer runs it. A restore would bring its body back; one
/// made since changes nothing.
pub(super) fn dispatchable_agents() -> Result<Case> {
    let (dir, vault) = open_vault();
    let worker = crate::test_util::seed_agent_definition(&vault, entity(0x81), "worker");
    Case::after_backup(
        "dispatchable agents",
        (dir, vault),
        |vault| {
            crate::test_util::seed_agent_definition(vault, entity(0x82), "helper");
            Ok(())
        },
        move |vault| vault.delete_entity(&worker).map(drop),
    )
}

/// A resident's binding holds only while its goal records resolve. A goal
/// erased since the backup leaves it void, its claim unchanged; a restore
/// would bring the goal back, and the wake with it.
pub(super) fn resident_wakes() -> Result<Case> {
    let (dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let (owner, inbox) = (EntityId::now(), EntityId::now());
    put_person(&vault, owner)?;
    let agent = crate::test_util::seed_agent_definition(&vault, EntityId::now(), "resident");
    vault.create_channel_identity(
        &inbox,
        &crate::test_util::self_held_identity_in_state(
            "email",
            "resident@example.com",
            SelfHeldShape::DedicatedAddress,
            ChannelIdentityBinding::agent(agent),
            ChannelIdentityState::Active,
            1,
        ),
    )?;
    let (room, node, goal) = (EntityId::now(), EntityId::now(), EntityId::now());
    put_turn(&vault, goal, "goal", 1)?;
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: None,
            occurred_at: 2,
            messages: vec![WitnessMessage {
                id: Some(node.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "room".into(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        })
        .map_err(memory)?;
    let auth = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.bind_resident_agent(
        &auth,
        &ResidentAgentSpec {
            agent_def_ref: agent,
            inbox_identity_ref: inbox,
            home_conversation_ref: room,
            home_message_ref: node,
            goal: ResidentGoalRecord {
                goal: ConsultPayloadRef::Turn(goal),
                why: ConsultPayloadRef::Turn(goal),
                axes: vec![],
            },
            wake: ResidentWakeMode::HumanMessages,
        },
        3,
    )?;
    Case::after_backup(
        "resident agent wakes",
        (dir, vault),
        |vault| put_turn(vault, EntityId::now(), "aside", 4),
        move |vault| {
            vault
                .delete_entity_with_options(&goal, DeleteEntityOptions { purge: true })
                .map(drop)
        },
    )
}

/// A fork is bounded by its parent row's stored ceiling. A parent deleted
/// since the backup bounds the fork to asking, the fork's own row
/// unchanged; a restore would bring the parent back, and let the fork act
/// without asking again.
pub(super) fn agent_ceilings() -> Result<Case> {
    let (dir, vault) = open_vault();
    let (parent, fork) = (entity(0x91), entity(0x92));
    // Disabled, so only its ceiling, and not its dispatch, is in question.
    put_agent(&vault, parent, None, false)?;
    put_agent(&vault, fork, Some(parent), true)?;
    Case::after_backup(
        "agent approval ceilings",
        (dir, vault),
        |vault| put_agent(vault, entity(0x93), None, true),
        move |vault| vault.delete_entity(&parent).map(drop),
    )
}

/// A delegate of an action grant holds its authority only while the
/// delegate's entity is there. A delegate erased since the backup, the
/// grant unchanged, is one a restore would make a holder again.
pub(super) fn ask_holders() -> Result<Case> {
    let (dir, vault) = open_vault();
    let (owner, delegate) = (entity(0x71), entity(0x72));
    put_person(&vault, owner)?;
    put_person(&vault, delegate)?;
    let auth = vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?;
    vault.create_standing_grant(
        &auth,
        GrantBound::action(
            ActorBound::new(delegate.to_hex())?,
            ActionClass::new("review")?,
            ActionEnvelope::new(["project:alpha".to_owned()])?,
        )?,
    )?;
    Case::after_backup(
        "ask authority holders",
        (dir, vault),
        |vault| put_person(vault, entity(0x73)),
        move |vault| {
            vault
                .delete_entity_with_options(&delegate, DeleteEntityOptions { purge: true })
                .map(drop)
        },
    )
}
