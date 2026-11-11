//! A TASK made from a project-room message binds to that message's thread
//! in the create's own write (THREAD-TASK-ONE-SURFACE,
//! `tasks.create.from_message`), and a later reply in the thread wakes its
//! assignee. A spec that routes through approval, and a trunk message, are
//! refused with nothing written.
//!
//! Fixture: a project whose roster seats owen and agent A; a trunk witness
//! turn (the anchor) and a private thread on it, rooted on a witness turn
//! whose audience is owen and A. owen makes each TASK, assigned to A.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test thread_task_from_message`.

use std::collections::BTreeSet;

use oneiron::claim::ClaimApprovalStatus;
use oneiron::federation::Scope;
use oneiron::memory::{MEMORY_CODE_BAD_REQUEST, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec};
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

/// The label this file's TASKs carry.
const FIXTURE_PATH: &str = "crates/oneiron/tests/thread_task_from_message.rs";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    vault: Vault,
    owner: EntityId,
    owen: EntityId,
    agent_a: EntityId,
    room: EntityId,
    /// The trunk turn the thread hangs on.
    anchor: EntityId,
    /// The anchor's MESSAGE.
    trunk_message: EntityId,
    /// The private thread's root, a witness turn.
    thread: EntityId,
    /// The root's MESSAGE.
    root_message: EntityId,
    _directory: tempfile::TempDir,
}

/// owen's witness turn `turn` in `room`, one MESSAGE: a trunk turn, or with
/// `anchor` a turn of a thread on it, replying to `reply_to` when named and
/// private to `audience` when named. Returns the MESSAGE id.
fn speak_turn(
    vault: &Vault,
    owen: EntityId,
    room: EntityId,
    turn: EntityId,
    anchor: Option<EntityId>,
    reply_to: Option<EntityId>,
    audience: Option<BTreeSet<EntityId>>,
) -> TestResult<EntityId> {
    let mut metadata = serde_json::Map::new();
    if let Some(anchor) = anchor {
        metadata.insert("room_thread_of".into(), anchor.to_hex().into());
    }
    if let Some(parent) = reply_to {
        metadata.insert("room_reply_to".into(), parent.to_hex().into());
    }
    let message = EntityId::now();
    vault
        .memory(owen, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: audience,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "owen".into(),
                parts: None,
                metadata: Some(serde_json::Value::Object(metadata)),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
    Ok(message)
}

fn open_fixture() -> TestResult<Fixture> {
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    let owen = EntityId::now();
    let now = vault.now_recorded_at();
    vault.put_entity(
        &owen,
        ENTITY_TYPE_PERSON,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        b"owen",
    )?;
    let agent_a = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(serde_json::json!({
        "agent_id": "yuki",
        "display_name": "yuki",
        "desc": "yuki",
        "version": "1",
        "ceiling": "auto",
    }))?;
    oneiron::verbs::create_agent_definition_as(
        &vault,
        &proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent_a,
            definition,
        },
    )?;
    // A asks under its own Auto ceiling; owen and A read the vault's
    // records. The shipped rows stay.
    let view =
        policy_manifests_as_owner(&vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    manifest.actor_ceilings.push(ActorCeiling {
        actor_class: "agent".into(),
        actor_ref: Some(agent_a.to_hex()),
        ceiling: PolicyCeiling::Auto,
    });
    let mut rows = manifest.scoped_grants.clone().unwrap_or_default();
    for actor in [owen, agent_a] {
        rows.push(PolicyScopedGrantRow {
            // Bare census keys carry no actor class.
            actor_class: None,
            actor_ref: Some(actor.to_hex()),
            effector: "core:read".into(),
            scope: Scope::top(),
            selectors: None,
            budget: None,
            receipt_required: false,
        });
    }
    manifest.scoped_grants = Some(rows);
    put_policy_manifest_as_owner(
        &vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )?;
    let root_project = vault.root_project()?;
    let project_id = EntityId::now();
    let mut project = ProjectRecord::new(project_id, Some(root_project), root_project, owen)?;
    project.roster.extend([agent_a.to_hex()]);
    vault.put_project(project_id, &project, vault.now_recorded_at())?;
    let room = EntityId::from_hex(&project.home_room)?;
    let anchor = EntityId::now();
    let trunk_message = speak_turn(&vault, owen, room, anchor, None, None, None)?;
    let thread = EntityId::now();
    let root_message = speak_turn(
        &vault,
        owen,
        room,
        thread,
        Some(anchor),
        None,
        Some(BTreeSet::from([owen, agent_a])),
    )?;
    Ok(Fixture {
        vault,
        owner,
        owen,
        agent_a,
        room,
        anchor,
        trunk_message,
        thread,
        root_message,
        _directory: directory,
    })
}

/// A brief-less create owen owns, assigned to A.
fn create_spec(fixture: &Fixture) -> TaskCreateSpec {
    TaskCreateSpec::new(
        rmpv::Value::Nil,
        Some(FIXTURE_PATH.into()),
        Some(fixture.owen),
        Some(fixture.vault.now_recorded_at()),
    )
    .with_assignee(TaskAssignee::AgentDef {
        agent_def_ref: fixture.agent_a,
    })
}

/// The TASK ids bound on room turn `turn`, read through owen's room page.
fn bound_task_ids(fixture: &Fixture, turn: EntityId) -> TestResult<Vec<String>> {
    let rows = fixture
        .vault
        .memory(fixture.owen, EdgeActorClass::Human)
        .rooms_messages(fixture.room)?;
    let row = rows
        .iter()
        .find(|row| row.turn_id == turn.to_hex())
        .ok_or("room turn row missing")?;
    Ok(row.task_ids.clone())
}

/// owen's witness reply to `parent` in the fixture's thread. Returns the
/// reply TURN and its MESSAGE.
fn reply_in_thread(fixture: &Fixture, parent: EntityId) -> TestResult<(EntityId, EntityId)> {
    let reply = EntityId::now();
    let message = speak_turn(
        &fixture.vault,
        fixture.owen,
        fixture.room,
        reply,
        Some(fixture.anchor),
        Some(parent),
        None,
    )?;
    Ok((reply, message))
}

/// The agents a wake is staged for on room turn `turn`, duplicates kept.
fn woken_agents(fixture: &Fixture, turn: EntityId) -> TestResult<Vec<EntityId>> {
    Ok(fixture
        .vault
        .staged_room_wakes()?
        .into_iter()
        .filter(|entry| entry.wake.turn == turn)
        .map(|entry| entry.wake.agent)
        .collect())
}

/// Ruling (b): the TASK exists, is bound on the thread root, and a later
/// reply in the thread wakes A, its assignee, alone.
#[test]
fn task_from_root_message_binds_and_later_reply_wakes_assignee() -> TestResult {
    let fixture = open_fixture()?;
    let owen = fixture.vault.memory(fixture.owen, EdgeActorClass::Human);
    assert!(
        owen.get_entity(&fixture.root_message.to_hex())?
            .value
            .is_some(),
        "fixture: owen reads the root's MESSAGE"
    );
    let receipt = owen.tasks_create_from_message(fixture.root_message, &create_spec(&fixture))?;
    let task = receipt
        .task_ref
        .ok_or("TASK creation did not take effect")?;
    assert_eq!(receipt.approval, ClaimApprovalStatus::Auto);
    assert!(receipt.effected);
    assert_eq!(receipt.proposal_ref, None);
    assert!(owen.get_entity(&task.to_hex())?.value.is_some());
    assert_eq!(
        fixture.vault.tasks_by_owner(fixture.owen, None, 64)?,
        vec![task]
    );
    assert_eq!(
        bound_task_ids(&fixture, fixture.thread)?,
        vec![task.to_hex()]
    );
    let (reply, _) = reply_in_thread(&fixture, fixture.thread)?;
    assert_eq!(woken_agents(&fixture, reply)?, vec![fixture.agent_a]);
    Ok(())
}

/// Ruling (iii): a MESSAGE of a reply binds the thread's root, never the
/// reply's own turn.
#[test]
fn task_from_reply_message_binds_its_thread_root() -> TestResult {
    let fixture = open_fixture()?;
    let (reply, reply_message) = reply_in_thread(&fixture, fixture.thread)?;
    let owen = fixture.vault.memory(fixture.owen, EdgeActorClass::Human);
    let receipt = owen.tasks_create_from_message(reply_message, &create_spec(&fixture))?;
    let task = receipt
        .task_ref
        .ok_or("TASK creation did not take effect")?;
    assert_eq!(
        bound_task_ids(&fixture, fixture.thread)?,
        vec![task.to_hex()]
    );
    assert!(bound_task_ids(&fixture, reply)?.is_empty());
    let (later, _) = reply_in_thread(&fixture, reply)?;
    assert_eq!(woken_agents(&fixture, later)?, vec![fixture.agent_a]);
    Ok(())
}

/// Ruling (ii): a spec owen's ceiling would park as a proposal is refused
/// as a bad request; no TASK, proposal or binding is written. The same spec
/// through `tasks.create` parks, which shows the refusal is the ceiling's.
#[test]
fn approval_routed_spec_is_refused_and_writes_no_task() -> TestResult {
    let fixture = open_fixture()?;
    let proof = fixture
        .vault
        .memory(fixture.owner, EdgeActorClass::Human)
        .embedded_owner("vault.gate.policy.put")?;
    let view = policy_manifests_as_owner(
        &fixture.vault,
        &proof,
        &PolicyManifestRead { manifest_ref: None },
    )?;
    let default = view
        .manifests
        .iter()
        .find(|entry| entry.manifest_ref == view.default_manifest_ref)
        .ok_or("default policy manifest missing")?;
    let mut manifest = default.manifest.clone();
    manifest.actor_ceilings.push(ActorCeiling {
        actor_class: "human".into(),
        actor_ref: Some(fixture.owen.to_hex()),
        ceiling: PolicyCeiling::Proposed,
    });
    put_policy_manifest_as_owner(
        &fixture.vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )?;
    let owen = fixture.vault.memory(fixture.owen, EdgeActorClass::Human);
    let spec = create_spec(&fixture);
    let error = match owen.tasks_create_from_message(fixture.root_message, &spec) {
        Err(error) => error,
        Ok(receipt) => return Err(format!("approval-routed spec landed: {receipt:?}").into()),
    };
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST, "{error:?}");
    assert!(
        fixture
            .vault
            .tasks_by_owner(fixture.owen, None, 64)?
            .is_empty()
    );
    assert!(bound_task_ids(&fixture, fixture.thread)?.is_empty());
    let parked = owen.tasks_create(&spec)?;
    assert_eq!(parked.task_ref, None);
    assert!(parked.proposal_ref.is_some());
    assert_eq!(parked.approval, ClaimApprovalStatus::Proposed);
    Ok(())
}

/// Ruling (ii): an intent key makes a create a post through the task
/// highway, so this door refuses it under an Auto ceiling too.
#[test]
fn keyed_spec_is_refused_and_writes_no_task() -> TestResult {
    let fixture = open_fixture()?;
    let owen = fixture.vault.memory(fixture.owen, EdgeActorClass::Human);
    let mut spec = create_spec(&fixture);
    spec.intent_key = Some(FIXTURE_PATH.into());
    let error = match owen.tasks_create_from_message(fixture.root_message, &spec) {
        Err(error) => error,
        Ok(receipt) => return Err(format!("keyed spec landed: {receipt:?}").into()),
    };
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST, "{error:?}");
    assert!(
        fixture
            .vault
            .tasks_by_owner(fixture.owen, None, 64)?
            .is_empty()
    );
    assert!(bound_task_ids(&fixture, fixture.thread)?.is_empty());
    Ok(())
}

/// Ruling (iii): a trunk message is refused even though a thread hangs on
/// it; the pane opens the thread first.
#[test]
fn trunk_message_is_refused_and_writes_no_task() -> TestResult {
    let fixture = open_fixture()?;
    let owen = fixture.vault.memory(fixture.owen, EdgeActorClass::Human);
    let error = match owen.tasks_create_from_message(fixture.trunk_message, &create_spec(&fixture))
    {
        Err(error) => error,
        Ok(receipt) => return Err(format!("trunk message landed a TASK: {receipt:?}").into()),
    };
    assert_eq!(error.code, MEMORY_CODE_BAD_REQUEST, "{error:?}");
    assert!(
        fixture
            .vault
            .tasks_by_owner(fixture.owen, None, 64)?
            .is_empty()
    );
    assert!(bound_task_ids(&fixture, fixture.thread)?.is_empty());
    assert!(bound_task_ids(&fixture, fixture.anchor)?.is_empty());
    Ok(())
}
