//! The room an agent's run works in (ROOM-SCOPED-PINS P2c; Engine ruling
//! THREADTASK-PINS-NATIVE Q1 = A): `Vault::agent_run_work_room` reads the
//! dispatch's frozen room work, else the room of the TURN whose room wake
//! dispatched it (from the engine-minted dedupe key, never the briefing),
//! else the one room of the threads its TASK is bound into. The first one
//! present wins; the room only selects, it grants nothing.
//!
//! Fixture: the vault's owner (`owen`) and a custom agent (`yuki`); each
//! project home room seats both, so the TASK owner and its assignee pass the
//! thread bind guard. Threads are trunk turns with a `room_thread_of` reply;
//! owen creates the TASK as a person (an agent-class create under a Proposed
//! ceiling only proposes it) and assigns it to the agent, so its create
//! routes to an agent dispatch and the receipt's route names the attempt.
//! The resident case binds the agent as a resident and addresses it by
//! handle, so the witness stages a room wake and the inbox pass dispatches
//! it. `agent.resident` is named by no rule of the shipped manifest, so its
//! binding would pend at the criticality floor; the fixture declares it
//! normal in the stored default manifest first.
//!
//! Public paths only; no test door.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test room_pins_work_room`.

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatcher, ResidentAgentSpec, ResidentGoalRecord, ResidentWakeMode,
};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::store::GateDecisionId;
use oneiron::task_verb::{ConsultPayloadRef, TaskAssignee, TaskCreateSpec, TaskRouteOutcome};
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::ProjectRecord;
use oneiron::{AttemptId, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn create_agent(
    vault: &Vault,
    proof: &AuthenticatedOwner,
    logical_id: &str,
) -> TestResult<EntityId> {
    let agent = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(serde_json::json!({
        "agent_id": logical_id,
        "display_name": "yuki",
        "desc": "yuki",
        "version": "1",
        "ceiling": "auto",
    }))?;
    oneiron::verbs::create_agent_definition_as(
        vault,
        proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition,
        },
    )?;
    Ok(agent)
}

fn owner_proof(vault: &Vault, owner: EntityId) -> TestResult<AuthenticatedOwner> {
    Ok(vault.authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())?)
}

/// Declares `agent.resident` normal in the stored default manifest, at its
/// own id: a manifest at a new id would still meet the shipped pack's
/// critical fallback.
fn declare_resident_binding_normal(vault: &Vault, proof: &AuthenticatedOwner) -> TestResult {
    use rmpv::Value;

    let id = oneiron_store::policy_record::default_policy_manifest_id()?;
    let body = vault
        .get(&id)?
        .ok_or("the default policy manifest is stored")?;
    let Value::Map(mut fields) = rmpv::decode::read_value(&mut body.as_slice())? else {
        return Err("the default policy manifest is a map".into());
    };
    let Some((_, Value::Array(rules))) = fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("rules"))
    else {
        return Err("the default policy manifest has a rules array".into());
    };
    rules.push(Value::Map(vec![
        (Value::from("prefix"), Value::from("agent.resident")),
        (Value::from("exact"), Value::Boolean(true)),
        (
            Value::from("axes"),
            Value::Map(vec![
                (Value::from("criticality"), Value::from("normal")),
                (Value::from("sensitivity"), Value::from("normal")),
            ]),
        ),
    ]));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &Value::Map(fields))?;
    vault.install_owner_policy_manifest(proof, id, bytes, vault.now_recorded_at())?;
    Ok(())
}

/// A project whose home room seats `leader` and `extra`, in roster order.
/// Returns the project id and its home room.
fn make_project(
    vault: &Vault,
    leader: EntityId,
    extra: &[EntityId],
) -> TestResult<(EntityId, EntityId)> {
    let root = vault.root_project()?;
    let project_id = EntityId::now();
    let mut project = ProjectRecord::new(project_id, Some(root), root, leader)?;
    for seat in extra {
        project.roster.push(seat.to_hex());
    }
    vault.put_project(project_id, &project, vault.now_recorded_at())?;
    let room = EntityId::from_hex(&project.home_room)?;
    Ok((project_id, room))
}

/// A trunk turn and its thread reply in `room`, spoken by `speaker`.
/// Returns the thread turn, the bind target.
fn speak_thread(vault: &Vault, speaker: EntityId, room: EntityId) -> TestResult<EntityId> {
    let trunk = EntityId::now();
    vault
        .memory(speaker, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(trunk.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "owen".into(),
                parts: None,
                metadata: Some(serde_json::json!({})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
    let thread = EntityId::now();
    vault
        .memory(speaker, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(thread.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "owen".into(),
                parts: None,
                metadata: Some(serde_json::json!({"room_thread_of": trunk.to_hex()})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
    Ok(thread)
}

/// A TASK `owner` creates as a person and owns, assigned to `agent`.
/// Returns the TASK and its dispatch attempt from the receipt's route.
fn create_dispatch_task(
    vault: &Vault,
    owner: EntityId,
    agent: EntityId,
) -> TestResult<(EntityId, AttemptId)> {
    let receipt = vault.memory(owner, EdgeActorClass::Human).tasks_create(
        &TaskCreateSpec::new(rmpv::Value::Nil, Some("owen".to_owned()), Some(owner), None)
            .with_assignee(TaskAssignee::AgentDef {
                agent_def_ref: agent,
            }),
    )?;
    let task = receipt
        .task_ref
        .ok_or_else(|| format!("the TASK is minted, got {receipt:?}"))?;
    let Some(TaskRouteOutcome::AgentDispatch { attempt_ref, .. }) = receipt.route else {
        return Err("an agent-definition assignee routes to an agent dispatch".into());
    };
    Ok((task, attempt_ref))
}

fn open_vault() -> TestResult<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open_owned(dir.path(), VaultConfig::default())?;
    Ok((dir, vault))
}

/// P2c Q1, TASK source: an unbound TASK's run works nowhere; bound into one
/// room's thread it works in that room; the same attempt is no run of
/// another agent.
#[test]
fn task_run_works_in_its_bound_thread_room() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = owner_proof(&vault, owner)?;
    let owen = owner;
    let yuki = create_agent(&vault, &proof, "yuki")?;
    let (_project, room_a) = make_project(&vault, owen, &[yuki])?;
    let thread_a = speak_thread(&vault, owen, room_a)?;
    let (task, attempt) = create_dispatch_task(&vault, owen, yuki)?;
    assert_eq!(vault.agent_run_work_room(attempt, yuki)?, None);
    vault.bind_room_thread_task(owen, room_a, thread_a, task)?;
    assert_eq!(vault.agent_run_work_room(attempt, yuki)?, Some(room_a));
    let other_agent = create_agent(&vault, &proof, "owen")?;
    assert_eq!(vault.agent_run_work_room(attempt, other_agent)?, None);
    Ok(())
}

/// P2c Q1, split TASK: a TASK bound into threads of two rooms selects none.
#[test]
fn task_bound_into_two_rooms_selects_none() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = owner_proof(&vault, owner)?;
    let owen = owner;
    let yuki = create_agent(&vault, &proof, "yuki")?;
    let (_project_a, room_a) = make_project(&vault, owen, &[yuki])?;
    let (_project_b, room_b) = make_project(&vault, owen, &[yuki])?;
    let thread_a = speak_thread(&vault, owen, room_a)?;
    let thread_b = speak_thread(&vault, owen, room_b)?;
    let (task, attempt) = create_dispatch_task(&vault, owen, yuki)?;
    vault.bind_room_thread_task(owen, room_a, thread_a, task)?;
    assert_eq!(vault.agent_run_work_room(attempt, yuki)?, Some(room_a));
    vault.bind_room_thread_task(owen, room_b, thread_b, task)?;
    assert_eq!(vault.agent_run_work_room(attempt, yuki)?, None);
    Ok(())
}

/// P2c Q1, room-wake source: a resident addressed by a room TURN runs in the
/// waking room, read from the engine-minted dedupe key, never the briefing.
#[test]
fn room_wake_run_works_in_the_waking_room() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = owner_proof(&vault, owner)?;
    let owen = owner;
    let yuki = create_agent(&vault, &proof, "yuki")?;
    let (_project, room_a) = make_project(&vault, owen, &[yuki])?;
    let goal = EntityId::now();
    let now = vault.now_recorded_at();
    vault.put_entity(
        &goal,
        ENTITY_TYPE_TURN,
        TimeRange {
            start: now,
            end: now,
        },
        now,
        &[0x80],
    )?;
    let inbox = EntityId::now();
    vault.create_own_app_channel_identity(&inbox, yuki, vault.now_recorded_at())?;
    let home_room = EntityId::now();
    let home_node = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: home_room.to_hex(),
            turn_ref: None,
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(home_node.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "owen".into(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
    let spec = ResidentAgentSpec {
        agent_def_ref: yuki,
        inbox_identity_ref: inbox,
        home_conversation_ref: home_room,
        home_message_ref: home_node,
        goal: ResidentGoalRecord {
            goal: ConsultPayloadRef::Turn(goal),
            why: ConsultPayloadRef::Turn(goal),
            axes: vec![],
        },
        wake: ResidentWakeMode::AllAddressed,
    };
    declare_resident_binding_normal(&vault, &proof)?;
    vault
        .bind_resident_agent(&proof, &spec, vault.now_recorded_at())
        .map_err(|error| format!("the owner binds the resident: {error:?}"))?;
    vault.bind_room_handle(room_a, "@yuki", yuki)?;
    let wake_turn = EntityId::now();
    vault
        .memory(owen, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room_a.to_hex(),
            turn_ref: Some(wake_turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "owen".into(),
                parts: None,
                metadata: Some(serde_json::json!({"room_mentions": ["@yuki"]})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
    let staged = vault.staged_room_wakes()?;
    assert!(
        staged.iter().any(|row| {
            row.wake.room == room_a && row.wake.turn == wake_turn && row.wake.agent == yuki
        }),
        "the addressing turn stages the resident wake: {staged:?}"
    );
    let outcomes =
        AgentDispatcher::new(&vault).dispatch_resident_inbox(yuki, 16, vault.now_recorded_at())?;
    if outcomes.len() != 1 {
        return Err(format!("one room wake dispatches, got {outcomes:?}").into());
    }
    let record = match &outcomes[0] {
        AgentDispatchOutcome::Dispatched(status) | AgentDispatchOutcome::Existing(status) => {
            &status.attempt
        }
        other => return Err(format!("a room wake dispatches a run, got {other:?}").into()),
    };
    let key = format!(
        "agent.dispatch:resident:{}:room:{}",
        yuki.to_hex(),
        wake_turn.to_hex()
    );
    assert_eq!(record.dedupe_key.as_deref(), Some(key.as_str()));
    let attempt = record.id;
    assert_eq!(vault.agent_run_work_room(attempt, yuki)?, Some(room_a));
    Ok(())
}

// The explicit `RoomWork` case (`spawn_room_work_wins_over_the_task_room`) is
// omitted: ordinary TASK creation cannot set `AgentSpawnContext.room`. The
// public leader-task dispatch can carry both, but this fixture's assignee is
// not the project leader and has no payer scope or Ready paid room join.
// Those admission requirements are not bypassed here. See the parent report.
