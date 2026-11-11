#![cfg(oneiron_test_support)]
//! A pumped run's native board and self brief join its work room's shared pins.
//! Run on a build host with `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test room_pins_native`.

use std::sync::Arc;

use oneiron::claim::{CallerLocality, ScopedReadActorKey};
use oneiron::conversation::RoomPin;
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::federation::Scope;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec, TaskRouteOutcome};
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::{ProjectRecord, RoomPinRequest};
use oneiron::{AttemptId, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::test_doors::native_board::{run_board_pins, run_brief_pins};
use oneiron_server::{ENGINE_THREAD_STACK_BYTES, config::SyncServerConfig, server::SyncServer};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    leader: EntityId,
    agent: EntityId,
    outsider: EntityId,
    room_a: EntityId,
    trunk_a: EntityId,
    target_t: EntityId,
    target_u: EntityId,
    pin_a: RoomPin,
    project_a: EntityId,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.map_size = 32 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let vault = Arc::new(Vault::open_owned(directory.path(), config)?);
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));

        let member = vault.ensure_embedded_owner_actor()?;
        let proof = vault
            .memory(member, EdgeActorClass::Human)
            .embedded_owner("vault.agents.create")?;
        let leader = EntityId::now();
        let outsider_person = EntityId::now();
        let now = vault.now_recorded_at();
        for person in [leader, outsider_person] {
            vault.put_entity(
                &person,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                b"owen",
            )?;
        }

        // The agent under test pens the leader, who sits in both rooms; the
        // outsider pens a PERSON seated nowhere, so it stands nowhere.
        let agent = EntityId::now();
        let outsider = EntityId::now();
        for (agent_id, agent_ref, person) in
            [("owen", agent, leader), ("yuki", outsider, outsider_person)]
        {
            let definition: AgentDefinitionSpec = serde_json::from_value(json!({
                "agent_id": agent_id,
                "display_name": "yuki",
                "desc": "yuki",
                "version": "1",
                "ceiling": "auto"
            }))?;
            oneiron::verbs::create_agent_definition_as(
                &vault,
                &proof,
                AgentDefinitionCreateRequest {
                    agent_def_ref: agent_ref,
                    definition,
                },
            )?;
            oneiron::subject_model::anchor_actor_subject(
                &vault,
                agent_ref,
                person,
                WriteActor::new(member, EdgeActorClass::Human),
                vault.now_recorded_at(),
            )?;
        }

        let view =
            policy_manifests_as_owner(&vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
        let default = view
            .manifests
            .iter()
            .find(|entry| entry.manifest_ref == view.default_manifest_ref)
            .ok_or("default policy manifest missing")?;
        let mut manifest = default.manifest.clone();
        let mut grants = manifest.scoped_grants.clone().unwrap_or_default();
        for agent_ref in [agent, outsider] {
            manifest.actor_ceilings.push(ActorCeiling {
                actor_class: "agent".into(),
                actor_ref: Some(agent_ref.to_hex()),
                ceiling: PolicyCeiling::Auto,
            });
        }
        for actor in [leader, member, outsider_person, agent, outsider] {
            grants.push(PolicyScopedGrantRow {
                actor_class: None,
                actor_ref: Some(actor.to_hex()),
                effector: "core:read".into(),
                scope: Scope::top(),
                selectors: None,
                budget: None,
                receipt_required: false,
            });
        }
        manifest.scoped_grants = Some(grants);
        put_policy_manifest_as_owner(
            &vault,
            &proof,
            PolicyManifestPut {
                manifest_ref: Some(default.manifest_ref.clone()),
                expected_body_hash: Some(default.body_hash.clone()),
                manifest,
            },
        )?;

        let contact = EntityId::now();
        vault.create_counterparty_contact(
            &contact,
            &CounterpartyContactRecord::public(
                leader,
                "owen@example.com",
                vault.now_recorded_at(),
            )?,
        )?;
        vault.preclear_contact_disclosure(&proof, "owen", &[contact], Scope::top())?;

        // Two project home rooms, both seating the agent under test: room A
        // holds the work thread, room B holds the other room's pin. An
        // ordinary room seats PERSONs only, so only a second project seats
        // the agent in B for a read standing there.
        let root = vault.root_project()?;
        let project_a = EntityId::now();
        let mut record_a = ProjectRecord::new(project_a, Some(root), root, leader)?;
        record_a.roster.push(member.to_hex());
        record_a.roster.push(agent.to_hex());
        vault.put_project(project_a, &record_a, vault.now_recorded_at())?;
        let room_a = EntityId::from_hex(&record_a.home_room)?;
        let project_b = EntityId::now();
        let mut record_b = ProjectRecord::new(project_b, Some(root), root, leader)?;
        record_b.roster.push(member.to_hex());
        record_b.roster.push(agent.to_hex());
        vault.put_project(project_b, &record_b, vault.now_recorded_at())?;
        let room_b = EntityId::from_hex(&record_b.home_room)?;
        assert_ne!(room_a, room_b, "the two project rooms differ");

        let (trunk_a, target_t) = speak_trunk(&vault, leader, room_a)?;
        let (_, target_u) = speak_trunk(&vault, leader, room_b)?;
        let pin_a = vault
            .memory(leader, EdgeActorClass::Human)
            .rooms_pins_pin(&RoomPinRequest {
                room: room_a,
                target: target_t,
            })?
            .pin;
        vault
            .memory(leader, EdgeActorClass::Human)
            .rooms_pins_pin(&RoomPinRequest {
                room: room_b,
                target: target_u,
            })?;

        let server = Arc::new(SyncServer::new(vault.clone(), SyncServerConfig::default())?);
        Ok(Self {
            server,
            vault,
            leader,
            agent,
            outsider,
            room_a,
            trunk_a,
            target_t,
            target_u,
            pin_a,
            project_a,
            _directory: directory,
        })
    }
}

/// A trunk turn whose MESSAGE text carries its own id: the MEMORIES row head
/// renders the short id, so the hex below rides the snippet. Returns the TURN
/// and the MESSAGE.
fn speak_trunk(
    vault: &Vault,
    speaker: EntityId,
    room: EntityId,
) -> TestResult<(EntityId, EntityId)> {
    let turn = EntityId::now();
    let message = EntityId::now();
    vault
        .memory(speaker, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: format!("yuki {}", message.to_hex()),
                parts: None,
                metadata: Some(json!({})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
    Ok((turn, message))
}

/// A public thread root answering `trunk` in `room`; returns the thread TURN.
fn speak_thread(
    vault: &Vault,
    speaker: EntityId,
    room: EntityId,
    trunk: EntityId,
) -> TestResult<EntityId> {
    let thread = EntityId::now();
    let message = EntityId::now();
    vault
        .memory(speaker, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(thread.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "yuki".into(),
                parts: None,
                metadata: Some(json!({"room_thread_of": trunk.to_hex()})),
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: vault.now_recorded_at(),
            assertions: Default::default(),
        })?;
    Ok(thread)
}

/// A TASK owned by `owner` and assigned to `assignee`, created by `creator`;
/// returns the TASK and its agent-dispatch attempt, as the run-reader scope
/// fixture reads them.
fn dispatch_task(
    vault: &Vault,
    creator: EntityId,
    owner: EntityId,
    assignee: EntityId,
) -> TestResult<(EntityId, AttemptId)> {
    let receipt = vault.memory(creator, EdgeActorClass::Agent).tasks_create(
        &TaskCreateSpec::new(rmpv::Value::Nil, Some("yuki".to_owned()), Some(owner), None)
            .with_assignee(TaskAssignee::AgentDef {
                agent_def_ref: assignee,
            }),
    )?;
    let task = receipt.task_ref.ok_or("the TASK is minted")?;
    let Some(TaskRouteOutcome::AgentDispatch { attempt_ref, .. }) = receipt.route else {
        return Err("an agent-definition assignee routes to an agent dispatch".into());
    };
    Ok((task, attempt_ref))
}

/// The agent's own on-device lane, as the run board builds it: whether it
/// reads `target` now.
fn lane_reads(vault: &Vault, agent: EntityId, target: EntityId) -> TestResult<bool> {
    let key = ScopedReadActorKey::with_actor_class(
        agent.to_hex(),
        EdgeActorClass::Agent.gate_actor_class(),
    )
    .ok_or("the agent lane key builds")?
    .at(CallerLocality::OnDevice);
    Ok(vault.scoped_read(key).is_entity_readable(&target)?)
}

/// Both the driver and runtime workers need the server's engine-sized stack.
fn on_engine_stack<F, Fut>(test: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

fn board_pins_error(error: String) -> Box<dyn std::error::Error> {
    format!("the native board pins built: {error}").into()
}

/// P2c: the native board of a run working in room A pins A's pin T, not B's
/// pin U; a run bound to no attempt pins neither. U's absence is selection:
/// the agent stands in B and its own lane reads U.
#[test]
fn native_run_board_pins_only_its_work_room() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let (task, attempt) =
            dispatch_task(&fixture.vault, fixture.agent, fixture.agent, fixture.agent)?;
        let thread = speak_thread(
            &fixture.vault,
            fixture.leader,
            fixture.room_a,
            fixture.trunk_a,
        )?;
        fixture
            .vault
            .bind_room_thread_task(fixture.leader, fixture.room_a, thread, task)?;

        let (pinned_none, _) = run_board_pins(&fixture.server, fixture.agent, None)
            .await
            .map_err(board_pins_error)?;
        assert!(
            !pinned_none.contains(&fixture.target_t),
            "a run bound to no attempt pins no room pin: {pinned_none:?}"
        );
        assert!(
            !pinned_none.contains(&fixture.target_u),
            "a run bound to no attempt pins no room pin: {pinned_none:?}"
        );
        assert!(
            lane_reads(&fixture.vault, fixture.agent, fixture.target_t)?,
            "the agent's own lane reads T"
        );
        assert!(
            lane_reads(&fixture.vault, fixture.agent, fixture.target_u)?,
            "the agent's own lane reads U, so its absence below is selection"
        );

        let (pinned, lines) = run_board_pins(&fixture.server, fixture.agent, Some(attempt))
            .await
            .map_err(board_pins_error)?;
        assert!(
            pinned.contains(&fixture.target_t),
            "the work room's pin T rides the native board: {pinned:?}"
        );
        assert!(
            !pinned.contains(&fixture.target_u),
            "the other room's pin U stays off the native board: {pinned:?}"
        );
        let pinner = format!("pinned_by={}", fixture.pin_a.pinned_by.to_hex());
        let target = fixture.target_t.to_hex();
        assert!(
            lines
                .iter()
                .any(|line| line.contains(&target) && line.contains(&pinner)),
            "a MEMORIES line carries T and its pinner: {lines:?}"
        );
        Ok(())
    })
}

/// P2c: the self brief of a run working in room A names A's pin T, not B's
/// pin U; without an attempt it names neither.
#[test]
fn native_run_brief_names_only_its_work_room_pins() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        let (task, attempt) =
            dispatch_task(&fixture.vault, fixture.agent, fixture.agent, fixture.agent)?;
        let thread = speak_thread(
            &fixture.vault,
            fixture.leader,
            fixture.room_a,
            fixture.trunk_a,
        )?;
        fixture
            .vault
            .bind_room_thread_task(fixture.leader, fixture.room_a, thread, task)?;

        let brief = run_brief_pins(fixture.server.as_ref(), fixture.agent, Some(attempt))
            .ok_or("the brief pins read")?;
        assert!(
            brief.contains(&fixture.target_t),
            "the brief names the work room's pin T: {brief:?}"
        );
        assert!(
            !brief.contains(&fixture.target_u),
            "the brief names no other room's pin: {brief:?}"
        );
        let unbound = run_brief_pins(fixture.server.as_ref(), fixture.agent, None)
            .ok_or("the unbound brief pins read")?;
        assert!(
            !unbound.contains(&fixture.target_t),
            "a brief bound to no attempt names neither pin: {unbound:?}"
        );
        assert!(
            !unbound.contains(&fixture.target_u),
            "a brief bound to no attempt names neither pin: {unbound:?}"
        );
        Ok(())
    })
}

/// P2c: the work room selects but grants nothing. An agent with no standing
/// in room A, whose TASK is bound into A's thread, sees no T on its board.
#[test]
fn native_board_needs_standing_in_the_work_room() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new()?;
        // The bind asks the assignee to sit in the room, so the outsider sits
        // while it binds and leaves before its board reads.
        let mut seated = fixture
            .vault
            .project(fixture.project_a)?
            .ok_or("project A reads")?;
        seated.roster.push(fixture.outsider.to_hex());
        fixture
            .vault
            .put_project(fixture.project_a, &seated, fixture.vault.now_recorded_at())?;
        let (task, attempt) = dispatch_task(
            &fixture.vault,
            fixture.outsider,
            fixture.outsider,
            fixture.outsider,
        )?;
        let thread = speak_thread(
            &fixture.vault,
            fixture.leader,
            fixture.room_a,
            fixture.trunk_a,
        )?;
        fixture
            .vault
            .bind_room_thread_task(fixture.leader, fixture.room_a, thread, task)?;
        let mut unseated = fixture
            .vault
            .project(fixture.project_a)?
            .ok_or("project A reads after the bind")?;
        unseated
            .roster
            .retain(|seat| *seat != fixture.outsider.to_hex());
        fixture.vault.put_project(
            fixture.project_a,
            &unseated,
            fixture.vault.now_recorded_at(),
        )?;

        assert_eq!(
            fixture
                .vault
                .agent_run_work_room(attempt, fixture.outsider)?,
            Some(fixture.room_a),
            "the room still selects A after the outsider leaves"
        );
        let (pinned, _) = run_board_pins(&fixture.server, fixture.outsider, Some(attempt))
            .await
            .map_err(board_pins_error)?;
        assert!(
            !pinned.contains(&fixture.target_t),
            "no standing in the work room names no pin: {pinned:?}"
        );
        Ok(())
    })
}
