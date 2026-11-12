//! Every room keeps one turn projection and one access path
//! (THREAD-TASK-EVERY-ROOM, P1): a project's home room, a project's extra
//! room and a vault's ordinary room each row every TURN, trunk included,
//! serve their history and speech, bind a thread's TASK under one rule, and
//! wake the TASK's assignee on a plain reply.
//!
//! Fixture: owen, the vault's owner, and two agents, A and B, made through
//! the agent-definition door; each reads the vault's records under the
//! default policy manifest and the room's MESSAGEs under a grant. The room is
//! one of three kinds: a project's home room, whose roster seats owen and A;
//! an ordinary group room owen holds alone, linked to that project as an
//! extra room; or an ordinary group room owen holds alone. In the last two A
//! stands on the Ready join owen, the room's host, gave its offer card. B
//! stands nowhere. owen is the owner because a PERSON with no contact
//! clearance reads only public rows, and a room's TURNs and MESSAGEs are
//! born Sensitive.
//!
//! Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test room_thread_task_parity`.

use std::collections::BTreeSet;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::conversation::TurnActionRequest;
use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::core_write::ConversationCreateInput;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{Memory, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN};
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec};
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::{
    JoinDecision, OfferAnswer, OfferAnswerRequest, OfferDraft, ProjectRecord,
    ProjectRoomLinkRequest, RoomTurn,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

/// The label this file's TASKs carry.
const FIXTURE_PATH: &str = "crates/oneiron/tests/room_thread_task_parity.rs";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The room kinds every case runs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoomKind {
    /// A project's home room.
    Home,
    /// An ordinary room linked to a project as an extra room.
    Extra,
    /// An ordinary room of the vault.
    Ordinary,
}

const EVERY_ROOM: [RoomKind; 3] = [RoomKind::Home, RoomKind::Extra, RoomKind::Ordinary];

struct Fixture {
    vault: Vault,
    kind: RoomKind,
    owen: EntityId,
    agent_a: EntityId,
    agent_b: EntityId,
    room: EntityId,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn owen(&self) -> Memory<'_> {
        self.vault.memory(self.owen, EdgeActorClass::Human)
    }
}

/// An agent made through the agent-definition door, as the owner.
fn create_agent(vault: &Vault, owner: EntityId, name: &str) -> TestResult<EntityId> {
    let agent = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(serde_json::json!({
        "agent_id": name,
        "display_name": name,
        "desc": name,
        "version": "1",
        "ceiling": "auto",
    }))?;
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    oneiron::verbs::create_agent_definition_as(
        vault,
        &proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: agent,
            definition,
        },
    )?;
    Ok(agent)
}

/// A asks under its own Auto ceiling, and owen, A and B read the vault's
/// records: rows added to the default policy manifest, the shipped rows kept.
fn grant_reads(vault: &Vault, owen: EntityId, agent_a: EntityId, agent_b: EntityId) -> TestResult {
    let proof = vault
        .memory(owen, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    let view =
        policy_manifests_as_owner(vault, &proof, &PolicyManifestRead { manifest_ref: None })?;
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
    for actor in [owen, agent_a, agent_b] {
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
        vault,
        &proof,
        PolicyManifestPut {
            manifest_ref: Some(default.manifest_ref.clone()),
            expected_body_hash: Some(default.body_hash.clone()),
            manifest,
        },
    )?;
    Ok(())
}

/// A project led by owen whose roster also seats `seated`. Returns the
/// project and its home room.
fn project(vault: &Vault, owen: EntityId, seated: &[EntityId]) -> TestResult<(EntityId, EntityId)> {
    let root = vault.root_project()?;
    let id = EntityId::now();
    let mut record = ProjectRecord::new(id, Some(root), root, owen)?;
    record.roster.extend(seated.iter().map(EntityId::to_hex));
    vault.put_project(id, &record, vault.now_recorded_at())?;
    Ok((id, EntityId::from_hex(&record.home_room)?))
}

/// An ordinary group room owen creates, and so hosts, holding owen alone.
fn ordinary_room(vault: &Vault, owen: EntityId, title: &str) -> TestResult<EntityId> {
    let receipt = vault
        .memory(owen, EdgeActorClass::Human)
        .conversations_create(&ConversationCreateInput {
            id: None,
            occurred_start: None,
            occurred_end: None,
            learned_at: None,
            body: serde_json::json!({
                "v": 1,
                "kind": "group",
                "member_ids": [owen.to_hex()],
                "title": title,
            }),
            text: None,
        })?;
    Ok(EntityId::from_hex(&receipt.id)?)
}

/// `agent`'s Ready join for the whole of `room`: its offer card, accepted by
/// owen, the room's host.
fn join_room(vault: &Vault, owen: EntityId, room: EntityId, agent: EntityId) -> TestResult {
    let card = vault
        .memory(agent, EdgeActorClass::Agent)
        .rooms_offer(&OfferDraft {
            room,
            branch: None,
            agent,
            what: "Work the room's thread tasks.".to_owned(),
            artifact_ref: Some("artifact:thread-tasks".to_owned()),
            spend_scope: None,
            until: None,
            intent_key: format!("{FIXTURE_PATH}:offer:{}", agent.to_hex()),
        })?;
    let accepted = vault
        .memory(owen, EdgeActorClass::Human)
        .rooms_offer_answer(&OfferAnswerRequest {
            offer_id: card.offer_id.clone(),
            action: OfferAnswer::Join,
            intent_key: format!("{FIXTURE_PATH}:answer:{}", agent.to_hex()),
        })?;
    let join = accepted.join.ok_or("the host's answer carries no join")?;
    if join.decision.state != JoinDecision::Ready {
        return Err(format!("fixture: the join is {:?}, not Ready", join.decision.state).into());
    }
    Ok(())
}

/// `principal` reads `room`'s MESSAGEs under an active grant.
fn grant_messages(vault: &Vault, room: EntityId, principal: EntityId) -> TestResult {
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault.create_access_grant(
        &EntityId::now(),
        &AccessGrant {
            authority_scope,
            principal_ref: principal,
            scope: AccessGrantScope::ConversationMessages {
                conversation_ref: room,
            },
            capability: AccessGrantCapability::MessagesRead,
            status: AccessGrantStatus::Active,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            revoked_at: None,
            expires_at: None,
            companion_bounds: None,
        },
    )?;
    Ok(())
}

fn open_fixture(kind: RoomKind) -> TestResult<Fixture> {
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owen = vault.ensure_embedded_owner_actor()?;
    let agent_a = create_agent(&vault, owen, "yuki")?;
    let agent_b = create_agent(&vault, owen, "yuki-two")?;
    grant_reads(&vault, owen, agent_a, agent_b)?;
    let room = match kind {
        RoomKind::Home => project(&vault, owen, &[agent_a])?.1,
        RoomKind::Extra => {
            let (project, _home) = project(&vault, owen, &[agent_a])?;
            let room = ordinary_room(&vault, owen, "extra room")?;
            vault
                .memory(owen, EdgeActorClass::Human)
                .projects_rooms_link(&ProjectRoomLinkRequest {
                    project_ref: project.to_hex(),
                    room_ref: room.to_hex(),
                })?;
            room
        }
        RoomKind::Ordinary => ordinary_room(&vault, owen, "ordinary room")?,
    };
    for principal in [agent_a, agent_b] {
        grant_messages(&vault, room, principal)?;
    }
    if kind != RoomKind::Home {
        join_room(&vault, owen, room, agent_a)?;
    }
    Ok(Fixture {
        vault,
        kind,
        owen,
        agent_a,
        agent_b,
        room,
        _directory: directory,
    })
}

/// owen's witness turn on the room's trunk, one MESSAGE, through the room
/// speech door. Returns the TURN and its MESSAGE.
fn speak_trunk(fixture: &Fixture) -> TestResult<(EntityId, EntityId)> {
    let turn = EntityId::now();
    let message = EntityId::now();
    fixture.owen().rooms_speak(&WitnessTurn {
        conversation_ref: fixture.room.to_hex(),
        turn_ref: Some(turn.to_hex()),
        thread_audience: None,
        messages: vec![WitnessMessage {
            id: Some(message.to_hex()),
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: "owen".into(),
            parts: None,
            metadata: Some(serde_json::json!({})),
            is_visible: true,
            order: 0,
            quote: None,
        }],
        occurred_at: fixture.vault.now_recorded_at(),
        assertions: Default::default(),
    })?;
    Ok((turn, message))
}

/// owen's plain TURN for the DAG's append doors, naming `recipients`.
fn plain_turn(fixture: &Fixture, recipients: Vec<EntityId>) -> TestResult<AppendRecord> {
    let now = fixture.vault.now_recorded_at();
    Ok(AppendRecord {
        conversation: fixture.room,
        parent: None,
        reply_to: None,
        quote: None,
        address: if recipients.is_empty() {
            AddressMode::Broadcast
        } else {
            AddressMode::Direct
        },
        recipients,
        advance: false,
        kind: ENTITY_TYPE_TURN,
        containing_turn: None,
        occurred: TimeRange {
            start: now,
            end: now,
        },
        learned_at: now,
        body: rmp_serde::to_vec_named(&serde_json::json!({"txt": "owen"}))?,
        text: vec![],
        session: None,
        actor: WriteActor::new(fixture.owen, EdgeActorClass::Human),
        thread_audience: None,
    })
}

/// owen's plain reply on `anchor`, through the REST thread reply's door:
/// the first opens the thread, a later one continues it. Returns the TURN.
fn plain_reply(fixture: &Fixture, anchor: EntityId) -> TestResult<EntityId> {
    let input = plain_turn(fixture, vec![])?;
    Ok(fixture
        .vault
        .reply_in_thread(&fixture.owen(), anchor, &input)?
        .id)
}

/// An open TASK owen owns, assigned to `agent`.
fn create_task(fixture: &Fixture, agent: EntityId) -> TestResult<EntityId> {
    let created = fixture.owen().tasks_create(&task_spec(fixture, agent))?;
    let task = created
        .task_ref
        .ok_or("TASK creation did not take effect")?;
    Ok(task)
}

/// A brief-less create owen owns, assigned to `agent`.
fn task_spec(fixture: &Fixture, agent: EntityId) -> TaskCreateSpec {
    TaskCreateSpec::new(
        rmpv::Value::Nil,
        Some(FIXTURE_PATH.into()),
        Some(fixture.owen),
        Some(fixture.vault.now_recorded_at()),
    )
    .with_assignee(TaskAssignee::AgentDef {
        agent_def_ref: agent,
    })
}

/// The room row of `turn`, read through owen's room history.
fn row(fixture: &Fixture, turn: EntityId) -> TestResult<RoomTurn> {
    fixture
        .owen()
        .rooms_messages(fixture.room)?
        .into_iter()
        .find(|row| row.turn_id == turn.to_hex())
        .ok_or_else(|| format!("{:?} room keeps no row for {}", fixture.kind, turn.to_hex()).into())
}

/// The agents a wake is staged for on `turn`, duplicates kept.
fn woken(fixture: &Fixture, turn: EntityId) -> TestResult<Vec<EntityId>> {
    Ok(fixture
        .vault
        .staged_room_wakes()?
        .into_iter()
        .filter(|entry| entry.wake.turn == turn)
        .map(|entry| entry.wake.agent)
        .collect())
}

/// A thread opened by owen's plain reply on a trunk witness turn. Returns
/// the anchor and the thread's root.
fn open_thread(fixture: &Fixture) -> TestResult<(EntityId, EntityId)> {
    let (anchor, _) = speak_trunk(fixture)?;
    let root = plain_reply(fixture, anchor)?;
    Ok((anchor, root))
}

/// Q1: a TURN the DAG appends on the trunk keeps a room row in every room,
/// one that answers no turn and names no thread.
#[test]
fn every_room_rows_a_native_trunk_turn() -> TestResult {
    for kind in EVERY_ROOM {
        let fixture = open_fixture(kind)?;
        let mut input = plain_turn(&fixture, vec![])?;
        input.parent = fixture.vault.head(&fixture.room)?;
        input.advance = true;
        let turn = fixture.vault.append_dag_record(&fixture.owen(), &input)?.id;
        let row = row(&fixture, turn)?;
        assert_eq!(row.actor, fixture.owen.to_hex(), "{kind:?}");
        assert_eq!(row.reply_to, None, "{kind:?}");
        assert_eq!(row.thread_of, None, "{kind:?}");
    }
    Ok(())
}

/// ORDINARY-ROOM-HISTORY-SPEECH-PROJECTROOM-ONLY: the room speech door
/// lands a turn in every room, and the room's history serves its row.
#[test]
fn every_room_serves_speech_and_history() -> TestResult {
    for kind in EVERY_ROOM {
        let fixture = open_fixture(kind)?;
        let (turn, message) = speak_trunk(&fixture)?;
        let row = row(&fixture, turn)?;
        assert_eq!(row.message_ids, vec![message.to_hex()], "{kind:?}");
        assert_eq!(row.reply_to, None, "{kind:?}");
        assert_eq!(row.thread_of, None, "{kind:?}");
    }
    Ok(())
}

/// A plain thread reply keeps its row in every room and wakes the holder of
/// the thread's bound TASK in its own write, and only that holder.
#[test]
fn every_room_rows_a_plain_reply_and_wakes_the_bound_assignee() -> TestResult {
    for kind in EVERY_ROOM {
        let fixture = open_fixture(kind)?;
        let (anchor, root) = open_thread(&fixture)?;
        let root_row = row(&fixture, root)?;
        assert_eq!(root_row.reply_to, Some(anchor.to_hex()), "{kind:?}");
        assert_eq!(root_row.thread_of, Some(anchor.to_hex()), "{kind:?}");
        let task = create_task(&fixture, fixture.agent_a)?;
        fixture
            .vault
            .bind_room_thread_task(fixture.owen, fixture.room, root, task)?;
        assert_eq!(
            row(&fixture, root)?.task_ids,
            vec![task.to_hex()],
            "{kind:?}"
        );
        let reply = plain_reply(&fixture, anchor)?;
        let reply_row = row(&fixture, reply)?;
        assert_eq!(reply_row.reply_to, Some(root.to_hex()), "{kind:?}");
        assert_eq!(reply_row.thread_of, Some(anchor.to_hex()), "{kind:?}");
        let agents = woken(&fixture, reply)?;
        assert_eq!(agents, vec![fixture.agent_a], "{kind:?}");
        assert!(!agents.contains(&fixture.owen), "{kind:?}");
        assert!(!agents.contains(&fixture.agent_b), "{kind:?}");
    }
    Ok(())
}

/// `tasks.create.from_message` mints and binds a TASK on a thread in every
/// room, and a later reply there wakes its assignee.
#[test]
fn every_room_binds_a_task_made_from_a_thread_turn() -> TestResult {
    for kind in EVERY_ROOM {
        let fixture = open_fixture(kind)?;
        let (anchor, root) = open_thread(&fixture)?;
        let receipt = fixture
            .owen()
            .tasks_create_from_message(root, &task_spec(&fixture, fixture.agent_a))?;
        let task = receipt
            .task_ref
            .ok_or("TASK creation did not take effect")?;
        assert_eq!(
            row(&fixture, root)?.task_ids,
            vec![task.to_hex()],
            "{kind:?}"
        );
        let reply = plain_reply(&fixture, anchor)?;
        assert_eq!(woken(&fixture, reply)?, vec![fixture.agent_a], "{kind:?}");
    }
    Ok(())
}

/// Q3, the binder: a PERSON with no standing in the room binds nothing, in
/// any room, and the thread's bindings stay as they were; owen, who reads
/// the thread, binds the same TASK after.
#[test]
fn every_room_refuses_a_binder_without_read_standing() -> TestResult {
    for kind in EVERY_ROOM {
        let fixture = open_fixture(kind)?;
        let (_, root) = open_thread(&fixture)?;
        let task = create_task(&fixture, fixture.agent_a)?;
        let outsider = EntityId::now();
        fixture.vault.put_entity(
            &outsider,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
        let refused = fixture
            .vault
            .bind_room_thread_task(outsider, fixture.room, root, task);
        assert!(
            matches!(refused, Err(oneiron::Error::InvalidConfig(_))),
            "{kind:?}: an outsider's bind is refused as an unknown thread, not {refused:?}"
        );
        assert!(row(&fixture, root)?.task_ids.is_empty(), "{kind:?}");
        fixture
            .vault
            .bind_room_thread_task(fixture.owen, fixture.room, root, task)?;
        assert_eq!(
            row(&fixture, root)?.task_ids,
            vec![task.to_hex()],
            "{kind:?}"
        );
    }
    Ok(())
}

/// Q3, the assignee: a TASK whose assignee stands nowhere in the room, B,
/// binds to no thread there, in any room.
#[test]
fn every_room_refuses_an_assignee_without_standing() -> TestResult {
    for kind in EVERY_ROOM {
        let fixture = open_fixture(kind)?;
        let (_, root) = open_thread(&fixture)?;
        let task = create_task(&fixture, fixture.agent_b)?;
        let refused = fixture
            .vault
            .bind_room_thread_task(fixture.owen, fixture.room, root, task);
        assert!(
            matches!(
                refused,
                Err(oneiron::Error::Record(
                    oneiron::error::RecordError::InvalidTaskBody(_)
                ))
            ),
            "{kind:?}: a TASK for an agent off the room is refused on its assignee, not {refused:?}"
        );
        assert!(row(&fixture, root)?.task_ids.is_empty(), "{kind:?}");
    }
    Ok(())
}

/// Q4 (THREAD-TASK-NATIVE-AGENT-RETRY), in an ordinary room: A's generated
/// reply keeps a room row, and its parent holds no claim, so owen's Retry
/// of it is queued for its DAG path, not refused for a claim it never had.
#[test]
fn ordinary_room_retry_of_an_unclaimed_rowed_reply_is_queued() -> TestResult {
    let fixture = open_fixture(RoomKind::Ordinary)?;
    speak_trunk(&fixture)?;
    let agent = fixture.vault.memory(fixture.agent_a, EdgeActorClass::Agent);
    let reply = EntityId::now();
    let handle = agent.begin_message_stream(
        &WitnessTurn {
            conversation_ref: fixture.room.to_hex(),
            turn_ref: Some(reply.to_hex()),
            thread_audience: None,
            messages: vec![WitnessMessage {
                id: Some(EntityId::now().to_hex()),
                author: WitnessAuthor::Companion,
                message_type: "text".into(),
                content: String::new(),
                parts: None,
                metadata: None,
                is_visible: true,
                order: 0,
                quote: None,
            }],
            occurred_at: fixture.vault.now_recorded_at(),
            assertions: Default::default(),
        },
        None,
    )?;
    agent.append_to_stream(handle, "yuki")?;
    agent.finalize_stream(handle)?;
    let reply_row = row(&fixture, reply)?;
    assert_eq!(reply_row.actor, fixture.agent_a.to_hex());
    let receipt = fixture
        .owen()
        .conversations_turn_retry(&TurnActionRequest {
            turn_id: reply.to_hex(),
        })?;
    assert_eq!(receipt.turn_id, reply.to_hex());
    Ok(())
}
