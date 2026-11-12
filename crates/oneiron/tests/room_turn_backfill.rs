//! The one-time room-row backfill at writable open (THREAD-TASK-EVERY-ROOM
//! P2; Engine RULING EVERYROOM-P2-SHAPE Q1-Q4 = A, 12 Nov 16:01). A vault
//! older than P1 holds TURNs with no room row. Reopening it rows each of
//! them once, from what the TURN recorded, with the fields its own write
//! gave it at P1, and indexes it; a row that is present is kept as it is;
//! no wake is staged; every room is marked, an empty one too; a second pass
//! writes nothing.
//!
//! Fixture: owen, the vault's owner, and two agents, A and B, made through
//! the agent-definition door, reading the vault's records under the default
//! policy manifest and each room's MESSAGEs under a grant. Three rooms in
//! one vault: a project's home room seating owen and A, an ordinary room
//! linked to that project as an extra room, and an ordinary room; A stands
//! in the last two on the Ready join owen gave its offer card. A fourth,
//! empty ordinary room. In each of the three: owen's witness turn on the
//! trunk (T1), owen's native DAG turn on the trunk (T2), a thread on T1
//! opened by owen's plain reply (R1) and continued (R2), a thread on T2
//! (R3), and a TASK assigned to A bound to R1. The strip takes away every
//! row a vault older than P1 lacks; it keeps the rows such a vault held:
//! the home room's witness turn and the bound reply.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test room_turn_backfill`.
#![cfg(oneiron_test_support)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::conversation_dag::{AddressMode, AppendRecord};
use oneiron::core_write::ConversationCreateInput;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{Memory, WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::policy_manifest_doors::{
    ActorCeiling, PolicyCeiling, PolicyManifestPut, PolicyManifestRead, PolicyScopedGrantRow,
    policy_manifests_as_owner, put_policy_manifest_as_owner,
};
use oneiron::registry::ENTITY_TYPE_TURN;
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec};
use oneiron::test_doors::room_turn_backfill::{self as doors, ROOM_TURN_BACKFILL_VERSION};
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec};
use oneiron::workspace_roster::{
    JoinDecision, OfferAnswer, OfferAnswerRequest, OfferDraft, ProjectRecord,
    ProjectRoomLinkRequest, RoomTurn,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

/// The label this file's TASKs carry.
const FIXTURE_PATH: &str = "crates/oneiron/tests/room_turn_backfill.rs";

/// The TURNs the bulk room holds: a quarter on the trunk, each with a
/// thread of three replies.
const BULK_TURNS: u64 = 1_200;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The room kinds the fixture fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoomKind {
    /// A project's home room.
    Home,
    /// An ordinary room linked to a project as an extra room.
    Extra,
    /// An ordinary room of the vault.
    Ordinary,
}

struct Rig {
    vault: Vault,
    owen: EntityId,
    agent_a: EntityId,
    agent_b: EntityId,
    directory: tempfile::TempDir,
}

impl Rig {
    fn owen(&self) -> Memory<'_> {
        self.vault.memory(self.owen, EdgeActorClass::Human)
    }
}

/// The TURNs one filled room holds, and the ones the strip keeps.
struct FilledRoom {
    kind: RoomKind,
    room: EntityId,
    turns: Vec<EntityId>,
    keep: Vec<EntityId>,
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
            intent_key: format!("{FIXTURE_PATH}:offer:{}:{}", room.to_hex(), agent.to_hex()),
        })?;
    let accepted = vault
        .memory(owen, EdgeActorClass::Human)
        .rooms_offer_answer(&OfferAnswerRequest {
            offer_id: card.offer_id.clone(),
            action: OfferAnswer::Join,
            intent_key: format!("{FIXTURE_PATH}:answer:{}:{}", room.to_hex(), agent.to_hex()),
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

/// A vault with owen and the two agents, reading.
fn open_rig() -> TestResult<Rig> {
    let directory = tempfile::tempdir()?;
    // `open_owned` holds the writer lease the owner's doors ask for.
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owen = vault.ensure_embedded_owner_actor()?;
    let agent_a = create_agent(&vault, owen, "yuki")?;
    let agent_b = create_agent(&vault, owen, "yuki-two")?;
    grant_reads(&vault, owen, agent_a, agent_b)?;
    Ok(Rig {
        vault,
        owen,
        agent_a,
        agent_b,
        directory,
    })
}

/// A room of `kind` in the rig's vault, A standing in it.
fn make_room(rig: &Rig, kind: RoomKind) -> TestResult<EntityId> {
    let room = match kind {
        RoomKind::Home => project(&rig.vault, rig.owen, &[rig.agent_a])?.1,
        RoomKind::Extra => {
            let (project, _home) = project(&rig.vault, rig.owen, &[rig.agent_a])?;
            let room = ordinary_room(&rig.vault, rig.owen, "extra room")?;
            rig.owen().projects_rooms_link(&ProjectRoomLinkRequest {
                project_ref: project.to_hex(),
                room_ref: room.to_hex(),
            })?;
            room
        }
        RoomKind::Ordinary => ordinary_room(&rig.vault, rig.owen, "ordinary room")?,
    };
    for principal in [rig.agent_a, rig.agent_b] {
        grant_messages(&rig.vault, room, principal)?;
    }
    if kind != RoomKind::Home {
        join_room(&rig.vault, rig.owen, room, rig.agent_a)?;
    }
    Ok(room)
}

/// Drops the rig's vault and opens its directory again, the way a host
/// restarts. Returns the rig and the open's wall time in milliseconds.
fn reopen(rig: Rig) -> TestResult<(Rig, u128)> {
    let Rig {
        vault,
        owen,
        agent_a,
        agent_b,
        directory,
    } = rig;
    drop(vault);
    let started = Instant::now();
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let ms = started.elapsed().as_millis();
    Ok((
        Rig {
            vault,
            owen,
            agent_a,
            agent_b,
            directory,
        },
        ms,
    ))
}

/// owen's witness turn on `room`'s trunk, one MESSAGE, through the room
/// speech door. Returns the TURN.
fn speak_trunk(rig: &Rig, room: EntityId) -> TestResult<EntityId> {
    let turn = EntityId::now();
    rig.owen().rooms_speak(&WitnessTurn {
        conversation_ref: room.to_hex(),
        turn_ref: Some(turn.to_hex()),
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
        occurred_at: rig.vault.now_recorded_at(),
        assertions: Default::default(),
    })?;
    Ok(turn)
}

/// owen's plain TURN in `room` for the DAG's append doors, naming
/// `recipients`.
fn plain_turn(rig: &Rig, room: EntityId, recipients: Vec<EntityId>) -> TestResult<AppendRecord> {
    let now = rig.vault.now_recorded_at();
    Ok(AppendRecord {
        conversation: room,
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
        actor: WriteActor::new(rig.owen, EdgeActorClass::Human),
        thread_audience: None,
    })
}

/// owen's native DAG turn on `room`'s trunk, naming `recipients`.
fn native_trunk(rig: &Rig, room: EntityId, recipients: Vec<EntityId>) -> TestResult<EntityId> {
    let mut input = plain_turn(rig, room, recipients)?;
    input.parent = rig.vault.head(&room)?;
    input.advance = true;
    Ok(rig.vault.append_dag_record(&rig.owen(), &input)?.id)
}

/// owen's plain reply on `anchor`, through the REST thread reply's door:
/// the first opens the thread, a later one continues it. Returns the TURN.
fn plain_reply(rig: &Rig, room: EntityId, anchor: EntityId) -> TestResult<EntityId> {
    let input = plain_turn(rig, room, vec![])?;
    Ok(rig.vault.reply_in_thread(&rig.owen(), anchor, &input)?.id)
}

/// An open TASK owen owns, assigned to A.
fn create_task(rig: &Rig) -> TestResult<EntityId> {
    let spec = TaskCreateSpec::new(
        rmpv::Value::Nil,
        Some(FIXTURE_PATH.into()),
        Some(rig.owen),
        Some(rig.vault.now_recorded_at()),
    )
    .with_assignee(TaskAssignee::AgentDef {
        agent_def_ref: rig.agent_a,
    });
    let created = rig.owen().tasks_create(&spec)?;
    Ok(created
        .task_ref
        .ok_or("TASK creation did not take effect")?)
}

/// A room of `kind` holding T1, T2, R1 (bound), R2 and R3.
fn fill_room(rig: &Rig, kind: RoomKind) -> TestResult<FilledRoom> {
    let room = make_room(rig, kind)?;
    let t1 = speak_trunk(rig, room)?;
    let t2 = native_trunk(rig, room, vec![])?;
    let r1 = plain_reply(rig, room, t1)?;
    let task = create_task(rig)?;
    rig.vault.bind_room_thread_task(rig.owen, room, r1, task)?;
    let r2 = plain_reply(rig, room, t1)?;
    let r3 = plain_reply(rig, room, t2)?;
    // A vault older than P1 rowed a home room's witness turn, and a binding
    // needs the row it binds on.
    let keep = match kind {
        RoomKind::Home => vec![t1, r1],
        RoomKind::Extra | RoomKind::Ordinary => vec![r1],
    };
    Ok(FilledRoom {
        kind,
        room,
        turns: vec![t1, t2, r1, r2, r3],
        keep,
    })
}

/// The room rows of `room`, by TURN id.
fn rows_by_turn(vault: &Vault, room: EntityId) -> TestResult<BTreeMap<String, RoomTurn>> {
    Ok(doors::room_turn_rows(vault, room)?
        .into_iter()
        .map(|row| (row.turn_id.clone(), row))
        .collect())
}

/// `rebuilt` equals `native` field by field, then byte for byte.
fn assert_same_row(native: &RoomTurn, rebuilt: &RoomTurn, label: &str) -> TestResult {
    assert_eq!(rebuilt.turn_id, native.turn_id, "{label}: turn_id");
    assert_eq!(rebuilt.room_id, native.room_id, "{label}: room_id");
    assert_eq!(rebuilt.actor, native.actor, "{label}: actor");
    assert_eq!(
        rebuilt.addressed_agents, native.addressed_agents,
        "{label}: addressed_agents"
    );
    assert_eq!(
        rebuilt.message_ids, native.message_ids,
        "{label}: message_ids"
    );
    assert_eq!(rebuilt.reply_to, native.reply_to, "{label}: reply_to");
    assert_eq!(rebuilt.thread_of, native.thread_of, "{label}: thread_of");
    assert_eq!(rebuilt.at, native.at, "{label}: at");
    assert_eq!(rebuilt.task_ids, native.task_ids, "{label}: task_ids");
    assert_eq!(
        rebuilt.converted_project, native.converted_project,
        "{label}: converted_project"
    );
    assert_eq!(rebuilt.quotes, native.quotes, "{label}: quotes");
    assert_eq!(
        serde_json::to_vec(rebuilt)?,
        serde_json::to_vec(native)?,
        "{label}: stored bytes"
    );
    Ok(())
}

/// Every room wake attempt row and every staged wake's TURN.
fn wake_state(vault: &Vault) -> TestResult<(u64, Vec<EntityId>)> {
    let staged = vault
        .staged_room_wakes()?
        .into_iter()
        .map(|entry| entry.wake.turn)
        .collect();
    Ok((doors::room_wake_attempt_rows(vault)?, staged))
}

/// A vault whose three filled rooms lost every row a vault older than P1
/// lacks is reopened: each row comes back as P1's own write gave it, with
/// its index rows; the bound and the home witness rows were kept; no wake
/// is staged; every room, the empty one too, is marked; a second pass
/// writes nothing.
#[test]
fn reopen_rows_every_stripped_turn_of_every_room() -> TestResult {
    let rig = open_rig()?;
    let filled = vec![
        fill_room(&rig, RoomKind::Home)?,
        fill_room(&rig, RoomKind::Extra)?,
        fill_room(&rig, RoomKind::Ordinary)?,
    ];
    let empty = ordinary_room(&rig.vault, rig.owen, "empty room")?;
    let mut native = BTreeMap::new();
    let mut indexes = BTreeMap::new();
    for room in &filled {
        let rows = rows_by_turn(&rig.vault, room.room)?;
        for turn in &room.turns {
            assert!(
                rows.contains_key(&turn.to_hex()),
                "{:?}: P1 rows {}",
                room.kind,
                turn.to_hex()
            );
        }
        native.insert(room.room, rows);
        indexes.insert(room.room, doors::room_index_rows(&rig.vault, room.room)?);
    }
    let wakes = wake_state(&rig.vault)?;
    let mut stripped = 0;
    for room in &filled {
        stripped += doors::strip_room_turn_rows(&rig.vault, room.room, &room.keep)?;
        let left = rows_by_turn(&rig.vault, room.room)?;
        let kept: BTreeSet<String> = room.keep.iter().map(EntityId::to_hex).collect();
        assert_eq!(
            left.keys().cloned().collect::<BTreeSet<_>>(),
            kept,
            "{:?}: the strip leaves only the kept rows",
            room.kind
        );
        assert_eq!(
            doors::room_turn_backfill_marker(&rig.vault, room.room)?,
            None,
            "{:?}",
            room.kind
        );
    }
    assert_eq!(stripped, 11, "rows stripped: 3 + 4 + 4");
    let (rig, _) = reopen(rig)?;
    for room in &filled {
        let rebuilt = rows_by_turn(&rig.vault, room.room)?;
        let held = &native[&room.room];
        assert_eq!(
            rebuilt.keys().collect::<Vec<_>>(),
            held.keys().collect::<Vec<_>>(),
            "{:?}: every TURN keeps a row again",
            room.kind
        );
        for (turn, row) in held {
            assert_same_row(row, &rebuilt[turn], &format!("{:?} {turn}", room.kind))?;
        }
        assert_eq!(
            doors::room_index_rows(&rig.vault, room.room)?,
            indexes[&room.room],
            "{:?}: HISTORY, HEADS and THREAD_CHILDREN",
            room.kind
        );
        let served: BTreeSet<String> = rig
            .owen()
            .rooms_messages(room.room)?
            .into_iter()
            .map(|row| row.turn_id)
            .collect();
        for turn in &room.turns {
            assert!(
                served.contains(&turn.to_hex()),
                "{:?}: owen's room history serves {}",
                room.kind,
                turn.to_hex()
            );
        }
    }
    for room in filled.iter().map(|room| room.room).chain([empty]) {
        assert_eq!(
            doors::room_turn_backfill_marker(&rig.vault, room)?,
            Some(ROOM_TURN_BACKFILL_VERSION),
            "room {} is marked",
            room.to_hex()
        );
    }
    assert_eq!(
        wake_state(&rig.vault)?,
        wakes,
        "the backfill stages no wake"
    );
    let again = doors::run_room_turn_backfill(&rig.vault)?;
    assert_eq!(again.rooms_completed, 0, "{again:?}");
    assert_eq!(again.turns_written, 0, "{again:?}");
    Ok(())
}

/// A row that is present at the open is kept byte for byte, even one that
/// differs from what its TURN recorded; the rows around it are rebuilt.
#[test]
fn reopen_keeps_a_present_row_as_it_is() -> TestResult {
    let rig = open_rig()?;
    let filled = fill_room(&rig, RoomKind::Ordinary)?;
    let native = rows_by_turn(&rig.vault, filled.room)?;
    let t2 = filled.turns[1];
    let mut altered = native[&t2.to_hex()].clone();
    altered.addressed_agents.insert(rig.agent_b.to_hex());
    doors::strip_room_turn_rows(&rig.vault, filled.room, &[t2])?;
    doors::put_room_turn_row(&rig.vault, &altered)?;
    let (rig, _) = reopen(rig)?;
    let rebuilt = rows_by_turn(&rig.vault, filled.room)?;
    assert_eq!(
        serde_json::to_vec(&rebuilt[&t2.to_hex()])?,
        serde_json::to_vec(&altered)?,
        "the present row is never rewritten"
    );
    for (turn, row) in &native {
        if *turn != t2.to_hex() {
            assert_same_row(row, &rebuilt[turn], turn)?;
        }
    }
    Ok(())
}

/// Q1 = A: a rebuilt row names every recipient its DAG record named, and
/// the rebuild wakes none of them.
#[test]
fn reopen_names_every_recorded_recipient_and_wakes_no_one() -> TestResult {
    let rig = open_rig()?;
    let room = make_room(&rig, RoomKind::Ordinary)?;
    let turn = native_trunk(&rig, room, vec![rig.agent_a])?;
    let wakes = wake_state(&rig.vault)?;
    doors::strip_room_turn_rows(&rig.vault, room, &[])?;
    let (rig, _) = reopen(rig)?;
    let row = doors::room_turn_row(&rig.vault, turn)?.ok_or("no row after the reopen")?;
    assert_eq!(
        row.addressed_agents,
        BTreeSet::from([rig.agent_a.to_hex()]),
        "the recorded recipient"
    );
    assert_eq!(row.reply_to, None);
    assert_eq!(row.thread_of, None);
    assert_eq!(
        wake_state(&rig.vault)?,
        wakes,
        "the backfill stages no wake"
    );
    Ok(())
}

/// The time the pass takes for one room of `BULK_TURNS` TURNs, all in one
/// write, measured on its own and as the difference between the open that
/// runs it and an open that finds every room marked. No ceiling is asserted:
/// the fleet log carries the figures for the READY.
#[test]
fn backfill_time_on_a_bulk_room() -> TestResult {
    let rig = open_rig()?;
    let room = make_room(&rig, RoomKind::Ordinary)?;
    let mut anchor = None;
    for index in 0..BULK_TURNS {
        match (index % 4, anchor) {
            (0, _) | (_, None) => anchor = Some(native_trunk(&rig, room, vec![])?),
            (_, Some(anchor)) => {
                plain_reply(&rig, room, anchor)?;
            }
        }
    }
    let native = rows_by_turn(&rig.vault, room)?;
    assert_eq!(native.len() as u64, BULK_TURNS);
    assert_eq!(
        doors::strip_room_turn_rows(&rig.vault, room, &[])?,
        BULK_TURNS
    );
    let started = Instant::now();
    let pass = doors::run_room_turn_backfill(&rig.vault)?;
    let pass_ms = started.elapsed().as_millis();
    assert_eq!(pass.rooms_completed, 1, "{pass:?}");
    assert_eq!(pass.turns_written, BULK_TURNS, "{pass:?}");
    println!("BACKFILL turns={BULK_TURNS} rooms=1 ms={pass_ms}");
    let rebuilt = rows_by_turn(&rig.vault, room)?;
    for (turn, row) in &native {
        assert_same_row(row, &rebuilt[turn], turn)?;
    }
    doors::strip_room_turn_rows(&rig.vault, room, &[])?;
    let (rig, open_stripped_ms) = reopen(rig)?;
    let (rig, open_marked_ms) = reopen(rig)?;
    assert_eq!(rows_by_turn(&rig.vault, room)?.len() as u64, BULK_TURNS);
    println!(
        "BACKFILL-OPEN turns={BULK_TURNS} open_stripped_ms={open_stripped_ms} open_marked_ms={open_marked_ms}"
    );
    Ok(())
}
