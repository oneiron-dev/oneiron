//! A closed room (ARCH-0082 #closed-room; Engine ruling P26-SHAPE Q5 = A),
//! its setting: `vault.rooms.closed.set` closes or opens a room, and only a
//! person who is an owner of the room sets it, never an agent. The bit lives
//! on the room body; no other writer changes it, a new room starts open, and
//! a project's home room is not closed here.
//!
//! The vault is unrooted: its embedded owner is an owner of every room, and
//! the role door seats a second owner. Public paths only; no test door.
//! `cargo test --locked -p oneiron --all-features --test room_closed_set`.

use oneiron::conversation::{ConversationBody, ConversationKind, RoomRole};
use oneiron::memory::{CanAnswer, CanVerbAnswer, CanVerbGate, Memory, MemoryError};
use oneiron::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_PERSON};
use oneiron::verbs::{AgentDefinitionCreateRequest, AgentDefinitionSpec, CanRequest};
use oneiron::workspace_roster::{ProjectRecord, RoomClosedSet};
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CLOSED_SET: &str = "vault.rooms.closed.set";

struct Fixture {
    vault: Vault,
    owner: EntityId,
    co_owner: EntityId,
    admin: EntityId,
    member: EntityId,
    outsider: EntityId,
    agent: EntityId,
    room: EntityId,
    _directory: tempfile::TempDir,
}

fn put_person(vault: &Vault) -> TestResult<EntityId> {
    let person = EntityId::now();
    let now = vault.now_recorded_at();
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
    Ok(person)
}

/// The owner's group room seating a second owner, an admin and a member;
/// an outsider the room does not seat; one agent.
fn open_fixture() -> TestResult<Fixture> {
    let directory = tempfile::tempdir()?;
    let vault = Vault::open_owned(directory.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor()?;
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")?;
    let [co_owner, admin, member, outsider] = [
        put_person(&vault)?,
        put_person(&vault)?,
        put_person(&vault)?,
        put_person(&vault)?,
    ];
    let agent = EntityId::now();
    let definition: AgentDefinitionSpec = serde_json::from_value(json!({
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
            agent_def_ref: agent,
            definition,
        },
    )?;
    let room = EntityId::now();
    let as_owner = WriteActor::new(owner, EdgeActorClass::Human);
    vault.create_conversation(
        room,
        &ConversationBody {
            kind: ConversationKind::Group,
            member_ids: vec![co_owner, admin, member],
            ..Default::default()
        },
        as_owner,
        vault.now_recorded_at(),
    )?;
    vault.set_room_role(room, co_owner, RoomRole::Owner, as_owner)?;
    vault.set_room_role(room, admin, RoomRole::Admin, as_owner)?;
    Ok(Fixture {
        vault,
        owner,
        co_owner,
        admin,
        member,
        outsider,
        agent,
        room,
        _directory: directory,
    })
}

fn person(fx: &Fixture, actor: EntityId) -> Memory<'_> {
    fx.vault.memory(actor, EdgeActorClass::Human)
}

fn set_closed(
    memory: &Memory<'_>,
    room: EntityId,
    closed: bool,
) -> Result<RoomClosedSet, MemoryError> {
    memory.rooms_closed_set(&RoomClosedSet {
        room_ref: room,
        closed,
    })
}

fn stored_closed(fx: &Fixture, room: EntityId) -> TestResult<bool> {
    Ok(fx.vault.conversation_body(room)?.closed)
}

/// An owner of the room closes it, and the call answers the stored setting;
/// the same call again changes nothing; the second owner opens it.
#[test]
fn an_owner_closes_and_opens_the_room() -> TestResult {
    let fx = open_fixture()?;
    assert!(!stored_closed(&fx, fx.room)?, "a new room starts open");
    let closed = set_closed(&person(&fx, fx.owner), fx.room, true)?;
    assert_eq!(
        closed,
        RoomClosedSet {
            room_ref: fx.room,
            closed: true
        }
    );
    assert!(stored_closed(&fx, fx.room)?);
    assert!(set_closed(&person(&fx, fx.owner), fx.room, true)?.closed);
    assert!(stored_closed(&fx, fx.room)?);
    assert!(!set_closed(&person(&fx, fx.co_owner), fx.room, false)?.closed);
    assert!(!stored_closed(&fx, fx.room)?);
    Ok(())
}

/// No one but an owner sets it: the room's admin, a plain member and an
/// outsider are refused, and so is an agent, before anything is read. The
/// room stays as it was each time, open and then closed.
#[test]
fn no_one_but_an_owner_sets_it() -> TestResult {
    let fx = open_fixture()?;
    for closed in [true, false] {
        for caller in [fx.admin, fx.member, fx.outsider] {
            let refusal = set_closed(&person(&fx, caller), fx.room, closed)
                .expect_err("only an owner of the room closes or opens it");
            assert!(
                refusal.message.contains("only an owner of the room"),
                "{refusal:?}"
            );
        }
        let refusal = set_closed(
            &fx.vault.memory(fx.agent, EdgeActorClass::Agent),
            fx.room,
            closed,
        )
        .expect_err("an agent never closes or opens a room");
        assert!(refusal.message.contains("never an agent"), "{refusal:?}");
        assert_eq!(stored_closed(&fx, fx.room)?, !closed);
        set_closed(&person(&fx, fx.owner), fx.room, closed)?;
    }
    Ok(())
}

/// Only the door changes the bit: a room created closed is refused, a
/// generic put that closes or opens the room is refused, and another door's
/// rewrite of the body (the role door) keeps it.
#[test]
fn only_the_door_changes_the_bit() -> TestResult {
    let fx = open_fixture()?;
    let as_owner = WriteActor::new(fx.owner, EdgeActorClass::Human);
    let seeded = ConversationBody {
        kind: ConversationKind::Group,
        member_ids: vec![fx.member],
        closed: true,
        ..Default::default()
    };
    let refusal = fx
        .vault
        .create_conversation(
            EntityId::now(),
            &seeded,
            as_owner,
            fx.vault.now_recorded_at(),
        )
        .expect_err("a new room starts open");
    assert!(format!("{refusal:?}").contains("closed"), "{refusal:?}");
    let now = fx.vault.now_recorded_at();
    let range = TimeRange {
        start: now,
        end: now,
    };
    let mut body = fx.vault.conversation_body(fx.room)?;
    body.closed = true;
    let refusal = fx
        .vault
        .put_entity(
            &fx.room,
            ENTITY_TYPE_CONVERSATION,
            range,
            now,
            &body.to_bytes()?,
        )
        .expect_err("a generic put never closes a room");
    assert!(format!("{refusal:?}").contains("closed"), "{refusal:?}");
    assert!(!stored_closed(&fx, fx.room)?);
    set_closed(&person(&fx, fx.owner), fx.room, true)?;
    let mut body = fx.vault.conversation_body(fx.room)?;
    body.closed = false;
    assert!(
        fx.vault
            .put_entity(
                &fx.room,
                ENTITY_TYPE_CONVERSATION,
                range,
                now,
                &body.to_bytes()?
            )
            .is_err(),
        "a generic put never opens a room"
    );
    fx.vault
        .set_room_role(fx.room, fx.member, RoomRole::Admin, as_owner)?;
    assert!(stored_closed(&fx, fx.room)?, "the role door keeps the bit");
    Ok(())
}

/// A project's home room is not closed here, even by the vault's owner.
#[test]
fn a_home_room_is_not_closed_here() -> TestResult {
    let fx = open_fixture()?;
    let root_project = fx.vault.root_project()?;
    let project_id = EntityId::now();
    let project = ProjectRecord::new(project_id, Some(root_project), root_project, fx.member)?;
    fx.vault
        .put_project(project_id, &project, fx.vault.now_recorded_at())?;
    let home = EntityId::from_hex(&project.home_room)?;
    let refusal =
        set_closed(&person(&fx, fx.owner), home, true).expect_err("a home room is not closed here");
    assert!(refusal.message.contains("home room"), "{refusal:?}");
    Ok(())
}

/// `can({verb})` agrees with the call: an agent's gate says `person`, the
/// room's admin is refused with the door's reason, an owner's call lands.
#[test]
fn the_closed_gate_agrees_with_the_door() -> TestResult {
    let fx = open_fixture()?;
    let params = json!({ "room_ref": fx.room, "closed": true });
    let input: RoomClosedSet = serde_json::from_value(params.clone())?;
    for (memory, expected) in [
        (
            fx.vault.memory(fx.agent, EdgeActorClass::Agent),
            CanVerbGate::Person,
        ),
        (person(&fx, fx.admin), CanVerbGate::Refused),
        (person(&fx, fx.owner), CanVerbGate::Auto),
    ] {
        let answer = ask_gate(&memory, &params)?;
        assert_eq!(answer.gate, expected, "{answer:?}");
        match (answer.gate, memory.rooms_closed_set(&input)) {
            (CanVerbGate::Auto, Ok(_)) => {}
            (CanVerbGate::Person | CanVerbGate::Refused, Err(error)) => {
                assert_eq!(answer.reasons, vec![error.message], "{answer:?}");
            }
            (gate, call) => {
                return Err(format!("the gate answered {gate:?}, the call {call:?}").into());
            }
        }
    }
    assert!(stored_closed(&fx, fx.room)?);
    Ok(())
}

fn ask_gate(memory: &Memory<'_>, params: &serde_json::Value) -> TestResult<CanVerbAnswer> {
    let request: CanRequest =
        serde_json::from_value(json!({ "verb": { "name": CLOSED_SET, "params": params } }))?;
    match memory.can(&request)? {
        CanAnswer::Verb(answer) => Ok(answer),
        other => Err(format!("not a verb gate: {other:?}").into()),
    }
}
