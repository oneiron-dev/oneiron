//! Shared room fixture for the reaction-claim suites.
use super::*;
use crate::conversation::{ConversationBody, ConversationKind, HistoryChoice};
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig, WriteActor};

mod claims;
mod lifecycle;
mod mirror;
mod recall;
mod signal;

pub(super) const PLAN: &str = "Friday plan works for everyone at noon";

pub(super) struct Room {
    pub(super) _dir: tempfile::TempDir,
    pub(super) vault: Vault,
    pub(super) room: EntityId,
    pub(super) alice: EntityId,
    pub(super) bob: EntityId,
    pub(super) dave: EntityId,
    pub(super) erin: EntityId,
    /// A PERSON who never joins the room.
    pub(super) carol: EntityId,
    /// Alice's message in the room.
    pub(super) message: EntityId,
}

pub(super) fn person(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("name"), rmpv::Value::from(name))]),
    )
    .unwrap();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &body,
        )
        .unwrap();
    id
}

pub(super) fn human(person: EntityId) -> WriteActor {
    WriteActor::new(person, EdgeActorClass::Human)
}

pub(super) fn witness(vault: &Vault, room: EntityId, author: EntityId, text: &str) -> EntityId {
    let message = EntityId::now();
    vault
        .memory(author, EdgeActorClass::Human)
        .witness(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: None,
            occurred_at: 10,
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "dialogue".to_owned(),
                content: text.to_owned(),
                metadata: None,
                is_visible: true,
                order: 0,
            }],
        })
        .unwrap();
    message
}

/// A room with Alice, Bob, Dave and Erin, and one message by Alice. A mirror
/// room also roots the vault and provisions the engine MACHINE writers.
pub(super) fn room_with(external_id: Option<&str>) -> Room {
    let dir = tempfile::tempdir().unwrap();
    let vault = Vault::open(dir.path(), VaultConfig::default()).unwrap();
    if external_id.is_some() {
        crate::test_util::provision_engine_machines(&vault);
    }
    let alice = person(&vault, "Alice");
    let bob = person(&vault, "Bob");
    let dave = person(&vault, "Dave");
    let erin = person(&vault, "Erin");
    let carol = person(&vault, "Carol");
    let room = EntityId::now();
    vault
        .create_conversation(
            room,
            &ConversationBody {
                kind: if external_id.is_some() {
                    ConversationKind::Mirror
                } else {
                    ConversationKind::Group
                },
                external_id: external_id.map(ToOwned::to_owned),
                ..Default::default()
            },
            human(alice),
            1,
        )
        .unwrap();
    for (at, member) in [(2, alice), (3, bob), (4, dave), (5, erin)] {
        vault
            .join_member(room, member, human(alice), at, HistoryChoice::Share)
            .unwrap();
    }
    let message = witness(&vault, room, alice, PLAN);
    permit_reads(&vault, alice);
    Room {
        _dir: dir,
        vault,
        room,
        alice,
        bob,
        dave,
        erin,
        carol,
        message,
    }
}

pub(super) fn room() -> Room {
    room_with(None)
}

pub(super) fn input(room: &Room, by: EntityId, glyph: &str) -> ReactionInput {
    ReactionInput {
        message: room.message,
        by,
        glyph: glyph.to_owned(),
        occurred_at: 20,
        actor: human(by),
    }
}

pub(super) fn react(room: &Room, by: EntityId, glyph: &str) -> ReactionChange {
    room.vault.react(input(room, by, glyph)).unwrap()
}

/// Grants `reader` the core read preset, as a host grants a reading actor.
pub(super) fn permit_reads(vault: &Vault, reader: EntityId) {
    let scope = crate::federation::scope_codec::encode_scope_value(
        &crate::federation::scope_codec::read_preset(),
    )
    .unwrap();
    let grant = rmpv::Value::Map(vec![
        ("actor_ref".into(), reader.to_hex().into()),
        ("effector".into(), "core:read".into()),
        ("scope".into(), scope),
        ("receipt_required".into(), false.into()),
    ]);
    let policy = rmpv::Value::Map(vec![
        ("schema_version".into(), "1.2".into()),
        ("pack_id".into(), "reaction-reader-test".into()),
        ("pack_version".into(), "1".into()),
        ("min_engine_version".into(), "0.0.0".into()),
        ("defaults".into(), rmpv::Value::Map(vec![])),
        ("rules".into(), rmpv::Value::Array(vec![])),
        ("actor_ceilings".into(), rmpv::Value::Array(vec![])),
        ("scoped_grants".into(), rmpv::Value::Array(vec![grant])),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &policy).unwrap();
    crate::test_util::put_policy_manifest_bytes(vault, EntityId::now(), &bytes).unwrap();
}

/// A scoped read as Alice, the room's owner, granted the core read preset.
pub(super) fn owner_read(room: &Room) -> crate::claim::ScopedRead<'_> {
    room.vault
        .scoped_read(crate::claim::ScopedReadActorKey::new(room.alice.to_hex()).unwrap())
}

/// Lets an agent PERSON write Auto claims, as an owner's ceiling row does.
pub(super) fn trust_agent(vault: &Vault, agent: EntityId) -> WriteActor {
    let actor = WriteActor::new(agent, EdgeActorClass::Agent);
    crate::conversation_dag::fixtures::grant(vault, actor, true);
    actor
}

pub(super) fn claim(vault: &Vault, id: EntityId) -> crate::ClaimBody {
    vault.get_claim(&id).unwrap().expect("reaction claim")
}
