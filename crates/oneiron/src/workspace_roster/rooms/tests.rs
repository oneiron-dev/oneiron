use super::*;
use crate::TimeRange;
use crate::edge::EdgeActorClass;
use crate::memory::{WitnessAuthor, WitnessMessage};
use crate::workspace_roster::ProjectRecord;

fn turn(
    room: EntityId,
    id: EntityId,
    author: WitnessAuthor,
    metadata: serde_json::Value,
    at: u64,
) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: room.to_hex(),
        turn_ref: Some(id.to_hex()),
        messages: vec![WitnessMessage {
            id: Some(EntityId::now().to_hex()),
            author,
            message_type: "text".into(),
            content: "room message".into(),
            metadata: Some(metadata),
            is_visible: true,
            order: 0,
        }],
        occurred_at: at,
    }
}
#[test]
fn mention_claim_speech_scope_and_thread_head() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let owner = EntityId::now();
    let a = EntityId::from_bytes([0xE1; 16])?;
    let b = EntityId::now();
    for actor in [owner, a, b] {
        vault.put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"room participant",
        )?;
    }
    let project = EntityId::now();
    let mut spec = ProjectRecord::new(
        project,
        Some(vault.root_project()?),
        vault.root_project()?,
        owner,
    );
    spec.roster.extend([a.to_hex(), b.to_hex()]);
    vault.put_project(project, &spec, 1)?;
    let room = EntityId::from_hex(&spec.home_room)?;
    vault.bind_room_handle(room, "@companion", a)?;
    let user = vault.memory(owner, EdgeActorClass::Human);
    let first = vault.memory(a, EdgeActorClass::Agent);
    let other = vault.memory(b, EdgeActorClass::Agent);
    let asked = EntityId::now();
    user.rooms_speak(&turn(
        room,
        asked,
        WitnessAuthor::User,
        serde_json::json!({"room_mentions": ["@companion"]}),
        2,
    ))
    .expect("incoming mention");
    assert_eq!(first.rooms_list().unwrap().len(), 1);
    let messages = first.rooms_messages(room).unwrap();
    assert_eq!(messages[0].addressed_agents, BTreeSet::from([a.to_hex()]));
    let reply = turn(
        room,
        EntityId::now(),
        WitnessAuthor::Companion,
        serde_json::json!({"room_reply_to": asked.to_hex()}),
        3,
    );
    assert!(first.rooms_speak(&reply).is_err());
    assert_eq!(
        other.rooms_claim(room, asked, 3).unwrap(),
        RoomClaimOutcome::NotAddressed
    );
    assert!(other.rooms_speak(&reply).is_err());
    let RoomClaimOutcome::Claimed(receipt) = first.rooms_claim(room, asked, 3).unwrap() else {
        panic!("addressed companion claims");
    };
    assert_eq!(receipt.actor, a.to_hex());
    assert!(first.rooms_speak(&reply).is_ok());
    assert_eq!(first.rooms_messages(room).unwrap().len(), 2);
    let head = user.room_head(room).unwrap();
    user.rooms_speak(&turn(
        room,
        EntityId::now(),
        WitnessAuthor::User,
        serde_json::json!({"room_thread_of": asked.to_hex()}),
        4,
    ))
    .unwrap();
    assert_eq!(user.room_head(room).unwrap(), head);
    assert_eq!(user.rooms_messages(room).unwrap().len(), 3);
    let prior_scope = vault.project_room(room)?.unwrap().claims_scope_ref;
    spec.roster.push(EntityId::now().to_hex());
    vault.put_project(project, &spec, 5)?;
    assert_eq!(
        vault.project_room(room)?.unwrap().claims_scope_ref,
        prior_scope
    );
    Ok(())
}
