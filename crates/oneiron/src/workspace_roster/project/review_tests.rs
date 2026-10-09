//! Acceptance regressions for indexed project origin and policy narrowing.
use super::*;
use crate::edge::EdgeActorClass;
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::registry::ENTITY_TYPE_PERSON;

fn room_fixture() -> Result<(
    tempfile::TempDir,
    Vault,
    EntityId,
    EntityId,
    EntityId,
    EntityId,
    EntityId,
)> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let host = EntityId::now();
    vault.put_entity(
        &host,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"host",
    )?;
    let source_id = EntityId::now();
    let root = vault.root_project()?;
    let source = ProjectRecord::new(source_id, Some(root), root, host).unwrap();
    vault.put_project(source_id, &source, 1)?;
    let room = EntityId::from_hex(&source.home_room)?;
    let trunk = EntityId::now();
    let message = EntityId::now();
    let thread = EntityId::now();
    let speak = |turn: EntityId, text: &str, parent: Option<EntityId>| WitnessTurn {
        conversation_ref: room.to_hex(),
        turn_ref: Some(turn.to_hex()),
        messages: vec![WitnessMessage {
            id: Some(
                if parent.is_some() {
                    message
                } else {
                    EntityId::now()
                }
                .to_hex(),
            ),
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: text.into(),
            metadata: Some(parent.map_or(
                serde_json::json!({}),
                |id| serde_json::json!({"room_thread_of":id.to_hex()}),
            )),
            is_visible: true,
            order: 0,
        }],
        occurred_at: 2,
    };
    let user = vault.memory(host, EdgeActorClass::Human);
    user.rooms_speak(&speak(trunk, "trunk", None))
        .expect("trunk");
    user.rooms_speak(&speak(thread, "thread", Some(trunk)))
        .expect("thread");
    Ok((dir, vault, room, thread, message, host, source_id))
}

#[test]
fn replicated_project_body_indexes_origin_and_blocks_later_local_conversion() -> Result<()> {
    let (_dir, vault, room, thread, message, host, source_id) = room_fixture()?;
    let source = vault.project(source_id)?.expect("source project");
    let kind = vault.project_type_byte()?;
    let id = EntityId::now();
    let mut record = ProjectRecord::new(
        id,
        Some(source_id),
        EntityId::from_hex(&source.claims_scope_ref)?,
        host,
    )
    .unwrap();
    record.born_from = Some(message.to_hex());
    record.origin_room = Some(room.to_hex());
    record.origin_thread = Some(thread.to_hex());
    record.origin_at = Some(2);
    let mut missing = record.clone();
    missing.born_from = Some(EntityId::now().to_hex());
    let pending = vault
        .batch()
        .put_replicated(
            &id,
            kind,
            TimeRange { start: 3, end: 3 },
            3,
            &encode(&missing)?,
        )
        .commit()
        .unwrap_err();
    assert_eq!(pending.kind(), crate::ErrorKind::ProjectDependencyPending);
    assert!(vault.project(id)?.is_none());
    vault
        .batch()
        .put_replicated(
            &id,
            kind,
            TimeRange { start: 3, end: 3 },
            3,
            &encode(&record)?,
        )
        .commit()?;
    assert_eq!(vault.thread_project(room, thread)?, Some(id));
    assert!(
        vault
            .convert_thread_to_project(room, thread, message, EntityId::now(), None, 4)
            .is_err()
    );
    Ok(())
}

#[test]
fn same_batch_source_roster_and_child_edit_commit_in_both_orders() -> Result<()> {
    let (_dir, vault, room, thread, message, _host, source_id) = room_fixture()?;
    let child_id = EntityId::now();
    vault.convert_thread_to_project(room, thread, message, child_id, None, 3)?;
    let kind = vault.project_type_byte()?;
    for (at, source_first) in [(4_u64, true), (5, false)] {
        let member = EntityId::now();
        vault.put_entity(
            &member,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"member",
        )?;
        let mut source = vault.project(source_id)?.expect("source project");
        source.roster.push(member.to_hex());
        let mut child = vault.project(child_id)?.expect("converted child");
        child.roster.push(member.to_hex());
        let (source_bytes, child_bytes) = (encode(&source)?, encode(&child)?);
        let when = TimeRange { start: at, end: at };
        let batch = vault.batch();
        let batch = if source_first {
            batch.put(&source_id, kind, when, at, &source_bytes).put(
                &child_id,
                kind,
                when,
                at,
                &child_bytes,
            )
        } else {
            batch.put(&child_id, kind, when, at, &child_bytes).put(
                &source_id,
                kind,
                when,
                at,
                &source_bytes,
            )
        };
        batch.commit()?;
        assert_eq!(vault.project(source_id)?, Some(source));
        assert_eq!(vault.project(child_id)?, Some(child));
    }
    assert_eq!(vault.thread_project(room, thread)?, Some(child_id));
    Ok(())
}
