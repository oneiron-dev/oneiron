use oneiron::edge::EdgeActorClass;
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::TaskCreateSpec;
use oneiron::workspace_roster::{ProjectRecord, RoomOriginCard, RoomTrunkItem};
use oneiron::{EntityId, Result, TimeRange, Vault, WriteActor};

fn speak(
    vault: &Vault,
    host: EntityId,
    room: EntityId,
    turn: EntityId,
    message: EntityId,
    parent: Option<EntityId>,
) -> Result<()> {
    vault
        .memory(host, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(turn.to_hex()),
            messages: vec![WitnessMessage {
                id: Some(message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "thread message".into(),
                metadata: Some(match parent {
                    Some(id) => serde_json::json!({"room_thread_of":id.to_hex()}),
                    None => serde_json::json!({}),
                }),
                is_visible: true,
                order: 0,
            }],
            occurred_at: 2,
        })
        .expect("room speech");
    Ok(())
}

#[test]
fn conversion_moves_open_task_and_projects_thread_origin_without_copy() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), oneiron::VaultConfig::default())?;
    let host = EntityId::now();
    let holder = EntityId::from_bytes([0xE1; 16])?;
    for id in [host, holder] {
        vault.put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"actor",
        )?;
    }
    let source_id = EntityId::now();
    let mut source = ProjectRecord::new(
        source_id,
        Some(vault.root_project()?),
        vault.root_project()?,
        host,
    );
    source.roster.push(holder.to_hex());
    vault.put_project(source_id, &source, 1)?;
    let room = EntityId::from_hex(&source.home_room)?;
    let trunk = EntityId::now();
    let message = EntityId::now();
    speak(&vault, host, room, trunk, message, None)?;
    let thread = EntityId::now();
    speak(&vault, host, room, thread, EntityId::now(), Some(trunk))?;
    let run = vault.spawn_dag_sub_session(&trunk, WriteActor::new(host, EdgeActorClass::Human))?;
    let task = vault
        .memory(holder, EdgeActorClass::Agent)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::from("work"),
            Some("task".into()),
            None,
            Some(3),
        ))
        .expect("task created")
        .task_ref
        .expect("open task effects");
    vault
        .bind_room_thread_task(room, thread, task)
        .expect("task binding");
    let project_id = EntityId::now();
    let project = vault
        .convert_thread_to_project(room, thread, message, project_id, None, 4)
        .expect("conversion");
    assert_eq!(
        project.born_from.as_deref(),
        Some(message.to_hex().as_str())
    );
    assert_eq!(project.leader, holder.to_hex());
    assert_eq!(project.tasks, vec![task.to_hex()]);
    assert_eq!(vault.project(project_id)?, Some(project.clone()));
    let folded = vault
        .memory(host, EdgeActorClass::Human)
        .rooms_messages(room)
        .expect("source room still readable")
        .into_iter()
        .find(|turn_row| turn_row.turn_id == thread.to_hex())
        .expect("source thread");
    assert_eq!(
        folded.converted_project.as_deref(),
        Some(project_id.to_hex().as_str())
    );
    assert!(
        folded.task_ids.is_empty(),
        "tasks moved, not duplicated on the source thread"
    );

    let new_room = EntityId::from_hex(&project.home_room)?;
    assert_eq!(
        vault.room_origin_card(new_room)?,
        Some(RoomOriginCard {
            room: room.to_hex(),
            thread: thread.to_hex(),
            message: message.to_hex(),
            at: 2,
        })
    );
    let trunk = vault
        .memory(host, EdgeActorClass::Human)
        .room_trunk(new_room)
        .expect("origin trunk");
    assert_eq!(trunk.len(), 1);
    assert!(
        matches!(&trunk[0], RoomTrunkItem::Origin(card) if card.thread == thread.to_hex() && card.at == 2)
    );
    assert_eq!(
        vault.thread_project(room, thread).expect("thread lens"),
        Some(project_id)
    );
    let hangs = vault.message_hangs(message, room).expect("message hangs");
    assert_eq!(hangs.runs, vec![run]);
    assert_eq!(hangs.threads, vec![thread]);
    assert_eq!(hangs.projects, vec![project_id]);
    assert_eq!(
        hangs.meta_line(),
        vec![
            format!("run:{}", run.to_hex()),
            format!("thread:{}", thread.to_hex()),
            format!("project:{}", project_id.to_hex())
        ]
    );
    assert!(
        vault
            .convert_thread_to_project(room, thread, message, EntityId::now(), None, 5)
            .is_err()
    );
    drop(vault);
    let reopened = Vault::open(dir.path(), oneiron::VaultConfig::default())?;
    assert_eq!(
        reopened.room_origin_card(new_room)?,
        Some(RoomOriginCard {
            room: room.to_hex(),
            thread: thread.to_hex(),
            message: message.to_hex(),
            at: 2,
        })
    );
    Ok(())
}

#[test]
fn conversion_without_open_task_uses_room_host_and_rejects_wrong_origin() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), oneiron::VaultConfig::default())?;
    let host = EntityId::now();
    vault.put_entity(
        &host,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"host",
    )?;
    let source_id = EntityId::now();
    let source = ProjectRecord::new(
        source_id,
        Some(vault.root_project()?),
        vault.root_project()?,
        host,
    );
    vault.put_project(source_id, &source, 1)?;
    let room = EntityId::from_hex(&source.home_room)?;
    let trunk = EntityId::now();
    let message = EntityId::now();
    let thread = EntityId::now();
    speak(&vault, host, room, trunk, message, None)?;
    speak(&vault, host, room, thread, EntityId::now(), Some(trunk))?;
    let id = EntityId::now();
    assert!(
        vault
            .convert_thread_to_project(room, thread, EntityId::now(), id, None, 3)
            .is_err()
    );
    assert!(vault.project(id)?.is_none());
    let project = vault.convert_thread_to_project(room, thread, message, id, None, 3)?;
    assert_eq!(project.leader, host.to_hex());
    assert!(project.tasks.is_empty());
    Ok(())
}
