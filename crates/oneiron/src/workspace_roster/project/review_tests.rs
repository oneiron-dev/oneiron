//! Acceptance regressions for indexed project origin and policy narrowing.
use super::*;
use crate::edge::EdgeActorClass;
use crate::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::task_verb::TaskCreateSpec;

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
    let source = ProjectRecord::new(source_id, Some(root), root, host);
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
fn indexed_reads_ignore_unrelated_type_and_history_entries_past_old_scan_cap() -> Result<()> {
    let (_dir, vault, room, thread, message, _host, _source) = room_fixture()?;
    let project_id = EntityId::now();
    vault.convert_thread_to_project(room, thread, message, project_id, None, 3)?;
    let kind = vault.project_type_byte()?;
    vault.with_write_txn(|txn| {
        for n in 0..4100_u64 {
            let id = vault.store.clock.entity_id()?;
            let type_key = [&[kind][..], id.as_bytes()].concat();
            vault.store.type_index.put(txn, &type_key, &[])?;
            let history_key = [
                b"rooms.history.v1/".as_slice(),
                room.as_bytes(),
                (n + 100).to_be_bytes().as_slice(),
                id.as_bytes(),
            ]
            .concat();
            vault
                .store
                .vault_meta
                .put(txn, &history_key, id.as_bytes())?;
        }
        Ok(())
    })?;
    assert_eq!(vault.thread_project(room, thread)?, Some(project_id));
    assert_eq!(vault.message_hangs(message, room)?.projects, [project_id]);
    Ok(())
}

#[test]
fn policy_row_narrows_leader_roster_and_task_cap_at_conversion_door() -> Result<()> {
    let (_dir, vault, room, thread, message, host, _source) = room_fixture()?;
    let holder = EntityId::from_bytes([0xE1; 16])?;
    vault.put_entity(
        &holder,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"holder",
    )?;
    let task = vault
        .memory(holder, EdgeActorClass::Agent)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::from("work"),
            Some("task".into()),
            None,
            Some(2),
        ))
        .expect("task")
        .task_ref
        .expect("effected");
    let mut map = vec![
        (
            rmpv::Value::from("schema_version"),
            rmpv::Value::from("1.2"),
        ),
        (
            rmpv::Value::from("pack_id"),
            rmpv::Value::from("project-conversion-test"),
        ),
        (rmpv::Value::from("pack_version"), rmpv::Value::from("v1")),
        (
            rmpv::Value::from("min_engine_version"),
            rmpv::Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (rmpv::Value::from("defaults"), rmpv::Value::Map(vec![])),
        (rmpv::Value::from("rules"), rmpv::Value::Array(vec![])),
        (
            rmpv::Value::from("actor_ceilings"),
            rmpv::Value::Array(vec![]),
        ),
    ];
    map.push((
        rmpv::Value::from("project_conversion"),
        rmpv::Value::Map(vec![
            (
                rmpv::Value::from("precedence"),
                rmpv::Value::from("nested_narrowing_holder_override_capped_vault"),
            ),
            (
                rmpv::Value::from("leader_fallback"),
                rmpv::Value::from("task_holder_then_source_leader"),
            ),
            (
                rmpv::Value::from("roster_selection"),
                rmpv::Value::from("leader_only"),
            ),
            (rmpv::Value::from("max_tasks"), rmpv::Value::from(1)),
            (
                rmpv::Value::from("task_holder_fallback"),
                rmpv::Value::from("assignee_only"),
            ),
            (
                rmpv::Value::from("allow_holder_override"),
                rmpv::Value::Boolean(false),
            ),
        ]),
    ));
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &rmpv::Value::Map(map)).expect("policy encode");
    crate::test_util::put_policy_manifest_bytes(&vault, EntityId::now(), &bytes)?;
    vault.bind_room_thread_task(room, thread, task)?;
    let other_task = vault
        .memory(holder, EdgeActorClass::Agent)
        .tasks_create(&TaskCreateSpec::new(
            rmpv::Value::from("more"),
            Some("other".into()),
            None,
            Some(3),
        ))
        .expect("task")
        .task_ref
        .expect("effected");
    assert!(
        vault
            .bind_room_thread_task(room, thread, other_task)
            .is_err()
    );
    let refused = EntityId::now();
    assert!(
        vault
            .convert_thread_to_project(room, thread, message, refused, Some(holder), 4)
            .is_err()
    );
    assert!(vault.project(refused)?.is_none());
    let id = EntityId::now();
    let converted = vault.convert_thread_to_project(room, thread, message, id, None, 4)?;
    assert_eq!(converted.leader, host.to_hex());
    assert_eq!(converted.roster, [host.to_hex()]);
    assert_eq!(converted.tasks, [task.to_hex()]);
    Ok(())
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
    );
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
