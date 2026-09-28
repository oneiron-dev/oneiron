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

/// Installs one locally authored conversion row that narrows only its task cap.
fn narrow_conversion_task_cap(vault: &Vault, max_tasks: u64) -> Result<()> {
    let manifest = rmpv::Value::Map(vec![
        (
            rmpv::Value::from("schema_version"),
            rmpv::Value::from("1.2"),
        ),
        (
            rmpv::Value::from("pack_id"),
            rmpv::Value::from("project-conversion-cap-test"),
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
        (
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
                    rmpv::Value::from("inherit_source"),
                ),
                (rmpv::Value::from("max_tasks"), rmpv::Value::from(max_tasks)),
                (
                    rmpv::Value::from("task_holder_fallback"),
                    rmpv::Value::from("assignee_then_owner"),
                ),
                (
                    rmpv::Value::from("allow_holder_override"),
                    rmpv::Value::Boolean(true),
                ),
            ]),
        ),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &manifest).expect("policy encode");
    crate::test_util::put_policy_manifest_bytes(vault, EntityId::now(), &bytes)
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

#[test]
fn conversion_task_cap_does_not_limit_ordinary_project_edit_or_replay() -> Result<()> {
    let (_dir, vault, room, thread, message, host, source_id) = room_fixture()?;
    let worker = EntityId::from_bytes([0xE1; 16])?;
    vault.put_entity(
        &worker,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"worker",
    )?;
    let task = |n: u64| {
        vault
            .memory(worker, EdgeActorClass::Agent)
            .tasks_create(&TaskCreateSpec::new(
                rmpv::Value::from("work"),
                Some(format!("task {n}")),
                None,
                Some(n),
            ))
            .expect("task")
            .task_ref
            .expect("effected")
    };
    let source = vault.project(source_id)?.expect("source project");
    let ordinary_id = EntityId::now();
    let mut ordinary = ProjectRecord::new(
        ordinary_id,
        Some(source_id),
        EntityId::from_hex(&source.claims_scope_ref)?,
        host,
    );
    ordinary.tasks = vec![task(2).to_hex(), task(3).to_hex()];
    vault.put_project(ordinary_id, &ordinary, 3)?;
    vault.bind_room_thread_task(room, thread, task(4))?;
    vault.bind_room_thread_task(room, thread, task(5))?;
    narrow_conversion_task_cap(&vault, 1)?;

    // An ordinary roster and goal edit is not a conversion.
    let member = EntityId::now();
    vault.put_entity(
        &member,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"member",
    )?;
    ordinary.roster.push(member.to_hex());
    ordinary.why = Some("Keep shipping".into());
    ordinary.goal_record = Some(ProjectGoalRecord {
        project_id: ordinary_id.to_hex(),
        goal: "Ship the release".into(),
        why: "Keep shipping".into(),
        axes: vec!["pace".into()],
    });
    vault.put_project(ordinary_id, &ordinary, 4)?;
    assert_eq!(vault.project(ordinary_id)?, Some(ordinary.clone()));

    // Nor is a body replayed from another device.
    ordinary
        .goal_record
        .as_mut()
        .expect("goal record")
        .axes
        .push("quality".into());
    vault
        .batch()
        .put_replicated(
            &ordinary_id,
            vault.project_type_byte()?,
            TimeRange { start: 5, end: 5 },
            5,
            &encode(&ordinary)?,
        )
        .commit()?;
    assert_eq!(vault.project(ordinary_id)?, Some(ordinary));

    // Converting the two-task thread under the same row still rejects.
    let refused = EntityId::now();
    assert!(
        vault
            .convert_thread_to_project(room, thread, message, refused, None, 6)
            .is_err()
    );
    assert!(vault.project(refused)?.is_none());
    assert!(vault.thread_project(room, thread)?.is_none());
    Ok(())
}
