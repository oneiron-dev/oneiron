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
    assert_eq!(vault.room_audience_members(room)?, vec![owner, a, b]);
    // The ordinary Conversation ledger is not the PROJECT roster source.
    assert!(vault.members(room)?.is_empty());
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

#[test]
fn room_history_is_bounded_paged_and_removed_with_its_project() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let owner = EntityId::now();
    vault.put_entity(
        &owner,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owner",
    )?;
    let root = vault.root_project()?;
    let project = EntityId::now();
    let record = ProjectRecord::new(project, Some(root), root, owner);
    vault.put_project(project, &record, 1)?;
    let room = EntityId::from_hex(&record.home_room)?;
    let other_project = EntityId::now();
    let other_record = ProjectRecord::new(other_project, Some(root), root, owner);
    vault.put_project(other_project, &other_record, 1)?;
    let other_room = EntityId::from_hex(&other_record.home_room)?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    vault.bind_room_handle(room, "@owner", owner)?;
    let mut turns = Vec::new();
    for n in 0..257 {
        let id = EntityId::now();
        memory
            .rooms_speak(&turn(
                room,
                id,
                WitnessAuthor::User,
                serde_json::json!({}),
                2 + n,
            ))
            .expect("speak");
        turns.push(id);
    }
    let foreign_turn = EntityId::now();
    memory
        .rooms_speak(&turn(
            other_room,
            foreign_turn,
            WitnessAuthor::User,
            serde_json::json!({}),
            999,
        ))
        .expect("other room");
    let page = memory.rooms_messages_page(room, None, 256).expect("page");
    assert_eq!(page.next_after, Some(turns[255].to_hex()));
    let exact = memory
        .rooms_messages_page(room, Some(turns[0]), 256)
        .expect("exact page");
    assert_eq!(exact.rows.len(), 256);
    assert_eq!(exact.next_after, None);
    let first = memory.rooms_messages(room).expect("first page");
    assert_eq!(first.len(), 256);
    assert_eq!(first[0].turn_id, turns[0].to_hex());
    assert_eq!(first[255].turn_id, turns[255].to_hex());
    let last = memory
        .rooms_messages_page(room, Some(turns[255]), 1)
        .expect("last page");
    assert_eq!(last.rows.len(), 1);
    assert_eq!(last.next_after, None);
    assert_eq!(last.rows[0].turn_id, turns[256].to_hex());
    assert!(
        memory
            .rooms_messages_page(room, Some(turns[256]), 256)
            .unwrap()
            .rows
            .is_empty()
    );
    assert!(
        memory
            .rooms_messages_page(room, Some(foreign_turn), 1)
            .is_err()
    );
    assert!(memory.rooms_messages_page(room, None, 257).is_err());
    // A cursor in another room is not a valid room-thread page boundary.
    assert!(
        memory
            .rooms_find_threads(room, Some(foreign_turn), 1)
            .is_err()
    );
    assert_eq!(
        memory.room_head(room).unwrap().unwrap().turn_id,
        turns[256].to_hex()
    );
    assert!(matches!(
        memory.rooms_claim(room, turns[0], 1000).unwrap(),
        RoomClaimOutcome::Claimed(_)
    ));
    vault.batch().delete(&project).commit()?;
    vault.put_project(project, &record, 1001)?;
    assert!(memory.rooms_messages(room).unwrap().is_empty());
    assert!(memory.room_head(room).unwrap().is_none());
    assert!(memory.rooms_claim(room, turns[0], 1002).is_err());
    assert!(
        memory
            .rooms_speak(&turn(
                room,
                EntityId::now(),
                WitnessAuthor::User,
                serde_json::json!({"room_mentions":["@owner"]}),
                1002
            ))
            .is_err()
    );
    assert_eq!(memory.rooms_messages(other_room).unwrap().len(), 1);
    Ok(())
}

#[test]
fn room_projection_reads_task_register_and_reply_without_stored_liveness() -> Result<()> {
    use crate::task_verb::{
        TaskAssignee, TaskCreateSpec, TaskResultInput, TaskTerminalDisposition,
    };
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let owner = EntityId::now();
    let agent = EntityId::from_bytes([0xE1; 16])?;
    for actor in [owner, agent] {
        vault.put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"room member",
        )?;
    }
    let project = EntityId::now();
    let mut record = ProjectRecord::new(
        project,
        Some(vault.root_project()?),
        vault.root_project()?,
        owner,
    );
    record.roster.push(agent.to_hex());
    vault.put_project(project, &record, 1)?;
    let room = EntityId::from_hex(&record.home_room)?;
    let human = vault.memory(owner, EdgeActorClass::Human);
    let worker = vault.memory(agent, EdgeActorClass::Agent);
    let trunk = EntityId::now();
    let root = EntityId::now();
    human
        .rooms_speak(&turn(
            room,
            trunk,
            WitnessAuthor::User,
            serde_json::json!({}),
            2,
        ))
        .unwrap();
    human
        .rooms_speak(&turn(
            room,
            root,
            WitnessAuthor::User,
            serde_json::json!({"room_thread_of": trunk.to_hex()}),
            3,
        ))
        .unwrap();
    let spec = TaskCreateSpec::new(
        rmpv::Value::Map(vec![(
            rmpv::Value::from("thread_ref"),
            rmpv::Value::from(root.to_hex()),
        )]),
        None,
        None,
        Some(4),
    )
    .with_assignee(TaskAssignee::Dreamer);
    let task = worker.tasks_create(&spec).unwrap().task_ref.unwrap();
    let policy = RoomThreadPolicy {
        now: 1_000_000,
        fresh_for: 1,
        rows_per_list: 4,
        tokens_per_list: 512,
    };
    let live = human.rooms_threads(room, policy).unwrap();
    assert_eq!(live.active.rows[0].handle, root);
    assert_eq!(live.active.rows[0].open_tasks, 1);
    assert!(
        human
            .rooms_render_threads(room, policy)
            .unwrap()
            .iter()
            .any(|row| row.starts_with("threads active: 1"))
    );
    // A room TURN is a resolved durable output ref, independent of the task.
    let result = trunk;
    worker
        .land_task_result(
            task,
            &TaskResultInput {
                result_ref: result,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: 5,
            },
        )
        .unwrap();
    let folded = human.rooms_threads(room, policy).unwrap();
    assert_eq!(folded.quiet.rows[0].result_header, Some(result));
    assert_eq!(folded.quiet.rows[0].trunk, trunk);
    assert_eq!(
        human.rooms_find_threads(room, None, 10).unwrap(),
        vec![root]
    );
    assert_eq!(
        human
            .rooms_get_thread(room, root)
            .unwrap()
            .unwrap()
            .result_header,
        Some(result)
    );
    human
        .rooms_speak(&turn(
            room,
            EntityId::now(),
            WitnessAuthor::User,
            serde_json::json!({"room_reply_to": root.to_hex()}),
            1_000_000,
        ))
        .unwrap();
    let active = human.rooms_threads(room, policy).unwrap();
    assert_eq!(active.active.rows[0].handle, root);
    assert_eq!(active.active.rows[0].result_header, Some(result));
    Ok(())
}

#[test]
fn consult_question_turn_projects_an_open_wait_without_a_room_state_row() -> Result<()> {
    use crate::task_verb::{
        ConsultPayload, ConsultPayloadRef, TaskAssignee, TaskCreateSpec, TaskKind, TaskTtl,
    };
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let owner = EntityId::now();
    let asker = EntityId::from_bytes([0xE1; 16])?;
    let peer = EntityId::from_bytes([0xE2; 16])?;
    for actor in [owner, asker, peer] {
        vault.put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"room member",
        )?;
    }
    let project = EntityId::now();
    let mut record = ProjectRecord::new(
        project,
        Some(vault.root_project()?),
        vault.root_project()?,
        owner,
    );
    record.roster.extend([asker.to_hex(), peer.to_hex()]);
    vault.put_project(project, &record, 1)?;
    let room = EntityId::from_hex(&record.home_room)?;
    let human = vault.memory(owner, EdgeActorClass::Human);
    let trunk = EntityId::now();
    let root = EntityId::now();
    human
        .rooms_speak(&turn(
            room,
            trunk,
            WitnessAuthor::User,
            serde_json::json!({}),
            2,
        ))
        .unwrap();
    human
        .rooms_speak(&turn(
            room,
            root,
            WitnessAuthor::User,
            serde_json::json!({"room_thread_of": trunk.to_hex()}),
            3,
        ))
        .unwrap();
    let spec = TaskCreateSpec::new(rmpv::Value::Nil, None, None, Some(4))
        .with_kind(TaskKind::Consult)
        .with_consult(ConsultPayload::question(
            ConsultPayloadRef::Turn(root),
            Vec::new(),
            EntityId::now(),
        ))
        .with_assignee(TaskAssignee::Peer { actor_ref: peer })
        .with_ttl(TaskTtl::at(1_000_010));
    assert!(
        vault
            .memory(asker, EdgeActorClass::Agent)
            .tasks_create(&spec)
            .unwrap()
            .task_ref
            .is_some()
    );
    let policy = RoomThreadPolicy {
        now: 1_000_000,
        fresh_for: 1,
        rows_per_list: 4,
        tokens_per_list: 512,
    };
    let projection = human.rooms_threads(room, policy).unwrap();
    assert!(projection.active.rows.is_empty());
    assert_eq!(projection.waiting.rows.len(), 1);
    assert_eq!(projection.waiting.rows[0].waits[0].who, peer);
    assert_eq!(projection.waiting.rows[0].waits[0].kind, RoomWaitKind::Ask);
    assert_eq!(projection.waiting.rows[0].waits[0].since, 4);
    assert_eq!(projection.waiting.rows[0].waits[0].next_nudge, None);
    Ok(())
}

#[test]
fn exact_project_and_room_batch_still_has_a_roster_audience() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let leader = EntityId::now();
    let peer = EntityId::now();
    for person in [leader, peer] {
        vault.put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"member",
        )?;
    }
    let project = EntityId::now();
    let root = vault.root_project()?;
    let mut record = ProjectRecord::new(project, Some(root), root, leader);
    record.roster.push(peer.to_hex());
    let room = EntityId::from_hex(&record.home_room)?;
    let room_body = crate::workspace_roster::ProjectRoom {
        schema_version: 1,
        kind: "channel".into(),
        project_id: project.to_hex(),
        member_ids: record.roster.clone(),
        claims_scope_ref: record.claims_scope_ref.clone(),
    };
    vault
        .batch()
        .put(
            &project,
            vault.project_type_byte()?,
            TimeRange { start: 2, end: 2 },
            2,
            &rmp_serde::to_vec_named(&record).expect("project encode"),
        )
        .put(
            &room,
            crate::registry::ENTITY_TYPE_CONVERSATION,
            TimeRange { start: 2, end: 2 },
            2,
            &rmp_serde::to_vec_named(&room_body).expect("room encode"),
        )
        .commit()?;
    assert_eq!(vault.room_audience_members(room)?, vec![leader, peer]);
    // The stored derived body identifies the substrate even if the auxiliary
    // marker is absent. Losing it cannot reinterpret this room as empty.
    let key = [super::super::project::ROOM_PROJECT, room.as_bytes()].concat();
    let mut txn = vault.store.env.write_txn()?;
    vault.store.vault_meta.delete(&mut txn, &key)?;
    txn.commit()?;
    assert_eq!(vault.room_audience_members(room)?, vec![leader, peer]);
    Ok(())
}
