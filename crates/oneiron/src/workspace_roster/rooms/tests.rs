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
fn permit_room_reads(vault: &Vault, actors: &[EntityId]) -> Result<()> {
    permit_room_reads_with_types(vault, actors, None)
}

fn permit_room_reads_with_types(
    vault: &Vault,
    actors: &[EntityId],
    types: Option<&[u8]>,
) -> Result<()> {
    let bytes = crate::gate::default_policy_manifest();
    let mut manifest: serde_json::Value = rmp_serde::from_slice(&bytes).expect("policy");
    manifest["scoped_grants"] = serde_json::Value::Array(actors.iter().map(|actor| {
        let mut row = serde_json::json!({
            "actor_ref": actor.to_hex(), "effector": "core:read",
            "scope": serde_json::to_value(crate::federation::scope_codec::read_preset()).unwrap(),
            "receipt_required": false,
        });
        if let Some(types) = types { row["selectors"] = serde_json::json!({"entity_types": types}); }
        row
    }).collect());
    crate::test_util::put_policy_manifest_bytes(
        vault,
        crate::gate::default_policy_manifest_id()?,
        &rmp_serde::to_vec_named(&manifest).expect("encode policy"),
    )
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
    )?;
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
    let record = ProjectRecord::new(project, Some(root), root, owner)?;
    vault.put_project(project, &record, 1)?;
    let room = EntityId::from_hex(&record.home_room)?;
    let other_project = EntityId::now();
    let other_record = ProjectRecord::new(other_project, Some(root), root, owner)?;
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
    assert!(memory.rooms_trunk(room, foreign_turn).is_err());
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
    permit_room_reads(&vault, &[owner, agent])?;
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
        fill: RoomThreadFill::Stage,
        waits_per_thread: 8,
    };
    // A room-linked open TASK outside this reader's grant cannot affect
    // active/waiting rows, counts, direct get, or trunk headers.
    permit_room_reads_with_types(
        &vault,
        &[owner, agent],
        Some(&[crate::registry::ENTITY_TYPE_TURN]),
    )?;
    let hidden = human.rooms_threads(room, policy).unwrap();
    assert_eq!(hidden.quiet.rows.len(), 1);
    assert!(hidden.active.rows.is_empty());
    assert!(hidden.waiting.rows.is_empty());
    assert_eq!(
        human
            .rooms_get_thread(room, root)
            .unwrap()
            .unwrap()
            .open_tasks,
        0
    );
    assert!(human.rooms_trunk(room, trunk).unwrap().headers.is_empty());
    permit_room_reads(&vault, &[owner, agent])?;
    let sdk_render = crate::task_verb::sdk::invoke(
        &human,
        "rooms.render",
        serde_json::json!({"room_ref":room.to_hex()}),
    )
    .unwrap();
    assert!(sdk_render.as_array().is_some());
    let sdk_find = crate::task_verb::sdk::invoke(
        &human,
        "rooms.find",
        serde_json::json!({"room_ref":room.to_hex(),"limit":1}),
    )
    .unwrap();
    assert_eq!(sdk_find["rows"].as_array().unwrap().len(), 1);
    assert!(sdk_find["next_after"].is_null());
    let live = human.rooms_threads(room, policy).unwrap();
    assert!(human.rooms_trunk(room, trunk).unwrap().headers.is_empty());
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
    let sdk_get = crate::task_verb::sdk::invoke(
        &human,
        "rooms.get",
        serde_json::json!({"room_ref":room.to_hex(),"turn_ref":root.to_hex()}),
    )
    .unwrap();
    assert_eq!(sdk_get["result_header"], serde_json::json!(result.to_hex()));
    let sdk_trunk = crate::task_verb::sdk::invoke(
        &human,
        "rooms.trunk",
        serde_json::json!({"room_ref":room.to_hex(),"turn_ref":trunk.to_hex()}),
    )
    .unwrap();
    assert_eq!(
        sdk_trunk["headers"][0]["result_ref"],
        serde_json::json!(result.to_hex())
    );
    let trunk_view = human.rooms_trunk(room, trunk).unwrap();
    assert_eq!(trunk_view.turn.turn_id, trunk.to_hex());
    assert_eq!(
        human.room_head(room).unwrap().unwrap().turn_id,
        trunk.to_hex()
    );
    assert_eq!(
        trunk_view.headers,
        vec![RoomTrunkHeader {
            thread: root,
            task,
            result_ref: result,
        }]
    );
    assert_eq!(folded.quiet.rows[0].result_header, Some(result));
    // A TASK-only grant must not reveal the referenced TURN or its header.
    permit_room_reads_with_types(
        &vault,
        &[owner, agent],
        Some(&[crate::registry::ENTITY_TYPE_TASK]),
    )?;
    assert!(human.rooms_trunk(room, trunk).unwrap().headers.is_empty());
    assert_eq!(
        human
            .rooms_get_thread(room, root)
            .unwrap()
            .unwrap()
            .result_header,
        None
    );
    assert_eq!(
        human.rooms_threads(room, policy).unwrap().quiet.rows[0].result_header,
        None
    );
    // With no TASK grant, even its open/wait metadata and list count vanish.
    permit_room_reads_with_types(
        &vault,
        &[owner, agent],
        Some(&[crate::registry::ENTITY_TYPE_TURN]),
    )?;
    assert_eq!(
        human
            .rooms_get_thread(room, root)
            .unwrap()
            .unwrap()
            .open_tasks,
        0
    );
    assert!(human.rooms_trunk(room, trunk).unwrap().headers.is_empty());
    permit_room_reads(&vault, &[owner, agent])?;
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
    let direct = EntityId::now();
    human
        .rooms_speak(&turn(
            room,
            direct,
            WitnessAuthor::User,
            serde_json::json!({"room_reply_to": root.to_hex()}),
            1_000_000,
        ))
        .unwrap();
    assert_eq!(
        human.room_head(room).unwrap().unwrap().turn_id,
        trunk.to_hex()
    );
    let nested = EntityId::now();
    human
        .rooms_speak(&turn(
            room,
            nested,
            WitnessAuthor::User,
            serde_json::json!({"room_reply_to": direct.to_hex()}),
            1_000_001,
        ))
        .unwrap();
    assert_eq!(
        human.room_head(room).unwrap().unwrap().turn_id,
        trunk.to_hex()
    );
    assert_eq!(
        human
            .rooms_get_thread(room, root)
            .unwrap()
            .unwrap()
            .last_message_at,
        1_000_001
    );
    let active = human.rooms_threads(room, policy).unwrap();
    assert_eq!(active.active.rows[0].handle, root);
    assert_eq!(active.active.rows[0].result_header, Some(result));
    // A completed task may name a CLAIM in another world. Its TASK remains
    // readable, but the foreign result cannot appear as a trunk header.
    let foreign_world = EntityId::from_bytes([0xD6; 16])?;
    let allowed_world = EntityId::from_bytes([0xD7; 16])?;
    let foreign_result = EntityId::now();
    let mut claim = crate::claim::ClaimBody::new(
        "test.room_result",
        crate::claim::ClaimSubject::Entity(owner),
        rmpv::Value::from("private"),
        1.0,
        crate::claim::ClaimApprovalStatus::Approved,
        crate::claim::ClaimLifecycleStatus::Active,
    );
    claim.world = Some(foreign_world);
    vault
        .batch()
        .put_replicated(
            &foreign_result,
            crate::registry::ENTITY_TYPE_CLAIM,
            TimeRange { start: 5, end: 5 },
            5,
            &crate::claim::encode_claim_body(&claim)?,
        )
        .commit()?;
    let foreign_task = worker.tasks_create(&spec).unwrap().task_ref.unwrap();
    worker
        .land_task_result(
            foreign_task,
            &TaskResultInput {
                result_ref: foreign_result,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: 6,
            },
        )
        .unwrap();
    let mut manifest: serde_json::Value =
        rmp_serde::from_slice(&crate::gate::default_policy_manifest()).unwrap();
    let full = serde_json::to_value(crate::federation::scope_codec::read_preset()).unwrap();
    manifest["scoped_grants"] = serde_json::json!([
        {"actor_ref":owner.to_hex(),"effector":"core:read","scope":full,
            "selectors":{"entity_types":[crate::registry::ENTITY_TYPE_TASK,crate::registry::ENTITY_TYPE_TURN]},
            "receipt_required":false},
        {"actor_ref":owner.to_hex(),"effector":"core:read",
            "scope":serde_json::to_value(crate::federation::scope_codec::read_preset()).unwrap(),
            "selectors":{"world_ref":allowed_world.to_hex()},"receipt_required":false}
    ]);
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &rmp_serde::to_vec_named(&manifest).unwrap(),
    )?;
    let scoped = vault.scoped_read(
        crate::claim::ScopedReadActorKey::with_actor_class(owner.to_hex(), "human").unwrap(),
    );
    assert!(
        scoped
            .read(&[crate::claim::PointRead::id(foreign_result)], None)?
            .single()
            .value
            .is_none()
    );
    assert!(
        !human
            .rooms_trunk(room, trunk)
            .unwrap()
            .headers
            .iter()
            .any(|header| header.result_ref == foreign_result)
    );
    assert_ne!(
        human
            .rooms_get_thread(room, root)
            .unwrap()
            .unwrap()
            .result_header,
        Some(foreign_result)
    );
    permit_room_reads(&vault, &[owner, agent])?;
    // A reply changes liveness, not the durable terminal header on the trunk.
    assert!(
        human
            .rooms_trunk(room, trunk)
            .unwrap()
            .headers
            .contains(&trunk_view.headers[0])
    );
    Ok(())
}

#[test]
fn consult_question_turn_projects_an_open_wait_without_a_room_state_row() -> Result<()> {
    use crate::task_verb::{
        ConsultPayload, ConsultPayloadRef, ConsultResultInput, ConsultResultKind, TaskAssignee,
        TaskCreateSpec, TaskKind, TaskTtl,
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
    permit_room_reads(&vault, &[owner, asker, peer])?;
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
    let question = EntityId::now();
    human
        .rooms_speak(&turn(
            room,
            question,
            WitnessAuthor::User,
            serde_json::json!({"room_reply_to": root.to_hex()}),
            4,
        ))
        .unwrap();
    assert_eq!(
        human.room_head(room).unwrap().unwrap().turn_id,
        trunk.to_hex()
    );
    let spec = TaskCreateSpec::new(rmpv::Value::Nil, None, None, Some(5))
        .with_kind(TaskKind::Consult)
        .with_consult(ConsultPayload::question(
            ConsultPayloadRef::Turn(question),
            Vec::new(),
            EntityId::now(),
        ))
        .with_assignee(TaskAssignee::Peer { actor_ref: peer })
        .with_ttl(TaskTtl::at(1_000_010));
    let task = vault
        .memory(asker, EdgeActorClass::Agent)
        .tasks_create(&spec)
        .unwrap()
        .task_ref
        .unwrap();
    let policy = RoomThreadPolicy {
        now: 1_000_000,
        fresh_for: 1,
        rows_per_list: 4,
        tokens_per_list: 512,
        fill: RoomThreadFill::Stage,
        waits_per_thread: 8,
    };
    let projection = human.rooms_threads(room, policy).unwrap();
    assert!(projection.active.rows.is_empty());
    assert_eq!(projection.waiting.rows.len(), 1);
    assert_eq!(projection.waiting.rows[0].waits[0].who, peer);
    assert_eq!(projection.waiting.rows[0].waits[0].kind, RoomWaitKind::Ask);
    assert_eq!(projection.waiting.rows[0].waits[0].since, 5);
    assert_eq!(projection.waiting.rows[0].waits[0].next_nudge, None);
    vault
        .memory(peer, EdgeActorClass::Agent)
        .land_consult_result(
            task,
            &ConsultResultInput {
                kind: ConsultResultKind::Answer {
                    result_ref: trunk,
                    option: None,
                    evidence_refs: vec![ConsultPayloadRef::Turn(question)],
                },
                completed_at: 1_000_001,
            },
        )
        .unwrap();
    assert_eq!(
        human.rooms_threads(room, policy).unwrap().quiet.rows[0].result_header,
        Some(trunk)
    );
    assert_eq!(
        human.rooms_trunk(room, trunk).unwrap().headers[0].task,
        task
    );
    Ok(())
}

#[test]
fn peer_ask_wait_projects_its_existing_followup_ladder() -> Result<()> {
    use crate::task_verb::{
        ConsultPayloadRef, TaskAskDefault, TaskAskQuestion, TaskAskSpec, TaskAskTarget,
        TaskAssignee,
    };
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let peer = EntityId::from_bytes([0xE2; 16])?;
    vault.put_entity(
        &peer,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"room peer",
    )?;
    let project = EntityId::now();
    let mut record = ProjectRecord::new(
        project,
        Some(vault.root_project()?),
        vault.root_project()?,
        owner,
    );
    record.roster.push(peer.to_hex());
    vault.put_project(project, &record, 1)?;
    let room = EntityId::from_hex(&record.home_room)?;
    permit_room_reads(&vault, &[owner, peer])?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let trunk = EntityId::now();
    let root = EntityId::now();
    memory
        .rooms_speak(&turn(
            room,
            trunk,
            WitnessAuthor::User,
            serde_json::json!({}),
            2,
        ))
        .unwrap();
    memory
        .rooms_speak(&turn(
            room,
            root,
            WitnessAuthor::User,
            serde_json::json!({"room_thread_of": trunk.to_hex()}),
            3,
        ))
        .unwrap();
    let before = crate::unix_seconds_now();
    let mut ask = TaskAskSpec::shorthand(
        Some(TaskAskTarget::Responder(TaskAssignee::Peer {
            actor_ref: peer,
        })),
        TaskAskQuestion::new(ConsultPayloadRef::Turn(root)),
        Some(before + 300),
        TaskAskDefault::AskMe,
    );
    ask.remind = Some(vec![30, 60]);
    let receipt = memory.tasks_ask(&ask).unwrap();
    assert_eq!(receipt.task_refs.len(), 1);
    let projection = memory
        .rooms_threads(
            room,
            RoomThreadPolicy {
                now: before + 100,
                fresh_for: 1,
                rows_per_list: 8,
                tokens_per_list: 512,
                fill: RoomThreadFill::Stage,
                waits_per_thread: 8,
            },
        )
        .unwrap();
    assert_eq!(projection.waiting.rows.len(), 1);
    assert_eq!(projection.waiting.rows[0].waits[0].kind, RoomWaitKind::Ask);
    let due = projection.waiting.rows[0].waits[0].next_nudge.unwrap();
    assert!(due >= before + 30 && due <= crate::unix_seconds_now() + 30);
    Ok(())
}

#[test]
fn settled_multi_recipient_ask_drops_unanswered_sibling_wait() -> Result<()> {
    use crate::task_verb::{
        ConsultPayloadRef, TaskAskDefault, TaskAskQuestion, TaskAskSpec, TaskAskTarget, TaskAskWord,
    };
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let responders = [
        EntityId::from_bytes([0xD1; 16])?,
        EntityId::from_bytes([0xD2; 16])?,
    ];
    for id in responders {
        vault.put_entity(
            &id,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"responder",
        )?;
    }
    let project = EntityId::now();
    let mut record = ProjectRecord::new(
        project,
        Some(vault.root_project()?),
        vault.root_project()?,
        owner,
    );
    record
        .roster
        .extend(responders.iter().map(EntityId::to_hex));
    vault.put_project(project, &record, 1)?;
    let room = EntityId::from_hex(&record.home_room)?;
    permit_room_reads(&vault, &[owner, responders[0], responders[1]])?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let trunk = EntityId::now();
    let root = EntityId::now();
    memory
        .rooms_speak(&turn(
            room,
            trunk,
            WitnessAuthor::User,
            serde_json::json!({}),
            2,
        ))
        .unwrap();
    memory
        .rooms_speak(&turn(
            room,
            root,
            WitnessAuthor::User,
            serde_json::json!({"room_thread_of":trunk.to_hex()}),
            3,
        ))
        .unwrap();
    let now = crate::unix_seconds_now();
    let ask = TaskAskSpec::shorthand(
        Some(TaskAskTarget::People(responders.into())),
        TaskAskQuestion::new(ConsultPayloadRef::Turn(root)),
        Some(now + 300),
        TaskAskDefault::AskMe,
    );
    let receipt = memory.tasks_ask(&ask).unwrap();
    assert_eq!(receipt.task_refs.len(), 2);
    let policy = RoomThreadPolicy {
        now: now + 10,
        fresh_for: 1,
        rows_per_list: 8,
        tokens_per_list: 512,
        fill: RoomThreadFill::Stage,
        waits_per_thread: 8,
    };
    assert_eq!(
        memory.rooms_threads(room, policy).unwrap().waiting.rows[0]
            .waits
            .len(),
        2
    );
    vault
        .memory(responders[0], EdgeActorClass::Human)
        .tasks_answer(&receipt.handle, &TaskAskWord::new(responders[0]))
        .unwrap();
    let after = memory.rooms_threads(room, policy).unwrap();
    assert!(after.waiting.rows.is_empty());
    assert_eq!(after.quiet.rows.len(), 1);
    assert_eq!(memory.rooms_trunk(room, trunk).unwrap().headers.len(), 1);
    Ok(())
}

#[test]
fn room_manifest_changes_selected_rows_and_cannot_be_widened_by_caller() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), crate::VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let project = EntityId::now();
    let record = ProjectRecord::new(
        project,
        Some(vault.root_project()?),
        vault.root_project()?,
        owner,
    );
    vault.put_project(project, &record, 1)?;
    let room = EntityId::from_hex(&record.home_room)?;
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let trunk = EntityId::now();
    memory
        .rooms_speak(&turn(
            room,
            trunk,
            WitnessAuthor::User,
            serde_json::json!({}),
            1,
        ))
        .unwrap();
    for n in 2..=3 {
        memory
            .rooms_speak(&turn(
                room,
                EntityId::now(),
                WitnessAuthor::User,
                serde_json::json!({"room_thread_of":trunk.to_hex()}),
                n,
            ))
            .unwrap();
    }
    let caller = RoomThreadPolicy {
        now: 1000,
        fresh_for: 1,
        rows_per_list: 8,
        tokens_per_list: 512,
        fill: RoomThreadFill::Stage,
        waits_per_thread: 8,
    };
    assert_eq!(
        memory.rooms_threads(room, caller).unwrap().quiet.rows.len(),
        2
    );
    let mut manifest: serde_json::Value =
        rmp_serde::from_slice(&crate::gate::default_policy_manifest()).unwrap();
    manifest["room_thread"]["base"] = serde_json::json!({"fresh_for_secs":1,
        "rows_per_list":1, "tokens_per_list":256, "fill":"recency","waits_per_thread":4});
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &rmp_serde::to_vec_named(&manifest).unwrap(),
    )?;
    let narrowed = memory.rooms_threads(room, caller).unwrap();
    assert_eq!((narrowed.quiet.rows.len(), narrowed.quiet.more), (1, 1));
    assert_eq!(narrowed.quiet.rows[0].last_message_at, 3);
    assert_eq!(memory.rooms_find_threads(room, None, 8).unwrap().len(), 2);
    let first = crate::task_verb::sdk::invoke(
        &memory,
        "rooms.find",
        serde_json::json!({"room_ref":room.to_hex(),"limit":1}),
    )
    .unwrap();
    let cursor = first["next_after"].as_str().unwrap();
    let last = crate::task_verb::sdk::invoke(
        &memory,
        "rooms.find",
        serde_json::json!({"room_ref":room.to_hex(),"after":cursor,"limit":1}),
    )
    .unwrap();
    assert_eq!(last["rows"].as_array().unwrap().len(), 1);
    assert!(last["next_after"].is_null());
    // The owner can choose fourteen-day freshness above the shipped seven-day
    // working-set default; only the manifest's vault ceiling caps it.
    manifest["room_thread"]["base"]["fresh_for_secs"] = serde_json::json!(14 * 86_400);
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id()?,
        &rmp_serde::to_vec_named(&manifest).unwrap(),
    )?;
    let longer = RoomThreadPolicy {
        now: 10 * 86_400,
        fresh_for: 14 * 86_400,
        ..caller
    };
    assert_eq!(
        memory
            .rooms_threads(room, longer)
            .unwrap()
            .active
            .rows
            .len(),
        1
    );
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
    let key = super::super::project::ROOM_PROJECT.key_bytes(&room);
    let mut txn = vault.store.env.write_txn()?;
    vault.store.vault_meta.delete(&mut txn, &key)?;
    txn.commit()?;
    assert_eq!(vault.room_audience_members(room)?, vec![leader, peer]);
    Ok(())
}
