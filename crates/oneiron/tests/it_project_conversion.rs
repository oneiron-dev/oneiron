use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::edge::EdgeActorClass;
use oneiron::genui::{
    ConsentActionKind, ConsentActionRequest, ConsentActorIdentity, ConsentSurface,
    PROJECT_PROPOSAL_MINT_ACTION_ID, ProjectGoalDraft, ProjectProposalCard, ProjectProposalPicks,
};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{ENTITY_TYPE_PERSON, ENTITY_TYPE_POLICY_MANIFEST, ENTITY_TYPE_SKILL};
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::store::GateDecisionId;
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
) {
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
    )
    .expect("fixture");
    source.roster.push(holder.to_hex());
    vault.put_project(source_id, &source, 1)?;
    let room = EntityId::from_hex(&source.home_room)?;
    let trunk = EntityId::now();
    let message = EntityId::now();
    speak(&vault, host, room, trunk, EntityId::now(), None);
    let thread = EntityId::now();
    speak(&vault, host, room, thread, message, Some(trunk));
    let run = vault.spawn_dag_sub_session(&thread, WriteActor::new(host, EdgeActorClass::Human))?;
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
    )
    .expect("fixture");
    vault.put_project(source_id, &source, 1)?;
    let room = EntityId::from_hex(&source.home_room)?;
    let trunk = EntityId::now();
    let message = EntityId::now();
    let thread = EntityId::now();
    speak(&vault, host, room, trunk, EntityId::now(), None);
    speak(&vault, host, room, thread, message, Some(trunk));
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

#[test]
fn confirmed_card_in_thread_mints_exact_terms_and_rejects_sibling_and_retired_owner() -> Result<()>
{
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), oneiron::VaultConfig::default())?;
    let host = EntityId::now();
    let owner_id = EntityId::now();
    for id in [host, owner_id] {
        vault.put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
    }
    let proof =
        vault.authenticate_owner(owner_id, "principal:owner", true, GateDecisionId::now())?;
    let source_id = EntityId::now();
    let mut source = ProjectRecord::new(
        source_id,
        Some(vault.root_project()?),
        vault.root_project()?,
        host,
    )
    .expect("fixture");
    source.roster.push(owner_id.to_hex());
    vault.put_project(source_id, &source, 1)?;
    let room = EntityId::from_hex(&source.home_room)?;
    let trunk = EntityId::now();
    speak(&vault, host, room, trunk, EntityId::now(), None);
    let thread = EntityId::now();
    let message = EntityId::now();
    speak(&vault, host, room, thread, message, Some(trunk));
    let second_message = EntityId::now();
    vault
        .memory(host, EdgeActorClass::Human)
        .rooms_speak(&WitnessTurn {
            conversation_ref: room.to_hex(),
            turn_ref: Some(thread.to_hex()),
            messages: vec![WitnessMessage {
                id: Some(second_message.to_hex()),
                author: WitnessAuthor::User,
                message_type: "text".into(),
                content: "another message".into(),
                metadata: Some(serde_json::json!({"room_thread_of": trunk.to_hex()})),
                is_visible: true,
                order: 1,
            }],
            occurred_at: 2,
        })
        .expect("second message in thread turn");
    let sibling = EntityId::now();
    speak(&vault, host, room, sibling, EntityId::now(), Some(trunk));
    let skill = EntityId::now();
    vault.put_skill_record(
        &skill,
        &SkillRecord::new(
            "project.seed.skill",
            "source skill",
            "1",
            ClaimApprovalStatus::Approved,
            SkillLifecycle::Candidate,
            ClaimSource::UserStated,
            1.0,
            false,
            true,
            vec![],
            rmpv::Value::Map(vec![(
                rmpv::Value::from("source"),
                rmpv::Value::from("owner"),
            )]),
        ),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let selected_leader =
        EntityId::from_hex(&vault.project(vault.root_project()?)?.expect("root").leader)?;
    assert_ne!(selected_leader, host);
    let card = ProjectProposalCard::new(
        "proposal-1",
        "principal:owner",
        message.to_hex(),
        ProjectGoalDraft {
            goal: "Build index".into(),
            why: "Find evidence".into(),
            axes: vec!["coverage".into()],
        },
        ProjectProposalPicks {
            leader_agent_def_ref: selected_leader.to_hex(),
            board_human_refs: vec![owner_id.to_hex()],
            budget_share_bps: 1250,
            starting_skill_refs: vec![skill.to_hex()],
        },
    )?
    .on_thread(room, thread)?;
    let request = ConsentActionRequest::new(
        "proposal-1",
        PROJECT_PROPOSAL_MINT_ACTION_ID,
        ConsentActionKind::ProjectMint,
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "principal:owner".into(),
        },
        ConsentSurface::CompanionConversation,
        4,
    )?;
    let wrong = EntityId::now();
    assert!(
        card.clone()
            .on_thread(room, sibling)?
            .convert_thread(&vault, &request, &proof, wrong, 4)
            .is_err()
    );
    assert!(vault.project(wrong)?.is_none());
    let id = EntityId::now();
    let project = card.convert_thread(&vault, &request, &proof, id, 4)?;
    assert_eq!(
        project.born_from.as_deref(),
        Some(message.to_hex().as_str())
    );
    assert_eq!(project.leader, selected_leader.to_hex());
    assert_eq!(project.board, vec![owner_id.to_hex()]);
    assert_eq!(
        project.goal_record.as_ref().expect("confirmed goal").why,
        "Find evidence"
    );
    assert_eq!(
        project.goal_record.as_ref().expect("confirmed goal").axes,
        vec!["coverage"]
    );
    assert_eq!(
        project.budget_share.as_ref().map(|share| share.share_bps),
        Some(1250)
    );
    assert_eq!(vault.message_hangs(message, room)?.projects, vec![id]);
    assert!(
        vault
            .message_hangs(second_message, room)?
            .projects
            .is_empty(),
        "only the card's message gets a project hang"
    );
    assert_eq!(project.skill_forks.len(), 1);
    let fork = EntityId::from_hex(&project.skill_forks[0])?;
    assert_eq!(
        vault.get_skill_record(&fork)?.expect("fork").forked_from,
        Some(skill)
    );

    // A fresh source thread with the same card terms, but a retired proof,
    // cannot create even the derived room or source fold marker.
    let fresh = EntityId::now();
    let fresh_message = EntityId::now();
    speak(&vault, host, room, fresh, fresh_message, Some(trunk));
    let stale = ProjectProposalCard::new(
        "proposal-1",
        "principal:owner",
        fresh_message.to_hex(),
        card.goal,
        ProjectProposalPicks {
            leader_agent_def_ref: selected_leader.to_hex(),
            board_human_refs: vec![owner_id.to_hex()],
            budget_share_bps: 1250,
            starting_skill_refs: vec![skill.to_hex()],
        },
    )?
    .on_thread(room, fresh)?;
    let survivor = EntityId::now();
    vault.put_entity(
        &survivor,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"survivor",
    )?;
    vault.apply_identity_topology_op(
        &oneiron::identity_topology::IdentityTopologyOp::Merge(
            oneiron::identity_topology::MergeOp {
                sources: vec![owner_id],
                survivor,
                evidence: oneiron::identity_topology::IdentityOpEvidence {
                    refs: vec![],
                    rationale: "retire owner proof".into(),
                },
                survivorship_plan: oneiron::identity_topology::SurvivorshipPlan::ReadThrough,
            },
        ),
        &oneiron::identity_topology::IdentityOpWrite::auto(ClaimSource::Inferred)
            .with_actor(WriteActor::new(host, EdgeActorClass::Human)),
        5,
    )?;
    let rejected = EntityId::now();
    assert!(
        stale
            .convert_thread(&vault, &request, &proof, rejected, 5)
            .is_err()
    );
    assert!(vault.project(rejected)?.is_none());
    assert!(vault.thread_project(room, fresh)?.is_none());
    Ok(())
}

#[test]
fn generic_project_write_proves_origin_and_prevents_duplicate_conversion() -> Result<()> {
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
    )
    .expect("fixture");
    vault.put_project(source_id, &source, 1)?;
    let room = EntityId::from_hex(&source.home_room)?;
    let trunk = EntityId::now();
    speak(&vault, host, room, trunk, EntityId::now(), None);
    let thread = EntityId::now();
    let message = EntityId::now();
    speak(&vault, host, room, thread, message, Some(trunk));
    let id = EntityId::now();
    let mut record = ProjectRecord::new(
        id,
        Some(source_id),
        EntityId::from_hex(&source.claims_scope_ref)?,
        host,
    )
    .expect("fixture");
    record.born_from = Some(host.to_hex()); // wrong type: PERSON, not MESSAGE
    record.origin_room = Some(room.to_hex());
    record.origin_thread = Some(thread.to_hex());
    record.origin_at = Some(2);
    assert_eq!(
        vault.put_project(id, &record, 3).unwrap_err().kind(),
        oneiron::ErrorKind::InvalidProjectBody
    );
    assert!(vault.project(id)?.is_none());
    record.born_from = Some(EntityId::now().to_hex()); // missing dependency stays pending for replay
    assert_eq!(
        vault.put_project(id, &record, 3).unwrap_err().kind(),
        oneiron::ErrorKind::ProjectDependencyPending
    );
    assert!(
        vault
            .project_room(EntityId::from_hex(&record.home_room)?)?
            .is_none()
    );
    record.born_from = Some(message.to_hex());
    vault
        .put_project(id, &record, 3)
        .expect("valid generic origin");
    assert_eq!(vault.thread_project(room, thread)?, Some(id));
    let second = EntityId::now();
    let mut duplicate = ProjectRecord::new(
        second,
        Some(source_id),
        EntityId::from_hex(&source.claims_scope_ref)?,
        host,
    )
    .expect("fixture");
    duplicate.born_from = record.born_from.clone();
    duplicate.origin_room = record.origin_room.clone();
    duplicate.origin_thread = record.origin_thread.clone();
    duplicate.origin_at = record.origin_at;
    assert!(vault.put_project(second, &duplicate, 3).is_err());
    assert!(
        vault
            .convert_thread_to_project(room, thread, message, second, None, 3)
            .is_err()
    );
    assert!(vault.project(second)?.is_none());
    // Common delete cleans the mapping; a new typed conversion can use the origin.
    assert!(vault.delete_entity(&id)?);
    assert_eq!(vault.thread_project(room, thread)?, None);
    Ok(())
}

/// Forbid the task-holder override in this fixture's shipped conversion row.
/// Only the closed fixture store is edited; no policy door is added.
fn forbid_holder_override(vault: Vault, path: &std::path::Path) -> Vault {
    use rmpv::Value;
    let config = oneiron::VaultConfig::default();
    let manifests = vault
        .entities_by_type(ENTITY_TYPE_POLICY_MANIFEST)
        .expect("policy ids");
    assert_eq!(manifests.len(), 1, "one seeded default policy");
    let id = manifests[0];
    let body = vault.get(&id).expect("policy body").expect("policy");
    let mut raw = vault.get_raw(&id).expect("policy record").expect("record");
    let mut manifest = rmpv::decode::read_value(&mut body.as_slice()).expect("decode policy");
    let Value::Map(entries) = &mut manifest else {
        panic!("policy is a map");
    };
    let Some(Value::Map(row)) = entries
        .iter_mut()
        .find_map(|(key, value)| (key.as_str() == Some("project_conversion")).then_some(value))
    else {
        panic!("shipped conversion row");
    };
    for (key, value) in row.iter_mut() {
        if key.as_str() == Some("allow_holder_override") {
            *value = Value::Boolean(false);
        }
    }
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, &manifest).expect("encode policy");
    raw.truncate(raw.len() - body.len());
    raw.extend_from_slice(&encoded);
    drop(vault);
    // SAFETY: the only Vault handle is dropped. This TempDir store is opened by
    // no other thread, and this Env closes before the Vault reopens.
    let env = unsafe {
        heed::EnvOpenOptions::new()
            .map_size(config.map_size)
            .max_readers(config.max_readers)
            .max_dbs(oneiron::store::MAX_DBS)
            .open(path)
            .expect("open the closed fixture store")
    };
    let mut wtxn = env.write_txn().expect("policy transaction");
    let entities: heed::Database<heed::types::Bytes, heed::types::Bytes> = env
        .open_database(&wtxn, Some("entities"))
        .expect("open entities")
        .expect("entities exist");
    entities
        .put(&mut wtxn, id.as_bytes(), &raw)
        .expect("store policy");
    // The fixture authored these bytes locally, so they keep the trusted stamp.
    let sync_state: heed::Database<heed::types::Str, heed::types::Bytes> = env
        .open_database(&wtxn, Some("sync_state"))
        .expect("open sync state")
        .expect("sync state exists");
    sync_state
        .put(
            &mut wtxn,
            &format!("manifest:trusted:{}", id.to_hex()),
            blake3::hash(&encoded).as_bytes(),
        )
        .expect("stamp policy");
    wtxn.commit().expect("commit policy");
    let _closing = env.prepare_for_closing();
    Vault::open(path, config).expect("reopen the fixture vault")
}

struct HeldThread {
    dir: tempfile::TempDir,
    vault: Vault,
    owner: EntityId,
    source_id: EntityId,
    source: ProjectRecord,
    room: EntityId,
    thread: EntityId,
    message: EntityId,
    task: EntityId,
    leader: EntityId,
}

/// A thread whose bound open task is held by an actor outside the source
/// roster, under a row that forbids that holder as leader.
fn held_thread(leader_in_roster: bool) -> Result<HeldThread> {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), oneiron::VaultConfig::default())?;
    let host = EntityId::now();
    let owner = EntityId::now();
    // The first-party connector actor may create tasks under the shipped policy.
    let holder = EntityId::from_bytes([0xE1; 16])?;
    for id in [host, owner, holder] {
        vault.put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"person",
        )?;
    }
    let root = vault.root_project()?;
    let leader = EntityId::from_hex(&vault.project(root)?.expect("root").leader)?;
    let source_id = EntityId::now();
    let mut source = ProjectRecord::new(source_id, Some(root), root, host).expect("fixture");
    source.roster.push(owner.to_hex());
    if leader_in_roster {
        source.roster.push(leader.to_hex());
    }
    vault.put_project(source_id, &source, 1)?;
    let room = EntityId::from_hex(&source.home_room)?;
    let trunk = EntityId::now();
    speak(&vault, host, room, trunk, EntityId::now(), None);
    let thread = EntityId::now();
    let message = EntityId::now();
    speak(&vault, host, room, thread, message, Some(trunk));
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
    vault.bind_room_thread_task(room, thread, task)?;
    let vault = forbid_holder_override(vault, dir.path());
    Ok(HeldThread {
        dir,
        vault,
        owner,
        source_id,
        source,
        room,
        thread,
        message,
        task,
        leader,
    })
}

fn mint_card(
    message: EntityId,
    leader: EntityId,
    owner: EntityId,
    skills: Vec<String>,
) -> Result<ProjectProposalCard> {
    ProjectProposalCard::new(
        "proposal-1",
        "principal:owner",
        message.to_hex(),
        ProjectGoalDraft {
            goal: "Build index".into(),
            why: "Find evidence".into(),
            axes: vec!["coverage".into()],
        },
        ProjectProposalPicks {
            leader_agent_def_ref: leader.to_hex(),
            board_human_refs: vec![owner.to_hex()],
            budget_share_bps: 1250,
            starting_skill_refs: skills,
        },
    )
}

fn mint_request() -> Result<ConsentActionRequest> {
    ConsentActionRequest::new(
        "proposal-1",
        PROJECT_PROPOSAL_MINT_ACTION_ID,
        ConsentActionKind::ProjectMint,
        ConsentActorIdentity::SurfaceActor {
            actor_ref: "principal:owner".into(),
        },
        ConsentSurface::CompanionConversation,
        4,
    )
}

#[test]
fn card_confirmed_leader_skips_task_holder_fallback() -> Result<()> {
    let HeldThread {
        dir: _dir,
        vault,
        owner,
        room,
        thread,
        message,
        task,
        leader,
        ..
    } = held_thread(true)?;
    // The row is in force: the unchosen fallback, the outside holder, is refused.
    assert!(
        vault
            .convert_thread_to_project(room, thread, message, EntityId::now(), None, 4)
            .is_err()
    );
    let proof = vault.authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())?;
    let id = EntityId::now();
    let project = mint_card(message, leader, owner, vec![])?
        .on_thread(room, thread)?
        .convert_thread(&vault, &mint_request()?, &proof, id, 4)?;
    assert_eq!(project.leader, leader.to_hex());
    assert_eq!(project.tasks, vec![task.to_hex()]);
    assert_eq!(vault.project(id)?, Some(project));
    assert_eq!(vault.thread_project(room, thread)?, Some(id));
    Ok(())
}

#[test]
fn disallowed_final_leader_rejects_with_no_writes() -> Result<()> {
    let HeldThread {
        dir: _dir,
        vault,
        owner,
        source_id,
        mut source,
        room,
        thread,
        message,
        task,
        leader,
    } = held_thread(false)?;
    let skill = EntityId::now();
    vault.put_skill_record(
        &skill,
        &SkillRecord::new(
            "project.seed.skill",
            "source skill",
            "1",
            ClaimApprovalStatus::Approved,
            SkillLifecycle::Candidate,
            ClaimSource::UserStated,
            1.0,
            false,
            true,
            vec![],
            rmpv::Value::Map(vec![(
                rmpv::Value::from("source"),
                rmpv::Value::from("owner"),
            )]),
        ),
        TimeRange { start: 1, end: 1 },
        1,
    )?;
    let skills = vault.entities_by_type(ENTITY_TYPE_SKILL)?.len();
    let proof = vault.authenticate_owner(owner, "principal:owner", true, GateDecisionId::now())?;
    let card = mint_card(message, leader, owner, vec![skill.to_hex()])?.on_thread(room, thread)?;
    let request = mint_request()?;

    // The confirmed leader is outside the source roster and is not the holder.
    let rejected = EntityId::now();
    assert!(
        card.convert_thread(&vault, &request, &proof, rejected, 4)
            .is_err()
    );
    assert!(vault.project(rejected)?.is_none(), "no PROJECT");
    let home_room = ProjectRecord::new(rejected, None, source_id, leader)
        .expect("fixture")
        .home_room;
    assert!(
        vault.get(&EntityId::from_hex(&home_room)?)?.is_none(),
        "no home room"
    );
    let row = vault
        .memory(owner, EdgeActorClass::Human)
        .rooms_messages(room)
        .expect("source room")
        .into_iter()
        .find(|turn_row| turn_row.turn_id == thread.to_hex())
        .expect("source thread");
    assert!(row.converted_project.is_none(), "no fold marker");
    assert_eq!(row.task_ids, vec![task.to_hex()], "no task move");
    assert_eq!(
        vault.entities_by_type(ENTITY_TYPE_SKILL)?.len(),
        skills,
        "no skill fork"
    );
    assert!(vault.thread_project(room, thread)?.is_none());

    // Once the source roster admits that leader, the untouched thread converts.
    source.roster.push(leader.to_hex());
    vault.put_project(source_id, &source, 5)?;
    let id = EntityId::now();
    let project = card.convert_thread(&vault, &request, &proof, id, 6)?;
    assert_eq!(project.leader, leader.to_hex());
    assert_eq!(project.tasks, vec![task.to_hex()]);
    assert_eq!(project.skill_forks.len(), 1);
    Ok(())
}
