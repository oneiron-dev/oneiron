//! ARCH-0067 §8 acceptance: one roster-to-Scope function, and every read a
//! room turn makes runs inside the Scope it returns.
use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource, PointRead};
use crate::edge::EdgeActorClass;
use crate::memory::{ClaimInput, ClaimListFilter, WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::pipeline::{PREDICATE_WORLD_ACCESS_ALLOWED_SET, world_access_claim_body};
use crate::workspace_roster::ProjectRecord;
use crate::{TimeRange, Vault, VaultConfig};

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).unwrap()
}

fn member(actor: EntityId, worlds: WorldAuthoritySet) -> RoomPresence {
    RoomPresence {
        actor,
        actor_class: None,
        label: actor.to_hex(),
        present: true,
        active_worlds: worlds,
        clearance: None,
    }
}

#[test]
fn room_scope_is_the_ordinary_scope_and_a_join_only_narrows() -> Result<()> {
    let a = member(id(1), WorldAuthoritySet::new(true, [id(3), id(4)])?);
    let b = member(id(2), WorldAuthoritySet::new(false, [id(4), id(5)])?);
    let one: Scope = room_scope(std::slice::from_ref(&a))?;
    let two = room_scope(&[a.clone(), b.clone()])?;
    assert!(two.is_narrowing_of(&one));
    assert_eq!(
        two.worlds,
        ScopeAxis::Some(BTreeSet::from([ScopeId(id(4))]))
    );
    assert_eq!(two.facets, Scope::top().facets);
    // An away member does not count, and nobody present reads nothing.
    let away = RoomPresence {
        present: false,
        ..b
    };
    assert_eq!(room_scope(&[a, away])?, one);
    assert_eq!(room_scope::<RoomPresence>(&[])?, Scope::default());
    // A world id equal to the reserved base id is not base authority.
    let smuggled = member(
        id(8),
        WorldAuthoritySet::new(false, [crate::claim::base_world_id()])?,
    );
    assert_eq!(room_scope(&[smuggled])?.worlds, ScopeAxis::Bottom);
    Ok(())
}

fn grant(vault: &Vault, row: EntityId, actor: EntityId, worlds: WorldAuthoritySet) -> Result<()> {
    let body = world_access_claim_body(
        PREDICATE_WORLD_ACCESS_ALLOWED_SET,
        actor,
        &worlds,
        ClaimSource::UserStated,
        ClaimApprovalStatus::Approved,
        None,
        None,
    )?;
    vault.put_claim(&row, &body, TimeRange { start: 1, end: 1 }, 1)
}

fn note(subject: EntityId, value: &str, world: Option<EntityId>) -> ClaimInput {
    ClaimInput {
        id: None,
        predicate: "note.topic".into(),
        subject_ref: subject.to_hex(),
        value: serde_json::json!(value),
        confidence: 1.0,
        source: "user_stated".into(),
        world_ref: world.map(|world| world.to_hex()),
        relationship_ref: None,
        scope: None,
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
    }
}

fn spoken(room: EntityId, turn: EntityId, at: u64) -> WitnessTurn {
    WitnessTurn {
        conversation_ref: room.to_hex(),
        turn_ref: Some(turn.to_hex()),
        messages: vec![WitnessMessage {
            id: Some(EntityId::now().to_hex()),
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: "lantern check".into(),
            metadata: None,
            is_visible: true,
            order: 0,
        }],
        occurred_at: at,
    }
}

fn project_room(
    vault: &Vault,
    leader: EntityId,
    members: &[EntityId],
) -> Result<(EntityId, ProjectRecord)> {
    let root = vault.root_project()?;
    let project = EntityId::now();
    let mut record = ProjectRecord::new(project, Some(root), root, leader)?;
    record.roster.extend(members.iter().map(EntityId::to_hex));
    vault.put_project(project, &record, 1)?;
    Ok((project, record))
}

/// The owner reads the whole vault, so anything a room turn hides here is
/// hidden by the room's Scope, its audience, or a peer's own read.
#[test]
fn every_read_a_room_turn_makes_runs_inside_the_rosters_scope() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let agent = id(0x41);
    let stranger = id(0x44);
    for person in [agent, stranger] {
        vault.put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )?;
    }
    let fiction = id(0x42);
    // The agent's grant holds base only, so the room reads base reality. The
    // stranger, not yet a member, holds the fiction world alone.
    grant(&vault, id(0x43), agent, WorldAuthoritySet::new(true, [])?)?;
    grant(
        &vault,
        id(0x45),
        stranger,
        WorldAuthoritySet::new(false, [fiction])?,
    )?;
    crate::test_util::authorize_readers(&vault, &[&agent.to_hex(), &stranger.to_hex()]);
    let (project, mut record) = project_room(&vault, owner, &[agent])?;
    let room = EntityId::from_hex(&record.home_room)?;
    let elsewhere = EntityId::from_hex(&project_room(&vault, owner, &[])?.1.home_room)?;
    // The agent is the vault's own: it adds no clearance term. Binding
    // roots the vault, so it follows the projects' implicit births.
    crate::test_util::bind_test_agent(&vault, agent);
    let host = vault.memory(owner, EdgeActorClass::Human);
    let hex_of = |input: ClaimInput| {
        let receipt = host.claim_upsert(&input).expect("note");
        host.get_entity(&receipt.claim_short_id)
            .expect("note read")
            .value
            .expect("owner reads the note")
            .id_hex
    };
    let base_ref = hex_of(note(room, "lantern harbor", None));
    let fiction_ref = hex_of(note(room, "lantern dragon", Some(fiction)));
    // Only the owner may read this one, so it is not the room's to read.
    let mut private = note(room, "lantern ledger", None);
    private.scope = Some(serde_json::json!({"typed_question_principal": owner.to_hex()}));
    let private_ref = hex_of(private);
    host.rooms_speak(&spoken(room, EntityId::now(), 2))
        .expect("speak");

    let filter = ClaimListFilter {
        subject_ref: Some(room.to_hex()),
        predicate: Some("note.topic".into()),
        lifecycle: None,
        limit: 10,
    };
    let refs = |listed: crate::memory::MemoryResult<
        crate::claim::ScopedReadResult<Vec<crate::memory::ClaimView>>,
    >| {
        let mut refs: Vec<_> = listed
            .expect("claim list")
            .value
            .into_iter()
            .map(|claim| claim.claim_ref)
            .collect();
        refs.sort();
        refs
    };
    let mut all = vec![base_ref.clone(), fiction_ref.clone(), private_ref.clone()];
    all.sort();
    assert_eq!(refs(host.claim_list(&filter)), all, "outside a room");

    let roster = host.room_roster(room).expect("roster");
    let mut members = vec![owner, agent];
    members.sort();
    assert_eq!(
        roster.iter().map(|member| member.actor).collect::<Vec<_>>(),
        members
    );
    let expected = room_scope(&roster)?;
    assert_eq!(
        expected.worlds,
        ScopeAxis::Some(BTreeSet::from([ScopeId(crate::claim::base_world_id())]))
    );
    let turn = host.for_room_turn(room).expect("open room turn");
    assert_eq!(
        refs(turn.claim_list(&filter)),
        vec![base_ref],
        "a world outside the room and a row private to the caller stay out"
    );
    for hidden in [&fiction_ref, &private_ref] {
        assert!(
            turn.get_entity(hidden)
                .expect("entity read")
                .value
                .is_none()
        );
    }
    let named = turn
        .recall(
            "lantern",
            crate::memory::Effort::Light,
            &crate::memory::RecallScope {
                world_ref: Some(fiction.to_hex()),
                facet: None,
                kinds: None,
            },
            10,
            None,
            None,
        )
        .expect("recall in the turn");
    assert!(
        named
            .items
            .iter()
            .all(|item| item.world.as_deref() != Some(fiction.to_hex().as_str())),
        "naming a world cannot reach past the room"
    );
    let page = turn
        .invoke(
            "rooms.messages",
            serde_json::json!({"room_ref": room.to_hex()}),
        )
        .expect("room history");
    assert_eq!(page["rows"].as_array().unwrap().len(), 1);
    let applied: Scope = serde_json::from_value(page["scope"].clone()).unwrap();
    assert_eq!(applied, expected, "the history read ran inside room_scope");
    let other = serde_json::json!({"room_ref": elsewhere.to_hex()});
    assert!(
        turn.invoke("rooms.messages", other).is_err(),
        "a turn in one room reads no other room"
    );
    for verb in ["export", "key_value_get", "receipts", "describe"] {
        assert!(
            turn.invoke(verb, serde_json::json!({})).is_err(),
            "{verb} reads around the room, so a turn refuses it"
        );
    }

    // The stranger joins. The meet leaves the room no world, so the room now
    // reads nothing, and the turn already open narrows with it.
    record.roster.push(stranger.to_hex());
    vault.put_project(project, &record, 2)?;
    let page = host
        .rooms_messages_page(room, None, 256)
        .expect("history outside a turn");
    assert!(page.rows.is_empty());
    assert_eq!(page.scope.worlds, ScopeAxis::Bottom);
    assert!(turn.rooms_messages().expect("narrowed turn").is_empty());
    assert!(refs(turn.claim_list(&filter)).is_empty(), "the open turn");
    assert!(turn.rooms_speak(&spoken(room, EntityId::now(), 3)).is_err());
    Ok(())
}

/// Astra on #1401 (P1): a TASK and its authority facts sit in the world they
/// were born in (ARCH-0067 §5), and every world check reads them there. A
/// room whose Scope holds base reality but not that world serves neither,
/// by id or hydrated, beside a base TASK it does serve; a retrieval filtered
/// to base reality finds only the base TASK, and one filtered to the world
/// only the TASK born there.
#[test]
fn a_room_reads_no_task_born_outside_its_worlds() -> Result<()> {
    // The shipped default policy, under which a writer's create mints its
    // TASK rather than parking a proposal. The room's grant would pend under
    // it, so the fixture clears it once the TASKs are minted.
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::default())?;
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let fiction = id(0x72);
    let writer = id(0x74);
    vault.put_entity(
        &writer,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"writer",
    )?;
    let mint = |world: Option<EntityId>| -> Result<Vec<EntityId>> {
        let task = vault
            .memory(writer, EdgeActorClass::Human)
            .with_birth_position(crate::federation::record_scope::BirthPosition {
                world,
                facet: None,
            })
            .tasks_create(&crate::task_verb::TaskCreateSpec::new(
                rmpv::Value::from("lantern work"),
                None,
                None,
                Some(2),
            ))
            .expect("the writer creates a TASK")
            .task_ref
            .expect("the create mints a TASK");
        // The TASK with the authority facts it was minted with.
        let mut rows = vec![task];
        rows.extend(
            vault
                .edges_in(&task)?
                .into_iter()
                .filter(|edge| edge.kind == crate::edge::EdgeKind::ScopedTo)
                .map(|edge| edge.target),
        );
        assert!(rows.len() > 1, "a minted TASK carries its Owner fact");
        Ok(rows)
    };
    let base = mint(None)?;
    let born = mint(Some(fiction))?;
    crate::test_util::clear_default_policy_manifest_for_legacy_tests(&vault);
    vault
        .batch()
        .text(&base[0], &[("body", "lantern harbor")])
        .text(&born[0], &[("body", "lantern dragon")])
        .commit()?;
    // The agent's grant holds base only, so the room reads base reality.
    let agent = id(0x71);
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"agent",
    )?;
    grant(&vault, id(0x73), agent, WorldAuthoritySet::new(true, [])?)?;
    crate::test_util::authorize_readers(&vault, &[&agent.to_hex()]);
    let (_, record) = project_room(&vault, owner, &[agent])?;
    let room = EntityId::from_hex(&record.home_room)?;
    crate::test_util::bind_test_agent(&vault, agent);

    let turn = vault
        .memory(owner, EdgeActorClass::Human)
        .for_room_turn(room)
        .expect("open room turn");
    for (rows, served) in [(&base, true), (&born, false)] {
        for row in rows {
            assert_eq!(
                turn.get_entity(&row.to_hex())
                    .expect("entity read")
                    .value
                    .is_some(),
                served,
                "{}",
                row.to_hex()
            );
        }
    }
    let mut expected: Vec<String> = base.iter().map(EntityId::to_hex).collect();
    let mut hydrated: Vec<String> = turn
        .hydrate(&expected)
        .expect("hydrate the base TASK")
        .value
        .into_iter()
        .map(|view| view.id_hex)
        .collect();
    hydrated.sort();
    expected.sort();
    assert_eq!(hydrated, expected, "hydration serves the base TASK");
    // Hydration refuses a ref it cannot serve as NOT_FOUND, as for an id
    // nothing holds.
    for row in &born {
        let refused = turn
            .hydrate(&[row.to_hex()])
            .expect_err("hydration withholds the TASK born outside the room");
        assert_eq!(refused.code, crate::memory::MEMORY_CODE_NOT_FOUND);
    }

    let found = |scope: crate::pipeline::WorldScope| -> Result<Vec<EntityId>> {
        Ok(vault
            .query()
            .search_text("lantern", 10)
            .filter_types(&[crate::registry::ENTITY_TYPE_TASK])
            .world(scope)
            .run()?
            .into_iter()
            .map(|entry| entry.id)
            .collect())
    };
    assert_eq!(found(crate::pipeline::WorldScope::Base)?, vec![base[0]]);
    assert_eq!(
        found(crate::pipeline::WorldScope::World(fiction))?,
        vec![born[0]]
    );
    Ok(())
}

/// Greptile on #1312: a member who joins after a turn's read lane copied
/// the roster still binds the rows that lane serves. Each row's own snapshot
/// reads the room again, so the join narrows the read it lands under.
#[test]
fn a_member_who_joins_mid_read_binds_the_rows_it_serves() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let agent = id(0x61);
    let stranger = id(0x64);
    for person in [agent, stranger] {
        vault.put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )?;
    }
    // The room reads base reality. The stranger holds the fiction world
    // alone, so once it joins the room reads no world at all.
    let fiction = id(0x62);
    grant(&vault, id(0x63), agent, WorldAuthoritySet::new(true, [])?)?;
    grant(
        &vault,
        id(0x65),
        stranger,
        WorldAuthoritySet::new(false, [fiction])?,
    )?;
    crate::test_util::authorize_readers(&vault, &[&agent.to_hex(), &stranger.to_hex()]);
    let (project, mut record) = project_room(&vault, owner, &[agent])?;
    // The agent's contact clears everything: only worlds and reads decide.
    crate::test_util::clear_test_contact(&vault, agent);
    let room = EntityId::from_hex(&record.home_room)?;
    let host = vault.memory(owner, EdgeActorClass::Human);
    let receipt = host
        .claim_upsert(&note(room, "lantern harbor", None))
        .expect("note");
    let harbor = EntityId::from_hex(
        &host
            .get_entity(&receipt.claim_short_id)
            .expect("note read")
            .value
            .expect("owner reads the note")
            .id_hex,
    )?;
    let turn = host.for_room_turn(room).expect("open room turn");
    let lane = turn
        .memory()
        .read_lane(crate::claim::ClaimReadStatus::Recorded)
        .expect("room lane");
    let served = || -> Result<bool> {
        Ok(lane
            .read(&[crate::claim::PointRead::id(harbor)], None)?
            .value
            .into_iter()
            .flatten()
            .next()
            .is_some())
    };
    assert!(served()?, "before the join the room reads base");
    record.roster.push(stranger.to_hex());
    vault.put_project(project, &record, 2)?;
    assert!(!served()?, "the row's snapshot holds the stranger");
    Ok(())
}

/// A member who leaves after a lane opened still binds the rows that lane
/// serves: reading the room again narrows a lane and never drops a read it
/// held. A lane opened after the leave reads the room as it is.
#[test]
fn a_member_who_leaves_mid_read_still_binds_the_rows_it_serves() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let agent = id(0x66);
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"agent",
    )?;
    let (project, mut record) = project_room(&vault, owner, &[agent])?;
    // The agent's contact clears everything, but it holds no read grant,
    // so its own read withholds the note.
    crate::test_util::clear_test_contact(&vault, agent);
    let room = EntityId::from_hex(&record.home_room)?;
    let host = vault.memory(owner, EdgeActorClass::Human);
    let receipt = host
        .claim_upsert(&note(room, "lantern harbor", None))
        .expect("note");
    let harbor = EntityId::from_hex(
        &host
            .get_entity(&receipt.claim_short_id)
            .expect("note read")
            .value
            .expect("owner reads the note")
            .id_hex,
    )?;
    let turn = host.for_room_turn(room).expect("open room turn");
    let served = |lane: &crate::claim::ScopedRead<'_>| -> Result<bool> {
        Ok(lane
            .read(&[crate::claim::PointRead::id(harbor)], None)?
            .value
            .into_iter()
            .flatten()
            .next()
            .is_some())
    };
    let lane = turn
        .memory()
        .read_lane(crate::claim::ClaimReadStatus::Recorded)
        .expect("room lane");
    assert!(!served(&lane)?, "the agent's read withholds the note");
    record.roster.retain(|member| *member != agent.to_hex());
    vault.put_project(project, &record, 2)?;
    assert!(
        !served(&lane)?,
        "the open lane still holds the agent's read"
    );
    let fresh = turn
        .memory()
        .read_lane(crate::claim::ClaimReadStatus::Recorded)
        .expect("room lane");
    assert!(served(&fresh)?, "a lane opened after the leave");
    Ok(())
}

/// Every row a room lane serves reads the roster in its own snapshot, but
/// the room's ceiling is rebuilt only for a member the lane does not bind
/// yet, never once per row.
#[test]
fn a_room_lane_rebuilds_its_ceiling_only_for_a_new_member() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let agent = id(0x67);
    let joiner = id(0x68);
    for person in [agent, joiner] {
        vault.put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )?;
    }
    let (project, mut record) = project_room(&vault, owner, &[agent])?;
    // Both contacts clear everything, so only the ceiling's rebuild is
    // under test.
    crate::test_util::clear_test_contact(&vault, agent);
    crate::test_util::clear_test_contact(&vault, joiner);
    let room = EntityId::from_hex(&record.home_room)?;
    let host = vault.memory(owner, EdgeActorClass::Human);
    let mut notes = Vec::new();
    for topic in ["lantern", "harbor", "beacon", "tide"] {
        let receipt = host.claim_upsert(&note(room, topic, None)).expect("note");
        let id = host
            .get_entity(&receipt.claim_short_id)
            .expect("note read")
            .value
            .expect("owner reads the note")
            .id_hex;
        notes.push(crate::claim::PointRead::id(EntityId::from_hex(&id)?));
    }
    crate::test_util::authorize_readers(&vault, &[&agent.to_hex(), &joiner.to_hex()]);
    let turn = host.for_room_turn(room).expect("open room turn");
    let lane = turn
        .memory()
        .read_lane(crate::claim::ClaimReadStatus::Recorded)
        .expect("room lane");
    let served =
        || -> Result<usize> { Ok(lane.read(&notes, None)?.value.into_iter().flatten().count()) };
    assert_eq!(served()?, notes.len());
    assert_eq!(lane.room_ceilings_built(), 0, "the roster did not change");
    record.roster.push(joiner.to_hex());
    vault.put_project(project, &record, 2)?;
    assert_eq!(served()?, notes.len());
    assert_eq!(
        lane.room_ceilings_built(),
        1,
        "one rebuild binds the joiner"
    );
    Ok(())
}

/// The roster is the channel's own membership: an ordinary channel's ledger,
/// never an unchecked field a body carries beside it.
#[test]
fn the_roster_is_the_channels_own_membership() -> Result<()> {
    use crate::conversation::{ConversationBody, ConversationKind};
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let agent = id(0x51);
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"agent",
    )?;
    let actor = crate::WriteActor::new(owner, EdgeActorClass::Human);
    let channel = |extra: Option<serde_json::Value>| -> Result<EntityId> {
        let id = EntityId::now();
        let mut body = ConversationBody {
            kind: ConversationKind::Channel,
            member_ids: vec![owner, agent],
            ..ConversationBody::default()
        };
        if let Some(extra) = extra {
            body.extra.insert(
                "memberIds".into(),
                crate::companion::companion_value_from_json(&extra)?,
            );
        }
        vault.create_conversation(id, &body, actor, 2)?;
        Ok(id)
    };
    let host = vault.memory(owner, EdgeActorClass::Human);
    let mut members = vec![owner, agent];
    members.sort();
    let ordinary = channel(None)?;
    let roster = host.room_roster(ordinary).expect("ordinary channel roster");
    assert_eq!(
        roster.iter().map(|member| member.actor).collect::<Vec<_>>(),
        members
    );
    // A body naming a narrower roster in an unchecked field never narrows
    // the meet: the room either reads its real members or refuses.
    if let Ok(forged) = channel(Some(serde_json::json!([owner.to_hex()]))) {
        assert!(host.room_roster(forged).map_or(true, |roster| {
            roster.iter().any(|member| member.actor == agent)
        }));
    }
    Ok(())
}

/// Greptile on #1312: past one pass of grant rows, a member whose grant row
/// lost its `claim_of` edge is still under world-access law, so the room
/// reads no base reality the grant withholds.
#[test]
fn a_grant_that_lost_its_edge_still_governs_past_one_pass() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let agent = id(0x71);
    let fiction = id(0x72);
    let others = [id(0x73), id(0x74), id(0x75)];
    for person in std::iter::once(agent).chain(others) {
        vault.put_entity(
            &person,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )?;
    }
    let row = id(0x76);
    grant(
        &vault,
        row,
        agent,
        WorldAuthoritySet::new(false, [fiction])?,
    )?;
    for (other, other_row) in others.into_iter().zip([id(0x77), id(0x78), id(0x79)]) {
        grant(&vault, other_row, other, WorldAuthoritySet::new(true, [])?)?;
    }
    assert!(vault.delete_edge(&row, crate::edge::EdgeKind::ClaimOf, &agent)?);
    let (_, record) = project_room(&vault, owner, &[agent])?;
    let room = EntityId::from_hex(&record.home_room)?;
    let host = vault.memory(owner, EdgeActorClass::Human);

    let roster = host.room_roster(room).expect("roster");
    let seat = |actor: EntityId| {
        roster
            .iter()
            .find(|member| member.actor == actor)
            .expect("member seat")
            .active_worlds
            .include_base()
    };
    assert!(seat(owner), "an actor no grant names reads base");
    assert!(!seat(agent), "the agent's grant withholds base");
    let page = host
        .rooms_messages_page(room, None, 256)
        .expect("room history");
    assert_eq!(
        page.scope.worlds,
        ScopeAxis::Bottom,
        "the room reads nothing"
    );
    Ok(())
}

/// ILDF2 in a room (ARCH-0067 §8): a guest's contact clearance bounds every
/// read a room turn makes. Its bottom clearance keeps a tier-B note and the
/// room's own default-Sensitive history out and a positively public note
/// in. A wider clearance admits them on the next turn, never mid-turn. The
/// owner adds no term, and the room roster and the context-pack interlocutor
/// set resolve one clearance through one function.
#[test]
fn a_guests_clearance_bounds_every_read_a_room_turn_makes() -> Result<()> {
    use crate::disclosure::{DisclosableSet, DisclosureScope, disclosable_set};
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let guest = id(0x71);
    vault.put_entity(
        &guest,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"guest",
    )?;
    let contact = id(0x72);
    let introduced = crate::counterparty_contact::CounterpartyContactRecord::user_introduction(
        id(0x73),
        "guest@example.com",
        10,
    )
    .expect("contact record");
    vault.create_counterparty_contact(&contact, &introduced)?;
    vault.put_edge(&contact, crate::edge::EdgeKind::About, &guest, 1.0)?;
    crate::test_util::authorize_readers(&vault, &[&guest.to_hex()]);
    let (_, record) = project_room(&vault, owner, &[guest])?;
    let room = EntityId::from_hex(&record.home_room)?;
    let host = vault.memory(owner, EdgeActorClass::Human);
    let hex_of = |input: ClaimInput| {
        let receipt = host.claim_upsert(&input).expect("note");
        host.get_entity(&receipt.claim_short_id)
            .expect("note read")
            .value
            .expect("owner reads the note")
            .id_hex
    };
    let tier_b = hex_of(note(room, "lantern ledger", None));
    let mut public = note(room, "lantern harbor", None);
    public.scope = Some(serde_json::json!({"sensitivity": "public"}));
    let public = hex_of(public);
    host.rooms_speak(&spoken(room, EntityId::now(), 2))
        .expect("speak");
    let filter = ClaimListFilter {
        subject_ref: Some(room.to_hex()),
        predicate: Some("note.topic".into()),
        lifecycle: None,
        limit: 10,
    };
    // What one room turn reads: the room's notes, each note by id, and the
    // room's own history.
    let reads = |turn: &crate::memory::RoomTurnHandle<'_>| {
        let mut listed: Vec<_> = turn
            .claim_list(&filter)
            .expect("claim list")
            .value
            .into_iter()
            .map(|claim| claim.claim_ref)
            .collect();
        listed.sort();
        let got = |note: &str| turn.get_entity(note).expect("read").value.is_some();
        let history = turn.rooms_messages().expect("history").len();
        (listed, got(&tier_b), got(&public), history)
    };

    let roster = host.room_roster(room).expect("roster");
    assert_eq!(disclosable_set(&roster)?, room_scope(&roster)?);
    let terms: Vec<_> = roster
        .iter()
        .map(|member| member.clearance.clone())
        .collect();
    assert_eq!(
        terms.iter().filter(|term| term.is_none()).count(),
        1,
        "the owner adds none"
    );
    let interlocutors = crate::interlocutor::InterlocutorSet::with_session_owner(vec![
        crate::interlocutor::Interlocutor::known_contact(
            contact,
            "guest@example.com",
            crate::counterparty_contact::CounterpartyFirstTouch::UserIntroduction,
        ),
    ]);
    assert_eq!(
        &disclosable_set(&terms)?,
        DisclosableSet::resolve(&vault, &interlocutors, false)?.clearance()
    );

    let narrow = host.for_room_turn(room).expect("open room turn");
    assert_eq!(reads(&narrow), (vec![public.clone()], false, true, 0));
    vault.set_counterparty_disclosure_scope(
        &contact,
        &DisclosureScope::new(Scope::top(), "room guest", 200)?,
    )?;
    assert_eq!(
        reads(&narrow),
        (vec![public.clone()], false, true, 0),
        "a turn never widens mid-turn"
    );
    let mut both = vec![tier_b.clone(), public.clone()];
    both.sort();
    let wide = host.for_room_turn(room).expect("open room turn");
    assert_eq!(reads(&wide), (both.clone(), true, true, 1));

    // A turn only narrows. A clearance narrowed after the turn opened
    // withholds the note from the lane already reading it and from the
    // turn's next verb, and neither reads it again once the clearance
    // widens. Only a new turn does.
    let tier_b_id = EntityId::from_hex(&tier_b)?;
    let lane = wide
        .memory()
        .read_lane(crate::claim::ClaimReadStatus::Recorded)
        .expect("room lane");
    let lane_reads = || {
        lane.read(&[PointRead::id(tier_b_id)], None)
            .expect("lane read")
            .value[0]
            .is_some()
    };
    let set = |scope: Scope, at: u64| {
        vault.set_counterparty_disclosure_scope(
            &contact,
            &DisclosureScope::new(scope, "room guest", at).expect("clearance"),
        )
    };
    assert!(lane_reads());
    set(Scope::default(), 300)?;
    assert!(!lane_reads(), "the lane narrows in the snapshot it serves");
    assert!(
        wide.get_entity(&tier_b).expect("read").value.is_none(),
        "and so does the turn's next verb"
    );
    set(Scope::top(), 400)?;
    assert!(!lane_reads(), "neither widens back");
    assert_eq!(reads(&wide), (vec![public.clone()], false, true, 0));
    assert_eq!(
        reads(&host.for_room_turn(room).expect("open room turn")),
        (both, true, true, 1)
    );

    // A render judges each rule's P7 in the snapshot that reads the rule:
    // a clearance captured wide before a narrowing renders nothing it no
    // longer admits, and a member the render never checked keeps it out.
    let captured = crate::claim::RoomTerms {
        worlds: Scope::top(),
        facets: ScopeAxis::All,
        clearance: Some(Scope::top()),
        p7: true,
    };
    let mut members = vec![owner, guest];
    members.sort();
    let renders = |members: &[EntityId]| {
        host.room_discloses(room, &captured, members, tier_b_id)
            .expect("render p7")
    };
    assert!(renders(&members));
    assert!(!renders(&[owner]), "a member who joined since");
    set(Scope::default(), 500)?;
    assert!(!renders(&members), "a clearance narrowed since");
    set(Scope::top(), 600)?;
    // Through a turn, a narrowing one rule meets holds for the next rule.
    let turn = host.for_room_turn(room).expect("open room turn");
    let renders_in_turn = || {
        turn.memory()
            .room_discloses(room, &captured, &members, tier_b_id)
            .expect("render p7")
    };
    assert!(renders_in_turn());
    set(Scope::default(), 610)?;
    assert!(!renders_in_turn());
    set(Scope::top(), 620)?;
    assert!(
        !renders_in_turn(),
        "a render through a turn never widens back"
    );

    // A revoked contact keeps its clearance row, yet its member is unknown
    // again: bottom, as the context-pack resolver reads the same contact.
    vault.revoke_counterparty_contact(&contact, 700)?;
    assert_eq!(
        reads(&host.for_room_turn(room).expect("open room turn")),
        (vec![public.clone()], false, true, 0)
    );
    let terms: Vec<_> = host
        .room_roster(room)
        .expect("roster")
        .iter()
        .map(|member| member.clearance.clone())
        .collect();
    let revoked = vault.resolve_interlocutors(&crate::InterlocutorResolutionInput {
        owner_session: true,
        parties: vec![crate::InterlocutorPartyInput::ContactRef(contact)],
        voice_session_ref: None,
    })?;
    assert_eq!(disclosable_set(&terms)?, Scope::default());
    assert_eq!(
        &disclosable_set(&terms)?,
        DisclosableSet::resolve(&vault, &revoked, false)?.clearance()
    );
    Ok(())
}

/// ARCH-0067 §8, the Engine lane's rule 3: an agent bound to a contact
/// takes that contact's clearance, an AGENT_DEF as much as a PERSON. A
/// second contact About it makes the link ambiguous, so it is unknown.
#[test]
fn a_contact_bound_agent_definition_takes_its_contacts_clearance() -> Result<()> {
    use crate::counterparty_contact::CounterpartyContactRecord;
    use crate::disclosure::RoomParty;
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let agent = crate::test_util::seed_agent_definition(&vault, id(0x81), "room agent");
    assert_eq!(vault.room_parties(&[agent])?, vec![RoomParty::VaultAgent]);
    let contact = |seed: u8, counterparty: &str| -> Result<EntityId> {
        let contact = id(seed);
        let record = CounterpartyContactRecord::user_introduction(id(seed + 1), counterparty, 10)
            .expect("contact record");
        vault.create_counterparty_contact(&contact, &record)?;
        vault.put_edge(&contact, crate::edge::EdgeKind::About, &agent, 1.0)?;
        Ok(contact)
    };
    let first = contact(0x82, "agent@example.com")?;
    assert_eq!(
        vault.room_parties(&[agent])?,
        vec![RoomParty::Contact(first)]
    );
    contact(0x84, "other@example.com")?;
    assert_eq!(vault.room_parties(&[agent])?, vec![RoomParty::Unknown]);
    Ok(())
}

/// P7 follows a record's words to where they came from (ILDF2): a room
/// TURN is disclosed only with its messages, and a summary's TURN copy,
/// which has no messages of its own, only with the records and messages
/// the summary came from. A clearance that reads TURNs but not MESSAGEs
/// discloses neither; one that reads both discloses both.
#[test]
fn p7_follows_a_records_words_to_their_sources() -> Result<()> {
    use crate::ports::EntityStoreRead;
    use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let (_, record) = project_room(&vault, owner, &[])?;
    let room = EntityId::from_hex(&record.home_room)?;
    let turn = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .rooms_speak(&spoken(room, turn, 2))
        .expect("speak");
    // A summary's merge header is a generated claim the owner may land.
    crate::conversation_dag::test_support::put_dag_test_policy(
        &vault,
        crate::WriteActor::new(owner, EdgeActorClass::Human),
        true,
    )?;
    let scope = crate::conversation_dag::ScopeSelector {
        conversation: room,
        session: None,
        path: crate::conversation_dag::ScopePath::Canonical,
        include_forks: false,
    };
    let (summary, landed) = vault.mint_and_land_scope_summary(
        &scope,
        "lantern summary",
        crate::WriteActor::new(owner, EdgeActorClass::Human),
        Some(turn),
        true,
    )?;
    let copy = landed.and_then(|landed| landed.record).expect("TURN copy");
    let clearance = |bands: &[u8]| Scope {
        bands: ScopeAxis::Some(bands.iter().copied().collect()),
        ..Scope::top()
    };
    let discloses = |id: EntityId, scope: &Scope| -> Result<bool> {
        let txn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .port_entity_record(&txn, &id)?
            .expect("row")
            .encode();
        crate::disclosure::discloses_raw(&vault, &txn, scope, id, &raw)
    };
    let turns = clearance(&[ENTITY_TYPE_TURN]);
    let both = clearance(&[ENTITY_TYPE_TURN, ENTITY_TYPE_MESSAGE]);
    assert!(!discloses(turn, &turns)?);
    assert!(
        !discloses(copy, &turns)?,
        "the copy carries the messages' words"
    );
    assert!(discloses(turn, &both)?);
    assert!(discloses(copy, &both)?);
    let recover = |covers: Vec<EntityId>, at: u64| -> Result<()> {
        let mut body = crate::scope_summary::decode_scope_summary_body(
            &vault.get(&summary)?.expect("summary body"),
        )?;
        body.covers = covers;
        vault.put_entity(
            &summary,
            crate::registry::ENTITY_TYPE_SUMMARY,
            TimeRange { start: at, end: at },
            at,
            &crate::scope_summary::encode_scope_summary_body(&body)?,
        )
    };
    // A summary put again over other records leaves the copy's words with
    // the records they came from. The landing moved the room onto its DAG.
    let later = vault
        .append_dag_record(&crate::conversation_dag::AppendRecord {
            conversation: room,
            parent: Some(copy),
            reply_to: None,
            address: crate::conversation_dag::AddressMode::Broadcast,
            recipients: vec![],
            advance: true,
            kind: ENTITY_TYPE_TURN,
            occurred: TimeRange { start: 3, end: 3 },
            learned_at: 3,
            body: crate::conversation_dag::fixtures::body("later"),
            text: vec![],
            session: None,
            actor: crate::WriteActor::new(owner, EdgeActorClass::Human),
        })?
        .id;
    recover(vec![later], 4)?;
    let sources = {
        let txn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .port_entity_record(&txn, &copy)?
            .expect("row")
            .encode();
        crate::scope_summary::word_sources_in(&vault, &txn, &copy, &raw)?
    };
    assert!(
        matches!(
            sources,
            crate::scope_summary::WordSources::From(ref sources)
                if sources.contains(&turn) && sources.contains(&later)
        ),
        "the copy's words still came from the first turn"
    );
    // A summary put again to cover its own copy makes the copy's words a
    // cycle: P7 discloses nothing rather than walking it forever.
    recover(vec![copy], 5)?;
    assert!(!discloses(copy, &both)?, "a cycle discloses nothing");
    Ok(())
}

/// A summary of summaries carries every level's words. P7 walks the whole
/// closure on a heap stack, so the first turn's message still binds the
/// last copy, and records the levels share are judged once.
#[test]
fn p7_walks_a_summary_of_summaries_to_its_first_words() -> Result<()> {
    use crate::ports::EntityStoreRead;
    use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let (_, record) = project_room(&vault, owner, &[])?;
    let room = EntityId::from_hex(&record.home_room)?;
    let turn = EntityId::now();
    vault
        .memory(owner, EdgeActorClass::Human)
        .rooms_speak(&spoken(room, turn, 2))
        .expect("speak");
    // A summary's merge header is a generated claim the owner may land.
    crate::conversation_dag::test_support::put_dag_test_policy(
        &vault,
        crate::WriteActor::new(owner, EdgeActorClass::Human),
        true,
    )?;
    let scope = crate::conversation_dag::ScopeSelector {
        conversation: room,
        session: None,
        path: crate::conversation_dag::ScopePath::Canonical,
        include_forks: false,
    };
    let mut head = turn;
    for level in 0..8 {
        let (_, landed) = vault.mint_and_land_scope_summary(
            &scope,
            &format!("lantern summary {level}"),
            crate::WriteActor::new(owner, EdgeActorClass::Human),
            Some(head),
            true,
        )?;
        head = landed.and_then(|landed| landed.record).expect("TURN copy");
    }
    let clearance = |bands: &[u8]| Scope {
        bands: ScopeAxis::Some(bands.iter().copied().collect()),
        ..Scope::top()
    };
    let txn = vault.store.env.read_txn()?;
    let raw = vault
        .store
        .port_entity_record(&txn, &head)?
        .expect("row")
        .encode();
    assert!(crate::disclosure::discloses_raw(
        &vault,
        &txn,
        &clearance(&[ENTITY_TYPE_TURN, ENTITY_TYPE_MESSAGE]),
        head,
        &raw
    )?);
    assert!(
        !crate::disclosure::discloses_raw(
            &vault,
            &txn,
            &clearance(&[ENTITY_TYPE_TURN]),
            head,
            &raw
        )?,
        "the last copy carries the first turn's message"
    );
    Ok(())
}

/// A `conversation.summary` claim carries the words of the turns it covers
/// (Astra #1394 P1). A guest cleared for claims but not turns keeps such a
/// summary out of every read the owner's bound turn makes, while a note of
/// the same kind stays readable. Cleared for the turn's words too, the
/// summary discloses.
#[test]
fn p7_follows_a_conversation_summary_to_the_turns_it_covers() -> Result<()> {
    use crate::disclosure::DisclosureScope;
    use crate::ports::EntityStoreRead;
    use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let guest = id(0x75);
    vault.put_entity(
        &guest,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"guest",
    )?;
    let contact = id(0x76);
    let introduced = crate::counterparty_contact::CounterpartyContactRecord::user_introduction(
        id(0x77),
        "guest@example.com",
        10,
    )
    .expect("contact record");
    vault.create_counterparty_contact(&contact, &introduced)?;
    vault.put_edge(&contact, crate::edge::EdgeKind::About, &guest, 1.0)?;
    let (_, record) = project_room(&vault, owner, &[guest])?;
    let room = EntityId::from_hex(&record.home_room)?;
    let host = vault.memory(owner, EdgeActorClass::Human);
    let turn = EntityId::now();
    host.rooms_speak(&spoken(room, turn, 2)).expect("speak");
    let summary = EntityId::now();
    let mut body = crate::ClaimBody::new(
        "conversation.summary",
        crate::ClaimSubject::Entity(room),
        rmpv::Value::Map(vec![
            ("text".into(), "lantern summary words".into()),
            (
                "covers".into(),
                rmpv::Value::Array(vec![rmpv::Value::Binary(turn.as_bytes().to_vec())]),
            ),
        ]),
        1.0,
        ClaimApprovalStatus::Approved,
        crate::ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::Observed);
    // A reader's grant makes later direct claim writes pend, so the
    // summary lands first.
    vault.put_claim(&summary, &body, TimeRange { start: 3, end: 3 }, 3)?;
    crate::test_util::authorize_readers(&vault, &[&guest.to_hex()]);
    let note = host
        .claim_upsert(&note(room, "lantern ledger", None))
        .expect("note");
    let note = host
        .get_entity(&note.claim_short_id)
        .expect("note read")
        .value
        .expect("owner reads the note")
        .id_hex;

    let clearance = |bands: &[u8]| Scope {
        bands: ScopeAxis::Some(bands.iter().copied().collect()),
        ..Scope::top()
    };
    let discloses = |id: EntityId, scope: &Scope| -> Result<bool> {
        let txn = vault.store.env.read_txn()?;
        let raw = vault
            .store
            .port_entity_record(&txn, &id)?
            .expect("row")
            .encode();
        crate::disclosure::discloses_raw(&vault, &txn, scope, id, &raw)
    };
    let claims = clearance(&[ENTITY_TYPE_CLAIM]);
    assert!(!discloses(turn, &claims)?);
    assert!(
        !discloses(summary, &claims)?,
        "the summary carries the turn's words"
    );
    assert!(discloses(
        summary,
        &clearance(&[ENTITY_TYPE_CLAIM, ENTITY_TYPE_TURN, ENTITY_TYPE_MESSAGE])
    )?);

    vault.set_counterparty_disclosure_scope(
        &contact,
        &DisclosureScope::new(claims, "room guest", 200)?,
    )?;
    let listed = |turn: &crate::memory::RoomTurnHandle<'_>, predicate: &str| -> Vec<String> {
        let filter = ClaimListFilter {
            subject_ref: Some(room.to_hex()),
            predicate: Some(predicate.into()),
            lifecycle: None,
            limit: 10,
        };
        turn.claim_list(&filter)
            .expect("claim list")
            .value
            .into_iter()
            .map(|claim| claim.claim_ref)
            .collect()
    };
    let summary_hex = summary.to_hex();
    assert_eq!(
        host.get_entity(&summary_hex)
            .expect("owner read")
            .value
            .map(|view| view.id_hex),
        Some(summary_hex.clone()),
        "the owner alone reads the summary"
    );
    let bound = host.for_room_turn(room).expect("open room turn");
    assert_eq!(listed(&bound, "note.topic"), std::slice::from_ref(&note));
    assert_eq!(
        bound
            .hydrate(&[note])
            .expect("hydrate the note")
            .value
            .len(),
        1
    );
    assert!(listed(&bound, "conversation.summary").is_empty());
    assert!(
        bound
            .get_entity(&summary_hex)
            .expect("read")
            .value
            .is_none()
    );
    // A withheld hydrate is NOT_FOUND, and the refusal carries the receipt.
    let refused = bound.hydrate(&[summary_hex]).expect_err("withheld hydrate");
    assert_eq!(refused.code, crate::MEMORY_CODE_NOT_FOUND);
    assert!(refused.read_receipt.is_some());
    Ok(())
}
