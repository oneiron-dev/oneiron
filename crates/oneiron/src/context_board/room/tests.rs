//! ARCH-0067 §8 acceptance: one roster-to-Scope function, and every read a
//! room turn makes runs inside the Scope it returns.
use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
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
    assert_eq!(room_scope(&[])?, Scope::default());
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
    // The agent holds no read grant, so its own read withholds the note.
    let (project, mut record) = project_room(&vault, owner, &[agent])?;
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
