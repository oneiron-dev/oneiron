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

fn project_room(vault: &Vault, leader: EntityId, members: &[EntityId]) -> Result<EntityId> {
    let root = vault.root_project()?;
    let project = EntityId::now();
    let mut record = ProjectRecord::new(project, Some(root), root, leader)?;
    record.roster.extend(members.iter().map(EntityId::to_hex));
    vault.put_project(project, &record, 1)?;
    EntityId::from_hex(&record.home_room)
}

/// The owner reads the whole vault, so anything a room turn hides here is
/// hidden by the room's Scope alone.
#[test]
fn every_read_a_room_turn_makes_runs_inside_the_rosters_scope() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let agent = id(0x41);
    vault.put_entity(
        &agent,
        crate::registry::ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"agent",
    )?;
    let fiction = id(0x42);
    let room = project_room(&vault, owner, &[agent])?;
    let elsewhere = project_room(&vault, owner, &[])?;
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
    host.rooms_speak(&spoken(room, EntityId::now(), 2))
        .expect("speak");
    // The agent's grant holds base only, so the room reads base reality.
    grant(&vault, id(0x43), agent, WorldAuthoritySet::new(true, [])?)?;

    let notes = |memory: &crate::memory::Memory<'_>| -> Vec<String> {
        memory
            .claim_list(&ClaimListFilter {
                subject_ref: Some(room.to_hex()),
                predicate: Some("note.topic".into()),
                lifecycle: None,
                limit: 10,
            })
            .expect("claim list")
            .value
            .into_iter()
            .map(|claim| claim.claim_ref)
            .collect()
    };
    let mut outside = notes(&host);
    outside.sort();
    let mut both = vec![base_ref.clone(), fiction_ref.clone()];
    both.sort();
    assert_eq!(outside, both, "outside a room the owner lists both notes");

    let roster = host.room_roster(room).expect("roster");
    assert_eq!(
        roster.iter().map(|member| member.actor).collect::<Vec<_>>(),
        {
            let mut ids = vec![owner, agent];
            ids.sort();
            ids
        }
    );
    let expected = room_scope(&roster)?;
    assert_eq!(
        expected.worlds,
        ScopeAxis::Some(BTreeSet::from([ScopeId(crate::claim::base_world_id())]))
    );
    let turn = host.for_room_turn(room).expect("bind room turn");
    assert_eq!(notes(&turn), vec![base_ref], "ordinary claim read");
    assert!(
        turn.get_entity(&fiction_ref)
            .expect("entity read")
            .value
            .is_none(),
        "ordinary entity read"
    );
    let named = turn
        .recall(
            "lantern",
            crate::memory::Effort::Light,
            &crate::memory::RecallScope {
                world_ref: Some(fiction.to_hex()),
                facet: None,
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
    let page = crate::task_verb::sdk::invoke(
        &turn,
        "rooms.messages",
        serde_json::json!({"room_ref": room.to_hex()}),
    )
    .expect("room history");
    assert_eq!(page["rows"].as_array().unwrap().len(), 1);
    let applied: Scope = serde_json::from_value(page["scope"].clone()).unwrap();
    assert_eq!(applied, expected, "the history read ran inside room_scope");
    assert!(
        turn.rooms_messages(elsewhere).is_err(),
        "a turn in one room reads no other room"
    );

    // A second owner grant meets the first, leaving the agent no world. The
    // room now reads nothing, and an open turn narrows with it.
    grant(
        &vault,
        id(0x44),
        agent,
        WorldAuthoritySet::new(false, [fiction])?,
    )?;
    let page = host
        .rooms_messages_page(room, None, 256)
        .expect("history outside a turn");
    assert!(page.rows.is_empty());
    assert_eq!(page.scope.worlds, ScopeAxis::Bottom);
    assert!(turn.rooms_messages(room).expect("narrowed turn").is_empty());
    let narrow = host.for_room_turn(room).expect("bind narrowed turn");
    assert!(notes(&narrow).is_empty());
    assert!(
        narrow
            .rooms_speak(&spoken(room, EntityId::now(), 3))
            .is_err()
    );
    Ok(())
}
