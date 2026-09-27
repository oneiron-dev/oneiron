//! Channel fixture for ROOM scope, fresh projection, and rooms.* verbs.
use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::edge::EdgeActorClass;
use crate::memory::{ClaimInput, WitnessAuthor, WitnessMessage, WitnessTurn};
use crate::pipeline::{PREDICATE_WORLD_ACCESS_ALLOWED_SET, world_access_claim_body};
use crate::task_verb::sdk as sdk_generated;
use crate::workspace_roster::ProjectRecord;
use crate::{TimeRange, VaultConfig};

fn id(byte: u8) -> EntityId {
    EntityId::from_bytes([byte; 16]).unwrap()
}
fn presence(
    actor: EntityId,
    class: EdgeActorClass,
    label: &str,
    worlds: WorldAuthoritySet,
) -> RoomPresence {
    RoomPresence {
        actor,
        actor_class: Some(class),
        label: label.into(),
        present: true,
        active_worlds: worlds,
    }
}

#[test]
fn room_scope_is_ordinary_scope_and_never_widens_on_join() -> Result<()> {
    let a = presence(
        id(1),
        EdgeActorClass::Human,
        "a",
        WorldAuthoritySet::new(true, [id(3), id(4)])?,
    );
    let b = presence(
        id(2),
        EdgeActorClass::Agent,
        "b",
        WorldAuthoritySet::new(false, [id(4), id(5)])?,
    );
    let one: Scope = room_scope(std::slice::from_ref(&a))?;
    let two: Scope = room_scope(&[a.clone(), b.clone()])?;
    assert!(two.is_narrowing_of(&one));
    assert_eq!(
        two.worlds,
        ScopeAxis::Some(BTreeSet::from([ScopeId(id(4))]))
    );
    assert!(!two.worlds.contains(&ScopeId(crate::claim::base_world_id())));
    assert_eq!(two.facets, one.facets);
    assert_eq!(two.audience, one.audience);
    assert_eq!(
        room_scope(&[
            a,
            RoomPresence {
                present: false,
                ..b
            }
        ])?,
        one
    );
    assert_eq!(room_scope(&[])?, Scope::default());
    let reserved = presence(
        id(8),
        EdgeActorClass::Human,
        "reserved",
        WorldAuthoritySet::new(false, [crate::claim::base_world_id()])?,
    );
    assert_eq!(room_scope(&[reserved])?.worlds, ScopeAxis::Bottom);
    Ok(())
}
fn claim(room: EntityId, predicate: &str, value: &str) -> ClaimInput {
    ClaimInput {
        id: None,
        predicate: predicate.into(),
        subject_ref: room.to_hex(),
        value: serde_json::json!(value),
        confidence: 1.0,
        source: "user_stated".into(),
        world_ref: None,
        relationship_ref: None,
        scope: None,
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
    }
}

#[test]
fn channel_render_and_rooms_verbs_round_trip() -> Result<()> {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::default());
    let owner = id(0x31);
    let agent = id(0x32);
    let away = id(0x33);
    for actor in [owner, agent, away] {
        vault.put_entity(
            &actor,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"participant",
        )?;
    }
    let project = id(0x34);
    let root = vault.root_project()?;
    let mut record = ProjectRecord::new(project, Some(root), root, owner);
    record.roster.extend([agent.to_hex(), away.to_hex()]);
    vault.put_project(project, &record, 1)?;
    let room = EntityId::from_hex(&record.home_room)?;
    let base = WorldAuthoritySet::new(true, [])?;
    let world = id(0x37);
    let allowed = WorldAuthoritySet::new(true, [world])?;
    for (n, actor) in [(0x35, owner), (0x36, agent)] {
        let grant = world_access_claim_body(
            PREDICATE_WORLD_ACCESS_ALLOWED_SET,
            actor,
            &allowed,
            ClaimSource::UserStated,
            ClaimApprovalStatus::Approved,
            None,
            None,
        )?;
        vault.put_claim(&id(n), &grant, TimeRange { start: 1, end: 1 }, 1)?;
    }
    let host = vault.memory(owner, EdgeActorClass::Human);
    let member = vault.memory(agent, EdgeActorClass::Human);
    let mode_receipt = host
        .claim_upsert(&claim(room, "room.posture.mode", "asked_only"))
        .expect("mode");
    assert_eq!(mode_receipt.approval, "auto", "mode must be active");
    let bar_receipt = host
        .claim_upsert(&claim(room, "room.posture.bar", "high"))
        .expect("bar");
    assert_eq!(bar_receipt.approval, "auto", "bar must be active");
    host.claim_upsert(&claim(
        room,
        "room.rule",
        "offer the next turn to the addressed member",
    ))
    .expect("rule");
    // Grant the two present readers through the normal policy read door.
    crate::test_util::authorize_readers(&vault, &[&owner.to_hex(), &agent.to_hex()]);
    let roster = vec![
        presence(owner, EdgeActorClass::Human, "owner", base.clone()),
        presence(agent, EdgeActorClass::Human, "agent", base),
    ];
    let host_turn = host.for_room_turn(room, &roster).expect("bind host turn");
    let member_turn = member
        .for_room_turn(room, &roster)
        .expect("bind member turn");
    let render = host_turn.rooms_render(room, &roster).expect("ROOM read");
    assert!(
        render
            .scope
            .worlds
            .contains(&ScopeId(crate::claim::base_world_id()))
    );
    assert_eq!(render.roster.len(), 3);
    assert_eq!(
        render.posture,
        RoomPosture {
            mode: RoomMode::AskedOnly,
            bar: RoomBar::High
        }
    );
    assert!(render.claims.iter().any(|row| row.predicate == "room.rule"));
    let rows = render
        .board_section()
        .expect("section")
        .pinned_rows()
        .join("\n");
    assert!(rows.contains("owner"));
    assert!(rows.contains("away"));
    assert!(rows.contains("scope: base=true worlds="));
    assert!(rows.contains("posture: asked-only"));
    assert!(rows.contains("room.rule"));

    let listed =
        sdk_generated::invoke(&host_turn, "rooms.list", serde_json::json!({})).expect("list");
    assert!(
        listed
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == room.to_hex())
    );
    let asked = id(0x39);
    let turn = WitnessTurn {
        conversation_ref: room.to_hex(),
        turn_ref: Some(asked.to_hex()),
        messages: vec![WitnessMessage {
            id: Some(id(0x3a).to_hex()),
            author: WitnessAuthor::User,
            message_type: "text".into(),
            content: "question".into(),
            metadata: Some(serde_json::json!({})),
            is_visible: true,
            order: 0,
        }],
        occurred_at: 2,
    };
    let spoken = sdk_generated::invoke(
        &host_turn,
        "rooms.speak",
        serde_json::to_value(&turn).unwrap(),
    )
    .expect("speak");
    assert!(!spoken.is_null());
    let request = serde_json::json!({"room_ref": room.to_hex()});
    assert!(sdk_generated::invoke(&member, "rooms.messages", request.clone()).is_err());
    let messages = sdk_generated::invoke(&member_turn, "rooms.messages", request.clone())
        .expect("bound room-turn read");
    assert_eq!(messages["rows"].as_array().unwrap().len(), 1);
    assert_eq!(messages["rows"][0]["turn_id"], asked.to_hex());
    let applied: Scope = serde_json::from_value(messages["applied_scope"].clone()).unwrap();
    assert_eq!(
        applied, render.scope,
        "actual history read uses the ROOM Scope"
    );
    let claim_request = serde_json::json!({"room_ref": room.to_hex(), "turn_ref": asked.to_hex()});
    let claimed =
        sdk_generated::invoke(&member_turn, "rooms.claim", claim_request.clone()).expect("claim");
    assert_eq!(claimed["Claimed"]["actor"], agent.to_hex());

    // A nonempty world intersection still excludes a base-world TURN.
    let world_roster = vec![
        presence(owner, EdgeActorClass::Human, "owner", allowed),
        presence(
            agent,
            EdgeActorClass::Human,
            "agent",
            WorldAuthoritySet::new(false, [world])?,
        ),
    ];
    let world_turn = member
        .for_room_turn(room, &world_roster)
        .expect("world turn");
    let world_render = world_turn
        .rooms_render(room, &world_roster)
        .expect("world ROOM");
    assert_eq!(
        world_render.scope.worlds,
        ScopeAxis::Some(BTreeSet::from([ScopeId(world)]))
    );
    let world_page = sdk_generated::invoke(&world_turn, "rooms.messages", request.clone())
        .expect("world-scoped history");
    assert!(world_page["rows"].as_array().unwrap().is_empty());
    let applied_world: Scope = serde_json::from_value(world_page["applied_scope"].clone()).unwrap();
    assert_eq!(applied_world, world_render.scope);
    assert!(
        sdk_generated::invoke(&world_turn, "rooms.list", serde_json::json!({}))
            .expect("world-scoped list")
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(sdk_generated::invoke(&world_turn, "rooms.claim", claim_request.clone()).is_err());

    // A present participant with no active world removes even a stored base
    // TURN from the room-turn read. Generic history outside a turn remains a
    // separate member-only door; it cannot be reached through the agent SDK.
    let narrowed = vec![
        roster[0].clone(),
        presence(
            agent,
            EdgeActorClass::Human,
            "agent",
            WorldAuthoritySet::default(),
        ),
    ];
    let narrow_turn = member
        .for_room_turn(room, &narrowed)
        .expect("bind narrowed turn");
    let narrow_render = narrow_turn
        .rooms_render(room, &narrowed)
        .expect("ROOM bottom");
    assert_eq!(narrow_render.scope.worlds, ScopeAxis::Bottom);
    assert_eq!(
        member.rooms_messages(room).expect("generic history").len(),
        1
    );
    let hidden = sdk_generated::invoke(&narrow_turn, "rooms.messages", request)
        .expect("scoped empty room history");
    assert!(hidden["rows"].as_array().unwrap().is_empty());
    let hidden_scope: Scope = serde_json::from_value(hidden["applied_scope"].clone()).unwrap();
    assert_eq!(hidden_scope, narrow_render.scope);
    assert!(
        sdk_generated::invoke(&narrow_turn, "rooms.list", serde_json::json!({}))
            .expect("bottom-scoped list")
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(narrow_turn.room_head(room).expect("scoped HEAD").is_none());
    assert!(sdk_generated::invoke(&narrow_turn, "rooms.claim", claim_request).is_err());
    assert!(
        sdk_generated::invoke(
            &narrow_turn,
            "rooms.speak",
            serde_json::to_value(&turn).unwrap()
        )
        .is_err()
    );
    Ok(())
}
