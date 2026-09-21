//! ROOM derives live roster, authority, posture and rule claims with no board store.
use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::pipeline::{
    PREDICATE_WORLD_ACCESS_ALLOWED_SET, WorldAuthoritySet, world_access_claim_body,
};
use crate::{EdgeActorClass, EntityId, TimeRange, VaultConfig};

#[test]
fn room_scope_narrows_and_rooms_verbs_round_trip() {
    let (_dir, vault) = crate::test_util::open_test_vault_with(VaultConfig::device());
    let actor = EntityId::from_bytes([0x71; 16]).unwrap();
    let other = EntityId::from_bytes([0x72; 16]).unwrap();
    let room = EntityId::from_bytes([0x73; 16]).unwrap();
    let world_a = EntityId::from_bytes([0x74; 16]).unwrap();
    let world_b = EntityId::from_bytes([0x75; 16]).unwrap();
    let at = TimeRange { start: 1, end: 1 };
    for id in [actor, other] {
        vault
            .put_entity(&id, crate::registry::ENTITY_TYPE_PERSON, at, 1, b"person")
            .unwrap();
    }
    let body = rmp_serde::to_vec_named(
        &serde_json::json!({"kind":"channel", "memberIds":[actor.to_hex(), other.to_hex()]}),
    )
    .unwrap();
    vault
        .put_entity(
            &room,
            crate::registry::ENTITY_TYPE_CONVERSATION,
            at,
            1,
            &body,
        )
        .unwrap();
    let a = WorldAuthoritySet::new(true, [world_a, world_b]).unwrap();
    let b = WorldAuthoritySet::new(true, [world_b]).unwrap();
    for (id, scope, claim_byte) in [(actor, a.clone(), 0x76), (other, b.clone(), 0x77)] {
        let grant = world_access_claim_body(
            PREDICATE_WORLD_ACCESS_ALLOWED_SET,
            id,
            &scope,
            ClaimSource::UserStated,
            ClaimApprovalStatus::Approved,
            None,
            None,
        )
        .unwrap();
        vault
            .put_claim(
                &EntityId::from_bytes([claim_byte; 16]).unwrap(),
                &grant,
                at,
                1,
            )
            .unwrap();
    }
    let presence = [
        RoomPresence {
            actor,
            actor_class: Some(EdgeActorClass::Human),
            label: "first".into(),
            present: true,
            active_worlds: a,
        },
        RoomPresence {
            actor: other,
            actor_class: Some(EdgeActorClass::Human),
            label: "second".into(),
            present: true,
            active_worlds: b.clone(),
        },
    ];
    assert_eq!(room_scope(&presence).unwrap(), b);
    let turn_scope = crate::pipeline::ActiveWorldSelection {
        agent_ref: actor,
        selected: Some(room_scope(&presence).unwrap()),
    };
    let memory = vault.memory(actor, EdgeActorClass::Human);
    assert_eq!(memory.rooms_list(10).unwrap()[0].id_hex, room.to_hex());
    let receipt = memory
        .rooms_speak(
            room,
            &crate::memory::WitnessTurn {
                conversation_ref: room.to_hex(),
                turn_ref: None,
                messages: vec![crate::memory::WitnessMessage {
                    id: None,
                    author: crate::memory::WitnessAuthor::User,
                    message_type: "dialogue".into(),
                    content: "hello room".into(),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                }],
                occurred_at: 2,
            },
        )
        .unwrap();
    assert_eq!(receipt.message_short_ids.len(), 1);
    assert_eq!(memory.rooms_messages(room, &presence, 10).unwrap().len(), 1);
    vault
        .put_edge(&room, crate::EdgeKind::BelongsTo, &actor, 1.0)
        .unwrap();
    vault
        .put_edge(&other, crate::EdgeKind::BelongsTo, &room, 1.0)
        .unwrap();
    assert_eq!(memory.rooms_messages(room, &presence, 1).unwrap().len(), 1);

    let input = crate::memory::ClaimInput {
        id: None,
        predicate: "room.posture.mode".into(),
        subject_ref: room.to_hex(),
        value: serde_json::json!("silent"),
        confidence: 1.0,
        source: "user_stated".into(),
        world_ref: None,
        scope: None,
        valid_from: None,
        valid_to: None,
        occurred_at: None,
        learned_at: None,
        salience: None,
    };
    let claim = memory.rooms_claim(room, &input).unwrap();
    // Earlier hidden rows may not consume the room's visible claim budget.
    for n in 1..=1000u16 {
        let mut bytes = [0u8; 16];
        bytes[14..].copy_from_slice(&n.to_be_bytes());
        let mut hidden = crate::ClaimBody::new(
            "room.rule",
            crate::ClaimSubject::Entity(room),
            rmpv::Value::from("hidden"),
            1.0,
            ClaimApprovalStatus::Approved,
            crate::ClaimLifecycleStatus::Active,
        );
        hidden.world = Some(world_a);
        vault
            .put_claim(&EntityId::from_bytes(bytes).unwrap(), &hidden, at, 1)
            .unwrap();
    }
    // Both participants' authenticated class must survive the scoped-read key.
    let mut policy: rmpv::Value =
        rmpv::decode::read_value(&mut crate::gate::default_policy_manifest().as_slice()).unwrap();
    let rmpv::Value::Map(entries) = &mut policy else {
        panic!("manifest map")
    };
    entries.retain(|(key, _)| key.as_str() != Some("scoped_grants"));
    entries.push((
        "scoped_grants".into(),
        rmpv::Value::Array(
            [actor, other]
                .map(|id| {
                    rmpv::Value::Map(vec![
                        ("actor_ref".into(), id.to_hex().into()),
                        ("actor_class".into(), "human".into()),
                        ("effector".into(), "core:read".into()),
                        ("scope".into(), rmpv::Value::Map(vec![])),
                        ("receipt_required".into(), false.into()),
                    ])
                })
                .to_vec(),
        ),
    ));
    let mut policy_bytes = Vec::new();
    rmpv::encode::write_value(&mut policy_bytes, &policy).unwrap();
    crate::test_util::put_policy_manifest_bytes(
        &vault,
        crate::gate::default_policy_manifest_id().unwrap(),
        &policy_bytes,
    )
    .unwrap();
    let section = memory.rooms_render(room, &presence).unwrap();
    assert_eq!(section.scope, turn_scope.selected.unwrap());
    assert_eq!(section.posture.mode, RoomMode::Silent);
    assert!(
        section
            .claims
            .iter()
            .any(|row| row.short_ref.as_ref() == Some(&claim.claim_short_id))
    );
    let rendered = section.board_section().unwrap();
    assert!(
        rendered
            .pinned_rows()
            .iter()
            .any(|line| line.contains("posture: silent"))
    );
    assert_eq!(
        RoomPosture {
            mode: RoomMode::AskedOnly,
            bar: RoomBar::High
        }
        .compose(RoomPosture {
            mode: RoomMode::Chime,
            bar: RoomBar::Low
        }),
        RoomPosture {
            mode: RoomMode::AskedOnly,
            bar: RoomBar::High
        }
    );

    // A capped room read must not materialize the rest of a large inbound lane.
    let edge_value = crate::edge::encode_edge_value(
        crate::EdgeKind::BelongsTo,
        1.0,
        0,
        crate::affect::Vad::NEUTRAL,
        None,
    )
    .unwrap();
    vault
        .with_write_txn(|txn| {
            for n in 0..=crate::vault::MAX_EDGE_QUERY_RESULTS {
                let mut bytes = [0xff; 16];
                bytes[8..].copy_from_slice(&(n as u64).to_be_bytes());
                let peer = EntityId::from_bytes(bytes).unwrap();
                let key =
                    crate::store::Store::encode_edge_key(&room, crate::EdgeKind::BelongsTo, &peer);
                vault.store.edges_in.put(txn, &key, &edge_value)?;
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(memory.rooms_messages(room, &presence, 1).unwrap().len(), 1);
}
