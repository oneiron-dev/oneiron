//! Carrier-level generation receipt proof through real Observer B rematerialization.
#![cfg(feature = "sync")]
use crate::sync_harness::{TestNode, exchange};
use oneiron::conversation::{ConversationBody, ConversationKind, HistoryChoice};
use oneiron::reaction::{
    ReactionAcknowledgment, ReactionGeneration, ReactionIngress, ReactionInput, ReactionState,
};
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange, WriteActor};

#[test]
fn first_party_ack_binding_survives_carrier_exchange_and_remote_removal_replays() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs();
    let window = chrono::DateTime::from_timestamp(now as i64, 0)
        .expect("valid date")
        .format("%Y-%m")
        .to_string();
    let mut a = TestNode::new("reaction-a", 1);
    let mut b = TestNode::new("reaction-b", 2);
    a.open_window(&window);
    b.open_window(&window);
    let person = EntityId::now();
    let room = EntityId::now();
    let turn = EntityId::now();
    let actor = WriteActor::new(person, EdgeActorClass::Human);
    for node in [&a, &b] {
        node.vault
            .put_entity(
                &person,
                oneiron::registry::ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                b"person",
            )
            .unwrap();
        node.vault
            .create_conversation(
                room,
                &ConversationBody {
                    kind: ConversationKind::Mirror,
                    external_id: Some("slack:room".into()),
                    ..Default::default()
                },
                actor,
                1,
            )
            .unwrap();
        node.vault
            .join_member(room, person, actor, 2, HistoryChoice::None)
            .unwrap();
        node.vault
            .put_entity(
                &turn,
                oneiron::registry::ENTITY_TYPE_TURN,
                TimeRange { start: 10, end: 10 },
                10,
                &rmp_serde::to_vec_named(&serde_json::json!({"speaker":"user"})).unwrap(),
            )
            .unwrap();
        node.vault
            .put_edge(&turn, EdgeKind::ChildOf, &room, 1.0)
            .unwrap();
        node.vault
            .put_edge(&turn, EdgeKind::AuthoredBy, &person, 1.0)
            .unwrap();
    }
    let original = a
        .vault
        .react(ReactionInput {
            message: turn,
            by: person,
            glyph: "👀".into(),
            occurred_at: 20,
            external_id: None,
            actor,
        })
        .unwrap()
        .id;
    let generation = ReactionGeneration {
        connector: "slack".into(),
        id: "wire-gen-1".into(),
    };
    let binding = a
        .vault
        .acknowledge_reaction(ReactionAcknowledgment {
            original,
            generation: generation.clone(),
            actor,
        })
        .unwrap()
        .id;
    let original_blob = a.vault.get_raw(&original).unwrap().unwrap();
    let binding_blob = a.vault.get_raw(&binding).unwrap().unwrap();
    a.put_entity_in_window(&window, &original, &original_blob);
    a.put_entity_in_window(&window, &binding, &binding_blob);
    a.put_edge_in_window(
        &window,
        &original,
        EdgeKind::About,
        &turn,
        1.0,
        now,
        oneiron::Vad::NEUTRAL,
    );
    a.put_edge_in_window(
        &window,
        &original,
        EdgeKind::AuthoredBy,
        &person,
        1.0,
        now,
        oneiron::Vad::NEUTRAL,
    );
    exchange(&a, &b, &window);
    assert!(
        b.vault
            .entities_by_type(oneiron::registry::ENTITY_TYPE_REACTION_BINDING)
            .unwrap()
            .contains(&binding),
        "receipt arrived via CRDT carrier"
    );
    assert_eq!(
        b.vault.reaction_pills(&[turn], person).unwrap()[&turn][0].count,
        1
    );
    b.close_window(&window);
    let removed = b
        .vault
        .ingest_reaction(ReactionIngress::Remove {
            message: turn,
            by: person,
            glyph: "👀".into(),
            generation: generation.clone(),
            actor,
        })
        .unwrap();
    assert_eq!(removed.state, ReactionState::Revoked);
    b.recover(&window);
    exchange(&a, &b, &window);
    for node in [&a, &b] {
        assert!(node.vault.reaction_pills(&[turn], person).unwrap()[&turn].is_empty());
        assert_eq!(
            node.vault
                .acknowledge_reaction(ReactionAcknowledgment {
                    original,
                    generation: generation.clone(),
                    actor
                })
                .unwrap()
                .state,
            ReactionState::Replayed,
            "late echo after remote revoke must not resurrect"
        );
    }
}
