//! Acceptance 4: a recalled or context-packed message carries its grouped
//! reactions; a direct query finds a reaction; a reaction never outranks an
//! ordinary memory of equal relevance.
use super::*;
use crate::memory::{Effort, RecallScope};

fn reacted_room() -> Room {
    let room = room();
    for by in [room.bob, room.dave, room.erin] {
        react(&room, by, "👍");
    }
    react(&room, room.bob, "🎉");
    room.vault
        .remove_reaction(room.message, room.dave, "👍", human(room.dave))
        .unwrap();
    room
}

#[test]
fn recalled_and_context_packed_message_carries_its_grouped_reactions() {
    let room = reacted_room();
    let expected = vec!["👍×2 (Bob, Erin)".to_owned(), "🎉×1 (Bob)".to_owned()];
    assert_eq!(
        owner_read(&room).reaction_lines(&room.message).unwrap(),
        expected
    );
    for effort in [Effort::Light, Effort::Medium] {
        let pack = room
            .vault
            .memory(room.alice, EdgeActorClass::Human)
            .recall(
                "Friday plan",
                effort,
                &RecallScope::default(),
                20,
                Some("md"),
                None,
            )
            .unwrap();
        let item = pack
            .items
            .iter()
            .find(|item| item.kind == "MESSAGE")
            .expect("the message is recalled");
        assert_eq!(item.reactions, expected, "{effort:?}");
        if effort == Effort::Medium {
            let rendered = pack.rendered.expect("rendered pack");
            assert!(rendered.contains("👍×2 (Bob, Erin)"), "{rendered}");
        }
    }
    let mut pack = room
        .vault
        .context_pack()
        .search_text("Friday plan", 20)
        .limit(20)
        .hydrate(true)
        .run()
        .unwrap();
    owner_read(&room).attach_reactions(&mut pack).unwrap();
    let message = pack
        .results
        .iter()
        .find(|entity| entity.id == room.message)
        .expect("the message is packed");
    assert_eq!(
        message.fields.as_ref().unwrap()[REACTIONS_FIELD],
        serde_json::json!(expected)
    );
    // A reader outside the room gets no reaction lines at all.
    assert!(
        owner_read(&room)
            .for_audience(&[room.carol])
            .reaction_lines(&room.message)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_direct_query_finds_a_reaction() {
    let room = reacted_room();
    let pack = room
        .vault
        .memory(room.alice, EdgeActorClass::Human)
        .recall(
            "Erin",
            Effort::Medium,
            &RecallScope::default(),
            20,
            None,
            None,
        )
        .unwrap();
    assert!(
        pack.items
            .iter()
            .any(|item| item.predicate.as_deref() == Some(PREDICATE_CONVERSATION_REACTION)),
        "{:?}",
        pack.items
    );
}
