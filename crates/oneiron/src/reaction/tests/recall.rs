//! Acceptance 4: a recalled or context-packed message carries its grouped
//! reactions; a direct query finds a reaction; a reaction never outranks an
//! ordinary memory of equal relevance.
use super::*;
use crate::memory::{Effort, RecallScope};

#[test]
fn reaction_line_names_the_first_reactors_and_counts_the_rest() {
    let names = |list: &[&str]| {
        list.iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        reaction_line("👍", 8, &names(&["Anna", "Ben"])),
        "👍×8 (Anna, Ben, +6)"
    );
    assert_eq!(
        reaction_line("👍", 2, &names(&["Anna", "Ben"])),
        "👍×2 (Anna, Ben)"
    );
    assert_eq!(reaction_line("🎉", 1, &names(&["Anna"])), "🎉×1 (Anna)");
}

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

#[test]
fn a_reaction_never_outranks_an_ordinary_memory_of_equal_relevance() {
    let room = room();
    let put = react(&room, room.bob, "👍");
    let reaction = claim(&room.vault, put.id);
    let mut ordinary = reaction.clone();
    ordinary.predicate = "conversation.note".to_owned();
    for age in [0, 86_400, 86_400 * 400] {
        let weight = |body: &crate::ClaimBody| {
            crate::claim::claim_access_factor(body, 1_000, 1_000 + age, None)
                .unwrap()
                .access_factor
        };
        assert!(weight(&reaction) > 0.0, "still findable");
        assert!(weight(&reaction) < weight(&ordinary), "age {age}");
    }
    // End to end: an ordinary claim with the same text, subject, salience and
    // time ranks above the reaction.
    let note = EntityId::now();
    let now = room.vault.store.clock.now_recorded_at();
    let envelope = crate::WriteEnvelope::new(
        human(room.bob),
        crate::ClaimSource::UserStated,
        crate::WriteProvenance::new(rmpv::Value::Map(vec![])).unwrap(),
        crate::claim::ClaimApprovalStatus::Auto,
    );
    let text = format!("👍 Bob {PLAN}");
    room.vault
        .batch()
        .claim_candidate(
            &note,
            crate::ClaimCandidate::new(
                "conversation.note",
                crate::claim::ClaimSubject::Entity(room.message),
                rmpv::Value::from(text.as_str()),
                1.0,
            )
            .with_salience(0.1),
            &envelope,
            TimeRange { start: 20, end: 20 },
            now,
        )
        .text(&note, &[("val", text.as_str())])
        .commit()
        .unwrap();
    let pack = room
        .vault
        .memory(room.alice, EdgeActorClass::Human)
        .recall(
            "Bob Friday",
            Effort::Medium,
            &RecallScope::default(),
            20,
            None,
            None,
        )
        .unwrap();
    let position = |predicate: &str| {
        pack.items
            .iter()
            .position(|item| item.predicate.as_deref() == Some(predicate))
    };
    let note_at = position("conversation.note").expect("ordinary memory recalled");
    let reaction_at = position(PREDICATE_CONVERSATION_REACTION).expect("reaction recalled");
    assert!(note_at < reaction_at, "{:?}", pack.items);
}
