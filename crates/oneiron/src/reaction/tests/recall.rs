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
        // The message comes back as its turn, which quotes it (ARCH-0004).
        let item = pack
            .items
            .iter()
            .find(|item| item.kind == "TURN")
            .expect("the message's turn is recalled");
        assert_eq!(item.cited_messages.len(), 1, "{effort:?}");
        assert_eq!(item.cited_messages[0].value_text, PLAN, "{effort:?}");
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

/// Sol R9 F3: a recalled message's reaction lines are derived from the
/// reaction claims they count, so recall lists each one among the rows its
/// pack was derived from, at every effort (DEC-0005).
#[test]
fn a_recall_lists_the_reaction_claims_its_lines_count() {
    let room = room();
    let counted = [
        react(&room, room.bob, "👍").id,
        react(&room, room.erin, "🎉").id,
    ];
    for effort in [Effort::Light, Effort::Medium] {
        let producers = crate::memory::ProducerRows::default();
        let pack = room
            .vault
            .memory(room.alice, EdgeActorClass::Human)
            .listing_producers(&producers)
            .recall(
                "Friday plan",
                effort,
                &RecallScope::default(),
                20,
                None,
                None,
            )
            .unwrap();
        assert!(
            pack.items.iter().any(|item| !item.reactions.is_empty()),
            "{effort:?}"
        );
        let listed = producers.take();
        assert!(
            counted.iter().all(|claim| listed.contains(claim)),
            "{effort:?}: {listed:?}"
        );
    }
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
    let text = "👍 Bob".to_owned();
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
            "Bob",
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

/// Puts `by`'s `glyph` on the room's message as the claim `Vault::react`
/// writes, plus a `sensitivity: private` stamp. A first-party reaction is
/// unstamped, and an unstamped claim is Tier A, which no contact clearance
/// admits; the stamp leaves the reaction to the clearance's bands.
fn react_private(room: &Room, by: EntityId, glyph: &str) {
    let now = room.vault.store.clock.now_recorded_at();
    let value = ReactionValue {
        glyph: glyph.to_owned(),
        occurred_at: now,
        by,
        external_id: None,
    };
    let envelope = crate::WriteEnvelope::new(
        human(by),
        crate::ClaimSource::UserStated,
        crate::WriteProvenance::new(rmpv::Value::Map(vec![(
            "kind".into(),
            "conversation_reaction".into(),
        )]))
        .unwrap(),
        crate::claim::ClaimApprovalStatus::Auto,
    );
    let id = EntityId::now();
    room.vault
        .batch()
        .claim_candidate(
            &id,
            crate::ClaimCandidate::new(
                PREDICATE_CONVERSATION_REACTION,
                crate::claim::ClaimSubject::Entity(room.message),
                value.to_value(),
                1.0,
            )
            .with_salience(0.1)
            .with_scope(rmpv::Value::Map(vec![(
                "sensitivity".into(),
                "private".into(),
            )])),
            &envelope,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .commit()
        .unwrap();
}

/// A pack read under a disclosure clamp carries only the reaction data the
/// clamp admits (Astra #1394 P2). Under a guest's bottom clearance no signal
/// names the withheld message. A clearance that admits messages and turns
/// but no claims leaves an admitted message without reaction lines. A
/// clearance that admits the stamped reactions' band gets their signals and
/// lines back, as an unclamped read does, but never Alice's unstamped
/// (Tier A) one.
#[test]
fn reactions_ride_the_packs_disclosure_clamp() {
    use crate::counterparty_contact::{CounterpartyContactRecord, CounterpartyFirstTouch};
    use crate::disclosure::{DisclosureContext, DisclosureScope};
    use crate::federation::{Scope, ScopeAxis};
    use crate::interlocutor::{Interlocutor, InterlocutorSet};
    use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};

    let room = room();
    for by in [room.bob, room.dave, room.erin] {
        react_private(&room, by, "👍");
    }
    react_private(&room, room.bob, "🎉");
    room.vault
        .remove_reaction(room.message, room.dave, "👍", human(room.dave))
        .unwrap();
    react(&room, room.alice, "🎉");
    let contact = EntityId::now();
    let introduced =
        CounterpartyContactRecord::user_introduction(EntityId::now(), "guest@example.com", 10)
            .unwrap();
    room.vault
        .create_counterparty_contact(&contact, &introduced)
        .unwrap();
    let clamp = |scope: Option<Scope>, at: u64| {
        if let Some(scope) = scope {
            room.vault
                .set_counterparty_disclosure_scope(
                    &contact,
                    &DisclosureScope::new(scope, "room guest", at).unwrap(),
                )
                .unwrap();
        }
        let set = InterlocutorSet::with_session_owner(vec![Interlocutor::known_contact(
            contact,
            "guest@example.com",
            CounterpartyFirstTouch::UserIntroduction,
        )]);
        DisclosureContext::resolve(&room.vault, set).unwrap()
    };
    let read = owner_read(&room);
    let signals = room.vault.reactions_since(room.alice, 0).unwrap();
    assert!(!signals.is_empty());
    let readable = |clamp: Option<&DisclosureContext>| {
        signals
            .iter()
            .filter(|signal| {
                read.is_reaction_signal_readable_under(signal, clamp)
                    .unwrap()
            })
            .count()
    };
    let lines = |clamp: Option<&DisclosureContext>| {
        let mut pack = room
            .vault
            .context_pack()
            .search_text("Friday plan", 20)
            .limit(20)
            .hydrate(true)
            .run()
            .unwrap();
        read.attach_reactions_under(&mut pack, clamp).unwrap();
        pack.results
            .iter()
            .find(|entity| entity.id == room.message)
            .expect("the message is packed")
            .fields
            .as_ref()
            .unwrap()
            .get(REACTIONS_FIELD)
            .cloned()
    };
    assert_eq!(readable(None), signals.len());
    assert_eq!(
        lines(None),
        Some(serde_json::json!(["👍×2 (Bob, Erin)", "🎉×2 (Bob, Alice)"]))
    );

    let bottom = clamp(None, 0);
    assert_eq!(readable(Some(&bottom)), 0);
    let words = clamp(
        Some(Scope {
            bands: ScopeAxis::Some([ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN].into()),
            ..Scope::top()
        }),
        200,
    );
    assert_eq!(readable(Some(&words)), 0);
    assert_eq!(lines(Some(&words)), None);
    let all = clamp(Some(Scope::top()), 300);
    assert_eq!(readable(Some(&all)), signals.len());
    assert_eq!(
        lines(Some(&all)),
        Some(serde_json::json!(["👍×2 (Bob, Erin)", "🎉×1 (Bob)"]))
    );
}
