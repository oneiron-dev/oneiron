//! Acceptance 1 and 2: a reaction is a room-scoped claim about the message,
//! authored by the person, one live per (message, person, glyph).
use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus, ClaimSubject};

#[test]
fn reaction_is_visible_exactly_to_the_room_audience() {
    let room = room();
    let put = react(&room, room.bob, "👍");
    let read = |audience: &[EntityId]| {
        owner_read(&room)
            .for_audience(audience)
            .is_entity_readable(&put.id)
            .unwrap()
    };
    assert!(read(&[room.alice]));
    assert!(read(&[room.alice, room.bob, room.dave]));
    assert!(!read(&[room.carol]), "a non-member cannot read a reaction");
    assert!(!read(&[room.alice, room.carol]));
    // A non-member cannot react at all.
    let err = room
        .vault
        .react(input(&room, room.carol, "👍"))
        .unwrap_err();
    assert_eq!(err.kind(), crate::error::ErrorKind::ConversationDenied);
    // Nor can anyone react as someone else.
    let mut forged = input(&room, room.dave, "👍");
    forged.actor = human(room.bob);
    assert!(room.vault.react(forged).is_err());
}

#[test]
fn reaction_in_a_thread_inherits_its_room() {
    let room = room();
    let owner = human(room.alice);
    crate::conversation_dag::fixtures::grant(&room.vault, owner, true);
    let record = |parent, advance| crate::conversation_dag::AppendRecord {
        parent,
        advance,
        occurred: TimeRange { start: 12, end: 12 },
        learned_at: 12,
        ..crate::conversation_dag::fixtures::input(room.room, None, true, owner)
    };
    let head = room
        .vault
        .main_line(
            &room.room,
            crate::conversation_dag::DagPageRequest {
                after: None,
                limit: 10,
            },
        )
        .unwrap()
        .head;
    let trunk = room
        .vault
        .append_dag_record(&record(head, true))
        .unwrap()
        .id;
    let reply = room
        .vault
        .reply_in_thread(trunk, &record(Some(trunk), false))
        .unwrap()
        .id;
    let put = room
        .vault
        .react(ReactionInput {
            message: reply,
            ..input(&room, room.bob, "🎉")
        })
        .unwrap();
    assert_eq!(put.state, ReactionState::Put);
    let read = |audience: &[EntityId]| {
        owner_read(&room)
            .for_audience(audience)
            .is_entity_readable(&put.id)
            .unwrap()
    };
    assert!(read(&[room.dave]));
    assert!(!read(&[room.carol]));
}

#[test]
fn a_reaction_never_broadens_its_message_audience() {
    let room = room();
    // Carol joins after the message, without history, before the reaction:
    // her window holds the reaction's time but not the message's.
    room.vault
        .join_member(
            room.room,
            room.carol,
            human(room.alice),
            15,
            HistoryChoice::None,
        )
        .unwrap();
    let put = react(&room, room.bob, "👍");
    assert!(
        !owner_read(&room)
            .for_audience(&[room.carol])
            .is_entity_readable(&put.id)
            .unwrap()
    );
    assert!(
        owner_read(&room)
            .for_audience(&[room.carol])
            .reaction_lines(&room.message)
            .unwrap()
            .is_empty()
    );
    let err = room
        .vault
        .react(input(&room, room.carol, "👍"))
        .unwrap_err();
    assert_eq!(err.kind(), crate::error::ErrorKind::ConversationDenied);
}

#[test]
fn one_live_reaction_per_tuple_and_the_toggle_history_reads_in_order() {
    let room = room();
    let first = react(&room, room.bob, "👍");
    assert_eq!(first.state, ReactionState::Put);
    assert_eq!(
        react(&room, room.bob, "👍"),
        ReactionChange {
            id: first.id,
            state: ReactionState::Replayed
        },
        "a repeat put is idempotent"
    );
    let removed = room
        .vault
        .remove_reaction(room.message, room.bob, "👍", human(room.bob))
        .unwrap();
    assert_eq!(
        removed,
        ReactionChange {
            id: first.id,
            state: ReactionState::Revoked
        }
    );
    let body = claim(&room.vault, first.id);
    assert_eq!(body.lifecycle, ClaimLifecycleStatus::Retracted);
    assert_eq!(
        room.vault
            .remove_reaction(room.message, room.bob, "👍", human(room.bob))
            .unwrap()
            .state,
        ReactionState::Replayed
    );
    assert!(
        room.vault
            .reaction_pills(&[room.message], room.alice)
            .unwrap()[&room.message]
            .is_empty()
    );
    let again = react(&room, room.bob, "👍");
    assert_eq!(again.state, ReactionState::Put);
    assert_ne!(again.id, first.id, "a re-add is a new claim");
    room.vault
        .remove_reaction(room.message, room.bob, "👍", human(room.bob))
        .unwrap();
    let third = react(&room, room.bob, "👍");
    let history = room
        .vault
        .reaction_history(room.message, room.bob, "👍")
        .unwrap();
    assert_eq!(
        history.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        vec![first.id, again.id, third.id],
        "the whole toggle chain reads back in order"
    );
    assert!(history[0].removed_at.is_some());
    assert!(history[1].removed_at.is_some());
    assert_eq!(history[2].removed_at, None);
    // Another glyph is another chain.
    let other = react(&room, room.bob, "🎉");
    assert_ne!(other.id, third.id);
    let pills = &room
        .vault
        .reaction_pills(&[room.message], room.bob)
        .unwrap()[&room.message];
    assert_eq!(
        pills
            .iter()
            .map(|pill| (pill.glyph.as_str(), pill.count, pill.mine))
            .collect::<Vec<_>>(),
        vec![("👍", 1, true), ("🎉", 1, true)],
    );
}

#[test]
fn an_agent_person_reacts_through_the_same_door_under_its_ceiling() {
    let room = room();
    let agent = WriteActor::new(room.dave, EdgeActorClass::Agent);
    // Without an Auto ceiling the owner's lever refuses the put outright.
    let err = room
        .vault
        .react(ReactionInput {
            actor: agent,
            ..input(&room, room.dave, "✅")
        })
        .unwrap_err();
    assert_eq!(err.kind(), crate::error::ErrorKind::GateWriteRejected);
    trust_agent(&room.vault, room.dave);
    let put = room
        .vault
        .react(ReactionInput {
            actor: agent,
            ..input(&room, room.dave, "✅")
        })
        .unwrap();
    let body = claim(&room.vault, put.id);
    assert_eq!(body.approval, ClaimApprovalStatus::Auto);
    assert_eq!(body.source, Some(crate::ClaimSource::Observed));
}

#[test]
fn generic_claim_door_cannot_forge_another_persons_reaction() {
    let room = room();
    let value = ReactionValue {
        glyph: "👍".to_owned(),
        occurred_at: 20,
        by: room.bob,
        external_id: None,
    };
    let envelope = crate::WriteEnvelope::new(
        human(room.dave),
        crate::ClaimSource::UserStated,
        crate::WriteProvenance::new(rmpv::Value::Map(vec![])).unwrap(),
        ClaimApprovalStatus::Auto,
    );
    let candidate = crate::ClaimCandidate::new(
        PREDICATE_CONVERSATION_REACTION,
        ClaimSubject::Entity(room.message),
        value.to_value(),
        1.0,
    );
    let err = room
        .vault
        .batch()
        .claim_candidate(
            &EntityId::now(),
            candidate,
            &envelope,
            TimeRange { start: 20, end: 20 },
            20,
        )
        .commit()
        .unwrap_err();
    assert!(
        err.to_string().contains("reacting person"),
        "unexpected refusal: {err}"
    );
    for glyph in ["", "a\u{0}b"] {
        assert!(
            ReactionValue {
                glyph: glyph.to_owned(),
                ..value.clone()
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        ReactionValue {
            glyph: "x".repeat(65),
            ..value
        }
        .validate()
        .is_err()
    );
}

#[test]
fn a_peer_copy_of_the_same_reaction_counts_once_and_one_remove_retracts_both() {
    let room = room();
    let local = react(&room, room.bob, "👍");
    // A disconnected peer's put of the same tuple arrives by replication.
    let peer = EntityId::now();
    let value = ReactionValue {
        glyph: "👍".to_owned(),
        occurred_at: 21,
        by: room.bob,
        external_id: None,
    };
    room.vault
        .batch()
        .claim_candidate(
            &peer,
            crate::ClaimCandidate::new(
                PREDICATE_CONVERSATION_REACTION,
                ClaimSubject::Entity(room.message),
                value.to_value(),
                1.0,
            ),
            &crate::WriteEnvelope::new(
                human(room.bob),
                crate::ClaimSource::UserStated,
                crate::WriteProvenance::new(rmpv::Value::Map(vec![])).unwrap(),
                ClaimApprovalStatus::Auto,
            ),
            TimeRange { start: 21, end: 21 },
            21,
        )
        .commit()
        .unwrap();
    let pills = &room
        .vault
        .reaction_pills(&[room.message], room.alice)
        .unwrap()[&room.message];
    assert_eq!(pills[0].count, 1);
    assert_eq!(pills[0].by, vec![room.bob]);
    room.vault
        .remove_reaction(room.message, room.bob, "👍", human(room.bob))
        .unwrap();
    for id in [local.id, peer] {
        assert_eq!(
            claim(&room.vault, id).lifecycle,
            ClaimLifecycleStatus::Retracted
        );
    }
    assert!(
        room.vault
            .reaction_pills(&[room.message], room.alice)
            .unwrap()[&room.message]
            .is_empty()
    );
}

#[test]
fn a_first_party_reaction_cannot_be_backdated_or_flood_a_message() {
    let room = room();
    let now = room.vault.store.clock.now_recorded_at();
    let err = room
        .vault
        .react(ReactionInput {
            occurred_at: now - 3_600,
            ..input(&room, room.bob, "👍")
        })
        .unwrap_err();
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidClaimBody);
    for index in 0..super::super::write::MAX_REACTIONS_PER_PERSON {
        react(&room, room.bob, &format!("g{index}"));
    }
    let err = room
        .vault
        .react(input(&room, room.bob, "one more"))
        .unwrap_err();
    assert_eq!(err.kind(), crate::error::ErrorKind::InvalidClaimBody);
    // Another member is unaffected.
    assert_eq!(react(&room, room.dave, "👍").state, ReactionState::Put);
}
