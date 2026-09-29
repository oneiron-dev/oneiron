//! Acceptance 6 and 7: outbound reactions go only where the adapter declares
//! `ReactionTarget`; erasing the message or the person erases its reactions.
use super::*;
use crate::attempt_queue::AttemptQueue;
use crate::deletion::DeleteReason;

fn outbound(vault: &Vault) -> Vec<ReactionOutboundAttempt> {
    AttemptQueue::new(vault)
        .list()
        .unwrap()
        .into_iter()
        .filter(|attempt| attempt.kind == REACTION_OUTBOUND_ATTEMPT_KIND)
        .map(|attempt| rmp_serde::from_slice(&attempt.payload).unwrap())
        .collect()
}

#[test]
fn outbound_react_is_queued_only_where_the_adapter_declares_reaction_target() {
    for connector in ["slack", "telegram", "discord"] {
        assert!(connector_declares_reaction_target(connector), "{connector}");
    }
    assert!(!connector_declares_reaction_target("linear"));

    let slack = room_with(Some("slack:room-1"));
    let agent = trust_agent(&slack.vault, slack.dave);
    assert_eq!(
        slack.vault.reactions_outbound(slack.room).unwrap(),
        "mirrored"
    );
    let put = slack
        .vault
        .react(ReactionInput {
            actor: agent,
            ..input(&slack, slack.dave, "👍")
        })
        .unwrap();
    slack
        .vault
        .remove_reaction(slack.message, slack.dave, "👍", agent)
        .unwrap();
    let attempt = |remove| ReactionOutboundAttempt {
        reaction: put.id,
        connector: "slack".to_owned(),
        room_external_id: "slack:room-1".to_owned(),
        remove,
    };
    assert_eq!(outbound(&slack.vault), vec![attempt(false), attempt(true)]);

    let linear = room_with(Some("linear:room-1"));
    let agent = trust_agent(&linear.vault, linear.dave);
    assert_eq!(
        linear.vault.reactions_outbound(linear.room).unwrap(),
        "first_party_only"
    );
    linear
        .vault
        .react(ReactionInput {
            actor: agent,
            ..input(&linear, linear.dave, "👍")
        })
        .unwrap();
    assert!(outbound(&linear.vault).is_empty());

    let plain = room();
    assert_eq!(
        plain.vault.reactions_outbound(plain.room).unwrap(),
        "first_party_only"
    );
    react(&plain, plain.bob, "👍");
    assert!(outbound(&plain.vault).is_empty());
}

fn gone(vault: &Vault, id: EntityId) -> bool {
    vault.get(&id).unwrap().is_none()
}

#[test]
fn deleting_a_message_erases_its_reactions_and_echo_bindings() {
    let room = room_with(Some("slack:room-1"));
    let own = react(&room, room.bob, "👍");
    room.vault
        .ingest_reaction(ReactionIngress::Echo {
            original: own.id,
            message: room.message,
            by: room.bob,
            glyph: "👍".to_owned(),
            generation: ReactionExternalId {
                connector: "slack".to_owned(),
                id: "echo-1".to_owned(),
            },
        })
        .unwrap();
    let echoes = room.vault.claims_for_subject(&own.id).unwrap();
    assert_eq!(echoes.len(), 1);
    let mirrored = room
        .vault
        .ingest_reaction(ReactionIngress::ProviderAdd {
            message: room.message,
            by: room.dave,
            glyph: "🎉".to_owned(),
            occurred_at: 20,
            generation: ReactionExternalId {
                connector: "slack".to_owned(),
                id: "g-2".to_owned(),
            },
        })
        .unwrap();
    room.vault
        .remove_reaction(room.message, room.bob, "👍", human(room.bob))
        .unwrap();
    let readded = react(&room, room.bob, "👍");
    room.vault
        .delete_own_room_record(room.message, DeleteReason::UserHardDelete)
        .unwrap();
    for id in [own.id, echoes[0], mirrored.id, readded.id] {
        assert!(gone(&room.vault, id), "{id:?} survived its message");
    }
}

#[test]
fn erasing_a_person_erases_every_reaction_they_made_in_the_room() {
    let room = room();
    let bobs = react(&room, room.bob, "👍");
    let daves = react(&room, room.dave, "👍");
    let second = witness(&room.vault, room.room, room.dave, "a message by Dave");
    let removed = room
        .vault
        .react(ReactionInput {
            message: second,
            ..input(&room, room.bob, "🎉")
        })
        .unwrap();
    room.vault
        .remove_reaction(second, room.bob, "🎉", human(room.bob))
        .unwrap();
    room.vault
        .erase_room_person(room.room, room.bob, human(room.bob))
        .unwrap();
    assert!(gone(&room.vault, bobs.id));
    assert!(
        gone(&room.vault, removed.id),
        "a retracted put is erased too"
    );
    assert!(
        !gone(&room.vault, daves.id),
        "other people's reactions stay"
    );
    assert!(
        room.vault
            .reaction_history(room.message, room.bob, "👍")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        room.vault
            .reaction_pills(&[room.message], room.alice)
            .unwrap()[&room.message][0]
            .by,
        vec![room.dave]
    );
}
