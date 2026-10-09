//! Acceptance 5: the agent signal feed returns new reactions to the agent's
//! own messages since its last turn, paged.
use super::*;

#[test]
fn signal_feed_pages_new_reactions_to_own_messages_since_the_last_turn() {
    let room = room();
    let bobs = react(&room, room.bob, "👍");
    let daves = react(&room, room.dave, "🎉");
    react(&room, room.alice, "👀");
    room.vault
        .remove_reaction(room.message, room.bob, "👍", human(room.bob))
        .unwrap();
    let other = witness(&room.vault, room.room, room.bob, "a message by Bob");
    room.vault
        .react(ReactionInput {
            message: other,
            ..input(&room, room.dave, "👍")
        })
        .unwrap();

    let all = room.vault.reactions_since(room.alice, 0).unwrap();
    let events: Vec<_> = all
        .iter()
        .map(|signal| (signal.reaction, signal.event()))
        .collect();
    assert_eq!(events.len(), 3, "own reactions and other messages excluded");
    let at = |event| events.iter().position(|row| *row == event).expect("event");
    assert!(at((bobs.id, "reaction.put")) < at((bobs.id, "reaction.revoked")));
    at((daves.id, "reaction.put"));
    assert!(all.iter().all(|signal| signal.message == room.message));
    assert!(
        all.windows(2)
            .all(|pair| pair[0].recorded_at <= pair[1].recorded_at)
    );

    // One signal per page; the pages concatenate to the whole feed.
    let mut paged = Vec::new();
    let mut after = None;
    loop {
        let page = room
            .vault
            .reactions_since_page(room.alice, 0, after.as_deref(), 1)
            .unwrap();
        assert!(page.signals.len() <= 1);
        paged.extend(page.signals);
        match page.next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    assert_eq!(paged, all);

    // Since the last turn: nothing after it, then the new reaction.
    let last_turn = all.iter().map(|signal| signal.recorded_at).max().unwrap();
    assert!(
        room.vault
            .reactions_since(room.alice, u64::MAX)
            .unwrap()
            .is_empty()
    );
    let erins = react(&room, room.erin, "✅");
    let since = room.vault.reactions_since(room.alice, last_turn).unwrap();
    assert!(since.iter().all(|signal| signal.recorded_at >= last_turn));
    assert!(
        since
            .iter()
            .any(|signal| signal.reaction == erins.id && signal.event() == "reaction.put")
    );

    // Bob's feed holds only the reaction to Bob's own message.
    let bob_feed = room.vault.reactions_since(room.bob, 0).unwrap();
    assert_eq!(bob_feed.len(), 1);
    assert_eq!(bob_feed[0].message, other);
}
