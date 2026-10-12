//! ARCH-0052 D4, D5: saving the talk of a room off record while a run keeps
//! speaking into one turn. A save keeps what was said up to it; what the run
//! says after, or while the save waits for the writer, stays in the room for
//! the next save, which keeps it once (Codex burn engine-prs-30, -31).

use super::*;
use crate::conversation::{ConversationBody, HistoryChoice};
use crate::edge::EdgeKind;
use crate::off_record::{OffRecordBackendClass, OffRecordNoticeAct, OffRecordSession};

struct Room {
    owner: EntityId,
    agent: EntityId,
}

/// A room off record holding the vault's owner, an agent, and another
/// person, who hears its notices.
fn room_off_record(vault: &Vault) -> (Room, OffRecordSession<'_>) {
    room_off_record_seeing(vault, HistoryChoice::Share)
}

/// [`room_off_record`], each member seeing the room's history as `history`.
fn room_off_record_seeing(vault: &Vault, history: HistoryChoice) -> (Room, OffRecordSession<'_>) {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let agent = seed_first_party_actor(vault);
    let listener = seed_person(vault, 0x51);
    let by = WriteActor::new(owner, EdgeActorClass::Human);
    let id = EntityId::now();
    vault
        .create_conversation(id, &ConversationBody::default(), by, 1)
        .expect("room");
    for (at, member) in [(2, owner), (3, agent), (4, listener)] {
        vault
            .join_member(id, member, by, at, history)
            .expect("join the room");
    }
    install_self_memory_allow_policy(vault, agent).expect("policy");
    let session = vault
        .off_record_session_vault()
        .enter_in_room("deck", OffRecordBackendClass::Local, id, owner)
        .expect("start off record");
    (Room { owner, agent }, session)
}

/// Every run bound as `room-run` speaks into the same turn.
fn bind_run<'a>(session: &'a OffRecordSession<'a>, room: &Room) -> HostSelfDispatcher<'a> {
    HostSelfDispatcher::for_off_record_session(
        session,
        WriteActor::new(room.agent, EdgeActorClass::Agent),
        "room-run",
    )
    .expect("bind the run")
}

fn said(order: u64, text: &str) -> SelfCall {
    SelfCall::Speak(SelfSpeechCall::new(text)).with_bridge_stamp(order, 60_000 + order)
}

fn message(order: u32) -> EntityId {
    crate::code_run::executor_speech_message_id("room-run", order).expect("message id")
}

/// The messages of the owner's copy of the talk, by order, each as often as
/// the copy holds it.
fn exported(session: &OffRecordSession<'_>, room: &Room) -> Vec<u64> {
    let mut orders: Vec<u64> = session
        .export_talk_by(room.owner, None)
        .expect("export the talk")
        .turns
        .iter()
        .flat_map(|turn| turn.messages.iter().map(|message| message.order))
        .collect();
    orders.sort_unstable();
    orders
}

/// Codex burn engine-prs-30: a run spoke into a turn, the owner saved the
/// talk, and the run spoke on into the same turn. The next save found the
/// turn saved and kept nothing, so the new message evaporated at close. A
/// later save now copies what was said into a saved turn since, once: a save
/// after that adds nothing, and the room hears every save.
#[test]
fn a_later_save_keeps_once_what_a_run_said_into_a_saved_turn() {
    let (_dir, vault) = open_test_vault();
    let (room, session) = room_off_record(&vault);
    let run = bind_run(&session, &room);
    let (first, second) = (message(0), message(1));

    run.dispatch(said(0, "the lighthouse key is under the blue stone"))
        .expect("the run speaks");
    let saved = session.save_talk_by(room.owner, None).expect("save");
    assert_eq!(saved.len(), 1, "{saved:?}");
    let turn = saved[0].0;
    assert!(saved[0].1.replayed.contains(&first), "{saved:?}");

    run.dispatch(said(1, "and the boat is moored at the north pier"))
        .expect("the run speaks on into its turn");
    assert_eq!(exported(&session, &room), vec![0, 1]);
    let saved = session.save_talk_by(room.owner, None).expect("save again");
    assert_eq!(saved.len(), 1, "{saved:?}");
    assert_eq!(saved[0].0, turn);
    assert_eq!(saved[0].1.replayed, vec![second]);

    let saved = session
        .save_talk_by(room.owner, None)
        .expect("save once more");
    assert!(saved.is_empty(), "nothing new to keep: {saved:?}");
    let notices = session
        .record_for(room.owner)
        .expect("the record")
        .notices
        .iter()
        .filter(|notice| notice.act == OffRecordNoticeAct::SavedTalk)
        .count();
    assert_eq!(notices, 3, "the room hears every save");
    assert_eq!(exported(&session, &room), vec![0, 1]);

    session.close().expect("close");
    for id in [first, second] {
        assert!(vault.get(&id).expect("read").is_some(), "kept in the vault");
        assert_eq!(
            vault
                .targets(&id, EdgeKind::PartOf, None)
                .expect("its turn"),
            vec![turn]
        );
    }
}

/// Codex burn engine-prs-31: a save cut its plan from the room's journal, and
/// while it waited for the writer the run's next message landed in the same
/// turn. The save then retired every journal entry of the turn, the new
/// message's too, so the copy of the talk lost it and no later save could
/// find it. A save retires only the entries it was cut from: the message
/// stays in the room, and the next save keeps it.
#[test]
fn a_message_said_while_a_save_waits_stays_for_the_next_save() {
    use std::sync::mpsc::sync_channel;

    let (_dir, vault) = open_test_vault();
    let (room, session) = room_off_record(&vault);
    let (first, second) = (message(0), message(1));
    bind_run(&session, &room)
        .dispatch(said(0, "the lighthouse key is under the blue stone"))
        .expect("the run speaks");

    let (at_writer, speech_at_writer) = sync_channel(0);
    let (let_speak, speech_go) = sync_channel::<()>(0);
    *vault
        .test_hooks()
        .before_run_speech_writer
        .lock()
        .expect("hook") = Some(Box::new(move || {
        at_writer.send(()).expect("signal the speech");
        speech_go.recv().expect("release the speech");
    }));
    let (planned, save_planned) = sync_channel(0);
    let (let_save, save_go) = sync_channel::<()>(0);
    *vault.test_hooks().after_save_plan.lock().expect("hook") = Some(Box::new(move || {
        planned.send(()).expect("signal the save");
        save_go.recv().expect("release the save");
    }));

    let (saved, spoke) = std::thread::scope(|scope| {
        let speech = scope.spawn(|| {
            bind_run(&session, &room).dispatch(said(1, "and the boat is moored at the north pier"))
        });
        // The run has made every check it makes outside its transaction.
        speech_at_writer
            .recv()
            .expect("the speech reaches the writer");
        let save = scope.spawn(|| session.save_talk_by(room.owner, None));
        // The save has cut its plan from a journal without the second
        // message, and holds the session.
        save_planned.recv().expect("the save cuts its plan");
        let_speak.send(()).expect("let the run speak");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !session.overlay().contains_entity(&second).expect("probe") {
            assert!(
                std::time::Instant::now() < deadline,
                "the speech never landed"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let_save.send(()).expect("let the save commit");
        (
            save.join().expect("the save must not panic"),
            speech.join().expect("the speech must not panic"),
        )
    });
    spoke.expect("the run speaks while the save waits");
    let saved = saved.expect("save");
    assert_eq!(saved.len(), 1, "{saved:?}");
    assert!(saved[0].1.replayed.contains(&first), "{saved:?}");
    assert!(!saved[0].1.replayed.contains(&second), "{saved:?}");
    assert!(vault.get(&second).expect("read").is_none());
    assert_eq!(exported(&session, &room), vec![0, 1], "the copy keeps it");

    let saved = session.save_talk_by(room.owner, None).expect("save again");
    assert_eq!(saved.len(), 1, "{saved:?}");
    assert_eq!(saved[0].1.replayed, vec![second]);
    session.close().expect("close");
    assert!(vault.get(&second).expect("read").is_some(), "kept");
}

/// Sol on engine-prs-30: the owner deleted a turn this stretch had saved,
/// and the run had said more into it. A deleted turn keeps its header and
/// edges as a shell, and the next save took the shell for the turn and
/// copied the new message under it. A save copies nothing into a deleted
/// turn; the message stays in the room, unsaved.
#[test]
fn a_save_copies_nothing_into_a_saved_turn_since_deleted() {
    let (_dir, vault) = open_test_vault();
    let (room, session) = room_off_record(&vault);
    let run = bind_run(&session, &room);
    run.dispatch(said(0, "the lighthouse key is under the blue stone"))
        .expect("the run speaks");
    let turn = session.save_talk_by(room.owner, None).expect("save")[0].0;
    run.dispatch(said(1, "and the boat is moored at the north pier"))
        .expect("the run speaks on into its turn");
    // Deleted as any room door deletes it: a shell keeps its header and edges.
    let deleted = vault
        .delete_room_record_unchecked_for_test(&turn, crate::DeleteReason::UserDelete)
        .expect("delete the saved turn");
    assert!(deleted.existed);

    let saved = session.save_talk_by(room.owner, None).expect("save again");
    assert!(saved.is_empty(), "copied into a deleted turn: {saved:?}");
    assert!(vault.get_raw(&message(1)).expect("read").is_none());
    assert!(
        session
            .overlay()
            .contains_entity(&message(1))
            .expect("probe")
    );
}

/// Sol on engine-prs-30: a save read a saved turn's time when it cut its
/// plan, and checked the saver's sight against that time where it commits.
/// While the save waited for the writer, another write moved the turn to
/// before the saver joined the room, and the save still copied into it. The
/// save reads the turn's time again in its own transaction, so it keeps
/// nothing of a turn the saver's membership does not show whole.
#[test]
fn a_save_keeps_nothing_of_a_saved_turn_moved_out_of_sight_while_it_waits() {
    use std::sync::mpsc::sync_channel;

    let (_dir, vault) = open_test_vault();
    // The owner sees the room from when they joined it, at 2.
    let (room, session) = room_off_record_seeing(&vault, HistoryChoice::None);
    let run = bind_run(&session, &room);
    run.dispatch(said(0, "the lighthouse key is under the blue stone"))
        .expect("the run speaks");
    let turn = session.save_talk_by(room.owner, None).expect("save")[0].0;
    run.dispatch(said(1, "and the boat is moored at the north pier"))
        .expect("the run speaks on into its turn");

    let (planned, save_planned) = sync_channel(0);
    let (let_save, save_go) = sync_channel::<()>(0);
    *vault.test_hooks().after_save_plan.lock().expect("hook") = Some(Box::new(move || {
        planned.send(()).expect("signal the save");
        save_go.recv().expect("release the save");
    }));
    let refused = std::thread::scope(|scope| {
        let save = scope.spawn(|| session.save_talk_by(room.owner, None));
        save_planned.recv().expect("the save cuts its plan");
        // The turn now says it began at 1, before the owner joined.
        let body = vault.get(&turn).expect("read").expect("the saved turn");
        vault
            .put_entity(
                &turn,
                crate::registry::ENTITY_TYPE_TURN,
                TimeRange { start: 1, end: 1 },
                1,
                &body,
            )
            .expect("move the turn");
        let_save.send(()).expect("let the save commit");
        save.join().expect("the save must not panic").err()
    });
    assert!(
        matches!(
            refused,
            Some(Error::OffRecord(
                crate::error::OffRecordError::OffRecordNotInRoom { .. }
            ))
        ),
        "the save kept a turn its saver cannot see whole: {refused:?}"
    );
    assert!(vault.get_raw(&message(1)).expect("read").is_none());
    assert!(
        session
            .overlay()
            .contains_entity(&message(1))
            .expect("probe")
    );
}

/// The orders of the messages base holds in `turn`, sorted.
fn base_orders(vault: &Vault, turn: &EntityId) -> Vec<u32> {
    let mut orders: Vec<u32> = vault
        .sources(turn, EdgeKind::PartOf, None)
        .expect("the turn's messages")
        .iter()
        .map(|id| {
            let body = vault.get(id).expect("read").expect("a message");
            crate::memory::witness_message_order(&body).expect("its order")
        })
        .collect();
    orders.sort_unstable();
    orders
}

/// Astra on #1411: a save copied a message said into a saved turn at the
/// order it was said at, and an ordinary witness had put another message at
/// that order into the turn since, seeing only base. The turn then held two
/// messages at one order, and the run could not speak into it again. The
/// save refuses with a conflict naming the turn and keeps nothing; the
/// message stays in the room, and the run speaks on at a free order.
#[test]
fn a_save_refuses_a_copy_whose_order_the_turn_took_since() {
    let (_dir, vault) = open_test_vault();
    let (room, session) = room_off_record(&vault);
    let run = bind_run(&session, &room);
    run.dispatch(said(0, "the lighthouse key is under the blue stone"))
        .expect("the run speaks");
    let turn = session.save_talk_by(room.owner, None).expect("save")[0].0;
    run.dispatch(said(1, "and the boat is moored at the north pier"))
        .expect("the run speaks on into its turn");
    let shell = vault
        .targets(&turn, EdgeKind::ChildOf, None)
        .expect("its conversation")[0];
    vault
        .memory(room.agent, EdgeActorClass::Agent)
        .witness(&crate::memory::WitnessTurn {
            conversation_ref: shell.to_hex(),
            turn_ref: Some(turn.to_hex()),
            messages: vec![crate::memory::WitnessMessage {
                id: None,
                author: crate::memory::WitnessAuthor::Companion,
                message_type: "text".to_owned(),
                content: "a word said on record at order 1".to_owned(),
                metadata: None,
                is_visible: true,
                order: 1,
            }],
            occurred_at: 60_500,
        })
        .expect("an ordinary witness appends to the saved turn");
    assert_eq!(base_orders(&vault, &turn), vec![0, 1]);

    let refused = session.save_talk_by(room.owner, None).err();
    assert!(
        matches!(
            &refused,
            Some(Error::OffRecord(
                crate::error::OffRecordError::OffRecordCopyConflict { turn_ref, order: 1 }
            )) if *turn_ref == turn.to_hex()
        ),
        "the save copied onto a taken order: {refused:?}"
    );
    assert_eq!(base_orders(&vault, &turn), vec![0, 1], "one message per order");
    assert!(vault.get_raw(&message(1)).expect("read").is_none());
    assert!(
        session
            .overlay()
            .contains_entity(&message(1))
            .expect("probe")
    );

    run.dispatch(said(2, "the tide turns at nine"))
        .expect("the run speaks on at a free order");
    assert!(
        session
            .overlay()
            .contains_entity(&message(2))
            .expect("probe")
    );
}

/// Astra on #1411: the owner deleted the conversation a stretch had saved a
/// turn into and kept the turn. The next save found the turn live and still
/// under the conversation, and copied what the run said since into the
/// deleted conversation. A save copies nothing into a deleted conversation;
/// the message stays in the room, unsaved.
#[test]
fn a_save_copies_nothing_into_a_saved_conversation_since_deleted() {
    let (_dir, vault) = open_test_vault();
    let (room, session) = room_off_record(&vault);
    let run = bind_run(&session, &room);
    run.dispatch(said(0, "the lighthouse key is under the blue stone"))
        .expect("the run speaks");
    let turn = session.save_talk_by(room.owner, None).expect("save")[0].0;
    run.dispatch(said(1, "and the boat is moored at the north pier"))
        .expect("the run speaks on into its turn");
    let shell = vault
        .targets(&turn, EdgeKind::ChildOf, None)
        .expect("its conversation")[0];
    let deleted = vault
        .delete_entity_with_reason(&shell, crate::DeleteReason::UserDelete)
        .expect("delete the saved conversation");
    assert!(deleted.existed);
    assert!(vault.get(&turn).expect("read").is_some(), "the turn stays");

    let saved = session.save_talk_by(room.owner, None).expect("save again");
    assert!(
        saved.is_empty(),
        "copied into a deleted conversation: {saved:?}"
    );
    assert!(vault.get_raw(&message(1)).expect("read").is_none());
    assert!(
        session
            .overlay()
            .contains_entity(&message(1))
            .expect("probe")
    );
}
