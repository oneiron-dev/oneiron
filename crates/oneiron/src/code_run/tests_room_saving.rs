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
    /// The owner's proof, which every save of theirs takes.
    proof: crate::consent::AuthenticatedOwner,
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
    let proof = crate::test_util::embedded_owner_proof(vault);
    (
        Room {
            owner,
            agent,
            proof,
        },
        session,
    )
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
    let saved = session.save_talk_as(&room.proof).expect("save");
    assert_eq!(saved.len(), 1, "{saved:?}");
    let turn = saved[0].0;
    assert!(saved[0].1.replayed.contains(&first), "{saved:?}");

    run.dispatch(said(1, "and the boat is moored at the north pier"))
        .expect("the run speaks on into its turn");
    assert_eq!(exported(&session, &room), vec![0, 1]);
    let saved = session.save_talk_as(&room.proof).expect("save again");
    assert_eq!(saved.len(), 1, "{saved:?}");
    assert_eq!(saved[0].0, turn);
    assert_eq!(saved[0].1.replayed, vec![second]);

    let saved = session.save_talk_as(&room.proof).expect("save once more");
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
        let save = scope.spawn(|| session.save_talk_as(&room.proof));
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

    let saved = session.save_talk_as(&room.proof).expect("save again");
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
    let turn = session.save_talk_as(&room.proof).expect("save")[0].0;
    run.dispatch(said(1, "and the boat is moored at the north pier"))
        .expect("the run speaks on into its turn");
    // Deleted as any room door deletes it: a shell keeps its header and edges.
    let deleted = vault
        .delete_room_record_unchecked_for_test(&turn, crate::DeleteReason::UserDelete)
        .expect("delete the saved turn");
    assert!(deleted.existed);

    let saved = session.save_talk_as(&room.proof).expect("save again");
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
    let turn = session.save_talk_as(&room.proof).expect("save")[0].0;
    run.dispatch(said(1, "and the boat is moored at the north pier"))
        .expect("the run speaks on into its turn");

    let (planned, save_planned) = sync_channel(0);
    let (let_save, save_go) = sync_channel::<()>(0);
    *vault.test_hooks().after_save_plan.lock().expect("hook") = Some(Box::new(move || {
        planned.send(()).expect("signal the save");
        save_go.recv().expect("release the save");
    }));
    let refused = std::thread::scope(|scope| {
        let save = scope.spawn(|| session.save_talk_as(&room.proof));
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
    let turn = session.save_talk_as(&room.proof).expect("save")[0].0;
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

    let refused = session.save_talk_as(&room.proof).err();
    assert!(
        matches!(
            &refused,
            Some(Error::OffRecord(
                crate::error::OffRecordError::OffRecordCopyConflict { turn_ref, order: 1 }
            )) if *turn_ref == turn.to_hex()
        ),
        "the save copied onto a taken order: {refused:?}"
    );
    assert_eq!(
        base_orders(&vault, &turn),
        vec![0, 1],
        "one message per order"
    );
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
    let turn = session.save_talk_as(&room.proof).expect("save")[0].0;
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

    let saved = session.save_talk_as(&room.proof).expect("save again");
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

/// Sol on #1411: a save copied what a run said into a turn it saved, after a
/// native put had changed the turn's speaker. An ordinary append is checked
/// against the turn's speaker and would be refused; the copy was not. A save
/// copies nothing into a turn that no longer speaks as its messages; the
/// message stays in the room, unsaved.
#[test]
fn a_save_copies_nothing_into_a_saved_turn_whose_speaker_changed() {
    let (_dir, vault) = open_test_vault();
    let (room, session) = room_off_record(&vault);
    let run = bind_run(&session, &room);
    run.dispatch(said(0, "the lighthouse key is under the blue stone"))
        .expect("the run speaks");
    let turn = session.save_talk_as(&room.proof).expect("save")[0].0;
    run.dispatch(said(1, "and the boat is moored at the north pier"))
        .expect("the run speaks on into its turn");
    // A native put says the turn is the user's now.
    let body = vault.get(&turn).expect("read").expect("the saved turn");
    let Value::Map(fields) = rmpv::decode::read_value(&mut body.as_slice()).expect("decode") else {
        panic!("a turn body is a map");
    };
    let fields = fields
        .into_iter()
        .map(|(key, value)| {
            if key.as_str() == Some("speaker") {
                (key, Value::from("user"))
            } else {
                (key, value)
            }
        })
        .collect();
    let mut restamped = Vec::new();
    rmpv::encode::write_value(&mut restamped, &Value::Map(fields)).expect("encode");
    vault
        .put_entity(
            &turn,
            crate::registry::ENTITY_TYPE_TURN,
            TimeRange {
                start: 60_000,
                end: 60_000,
            },
            1,
            &restamped,
        )
        .expect("restamp the turn");

    let saved = session.save_talk_as(&room.proof).expect("save again");
    assert!(
        saved.is_empty(),
        "copied into a turn that speaks as another: {saved:?}"
    );
    assert!(vault.get_raw(&message(1)).expect("read").is_none());
    assert!(
        session
            .overlay()
            .contains_entity(&message(1))
            .expect("probe")
    );
}

/// Sol on #1411: a run said a message off record into a saved turn, and a
/// peer's hard-delete tombstone for that message's id arrived before the
/// next save, leaving the id deleted for good with no row. The save still
/// wrote the message under the deleted id. A save copies nothing of a turn
/// holding a message deleted for good; the message stays in the room.
#[test]
fn a_save_copies_nothing_of_a_message_hard_deleted_since() {
    let (_dir, vault) = open_test_vault();
    let (room, session) = room_off_record(&vault);
    let run = bind_run(&session, &room);
    run.dispatch(said(0, "the lighthouse key is under the blue stone"))
        .expect("the run speaks");
    session.save_talk_as(&room.proof).expect("save");
    run.dispatch(said(1, "and the boat is moored at the north pier"))
        .expect("the run speaks on into its turn");
    let tombstone = crate::deletion::TombstoneValueV2 {
        reason: crate::deletion::TombstoneReason::UserHardDelete,
        deleted_at: 20,
        request_id: *EntityId::now().as_bytes(),
    };
    vault
        .apply_replayed_tombstone(&message(1), &tombstone.encode())
        .expect("a peer's tombstone names the message");

    let saved = session.save_talk_as(&room.proof).expect("save again");
    assert!(
        saved.is_empty(),
        "copied a message deleted for good: {saved:?}"
    );
    assert!(vault.get_raw(&message(1)).expect("read").is_none());
    assert!(
        session
            .overlay()
            .contains_entity(&message(1))
            .expect("probe")
    );
}

/// The challenge a holder signs to prove a slip in these checks.
const BINDING: &[u8] = b"room-save";

/// A slip of `class` for `holder`, minted under the test host root, which
/// the first one roots.
fn minted(
    vault: &Vault,
    holder: EntityId,
    class: &str,
    id: u8,
) -> crate::authority::CapabilitySlip {
    minted_shaped(vault, holder, class, id, |_| {})
}

/// [`minted`], its claims shaped by `shape` first.
fn minted_shaped(
    vault: &Vault,
    holder: EntityId,
    class: &str,
    id: u8,
    shape: impl FnOnce(&mut crate::authority::SlipClaims),
) -> crate::authority::CapabilitySlip {
    let issuer = crate::test_support::test_host_issuer();
    let mut claims = vault
        .ensure_host_root_slip(&issuer)
        .expect("host root")
        .claims;
    claims.slip_id = [id; 32];
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some(class.to_owned());
    shape(&mut claims);
    vault
        .mint_capability_slip(&issuer, claims)
        .expect("mint the slip")
}

/// [`minted`], as the vault verifies it for the host that holds it.
fn slip(vault: &Vault, holder: EntityId, class: &str, id: u8) -> crate::authority::VerifiedSlip {
    verified(vault, &minted(vault, holder, class, id))
}

/// `minted` as the vault verifies it for the host that holds it.
fn verified(
    vault: &Vault,
    minted: &crate::authority::CapabilitySlip,
) -> crate::authority::VerifiedSlip {
    let issuer = crate::test_support::test_host_issuer();
    let signature = issuer
        .binding_proof(minted, BINDING)
        .expect("binding proof");
    vault
        .verify_capability_slip(&issuer.public_key(), minted, BINDING, &signature)
        .expect("a verified slip")
}

/// H203 (Sol R1 F3): a handle names whom its save is for only with their
/// own slip. The owner is in the room, but a slip naming someone else, or
/// naming the owner as an agent, saves nothing and the room hears nothing;
/// the owner's own slip saves, and the receipt names them.
#[test]
fn a_room_save_for_the_owner_takes_their_own_slip() {
    let (_dir, vault) = open_test_vault();
    let (room, session) = room_off_record(&vault);
    let run = bind_run(&session, &room);
    run.dispatch(said(0, "the lighthouse key is under the blue stone"))
        .expect("the run speaks");

    for other in [
        slip(&vault, room.agent, "human", 0xA1),
        slip(&vault, room.owner, "agent", 0xA2),
    ] {
        let refused = session.save_talk_by(room.owner, &other).err();
        assert!(
            matches!(
                &refused,
                Some(Error::OffRecord(
                    crate::error::OffRecordError::OffRecordPromoteUnauthenticated { .. }
                ))
            ),
            "a save ran on a slip that is not the owner's: {refused:?}"
        );
    }
    assert!(vault.get_raw(&message(0)).expect("read").is_none());
    let heard = session
        .record_for(room.owner)
        .expect("the record")
        .notices
        .iter()
        .filter(|notice| notice.act == OffRecordNoticeAct::SavedTalk)
        .count();
    assert_eq!(heard, 0, "the room heard a refused save");

    let own = slip(&vault, room.owner, "human", 0xA3);
    let saved = session
        .save_talk_by(room.owner, &own)
        .expect("the owner's own slip saves");
    assert_eq!(saved.len(), 1, "{saved:?}");
    let kept = vault
        .off_record_promote_receipt(&saved[0].0)
        .expect("read")
        .expect("the turn's receipt");
    assert_eq!(kept.initiator_ref, room.owner.to_hex());
    assert_eq!(
        kept.initiator_kind,
        crate::off_record::PROMOTE_INITIATOR_ROOM_OWNER
    );
}

/// H203 (Sol R1 F4): a later save that copies what a run said into a saved
/// turn names who saved it in each copy's receipt, as the turn's own receipt
/// names the save that first kept it.
#[test]
fn a_later_save_names_its_saver_in_each_copy() {
    let (_dir, vault) = open_test_vault();
    let (room, session) = room_off_record(&vault);
    let run = bind_run(&session, &room);
    run.dispatch(said(0, "the lighthouse key is under the blue stone"))
        .expect("the run speaks");
    let turn = session.save_talk_as(&room.proof).expect("save")[0].0;
    run.dispatch(said(1, "and the boat is moored at the north pier"))
        .expect("the run speaks on into its turn");

    let own = slip(&vault, room.owner, "human", 0xA4);
    let saved = session
        .save_talk_by(room.owner, &own)
        .expect("save again on the owner's slip");
    assert_eq!(saved.len(), 1, "{saved:?}");
    assert_eq!(saved[0].1.replayed, vec![message(1)]);
    let first = vault
        .off_record_promote_receipt(&turn)
        .expect("read")
        .expect("the turn's receipt");
    assert_eq!(
        first.initiator_kind,
        crate::off_record::PROMOTE_INITIATOR_OWNER
    );
    let copied = vault
        .off_record_copy_receipt(&message(1))
        .expect("read")
        .expect("the copy's receipt");
    assert_eq!(copied.initiator_ref, room.owner.to_hex());
    assert_eq!(
        copied.initiator_kind,
        crate::off_record::PROMOTE_INITIATOR_ROOM_OWNER
    );
}

/// H203 (Sol and Astra R2 F1, F4; R4 F1): a slip the owner narrowed and
/// handed on to another key still names them, but it is not their act.
/// Narrowed to reading, or to nothing at all, it saves nothing and the room
/// hears nothing, nor does one narrowed under the owner's own key: the save
/// takes only the slip this vault minted, as minted.
#[test]
fn a_room_save_refuses_a_slip_the_owner_handed_on() {
    use ed25519_dalek::{Signer, SigningKey};

    let (_dir, vault) = open_test_vault();
    let (room, session) = room_off_record(&vault);
    let run = bind_run(&session, &room);
    run.dispatch(said(0, "the lighthouse key is under the blue stone"))
        .expect("the run speaks");
    let issuer = crate::test_support::test_host_issuer();
    let helper = SigningKey::from_bytes(&[0x5C; 32]);
    let mut reading = crate::federation::Scope::top();
    reading.verbs = crate::federation::ScopeAxis::Some(["read".to_owned()].into());
    let narrowed = crate::authority::SlipCaveat {
        scope: Some(reading),
        ..Default::default()
    };
    let handed_on = crate::authority::SlipCaveat {
        ttl_secs: Some(30),
        ..Default::default()
    };
    for (id, caveat) in [(0xB1, narrowed), (0xB2, handed_on)] {
        let mut handed = minted(&vault, room.owner, "human", id);
        issuer
            .attenuate_to(&mut handed, caveat, helper.verifying_key().to_bytes())
            .expect("hand the slip on");
        let signature = helper
            .sign(&handed.binding_transcript(BINDING).expect("transcript"))
            .to_bytes();
        let verified = vault
            .verify_capability_slip(&issuer.public_key(), &handed, BINDING, &signature)
            .expect("the helper's verified slip");
        let refused = session.save_talk_by(room.owner, &verified).err();
        assert!(
            matches!(
                &refused,
                Some(Error::OffRecord(
                    crate::error::OffRecordError::OffRecordPromoteUnauthenticated { .. }
                ))
            ),
            "a slip handed on saved the room: {refused:?}"
        );
    }
    // Narrowed under the owner's own key, it is still not the slip as minted
    // (Sol and Astra R4 F1).
    let mut kept = minted(&vault, room.owner, "human", 0xB4);
    issuer
        .attenuate(
            &mut kept,
            crate::authority::SlipCaveat {
                ttl_secs: Some(30),
                ..Default::default()
            },
        )
        .expect("narrow the slip");
    let refused = session
        .save_talk_by(room.owner, &verified(&vault, &kept))
        .err();
    assert!(
        matches!(
            &refused,
            Some(Error::OffRecord(
                crate::error::OffRecordError::OffRecordPromoteUnauthenticated { .. }
            ))
        ),
        "a slip narrowed under the owner's key saved the room: {refused:?}"
    );
    assert!(vault.get_raw(&message(0)).expect("read").is_none());
    let heard = session
        .record_for(room.owner)
        .expect("the record")
        .notices
        .iter()
        .filter(|notice| notice.act == OffRecordNoticeAct::SavedTalk)
        .count();
    assert_eq!(heard, 0, "the room heard a refused save");
    let own = slip(&vault, room.owner, "human", 0xB3);
    session
        .save_talk_by(room.owner, &own)
        .expect("the owner's own slip saves");
}

/// H203 (Sol R3 F2, Astra R3 F1 and F3): the owner's own write slip saves
/// under either spelling of write the HTTP door reads. A one-shot slip saves
/// nothing: no save consumes it, so it would save again on the same proof.
#[test]
fn a_room_save_takes_a_core_write_slip_but_no_one_shot() {
    let (_dir, vault) = open_test_vault();
    let (room, session) = room_off_record(&vault);
    let run = bind_run(&session, &room);
    run.dispatch(said(0, "the lighthouse key is under the blue stone"))
        .expect("the run speaks");
    let one_shot = verified(
        &vault,
        &minted_shaped(&vault, room.owner, "human", 0xC1, |claims| {
            let lifetime = oneiron_authority::credential_door::DOOR_ONE_SHOT_MAX_LIFETIME_SECS;
            claims.single_use = true;
            claims.expires_at = claims.issued_at + lifetime;
            claims.ttl_secs = claims.ttl_secs.min(lifetime);
        }),
    );
    let refused = session.save_talk_by(room.owner, &one_shot).err();
    assert!(
        matches!(
            &refused,
            Some(Error::OffRecord(
                crate::error::OffRecordError::OffRecordPromoteUnauthenticated { .. }
            ))
        ),
        "a one-shot slip saved the room: {refused:?}"
    );
    assert!(vault.get_raw(&message(0)).expect("read").is_none());

    let core_write = verified(
        &vault,
        &minted_shaped(&vault, room.owner, "human", 0xC2, |claims| {
            claims.scope.verbs = crate::federation::ScopeAxis::Some(
                ["core:read".to_owned(), "core:write".to_owned()].into(),
            );
        }),
    );
    let saved = session
        .save_talk_by(room.owner, &core_write)
        .expect("the owner's core:write slip saves");
    assert_eq!(saved.len(), 1, "{saved:?}");
}
