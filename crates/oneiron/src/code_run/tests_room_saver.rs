//! ARCH-0052 D5: a run in a room on record writes into the vault of the
//! owner who put it on record, and only while that saving stands. Each check
//! drives the executor as a run does, through its session-bound dispatcher
//! (Astra #1373, re-check of the saver fixes).

use super::*;
use crate::conversation::{ConversationBody, HistoryChoice};
use crate::error::OffRecordError;
use crate::off_record::{OffRecordBackendClass, OffRecordMode, OffRecordSession};

struct Room {
    id: EntityId,
    owner: EntityId,
    agent: EntityId,
}

/// A room holding the vault's owner and an agent, whose stretch the owner
/// has put on record ("from here on").
fn room_on_record(vault: &Vault) -> (Room, OffRecordSession<'_>) {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let agent = seed_first_party_actor(vault);
    let by = WriteActor::new(owner, EdgeActorClass::Human);
    let id = EntityId::now();
    vault
        .create_conversation(id, &ConversationBody::default(), by, 1)
        .expect("room");
    for (at, member) in [(2, owner), (3, agent)] {
        vault
            .join_member(id, member, by, at, HistoryChoice::Share)
            .expect("join the room");
    }
    install_self_memory_allow_policy(vault, agent).expect("policy");
    let session = vault
        .off_record_session_vault()
        .enter_in_room("deck", OffRecordBackendClass::Local, id, owner)
        .expect("start off record");
    let proof = vault
        .authenticate_owner(
            owner,
            "principal:room-owner",
            true,
            crate::store::GateDecisionId::now(),
        )
        .expect("owner proof");
    session.flip_on_record_as(&proof).expect("from here on");
    (Room { id, owner, agent }, session)
}

fn said_in_the_room(room: &Room) -> ClaimCandidate {
    ClaimCandidate::new(
        "profile.room_note",
        ClaimSubject::Entity(room.owner),
        Value::from("the lighthouse key is under the blue stone"),
        0.9,
    )
}

fn bind_run<'a>(session: &'a OffRecordSession<'a>, room: &Room) -> HostSelfDispatcher<'a> {
    HostSelfDispatcher::for_off_record_session(
        session,
        WriteActor::new(room.agent, EdgeActorClass::Agent),
        "room-run",
    )
    .expect("bind the run")
}

/// Astra #1373 re-check, P1: after the owner who put the room on record
/// left it, a run's `put_claim` was refused, but the gate's decision about
/// it had already committed in the owner's vault, in a transaction of its
/// own that never checked the saver. That transaction checks first now, so
/// nothing of the write lands, and the saving stops.
#[test]
fn a_run_records_no_gate_decision_once_the_saver_left_the_room() {
    let (_dir, vault) = open_test_vault();
    let (room, session) = room_on_record(&vault);
    let run = bind_run(&session, &room);
    vault
        .leave_member(
            room.id,
            room.owner,
            WriteActor::new(room.owner, EdgeActorClass::Human),
            50,
        )
        .expect("the owner leaves");

    let id = EntityId::now();
    let refused = run
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id,
            said_in_the_room(&room),
            range(60),
            60,
        )))
        .err();
    assert!(
        matches!(
            refused,
            Some(Error::OffRecord(
                OffRecordError::OffRecordSavingStopped { .. }
            ))
        ),
        "{refused:?}"
    );
    assert!(vault.get_raw(&id).expect("read the claim").is_none());
    let decided = vault
        .gate_decisions(1_000)
        .expect("read the gate decisions")
        .into_iter()
        .filter(|decision| decision.claim_id == Some(*id.as_bytes()))
        .count();
    assert_eq!(decided, 0, "a gate decision landed after saving stopped");
    let record = vault
        .off_record_session(session.session_ref())
        .expect("read the stretch")
        .expect("the stretch");
    assert_eq!(record.mode, OffRecordMode::OffRecord);
}

/// Astra #1373 re-check, P1: a run's write checked its route only before it
/// waited for the writer. When the room went off record during that wait,
/// the write still landed in the owner's vault. The route is checked again
/// in the write's own transaction.
#[test]
fn a_run_write_waiting_for_the_writer_lands_nothing_once_the_room_goes_off_record() {
    let (_dir, vault) = open_test_vault();
    let (room, session) = room_on_record(&vault);
    let id = EntityId::now();
    let held = std::sync::Barrier::new(2);
    let refused = std::thread::scope(|scope| {
        let run = scope.spawn(|| {
            let run = bind_run(&session, &room);
            held.wait();
            run.dispatch(SelfCall::MemoryWriteFixture(
                SelfMemoryWriteFixtureCall::new(id, said_in_the_room(&room), range(60), 60),
            ))
            .err()
        });
        vault
            .with_write_txn(|_| {
                held.wait();
                // The run queues for the writer this closure holds only once
                // every check it makes before its transaction has passed, so
                // from here on only a check in that transaction still sees
                // the room go off record.
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                while vault.store.group_commit.queued() == 0 {
                    assert!(std::time::Instant::now() < deadline, "the run never queued");
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                vault
                    .set_off_record_session_mode(session.session_ref(), OffRecordMode::OffRecord)?;
                Ok(())
            })
            .expect("the owner stops saving");
        run.join().expect("the run must not panic")
    });
    assert!(
        matches!(
            refused,
            Some(Error::OffRecord(
                OffRecordError::OffRecordOverlayLeaseClosed { .. }
            ))
        ),
        "{refused:?}"
    );
    assert!(vault.get_raw(&id).expect("read the claim").is_none());
}
