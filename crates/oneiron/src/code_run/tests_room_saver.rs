//! ARCH-0052 D5: a run in a room on record writes into the vault of the
//! owner who put it on record, and only while that saving stands, and only
//! while the agent it acts as is in the room. Each check drives the executor
//! as a run does, through its session-bound dispatcher (Astra #1373, re-check
//! of the saver fixes; Codex burn engine-prs-01).

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
    room_on_record_as(vault, |proof| proof)
}

/// The same room, put on record under the proof `bind` makes of the
/// owner's.
fn room_on_record_as(
    vault: &Vault,
    bind: impl FnOnce(crate::consent::AuthenticatedOwner) -> crate::consent::AuthenticatedOwner,
) -> (Room, OffRecordSession<'_>) {
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
    session
        .flip_on_record_as(&bind(proof))
        .expect("from here on");
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

fn spoken(order: u64) -> SelfCall {
    SelfCall::Speak(SelfSpeechCall::new(
        "the lighthouse key is under the blue stone",
    ))
    .with_bridge_stamp(order, 60_000 + order)
}

fn not_in_room(refused: Option<&Error>, agent: EntityId) -> bool {
    matches!(
        refused,
        Some(Error::OffRecord(OffRecordError::OffRecordNotInRoom { actor_ref, .. }))
            if *actor_ref == agent.to_hex()
    )
}

/// Codex burn engine-prs-01 (P0): the owner removed an agent from a room on
/// record and stayed, saving. The run the agent had bound went on speaking:
/// its next `self.speak` wrote a TURN and a MESSAGE into the owner's vault,
/// because speech checked only the room's mode. A run is bound to the agent
/// it acts as and to its room, and each of its speech, write and read
/// transactions checks the agent is still on the roster, so once removed it
/// leaves nothing more in the room. The saving goes on for everyone else.
#[test]
fn a_run_whose_agent_left_the_room_speaks_writes_and_reads_nothing_more() {
    let (_dir, vault) = open_test_vault();
    let (room, session) = room_on_record(&vault);
    let run = bind_run(&session, &room);
    let storage = ExecutorStorage::for_session(&session, room.agent).expect("bind the storage");
    run.dispatch(spoken(0))
        .expect("the agent speaks in the room");
    let messages = || {
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_MESSAGE)
            .expect("read the messages")
            .len()
    };
    let said = messages();

    vault
        .leave_member(
            room.id,
            room.agent,
            WriteActor::new(room.owner, EdgeActorClass::Human),
            50,
        )
        .expect("the owner removes the agent");
    let members = vault.members(room.id).expect("the roster");
    assert_eq!(members, vec![room.owner], "only the agent left");

    let refused = run.dispatch(spoken(1)).err();
    assert!(not_in_room(refused.as_ref(), room.agent), "{refused:?}");
    let unsaid = crate::code_run::executor_speech_message_id("room-run", 1).expect("message id");
    assert!(vault.get_raw(&unsaid).expect("read the message").is_none());
    assert_eq!(messages(), said, "no MESSAGE after the agent left");

    let id = EntityId::now();
    let refused = run
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id,
            said_in_the_room(&room),
            range(60),
            60,
        )))
        .err();
    assert!(not_in_room(refused.as_ref(), room.agent), "{refused:?}");
    assert!(vault.get_raw(&id).expect("read the claim").is_none());
    let decided = vault
        .gate_decisions(1_000)
        .expect("read the gate decisions")
        .into_iter()
        .filter(|decision| decision.claim_id == Some(*id.as_bytes()))
        .count();
    assert_eq!(decided, 0, "a gate decision landed after the agent left");

    let refused = run
        .dispatch(SelfCall::MemorySearch(SelfMemorySearchCall::new(
            "lighthouse",
            5,
        )))
        .err();
    assert!(not_in_room(refused.as_ref(), room.agent), "{refused:?}");
    let refused = storage.get_code_run_replay_record(&EntityId::now()).err();
    assert!(not_in_room(refused.as_ref(), room.agent), "{refused:?}");

    let rebound = HostSelfDispatcher::for_off_record_session(
        &session,
        WriteActor::new(room.agent, EdgeActorClass::Agent),
        "room-run-again",
    )
    .err();
    assert!(not_in_room(rebound.as_ref(), room.agent), "{rebound:?}");
    assert_eq!(
        session.mode().expect("the stretch's mode"),
        OffRecordMode::OnRecord,
        "the owner's saving stands"
    );
}

/// Codex burn engine-prs-01: the agent's check runs in the transaction that
/// lands its speech, not only before it. A bubble the run had already
/// admitted, waiting for the writer behind the agent's removal, lands
/// nothing.
#[test]
fn a_run_speech_waiting_for_the_writer_lands_nothing_once_its_agent_left() {
    let (_dir, vault) = open_test_vault();
    let (room, session) = room_on_record(&vault);
    let queued = |writes: usize| {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while vault.store.group_commit.queued() < writes {
            assert!(std::time::Instant::now() < deadline, "a write never queued");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    };
    let removal_queued = std::sync::Barrier::new(2);
    let refused = std::thread::scope(|scope| {
        let run = scope.spawn(|| {
            let run = bind_run(&session, &room);
            removal_queued.wait();
            run.dispatch(spoken(0)).err()
        });
        let removal = vault
            .with_write_txn(|_| {
                // The removal queues first, then the bubble, which has made
                // every check it makes before its transaction while the agent
                // was still in the room. The group runs them in that order.
                let removal = scope.spawn(|| {
                    vault.leave_member(
                        room.id,
                        room.agent,
                        WriteActor::new(room.owner, EdgeActorClass::Human),
                        50,
                    )
                });
                queued(1);
                removal_queued.wait();
                queued(2);
                Ok(removal)
            })
            .expect("hold the writer");
        removal
            .join()
            .expect("the removal must not panic")
            .expect("the owner removes the agent");
        run.join().expect("the run must not panic")
    });
    assert!(not_in_room(refused.as_ref(), room.agent), "{refused:?}");
    let unsaid = crate::code_run::executor_speech_message_id("room-run", 0).expect("message id");
    assert!(vault.get_raw(&unsaid).expect("read the message").is_none());
}

/// Sol on engine-prs-01, round 2: a run whose agent was removed still read
/// the room before its check ran, and its refusal told what it read. Its
/// next bubble at an order another member had since taken, or its first
/// bubble at a TURN id someone else's row now held, came back as a broken
/// invariant instead of `NotInRoom`. The check runs first in every read the
/// speech makes, so the refusal is the same whatever the room holds.
#[test]
fn a_removed_agents_run_learns_nothing_of_the_room_from_its_refusal() {
    let (_dir, vault) = open_test_vault();
    let (room, session) = room_on_record(&vault);
    let run = bind_run(&session, &room);
    let fresh = HostSelfDispatcher::for_off_record_session(
        &session,
        WriteActor::new(room.agent, EdgeActorClass::Agent),
        "room-run-fresh",
    )
    .expect("bind a second run");
    run.dispatch(spoken(0))
        .expect("the agent speaks in the room");
    vault
        .leave_member(
            room.id,
            room.agent,
            WriteActor::new(room.owner, EdgeActorClass::Human),
            50,
        )
        .expect("the owner removes the agent");

    // The owner takes order 1 of the run's TURN.
    let turn_id =
        crate::code_run::storage::executor_speech_turn_id("room-run", None).expect("turn id");
    vault
        .memory(room.owner, EdgeActorClass::Human)
        .witness_into_session_as_member(
            &session,
            &crate::memory::WitnessTurn {
                conversation_ref: room.id.to_hex(),
                turn_ref: Some(turn_id.to_hex()),
                messages: vec![crate::memory::WitnessMessage {
                    id: None,
                    author: crate::memory::WitnessAuthor::Companion,
                    message_type: "text".to_owned(),
                    content: "the owner's word at order 1".to_owned(),
                    metadata: None,
                    is_visible: true,
                    order: 1,
                }],
                occurred_at: 70,
            },
            None,
            None,
        )
        .expect("the owner speaks into the run's turn");
    // Someone else's row sits where the fresh run's TURN would go.
    let fresh_turn =
        crate::code_run::storage::executor_speech_turn_id("room-run-fresh", None).expect("turn id");
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &Value::Map(vec![(Value::from("name"), Value::from("Gil"))]),
    )
    .expect("encode the person");
    vault
        .put_entity(
            &fresh_turn,
            crate::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &body,
        )
        .expect("a person at that id");

    let at_a_taken_order = run.dispatch(spoken(1)).err();
    let at_a_taken_turn = fresh.dispatch(spoken(0)).err();
    assert!(
        not_in_room(at_a_taken_order.as_ref(), room.agent)
            && not_in_room(at_a_taken_turn.as_ref(), room.agent),
        "{at_a_taken_order:?} / {at_a_taken_turn:?}"
    );
}

/// Astra on #1406, P2: the write gate read the run's actor row in a
/// transaction of its own, before the room's check. A run whose agent was
/// removed, and then purged from the vault, was told `EntityNotFound`, not
/// `NotInRoom`, so its refusal showed what the owner had done since. The
/// room's check now answers first, at the run's door and in the gate's
/// writer, where the actor's row is read after it.
#[test]
fn a_removed_agents_write_is_refused_alike_once_its_person_is_purged() {
    let (_dir, vault) = open_test_vault();
    let (room, session) = room_on_record(&vault);
    let run = bind_run(&session, &room);
    vault
        .leave_member(
            room.id,
            room.agent,
            WriteActor::new(room.owner, EdgeActorClass::Human),
            50,
        )
        .expect("the owner removes the agent");
    vault
        .delete_entity_with_options(
            &room.agent,
            crate::deletion::DeleteEntityOptions { purge: true },
        )
        .expect("the owner purges the agent");
    assert!(
        vault
            .get_raw(&room.agent)
            .expect("read the agent")
            .is_none(),
        "the agent's PERSON is gone"
    );

    let id = EntityId::now();
    let refused = run
        .dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            id,
            said_in_the_room(&room),
            range(60),
            60,
        )))
        .err();
    assert!(not_in_room(refused.as_ref(), room.agent), "{refused:?}");
    assert!(vault.get_raw(&id).expect("read the claim").is_none());
}

/// Sol on engine-prs-01, round 6: the roster check read a deleted room's
/// membership through the room's body door, which refuses a deleted room
/// with `EntityNotFound`. A run whose agent was removed, and whose room the
/// owner then deleted, was told that, not `NotInRoom`. A deleted room has
/// no one in it, as an absent one has no one.
#[test]
fn a_removed_agents_run_is_refused_alike_once_the_room_is_deleted() {
    let (_dir, vault) = open_test_vault();
    let (room, session) = room_on_record(&vault);
    let run = bind_run(&session, &room);
    let storage = ExecutorStorage::for_session(&session, room.agent).expect("bind the storage");
    vault
        .leave_member(
            room.id,
            room.agent,
            WriteActor::new(room.owner, EdgeActorClass::Human),
            50,
        )
        .expect("the owner removes the agent");
    assert!(
        vault
            .delete_entity(&room.id)
            .expect("the owner deletes the room"),
        "the room existed"
    );

    let refused = [
        run.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            EntityId::now(),
            said_in_the_room(&room),
            range(60),
            60,
        )))
        .err(),
        storage.get_code_run_replay_record(&EntityId::now()).err(),
    ];
    assert!(
        refused
            .iter()
            .all(|refused| not_in_room(refused.as_ref(), room.agent)),
        "{refused:?}"
    );
}

/// Astra on #1406, P2: a base write checked the saver before the run's
/// participant. Once the owner's credential was revoked, a run whose agent
/// had been removed was told `SavingStopped`, with the saver named, and once
/// the saving had stopped, that the room was talk-only: its refusal showed
/// the saver's state. The participant answers first now, whatever the saver
/// or the room's mode, and the saving still stops for everyone else.
#[test]
fn a_removed_agents_run_hears_nothing_of_the_saver() {
    use crate::authority::HostSlipIssuer;

    let (_dir, vault) = open_test_vault();
    let issuer = HostSlipIssuer::from_secret(b"room saver slip fixture").expect("issuer");
    let mut slip_id = None;
    let (room, session) = room_on_record_as(&vault, |proof| {
        let mut claims = vault
            .ensure_host_root_slip(&issuer)
            .expect("root slip")
            .claims;
        claims.slip_id = *blake3::hash(b"room-saver-owner-slip").as_bytes();
        claims.parent_id = None;
        claims.holder_ref = proof.actor().to_hex();
        claims.actor_class = Some("human".into());
        let slip = vault
            .mint_capability_slip(&issuer, claims)
            .expect("the owner's slip");
        slip_id = Some(slip.claims.slip_id);
        let verified = vault
            .verify_capability_slip(
                &issuer.public_key(),
                &slip,
                b"room-saver",
                &issuer
                    .binding_proof(&slip, b"room-saver")
                    .expect("binding proof"),
            )
            .expect("verify the slip");
        vault
            .bind_owner_credential(proof, verified)
            .expect("bind the owner's slip")
    });
    let run = bind_run(&session, &room);
    let storage = ExecutorStorage::for_session(&session, room.agent).expect("bind the storage");
    let note = |name: &str| {
        let raw = format!("{name}: the lighthouse key is under the blue stone");
        let output =
            CodeRunRawOutput::from_bytes(format!("/mnt/outputs/{name}.txt"), raw.as_bytes())
                .expect("raw output");
        storage
            .put_code_run_raw_output(&output, raw.as_bytes())
            .err()
    };
    let put_claim = || {
        run.dispatch(SelfCall::MemoryPutClaim(SelfMemoryPutClaimCall::new(
            EntityId::now(),
            said_in_the_room(&room),
            range(60),
            60,
        )))
        .err()
    };
    vault
        .leave_member(
            room.id,
            room.agent,
            WriteActor::new(room.owner, EdgeActorClass::Human),
            50,
        )
        .expect("the owner removes the agent");
    let refused = note("kept");
    assert!(not_in_room(refused.as_ref(), room.agent), "{refused:?}");

    vault
        .revoke_capability_slip(&issuer, slip_id.expect("the owner's slip"))
        .expect("revoke the owner's slip");
    let refused = [put_claim(), note("revoked")];
    assert!(
        refused
            .iter()
            .all(|refused| not_in_room(refused.as_ref(), room.agent)),
        "{refused:?}"
    );

    // The owner speaks: their landing finds the saving lapsed and stops it.
    vault
        .memory(room.owner, EdgeActorClass::Human)
        .witness_into_session_as_member(
            &session,
            &crate::memory::WitnessTurn {
                conversation_ref: room.id.to_hex(),
                turn_ref: None,
                messages: vec![crate::memory::WitnessMessage {
                    id: None,
                    author: crate::memory::WitnessAuthor::Companion,
                    message_type: "text".to_owned(),
                    content: "the owner's word after the revocation".to_owned(),
                    metadata: None,
                    is_visible: true,
                    order: 0,
                }],
                occurred_at: 70,
            },
            None,
            None,
        )
        .expect("the owner speaks");
    assert_eq!(
        session.mode().expect("the stretch's mode"),
        OffRecordMode::OffRecord,
        "the saving stopped"
    );
    let refused = [put_claim(), note("stopped"), run.dispatch(spoken(1)).err()];
    assert!(
        refused
            .iter()
            .all(|refused| not_in_room(refused.as_ref(), room.agent)),
        "{refused:?}"
    );
}
