//! Participation standing, admission and speech guards.
//! Entry: `admit_participation_in_txn`.
//! Fact, claimant and admitted-result types stay in `participation`.

use super::*;

/// The one rule for which Ready receipt covers a thread (OF-529). A thread
/// takes the receipt filed for it, or the one filed for its room: a room's
/// receipt covers each thread that reads as its room does. A private thread
/// (FIX 2951) is the exception: a subject off its audience stands on no
/// receipt there, the room's or the thread's, and nothing else is checked.
/// A thread's receipt never covers the room or another thread. Each receipt
/// is re-proved live by OF-531's exact-key check.
pub(crate) fn require_join_covering_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    subject: &JoinSubject,
    scope: Option<&SpendScopeId>,
) -> Result<JoinReceiptRef> {
    if let Some(thread) = branch {
        // A root not stored yet is the one this write births, whose
        // audience its own door checks; an erased one is refused there.
        match super::audience::thread_audience_allows_in(vault, txn, room, thread, subject.id()) {
            Ok(true) | Err(Error::EntityNotFound) => {}
            Ok(false) => {
                return Err(lacks(
                    "the subject has no Ready join in this room or thread",
                ));
            }
            Err(error) => return Err(error),
        }
        if let Some(receipt) = joined(require_join_for_branch_in_txn(
            vault, txn, room, branch, subject, scope,
        ))? {
            return Ok(receipt);
        }
    }
    require_join_for_branch_in_txn(vault, txn, room, None, subject, scope)
}

/// Refuses `actor` off the audience of `room`'s private thread `branch`
/// (FIX 2951), before any seat, receipt or host standing is read: none of
/// them stands in for it. A thread hidden from `actor` refuses as an
/// unknown one does.
pub(in crate::workspace_roster::rooms) fn require_thread_audience_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    actor: EntityId,
) -> Result<()> {
    match branch {
        Some(thread) => {
            super::audience::require_thread_audience_in(vault, txn, room, thread, actor)
        }
        None => Ok(()),
    }
}

/// A receipt check's answer, with "not joined" as `None`.
pub(in crate::workspace_roster::rooms) fn joined(
    proved: Result<JoinReceiptRef>,
) -> Result<Option<JoinReceiptRef>> {
    match proved {
        Ok(receipt) => Ok(Some(receipt)),
        Err(Error::Claim(ClaimError::ActorLacksClaimAuthority { .. })) => Ok(None),
        Err(error) => Err(error),
    }
}

/// `agent`'s standing in `room`, or its thread `branch`: a Ready receipt
/// that covers it, or the seat a project roster already gives it. Paid work
/// (`scope`) stands only on a receipt carrying its payer's consent.
pub(crate) fn agent_standing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    agent: EntityId,
    scope: Option<&SpendScopeId>,
) -> Result<Option<AgentStanding>> {
    if scope.is_none()
        && vault
            .room_audience_members_in_txn(txn, room)?
            .contains(&agent)
    {
        return Ok(Some(AgentStanding::Seat));
    }
    Ok(joined(require_join_covering_in_txn(
        vault,
        txn,
        room,
        branch,
        &JoinSubject::Agent(agent),
        scope,
    ))?
    .map(AgentStanding::Receipt))
}

/// A person's standing in `room`, or its thread `branch`, now: a project
/// home room's seat, an ordinary room's ledger seat or host role, or a live
/// Ready join for the PERSON that covers the place (OF-417: a home room's
/// join seats no one, and a companion's stands on her principal's standing,
/// both re-proved here). `actor` is the pen it acts through, when that is
/// not the PERSON itself. `None` for a home room whose roster does not seat
/// it and where it holds no Ready join.
pub(crate) fn person_standing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    person: EntityId,
    actor: Option<EntityId>,
) -> Result<Option<bool>> {
    let ids = || std::iter::once(person).chain(actor);
    let unseated = if let Some((_, seats)) = home_room_seats_in_txn(vault, txn, room)? {
        if ids().any(|id| seats.contains(&id.to_hex())) {
            return Ok(Some(true));
        }
        None
    } else {
        let members = vault.members_in_txn(txn, room)?;
        let own = WriteActor::new(person, EdgeActorClass::Human);
        if ids().any(|id| members.contains(&id))
            || crate::conversation::room_host_in_txn(vault, txn, room, own)?.is_some()
        {
            return Ok(Some(true));
        }
        Some(false)
    };
    let subject = JoinSubject::Person(person);
    let receipt = require_join_covering_in_txn(vault, txn, room, branch, &subject, None);
    if joined(receipt)?.is_some() {
        return Ok(Some(true));
    }
    Ok(unseated)
}

/// Whether `actor`, taking part as `subject`, stands as a person in `room`,
/// or its thread `branch`: [`person_standing_in_txn`] for its PERSON through
/// this pen. `false` for an agent, or an actor that takes part in no room.
pub(in crate::workspace_roster::rooms) fn person_stands_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    actor: EntityId,
    subject: Option<JoinSubject>,
) -> Result<bool> {
    let Some(JoinSubject::Person(person)) = subject else {
        return Ok(false);
    };
    let pen = (person != actor).then_some(actor);
    Ok(person_standing_in_txn(vault, txn, room, branch, person, pen)? == Some(true))
}

/// The one gate both write paths (a live DAG append, a room witness) call
/// before they write; the caller records the fact after its write, in the
/// same transaction, with [`Admitted::record_in_txn`].
///
/// A person with standing (its seat, or a live Ready join) writes on, and
/// its write is its thread join. A person with no standing files an OF-531
/// join for the room in this transaction, for nothing paid: Ready seats it
/// in an ordinary room, or in a project home room commits a receipt and
/// never a roster seat (only its board seats anyone), and the write goes
/// on; a held join refuses the write with the parties it waits on, and a
/// refused one refuses it. An agent never joins by writing: its write
/// records nothing here, and its speech, claims and reads stand on
/// [`agent_standing_in_txn`]. A write is no authority for an agent either
/// (ARCH-0006a, ruled 2026-09-23): it must stand there now and be spoken to
/// for the turn the write `answers`, by [`agent_spoken_to_in_txn`]. For any
/// other cause an agent must stand there now.
#[expect(
    clippy::too_many_arguments,
    reason = "the place, the writer, its cause, what it answers and paid scope, and the decision time"
)]
pub(crate) fn admit_participation_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    actor: WriteActor,
    cause: JoinCause,
    answers: Option<EntityId>,
    scope: Option<&SpendScopeId>,
    now: u64,
) -> Result<Admitted> {
    // A private thread is written by its audience alone (FIX 2951), checked
    // before any standing or join. The write that births its root is
    // checked where its audience is stamped.
    if !matches!(cause, JoinCause::Wrote { turn } if Some(turn) == branch) {
        require_thread_audience_in(vault, txn, room, branch, actor.entity_ref())?;
    }
    let mut admitted = Admitted {
        room,
        branch,
        subject: None,
        cause,
        join_ref: None,
    };
    let Some(subject) = participant_in_txn(vault, txn, actor.entity_ref(), now)? else {
        return Ok(admitted);
    };
    let writes = matches!(admitted.cause, JoinCause::Wrote { .. });
    match subject {
        JoinSubject::Agent(agent) => {
            let standing = agent_standing_in_txn(vault, txn, room, branch, agent, scope)?
                .ok_or_else(|| lacks("the agent has no Ready join in this room or thread"))?;
            if let JoinCause::Wrote { turn } = admitted.cause {
                if !agent_spoken_to_in_txn(vault, txn, room, branch, agent, turn, answers)? {
                    return Err(lacks(
                        "an agent speaks only when it is addressed, holds a task there, or lands an accepted offer",
                    ));
                }
                // Its write is no join, so it records no fact.
                return Ok(admitted);
            }
            admitted.join_ref = standing.receipt().cloned();
        }
        JoinSubject::Person(person) => {
            let pen = (person != actor.entity_ref()).then_some(actor.entity_ref());
            match person_standing_in_txn(vault, txn, room, branch, person, pen)? {
                Some(true) => {}
                Some(false) | None if writes => {
                    admitted.join_ref =
                        Some(write_join_in_txn(vault, txn, room, person, actor, now)?);
                }
                Some(false) => return Err(lacks("the person has no standing in this room")),
                None => {
                    return Err(lacks(
                        "the person has no seat or Ready join in this home room",
                    ));
                }
            }
        }
    }
    admitted.subject = Some(subject);
    Ok(admitted)
}

/// Whether `agent` is spoken to for the turn `record` it writes in `room`,
/// or its thread `branch` (ARCH-0006a, ruled 2026-09-23: an agent speaks
/// only when it is addressed or holds a task there, and asks in by an offer
/// card): it is named on the room turn `answers`, holds that turn's open
/// thread TASK, or `record` is the turn an accepted offer bound to it.
/// Standing alone never lets an agent speak, and none of these grants a
/// seat or mints a task.
pub(super) fn agent_spoken_to_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    agent: EntityId,
    record: EntityId,
    answers: Option<EntityId>,
) -> Result<bool> {
    if super::offers::accepts_offer_in_txn(vault, txn, room, branch, agent, record)? {
        return Ok(true);
    }
    let Some(answered) = answers else {
        return Ok(false);
    };
    let Some(turn) = super::TURNS.get(&vault.store, txn, &answered)? else {
        return Ok(false);
    };
    if turn.room_id != room.to_hex() {
        return Ok(false);
    }
    Ok(turn.addressed_agents.contains(&agent.to_hex())
        || held_thread_task_in_txn(vault, txn, &turn, agent)?.is_some())
}

/// Files the room join a person's first write in a room needs, in the
/// write's transaction, for nothing paid. Its intent key is the room and
/// the person, so `vault.rooms.join` with the same key files the same join
/// and holds it for the parties it waits on.
pub(super) fn write_join_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    person: EntityId,
    caller: WriteActor,
    now: u64,
) -> Result<JoinReceiptRef> {
    let request = JoinRequest {
        room,
        branch: None,
        subject: JoinSubject::Person(person),
        paid: false,
        spend_scope: None,
        intent_key: format!("write:{}:{}", room.to_hex(), person.to_hex()),
    };
    let outcome = rooms_join_in_txn(vault, txn, &request, caller, now)?;
    // FIX 3321: the receipt reaches the live window of its room once the
    // write commits; a held or refused join aborts it, and nothing travels.
    #[cfg(feature = "sync")]
    crate::batch::queue_room_join(vault, txn, &outcome.join_ref);
    match &outcome.decision.state {
        JoinDecision::Ready => JoinReceiptRef::parse(
            outcome
                .receipt_ref
                .as_deref()
                .ok_or(Error::CorruptedIndex("a Ready join has no receipt"))?,
        ),
        JoinDecision::Hold { needs } => Err(Error::Record(RecordError::RoomJoinHeld(Box::new(
            RoomJoinHold {
                room,
                person,
                intent_key: request.intent_key.clone(),
                needs: needs.clone(),
            },
        )))),
        JoinDecision::Refuse(refusal) => Err(Error::Record(RecordError::RoomJoinRefused {
            refusal: json(refusal)?,
        })),
    }
}

/// A join decision's typed parts, as the refusal carries them.
pub(super) fn json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| Error::InvariantViolation("join decision encode"))
}

pub(super) fn lacks(reason: &'static str) -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority { reason })
}

/// The speech door for a room turn: OF-528's for a seated speaker. A speaker
/// standing on a receipt has no seat, so it passes on speaking as a persona
/// (a live PERSON, or an enabled and active AGENT_DEF), never as upkeep.
pub(in crate::workspace_roster::rooms) fn admit_speech_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
    standing: Option<&AgentStanding>,
) -> Result<()> {
    match standing {
        Some(AgentStanding::Receipt(_)) => {
            if super::hosting::eligible_room_speaker_in(vault, txn, actor)? {
                Ok(())
            } else {
                Err(Error::Record(RecordError::RoomSpeakerIneligible { actor }))
            }
        }
        _ => super::hosting::admit_room_speech_in(vault, txn, room, actor),
    }
}

/// Whether `actor` may be named in a room it has no seat in: an agent that
/// speaks as a persona. Naming enrolls no one and reveals nothing; the agent
/// still claims and speaks only on a Ready receipt.
pub(in crate::workspace_roster::rooms) fn addressable_agent_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    at: u64,
) -> Result<bool> {
    Ok(matches!(
        participant_in_txn(vault, txn, actor, at)?,
        Some(JoinSubject::Agent(_))
    ) && super::hosting::eligible_room_speaker_in(vault, txn, actor)?)
}

/// Records `Addressed { turn }` for each agent named on `turn` that stands
/// on a Ready receipt for its thread or room now. An agent named without one
/// is recorded when its claim on the turn passes, never on the naming alone.
pub(in crate::workspace_roster::rooms) fn record_addressed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    turn: EntityId,
    addressed: &BTreeSet<String>,
    at: u64,
) -> Result<()> {
    for named in addressed {
        let named = EntityId::from_hex(named)?;
        let Some(subject @ JoinSubject::Agent(_)) = participant_in_txn(vault, txn, named, at)?
        else {
            continue;
        };
        let Some(receipt) = joined(require_join_covering_in_txn(
            vault, txn, room, branch, &subject, None,
        ))?
        else {
            continue;
        };
        record_participation_in_txn(
            vault,
            txn,
            room,
            branch,
            &subject,
            &JoinCause::Addressed { turn },
            Some(&receipt),
            at,
        )?;
    }
    Ok(())
}

/// The speech precheck before a witness (OF-529): for a person, its seat or
/// a Ready receipt for the thread its reply lands in, or for the room
/// (OF-417); for an agent, the same on its own receipt. The witness
/// transaction decides again.
pub(in crate::workspace_roster::rooms) fn require_speaker_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    input: &WitnessTurn,
    actor: EntityId,
) -> Result<()> {
    let now = vault.store.clock.now_recorded_at();
    let subject = participant_in_txn(vault, txn, actor, now)?;
    if subject.is_none() {
        require_member(vault, txn, room, actor)?;
        return Ok(());
    }
    room_in(vault, txn, room)?;
    let parent = input
        .messages
        .iter()
        .filter_map(|message| message.metadata.as_ref()?.get("room_reply_to")?.as_str())
        .find_map(|parent| EntityId::from_hex(parent).ok());
    let branch = match parent {
        Some(parent) => turn_root_in_txn(vault, txn, &turn_in(vault, txn, parent)?)?,
        None => None,
    };
    let Some(JoinSubject::Agent(agent)) = subject else {
        if !person_stands_in_txn(vault, txn, room, branch, actor, subject)? {
            require_member(vault, txn, room, actor)?;
        }
        return Ok(());
    };
    agent_standing_in_txn(vault, txn, room, branch, agent, None)?.ok_or_else(invalid)?;
    Ok(())
}
