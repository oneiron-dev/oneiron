//! Subject, spend and room admission consent.
//! Entry: `admission_in_txn`.
//! Consent vocabulary and `Loaded` stay in `join_consent`.

use super::*;

/// The subject's own consent: the latest answer the subject, or its
/// principal for it, recorded. A direct join carries it from its filing; an
/// invitation waits on it, and a no refuses the invitation for its intent.
/// A yes the erased actor gave proves nothing: the join waits on it again.
pub(super) fn subject_consent(
    request: &JoinRequest,
    answers: &[RecordedAnswer],
) -> Loaded<RosterActor> {
    let need = ConsentNeed {
        part: ConsentPart::Subject,
        party: RequiredParty::Subject(request.subject),
    };
    match latest(answers, ConsentPart::Subject).filter(|answer| answer.by.is(request.subject.id()))
    {
        Some(answer) if !answer.grant => Loaded::denied(answer),
        Some(answer) if answer.actor.id().is_some() => Loaded::granted(answer.actor),
        _ => Loaded::missing(need),
    }
}

/// The payer's consent. Paid work runs only under a scope whose root a payer
/// funds, and only once that payer said yes to this join for that scope.
pub(super) fn spend_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &JoinRequest,
    answers: &[RecordedAnswer],
) -> Result<Loaded<SpendConsent>> {
    if !request.paid {
        return Ok(Loaded::granted(SpendConsent::NoPaidWork));
    }
    let unknown = ConsentNeed {
        part: ConsentPart::Spend,
        party: RequiredParty::PayerUnknown,
    };
    let answer = latest(answers, ConsentPart::Spend);
    if let Some(answer) = answer
        && !answer.grant
    {
        return Ok(Loaded::denied(answer));
    }
    // A payer's yes names the scope it funds; else the request names one.
    let Some(scope) = answer
        .and_then(|answer| answer.spend_scope.clone())
        .or_else(|| request.spend_scope.clone())
    else {
        return Ok(Loaded::missing(unknown));
    };
    let Some((row, root)) = AgentDispatcher::new(vault).scope_with_root_in_txn(txn, &scope)? else {
        return Ok(Loaded::refused(
            unknown,
            JoinRefusal::UnknownSpendScope { scope },
        ));
    };
    let Some(payer) = root.payer else {
        return Ok(Loaded::missing(unknown));
    };
    let named = ConsentNeed {
        part: ConsentPart::Spend,
        party: RequiredParty::Payer(payer.party),
    };
    if !payer_binds_in_txn(vault, txn, &payer)? {
        return Ok(Loaded::refused(named, JoinRefusal::ForgedPayer { scope }));
    }
    // A closed tree spends nothing more: its payer is asked again.
    if row.state != SpendState::Open || root.state != SpendState::Open {
        return Ok(Loaded::missing(named));
    }
    // The payer's own yes to this join, for this scope, from an actor not
    // erased. A cap is no consent.
    let Some(yes) = answer.filter(|answer| {
        answer.by.is(payer.party)
            && answer.actor.id().is_some()
            && answer.spend_scope.as_ref() == Some(&scope)
    }) else {
        return Ok(Loaded::missing(named));
    };
    Ok(Loaded::granted(SpendConsent::Paid {
        payer: payer.party,
        granted_by: yes.actor,
        scope,
        unit: root.unit,
        cap_units: root.cap_units,
        at_ms: payer.at_ms,
    }))
}

/// Whether the request names a live room, and a thread of that room by its
/// root (FIX 2019) whose audience holds its subject: a private thread (FIX
/// 2951) admits no join, and its Ready re-proves none, for anyone else, and
/// reads to them as an unknown thread.
pub(super) fn room_holds_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &JoinRequest,
) -> Result<bool> {
    if vault.get_entity_type_in_txn(txn, &request.room)? != Some(ENTITY_TYPE_CONVERSATION)
        || !crate::vault::live_entity_row_in_txn(&vault.store, txn, &request.room)?.is_live()
    {
        return Ok(false);
    }
    let Some(branch) = request.branch else {
        return Ok(true);
    };
    // An erased thread root keeps its stored turn as topology for its
    // replies, so the stored turn alone admits no join to it.
    if branch == request.room
        || !crate::vault::live_entity_row_in_txn(&vault.store, txn, &branch)?.is_live()
    {
        return Ok(false);
    }
    // FIX 2019: a join names a thread by its root, the first turn every
    // reply's join and receipt keys by, never a reply inside it or a trunk
    // record: an erased root's sweep then reaches every join filed there.
    let held = match super::rooms::TURNS.get(&vault.store, txn, &branch)? {
        Some(turn) => turn.room_id == request.room.to_hex() && super::rooms::is_thread_root(&turn),
        None => {
            crate::conversation_dag::erased_thread_room_in_txn(&vault.store, txn, &branch)?
                == Some(request.room)
        }
    };
    if !held {
        return Ok(false);
    }
    match super::rooms::thread_audience_allows_in(
        vault,
        txn,
        request.room,
        branch,
        request.subject.id(),
    ) {
        Ok(allowed) => Ok(allowed),
        Err(Error::EntityNotFound) => Ok(false),
        Err(error) => Err(error),
    }
}

/// A project home room's project and effective seats; `None` for any other
/// room.
pub(in crate::workspace_roster) fn home_room_seats_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<Option<(EntityId, Vec<String>)>> {
    // The stored body, not only the auxiliary marker, identifies the
    // substrate, as the room audience reads it.
    let body = crate::conversation::body_in(vault, txn, room)?;
    if !body.extra.contains_key("project_id")
        && !body.extra.contains_key("memberIds")
        && !super::project::ROOM_PROJECT.contains(&vault.store, txn, &room)?
    {
        return Ok(None);
    }
    let room = super::rooms::room_in(vault, txn, room)?;
    Ok(Some((
        EntityId::from_hex(&room.project_id)?,
        room.member_ids,
    )))
}

/// Whether a home room's effective seats hold `subject`. An agent sits by
/// its own id. A person sits by its PERSON, or by any seat that takes part
/// as that person (its own pen: an AGENT_DEF whose live PERSON anchor names
/// it), resolved by OF-529's one resolver. The signed roster is only read.
pub(super) fn seats_hold_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    seats: &[String],
    subject: &JoinSubject,
    at: u64,
) -> Result<bool> {
    if seats.contains(&subject.id().to_hex()) {
        return Ok(true);
    }
    let JoinSubject::Person(person) = *subject else {
        return Ok(false);
    };
    for seat in seats {
        let seat = EntityId::from_hex(seat)?;
        if vault.get_entity_type_in_txn(txn, &seat)? == Some(ENTITY_TYPE_AGENT_DEF)
            && super::rooms::join_subject_for_actor_in_txn(vault, txn, seat, at)?
                == JoinSubject::Person(person)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The room's admission. Addressing, a task assignment, a claim or presence
/// is never admission. `membership` is this decision's own membership part:
/// a companion is admitted through her principal only while it reads
/// [`MembershipConsent::CompanionOfMember`] for her.
pub(super) fn admission_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    request: &JoinRequest,
    answers: &[RecordedAnswer],
    membership: &ConsentState<MembershipConsent>,
    now: u64,
) -> Result<Loaded<AdmissionConsent>> {
    let need = ConsentNeed {
        part: ConsentPart::Admission,
        party: RequiredParty::RoomHost { room: request.room },
    };
    if !room_holds_in_txn(vault, txn, request)? {
        return Ok(Loaded::refused(need, JoinRefusal::UnknownRoom));
    }
    let admitted = |granted_by, basis| {
        Loaded::granted(AdmissionConsent {
            room: request.room,
            branch: request.branch,
            subject: request.subject,
            granted_by: RosterActor::Actor(granted_by),
            basis,
        })
    };
    if let Some(answer) = latest(answers, ConsentPart::Admission) {
        if !answer.grant {
            return Ok(Loaded::denied(answer));
        }
        // A host's yes stands while that host still holds the room; an
        // erased host's holds nothing.
        if let (Some(actor), Some(by)) = (answer.actor.id(), answer.by.id())
            && room_host_in_txn(
                vault,
                txn,
                request.room,
                WriteActor::new(actor, EdgeActorClass::Human),
            )?
            .is_some()
        {
            return Ok(admitted(
                by,
                AdmissionBasis::HostAnswer {
                    answer_ref: answer.answer_ref.clone(),
                },
            ));
        }
    }
    if let JoinSubject::Person(person) = request.subject {
        let own = WriteActor::new(person, EdgeActorClass::Human);
        match room_host_in_txn(vault, txn, request.room, own)? {
            Some(RoomHost::Owner) => return Ok(admitted(person, AdmissionBasis::RoomOwner)),
            Some(RoomHost::Delegate) => return Ok(admitted(person, AdmissionBasis::DelegatedHost)),
            None => {}
        }
    }
    if let Some((project, seats)) = home_room_seats_in_txn(vault, txn, request.room)?
        && seats_hold_in_txn(vault, txn, &seats, &request.subject, now)?
    {
        return Ok(admitted(project, AdmissionBasis::StandingHomeRoster));
    }
    // A companion is her member's pen: she attends the rooms her member
    // attends, never on standing of her own and never for a non-companion.
    if let JoinSubject::Person(person) = request.subject
        && let ConsentState::Granted(MembershipConsent::CompanionOfMember {
            companion,
            principal,
            ..
        }) = membership
        && *companion == person
        && principal_stands_in_txn(vault, txn, request.room, *principal, now)?
    {
        return Ok(admitted(
            *principal,
            AdmissionBasis::ThroughPrincipal {
                principal: *principal,
            },
        ));
    }
    Ok(Loaded::missing(need))
}
