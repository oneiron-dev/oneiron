//! Workplace actors join rooms through the OF-531 consents (OF-417 slice 2).
//!
//! The house mind and each member's companion take part in rooms on the
//! same OF-531 decision and receipt as anyone else. A filing here is a plain
//! unpaid `rooms.join`, made only where an authenticated caller that OF-531's
//! caller rule allows is in hand, and its outcome is read, never assumed: a
//! Hold keeps its intent and the parties it waits on, a refusal is final for
//! its intent, and neither is participation. A roster write that seats a
//! person its caller cannot speak for files her an invitation instead, the
//! same join waiting on her own yes. Where no caller is in hand, the subject
//! joins on its own first write. Nothing here seats an agent, edits a roster
//! or caps anyone.

use std::collections::BTreeSet;

use super::join_consent::{
    JoinDecision, JoinRequest, JoinSubject, person_of_actor_in_txn, principal_stands_in_txn,
    require_join_for_branch_in_txn,
};
use super::join_door::{JoinOutcome, rooms_invite_in_txn, rooms_join_in_txn};
use super::join_receipt::JoinReceiptRef;
use crate::error::{ClaimError, Error, Result};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use crate::{EntityId, Vault, WriteActor};

/// Why a workplace filing is made: the purpose its intent key names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// The house mind joins a project home room whose roster seats it.
    House,
    /// A companion follows her principal into a room.
    Companion,
    /// A roster update newly seats a member in a project home room.
    Member,
}

impl Purpose {
    const fn as_str(self) -> &'static str {
        match self {
            Self::House => "workplace.house",
            Self::Companion => "workplace.companion",
            Self::Member => "workplace.member",
        }
    }
}

/// The filing's idempotency key: its purpose, then a digest of the purpose,
/// room and subject, well inside OF-531's 128 printable bytes. The same
/// filing replays its join; the decision is re-proved live on every use.
fn intent_key(purpose: Purpose, room: EntityId, subject: &JoinSubject) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"oneiron.workplace.join.v1");
    hasher.update(purpose.as_str().as_bytes());
    hasher.update(room.as_bytes());
    hasher.update(&[match subject {
        JoinSubject::Person(_) => 1,
        JoinSubject::Agent(_) => 2,
    }]);
    hasher.update(subject.id().as_bytes());
    let digest = hasher.finalize().to_hex();
    format!("{}:{}", purpose.as_str(), &digest[..32])
}

/// The live Ready join `subject` stands on in `room` itself, re-proved now;
/// `None` when it stands on none.
fn standing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    subject: &JoinSubject,
) -> Result<Option<JoinReceiptRef>> {
    match require_join_for_branch_in_txn(vault, txn, room, None, subject, None) {
        Ok(receipt) => Ok(Some(receipt)),
        Err(Error::Claim(ClaimError::ActorLacksClaimAuthority { .. })) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Files `subject`'s unpaid join of `room` for `purpose`, with the
/// authenticated `caller` in hand, in the caller's transaction, and returns
/// the receipt it now stands on. `None` when the join holds or is refused:
/// a held filing keeps its needs for the parties it waits on, and nothing
/// takes part. A subject already standing on a live Ready join of the room
/// keeps it, a paid one above all: an unpaid convenience filing never
/// replaces it. A replayed Ready is stored evidence, so it counts only once
/// re-proved against live facts.
fn file_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    purpose: Purpose,
    room: EntityId,
    subject: JoinSubject,
    caller: WriteActor,
    now: u64,
) -> Result<Option<JoinReceiptRef>> {
    if let Some(receipt) = standing_in_txn(vault, txn, room, &subject)? {
        return Ok(Some(receipt));
    }
    let request = JoinRequest {
        room,
        branch: None,
        subject,
        paid: false,
        spend_scope: None,
        intent_key: intent_key(purpose, room, &subject),
    };
    let outcome = rooms_join_in_txn(vault, txn, &request, caller, now)?;
    // FIX 3321: the filed receipt, held and refused ones too, reaches the
    // live window of its room or thread once this write commits.
    #[cfg(feature = "sync")]
    crate::batch::queue_room_join(vault, txn, &outcome.join_ref);
    if outcome.decision.state != JoinDecision::Ready {
        return Ok(None);
    }
    standing_in_txn(vault, txn, room, &subject)
}

/// Files the house mind's join of a project home room, with the revalidated
/// owner as `caller`: the house is the ORG given a pen, so it takes part as
/// itself, an agent, on institutional standing and the roster seat its
/// project gives it. A house some person stands behind is that person's
/// pen, whose own caller files for it, so none is filed here.
pub(super) fn file_house_join_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    house: EntityId,
    caller: WriteActor,
    now: u64,
) -> Result<Option<JoinReceiptRef>> {
    let subject = super::rooms::join_subject_for_actor_in_txn(vault, txn, house, now)?;
    if !matches!(subject, JoinSubject::Agent(_)) {
        return Ok(None);
    }
    file_in_txn(vault, txn, Purpose::House, room, subject, caller, now)
}

/// Files the join of each workspace house mind that `roster` seats, for the
/// project home room `room`, with the revalidated owner as `caller`. The
/// project's door calls it once its new head and home room are installed.
pub(super) fn file_house_joins_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    roster: &[String],
    caller: WriteActor,
    now: u64,
) -> Result<()> {
    let houses: BTreeSet<EntityId> = super::records::PRESET
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, row)| row.preset.house_actor_ref)
        .filter(|house| roster.contains(&house.to_hex()))
        .collect();
    for house in houses {
        file_house_join_in_txn(vault, txn, room, house, caller, now)?;
    }
    Ok(())
}

/// Files the joins a roster update newly seats, for the project home room
/// `room`, with the authenticated `caller` as filer, and returns the
/// invitations it filed. Each id in `added` is filed as a join where
/// OF-531's caller rule lets `caller` file for it: its own subject, its
/// principal, or a live owner for the vault's own agent. An unrelated person
/// with no live join of the room gets an invitation (OF-417), under a fresh
/// intent per seat-add, since a board write is no one's join consent: it
/// takes effect once she accepts through `rooms.consent`. Any other subject
/// the caller does not stand for (an agent, the house mind under a
/// non-owner) is left to its own filing or its owner's join. A seated house
/// mind files as the house; a person whose filing stands brings her
/// companions along. A seat that is neither a PERSON nor an AGENT_DEF takes
/// part in no room.
pub(super) fn file_roster_joins_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    added: &BTreeSet<String>,
    caller: WriteActor,
    now: u64,
) -> Result<Vec<JoinOutcome>> {
    let houses: BTreeSet<EntityId> = super::records::PRESET
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(_, row)| row.preset.house_actor_ref)
        .collect();
    // A PERSON and her pen are one subject, filed once.
    let mut subjects: Vec<JoinSubject> = Vec::new();
    for seat in added {
        let actor = EntityId::from_hex(seat)?;
        if !matches!(
            vault.get_entity_type_in_txn(txn, &actor)?,
            Some(ENTITY_TYPE_PERSON | ENTITY_TYPE_AGENT_DEF)
        ) {
            continue;
        }
        let subject = super::rooms::join_subject_for_actor_in_txn(vault, txn, actor, now)?;
        if !subjects.contains(&subject) {
            subjects.push(subject);
        }
    }
    let mut invitations = Vec::new();
    for subject in subjects {
        if !roster_caller_files_for_in_txn(vault, txn, caller, &subject, now)? {
            if matches!(subject, JoinSubject::Person(_))
                && standing_in_txn(vault, txn, room, &subject)?.is_none()
            {
                let request = JoinRequest {
                    room,
                    branch: None,
                    subject,
                    paid: false,
                    spend_scope: None,
                    intent_key: format!("invite:{}", vault.store.clock.entity_id()?.to_hex()),
                };
                invitations.push(rooms_invite_in_txn(vault, txn, &request, caller, now)?);
            }
            continue;
        }
        let purpose = match subject {
            JoinSubject::Agent(agent) if houses.contains(&agent) => Purpose::House,
            _ => Purpose::Member,
        };
        let receipt = file_in_txn(vault, txn, purpose, room, subject, caller, now)?;
        if let (JoinSubject::Person(person), Some(_)) = (subject, receipt) {
            file_companion_joins_in_txn(vault, txn, room, person, caller, now)?;
        }
    }
    Ok(invitations)
}

/// Whether `caller` files `subject`'s join on a roster update: OF-531's
/// caller rule, read live. A caller that does not stand for the subject
/// files no join for it, so a board write is never an unrelated person's
/// join consent: a person gets an invitation she answers herself.
fn roster_caller_files_for_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: WriteActor,
    subject: &JoinSubject,
    at: u64,
) -> Result<bool> {
    match super::join_door::caller_stands_for_in_txn(vault, txn, caller, subject, at) {
        Ok(_) => Ok(true),
        Err(Error::Claim(ClaimError::ActorLacksClaimAuthority { .. })) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Whether `caller` speaks for `person`: it is that PERSON, or its own pen.
fn speaks_for_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    caller: WriteActor,
    person: EntityId,
    at: u64,
) -> Result<bool> {
    let me = caller.entity_ref();
    Ok(me == person || person_of_actor_in_txn(vault, txn, me, at)? == Some(person))
}

/// Files `principal`'s companions into `room`, with `caller` as filer. Only
/// when `caller` speaks for the principal (OF-531's caller rule for a
/// companion), and never when the principal is itself a companion: a
/// companion follows her member, not another companion. Each companion is
/// admitted through her principal's live standing, decided again on every
/// use, so none is filed where the principal's join gave it no standing to
/// attend through (a host's yes into a home room seats no one). A companion
/// whose PERSON is not live yet is left to join later.
pub(super) fn file_companion_joins_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    principal: EntityId,
    caller: WriteActor,
    now: u64,
) -> Result<()> {
    if !speaks_for_in_txn(vault, txn, caller, principal, now)?
        || super::codec::companion_principal_in_txn(vault, txn, principal)?.is_some()
        || !principal_stands_in_txn(vault, txn, room, principal, now)?
    {
        return Ok(());
    }
    for companion in super::codec::companions_of_in_txn(vault, txn, principal)? {
        if !crate::consent::person_is_live_in_txn(vault, txn, &companion)? {
            continue;
        }
        file_in_txn(
            vault,
            txn,
            Purpose::Companion,
            room,
            JoinSubject::Person(companion),
            caller,
            now,
        )?;
    }
    Ok(())
}

/// Files `companion`'s join of every room `principal` stands in now, when
/// her onboarding completes. Only when `caller` speaks for the principal or
/// for the companion herself: an admin who onboards a member files for no
/// one, and the companion then joins on her own first write. A room that
/// does not read as a live room (a quarantined project's home) admits no
/// one through her principal.
pub(super) fn file_companion_rooms_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    principal: EntityId,
    companion: EntityId,
    caller: WriteActor,
    now: u64,
) -> Result<()> {
    if !(speaks_for_in_txn(vault, txn, caller, principal, now)?
        || speaks_for_in_txn(vault, txn, caller, companion, now)?)
        || super::codec::companion_principal_in_txn(vault, txn, companion)? != Some(principal)
        || super::codec::companion_principal_in_txn(vault, txn, principal)?.is_some()
        || !crate::consent::person_is_live_in_txn(vault, txn, &companion)?
    {
        return Ok(());
    }
    let mut rooms = Vec::new();
    for row in vault
        .store
        .type_index
        .prefix_iter(txn, &[crate::registry::ENTITY_TYPE_CONVERSATION])?
    {
        let (key, _) = row?;
        let id: [u8; 16] = key[1..]
            .try_into()
            .map_err(|_| Error::CorruptedIndex("conversation type index key"))?;
        rooms.push(EntityId::from_bytes(id)?);
    }
    for room in rooms {
        if !crate::vault::live_entity_row_in_txn(&vault.store, txn, &room)?.is_live()
            || !matches!(
                principal_stands_in_txn(vault, txn, room, principal, now),
                Ok(true)
            )
        {
            continue;
        }
        file_in_txn(
            vault,
            txn,
            Purpose::Companion,
            room,
            JoinSubject::Person(companion),
            caller,
            now,
        )?;
    }
    Ok(())
}
