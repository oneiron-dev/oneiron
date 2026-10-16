//! Workplace actors join rooms through the three consents (OF-417 slice 2).
//!
//! The house mind and each member's companion take part in rooms on the
//! same OF-531 decision and receipt as anyone else. A filing here is a plain
//! unpaid `rooms.join`, made only where an authenticated caller that OF-531's
//! caller rule allows is in hand, and its outcome is read, never assumed: a
//! Hold keeps its intent and the parties it waits on, a refusal is final for
//! its intent, and neither is participation. Where no such caller is in hand,
//! the subject joins on its own first write instead. Nothing here seats an
//! agent, edits a roster or caps anyone.

use std::collections::BTreeSet;

use super::join_consent::{
    JoinDecision, JoinRequest, JoinSubject, person_of_actor_in_txn, principal_stands_in_txn,
    require_join_for_branch_in_txn,
};
use super::join_door::rooms_join_in_txn;
use super::join_receipt::JoinReceiptRef;
use crate::error::{ClaimError, Error, Result};
use crate::{EntityId, Vault, WriteActor};

/// Why a workplace filing is made: the purpose its intent key names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// The house mind joins a project home room whose roster seats it.
    House,
    /// A companion follows her principal into a room.
    Companion,
}

impl Purpose {
    const fn as_str(self) -> &'static str {
        match self {
            Self::House => "workplace.house",
            Self::Companion => "workplace.companion",
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
