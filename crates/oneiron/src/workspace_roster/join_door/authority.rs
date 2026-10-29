//! Who answers for a join, read live (FIX 10223, 10236): the one admission
//! predicate every admission door asks, and the parties and readers a
//! settled join's outcome replays to.

use std::collections::{BTreeMap, BTreeSet};

use super::super::join_consent::{
    ConsentNeed, ConsentState, RequiredParty, SpendConsent, person_of_actor_in_txn,
};
use super::super::join_receipt::JoinReceipt;
use super::{caller_stands_for_in_txn, refused};
use crate::claim::ScopedRead;
use crate::conversation::{RoomRole, room_host_in_txn};
use crate::error::{ClaimError, Error, Result};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use crate::workspace_roster::ProjectEffective;
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};

/// Whether `actor` answers `room`'s admission now: a human who owns the room
/// or holds its delegated host role, or the live leader of the nearest
/// signed project the room sits in (its own project first, then each ring of
/// ancestors from the signed fold), an agent included, where the room's
/// `admission` policy row allows a leader to answer. The leader's granted
/// scope is that project's: a room no project of its leads holds is not its,
/// nor is one whose own project's view reaches past the slice of every ring
/// project it leads. Answering admission grants no payer or membership
/// consent.
pub(in crate::workspace_roster) fn admission_party_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: WriteActor,
) -> Result<bool> {
    if actor.actor_class() == EdgeActorClass::Human
        && room_host_in_txn(vault, txn, room, actor)?.is_some()
    {
        return Ok(true);
    }
    if actor.actor_class() == EdgeActorClass::System
        || nearest_leaders_in(vault, txn, room)?.get(&actor.entity_ref()) != Some(&true)
    {
        return Ok(false);
    }
    let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
    Ok(crate::gate::room_policy_allows(
        &policy,
        room,
        crate::gate::RoomAction::Admission,
        RoomRole::Member,
    ))
}

/// [`admission_party_in_txn`] for the actor a stored answer names, in the
/// class its live entity holds: a PERSON answers as a human, an AGENT_DEF as
/// an agent. Any other entity, or none, answers nothing.
pub(in crate::workspace_roster) fn answering_party_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<bool> {
    let class = match vault.get_entity_type_in_txn(txn, &actor)? {
        Some(ENTITY_TYPE_PERSON) => EdgeActorClass::Human,
        Some(ENTITY_TYPE_AGENT_DEF) => EdgeActorClass::Agent,
        _ => return Ok(false),
    };
    admission_party_in_txn(vault, txn, room, WriteActor::new(actor, class))
}

/// Refuses `caller` unless it answers `room`'s admission
/// ([`admission_party_in_txn`]).
pub(in crate::workspace_roster) fn require_admission_party_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    caller: WriteActor,
) -> Result<()> {
    if !admission_party_in_txn(vault, txn, room, caller)? {
        return Err(refused(
            "only the room's owner, a delegated host or its nearest project leader answers its admission",
        ));
    }
    Ok(())
}

/// The leaders of the nearest ring of signed projects `room` sits in: its
/// own project first, then each ring of ancestors the signed fold names.
/// Each maps to whether the slice of a ring project it leads holds the
/// room's own project's effective view (FIX 11087): a leader's slice that
/// does not cover the room answers nothing there. Empty for a room no
/// project holds, or none of whose projects folds to a signed authority.
fn nearest_leaders_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<BTreeMap<EntityId, bool>> {
    let mut seen: BTreeSet<EntityId> = crate::workspace_roster::room_project_in(vault, txn, room)?
        .into_iter()
        .collect();
    let mut ring: Vec<EntityId> = seen.iter().copied().collect();
    // The first ring is the room's own project alone, so the first view
    // read is the room's.
    let mut room_view: Option<ProjectEffective> = None;
    while !ring.is_empty() {
        let mut leaders = BTreeMap::new();
        let mut next = Vec::new();
        for id in ring {
            let Some((_, effective)) = vault.effective_project_in_txn(txn, id)? else {
                continue;
            };
            let room_view = room_view.get_or_insert_with(|| effective.clone());
            if let Ok(leader) = EntityId::from_hex(&effective.leader) {
                let covers = room_view.slice_fits_under(&effective);
                *leaders.entry(leader).or_insert(false) |= covers;
            }
            for parent in &effective.parents {
                let parent = EntityId::from_hex(parent)?;
                if seen.insert(parent) {
                    next.push(parent);
                }
            }
        }
        if !leaders.is_empty() {
            return Ok(leaders);
        }
        ring = next;
    }
    Ok(BTreeMap::new())
}

/// Refuses `caller` the settled join `receipt`'s outcome, with its payer,
/// spend cap, membership and admission, unless it is a party to the join or
/// reads its room: the subject or its principal, the payer the join names,
/// one that answers its admission now, or a reader standing in its room, or
/// its thread when the join names one. A door's `lane` must read that room
/// and thread too; a transport scope alone reads nothing. A refusal leaves
/// the join as it is.
pub(in crate::workspace_roster) fn require_outcome_reader_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &JoinReceipt,
    caller: WriteActor,
    now: u64,
    lane: Option<&ScopedRead<'_>>,
) -> Result<()> {
    let request = &receipt.request;
    match caller_stands_for_in_txn(vault, txn, caller, &request.subject, now) {
        Ok(_) => return Ok(()),
        Err(Error::Claim(ClaimError::ActorLacksClaimAuthority { .. })) => {}
        Err(error) => return Err(error),
    }
    let person = person_of_actor_in_txn(vault, txn, caller.entity_ref(), now)?;
    if person.is_some_and(|person| names_payer(receipt, person)) {
        return Ok(());
    }
    if admission_party_in_txn(vault, txn, request.room, caller)? {
        return Ok(());
    }
    let mut places = vec![request.room];
    places.extend(request.branch);
    if let Some(lane) = lane
        && lane
            .entities_readable_in_txn(txn, &places)?
            .contains(&false)
    {
        return Err(refused(
            "a join's outcome reads for a party to it or a reader of its room",
        ));
    }
    if stands_in_room_in(vault, txn, receipt, caller.entity_ref(), person)? {
        return Ok(());
    }
    Err(refused(
        "a join's outcome reads for a party to it or a reader of its room",
    ))
}

/// Whether `receipt` names `person` as its payer: the payer whose yes it
/// holds, or the one it waits on.
fn names_payer(receipt: &JoinReceipt, person: EntityId) -> bool {
    match &receipt.consents.spend {
        ConsentState::Granted(SpendConsent::Paid { payer, .. }) => *payer == person,
        ConsentState::Missing(ConsentNeed {
            party: RequiredParty::Payer(payer),
            ..
        }) => *payer == person,
        _ => false,
    }
}

/// Whether `actor`, or its PERSON `person`, stands in the room `receipt`'s
/// join names: a project room's reader, or its thread's when the join names
/// one, and an ordinary room's member, in its thread's audience when the
/// join names one.
fn stands_in_room_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    receipt: &JoinReceipt,
    actor: EntityId,
    person: Option<EntityId>,
) -> Result<bool> {
    let request = &receipt.request;
    if crate::workspace_roster::room_project_in(vault, txn, request.room)?.is_some() {
        let read = match request.branch {
            Some(thread) => crate::workspace_roster::rooms::require_thread_reader(
                vault,
                txn,
                request.room,
                thread,
                actor,
            ),
            None => crate::workspace_roster::rooms::require_reader(vault, txn, request.room, actor),
        };
        return Ok(read.is_ok());
    }
    let members = vault.members_in_txn(txn, request.room)?;
    if !members.contains(&actor) && !person.is_some_and(|person| members.contains(&person)) {
        return Ok(false);
    }
    match request.branch {
        Some(thread) => crate::workspace_roster::record_thread_admits_in(vault, txn, thread, actor),
        None => Ok(true),
    }
}
