//! A room side row as this vault takes it from a carrier (FIX 4227, 4228):
//! another machine's copy, a window's, or a recovery artifact's.
//!
//! Each actor this vault erased, as its own hard-delete marker reads
//! ([`crate::deletion::ACTOR_ERASE_CARRIER_SOURCE`]), reads as no one in the
//! carried copy and in the one this vault holds, as the erase took it out of
//! this vault's own rows. A host pin of an erased agent stays gone, a join no
//! one settled and an open card that wait on an erased party stay gone, a
//! settled join or card that names one by id takes its history form, and a
//! participation fact of an erased subject takes the key that names no one.
//! What is left merges as live copies merge, who they name settling by
//! [`crate::deletion::ACTOR_ERASE_CARRIER_MERGE`]. That is carrier
//! equivalence, never a proof, a replay or an answer.

use std::collections::BTreeSet;

use serde::Serialize;

use super::fact_subject::{
    ACTOR_ERASE_PARTICIPATION_KEY, FactSubject, ParticipationKeyErase, move_subject_facts_in_txn,
};
use super::hosting::{ACTOR_ERASE_HOST_PIN, HostPin};
use super::offer_history::{
    ACTOR_ERASE_OFFER_BINDING, OFFER_ROWS, OfferHistory, OfferRow, links as offer_links,
};
use super::offer_settle::RecordedOfferAnswer;
use super::offers::{OFFER_CURRENT, OfferState, StoredOffer, current_key};
use super::participation::{FACTS, FactKey};
use super::replica::{RoomSideRow, SideMerge, TurnMergeRefusal};
use crate::deletion::carrier_actor_merged;
use crate::error::Result;
use crate::side_table::{LegacyJson, SideTable};
use crate::workspace_roster::join_history::{
    ACTOR_ERASE_JOIN_BINDING, JOIN_ROWS, JoinHistory, JoinRow, links as join_links,
};
use crate::workspace_roster::join_receipt::{READY, ready_key};
use crate::workspace_roster::{
    ACTOR_ERASE_PENDING_JOIN, ConsentState, JoinDecision, JoinReceipt, JoinRefusal, RecordedAnswer,
    RosterActor, RosterBindingErase, RosterErase, SpendConsent,
};
use crate::{EntityId, Vault};

/// Every id `row` spells, in its keys and its values: among them each actor
/// it names, which [`erased_among`] reads against this vault's markers.
fn spelled_ids<T: Serialize>(row: &T) -> BTreeSet<EntityId> {
    let mut ids = BTreeSet::new();
    if let Ok(value) = serde_json::to_value(row) {
        spell(&value, &mut ids);
    }
    ids
}

fn spell(value: &serde_json::Value, ids: &mut BTreeSet<EntityId>) {
    match value {
        serde_json::Value::String(text) => spelled_into(text, ids),
        serde_json::Value::Array(items) => {
            for item in items {
                spell(item, ids);
            }
        }
        serde_json::Value::Object(fields) => {
            for (key, item) in fields {
                spelled_into(key, ids);
                spell(item, ids);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn spelled_into(text: &str, ids: &mut BTreeSet<EntityId>) {
    if let Ok(id) = EntityId::from_hex(text)
        && id.to_hex() == text
    {
        ids.insert(id);
    }
}

/// The ids `row` spells that this vault erased.
fn erased_among<T: Serialize>(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &T,
) -> Result<Vec<EntityId>> {
    let mut erased = Vec::new();
    for id in spelled_ids(row) {
        if vault.carrier_actor_erased_in_txn(txn, &id)? {
            erased.push(id);
        }
    }
    Ok(erased)
}

/// A carried host pin as this vault takes it: naming no one who pinned it
/// once this vault erased them, or `None` when this vault erased its agent,
/// whose pin that erase deleted ([`ACTOR_ERASE_HOST_PIN`]).
pub(super) fn carried_pin(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pin: &HostPin,
) -> Result<Option<HostPin>> {
    if ACTOR_ERASE_HOST_PIN == RosterErase::Delete
        && vault.carrier_actor_erased_in_txn(txn, &pin.agent)?
    {
        return Ok(None);
    }
    let mut pin = pin.clone();
    if let RosterActor::Actor(by) = pin.by
        && vault.carrier_actor_erased_in_txn(txn, &by)?
    {
        pin.by = RosterActor::Erased;
    }
    Ok(Some(pin))
}

/// The key this vault files a carried participation fact under: its live
/// key, or once this vault erased its subject the key that names no one,
/// where a fact this vault still holds under the live key moves too. `None`
/// when such a fact goes ([`ACTOR_ERASE_PARTICIPATION_KEY`]).
pub(super) fn carried_fact_key_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: FactKey,
) -> Result<Option<FactKey>> {
    let FactSubject::Live(subject) = key.subject else {
        return Ok(Some(key));
    };
    if !vault.carrier_actor_erased_in_txn(txn, &subject.id())? {
        return Ok(Some(key));
    }
    if let Some(held) = FACTS.get_lenient(&vault.store, txn, &key)? {
        move_subject_facts_in_txn(vault, txn, subject.id(), vec![(key, held)])?;
    }
    Ok(
        (ACTOR_ERASE_PARTICIPATION_KEY == ParticipationKeyErase::OpaqueHistoricalKey)
            .then(|| key.erased()),
    )
}

/// An index row a live copy kept that its history form must not: the key,
/// and the ref it must point at to go, or `None` when it goes whatever it
/// points at, because the key names the erased actor.
struct IndexRow {
    key: String,
    only: Option<String>,
}

/// One copy of a join or card as this vault knows it.
enum Form<L, H> {
    /// Live, naming no one this vault erased.
    Live(L),
    /// Its history form, with the index row the live copy kept.
    History(H, IndexRow),
    /// Gone with an erase: a join no one settled, or a card, that waits on
    /// an erased party.
    Gone,
}

fn join_form(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    mut receipt: JoinReceipt,
) -> Result<Form<JoinReceipt, JoinHistory>> {
    let erased = erased_among(vault, txn, &receipt)?;
    let links = erased.iter().any(|actor| join_links(&receipt, *actor));
    if !receipt.is_settled() {
        if ACTOR_ERASE_PENDING_JOIN == RosterErase::Delete
            && (links || erased.iter().any(|actor| receipt.waits_on(*actor)))
        {
            return Ok(Form::Gone);
        }
    } else if links {
        if ACTOR_ERASE_JOIN_BINDING == RosterBindingErase::Delete {
            return Ok(Form::Gone);
        }
        let request = &receipt.request;
        let index = IndexRow {
            key: ready_key(request.room, &request.subject, request.branch),
            only: (!erased.contains(&request.subject.id())).then(|| receipt.join_ref.clone()),
        };
        return Ok(Form::History(JoinHistory::of(&receipt, &erased)?, index));
    }
    for actor in &erased {
        receipt.forget(*actor);
    }
    Ok(Form::Live(receipt))
}

fn offer_form(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    mut stored: StoredOffer,
) -> Result<Form<StoredOffer, OfferHistory>> {
    let erased = erased_among(vault, txn, &stored)?;
    if erased.iter().any(|actor| offer_links(&stored, *actor)) {
        let keep = if matches!(stored.card.state, OfferState::Open { .. }) {
            ACTOR_ERASE_PENDING_JOIN == RosterErase::Keep
        } else {
            ACTOR_ERASE_OFFER_BINDING == RosterBindingErase::PreserveDigestInertHistory
        };
        if !keep {
            return Ok(Form::Gone);
        }
        let card = &stored.card;
        let index = IndexRow {
            key: current_key(card.room, card.branch, card.agent),
            only: (!erased.contains(&card.agent)).then(|| card.offer_id.clone()),
        };
        return Ok(Form::History(OfferHistory::of(&stored, &erased)?, index));
    }
    for actor in &erased {
        stored.forget(*actor);
    }
    Ok(Form::Live(stored))
}

/// A carried join or card with the copy this vault holds, as this vault
/// knows them.
pub(super) enum SharedHere {
    /// Both live, each naming no one this vault erased, to merge as live
    /// copies merge. `changed` says the held copy is not as stored.
    Live {
        carried: RoomSideRow,
        held: Option<RoomSideRow>,
        changed: bool,
    },
    /// Settled here, since one of them waits on or names by id an actor
    /// this vault erased.
    Settled(SideMerge),
}

/// [`SharedHere`] for a carried join or card `row`: the held one is read in
/// both its forms. A history form either copy takes is written here, and
/// the index row its live form kept goes.
pub(super) fn shared_here(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    row: &RoomSideRow,
) -> Result<SharedHere> {
    match row {
        RoomSideRow::Join { receipt } => {
            let carried = join_form(vault, txn, receipt.clone())?;
            let held = match JOIN_ROWS.get_lenient(&vault.store, txn, &receipt.join_ref)? {
                None => None,
                Some(JoinRow::Live(held)) => {
                    let stored = held.clone();
                    Some(match join_form(vault, txn, held)? {
                        Form::Live(held) => (held != stored, Form::Live(held)),
                        form => (true, form),
                    })
                }
                Some(JoinRow::History { mut erased_history }) => {
                    let mut changed = false;
                    for actor in erased_among(vault, txn, &erased_history)? {
                        changed |= erased_history.forget(actor);
                    }
                    Some((changed, Form::History(erased_history, IndexRow::none())))
                }
            };
            settle(
                carried,
                held,
                |carried| RoomSideRow::Join { receipt: carried },
                |txn, history, index| {
                    JOIN_ROWS.put(
                        &vault.store,
                        txn,
                        &receipt.join_ref,
                        &JoinRow::History {
                            erased_history: history,
                        },
                    )?;
                    drop_index_row(vault, txn, READY, &index)
                },
                txn,
            )
        }
        RoomSideRow::Offer { offer } => {
            let carried = offer_form(vault, txn, offer.clone())?;
            let held = match OFFER_ROWS.get_lenient(&vault.store, txn, &offer.card.offer_id)? {
                None => None,
                Some(OfferRow::Live(held)) => {
                    let stored = held.clone();
                    Some(match offer_form(vault, txn, held)? {
                        Form::Live(held) => (held != stored, Form::Live(held)),
                        form => (true, form),
                    })
                }
                Some(OfferRow::History { mut erased_history }) => {
                    let mut changed = false;
                    for actor in erased_among(vault, txn, &erased_history)? {
                        changed |= erased_history.forget(actor);
                    }
                    Some((changed, Form::History(erased_history, IndexRow::none())))
                }
            };
            settle(
                carried,
                held,
                |carried| RoomSideRow::Offer { offer: carried },
                |txn, history, index| {
                    OFFER_ROWS.put(
                        &vault.store,
                        txn,
                        &offer.card.offer_id,
                        &OfferRow::History {
                            erased_history: history,
                        },
                    )?;
                    drop_index_row(vault, txn, OFFER_CURRENT, &index)
                },
                txn,
            )
        }
        _ => Ok(SharedHere::Settled(SideMerge::Refused(
            TurnMergeRefusal::InvalidIds,
        ))),
    }
}

impl IndexRow {
    /// No index row: a stored history form keeps none.
    const fn none() -> Self {
        Self {
            key: String::new(),
            only: Some(String::new()),
        }
    }
}

/// Settles the carried copy's form against the held one's (`changed` when
/// the held one is not as stored). A history form is written by `write`
/// with the index row its live form kept.
fn settle<L, H: PartialEq>(
    carried: Form<L, H>,
    held: Option<(bool, Form<L, H>)>,
    live: impl Fn(L) -> RoomSideRow,
    write: impl FnOnce(&mut heed::RwTxn<'_>, H, IndexRow) -> Result<()>,
    txn: &mut heed::RwTxn<'_>,
) -> Result<SharedHere> {
    let refused = |reason: TurnMergeRefusal| -> Result<SharedHere> {
        Ok(SharedHere::Settled(SideMerge::Refused(reason)))
    };
    match (carried, held) {
        (Form::Gone, _) | (_, Some((_, Form::Gone))) => refused(TurnMergeRefusal::ActorErased),
        (Form::Live(carried), None) => Ok(SharedHere::Live {
            carried: live(carried),
            held: None,
            changed: false,
        }),
        (Form::Live(carried), Some((changed, Form::Live(held)))) => Ok(SharedHere::Live {
            carried: live(carried),
            held: Some(live(held)),
            changed,
        }),
        (Form::History(carried, index), None) => {
            write(txn, carried, index)?;
            Ok(SharedHere::Settled(SideMerge::Written))
        }
        (Form::History(carried, index), Some((changed, Form::History(held, held_index)))) => {
            if carried != held {
                return refused(TurnMergeRefusal::FixedFieldsConflict);
            }
            if !changed {
                return Ok(SharedHere::Settled(SideMerge::Held));
            }
            // The held copy turned history here: its own index row goes.
            let index = if held_index.key.is_empty() {
                index
            } else {
                held_index
            };
            write(txn, held, index)?;
            Ok(SharedHere::Settled(SideMerge::Written))
        }
        (Form::History(..), Some((_, Form::Live(_))))
        | (Form::Live(_), Some((_, Form::History(..)))) => {
            refused(TurnMergeRefusal::FixedFieldsConflict)
        }
    }
}

/// Deletes `index`'s row of `table` (the Ready or the current-card index)
/// when it points where `index` says.
fn drop_index_row(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    table: SideTable<String, String, LegacyJson>,
    index: &IndexRow,
) -> Result<()> {
    if index.key.is_empty() {
        return Ok(());
    }
    let held = table.get(&vault.store, txn, &index.key)?;
    if index.only.is_none() || held.as_ref() == index.only.as_ref() {
        table.delete(&vault.store, txn, &index.key)?;
    }
    Ok(())
}

/// Two copies of one join answer as one: the answer that stands, or `None`
/// when they differ but for who they name.
pub(super) fn answer_erased_wins(
    ours: &RecordedAnswer,
    theirs: &RecordedAnswer,
) -> Option<RecordedAnswer> {
    let by = carrier_actor_merged(ours.by, theirs.by, RosterActor::Erased)?;
    let actor = carrier_actor_merged(ours.actor, theirs.actor, RosterActor::Erased)?;
    let merged = RecordedAnswer {
        by,
        actor,
        ..ours.clone()
    };
    let other = RecordedAnswer {
        by,
        actor,
        ..theirs.clone()
    };
    (merged == other).then_some(merged)
}

/// Two copies of one card's answer as one, as [`answer_erased_wins`].
pub(super) fn offer_answer_erased_wins(
    ours: &Option<RecordedOfferAnswer>,
    theirs: &Option<RecordedOfferAnswer>,
) -> Option<Option<RecordedOfferAnswer>> {
    match (ours, theirs) {
        (Some(ours), Some(theirs)) => {
            let by = carrier_actor_merged(ours.by, theirs.by, RosterActor::Erased)?;
            let merged = RecordedOfferAnswer { by, ..ours.clone() };
            let other = RecordedOfferAnswer {
                by,
                ..theirs.clone()
            };
            (merged == other).then_some(Some(merged))
        }
        (None, None) => Some(None),
        _ => None,
    }
}

/// Makes `ours` no one where `theirs`, the same slot of the other copy,
/// names no one: erase wins.
fn erase_with(ours: &mut RosterActor, theirs: RosterActor) {
    if carrier_actor_merged(*ours, theirs, RosterActor::Erased) == Some(RosterActor::Erased) {
        *ours = RosterActor::Erased;
    }
}

fn denial_with<T>(ours: &mut ConsentState<T>, theirs: &ConsentState<T>) {
    if let (ConsentState::Denied(ours), ConsentState::Denied(theirs)) = (ours, theirs) {
        erase_with(&mut ours.party, theirs.party);
    }
}

/// The join `merged`, chosen of two copies, naming no one in each slot the
/// other copy, `other`, names no one in (FIX 4227): its filer, its
/// principal, and who gave or refused each consent where both copies hold
/// it alike.
pub(super) fn join_erased_with(merged: &mut JoinReceipt, other: &JoinReceipt) {
    erase_with(&mut merged.filed_by, other.filed_by);
    if let (Some(ours), Some(theirs)) = (&mut merged.principal, other.principal) {
        erase_with(ours, theirs);
    }
    let (ours, theirs) = (&mut merged.consents, &other.consents);
    if let (ConsentState::Granted(ours), ConsentState::Granted(theirs)) =
        (&mut ours.subject, &theirs.subject)
    {
        erase_with(ours, *theirs);
    }
    if let (
        ConsentState::Granted(SpendConsent::Paid { granted_by, .. }),
        ConsentState::Granted(SpendConsent::Paid {
            granted_by: theirs, ..
        }),
    ) = (&mut ours.spend, &theirs.spend)
    {
        erase_with(granted_by, *theirs);
    }
    if let (ConsentState::Granted(ours), ConsentState::Granted(theirs)) =
        (&mut ours.admission, &theirs.admission)
    {
        erase_with(&mut ours.granted_by, theirs.granted_by);
    }
    denial_with(&mut ours.subject, &theirs.subject);
    denial_with(&mut ours.spend, &theirs.spend);
    denial_with(&mut ours.membership, &theirs.membership);
    denial_with(&mut ours.admission, &theirs.admission);
    if let (
        JoinDecision::Refuse(JoinRefusal::Denied { party, .. }),
        JoinDecision::Refuse(JoinRefusal::Denied { party: theirs, .. }),
    ) = (&mut merged.decision, &other.decision)
    {
        erase_with(party, *theirs);
    }
}

/// `row` as a window carries it once this vault erased an actor it names
/// (FIX 4227, 4228): `None` when it names none, `Some(None)` when it leaves
/// the window, else the row naming no one there under the same key. A host
/// pin of an erased agent, a participation fact of an erased subject, a
/// join or card that waits on or names one by id leave: this vault keeps
/// the pin deleted, the fact under the key that names no one and the join
/// or card gone or as history, and no window carries those. A platform
/// handle, a claim and a response are not carriers this reads.
///
/// # Errors
///
/// Storage errors.
#[cfg(feature = "sync")]
pub(crate) fn erased_side_row_here(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    row: &RoomSideRow,
) -> Result<Option<Option<RoomSideRow>>> {
    if matches!(
        row,
        RoomSideRow::Handle { .. } | RoomSideRow::Claim { .. } | RoomSideRow::Response { .. }
    ) {
        return Ok(None);
    }
    let erased = erased_among(vault, txn, row)?;
    if erased.is_empty() {
        return Ok(None);
    }
    Ok(match row {
        RoomSideRow::HostPin { room, pin } => {
            carried_pin(vault, txn, pin)?.map_or(Some(None), |carried| {
                (carried != *pin).then_some(Some(RoomSideRow::HostPin {
                    room: *room,
                    pin: carried,
                }))
            })
        }
        RoomSideRow::Participation { subject, .. } => {
            erased.contains(&subject.id()).then_some(None)
        }
        RoomSideRow::Join { receipt } => match join_form(vault, txn, receipt.clone())? {
            Form::Live(carried) => {
                (carried != *receipt).then_some(Some(RoomSideRow::Join { receipt: carried }))
            }
            Form::History(..) | Form::Gone => Some(None),
        },
        RoomSideRow::Offer { offer } => match offer_form(vault, txn, offer.clone())? {
            Form::Live(carried) => {
                (carried != *offer).then_some(Some(RoomSideRow::Offer { offer: carried }))
            }
            Form::History(..) | Form::Gone => Some(None),
        },
        RoomSideRow::Handle { .. } | RoomSideRow::Claim { .. } | RoomSideRow::Response { .. } => {
            None
        }
    })
}
