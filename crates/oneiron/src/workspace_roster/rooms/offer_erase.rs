//! An erased actor out of the offer cards (FIX 3520).
//!
//! A card keeps its row, its state, its join and its times, and names no
//! one where it named the actor. An open card whose join waits on the actor
//! goes with that join, which the join's own erase deletes
//! ([`crate::workspace_roster::ACTOR_ERASE_PENDING_JOIN`]).

use super::offer_history::{ACTOR_ERASE_OFFER_BINDING, OFFER_ROWS, OfferHistory, OfferRow, links};
use super::offers::{OFFER_CURRENT, OFFERS, OfferState, StoredOffer, current_key};
use crate::error::Result;
use crate::store::Store;
use crate::workspace_roster::join_receipt::names_no_actor;
use crate::workspace_roster::{
    ACTOR_ERASE_PENDING_JOIN, JoinRequest, RosterBindingErase, RosterErase,
};
use crate::{EntityId, Vault};

/// The intent key an offer card files its agent's join under, before the
/// card's id.
const OFFER_JOIN_INTENT: &str = "offer:";

/// Erasing `actor` from the offer cards (FIX 3520): each card keeps its row,
/// its state, its join and its times, and names no one where the actor
/// minted it or answered it as the room's host. A ballot the actor cast
/// leaves the card: it was one voter's advisory word, it decided nothing,
/// and the tally counts no one who is gone. A card whose agent or payer is
/// the actor (FIX 4228) goes while it is open, as its join does
/// ([`ACTOR_ERASE_PENDING_JOIN`]), and once settled turns history, as
/// [`ACTOR_ERASE_OFFER_BINDING`] says; either way no current-card row
/// points at it. A history row takes the actor out too. One-way, in the
/// erase's own transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a card row that cannot be read.
pub(crate) fn erase_offer_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let store = &vault.store;
    let mut erased = Vec::new();
    let mut histories = Vec::new();
    let mut doomed = Vec::new();
    let mut current = Vec::new();
    for (offer_id, row) in OFFER_ROWS.scan(store, wtxn)? {
        let mut stored = match row {
            OfferRow::Live(stored) => stored,
            OfferRow::History { mut erased_history } => {
                if erased_history.forget(*actor) {
                    histories.push((offer_id, erased_history));
                }
                continue;
            }
        };
        if !links(&stored, *actor) {
            if stored.forget(*actor) {
                erased.push((offer_id, stored));
            }
            continue;
        }
        let card = &stored.card;
        let key = current_key(card.room, card.branch, card.agent);
        // A current row keyed by the erased agent goes whatever it points
        // at; another agent's goes when it points at this card.
        let only = (card.agent != *actor).then(|| offer_id.clone());
        let keep = if matches!(card.state, OfferState::Open { .. }) {
            ACTOR_ERASE_PENDING_JOIN == RosterErase::Keep
        } else {
            ACTOR_ERASE_OFFER_BINDING == RosterBindingErase::PreserveDigestInertHistory
        };
        current.push((key, only));
        if keep {
            histories.push((offer_id, OfferHistory::of(&stored, &[*actor])?));
        } else {
            doomed.push(offer_id);
        }
    }
    for (offer_id, stored) in &erased {
        OFFERS.put(store, wtxn, offer_id, stored)?;
    }
    for (offer_id, erased_history) in histories {
        OFFER_ROWS.put(
            store,
            wtxn,
            &offer_id,
            &OfferRow::History { erased_history },
        )?;
    }
    for offer_id in &doomed {
        OFFERS.delete(store, wtxn, offer_id)?;
    }
    for (key, only) in &current {
        if only.is_none() || OFFER_CURRENT.get(store, wtxn, key)?.as_ref() == only.as_ref() {
            OFFER_CURRENT.delete(store, wtxn, key)?;
        }
    }
    Ok(())
}

impl StoredOffer {
    /// Takes `actor` out of who minted or answered this card, and its
    /// ballot out of it (FIX 3520). Whether it named the actor.
    pub(super) fn forget(&mut self, actor: EntityId) -> bool {
        let mut named = self.minted_by.forget(actor);
        if let Some(answer) = &mut self.answer {
            named |= answer.by.forget(actor);
        }
        named |= self.votes.remove(&actor).is_some();
        named
    }
}

/// Deletes the open card that filed `request`, the join `join_ref` names,
/// and its current-card row when it points at the card: an actor's erase
/// deleted that join (FIX 3520), so no answer can settle the card. A card in
/// any other state keeps its row.
pub(in crate::workspace_roster) fn drop_open_offer_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    join_ref: &str,
    request: &JoinRequest,
) -> Result<()> {
    let Some(offer_id) = request.intent_key.strip_prefix(OFFER_JOIN_INTENT) else {
        return Ok(());
    };
    let offer_id = offer_id.to_owned();
    // A card that turned history is settled (FIX 4228).
    let Some(OfferRow::Live(stored)) = OFFER_ROWS.get(store, txn, &offer_id)? else {
        return Ok(());
    };
    let card = &stored.card;
    if card.join_ref != join_ref || !matches!(card.state, OfferState::Open { .. }) {
        return Ok(());
    }
    OFFERS.delete(store, txn, &offer_id)?;
    let key = current_key(card.room, card.branch, card.agent);
    if OFFER_CURRENT.get(store, txn, &key)?.as_deref() == Some(offer_id.as_str()) {
        OFFER_CURRENT.delete(store, txn, &key)?;
    }
    Ok(())
}
