//! A settled offer card of an erased agent or payer, as stored (FIX 4228):
//! history only.
//!
//! The card keeps its id, its draft digest, its join ref, its state and its
//! times, so the join and the participation facts that name it still find
//! it. Its agent, payer, minter and host read as [`RosterActor`]: no one
//! where the actor was erased. It sits in the card table under its own
//! shape, which no live reader decodes, and no current-card row points at
//! it, so nothing shows, answers, reopens or indexes it again.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::carrier_erase::offer_answer_erased_wins;
use super::offer_settle::{OfferAnswer, RecordedOfferAnswer};
use super::offers::{OfferBallot, OfferState, OfferVoteTally, StoredOffer};
use crate::EntityId;
use crate::deletion::carrier_actor_merged;
use crate::error::{Error, Result};
use crate::run_budget::DeclaredMaximum;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::store::Store;
use crate::workspace_roster::spend_scope::SpendScopeId;
use crate::workspace_roster::{RequiredParty, RosterActor, RosterBindingErase};

/// A settled card's id keys its join's intent and the participation facts
/// its acceptance recorded, so the card of an erased agent or payer stays as
/// history rather than going (FIX 4228; a call).
pub const ACTOR_ERASE_OFFER_BINDING: RosterBindingErase =
    RosterBindingErase::PreserveDigestInertHistory;

/// Every card row as stored: a live card, or one that turned history. Key:
/// the offer id.
pub(super) const OFFER_ROWS: SideTable<String, OfferRow, LegacyJson> =
    SideTable::new(&side_table::ROOMS_OFFER);

/// One card row: the live card every door reads, or its history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum OfferRow {
    Live(StoredOffer),
    History { erased_history: OfferHistory },
}

impl OfferRow {
    /// The room and thread the card was minted for.
    pub(super) fn place(&self) -> (EntityId, Option<EntityId>) {
        match self {
            Self::Live(stored) => (stored.card.room, stored.card.branch),
            Self::History { erased_history } => {
                (erased_history.card.room, erased_history.card.branch)
            }
        }
    }
}

/// The live card filed under `offer_id`, if any. A card that turned
/// history refuses: nothing shows, answers, reopens or replays it again
/// (FIX 4228, 4869).
///
/// # Errors
///
/// Storage errors, a row that cannot be read, or a history row.
pub(super) fn live_offer(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    offer_id: &str,
) -> Result<Option<StoredOffer>> {
    match OFFER_ROWS.get(store, txn, &offer_id.to_owned())? {
        None => Ok(None),
        Some(OfferRow::Live(stored)) => Ok(Some(stored)),
        Some(OfferRow::History { .. }) => Err(Error::InvalidConfig(
            "this offer card named a party that was erased; it is history, and nothing shows, \
             answers, reopens or replays it again"
                .into(),
        )),
    }
}

/// [`super::OfferCard`] as history holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryCard {
    offer_id: String,
    room: EntityId,
    branch: Option<EntityId>,
    agent: RosterActor,
    what: String,
    artifact_ref: Option<String>,
    lease_cap: Option<DeclaredMaximum>,
    payer: Option<RosterActor>,
    spend_scope: Option<SpendScopeId>,
    join_ref: String,
    state: OfferState,
    created_at: u64,
    until: Option<u64>,
    last_engaged_at: u64,
    vote_tally: OfferVoteTally,
}

/// A stored card as history holds it: [`StoredOffer`]'s fields, its agent
/// and payer each a [`RosterActor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OfferHistory {
    card: HistoryCard,
    draft_digest: String,
    minted_by: RosterActor,
    answer: Option<RecordedOfferAnswer>,
    votes: BTreeMap<EntityId, OfferBallot>,
    reopen_epoch: u32,
}

impl OfferHistory {
    /// `stored` as history once each of `erased` was erased: each names no
    /// one, and casts no ballot.
    ///
    /// # Errors
    ///
    /// A card that does not take history's shape, which no stored card is.
    pub(super) fn of(stored: &StoredOffer, erased: &[EntityId]) -> Result<Self> {
        let value = serde_json::to_value(stored)
            .map_err(|_| Error::InvariantViolation("offer card encode"))?;
        let mut history: Self = serde_json::from_value(value)
            .map_err(|_| Error::InvariantViolation("offer history shape"))?;
        for actor in erased {
            history.forget(*actor);
        }
        Ok(history)
    }

    /// Takes `actor` out of every party this history names, and its ballot
    /// out of the card (FIX 4228). Whether it named the actor.
    pub(super) fn forget(&mut self, actor: EntityId) -> bool {
        let mut named = self.card.agent.forget(actor);
        if let Some(payer) = &mut self.card.payer {
            named |= payer.forget(actor);
        }
        named |= self.minted_by.forget(actor);
        if let Some(answer) = &mut self.answer {
            named |= answer.by.forget(actor);
        }
        named |= self.votes.remove(&actor).is_some();
        named
    }
}

/// Two copies of one actor slot as one under carrier equivalence (FIX 4871):
/// erase wins, and two live actors still conflict.
fn merged_actor(ours: RosterActor, theirs: RosterActor) -> Option<RosterActor> {
    carrier_actor_merged(ours, theirs, RosterActor::Erased)
}

/// Two copies of one settled card's history as one (FIX 4871): the union of
/// what each forgot, where each vault erased a different party. Every field
/// but who they name must match, and two live actors in one slot still
/// conflict, as live copies do. Ballots union per voter, and the tally is
/// counted from them, as [`StoredOffer::into_card`] counts a live card's;
/// the latest engagement stands, as `merged_offer` keeps it.
pub(super) fn offer_history_erased_wins(
    ours: &OfferHistory,
    theirs: &OfferHistory,
) -> Option<OfferHistory> {
    let (card, other) = (&ours.card, &theirs.card);
    if card.offer_id != other.offer_id
        || card.room != other.room
        || card.branch != other.branch
        || card.what != other.what
        || card.artifact_ref != other.artifact_ref
        || card.lease_cap != other.lease_cap
        || card.spend_scope != other.spend_scope
        || card.join_ref != other.join_ref
        || card.state != other.state
        || card.created_at != other.created_at
        || card.until != other.until
        || ours.draft_digest != theirs.draft_digest
        || ours.reopen_epoch != theirs.reopen_epoch
    {
        return None;
    }
    let agent = merged_actor(card.agent, other.agent)?;
    let payer = match (&card.payer, &other.payer) {
        (Some(ours), Some(theirs)) => Some(merged_actor(*ours, *theirs)?),
        (None, None) => None,
        _ => return None,
    };
    let mut votes = ours.votes.clone();
    for (voter, ballot) in &theirs.votes {
        match votes.get(voter) {
            None => {
                votes.insert(*voter, *ballot);
            }
            Some(held) if held != ballot => return None,
            Some(_) => {}
        }
    }
    let mut vote_tally = OfferVoteTally::default();
    for ballot in votes.values() {
        match ballot.action {
            OfferAnswer::Join => vote_tally.join += 1,
            OfferAnswer::NotNow => vote_tally.not_now += 1,
        }
    }
    Some(OfferHistory {
        card: HistoryCard {
            offer_id: card.offer_id.clone(),
            room: card.room,
            branch: card.branch,
            agent,
            what: card.what.clone(),
            artifact_ref: card.artifact_ref.clone(),
            lease_cap: card.lease_cap.clone(),
            payer,
            spend_scope: card.spend_scope.clone(),
            join_ref: card.join_ref.clone(),
            state: card.state.clone(),
            created_at: card.created_at,
            until: card.until,
            last_engaged_at: card.last_engaged_at.max(other.last_engaged_at),
            vote_tally,
        },
        draft_digest: ours.draft_digest.clone(),
        minted_by: merged_actor(ours.minted_by, theirs.minted_by)?,
        answer: offer_answer_erased_wins(&ours.answer, &theirs.answer)?,
        votes,
        reopen_epoch: ours.reopen_epoch,
    })
}

/// Whether `stored` names `actor` where only a live party's id can stand
/// (FIX 4228): its agent, its payer, or a party its open card waits on.
pub(super) fn links(stored: &StoredOffer, actor: EntityId) -> bool {
    let card = &stored.card;
    card.agent == actor
        || card.payer == Some(actor)
        || matches!(&card.state, OfferState::Open { needs } if needs.iter().any(|need| match need.party {
            RequiredParty::Subject(subject) => subject.id() == actor,
            RequiredParty::Payer(payer) => payer == actor,
            _ => false,
        }))
}
