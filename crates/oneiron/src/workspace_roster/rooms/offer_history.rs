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

use super::offer_settle::RecordedOfferAnswer;
use super::offers::{OfferBallot, OfferState, OfferVoteTally, StoredOffer};
use crate::EntityId;
use crate::agent_dispatch::SpendScopeId;
use crate::error::{Error, Result};
use crate::llm::run_admission::DeclaredMaximum;
use crate::side_table::{self, LegacyJson, SideTable};
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
