//! Reopening a room-wide offer card (OF-530 ruling A): one click from the
//! room's host, once the card has aged out.
//!
//! The party that answers a card reopens it: the room's owner or a delegated
//! host, never its poster for having posted it and never an ordinary member.
//! The same card comes back open, under its id, its join and its publication
//! time, from now: for a day without engagement, or to the fixed deadline the
//! host names, the old one never carried over. Its advisory ballots are
//! cleared. Reopening files no join, lands no turn and launches nothing; the
//! host's answer still proves the join live.
//!
//! The request carries the card's `last_engaged_at` as the host saw it, so a
//! second click on the same card, or one on a card that has moved since,
//! returns the card as it stands and renews nothing.

use serde::{Deserialize, Serialize};

use super::offer_activity::{is_current_in_txn, room_offer_expired};
use super::offers::{OFFERS, OfferCard, OfferState, is_offer_id, join_refused};
use crate::WriteActor;
use crate::error::Error;
use crate::memory::{Memory, MemoryError, MemoryResult};
use crate::workspace_roster::JoinDecision;
use crate::workspace_roster::join_door::require_admission_party_in_txn;
use crate::workspace_roster::join_receipt::JOINS;

/// The host's reopening of one aged-out room-wide card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OfferReopenRequest {
    pub offer_id: String,
    /// The card's `last_engaged_at` as the host saw it aged out.
    pub expected_last_engaged_at: u64,
    /// A new fixed deadline, in Unix seconds; `None` reopens the card for a
    /// day without engagement.
    #[serde(default)]
    pub until: Option<u64>,
}

impl Memory<'_> {
    /// Reopens an aged-out room-wide card as the room's host. See the module
    /// docs.
    pub fn rooms_offer_reopen(&self, request: &OfferReopenRequest) -> MemoryResult<OfferCard> {
        if !is_offer_id(&request.offer_id) {
            return Err(MemoryError::bad_request(
                "offer_id is the 64-hex id rooms.offer returned",
            ));
        }
        let vault = self.vault();
        let caller = WriteActor::new(self.actor(), self.actor_class());
        let card = vault.try_with_write_txn_grouped(|txn| {
            let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
            vault.verify_write_actor_in_txn(txn, &caller)?;
            let mut stored = OFFERS
                .get(&vault.store, txn, &request.offer_id)?
                .ok_or_else(|| MemoryError::not_found("no offer card under this offer_id"))?;
            require_admission_party_in_txn(vault, txn, stored.card.room, caller)?;
            if stored.card.branch.is_some() || !is_current_in_txn(vault, txn, &stored.card)? {
                return Err(MemoryError::bad_request(
                    "only the current room-wide card reopens",
                ));
            }
            let expired = room_offer_expired(&stored.card, now);
            match stored.card.state {
                OfferState::AgedOut => {}
                OfferState::Open { .. } if expired => {}
                // Still open: an earlier click already reopened it.
                OfferState::Open { .. } => return Ok(stored.card),
                OfferState::Joined { .. }
                | OfferState::NotNow { .. }
                | OfferState::Superseded { .. } => {
                    return Err(MemoryError::bad_request(
                        "an answered or replaced offer does not reopen",
                    ));
                }
            }
            if request.expected_last_engaged_at != stored.card.last_engaged_at {
                if expired {
                    stored.card.state = OfferState::AgedOut;
                }
                return Ok(stored.card);
            }
            if stored.answer.is_some() || request.until.is_some_and(|until| until <= now) {
                return Err(MemoryError::bad_request(
                    "a reopened offer is unanswered, and its until a future Unix second",
                ));
            }
            // The card is open on what its join still waits for, as last
            // decided.
            let join = JOINS
                .get(&vault.store, txn, &stored.card.join_ref)?
                .ok_or(Error::CorruptedIndex("offer join receipt"))?;
            let needs = match join.decision {
                JoinDecision::Hold { needs } => needs,
                JoinDecision::Ready => Vec::new(),
                JoinDecision::Refuse(refusal) => return Err(join_refused(&refusal)),
            };
            stored.card.state = OfferState::Open { needs };
            stored.card.until = request.until;
            stored.card.last_engaged_at = now;
            stored.votes.clear();
            stored.reopen_epoch = stored.reopen_epoch.saturating_add(1);
            OFFERS.put(&vault.store, txn, &request.offer_id, &stored)?;
            Ok(stored.card)
        })?;
        // FIX 1794: the reopened card reaches its room's live window.
        #[cfg(feature = "sync")]
        vault.refresh_room_rows_in_live_windows(&[], &[request.offer_id.as_str()]);
        Ok(card)
    }
}
