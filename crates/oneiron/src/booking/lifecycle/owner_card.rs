//! The owner's same-day booking card (ARCH-0062:155 "every booking surfaces
//! to the owner as an inbox card same-day"; RULING INB-05-OWNER-CARD = A):
//! one INBOX row per booking committed or cancelled since the start of the
//! owner's day, for the vault's live owners. Nothing here is stored
//! (ARCH-0063:178, "a way of LOOKING"): the rows are read from each
//! booking's own lifecycle heads whenever the lens reads.
//!
//! The owner's day is the booking's host's day: the IANA zone its
//! confirmation froze for its first host, else UTC (the vault keeps no zone
//! of its own). A row stands from the commit or the cancel until that day
//! ends. A move keeps the booking's row and its time: it commits nothing and
//! cancels nothing.
//!
//! The card offers the owner's existing cancel and reschedule doors and no
//! new one: the emergency door (`Memory::record_emergency_instruction`, then
//! its plan and execute) over the booking's own slot, with `cancel` to cancel
//! it and `request_update` to keep it and ask the visitor to pick another
//! slot. The visitor's token doors (`vault.booking.cancel`, `.reschedule`)
//! take the visitor's bearer token, which the vault keeps only as a digest.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::authorship::counts_in_txn;
use super::claim::read_booking_facts;
use super::occurrence::inclusive_occurrence;
use super::storage::decode_claim_value;
use super::types::{
    BOOKING_BOOKER_CONTACT_PREDICATE, BOOKING_STATUS_PREDICATE, BookingBookerContactValue,
    BookingStatus, BookingStatusValue,
};
use crate::agent_inbox_lens::AgentInboxLensItem;
use crate::booking::BookingError;
use crate::booking::emergency_reschedule::EmergencyActionPolicy;
use crate::calendar::claims::{CalendarStatus, PREDICATE_CALENDAR_STATUS, decode_status_value};
use crate::calendar::query::CalendarRangeDto;
use crate::calendar::utc_to_wall;
use crate::claim::ClaimSubject;
use crate::error::Result;
use crate::inbox::view_values::{AgentInboxItemKind, AgentInboxParticipant, InboxImpact};
use crate::registry::ENTITY_TYPE_EVENT;
use crate::{EntityId, Vault};

/// The prefix of a booking card's INBOX item id; the booking's EVENT hex
/// follows it. The EVENT keeps its id through every move, so the row does.
pub const BOOKING_OWNER_CARD_ITEM_PREFIX: &str = "booking:";

/// A booking card is an update, as a meeting's prep pack is: the booking
/// stands, and nothing waits on the owner.
const BOOKING_OWNER_CARD_INBOX_IMPACT: u16 = 50;

/// The card one booking row carries, as the owner reads it when the row is
/// opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookingOwnerCard {
    /// The booking's EVENT, hex.
    pub event_ref: String,
    /// Who booked: the identity the visitor's PERSON row carries (an
    /// address). `None` when that row names no one.
    pub visitor: Option<String>,
    /// The event type the visitor booked.
    pub event_type: String,
    /// The booked slot's start, Unix seconds.
    pub start_utc: u64,
    /// The booked slot's end, Unix seconds, exclusive.
    pub end_utc: u64,
    /// The booking page the booking came from, hex.
    pub source_page: String,
    /// What the booking is now. A calendar provider's cancellation cancels
    /// it too, though it need not change the booking's own status (FIX 22385).
    pub status: BookingStatus,
    /// When the booking was committed, or when it was cancelled.
    pub recorded_at: u64,
    /// The owner's doors the card offers: cancel and reschedule over this
    /// booking's slot, while it stands confirmed and has not started; none
    /// on a cancelled or started booking.
    pub offers: Vec<BookingOwnerCardOffer>,
}

/// One door a booking card offers: the input of the owner's emergency door
/// (`Memory::record_emergency_instruction`, then its plan and execute) for
/// this booking alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookingOwnerCardOffer {
    /// `cancel` cancels the booking; `request_update` keeps it at its slot
    /// and asks the visitor to pick another.
    pub action_policy: EmergencyActionPolicy,
    /// The window the door takes: the booking's own slot, inclusive.
    pub affected_window: CalendarRangeDto,
}

/// Each booking committed or cancelled since the start of its owner's day as
/// an INBOX row for the vault's live owners (kind CoordinationUpdate, so
/// "Updates"): item id `booking:<event hex>`, the EVENT hex as its payload,
/// at the commit or the cancel. A vault with no live owner makes no row.
/// Never folded into a thread.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn booking_owner_card_inbox_items(vault: &Vault) -> Result<Vec<AgentInboxLensItem>> {
    let now = vault.now_recorded_at();
    let rtxn = vault.store.env.read_txn()?;
    let mut events = BTreeSet::new();
    vault.for_each_readable_claim_with_predicate_in_txn(
        &rtxn,
        BOOKING_STATUS_PREDICATE,
        |_, body| {
            if let ClaimSubject::Entity(event) = body.subject {
                events.insert(event);
            }
            Ok(())
        },
    )?;
    if events.is_empty() {
        return Ok(Vec::new());
    }
    let owners = crate::policy_model::owners_in_txn(vault, &rtxn)?;
    let Some(&actor_ref) = owners.first() else {
        return Ok(Vec::new());
    };
    let participants: Vec<AgentInboxParticipant> = owners
        .iter()
        .map(|&owner| AgentInboxParticipant {
            identity_ref: None,
            actor_ref: owner,
        })
        .collect();
    let mut items = Vec::new();
    for event_ref in events {
        let Some((card, zone)) = card_in_txn(vault, &rtxn, &event_ref, now)? else {
            continue;
        };
        if !same_owner_day(card.recorded_at, now, zone.as_deref()) {
            continue;
        }
        items.push(AgentInboxLensItem {
            item_id: format!("{BOOKING_OWNER_CARD_ITEM_PREFIX}{}", card.event_ref),
            kind: AgentInboxItemKind::CoordinationUpdate,
            thread_ref: None,
            identity_ref: None,
            actor_ref,
            facet_ref: None,
            participants: participants.clone(),
            impact: InboxImpact(BOOKING_OWNER_CARD_INBOX_IMPACT),
            occurred_at: card.recorded_at,
            receipt_ref: None,
            payload_ref: Some(card.event_ref),
            approval_digest: None,
            concern: None,
            diary_review: None,
            sender: None,
            widening: None,
        });
    }
    Ok(items)
}

/// The card the INBOX row `item_id` carries, read now; `None` for a row that
/// is no booking card, or for a booking that no longer reads as one.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn booking_owner_card_of_item(
    vault: &Vault,
    item_id: &str,
) -> Result<Option<BookingOwnerCard>> {
    let Some(event_ref) = item_id
        .strip_prefix(BOOKING_OWNER_CARD_ITEM_PREFIX)
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(None);
    };
    let now = vault.now_recorded_at();
    let rtxn = vault.store.env.read_txn()?;
    Ok(card_in_txn(vault, &rtxn, &event_ref, now)?.map(|(card, _)| card))
}

/// `event_ref`'s card at `now` and the zone of its owner's day, read in one
/// snapshot; `None` for an EVENT that is not a live booking the booking
/// process holds settled.
fn card_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
    now: u64,
) -> Result<Option<(BookingOwnerCard, Option<String>)>> {
    if !matches!(
        crate::vault::live_entity_row_in_txn(&vault.store, rtxn, event_ref)?,
        crate::vault::LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_EVENT,
            ..
        }
    ) {
        return Ok(None);
    }
    let facts = match read_booking_facts(vault, rtxn, event_ref) {
        Ok(facts) => facts,
        // A head that waits on its owner's confirm, or a missing lifecycle
        // claim: no settled booking to show.
        Err(BookingError::InvalidConstraint(_)) => return Ok(None),
        Err(error) => {
            tracing::warn!(%error, "booking not read; its owner card is left out");
            return Ok(None);
        }
    };
    let status = facts.effective_status();
    let heads = lifecycle_heads_in_txn(vault, rtxn, event_ref, status)?;
    let Some(recorded_at) = heads.recorded_at else {
        return Ok(None);
    };
    let visitor = match heads.booker {
        Some(contact) => {
            crate::booking::invite_grant::booker_identity_in_txn(vault, rtxn, &contact)
                .ok()
                .flatten()
        }
        None => None,
    };
    let offers = match inclusive_occurrence(facts.slot) {
        Ok(window) if status == BookingStatus::Confirmed && facts.slot.start > now => [
            EmergencyActionPolicy::Cancel,
            EmergencyActionPolicy::RequestUpdate,
        ]
        .into_iter()
        .map(|action_policy| BookingOwnerCardOffer {
            action_policy,
            affected_window: CalendarRangeDto {
                start: window.start,
                end: window.end,
            },
        })
        .collect(),
        _ => Vec::new(),
    };
    let zone = facts
        .context
        .as_ref()
        .and_then(|context| context.host_zones.first().cloned());
    let card = BookingOwnerCard {
        event_ref: event_ref.to_hex(),
        visitor,
        event_type: facts.event_type.0,
        start_utc: facts.slot.start,
        end_utc: facts.slot.end,
        source_page: facts.page_ref.to_hex(),
        status,
        recorded_at,
        offers,
    };
    Ok(Some((card, zone)))
}

/// What one booking's counted heads say beside its facts.
struct LifecycleHeads {
    /// When the booking became `status`: its newest counted `booking.status`
    /// head of that status, and for a cancelled booking also a
    /// `calendar.status` cancellation.
    recorded_at: Option<u64>,
    /// The visitor's PERSON, from the `booking.booker_contact` head.
    booker: Option<EntityId>,
}

/// Reads [`LifecycleHeads`] from `event_ref`'s surfaceable heads the booking
/// process issued, as the facts read counts them.
fn lifecycle_heads_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
    status: BookingStatus,
) -> Result<LifecycleHeads> {
    let mut heads = LifecycleHeads {
        recorded_at: None,
        booker: None,
    };
    for claim_id in vault.claims_for_subject_in_txn(rtxn, event_ref)? {
        let Some(body) = vault
            .get_claim_in_txn(rtxn, &claim_id)?
            .filter(crate::claim::claim_surfaceable)
        else {
            continue;
        };
        if body.subject != ClaimSubject::Entity(*event_ref)
            || !counts_in_txn(vault, rtxn, &claim_id, &body)?
        {
            continue;
        }
        let recorded_at = match body.predicate.as_str() {
            BOOKING_STATUS_PREDICATE => {
                decode_claim_value::<BookingStatusValue>(&body.value, "status")
                    .ok()
                    .filter(|value| value.status == status)
                    .map(|value| value.recorded_at)
            }
            PREDICATE_CALENDAR_STATUS if status == BookingStatus::Cancelled => {
                decode_status_value(&body.value)
                    .ok()
                    .filter(|value| value.status == CalendarStatus::Cancelled)
                    .map(|value| value.recorded_at)
            }
            BOOKING_BOOKER_CONTACT_PREDICATE => {
                heads.booker =
                    decode_claim_value::<BookingBookerContactValue>(&body.value, "booker contact")
                        .ok()
                        .map(|value| value.contact_ref);
                None
            }
            _ => None,
        };
        heads.recorded_at = heads.recorded_at.max(recorded_at);
    }
    Ok(heads)
}

/// Whether `at` falls on the same civil day as `now` in the owner's `zone`
/// (UTC when the booking froze none, or its zone does not resolve).
fn same_owner_day(at: u64, now: u64, zone: Option<&str>) -> bool {
    let date = |utc: u64| {
        zone.and_then(|tz| utc_to_wall(utc, tz).ok())
            .or_else(|| utc_to_wall(utc, "UTC").ok())
            .map(|wall| (wall.y, wall.mo, wall.d))
    };
    matches!((date(at), date(now)), (Some(day), Some(today)) if day == today)
}
