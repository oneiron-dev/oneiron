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
//!
//! Once a booking is cancelled or has started, the card also says what its
//! deposit still holds and offers Return deposit ([`held_deposit`]); where a
//! calendar's cancel moved no money, that line is an INBOX row of its own
//! ([`BOOKING_HELD_DEPOSIT_ITEM_PREFIX`]) until the deposit holds nothing.
//! A live owner's kept booking handle opens the card on any day, after its
//! row has left the same-day listing
//! ([`booking_owner_card_row_of_handle`]). The card of a booking the visitor
//! picked again from the owner's emergency cancel's proposals says where
//! the return of the deposit from before that cancel stands
//! ([`emergency_return`]).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::CalendarCancellation;
use super::authorship::counts_in_txn;
use super::claim::read_booking_facts;
use super::deposit::{
    emergency_return_in_txn, held_deposit_in_txn, unattributed_cancel_sequence_in_txn,
};
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

mod emergency_return;
mod held_deposit;

pub use self::emergency_return::{BookingDepositReturned, BookingOwnerCardEmergencyReturn};
pub use self::held_deposit::{
    BookingDepositHeld, BookingDepositHeldReason, BookingOwnerCardDeposit,
};

/// The prefix of a booking card's INBOX item id; the booking's EVENT hex
/// follows it. The EVENT keeps its id through every move, so the row does.
pub const BOOKING_OWNER_CARD_ITEM_PREFIX: &str = "booking:";

/// The prefix of a held deposit's INBOX item id; the booking's EVENT hex
/// follows it. The row stands while a calendar's cancel left the booking's
/// deposit held ([`BookingDepositHeldReason::lists_on_inbox`]), whatever
/// day it is, and opens the booking's card. Its own id, so marking the
/// booking's same-day row done never hides it.
pub const BOOKING_HELD_DEPOSIT_ITEM_PREFIX: &str = "booking-held-deposit:";

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
    /// What the booking's deposit still holds, once the booking is
    /// cancelled or has started, with the Return deposit act; `None` for a
    /// booking with no deposit, or one that holds nothing now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deposit: Option<BookingOwnerCardDeposit>,
    /// On a booking the visitor picked again from the owner's emergency
    /// cancel's proposals: no deposit is held, and the return of the deposit
    /// from before that cancel stands pending or made (RULING
    /// DEPOSIT-PICK-AFTER-EMERGENCY-CANCEL = A); `None` on every other card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emergency_return: Option<BookingOwnerCardEmergencyReturn>,
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
/// Beside it, any day, each booking whose deposit a calendar's cancel left
/// held, as a row of its own for `own_reader`, the one actor reading its own
/// slice, when it is a live owner and one of the hosts selected at the
/// booking's confirmation (who alone may return it): item id
/// `booking-held-deposit:<event hex>`, at the cancel, or at the start when
/// that came first, and no earlier than a cancel Oneiron cannot attribute
/// was noted. No other reader lists it, the cross-identity lens included
/// (review round 1 of #10028).
///
/// # Errors
///
/// Storage errors.
pub(crate) fn booking_owner_card_inbox_items(
    vault: &Vault,
    own_reader: Option<EntityId>,
) -> Result<Vec<AgentInboxLensItem>> {
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
    if owners.is_empty() {
        return Ok(Vec::new());
    }
    let held_reader = own_reader.filter(|reader| owners.contains(reader));
    let mut items = Vec::new();
    for event_ref in events {
        let Some(read) = card_in_txn(vault, &rtxn, &event_ref, now, None)? else {
            continue;
        };
        if let Some(held) = held_reader.and_then(|reader| held_deposit_row(&read, reader)) {
            items.push(held);
        }
        if same_owner_day(read.card.recorded_at, now, read.zone.as_deref()) {
            items.extend(booking_card_row(read.card, &owners));
        }
    }
    Ok(items)
}

/// The booking row `item_id` (`booking:<event hex>`) as `reader`, a live
/// owner, reads it now, whatever day it is: a booking handle the owner kept
/// opens the booking's card after its row has left the same-day listing, so
/// a booking that starts on a later day keeps its deposit line and Return
/// deposit within reach (review round 2 of #10028). `None` for any other
/// handle, for a reader who is no live owner, and for a booking that no
/// longer reads as a card.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn booking_owner_card_row_of_handle(
    vault: &Vault,
    item_id: &str,
    reader: EntityId,
) -> Result<Option<AgentInboxLensItem>> {
    let Some(event_ref) = item_id
        .strip_prefix(BOOKING_OWNER_CARD_ITEM_PREFIX)
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(None);
    };
    let now = vault.now_recorded_at();
    let rtxn = vault.store.env.read_txn()?;
    let owners = crate::policy_model::owners_in_txn(vault, &rtxn)?;
    if !owners.contains(&reader) {
        return Ok(None);
    }
    Ok(card_in_txn(vault, &rtxn, &event_ref, now, None)?
        .and_then(|read| booking_card_row(read.card, &owners)))
}

/// The version of the INBOX row `item_id` that its time and payload may not
/// show, for its read state: on a held-deposit row, the SEQUENCE of the
/// replay proof that made its cancel one Oneiron cannot attribute, once one
/// is noted, so a row marked done comes back when that proof lands in the
/// same second as the cancel the row was dated by (review round 2 of
/// #10028); `None` for every other row.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn booking_inbox_row_version_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    item_id: &str,
) -> Result<Option<String>> {
    let Some(event_ref) = item_id
        .strip_prefix(BOOKING_HELD_DEPOSIT_ITEM_PREFIX)
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(None);
    };
    Ok(
        unattributed_cancel_sequence_in_txn(vault, rtxn, &event_ref)?
            .map(|sequence| format!("unattributed_cancel:{sequence}")),
    )
}

/// The booking row of `card` for the vault's live `owners`: item id
/// `booking:<event hex>`, the EVENT hex as its payload, at the commit or the
/// cancel; `None` with no live owner.
fn booking_card_row(card: BookingOwnerCard, owners: &[EntityId]) -> Option<AgentInboxLensItem> {
    let &actor_ref = owners.first()?;
    Some(AgentInboxLensItem {
        item_id: format!("{BOOKING_OWNER_CARD_ITEM_PREFIX}{}", card.event_ref),
        kind: AgentInboxItemKind::CoordinationUpdate,
        thread_ref: None,
        identity_ref: None,
        actor_ref,
        facet_ref: None,
        participants: owners
            .iter()
            .map(|&owner| AgentInboxParticipant {
                identity_ref: None,
                actor_ref: owner,
            })
            .collect(),
        impact: InboxImpact(BOOKING_OWNER_CARD_INBOX_IMPACT),
        occurred_at: card.recorded_at,
        receipt_ref: None,
        payload_ref: Some(card.event_ref),
        approval_digest: None,
        concern: None,
        diary_review: None,
        sender: None,
        widening: None,
    })
}

/// The held-deposit row of the booking `read` describes, on the own slice
/// of `reader`, a live owner: when a calendar's cancel left its deposit
/// held and `reader` is one of its selected hosts; `None` otherwise. It is
/// dated by the cancel, or the start when that came first, and by a cancel
/// Oneiron cannot attribute once one is noted: its read state then counts
/// the line as new, so a row marked done before comes back under the same
/// handle (review round 1 of #10028).
fn held_deposit_row(read: &CardRead, reader: EntityId) -> Option<AgentInboxLensItem> {
    let deposit = read.card.deposit.as_ref()?;
    if !deposit.reason.lists_on_inbox() || !read.selected_hosts.contains(&reader.to_hex()) {
        return None;
    }
    let card = &read.card;
    let occurred_at = if card.status == BookingStatus::Cancelled {
        card.recorded_at.min(card.start_utc)
    } else {
        card.start_utc
    };
    let occurred_at = match read.unattributed_cancel_at {
        Some(noted_at) if deposit.reason == BookingDepositHeldReason::UnattributedCancel => {
            occurred_at.max(noted_at)
        }
        _ => occurred_at,
    };
    Some(AgentInboxLensItem {
        item_id: format!("{BOOKING_HELD_DEPOSIT_ITEM_PREFIX}{}", card.event_ref),
        kind: AgentInboxItemKind::CoordinationUpdate,
        thread_ref: None,
        identity_ref: None,
        actor_ref: reader,
        facet_ref: None,
        participants: vec![AgentInboxParticipant {
            identity_ref: None,
            actor_ref: reader,
        }],
        impact: InboxImpact(BOOKING_OWNER_CARD_INBOX_IMPACT),
        occurred_at,
        receipt_ref: None,
        payload_ref: Some(card.event_ref.clone()),
        approval_digest: None,
        concern: None,
        diary_review: None,
        sender: None,
        widening: None,
    })
}

/// The card the INBOX row `item_id` carries, read now for `reader`; `None`
/// for a row that is no booking card, for a booking that no longer reads as
/// one, and for a held-deposit row whose deposit no longer stands held as
/// the row says or whose reader is no selected host.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn booking_owner_card_of_item(
    vault: &Vault,
    item_id: &str,
    reader: EntityId,
) -> Result<Option<BookingOwnerCard>> {
    let (hex, held_row) = match item_id.strip_prefix(BOOKING_HELD_DEPOSIT_ITEM_PREFIX) {
        Some(hex) => (hex, true),
        None => match item_id.strip_prefix(BOOKING_OWNER_CARD_ITEM_PREFIX) {
            Some(hex) => (hex, false),
            None => return Ok(None),
        },
    };
    let Ok(event_ref) = EntityId::from_hex(hex) else {
        return Ok(None);
    };
    let now = vault.now_recorded_at();
    let rtxn = vault.store.env.read_txn()?;
    let card = card_in_txn(vault, &rtxn, &event_ref, now, Some(reader))?.map(|read| read.card);
    Ok(card.filter(|card| {
        !held_row
            || card
                .deposit
                .as_ref()
                .is_some_and(|deposit| deposit.reason.lists_on_inbox() && deposit.return_offered)
    }))
}

/// One booking's card as one snapshot reads it, with what its rows need
/// beside the card.
struct CardRead {
    card: BookingOwnerCard,
    /// The IANA zone of the owner's day: the first selected host's, frozen
    /// at confirmation.
    zone: Option<String>,
    /// The hosts selected at confirmation, hex: who may return its deposit.
    selected_hosts: Vec<String>,
    /// When a cancel Oneiron cannot attribute was first noted on its
    /// deposit, while the deposit holds anything.
    unattributed_cancel_at: Option<u64>,
}

/// `event_ref`'s card at `now`, as `reader` reads it, read in one snapshot;
/// `None` for an EVENT that is not a live booking the booking process holds
/// settled.
fn card_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
    now: u64,
    reader: Option<EntityId>,
) -> Result<Option<CardRead>> {
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
    let held = held_deposit_in_txn(vault, rtxn, event_ref)?;
    let unattributed_cancel_at = held.as_ref().and_then(|held| held.unattributed_cancel_at);
    let cancel_reported = held.is_some()
        && facts.calendar_cancellation == CalendarCancellation::Omission
        && calendar_cancel_reported_in_txn(vault, rtxn, event_ref);
    let deposit =
        held_deposit::deposit_note(&facts, held, cancel_reported, zone.as_deref(), now, reader);
    // Only the visitor's pick of an emergency proposal confirms an
    // emergency-cancelled booking again: confirmed, with the emergency
    // cancel's mark on its deposit, the booking is that pick.
    let emergency_return = if status == BookingStatus::Confirmed {
        emergency_return_in_txn(vault, rtxn, event_ref)?.map(|returned| {
            emergency_return::emergency_return_note(returned, facts.slot.start, zone.as_deref())
        })
    } else {
        None
    };
    let selected_hosts = facts
        .context
        .as_ref()
        .map(|context| context.owner_refs.clone())
        .unwrap_or_default();
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
        deposit,
        emergency_return,
    };
    Ok(Some(CardRead {
        card,
        zone,
        selected_hosts,
        unattributed_cancel_at,
    }))
}

/// Whether a calendar's report of the booking `event_ref` cancelled or
/// removed stands on one of its passports, absent or not: a tombstone or a
/// cancelled version the calendar sent and has not taken back
/// (`cancelled_since`), unless it is the engine's own cancelled write coming
/// back (`written_cancelled`), or a host's delete or cancel a pull held back
/// while a cancelled write of the UID was in flight
/// (`deferred_cancel_seen_at`), which a replay whose read proved no stored
/// copy keeps held (CAL-SEAT-DELETE-OF-WRITTEN-ONLY-EVENT-CANCELS-NOTHING).
/// A cancel that waited on another calendar still listing the booking
/// counts when that calendar's omission concludes it (review round 2 of
/// #10028). Passports that do not read count as no report, with a warning.
fn calendar_cancel_reported_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> bool {
    match crate::calendar::passport::live_passports_for_event_in_txn(vault, rtxn, event_ref) {
        Ok(passports) => passports.iter().any(|(_, value)| {
            (value.cancelled_since.is_some() && !value.written_cancelled)
                || value.deferred_cancel_seen_at.is_some()
        }),
        Err(error) => {
            tracing::warn!(%error, "calendar passports not read; no cancel report counted");
            false
        }
    }
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
