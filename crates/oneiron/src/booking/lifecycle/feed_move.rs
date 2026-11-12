//! A calendar feed's move of a booking's EVENT (FIX 22385; Engine ruling
//! BOOKING-FEED-DRIFT = B, 12 Nov).
//!
//! The host moved the booked event in their own calendar. That is the host's
//! own act on their own time, as the owner's own change of time is (ARCH-0062
//! R11), so the move lands with no solve and no token. It is still a booking
//! revision (ARCH-0062 RD-7): in ONE writer transaction the EVENT takes the
//! feed's slot, the outbound passport takes `last_sequence + 1`, the revision
//! receipt is recorded, and one [`BOOKING_REVISION_INVITE_ATTEMPT_KIND`] row
//! queues the booker's revised `REQUEST`. The feed never rewrites a live
//! booking's EVENT on its own, so no booking slot moves without its passport
//! and its receipt.

use serde::{Deserialize, Serialize};

use super::claim::{encode_event_body, read_booking_facts};
use super::occurrence::inclusive_occurrence;
use super::passport::supersede_outbound_passport;
use super::storage::{
    booking_writer, calendar_wrap, engine_failure, refused, revision_receipt_key, write_receipt,
};
use super::transition::booking_read_rows;
use super::types::{BOOKING_PASSPORT_SYSTEM, BookingStatus, CalendarRevision};
use super::{BookingContent, LifecycleReceiptRow};
use crate::attempt_queue::EnqueueAttempt;
use crate::booking::BookingError;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

/// The attempt kind of one booking revision's queued invite to its booker:
/// the revised `REQUEST` a feed move owes, sent through the page's standing
/// invite grant, the gate and the intent ledger as a reschedule's is.
pub const BOOKING_REVISION_INVITE_ATTEMPT_KIND: &str = "booking.revision_invite";

/// The payload of one [`BOOKING_REVISION_INVITE_ATTEMPT_KIND`] row: the
/// revision whose invite is owed. The invite's recipient, organizer and
/// times are read from committed state when it is sent, never from here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingRevisionInvitePayload {
    /// The booking's EVENT, lowercase hex.
    pub event_ref: String,
    /// The booking's outbound UID.
    pub uid: String,
    /// The SEQUENCE the revision committed.
    pub sequence: u32,
}

/// What one feed update did to the booking its EVENT carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FeedMoveOutcome {
    /// The EVENT carries no confirmed, uncancelled booking: the feed writes
    /// it as it writes any other EVENT.
    NotBooking,
    /// The feed reports no new slot: the slot the booking already sits at
    /// (the echo of our own revised invite included), or no bounded
    /// interval. Nothing is written.
    Unchanged,
    /// The booking moved to the feed's slot under this revision.
    Moved(CalendarRevision),
}

/// Moves the booking on `event_ref` to `feed_slot`, the half-open
/// `[DTSTART, DTEND)` a calendar feed now reports for it.
///
/// A held, partial or cancelled booking is [`FeedMoveOutcome::NotBooking`]:
/// only a confirmed, uncancelled booking has a slot its booker relies on.
/// The move does not consult the solver: a clash with another booking is two
/// overlapping EVENTs, as any feed drift makes.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] on store failures, and
/// [`BookingError::InvalidConstraint`] when the passport cannot take the next
/// SEQUENCE (a pending emergency effect, a competing outbound passport). The
/// feed then fails this pass and reads the update again on the next, so the
/// move is retried, never dropped.
pub(crate) fn move_booking_by_feed(
    vault: &Vault,
    event_ref: EntityId,
    feed_slot: Option<TimeRange>,
    now_utc: u64,
) -> Result<FeedMoveOutcome, BookingError> {
    booking_writer(vault, |wtxn| {
        if !carries_outbound_passport(vault, &*wtxn, &event_ref)? {
            return Ok(FeedMoveOutcome::NotBooking);
        }
        let booking = match read_booking_facts(vault, &*wtxn, &event_ref) {
            Ok(booking) => booking,
            // Held or missing heads: not a confirmed booking.
            Err(BookingError::InvalidConstraint(_)) => return Ok(FeedMoveOutcome::NotBooking),
            Err(error) => return Err(error),
        };
        if booking.effective_status() == BookingStatus::Cancelled {
            return Ok(FeedMoveOutcome::NotBooking);
        }
        let Some(slot) = feed_slot.filter(|range| range.start < range.end) else {
            return Ok(FeedMoveOutcome::Unchanged);
        };
        if slot == booking.slot {
            return Ok(FeedMoveOutcome::Unchanged);
        }
        let reads = booking_read_rows(vault, &*wtxn, &event_ref)?;

        // The booking's own body at the new interval, as a reschedule writes
        // it.
        vault
            .batch_in()
            .put(
                &event_ref,
                ENTITY_TYPE_EVENT,
                inclusive_occurrence(slot)?,
                now_utc,
                &encode_event_body(&booking.event_type)?,
            )
            .apply(wtxn)
            .map_err(|error| engine_failure("booking event rewrite", error))?;
        let revision = supersede_outbound_passport(
            vault,
            wtxn,
            &event_ref,
            &BookingContent {
                page_ref: booking.page_ref,
                event_type: booking.event_type,
                slot,
                status: BookingStatus::Confirmed,
                emergency_content_hash: None,
            },
            now_utc,
        )?;
        // Keyed as a reschedule to this slot is, so a token reschedule to
        // the slot the booking now sits at answers this revision.
        write_receipt(
            vault,
            wtxn,
            &revision_receipt_key(&event_ref, Some(slot)),
            &LifecycleReceiptRow {
                event_ref,
                uid: revision.uid.clone(),
                sequence: revision.sequence,
                session_hash: None,
                confirmation: None,
                invite_identity: None,
                reads,
            },
        )?;
        enqueue_revision_invite_in(vault, wtxn, &revision, now_utc)?;
        Ok(FeedMoveOutcome::Moved(revision))
    })
}

/// Whether the EVENT carries an admitted outbound booking passport: the one
/// fact every booking EVENT has and no other EVENT does.
fn carries_outbound_passport(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<bool, BookingError> {
    Ok(
        crate::calendar::passport::admitted_passports_for_event_in_txn(vault, txn, event_ref)
            .map_err(calendar_wrap)?
            .iter()
            .any(|(_, value)| value.system == BOOKING_PASSPORT_SYSTEM),
    )
}

/// Queues the revised invite `revision` owes its booker, in the revision's
/// own transaction. One row per revision: the dedupe key is the booking and
/// the SEQUENCE.
fn enqueue_revision_invite_in(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    revision: &CalendarRevision,
    now_utc: u64,
) -> Result<(), BookingError> {
    let event_hex = revision.event_ref.to_hex();
    let dedupe_key = format!(
        "{BOOKING_REVISION_INVITE_ATTEMPT_KIND}:{event_hex}:{}",
        revision.sequence
    );
    let payload = serde_json::to_vec(&BookingRevisionInvitePayload {
        event_ref: event_hex,
        uid: revision.uid.clone(),
        sequence: revision.sequence,
    })
    .map_err(|_| refused("booking revision invite payload did not encode"))?;
    crate::ports::JobQueue::port_job_enqueue(
        vault,
        wtxn,
        EnqueueAttempt {
            kind: BOOKING_REVISION_INVITE_ATTEMPT_KIND.to_owned(),
            payload,
            dedupe_key: Some(dedupe_key),
            run_id: None,
            now: now_utc,
        },
    )
    .map_err(|error| engine_failure("booking revision invite enqueue", error))?;
    Ok(())
}
