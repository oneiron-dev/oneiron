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
//!
//! [`run_booking_revision_invites`] drains those rows on the node that holds
//! the outbound sink, through the page's standing invite grant, the gate and
//! the intent ledger, as a reschedule's revised invite goes (FIX 7850). A
//! move a pending emergency delivery fences is held back on its own: the
//! feed keeps that item's update owed and lands every other item of the pass
//! (Engine ruling 16:10, 12 Nov).

use serde::{Deserialize, Serialize};

use super::claim::{encode_event_body, read_booking_facts};
use super::door::attempt_failure_reason;
use super::emergency::emergency_current_revision_in;
use super::occurrence::inclusive_occurrence;
use super::passport::supersede_outbound_passport;
use super::storage::{
    booking_writer, calendar_wrap, engine_failure, refused, revision_receipt_key, write_receipt,
};
use super::transition::booking_read_rows;
use super::types::{BOOKING_PASSPORT_SYSTEM, BookingStatus, CalendarRevision};
use super::{BookingContent, LifecycleReceiptRow};
use crate::attempt_queue::{
    AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt, EnqueueAttempt,
    FailAttempt, RequeueAttempt,
};
use crate::booking::BookingError;
use crate::booking::emergency_reschedule::pending_effect_fences_in;
use crate::booking::invite_grant::dispatch_booking_revision_invite_outcome;
use crate::outbound::OutboundExecutionSink;
use crate::registry::ENTITY_TYPE_EVENT;
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

/// The attempt kind of one booking revision's queued invite to its booker:
/// the revised `REQUEST` a feed move owes, sent through the page's standing
/// invite grant, the gate and the intent ledger as a reschedule's is.
pub const BOOKING_REVISION_INVITE_ATTEMPT_KIND: &str = "booking.revision_invite";

/// How many claims one revised invite's dispatch gets before its row fails
/// for good. A retry is safe: the intent ledger resolves a possibly-sent
/// effect before any transport is repeated.
const REVISION_INVITE_DISPATCH_ATTEMPTS: u32 = 5;

/// How long a revised invite whose dispatch failed waits before it is tried
/// again.
const REVISION_INVITE_RETRY_SECONDS: u64 = 300;

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
    /// A pending emergency delivery fences the booking's current revision,
    /// so the passport cannot take the next SEQUENCE. Nothing is written:
    /// the feed keeps this item's update owed and reads it again on its next
    /// poll, and every other item of the pass lands.
    HeldBack,
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
/// SEQUENCE for another reason than a pending emergency delivery (a
/// competing outbound passport, an exhausted SEQUENCE). The feed then fails
/// this pass and reads the update again on the next, so the move is retried,
/// never dropped.
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
        // The one refusal the ruling holds back per item: every other item
        // of the feed still lands, and this one is read again. The fence is
        // read as a fact, never from a refusal's variant.
        if pending_effect_fences_in(vault, &*wtxn, event_ref)? {
            return Ok(FeedMoveOutcome::HeldBack);
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

/// What one [`run_booking_revision_invites`] pass settled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BookingRevisionInviteDrain {
    /// Rows whose invite went through the dispatch gate: sent, or held for
    /// the owner's approve-once press.
    pub dispatched: u32,
    /// Rows that owed nothing any more: a later revision superseded theirs,
    /// the booking is cancelled, or the page has no live publisher to send
    /// as. Each completes unsent, as a lifecycle move on such a page sends
    /// nothing.
    pub settled_unsent: u32,
    /// Rows whose dispatch refused or failed: queued again five minutes
    /// later, or failed for good on their fifth claim.
    pub refused: u32,
}

/// Claims and sends up to `limit` queued [`BOOKING_REVISION_INVITE_ATTEMPT_KIND`]
/// rows on `sink`: each one the revised `REQUEST` a feed move owes its
/// booker, read from committed state, sent as the page's verified live
/// publisher through the page's standing invite grant, the gate and the
/// intent ledger, exactly as a reschedule's revised invite is sent. The
/// intent ref is the booking's (UID, SEQUENCE), so a row claimed again sends
/// nothing new.
///
/// A row whose revision is no longer the booking's current one completes
/// unsent: the booker hears the current revision, from its own row.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] on a queue or store failure. A dispatch that
/// refuses settles its row and does not fail the pass.
pub fn run_booking_revision_invites<S: OutboundExecutionSink>(
    vault: &Vault,
    lease_owner: &str,
    sink: &mut S,
    limit: usize,
    now_utc: u64,
) -> Result<BookingRevisionInviteDrain, BookingError> {
    let queue = AttemptQueue::new(vault);
    let mut drain = BookingRevisionInviteDrain::default();
    for _ in 0..limit {
        let claimed = queue
            .claim_kind(
                BOOKING_REVISION_INVITE_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: lease_owner.to_owned(),
                    now: now_utc,
                },
            )
            .map_err(|error| engine_failure("revision invite claim", error))?;
        let ClaimOutcome::Claimed(record) = claimed else {
            break;
        };
        let owed = match owed_revision_invite(vault, &record, now_utc) {
            Ok(owed) => owed,
            Err(error) => {
                fail_revision_invite(&queue, &record, lease_owner, &error, now_utc)?;
                drain.refused += 1;
                continue;
            }
        };
        let Some((actor, revision)) = owed else {
            complete_revision_invite(&queue, &record, lease_owner, now_utc)?;
            drain.settled_unsent += 1;
            continue;
        };
        match dispatch_booking_revision_invite_outcome(vault, actor, &revision, sink, now_utc) {
            Ok(_) => {
                complete_revision_invite(&queue, &record, lease_owner, now_utc)?;
                drain.dispatched += 1;
            }
            Err(error) if record.attempt_count >= REVISION_INVITE_DISPATCH_ATTEMPTS => {
                fail_revision_invite(&queue, &record, lease_owner, &error, now_utc)?;
                drain.refused += 1;
            }
            Err(error) => {
                tracing::debug!(%error, "booking revised invite runs again later");
                queue
                    .requeue(RequeueAttempt {
                        id: record.id,
                        lease_owner: lease_owner.to_owned(),
                        attempt_count: record.attempt_count,
                        reason: attempt_failure_reason(&error),
                        due_at: now_utc.saturating_add(REVISION_INVITE_RETRY_SECONDS),
                    })
                    .map_err(|error| engine_failure("revision invite requeue", error))?;
                drain.refused += 1;
            }
        }
    }
    Ok(drain)
}

/// The actor and the revision `record` still owes an invite for: `None`
/// when a later revision superseded it, the booking is cancelled, or the
/// page has no live publisher.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] for a payload that does not decode,
/// and [`BookingError::SlotOracle`] on store failures.
fn owed_revision_invite(
    vault: &Vault,
    record: &AttemptRecord,
    now_utc: u64,
) -> Result<Option<(EntityId, CalendarRevision)>, BookingError> {
    let payload: BookingRevisionInvitePayload = serde_json::from_slice(&record.payload)
        .map_err(|_| refused("booking revision invite payload did not decode"))?;
    let event_ref = EntityId::from_hex(&payload.event_ref)
        .map_err(|_| refused("booking revision invite names no EVENT"))?;
    let revision = CalendarRevision {
        event_ref,
        uid: payload.uid,
        sequence: payload.sequence,
    };
    let page_ref = {
        let rtxn = vault
            .store
            .env
            .read_txn()
            .map_err(|error| engine_failure("revision invite read", error))?;
        if emergency_current_revision_in(vault, &rtxn, event_ref)? != revision {
            return Ok(None);
        }
        let booking = read_booking_facts(vault, &rtxn, &event_ref)?;
        if booking.effective_status() == BookingStatus::Cancelled {
            return Ok(None);
        }
        booking.page_ref
    };
    let actor = crate::booking::publication::live_booking_page_publisher(vault, page_ref, now_utc)
        .map_err(|error| engine_failure("booking page publisher read", error))?;
    Ok(actor.map(|actor| (actor, revision)))
}

/// Completes one claimed revised-invite row.
fn complete_revision_invite(
    queue: &AttemptQueue<'_>,
    record: &AttemptRecord,
    lease_owner: &str,
    now_utc: u64,
) -> Result<(), BookingError> {
    queue
        .complete(CompleteAttempt {
            id: record.id,
            lease_owner: lease_owner.to_owned(),
            attempt_count: record.attempt_count,
            now: now_utc,
        })
        .map(|_| ())
        .map_err(|error| engine_failure("revision invite complete", error))
}

/// Fails one claimed revised-invite row for good, with its bounded reason.
fn fail_revision_invite(
    queue: &AttemptQueue<'_>,
    record: &AttemptRecord,
    lease_owner: &str,
    failure: &BookingError,
    now_utc: u64,
) -> Result<(), BookingError> {
    tracing::warn!(error = %failure, "booking revised invite failed for good");
    queue
        .fail(FailAttempt {
            id: record.id,
            lease_owner: lease_owner.to_owned(),
            attempt_count: record.attempt_count,
            reason: attempt_failure_reason(failure),
            now: now_utc,
        })
        .map(|_| ())
        .map_err(|error| engine_failure("revision invite fail", error))
}
