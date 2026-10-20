//! Booking facts on the EVENT: the four exact claims, their writes and
//! supersessions, the family validator, and the claim-class descriptor rows.

use crate::ports::EntityStoreRead;
use serde::{Deserialize, Serialize};

use super::BookingFacts;
use super::confirmation_state::confirmation_receipt_in;
use super::occurrence::{at, half_open_occurrence, inclusive_occurrence};
use super::storage::{
    claim_value, claims_for_subject, decode_claim_value, encode_claim_value, engine_failure,
    read_txn, refused,
};
use super::types::{
    BOOKING_BOOKER_CONTACT_PREDICATE, BOOKING_EVENT_TYPE_REF_PREDICATE,
    BOOKING_LIFECYCLE_PREDICATES, BOOKING_SOURCE_PAGE_PREDICATE, BOOKING_STATUS_PREDICATE,
    BookingBookerContactValue, BookingEventTypeRefValue, BookingSourcePageValue, BookingStatus,
    BookingStatusValue, SoftHoldRow,
};
use crate::booking::config::ClaimClassDescriptorRow;
use crate::booking::{BookingError, ConstraintObject, EventTypeKey};
use crate::calendar::claims::{
    CalendarStatus, CalendarStatusBasis, PREDICATE_CALENDAR_STATUS, decode_status_value,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::registry::ENTITY_TYPE_EVENT;
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

/// Whether `predicate` is an exact member of the lifecycle claim family.
#[must_use]
pub fn is_booking_lifecycle_claim_predicate(predicate: &str) -> bool {
    BOOKING_LIFECYCLE_PREDICATES.contains(&predicate)
}

/// Original confirmation inputs retained when the hold is consumed. The
/// solver's exact host choice is captured once, never inferred from later
/// routing membership. An empty owner set means the oracle attested no hosts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingConfirmationContext {
    pub owner_refs: Vec<String>,
    /// IANA zone per selected host, in `owner_refs` order, frozen at confirm.
    pub host_zones: Vec<String>,
    pub booker_ref: String,
    pub visitor_tz: String,
    pub constraint: Option<ConstraintObject>,
    /// The short answers given before confirm, bound to this EVENT's receipt.
    #[serde(default)]
    pub intake: Vec<crate::booking::agent_api::BookingIntakeAnswer>,
}

/// Reads only this booking's persisted confirmation context. Missing old data
/// is a booking-local refusal at the emergency door, never a guessed timezone.
pub fn booking_confirmation_context(
    vault: &Vault,
    event_ref: &EntityId,
) -> Result<Option<BookingConfirmationContext>, BookingError> {
    let rtxn = read_txn(vault)?;
    confirmation_context_in(vault, &rtxn, event_ref)
}

fn confirmation_context_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<Option<BookingConfirmationContext>, BookingError> {
    Ok(confirmation_receipt_in(vault, rtxn, event_ref)?
        .and_then(|(_, receipt)| receipt.confirmation))
}

/// Current start of a live confirmed booking, for BK-07 reminder wake checks.
/// This reads status and occurrence in one snapshot. A missing or malformed
/// booking fails closed rather than causing an outbound message.
pub(in crate::booking) fn confirmed_start_for_reminder(
    vault: &Vault,
    event_ref: &EntityId,
) -> Result<Option<u64>, BookingError> {
    let rtxn = read_txn(vault)?;
    // Soft deletion keeps the EVENT header, occurrence, claims, and receipt.
    // Resolve deletion metadata in this SAME snapshot before any of those
    // retained facts can authorize a due reminder.
    if !matches!(
        crate::vault::live_entity_row_in_txn(&vault.store, &rtxn, event_ref)
            .map_err(|error| engine_failure("booking EVENT liveness", error))?,
        crate::vault::LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_EVENT,
            ..
        }
    ) {
        return Ok(None);
    }
    let facts = read_booking_facts(vault, &rtxn, event_ref)?;
    if facts.status != BookingStatus::Confirmed {
        return Ok(None);
    }
    // An inbound calendar-provider cancellation need not change booking.status.
    // Check the effective CAL head in the same snapshot as the booking and
    // occurrence, never an unapproved or superseded claim.
    for claim_id in claims_for_subject(vault, &rtxn, event_ref)? {
        let body = vault
            .get_claim_in_txn(&rtxn, &claim_id)
            .map_err(|error| engine_failure("calendar status read", error))?;
        if let Some(body) = body.filter(crate::claim::claim_surfaceable)
            && body.predicate == PREDICATE_CALENDAR_STATUS
            && decode_status_value(&body.value)
                .map_err(|error| engine_failure("calendar status decode", error))?
                .status
                == CalendarStatus::Cancelled
        {
            return Ok(None);
        }
    }
    Ok(Some(facts.slot.start))
}

/// Current starts of one page's live confirmed bookings of one event type that
/// start inside `starts` (inclusive), read from one committed snapshot.
///
/// The daily and weekly caps charge these. A booking counts while its EVENT is
/// live, a booking status head says Confirmed, and no status head says
/// Cancelled — neither the booking's own nor the calendar's, since an inbound
/// cancellation need not change the booking's. It counts at its current
/// start, so a moved booking charges the day it sits on now. `excluding` is a
/// booking being moved, which never charges against its own move.
///
/// No index keys bookings by page, so this walks the EVENT type index, the
/// walk the calendar busy read already makes, and reads claims only for the
/// EVENTs that start inside `starts`.
pub(in crate::booking) fn confirmed_booking_starts(
    vault: &Vault,
    page_ref: EntityId,
    event_type: &EventTypeKey,
    starts: TimeRange,
    excluding: Option<EntityId>,
) -> Result<Vec<u64>, BookingError> {
    Ok(
        confirmed_booking_starts_in(vault, page_ref, event_type, starts, excluding, false)?
            .into_iter()
            .map(|(start, _)| start)
            .collect(),
    )
}

/// [`confirmed_booking_starts`], each start beside the rows that decided it
/// in that snapshot (FIX 4777): the booking's EVENT and every claim on it,
/// its page, event-type and status heads among them.
pub(in crate::booking) fn confirmed_booking_starts_listed(
    vault: &Vault,
    page_ref: EntityId,
    event_type: &EventTypeKey,
    starts: TimeRange,
    excluding: Option<EntityId>,
) -> Result<Vec<(u64, Vec<EntityId>)>, BookingError> {
    confirmed_booking_starts_in(vault, page_ref, event_type, starts, excluding, true)
}

fn confirmed_booking_starts_in(
    vault: &Vault,
    page_ref: EntityId,
    event_type: &EventTypeKey,
    starts: TimeRange,
    excluding: Option<EntityId>,
    list: bool,
) -> Result<Vec<(u64, Vec<EntityId>)>, BookingError> {
    let rtxn = read_txn(vault)?;
    let mut found = Vec::new();
    for id in vault
        .store
        .port_entity_ids_by_type(&rtxn, ENTITY_TYPE_EVENT, None)
        .map_err(|error| engine_failure("booking EVENT scan", error))?
    {
        let id = id.map_err(|error| engine_failure("booking EVENT scan", error))?;
        if excluding == Some(id) {
            continue;
        }
        let Some(record) = vault
            .store
            .port_entity_record(&rtxn, &id)
            .map_err(|error| engine_failure("booking EVENT header read", error))?
        else {
            continue;
        };
        let start = record.occurred.start.min(record.occurred.end);
        // Both bounds zero is an undated row, not 1970.
        if record.entity_type != ENTITY_TYPE_EVENT
            || (record.occurred.start == 0 && record.occurred.end == 0)
            || start < starts.start
            || start > starts.end
        {
            continue;
        }
        let visibility =
            crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, &rtxn, &id)
                .map_err(|error| engine_failure("booking EVENT liveness", error))?;
        if visibility.deleted || visibility.stale {
            continue;
        }
        if is_confirmed_booking_in(vault, &rtxn, &id, page_ref, event_type)? {
            let rows = if list {
                std::iter::once(id)
                    .chain(claims_for_subject(vault, &rtxn, &id)?)
                    .collect()
            } else {
                Vec::new()
            };
            found.push((start, rows));
        }
    }
    Ok(found)
}

/// The event type one booking's live head names, read without the rest of
/// its facts.
pub(super) fn booking_event_type_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<Option<EventTypeKey>, BookingError> {
    for claim_id in claims_for_subject(vault, rtxn, event_ref)? {
        let Some(body) = vault
            .get_claim_in_txn(rtxn, &claim_id)
            .map_err(|error| engine_failure("booking claim read", error))?
            .filter(crate::claim::claim_surfaceable)
        else {
            continue;
        };
        if body.predicate == BOOKING_EVENT_TYPE_REF_PREDICATE
            && body.subject == ClaimSubject::Entity(*event_ref)
            && head_counts(vault, rtxn, &claim_id, &body)?
        {
            return Ok(Some(
                decode_claim_value::<BookingEventTypeRefValue>(&body.value, "event type ref")?
                    .event_type,
            ));
        }
    }
    Ok(None)
}

/// Whether `event_ref`'s surfaceable heads make it a confirmed booking of
/// this page and event type. Order-independent: competing status heads
/// never count as Confirmed.
fn is_confirmed_booking_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
    page_ref: EntityId,
    event_type: &EventTypeKey,
) -> Result<bool, BookingError> {
    let (mut on_page, mut of_type, mut confirmed, mut cancelled) = (false, false, false, false);
    for claim_id in claims_for_subject(vault, rtxn, event_ref)? {
        let Some(body) = vault
            .get_claim_in_txn(rtxn, &claim_id)
            .map_err(|error| engine_failure("booking claim read", error))?
            .filter(crate::claim::claim_surfaceable)
        else {
            continue;
        };
        if body.subject != ClaimSubject::Entity(*event_ref)
            || !head_counts(vault, rtxn, &claim_id, &body)?
        {
            continue;
        }
        // A held head still charges the cap; only a settled one discharges it.
        let settled = || {
            crate::gate::claim_critical_confirm_settled_in_txn(&vault.store, rtxn, &claim_id)
                .map_err(|error| engine_failure("booking claim confirm read", error))
        };
        match body.predicate.as_str() {
            BOOKING_SOURCE_PAGE_PREDICATE => {
                on_page |=
                    decode_claim_value::<BookingSourcePageValue>(&body.value, "source page")?
                        .page_ref
                        == page_ref;
            }
            BOOKING_EVENT_TYPE_REF_PREDICATE => {
                of_type |=
                    decode_claim_value::<BookingEventTypeRefValue>(&body.value, "event type ref")?
                        .event_type
                        == *event_type;
            }
            BOOKING_STATUS_PREDICATE => {
                match decode_claim_value::<BookingStatusValue>(&body.value, "status")?.status {
                    BookingStatus::Confirmed => confirmed = true,
                    BookingStatus::Cancelled => cancelled |= settled()?,
                }
            }
            PREDICATE_CALENDAR_STATUS => {
                cancelled |= decode_status_value(&body.value)
                    .map_err(|error| engine_failure("calendar status decode", error))?
                    .status
                    == CalendarStatus::Cancelled
                    && settled()?;
            }
            _ => {}
        }
    }
    Ok(on_page && of_type && confirmed && !cancelled)
}

/// Creates the EVENT and its four exact booking claims.
pub(super) fn write_booking_event(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: &EntityId,
    hold: &SoftHoldRow,
    booker_contact: EntityId,
    now_utc: u64,
) -> Result<(), BookingError> {
    // The booking intent is a native authored calendar entry. Stage a non-calendar
    // stub, the projector-recorded origin, and the admitted body atomically.
    let stub = rmpv::Value::Map(vec![(
        rmpv::Value::from("name"),
        rmpv::Value::from(hold.event_type.0.as_str()),
    )]);
    let mut stub_bytes = Vec::new();
    rmpv::encode::write_value(&mut stub_bytes, &stub)
        .map_err(|_| refused("booking event stub encode"))?;
    vault
        .batch_in()
        .put(
            event_ref,
            ENTITY_TYPE_EVENT,
            inclusive_occurrence(hold.slot)?,
            now_utc,
            &stub_bytes,
        )
        .apply(wtxn)
        .map_err(|error| engine_failure("booking event write", error))?;
    let mut origin = ClaimBody::new(
        crate::calendar::claims::PREDICATE_CALENDAR_ORIGIN,
        ClaimSubject::Entity(*event_ref),
        rmpv::Value::from("native"),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .map_err(|error| engine_failure("booking origin claim body", error))?;
    origin.evidence = Some(rmpv::Value::Map(vec![
        (
            rmpv::Value::from("kind"),
            rmpv::Value::from("calendar_projector"),
        ),
        (
            rmpv::Value::from("write_class"),
            rmpv::Value::from("recorded"),
        ),
        (rmpv::Value::from("projector"), rmpv::Value::from("booking")),
    ]));
    vault
        .put_reserved_claim_in_txn(
            wtxn,
            &vault
                .new_entity_id()
                .map_err(|error| engine_failure("booking origin id", error))?,
            &origin,
            inclusive_occurrence(hold.slot)?,
            now_utc,
        )
        .map_err(|error| engine_failure("booking origin write", error))?;
    vault
        .batch_in()
        .put(
            event_ref,
            ENTITY_TYPE_EVENT,
            inclusive_occurrence(hold.slot)?,
            now_utc,
            &encode_event_body(&hold.event_type)?,
        )
        .apply(wtxn)
        .map_err(|error| engine_failure("booking event write", error))?;

    let values = [
        (
            BOOKING_EVENT_TYPE_REF_PREDICATE,
            encode_claim_value(&BookingEventTypeRefValue {
                event_type: hold.event_type.clone(),
            })?,
        ),
        (
            BOOKING_BOOKER_CONTACT_PREDICATE,
            encode_claim_value(&BookingBookerContactValue {
                contact_ref: booker_contact,
            })?,
        ),
        (
            BOOKING_SOURCE_PAGE_PREDICATE,
            encode_claim_value(&BookingSourcePageValue {
                page_ref: hold.page_ref,
            })?,
        ),
        (
            BOOKING_STATUS_PREDICATE,
            encode_claim_value(&BookingStatusValue {
                status: BookingStatus::Confirmed,
                recorded_at: now_utc,
            })?,
        ),
    ];
    for (predicate, value) in values {
        put_claim(vault, wtxn, event_ref, predicate, value, now_utc)?;
    }
    Ok(())
}

/// Writes one engine-recorded claim into the caller's transaction.
///
/// `Auto` approval with an `Observed` source is `calendar/outcome.rs`'s stance
/// for a family projector: the engine recorded a fact it witnessed, and the
/// shared write door still rules on source trust.
pub(super) fn put_claim(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    subject: &EntityId,
    predicate: &str,
    value: rmpv::Value,
    now_utc: u64,
) -> Result<EntityId, BookingError> {
    let id = vault
        .store
        .clock
        .entity_id()
        .map_err(|error| engine_failure("booking id allocation", error))?;
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(*subject),
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .map_err(|error| engine_failure("booking claim body", error))?;
    body.source = Some(ClaimSource::Observed);
    body.valid_from = Some(now_utc);
    vault
        .put_claim_in_txn(wtxn, &id, &body, at(now_utc), now_utc)
        .map_err(|error| engine_failure("booking claim write", error))?;
    // FIX 5994: the head is born of the booking process, in this write.
    super::authorship::stamp_engine_head_in_txn(vault, wtxn, &id, now_utc)
        .map_err(|error| engine_failure("booking head birth", error))?;
    Ok(id)
}

/// Whether a surfaceable head counts on a lifecycle read (FIX 5994): one no
/// booking process issued is ignored, never decoded.
fn head_counts(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    claim_id: &EntityId,
    body: &ClaimBody,
) -> Result<bool, BookingError> {
    super::authorship::counts_in_txn(vault, rtxn, claim_id, body)
        .map_err(|error| engine_failure("booking head birth read", error))
}

/// Writes a replacement head and supersedes every live claim it replaces, in
/// one transaction, so the EVENT can never carry two live heads.
pub(super) fn supersede_exact_claim(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    subject: &EntityId,
    predicate: &str,
    value: rmpv::Value,
    now_utc: u64,
) -> Result<(), BookingError> {
    let prior = live_claims_with_predicate(vault, &*wtxn, subject, predicate, now_utc)?;
    let new_id = put_claim(vault, wtxn, subject, predicate, value, now_utc)?;
    for old_id in prior {
        vault
            .supersede_claim_in_txn(wtxn, &new_id, &old_id, now_utc)
            .map_err(|error| engine_failure("booking claim supersession", error))?;
    }
    Ok(())
}

/// Every live claim about `subject` carrying exactly `predicate`, except a
/// pending one dated after `now_utc`: the store cannot close that yet, and a
/// proposal must never block the transition. It is left to its review.
fn live_claims_with_predicate(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    subject: &EntityId,
    predicate: &str,
    now_utc: u64,
) -> Result<Vec<EntityId>, BookingError> {
    let mut out = Vec::new();
    for claim_id in claims_for_subject(vault, rtxn, subject)? {
        let Ok(Some(body)) = vault.get_claim_in_txn(rtxn, &claim_id) else {
            continue;
        };
        if body.predicate != predicate
            || body.lifecycle != ClaimLifecycleStatus::Active
            || body.subject != ClaimSubject::Entity(*subject)
        {
            continue;
        }
        if !crate::claim::claim_surfaceable(&body)
            && vault
                .store
                .port_entity_record(rtxn, &claim_id)
                .map_err(|error| engine_failure("booking claim header read", error))?
                .is_some_and(|row| row.occurred.start > now_utc)
        {
            continue;
        }
        out.push(claim_id);
    }
    Ok(out)
}

/// Reads the booking facts one EVENT's live claims and structural row carry.
///
/// Only surfaceable heads count, as in the cap tally: a pending proposal
/// beside the engine's record must not move, cancel or retype a booking.
pub(super) fn read_booking_facts(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<BookingFacts, BookingError> {
    booking_facts_in(vault, rtxn, event_ref, true)
}

/// [`read_booking_facts`] for a door whose only effect is cancelling the
/// booking: held heads read as they stand, so a hold never stops a cancel.
pub(super) fn read_booking_facts_to_cancel(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<BookingFacts, BookingError> {
    booking_facts_in(vault, rtxn, event_ref, false)
}

fn booking_facts_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
    hold_enablers: bool,
) -> Result<BookingFacts, BookingError> {
    let mut page_ref = None;
    let mut event_type = None;
    let mut status = None;
    let mut held_confirmed = false;
    for claim_id in claims_for_subject(vault, rtxn, event_ref)? {
        let Ok(Some(body)) = vault.get_claim_in_txn(rtxn, &claim_id) else {
            continue;
        };
        if !crate::claim::claim_surfaceable(&body)
            || body.subject != ClaimSubject::Entity(*event_ref)
            || !head_counts(vault, rtxn, &claim_id, &body)?
        {
            continue;
        }
        // The hold binds the enabling heads only: a held Cancelled still
        // cancels, while a held page, type or Confirmed never decides.
        let settled = || -> Result<bool, BookingError> {
            Ok(!hold_enablers
                || crate::gate::claim_critical_confirm_settled_in_txn(
                    &vault.store,
                    rtxn,
                    &claim_id,
                )
                .map_err(|error| engine_failure("booking claim confirm read", error))?)
        };
        match body.predicate.as_str() {
            BOOKING_SOURCE_PAGE_PREDICATE => {
                let value =
                    decode_claim_value::<BookingSourcePageValue>(&body.value, "source page")?;
                if !settled()? {
                    return Err(refused("booking source page awaits its owner's confirm"));
                }
                page_ref = Some(value.page_ref);
            }
            BOOKING_EVENT_TYPE_REF_PREDICATE => {
                let value =
                    decode_claim_value::<BookingEventTypeRefValue>(&body.value, "event type ref")?;
                if !settled()? {
                    return Err(refused("booking event type awaits its owner's confirm"));
                }
                event_type = Some(value.event_type);
            }
            BOOKING_STATUS_PREDICATE => {
                match decode_claim_value::<BookingStatusValue>(&body.value, "status")?.status {
                    BookingStatus::Cancelled => status = Some(BookingStatus::Cancelled),
                    BookingStatus::Confirmed => {
                        if settled()? {
                            status = status.or(Some(BookingStatus::Confirmed));
                        } else {
                            held_confirmed = true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if status.is_none() && held_confirmed {
        return Err(refused("booking status awaits its owner's confirm"));
    }
    Ok(BookingFacts {
        page_ref: page_ref.ok_or_else(|| refused("booking carries no source page claim"))?,
        event_type: event_type.ok_or_else(|| refused("booking carries no event type claim"))?,
        slot: occurrence_in(vault, rtxn, event_ref)?,
        status: status.ok_or_else(|| refused("booking carries no status claim"))?,
        context: confirmation_context_in(vault, rtxn, event_ref)?,
    })
}

/// The EVENT's stored occurrence, read through the CALLER's transaction.
///
/// Deliberately not `Vault::read_entity_header`: that door opens a transaction
/// of its own, and LMDB gives a thread one read transaction at a time, so a
/// nested read would fail whenever this runs under a caller-owned read txn.
fn occurrence_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<TimeRange, BookingError> {
    let raw = vault
        .store
        .port_entity_record(rtxn, event_ref)
        .map(|row| row.map(|row| row.encode()))
        .map_err(|error| engine_failure("booking event header read", error))?
        .ok_or_else(|| refused("booking EVENT no longer exists"))?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or_else(|| refused("booking EVENT header did not parse"))?;
    Ok(half_open_occurrence(
        header.occurred_start,
        header.occurred_end,
    ))
}

/// Calendar writers may replace this structural body. Authority stays in the
/// immutable confirmation receipt, never in the provider-owned EVENT body.
pub(super) fn encode_event_body(event_type: &EventTypeKey) -> Result<Vec<u8>, BookingError> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![
            (
                rmpv::Value::from("name"),
                rmpv::Value::from(event_type.0.as_str()),
            ),
            (rmpv::Value::from("origin"), rmpv::Value::from("native")),
        ]),
    )
    .map_err(|_| refused("booking event body did not encode"))?;
    Ok(body)
}

/// The `calendar.status` wire map, keyed exactly as CAL-00's decoder reads it.
/// The shared write door validates it, so a misspelled key fails loud.
pub(super) fn calendar_status_value(status: CalendarStatus, recorded_at: u64) -> rmpv::Value {
    rmpv::Value::Map(vec![
        (
            rmpv::Value::from("status"),
            rmpv::Value::from(status.as_str()),
        ),
        (
            rmpv::Value::from("basis"),
            rmpv::Value::from(CalendarStatusBasis::Booking.as_str()),
        ),
        (
            rmpv::Value::from("recorded_at"),
            rmpv::Value::from(recorded_at),
        ),
    ])
}

/// Validates one lifecycle claim body's subject and value shape.
///
/// Exact and structural: an unknown `booking.*` predicate is rejected here
/// rather than accepted as a family member, and every value must match its
/// pinned schema with no extra keys.
///
/// # Errors
///
/// [`crate::Error::InvalidClaimBody`] naming the defect.
pub(super) fn validate_lifecycle_claim(body: &ClaimBody) -> crate::Result<()> {
    let ClaimSubject::Entity(_) = body.subject else {
        return Err(crate::Error::InvalidClaimBody(
            "booking lifecycle claim subject must be an entity",
        ));
    };
    let defect = match body.predicate.as_str() {
        BOOKING_EVENT_TYPE_REF_PREDICATE => claim_value::<BookingEventTypeRefValue>(&body.value)
            .map(|_| ())
            .ok_or("booking.event_type_ref value does not match the pinned schema"),
        BOOKING_BOOKER_CONTACT_PREDICATE => claim_value::<BookingBookerContactValue>(&body.value)
            .map(|_| ())
            .ok_or("booking.booker_contact value does not match the pinned schema"),
        BOOKING_SOURCE_PAGE_PREDICATE => claim_value::<BookingSourcePageValue>(&body.value)
            .map(|_| ())
            .ok_or("booking.source_page value does not match the pinned schema"),
        BOOKING_STATUS_PREDICATE => claim_value::<BookingStatusValue>(&body.value)
            .map(|_| ())
            .ok_or("booking.status value does not match the pinned schema"),
        _ => Err("unknown booking lifecycle claim predicate"),
    };
    defect.map_err(crate::Error::InvalidClaimBody)
}

/// Whether `predicate` belongs to the `booking.*` claim family.
///
/// The family is the UNION of its per-layer exact tables — the host
/// configuration predicate ONE-1823 owns, plus the four lifecycle predicates
/// this layer owns. It is deliberately a table union and never a `booking.`
/// prefix test: a prefix would silently adopt every future booking predicate
/// into whichever validator happened to be checked first.
///
/// It lives here rather than in `booking/mod.rs` because ONE-1816 asserts
/// mechanically that `mod.rs` defines nothing at all; `mod.rs` re-exports this.
#[must_use]
pub fn is_booking_family_claim_predicate(predicate: &str) -> bool {
    crate::booking::config::is_booking_claim_predicate(predicate)
        || is_booking_lifecycle_claim_predicate(predicate)
}

/// Validates one `booking.*` claim body against its own layer's validator.
///
/// This is the booking-family door: it routes on the exact predicate tables, so
/// a body whose predicate is not an exact member of ANY layer's table is
/// rejected here rather than accepted unvalidated.
///
/// # Errors
///
/// [`crate::Error::InvalidClaimBody`] naming the defect.
pub fn validate_booking_family_claim(body: &ClaimBody) -> crate::Result<()> {
    if crate::booking::config::is_booking_claim_predicate(&body.predicate) {
        return crate::booking::config::validate_event_type_claim(body);
    }
    if is_booking_lifecycle_claim_predicate(&body.predicate) {
        return validate_lifecycle_claim(body);
    }
    Err(crate::Error::InvalidClaimBody(
        "unknown booking claim predicate",
    ))
}

/// Every pure-data claim-class descriptor row the `booking.*` family ships.
///
/// The per-layer tables concatenated in family order: host configuration first,
/// then the lifecycle rows.
#[must_use]
pub fn booking_claim_class_descriptors() -> Vec<ClaimClassDescriptorRow> {
    let mut rows = crate::booking::config::claim_class_descriptors();
    rows.extend(claim_class_descriptors());
    rows
}

/// Descriptor rows for the lifecycle family, one per exact predicate.
///
/// All four are `recorded` and `projector_only`: the engine writes them from the
/// home-node transition as facts about a transaction that happened, and no human
/// or agent authors them by hand. No descriptor runtime or registry exists —
/// this is pure data, ready to register when one lands.
#[must_use]
pub fn claim_class_descriptors() -> Vec<ClaimClassDescriptorRow> {
    BOOKING_LIFECYCLE_PREDICATES
        .into_iter()
        .map(|predicate| ClaimClassDescriptorRow {
            predicate,
            write_class: "recorded",
            enforcement: false,
            restrictive: false,
            projector_only: true,
        })
        .collect()
}
