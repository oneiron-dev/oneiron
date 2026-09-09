//! Booking facts on the EVENT: the four exact claims, their writes and
//! supersessions, the family validator, and the claim-class descriptor rows.

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
use crate::calendar::claims::{CalendarStatus, CalendarStatusBasis};
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
    pub booker_ref: String,
    pub visitor_tz: String,
    pub constraint: Option<ConstraintObject>,
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

/// Creates the EVENT and its four exact booking claims.
pub(super) fn write_booking_event(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    event_ref: &EntityId,
    hold: &SoftHoldRow,
    booker_contact: EntityId,
    now_utc: u64,
) -> Result<(), BookingError> {
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
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        predicate,
        ClaimSubject::Entity(*subject),
        value,
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Observed);
    body.valid_from = Some(now_utc);
    vault
        .put_claim_in_txn(wtxn, &id, &body, at(now_utc), now_utc)
        .map_err(|error| engine_failure("booking claim write", error))?;
    Ok(id)
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
    let prior = live_claims_with_predicate(vault, &*wtxn, subject, predicate)?;
    let new_id = put_claim(vault, wtxn, subject, predicate, value, now_utc)?;
    for old_id in prior {
        vault
            .supersede_claim_in_txn(wtxn, &new_id, &old_id, now_utc)
            .map_err(|error| engine_failure("booking claim supersession", error))?;
    }
    Ok(())
}

/// Every live claim on `subject` carrying exactly `predicate`.
fn live_claims_with_predicate(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    subject: &EntityId,
    predicate: &str,
) -> Result<Vec<EntityId>, BookingError> {
    let mut out = Vec::new();
    for claim_id in claims_for_subject(vault, rtxn, subject)? {
        let Ok(Some(body)) = vault.get_claim_in_txn(rtxn, &claim_id) else {
            continue;
        };
        if body.predicate == predicate && body.lifecycle == ClaimLifecycleStatus::Active {
            out.push(claim_id);
        }
    }
    Ok(out)
}

/// Reads the booking facts one EVENT's live claims and structural row carry.
pub(super) fn read_booking_facts(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<BookingFacts, BookingError> {
    let mut page_ref = None;
    let mut event_type = None;
    let mut status = None;
    for claim_id in claims_for_subject(vault, rtxn, event_ref)? {
        let Ok(Some(body)) = vault.get_claim_in_txn(rtxn, &claim_id) else {
            continue;
        };
        if body.lifecycle != ClaimLifecycleStatus::Active {
            continue;
        }
        match body.predicate.as_str() {
            BOOKING_SOURCE_PAGE_PREDICATE => {
                page_ref = Some(
                    decode_claim_value::<BookingSourcePageValue>(&body.value, "source page")?
                        .page_ref,
                );
            }
            BOOKING_EVENT_TYPE_REF_PREDICATE => {
                event_type = Some(
                    decode_claim_value::<BookingEventTypeRefValue>(&body.value, "event type ref")?
                        .event_type,
                );
            }
            BOOKING_STATUS_PREDICATE => {
                status =
                    Some(decode_claim_value::<BookingStatusValue>(&body.value, "status")?.status);
            }
            _ => {}
        }
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
        .entities
        .get(rtxn, event_ref.as_bytes())
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
        &rmpv::Value::Map(vec![(
            rmpv::Value::from("name"),
            rmpv::Value::from(event_type.0.as_str()),
        )]),
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
