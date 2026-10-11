//! A pending proposal on a booking's EVENT is not the booking's record.

use super::{Fixture, NOW, book, expect_revision, session, slot_of, test_id};
use oneiron::booking::{BOOKING_STATUS_PREDICATE, BookingVerbRequest, CancelSpec, RescheduleSpec};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EntityId, TimeRange,
};
use rmpv::Value;

/// Files a pending `status: cancelled` proposal on `booking`, dated
/// `occurred_at`, under the highest id so it scans last, where an
/// approval-blind reader lets it win.
fn propose_cancelled(fixture: &Fixture, booking: EntityId, occurred_at: u64) {
    let proposal = ClaimBody::new(
        BOOKING_STATUS_PREDICATE,
        ClaimSubject::Entity(booking),
        Value::Map(vec![
            (Value::from("status"), Value::from("cancelled")),
            (Value::from("recorded_at"), Value::from(NOW)),
        ]),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    fixture
        .vault
        .put_claim(
            &test_id(0xF0),
            &proposal,
            TimeRange {
                start: occurred_at,
                end: occurred_at,
            },
            NOW,
        )
        .expect("the proposal is stored pending review");
}

/// A propose-only writer files `status: cancelled` beside the engine's
/// Confirmed head. Until someone approves it, the visitor's reschedule
/// still sees a confirmed booking.
#[test]
fn a_proposed_status_head_does_not_cancel_a_booking_before_approval() {
    let fixture = Fixture::open();
    let slots = fixture.offered_slots();
    let booked = book(&fixture, session(b"proposal"), slot_of(&slots[0]));

    propose_cancelled(&fixture, booked.calendar.event_ref, NOW);

    expect_revision(
        fixture
            .run(
                BookingVerbRequest::Reschedule(RescheduleSpec {
                    token: booked.reschedule_token,
                    new_slot: slot_of(&slots[4]),
                    visitor_tz: "UTC".to_owned(),
                    constraint: None,
                    idempotency_key: None,
                }),
                NOW + 60,
            )
            .expect("reschedule"),
    );
}

/// A pending proposal dated in the future cannot be closed yet. The visitor's
/// cancel replaces only the engine's record, so the proposal never blocks it.
#[test]
fn a_future_dated_proposal_does_not_block_a_cancel() {
    let fixture = Fixture::open();
    let slots = fixture.offered_slots();
    let booked = book(&fixture, session(b"proposal"), slot_of(&slots[0]));
    propose_cancelled(&fixture, booked.calendar.event_ref, NOW + 86_400);

    expect_revision(
        fixture
            .run(
                BookingVerbRequest::Cancel(CancelSpec {
                    token: booked.cancel_token,
                    idempotency_key: None,
                }),
                NOW + 60,
            )
            .expect("cancel"),
    );
}
