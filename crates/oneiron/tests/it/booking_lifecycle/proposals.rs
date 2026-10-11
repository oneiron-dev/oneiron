//! A pending proposal on a booking's EVENT is not the booking's record.

use super::{Fixture, NOW, book, expect_revision, session, slot_of, test_id};
use oneiron::booking::{BOOKING_STATUS_PREDICATE, BookingVerbRequest, RescheduleSpec};
use oneiron::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, TimeRange};
use rmpv::Value;

/// A propose-only writer files `status: cancelled` beside the engine's
/// Confirmed head. Until someone approves it, the visitor's reschedule
/// still sees a confirmed booking.
#[test]
fn a_proposed_status_head_does_not_cancel_a_booking_before_approval() {
    let fixture = Fixture::open();
    let slots = fixture.offered_slots();
    let booked = book(&fixture, session(b"proposal"), slot_of(&slots[0]));

    let proposal = ClaimBody::new(
        BOOKING_STATUS_PREDICATE,
        ClaimSubject::Entity(booked.calendar.event_ref),
        Value::Map(vec![
            (Value::from("status"), Value::from("cancelled")),
            (Value::from("recorded_at"), Value::from(NOW)),
        ]),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    // The highest id scans last, where an approval-blind reader lets it win.
    fixture
        .vault
        .put_claim(
            &test_id(0xF0),
            &proposal,
            TimeRange {
                start: NOW,
                end: NOW,
            },
            NOW,
        )
        .expect("the proposal is stored pending review");

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
