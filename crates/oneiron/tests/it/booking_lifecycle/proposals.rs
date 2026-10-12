//! A pending proposal on a booking's EVENT is not the booking's record.

use super::{Fixture, NOW, book, expect_revision, session, slot_of, test_id};
use oneiron::booking::{
    BOOKING_PASSPORT_SYSTEM, BOOKING_STATUS_PREDICATE, BookingVerbRequest, CancelSpec,
    OpaqueLifecycleToken, RescheduleSpec,
};
use oneiron::calendar::claims::PREDICATE_CALENDAR_PASSPORT;
use oneiron::calendar::passport::live_passports_for_event;
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

/// A pending proposal the store can close is closed by the cancel, as before:
/// only one dated in the future is left to its review.
#[test]
fn a_cancel_still_closes_a_proposal_it_can_close() {
    let fixture = Fixture::open();
    let slots = fixture.offered_slots();
    let booked = book(&fixture, session(b"proposal"), slot_of(&slots[0]));
    propose_cancelled(&fixture, booked.calendar.event_ref, NOW);

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
    let proposal = fixture
        .vault
        .get_claim(&test_id(0xF0))
        .expect("claim read")
        .expect("the proposal row stays in history");
    assert_eq!(proposal.lifecycle, ClaimLifecycleStatus::Superseded);
}

/// Files a pending outbound passport for `booking` under an id the vault mints
/// now: it scans after the passport the confirm wrote and before any later
/// revision's, where an approval-blind writer takes it as the head.
fn propose_passport(fixture: &Fixture, booking: EntityId, uid: &str, last_sequence: u32) {
    let proposal = ClaimBody::new(
        PREDICATE_CALENDAR_PASSPORT,
        ClaimSubject::Entity(booking),
        Value::Map(vec![
            (Value::from("system"), Value::from(BOOKING_PASSPORT_SYSTEM)),
            (Value::from("uid"), Value::from(uid)),
            (Value::from("last_sequence"), Value::from(last_sequence)),
            (Value::from("content_hash"), Value::Binary(vec![0xAB; 32])),
            (Value::from("direction"), Value::from("outbound")),
            (Value::from("last_seen_at"), Value::from(NOW)),
            (Value::from("presence"), Value::from("live")),
        ]),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    let id = fixture.vault.new_entity_id().expect("claim id");
    fixture
        .vault
        .put_claim(&id, &proposal, TimeRange { start: NOW, end: NOW }, NOW)
        .expect("the passport proposal is stored pending review");
}

fn reschedule(token: &OpaqueLifecycleToken, new_slot: TimeRange) -> BookingVerbRequest {
    BookingVerbRequest::Reschedule(RescheduleSpec {
        token: token.clone(),
        new_slot,
        visitor_tz: "UTC".to_owned(),
        constraint: None,
        idempotency_key: None,
    })
}

/// A pending passport at the last SEQUENCE a passport can carry does not
/// block the visitor's cancel after a move.
#[test]
fn a_proposed_passport_at_the_last_sequence_does_not_block_a_cancel() {
    let fixture = Fixture::open();
    let slots = fixture.offered_slots();
    let booked = book(&fixture, session(b"proposal"), slot_of(&slots[0]));
    propose_passport(
        &fixture,
        booked.calendar.event_ref,
        &booked.calendar.uid,
        u32::MAX,
    );

    expect_revision(
        fixture
            .run(
                reschedule(&booked.reschedule_token, slot_of(&slots[4])),
                NOW + 60,
            )
            .expect("reschedule"),
    );
    expect_revision(
        fixture
            .run(
                BookingVerbRequest::Cancel(CancelSpec {
                    token: booked.cancel_token,
                    idempotency_key: None,
                }),
                NOW + 120,
            )
            .expect("cancel"),
    );
}

/// A pending passport under another UID at SEQUENCE 99 sets neither the UID
/// nor the SEQUENCE of any amendment after it, and the engine's own passport
/// stays the one live Auto head.
#[test]
fn a_proposed_passport_never_sets_a_revision_uid_or_sequence() {
    let fixture = Fixture::open();
    let slots = fixture.offered_slots();
    let booked = book(&fixture, session(b"proposal"), slot_of(&slots[0]));
    let event = booked.calendar.event_ref;
    propose_passport(&fixture, event, "proposed@example.test", 99);

    for (sequence, index) in [(1_u32, 4), (2, 6)] {
        let revision = expect_revision(
            fixture
                .run(
                    reschedule(&booked.reschedule_token, slot_of(&slots[index])),
                    NOW + 60 * u64::from(sequence),
                )
                .expect("reschedule"),
        );
        assert_eq!(
            (revision.calendar.uid.as_str(), revision.calendar.sequence),
            (booked.calendar.uid.as_str(), sequence),
        );
        let auto: Vec<_> = live_passports_for_event(&fixture.vault, &event)
            .expect("live passports")
            .into_iter()
            .filter(|(id, _)| {
                fixture
                    .vault
                    .get_claim(id)
                    .expect("claim read")
                    .is_some_and(|body| body.approval == ClaimApprovalStatus::Auto)
            })
            .map(|(_, value)| (value.uid, value.last_sequence))
            .collect();
        assert_eq!(auto, [(booked.calendar.uid.clone(), sequence)]);
    }
}
