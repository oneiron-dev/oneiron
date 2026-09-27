use super::*;

fn id() -> EntityId {
    EntityId::from_bytes([42; 16]).expect("entity")
}

#[test]
fn two_exact_wakes_have_stable_ids_and_replace_on_move() {
    let first = plan_booking_reminders(id(), 200_000, 1);
    assert_eq!(first.len(), 2);
    assert_eq!([first[0].at_utc, first[1].at_utc], [113_600, 192_800]);
    let moved = plan_booking_reminders(id(), 250_000, 1);
    assert_eq!(
        first.iter().map(|wake| &wake.id).collect::<Vec<_>>(),
        moved.iter().map(|wake| &wake.id).collect::<Vec<_>>()
    );
    assert_ne!(first[0].at_utc, moved[0].at_utc);
    assert_eq!(plan_booking_reminders(id(), 200_000, 190_000).len(), 1);
    assert!(plan_booking_reminders(id(), 200_000, 199_999).is_empty());
    assert!(plan_booking_reminders(id(), 60, 0).is_empty());
}

#[test]
fn due_recheck_refuses_cancel_move_premature_and_started_event() {
    let wake = plan_booking_reminders(id(), 200_000, 1).remove(0);
    assert!(booking_reminder_is_due(
        &wake,
        wake.at_utc,
        BookingStatus::Confirmed,
        200_000
    ));
    let mut forged = wake.clone();
    forged.at_utc += 1;
    assert!(!booking_reminder_is_due(
        &forged,
        forged.at_utc,
        BookingStatus::Confirmed,
        200_000
    ));
    assert!(!booking_reminder_is_due(
        &wake,
        wake.at_utc,
        BookingStatus::Cancelled,
        200_000
    ));
    assert!(!booking_reminder_is_due(
        &wake,
        wake.at_utc,
        BookingStatus::Confirmed,
        250_000
    ));
    assert!(!booking_reminder_is_due(
        &wake,
        wake.at_utc - 1,
        BookingStatus::Confirmed,
        200_000
    ));
    assert!(!booking_reminder_is_due(
        &wake,
        200_000,
        BookingStatus::Confirmed,
        200_000
    ));
}

#[test]
fn no_show_history_never_infers_a_miss_from_silence() {
    use EventOutcome::{CancelledPreStart, Held, NoShow, Unknown};
    assert_eq!(
        booking_no_show_escalation(&[Unknown, Held, NoShow, CancelledPreStart]),
        NoShowEscalation::None
    );
    assert_eq!(
        booking_no_show_escalation(&[NoShow, Held, NoShow]),
        NoShowEscalation::OfferConfirmLink
    );
}
