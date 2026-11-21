//! BK-DEPOSITS PR 2: a deposit event type confirms only on an authorized
//! deposit (Engine ruling, Sun 15 Nov 01:10: authorize at hold, capture at
//! confirm).
//!
//! Only paths of PR 1 are named here, so PR 1 plus this file builds for the
//! red run: there the ordinary hold of a deposit event type confirms, and the
//! first test fails by its assert.

#[path = "booking_deposit_support/fixture.rs"]
mod fixture;

use fixture::{Fixture, NOW, slot_of};
use oneiron::booking::{BookingError, DepositRefundRule, DepositTerms, HoldLeaseSpec, SessionKey};

fn terms() -> DepositTerms {
    DepositTerms {
        amount_minor: 5_000,
        currency: "jpy".to_owned(),
        refund: DepositRefundRule::default(),
    }
}

#[test]
fn a_deposit_event_type_refuses_confirm_without_an_authorized_deposit() {
    let fixture = Fixture::open(Some(terms()));
    let slots = fixture.offered_slots();
    let session = SessionKey::derive(b"deposit-gate");
    let hold = fixture
        .hold(session, slot_of(&slots[0]), HoldLeaseSpec::Ordinary, NOW)
        .expect("an ordinary hold of a deposit event type is taken");

    let confirmed = fixture.confirm(&hold, session, NOW + 60);
    assert!(
        matches!(
            &confirmed,
            Err(BookingError::InvalidConstraint(reason)) if reason.contains("deposit")
        ),
        "a deposit event type must not confirm before its deposit is authorized; got {confirmed:?}"
    );

    // The refusal wrote nothing: the slot is still this session's hold, so
    // every other visitor sees it taken, and this one may still pay.
    assert!(
        fixture
            .offered_slots()
            .iter()
            .all(|slot| slot.start_utc != slots[0].start_utc),
        "the refused confirm keeps the session's hold on its slot"
    );
}

#[test]
fn an_event_type_without_a_deposit_confirms_as_before() {
    let fixture = Fixture::open(None);
    let slots = fixture.offered_slots();
    let session = SessionKey::derive(b"no-deposit");
    let hold = fixture
        .hold(session, slot_of(&slots[0]), HoldLeaseSpec::Ordinary, NOW)
        .expect("hold");
    fixture
        .confirm(&hold, session, NOW + 60)
        .expect("an event type with no deposit confirms on its hold alone");
}
