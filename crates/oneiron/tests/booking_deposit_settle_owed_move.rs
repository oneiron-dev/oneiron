//! FIX [BK-DEPOSIT-SETTLE-OUTAGE-STRANDS-MOVE] (OPUS-SPLIT-5, 16 Nov 2026): a
//! settle row asks again while its deposit owes the move.
//!
//! A settle row is the `booking.deposit.settle` attempt a deposit transition
//! queues (the checkout's start, the confirm, a cancel). It owes the
//! deposit's next provider move: capture, void or refund. A row is queued only
//! on a transition, so a row that ended while its deposit still owed the move
//! left the deposit in `CaptureDue`, `VoidDue` or `RefundDue` with nothing to
//! run it. The row must end only once its deposit owes nothing: a provider
//! refusal and a failing provider past the row's eighth claim queue the same
//! row again an hour later, and the deposit's move lands once the provider
//! answers.
//!
//! One test per move: a capture owed through an outage that outlasts the
//! row's prompt tries, a refund the provider refuses, a void the provider
//! refuses. The provider is a fake settlement port that blocks while its
//! failure is set.
//!
//! The tests name no item the fix added (the drain's `still_owed` counter),
//! so the same file builds on the base (603d35edac24, the head of PR #8231).
//! On the base each test is red by an assertion, not by a compile error: the
//! row failed for good (`failed` is not 0), nothing asked the provider again,
//! and the move never landed.

#[path = "booking_deposit_support/fixture.rs"]
mod fixture;

use fixture::{Fixture, MONDAY, NOW, event_type, slot_of};
use oneiron::booking::lifecycle::{
    BookingDepositSettlementDrain, DepositCheckoutLease, DepositCheckoutStart,
    DepositProviderEvent, DepositProviderEventKind, DepositProviderEventOutcome,
    DepositProviderFailure, DepositSettleMove, DepositSettleRequest, DepositSettleStep,
    DepositSettlementPort, DepositState, begin_deposit_checkout, booking_deposit_for_payment,
    record_deposit_provider_event, run_booking_deposit_settlement, settle_booking_deposit,
};
use oneiron::booking::{
    BookingError, ConfirmReceipt, DepositRefundRule, DepositTerms, HoldLeaseSpec, SessionKey,
};

/// The deposit every test here asks, in minor units of the terms' currency.
const DEPOSIT_AMOUNT_MINOR: u64 = 4_000;

/// The gap between two passes. A settle row waits at most this long before it
/// asks again (300 s after a failed call within its prompt tries, 3_600 s
/// after a refusal or a failing call past them), so a pass this long after
/// the last one claims every row the last one queued again.
const PASS_GAP_SECS: u64 = 3_600;

/// A provider that answers `failure` to every ask while it is set, and
/// otherwise does the move. It counts every ask and records the moves it did.
#[derive(Default)]
struct BlockedProvider {
    failure: Option<DepositProviderFailure>,
    asks: u32,
    done: Vec<(String, DepositSettleMove, String)>,
}

impl DepositSettlementPort for BlockedProvider {
    fn settle(
        &mut self,
        request: &DepositSettleRequest<'_>,
    ) -> Result<u64, DepositProviderFailure> {
        self.asks += 1;
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        self.done.push((
            request.payment_id.to_owned(),
            request.movement,
            request.idempotency_key.to_owned(),
        ));
        Ok(match request.movement {
            DepositSettleMove::Capture { amount_minor }
            | DepositSettleMove::Refund { amount_minor } => amount_minor,
            DepositSettleMove::Void => 0,
        })
    }
}

/// The moves the provider did, in order.
fn moves_done(provider: &BlockedProvider) -> Vec<DepositSettleMove> {
    provider
        .done
        .iter()
        .map(|(_, movement, _)| *movement)
        .collect()
}

/// Full refund at least two hours ahead, nothing later.
fn two_hour_terms() -> DepositTerms {
    DepositTerms {
        amount_minor: DEPOSIT_AMOUNT_MINOR,
        currency: "usd".to_owned(),
        refund: DepositRefundRule {
            full_refund_notice_secs: 2 * 3_600,
            late_cancel_refund_percent: 0,
        },
    }
}

fn checkout(
    fixture: &Fixture,
    session: SessionKey,
    payment_id: &str,
    now: u64,
) -> Result<DepositCheckoutLease, BookingError> {
    begin_deposit_checkout(
        &fixture.vault,
        &DepositCheckoutStart {
            page_ref: fixture.page,
            event_type: event_type(),
            session_key: session,
            terms: fixture.config.deposit.clone().expect("a deposit fixture"),
            payment_id: payment_id.to_owned(),
        },
        now,
    )
}

fn provider_event(
    fixture: &Fixture,
    event_id: &str,
    payment_id: &str,
    kind: DepositProviderEventKind,
    now: u64,
) -> DepositProviderEventOutcome {
    record_deposit_provider_event(
        &fixture.vault,
        &DepositProviderEvent {
            event_id: event_id.to_owned(),
            payment_id: payment_id.to_owned(),
            kind,
        },
        now,
    )
    .expect("record the provider event")
}

fn authorized(fixture: &Fixture) -> DepositProviderEventKind {
    let terms = fixture.config.deposit.clone().expect("a deposit fixture");
    DepositProviderEventKind::Authorized {
        amount_minor: terms.amount_minor,
        currency: terms.currency,
    }
}

fn lease_spec(lease: &DepositCheckoutLease) -> HoldLeaseSpec {
    HoldLeaseSpec::CheckoutExtension {
        server_issued_lease: lease.lease.clone(),
    }
}

fn state_of(fixture: &Fixture, payment_id: &str) -> DepositState {
    booking_deposit_for_payment(&fixture.vault, payment_id)
        .expect("read the deposit")
        .expect("the deposit exists")
        .state
}

/// One settle pass at `now`, as the server's worker runs it.
fn drain(
    fixture: &Fixture,
    provider: &mut BlockedProvider,
    now: u64,
) -> BookingDepositSettlementDrain {
    run_booking_deposit_settlement(&fixture.vault, "deposit-settle-worker", provider, 16, now)
        .expect("drain the settle rows")
}

/// Checkout, hold on the lease, the provider's authorization, confirm, for
/// the slot that starts at `hour` UTC on the fixture Monday.
fn paid_booking(
    fixture: &Fixture,
    session: SessionKey,
    payment_id: &str,
    hour: u64,
) -> ConfirmReceipt {
    let slot = fixture
        .offered_slots()
        .into_iter()
        .find(|slot| slot.start_utc == MONDAY + hour * 3_600)
        .expect("the fixture offers the slot");
    let lease = checkout(fixture, session, payment_id, NOW).expect("checkout");
    let hold = fixture
        .hold(session, slot_of(&slot), lease_spec(&lease), NOW)
        .expect("hold on the checkout lease");
    let event = format!("evt-auth-{payment_id}");
    assert_eq!(
        provider_event(fixture, &event, payment_id, authorized(fixture), NOW + 30),
        DepositProviderEventOutcome::Applied(DepositState::Authorized)
    );
    fixture
        .confirm(&hold, session, NOW + 40)
        .expect("confirm on the authorized deposit")
}

/// One pass at `at` while the provider blocks the move the deposit owes: the
/// pass fails no row for good, a live row asks the provider again, and the
/// deposit still owes the same move. `pass_number` names the pass in each
/// message.
fn assert_blocked_pass_keeps_move_owed(
    fixture: &Fixture,
    provider: &mut BlockedProvider,
    payment_id: &str,
    owed: DepositState,
    pass_number: u64,
    at: u64,
) {
    let asks_before = provider.asks;
    let pass = drain(fixture, provider, at);
    assert_eq!(
        pass.failed, 0,
        "pass {pass_number}: no row fails for good while its deposit owes the move"
    );
    assert!(
        provider.asks > asks_before,
        "pass {pass_number}: a live row asked the provider again"
    );
    assert_eq!(
        state_of(fixture, payment_id),
        owed,
        "pass {pass_number}: the deposit still owes its move"
    );
}

#[test]
fn a_capture_owed_through_an_outage_past_its_prompt_tries_lands_once_the_provider_answers() {
    let fixture = Fixture::open(Some(two_hour_terms()));
    // The confirm makes the capture due. The server's own capture right after
    // it is not run here, so the capture is owed to the settle rows alone: the
    // checkout's row and the confirm's.
    paid_booking(
        &fixture,
        SessionKey::derive(b"owed-capture"),
        "pi_owed_capture",
        12,
    );
    let owed = DepositState::CaptureDue {
        amount_minor: DEPOSIT_AMOUNT_MINOR,
    };
    assert_eq!(
        state_of(&fixture, "pi_owed_capture"),
        owed,
        "the confirm leaves the capture owed"
    );

    // An outage far longer than a row's eight prompt tries: ten passes an
    // hour apart, every ask unanswered.
    let mut provider = BlockedProvider {
        failure: Some(DepositProviderFailure::Transient(
            "the provider is unreachable".to_owned(),
        )),
        ..BlockedProvider::default()
    };
    for pass in 1..=10 {
        assert_blocked_pass_keeps_move_owed(
            &fixture,
            &mut provider,
            "pi_owed_capture",
            owed,
            pass,
            NOW + pass * PASS_GAP_SECS,
        );
    }
    assert!(
        moves_done(&provider).is_empty(),
        "the provider did no move during the outage"
    );

    // The outage ends: the next pass makes the capture.
    provider.failure = None;
    let landing = drain(&fixture, &mut provider, NOW + 11 * PASS_GAP_SECS);
    assert_eq!(
        landing.captured, 1,
        "the owed capture lands once the provider answers"
    );
    assert_eq!(landing.failed, 0, "the landing pass fails no row");
    assert_eq!(
        state_of(&fixture, "pi_owed_capture"),
        DepositState::Captured {
            amount_minor: DEPOSIT_AMOUNT_MINOR
        }
    );
    let capture = DepositSettleMove::Capture {
        amount_minor: DEPOSIT_AMOUNT_MINOR,
    };
    assert_eq!(moves_done(&provider), vec![capture]);

    // Once the deposit owes nothing, the rows end and ask no more.
    let after = drain(&fixture, &mut provider, NOW + 12 * PASS_GAP_SECS);
    assert_eq!(after.failed, 0, "a settled deposit fails no row");
    assert_eq!(
        moves_done(&provider),
        vec![capture],
        "the capture is made exactly once"
    );
}

#[test]
fn a_refund_the_provider_refuses_stays_owed_and_lands_once_the_provider_takes_it() {
    let fixture = Fixture::open(Some(two_hour_terms()));
    let mut provider = BlockedProvider::default();

    // 12:00 start, cancelled at 08:01: four hours ahead, a full refund.
    let booked = paid_booking(
        &fixture,
        SessionKey::derive(b"refused-refund"),
        "pi_refused_refund",
        12,
    );
    assert_eq!(
        settle_booking_deposit(
            &fixture.vault,
            &booked.calendar.event_ref,
            &mut provider,
            NOW + 50
        )
        .expect("capture"),
        DepositSettleStep::Moved(DepositSettleMove::Capture {
            amount_minor: DEPOSIT_AMOUNT_MINOR
        })
    );
    // The checkout's and the confirm's rows find nothing more to do.
    drain(&fixture, &mut provider, NOW + 55);
    fixture
        .cancel(&booked.cancel_token, NOW + 60)
        .expect("cancel");
    let owed = DepositState::RefundDue {
        amount_minor: DEPOSIT_AMOUNT_MINOR,
    };
    assert_eq!(state_of(&fixture, "pi_refused_refund"), owed);

    // The provider refuses the refund itself (a key without the permission),
    // three passes in a row.
    provider.failure = Some(DepositProviderFailure::Permanent(
        "the key may not refund".to_owned(),
    ));
    for pass in 1..=3 {
        assert_blocked_pass_keeps_move_owed(
            &fixture,
            &mut provider,
            "pi_refused_refund",
            owed,
            pass,
            NOW + pass * PASS_GAP_SECS,
        );
    }

    // The owner repairs the key: the next pass makes the refund.
    provider.failure = None;
    let landing = drain(&fixture, &mut provider, NOW + 4 * PASS_GAP_SECS);
    assert_eq!(
        landing.refunded, 1,
        "the owed refund lands once the provider takes it"
    );
    assert_eq!(landing.failed, 0, "the landing pass fails no row");
    assert_eq!(
        state_of(&fixture, "pi_refused_refund"),
        DepositState::Refunded {
            amount_minor: DEPOSIT_AMOUNT_MINOR
        }
    );
    assert_eq!(
        moves_done(&provider),
        vec![
            DepositSettleMove::Capture {
                amount_minor: DEPOSIT_AMOUNT_MINOR
            },
            DepositSettleMove::Refund {
                amount_minor: DEPOSIT_AMOUNT_MINOR
            }
        ],
        "the refund is made exactly once"
    );
}

#[test]
fn a_void_the_provider_refuses_stays_owed_and_lands_once_the_provider_takes_it() {
    let fixture = Fixture::open(Some(two_hour_terms()));
    let slots = fixture.offered_slots();
    let session = SessionKey::derive(b"refused-void");

    // The visitor pays and never confirms: the checkout window ends with the
    // deposit authorized and unconfirmed.
    let lease = checkout(&fixture, session, "pi_refused_void", NOW).expect("checkout");
    fixture
        .hold(session, slot_of(&slots[1]), lease_spec(&lease), NOW)
        .expect("hold");
    assert_eq!(
        provider_event(
            &fixture,
            "evt_refused_void",
            "pi_refused_void",
            authorized(&fixture),
            NOW + 30
        ),
        DepositProviderEventOutcome::Applied(DepositState::Authorized)
    );

    // The first pass is at the window's end: it turns the deposit void-due and
    // asks for the void, which the provider refuses (a key without the
    // permission). Three passes in a row.
    let mut provider = BlockedProvider {
        failure: Some(DepositProviderFailure::Permanent(
            "the key may not cancel".to_owned(),
        )),
        ..BlockedProvider::default()
    };
    for pass in 1..=3 {
        assert_blocked_pass_keeps_move_owed(
            &fixture,
            &mut provider,
            "pi_refused_void",
            DepositState::VoidDue,
            pass,
            lease.expires_at + (pass - 1) * PASS_GAP_SECS,
        );
    }
    assert!(
        moves_done(&provider).is_empty(),
        "the provider did no move while it refused"
    );

    // The owner repairs the key: the next pass makes the void.
    provider.failure = None;
    let landing = drain(
        &fixture,
        &mut provider,
        lease.expires_at + 3 * PASS_GAP_SECS,
    );
    assert_eq!(
        landing.voided, 1,
        "the owed void lands once the provider takes it"
    );
    assert_eq!(landing.failed, 0, "the landing pass fails no row");
    assert_eq!(state_of(&fixture, "pi_refused_void"), DepositState::Voided);
    assert_eq!(
        moves_done(&provider),
        vec![DepositSettleMove::Void],
        "the void is made exactly once"
    );
}
