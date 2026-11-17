//! BK-DEPOSITS PR 2: one deposit's payment from checkout to settlement
//! (Engine ruling, Sun 15 Nov 01:10): the checkout lease binds the session
//! and the provider payment and extends the hold to the checkout window; the
//! confirm waits for the provider's authorization and makes the capture due;
//! an unconfirmed deposit is voided when its window ends; a refused card
//! keeps the hold for a retry; a visitor's cancel refunds by the terms. A
//! capture whose reply was lost, a refund the provider holds pending, and a
//! host cancel stopped before its refund commits each still end with the
//! visitor's money back (Astra money review, 15 Nov).
//!
//! The provider is a recording fake of the settlement port. The deposit
//! doors are new, so PR 1 cannot build this file: its red is the missing
//! item. The assert-red half is `booking_deposit_confirm_gate.rs`.

#[path = "booking_deposit_support/fixture.rs"]
mod fixture;

use std::sync::Mutex;

use fixture::{Fixture, MONDAY, NOW, event_type, slot_of};
use oneiron::booking::lifecycle::{
    BookingDepositSettlementDrain, DEPOSIT_CHECKOUT_WINDOW_SECS, DepositCheckoutLease,
    DepositCheckoutStart, DepositProviderEvent, DepositProviderEventKind,
    DepositProviderEventOutcome, DepositProviderFailure, DepositSettleMove, DepositSettleRequest,
    DepositSettleStep, DepositSettlementPort, DepositState, begin_deposit_checkout,
    booking_deposit_for_event, booking_deposit_for_payment, booking_deposit_for_session_hold,
    record_deposit_provider_event, run_booking_deposit_settlement, settle_booking_deposit,
};
use oneiron::booking::{
    BookingError, ConfirmReceipt, DepositRefundRule, DepositTerms, EventTypeKey, HoldLeaseSpec,
    SessionKey,
};
use oneiron::calendar::CalendarError;
use oneiron::calendar::ingest::{
    IcsFeedFetcher, IcsFeedPollConfig, IcsFetchResponse, run_ics_feed_poll,
};

/// A provider that does every move and records each call.
#[derive(Default)]
struct RecordingProvider {
    calls: Vec<(String, DepositSettleMove, String)>,
    fail_next: Option<DepositProviderFailure>,
}

impl DepositSettlementPort for RecordingProvider {
    fn settle(
        &mut self,
        request: &DepositSettleRequest<'_>,
    ) -> Result<u64, DepositProviderFailure> {
        if let Some(failure) = self.fail_next.take() {
            return Err(failure);
        }
        self.calls.push((
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

/// A provider whose capture call lets `during_capture` run first: a cancel
/// landing while the capture is on the wire.
struct OvertakenProvider<'a> {
    recorded: RecordingProvider,
    during_capture: Option<Box<dyn FnMut() + 'a>>,
}

impl DepositSettlementPort for OvertakenProvider<'_> {
    fn settle(
        &mut self,
        request: &DepositSettleRequest<'_>,
    ) -> Result<u64, DepositProviderFailure> {
        if matches!(request.movement, DepositSettleMove::Capture { .. })
            && let Some(mut during) = self.during_capture.take()
        {
            during();
        }
        self.recorded.settle(request)
    }
}

/// A provider whose first capture is taken while its reply is lost: the
/// payment stands captured, and the caller hears a timeout. A later void
/// finds the capture and answers it, as the server's Stripe port does.
#[derive(Default)]
struct LostCaptureReplyProvider {
    captured: u64,
    recorded: RecordingProvider,
}

impl DepositSettlementPort for LostCaptureReplyProvider {
    fn settle(
        &mut self,
        request: &DepositSettleRequest<'_>,
    ) -> Result<u64, DepositProviderFailure> {
        match request.movement {
            DepositSettleMove::Capture { amount_minor } if self.captured == 0 => {
                self.captured = amount_minor;
                Err(DepositProviderFailure::Transient(
                    "the capture's reply was lost".to_owned(),
                ))
            }
            DepositSettleMove::Void if self.captured > 0 => {
                self.recorded.calls.push((
                    request.payment_id.to_owned(),
                    request.movement,
                    request.idempotency_key.to_owned(),
                ));
                Ok(self.captured)
            }
            _ => self.recorded.settle(request),
        }
    }
}

/// A provider that holds a refund pending for its first `pending` asks.
struct PendingRefundProvider {
    pending: u32,
    recorded: RecordingProvider,
}

impl DepositSettlementPort for PendingRefundProvider {
    fn settle(
        &mut self,
        request: &DepositSettleRequest<'_>,
    ) -> Result<u64, DepositProviderFailure> {
        if matches!(request.movement, DepositSettleMove::Refund { .. }) && self.pending > 0 {
            self.pending -= 1;
            return Err(DepositProviderFailure::Pending(
                "the refund is pending at the provider".to_owned(),
            ));
        }
        self.recorded.settle(request)
    }
}

/// Full refund at least two hours ahead, nothing later.
fn two_hour_terms() -> DepositTerms {
    DepositTerms {
        amount_minor: 4_000,
        currency: "usd".to_owned(),
        refund: DepositRefundRule {
            full_refund_notice_secs: 2 * 3_600,
            late_cancel_refund_percent: 0,
        },
    }
}

fn yen_terms() -> DepositTerms {
    DepositTerms {
        amount_minor: 5_000,
        currency: "jpy".to_owned(),
        refund: DepositRefundRule::default(),
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

fn drain<P: DepositSettlementPort>(
    fixture: &Fixture,
    provider: &mut P,
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

#[test]
fn deposit_hold_reaches_the_checkout_window_and_confirm_waits_for_authorization() {
    let fixture = Fixture::open(Some(yen_terms()));
    let slots = fixture.offered_slots();
    let session = SessionKey::derive(b"deposit-happy");

    let lease = checkout(&fixture, session, "pi_test_happy", NOW).expect("checkout");
    assert_eq!(lease.expires_at, NOW + DEPOSIT_CHECKOUT_WINDOW_SECS);
    let hold = fixture
        .hold(session, slot_of(&slots[0]), lease_spec(&lease), NOW)
        .expect("hold on the checkout lease");
    assert_eq!(
        hold.expires_at,
        NOW + DEPOSIT_CHECKOUT_WINDOW_SECS,
        "the payment's lease extends the hold to the checkout window"
    );

    let early = fixture.confirm(&hold, session, NOW + 20);
    assert!(
        matches!(&early, Err(BookingError::InvalidConstraint(reason)) if reason.contains("deposit")),
        "confirm before the provider's authorization is refused; got {early:?}"
    );

    assert_eq!(
        provider_event(
            &fixture,
            "evt_1",
            "pi_test_happy",
            authorized(&fixture),
            NOW + 30
        ),
        DepositProviderEventOutcome::Applied(DepositState::Authorized)
    );
    assert_eq!(
        provider_event(
            &fixture,
            "evt_1",
            "pi_test_happy",
            authorized(&fixture),
            NOW + 31
        ),
        DepositProviderEventOutcome::Replayed,
        "a redelivered provider event applies once"
    );

    let booked = fixture
        .confirm(&hold, session, NOW + 40)
        .expect("confirm on the authorized deposit");
    let status = booking_deposit_for_event(&fixture.vault, &booked.calendar.event_ref)
        .expect("read")
        .expect("the booking names its deposit");
    assert_eq!(
        status.state,
        DepositState::CaptureDue {
            amount_minor: 5_000
        }
    );
    assert_eq!(status.event_ref, Some(booked.calendar.event_ref));

    // The server's capture right after the confirm.
    let mut provider = RecordingProvider::default();
    assert_eq!(
        settle_booking_deposit(
            &fixture.vault,
            &booked.calendar.event_ref,
            &mut provider,
            NOW + 41
        )
        .expect("settle"),
        DepositSettleStep::Moved(DepositSettleMove::Capture {
            amount_minor: 5_000
        })
    );
    assert_eq!(
        state_of(&fixture, "pi_test_happy"),
        DepositState::Captured {
            amount_minor: 5_000
        }
    );

    // The queued rows (the window's end and the capture) find nothing owed.
    let pass = drain(
        &fixture,
        &mut provider,
        NOW + DEPOSIT_CHECKOUT_WINDOW_SECS + 1,
    );
    assert_eq!(pass.captured, 0);
    assert_eq!(pass.voided, 0);
    assert_eq!(pass.settled_nothing, 2);
    assert_eq!(
        provider.calls.len(),
        1,
        "the deposit is captured exactly once"
    );
    let (payment, movement, key) = &provider.calls[0];
    assert_eq!(payment, "pi_test_happy");
    assert_eq!(
        *movement,
        DepositSettleMove::Capture {
            amount_minor: 5_000
        }
    );
    assert!(
        key.contains("capture"),
        "the provider call carries its idempotency key: {key}"
    );
}

#[test]
fn an_unconfirmed_deposit_is_voided_when_its_window_ends() {
    let fixture = Fixture::open(Some(yen_terms()));
    let slots = fixture.offered_slots();
    let session = SessionKey::derive(b"deposit-abandoned");
    let lease = checkout(&fixture, session, "pi_test_abandoned", NOW).expect("checkout");
    fixture
        .hold(session, slot_of(&slots[1]), lease_spec(&lease), NOW)
        .expect("hold");
    provider_event(
        &fixture,
        "evt_a1",
        "pi_test_abandoned",
        authorized(&fixture),
        NOW + 30,
    );

    let mut provider = RecordingProvider::default();
    let early = drain(&fixture, &mut provider, NOW + 60);
    assert_eq!(
        early.waiting, 1,
        "inside its window the deposit waits for its end"
    );
    assert!(provider.calls.is_empty());

    let late = drain(&fixture, &mut provider, lease.expires_at);
    assert_eq!(
        late.voided, 1,
        "the window's end voids the unconfirmed authorization"
    );
    assert_eq!(provider.calls.len(), 1);
    assert_eq!(provider.calls[0].1, DepositSettleMove::Void);
    assert_eq!(
        state_of(&fixture, "pi_test_abandoned"),
        DepositState::Voided
    );

    assert!(
        checkout(&fixture, session, "pi_test_abandoned", lease.expires_at + 1).is_err(),
        "a voided payment opens no new checkout"
    );
}

#[test]
fn a_refused_card_keeps_the_hold_for_a_retry() {
    let fixture = Fixture::open(Some(yen_terms()));
    let slots = fixture.offered_slots();
    let session = SessionKey::derive(b"deposit-retry");
    let lease = checkout(&fixture, session, "pi_test_retry", NOW).expect("checkout");
    let hold = fixture
        .hold(session, slot_of(&slots[2]), lease_spec(&lease), NOW)
        .expect("hold");

    assert_eq!(
        provider_event(
            &fixture,
            "evt_r1",
            "pi_test_retry",
            DepositProviderEventKind::AuthorizationFailed {
                reason: "card_declined".to_owned()
            },
            NOW + 30,
        ),
        DepositProviderEventOutcome::Applied(DepositState::AuthorizationFailed)
    );
    let waiting = booking_deposit_for_session_hold(&fixture.vault, &session, NOW + 60)
        .expect("read")
        .expect("the live hold still waits on its deposit");
    assert_eq!(waiting.state, DepositState::AuthorizationFailed);
    assert_eq!(waiting.failure.as_deref(), Some("card_declined"));
    assert!(fixture.confirm(&hold, session, NOW + 61).is_err());

    assert_eq!(
        provider_event(
            &fixture,
            "evt_r2",
            "pi_test_retry",
            authorized(&fixture),
            NOW + 90
        ),
        DepositProviderEventOutcome::Applied(DepositState::Authorized),
        "a second card on the same payment authorizes it"
    );
    fixture
        .confirm(&hold, session, NOW + 100)
        .expect("the retried payment confirms the same hold");
}

#[test]
fn a_visitor_cancel_refunds_by_the_terms() {
    let terms = DepositTerms {
        amount_minor: 4_000,
        currency: "usd".to_owned(),
        refund: DepositRefundRule {
            full_refund_notice_secs: 2 * 3_600,
            late_cancel_refund_percent: 25,
        },
    };
    let fixture = Fixture::open(Some(terms));
    let mut provider = RecordingProvider::default();

    // 12:00 start, cancelled at 08:01: four hours ahead, a full refund.
    let early = paid_booking(
        &fixture,
        SessionKey::derive(b"refund-early"),
        "pi_early",
        12,
    );
    settle_booking_deposit(
        &fixture.vault,
        &early.calendar.event_ref,
        &mut provider,
        NOW + 50,
    )
    .expect("capture");
    fixture
        .cancel(&early.cancel_token, NOW + 60)
        .expect("cancel");
    assert_eq!(
        state_of(&fixture, "pi_early"),
        DepositState::RefundDue {
            amount_minor: 4_000
        }
    );

    // 09:00 start, cancelled at 08:01: under two hours ahead, 25 percent.
    let late = paid_booking(&fixture, SessionKey::derive(b"refund-late"), "pi_late", 9);
    settle_booking_deposit(
        &fixture.vault,
        &late.calendar.event_ref,
        &mut provider,
        NOW + 50,
    )
    .expect("capture");
    fixture
        .cancel(&late.cancel_token, NOW + 60)
        .expect("cancel");
    assert_eq!(
        state_of(&fixture, "pi_late"),
        DepositState::RefundDue {
            amount_minor: 1_000
        }
    );

    // 13:00 start, cancelled before its capture ran: the authorization is
    // released, nothing is captured.
    let uncaptured = paid_booking(
        &fixture,
        SessionKey::derive(b"refund-uncaptured"),
        "pi_uncaptured",
        13,
    );
    fixture
        .cancel(&uncaptured.cancel_token, NOW + 60)
        .expect("cancel");
    assert_eq!(state_of(&fixture, "pi_uncaptured"), DepositState::VoidDue);

    let pass = drain(&fixture, &mut provider, NOW + 70);
    assert_eq!(pass.refunded, 2);
    assert_eq!(pass.voided, 1);
    assert_eq!(
        pass.captured, 0,
        "the cancelled booking's capture never runs"
    );
    assert_eq!(
        state_of(&fixture, "pi_early"),
        DepositState::Refunded {
            amount_minor: 4_000
        }
    );
    assert_eq!(
        state_of(&fixture, "pi_late"),
        DepositState::Refunded {
            amount_minor: 1_000
        }
    );
    assert_eq!(state_of(&fixture, "pi_uncaptured"), DepositState::Voided);
    let moves_of = |payment: &str| -> Vec<DepositSettleMove> {
        provider
            .calls
            .iter()
            .filter(|(id, _, _)| id == payment)
            .map(|(_, movement, _)| *movement)
            .collect()
    };
    assert_eq!(
        moves_of("pi_early"),
        vec![
            DepositSettleMove::Capture {
                amount_minor: 4_000
            },
            DepositSettleMove::Refund {
                amount_minor: 4_000
            }
        ]
    );
    assert_eq!(
        moves_of("pi_late"),
        vec![
            DepositSettleMove::Capture {
                amount_minor: 4_000
            },
            DepositSettleMove::Refund {
                amount_minor: 1_000
            }
        ]
    );
    assert_eq!(moves_of("pi_uncaptured"), vec![DepositSettleMove::Void]);
}

#[test]
fn a_lease_or_event_of_another_checkout_changes_nothing() {
    let fixture = Fixture::open(Some(yen_terms()));
    let slots = fixture.offered_slots();
    let session = SessionKey::derive(b"deposit-owner");
    let lease = checkout(&fixture, session, "pi_test_bound", NOW).expect("checkout");

    // The payment is this session's: another session cannot reopen it.
    assert!(
        checkout(
            &fixture,
            SessionKey::derive(b"deposit-thief"),
            "pi_test_bound",
            NOW + 5
        )
        .is_err(),
        "a payment of another session opens no checkout"
    );
    // Terms other than the configured deposit open no checkout.
    let cheaper = begin_deposit_checkout(
        &fixture.vault,
        &DepositCheckoutStart {
            page_ref: fixture.page,
            event_type: event_type(),
            session_key: session,
            terms: DepositTerms {
                amount_minor: 1,
                ..yen_terms()
            },
            payment_id: "pi_test_cheap".to_owned(),
        },
        NOW,
    );
    assert!(
        cheaper.is_err(),
        "checkout terms must be the configured deposit"
    );

    // The lease extends no hold of another event type.
    let other_type = fixture.hold_type(
        session,
        EventTypeKey("other-type".to_owned()),
        slot_of(&slots[3]),
        lease_spec(&lease),
        NOW,
    );
    assert!(
        matches!(&other_type, Err(BookingError::InvalidConstraint(reason)) if reason.contains("another event type")),
        "a deposit lease is bound to its event type; got {other_type:?}"
    );

    // An authorization for another amount does not authorize the deposit.
    assert_eq!(
        provider_event(
            &fixture,
            "evt_b1",
            "pi_test_bound",
            DepositProviderEventKind::Authorized {
                amount_minor: 4_999,
                currency: "jpy".to_owned()
            },
            NOW + 30,
        ),
        DepositProviderEventOutcome::TermsMismatch
    );
    assert_eq!(
        state_of(&fixture, "pi_test_bound"),
        DepositState::AwaitingAuthorization
    );
    let hold = fixture
        .hold(session, slot_of(&slots[3]), lease_spec(&lease), NOW + 35)
        .expect("hold");
    assert!(fixture.confirm(&hold, session, NOW + 40).is_err());

    // A provider event about a payment no deposit has writes nothing.
    assert_eq!(
        provider_event(
            &fixture,
            "evt_x",
            "pi_someone_else",
            authorized(&fixture),
            NOW + 45
        ),
        DepositProviderEventOutcome::UnknownPayment
    );

    // A transient provider failure runs again later and settles then.
    let mut provider = RecordingProvider {
        fail_next: Some(DepositProviderFailure::Transient("timeout".to_owned())),
        ..RecordingProvider::default()
    };
    let first = drain(&fixture, &mut provider, lease.expires_at);
    assert_eq!(first.retrying, 1);
    assert_eq!(state_of(&fixture, "pi_test_bound"), DepositState::VoidDue);
    let second = drain(&fixture, &mut provider, lease.expires_at + 301);
    assert_eq!(second.voided, 1);
    assert_eq!(state_of(&fixture, "pi_test_bound"), DepositState::Voided);
}

/// The host's own calendar, as its feed system names it.
const HOST_FEED_SYSTEM: &str = "host-calendar";

/// A fetcher that answers one scripted response.
struct ScriptedFeed(Mutex<Option<IcsFetchResponse>>);

impl IcsFeedFetcher for ScriptedFeed {
    fn fetch(
        &self,
        _secret_ref: &str,
        _if_none_match: Option<&str>,
    ) -> Result<IcsFetchResponse, CalendarError> {
        self.0
            .lock()
            .expect("scripted response")
            .take()
            .ok_or_else(|| CalendarError::IcsFetch {
                reason: "the scripted feed has no response left".to_owned(),
            })
    }
}

/// A UTC instant on the fixture Monday as an ICS DATE-TIME.
fn ics_utc(ts: u64) -> String {
    let secs = ts - MONDAY;
    format!(
        "20260302T{:02}{:02}{:02}Z",
        secs / 3_600,
        secs / 60 % 60,
        secs % 60
    )
}

/// The host's feed with each booking at its slot, cancelled or not.
fn poll_host_feed(
    fixture: &Fixture,
    bookings: &[(&ConfirmReceipt, u64)],
    cancelled: bool,
    etag: &str,
    now: u64,
) {
    poll_host_feed_at(
        fixture,
        bookings,
        u32::from(cancelled),
        cancelled,
        etag,
        now,
    )
    .expect("host feed poll");
}

/// One poll of the host's feed with each booking at its slot and at
/// `sequence`, cancelled or not.
fn poll_host_feed_at(
    fixture: &Fixture,
    bookings: &[(&ConfirmReceipt, u64)],
    sequence: u32,
    cancelled: bool,
    etag: &str,
    now: u64,
) -> Result<(), CalendarError> {
    let mut body =
        String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n");
    for (booked, start) in bookings {
        body.push_str("BEGIN:VEVENT\r\n");
        body.push_str(&format!("UID:{}\r\n", booked.calendar.uid));
        body.push_str("DTSTAMP:20260302T070000Z\r\n");
        body.push_str(&format!("DTSTART:{}\r\n", ics_utc(*start)));
        body.push_str(&format!("DTEND:{}\r\n", ics_utc(*start + 30 * 60)));
        body.push_str(&format!("SEQUENCE:{sequence}\r\n"));
        body.push_str("SUMMARY:intro-call\r\n");
        if cancelled {
            body.push_str("STATUS:CANCELLED\r\n");
        }
        body.push_str("END:VEVENT\r\n");
    }
    body.push_str("END:VCALENDAR\r\n");
    let fetcher = ScriptedFeed(Mutex::new(Some(IcsFetchResponse::Complete {
        etag: Some(etag.to_owned()),
        body: body.into_bytes(),
    })));
    let config = IcsFeedPollConfig {
        secret_ref: format!("ics-feed:{HOST_FEED_SYSTEM}"),
        system: HOST_FEED_SYSTEM.to_owned(),
        cadence_min_seconds: 300,
        cadence_max_seconds: 900,
    };
    run_ics_feed_poll(&fixture.vault, &fetcher, &config, now, 7).map(|_| ())
}

#[test]
fn a_host_cancel_refunds_the_whole_deposit() {
    // A visitor's own cancel this late would refund nothing.
    let terms = DepositTerms {
        amount_minor: 4_000,
        currency: "usd".to_owned(),
        refund: DepositRefundRule {
            full_refund_notice_secs: 2 * 3_600,
            late_cancel_refund_percent: 0,
        },
    };
    let fixture = Fixture::open(Some(terms));
    fixture.enable_host_feed();
    let mut provider = RecordingProvider::default();

    let hosted = paid_booking(&fixture, SessionKey::derive(b"host-cancel"), "pi_host", 9);
    let visited = paid_booking(
        &fixture,
        SessionKey::derive(b"visitor-first"),
        "pi_visitor",
        10,
    );
    for booked in [&hosted, &visited] {
        settle_booking_deposit(
            &fixture.vault,
            &booked.calendar.event_ref,
            &mut provider,
            NOW + 50,
        )
        .expect("capture");
    }
    // The visitor cancels the 10:00 booking late: the rule keeps it all.
    fixture
        .cancel(&visited.cancel_token, NOW + 55)
        .expect("cancel");
    assert_eq!(
        state_of(&fixture, "pi_visitor"),
        DepositState::Captured {
            amount_minor: 4_000
        }
    );

    let bookings = [
        (&hosted, MONDAY + 9 * 3_600),
        (&visited, MONDAY + 10 * 3_600),
    ];
    poll_host_feed(&fixture, &bookings, false, "v1", NOW + 60);
    assert_eq!(
        state_of(&fixture, "pi_host"),
        DepositState::Captured {
            amount_minor: 4_000
        }
    );

    // The host cancels both in their own calendar.
    poll_host_feed(&fixture, &bookings, true, "v2", NOW + 120);
    assert_eq!(
        state_of(&fixture, "pi_host"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the host's cancel refunds the whole deposit, whatever the visitor's rule"
    );
    assert_eq!(
        state_of(&fixture, "pi_visitor"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a booking the visitor cancelled first keeps its own cancel's refund"
    );

    let pass = drain(&fixture, &mut provider, NOW + 130);
    assert_eq!(pass.refunded, 1);
    assert_eq!(
        state_of(&fixture, "pi_host"),
        DepositState::Refunded {
            amount_minor: 4_000
        }
    );
}

#[test]
fn a_cancel_that_overtakes_a_running_capture_owes_the_difference_back() {
    let terms = DepositTerms {
        amount_minor: 4_000,
        currency: "usd".to_owned(),
        refund: DepositRefundRule {
            full_refund_notice_secs: 2 * 3_600,
            late_cancel_refund_percent: 25,
        },
    };
    let fixture = Fixture::open(Some(terms));

    // 09:00 start: the late cancel keeps 3000 of the 4000 the capture took.
    // 12:00 start: the cancel releases it all while the capture runs.
    let late = paid_booking(
        &fixture,
        SessionKey::derive(b"overtaken-late"),
        "pi_overtaken_late",
        9,
    );
    let early = paid_booking(
        &fixture,
        SessionKey::derive(b"overtaken-early"),
        "pi_overtaken_early",
        12,
    );
    let mut provider = OvertakenProvider {
        recorded: RecordingProvider::default(),
        during_capture: Some(Box::new(|| {
            fixture
                .cancel(&late.cancel_token, NOW + 60)
                .expect("cancel");
        })),
    };
    settle_booking_deposit(
        &fixture.vault,
        &late.calendar.event_ref,
        &mut provider,
        NOW + 61,
    )
    .expect("capture");
    assert_eq!(
        state_of(&fixture, "pi_overtaken_late"),
        DepositState::RefundDue {
            amount_minor: 1_000
        },
        "the provider took 4000 while the cancel kept 3000: 1000 is owed back"
    );
    provider.during_capture = Some(Box::new(|| {
        fixture
            .cancel(&early.cancel_token, NOW + 62)
            .expect("cancel");
    }));
    settle_booking_deposit(
        &fixture.vault,
        &early.calendar.event_ref,
        &mut provider,
        NOW + 63,
    )
    .expect("capture");
    assert_eq!(
        state_of(&fixture, "pi_overtaken_early"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the provider took 4000 the cancel released: all of it is owed back"
    );

    let mut recorded = provider.recorded;
    let pass = drain(&fixture, &mut recorded, NOW + 70);
    assert_eq!(pass.refunded, 2);
    assert_eq!(pass.voided, 0, "no void of a payment that was captured");
    assert_eq!(
        state_of(&fixture, "pi_overtaken_late"),
        DepositState::Refunded {
            amount_minor: 1_000
        }
    );
    assert_eq!(
        state_of(&fixture, "pi_overtaken_early"),
        DepositState::Refunded {
            amount_minor: 4_000
        }
    );
}

#[test]
fn a_void_that_finds_the_capture_taken_owes_it_back() {
    let fixture = Fixture::open(Some(two_hour_terms()));
    let booked = paid_booking(
        &fixture,
        SessionKey::derive(b"lost-capture-reply"),
        "pi_lost_reply",
        12,
    );
    let mut provider = LostCaptureReplyProvider::default();
    let step = settle_booking_deposit(
        &fixture.vault,
        &booked.calendar.event_ref,
        &mut provider,
        NOW + 50,
    )
    .expect("capture");
    assert!(
        matches!(
            step,
            DepositSettleStep::Failed(DepositProviderFailure::Transient(_))
        ),
        "the capture's reply is lost: {step:?}"
    );
    assert_eq!(
        state_of(&fixture, "pi_lost_reply"),
        DepositState::CaptureDue {
            amount_minor: 4_000
        }
    );

    // 12:00 start, cancelled at 08:01: a full refund, so the capture the
    // deposit still owes turns into a void.
    fixture
        .cancel(&booked.cancel_token, NOW + 60)
        .expect("cancel");
    assert_eq!(state_of(&fixture, "pi_lost_reply"), DepositState::VoidDue);

    let first = drain(&fixture, &mut provider, NOW + 70);
    let second = drain(&fixture, &mut provider, NOW + 80);
    assert_eq!(first.failed + second.failed, 0);
    assert_eq!(
        state_of(&fixture, "pi_lost_reply"),
        DepositState::Refunded {
            amount_minor: 4_000
        },
        "the void found 4000 captured: all of it goes back to the visitor"
    );
    assert!(
        provider
            .recorded
            .calls
            .iter()
            .any(|(payment, movement, _)| {
                payment == "pi_lost_reply"
                    && *movement
                        == DepositSettleMove::Refund {
                            amount_minor: 4_000,
                        }
            }),
        "the provider was asked for the refund: {:?}",
        provider.recorded.calls
    );
}

#[test]
fn a_refund_the_provider_holds_pending_stays_owed_until_it_ends() {
    let fixture = Fixture::open(Some(two_hour_terms()));
    let booked = paid_booking(
        &fixture,
        SessionKey::derive(b"pending-refund"),
        "pi_pending_refund",
        12,
    );
    // More pending answers than a failing move gets claims.
    let mut provider = PendingRefundProvider {
        pending: 9,
        recorded: RecordingProvider::default(),
    };
    settle_booking_deposit(
        &fixture.vault,
        &booked.calendar.event_ref,
        &mut provider,
        NOW + 50,
    )
    .expect("capture");
    // The checkout's and the confirm's rows find nothing more to do.
    drain(&fixture, &mut provider, NOW + 55);
    fixture
        .cancel(&booked.cancel_token, NOW + 60)
        .expect("cancel");
    assert_eq!(
        state_of(&fixture, "pi_pending_refund"),
        DepositState::RefundDue {
            amount_minor: 4_000
        }
    );

    let mut now = NOW + 70;
    for ask in 1..=9 {
        let pass = drain(&fixture, &mut provider, now);
        assert_eq!(pass.failed, 0, "ask {ask}: a pending refund never fails");
        assert_eq!(pass.refunded, 0, "ask {ask}: a pending refund is no refund");
        assert_eq!(
            state_of(&fixture, "pi_pending_refund"),
            DepositState::RefundDue {
                amount_minor: 4_000
            },
            "ask {ask}: the refund stays owed while the provider holds it"
        );
        now += 3_600;
    }
    let pass = drain(&fixture, &mut provider, now);
    assert_eq!(pass.refunded, 1);
    assert_eq!(
        state_of(&fixture, "pi_pending_refund"),
        DepositState::Refunded {
            amount_minor: 4_000
        }
    );
}

#[cfg(oneiron_test_support)]
#[test]
fn a_host_cancel_stopped_before_its_refund_is_repaired_by_the_next_poll() {
    // The poll stops after the cancellation's passport commits and before
    // its refund does (on the old order, after its status did too). The next
    // poll reads the same feed (the passport skips it) or the cancellation
    // sent again at a higher SEQUENCE.
    for (case, replay_sequence) in [("same feed", 1), ("sent again", 2)] {
        let fixture = Fixture::open(Some(two_hour_terms()));
        fixture.enable_host_feed();
        let mut provider = RecordingProvider::default();
        let booked = paid_booking(
            &fixture,
            SessionKey::derive(case.as_bytes()),
            "pi_stopped",
            9,
        );
        settle_booking_deposit(
            &fixture.vault,
            &booked.calendar.event_ref,
            &mut provider,
            NOW + 50,
        )
        .expect("capture");
        let bookings = [(&booked, MONDAY + 9 * 3_600)];
        poll_host_feed(&fixture, &bookings, false, "v1", NOW + 60);

        oneiron::test_doors::host_cancel_refund::stop_before_next_host_cancel_refund();
        let stopped = poll_host_feed_at(&fixture, &bookings, 1, true, "v2", NOW + 120);
        assert!(stopped.is_err(), "{case}: the door stops the poll");
        assert_eq!(
            state_of(&fixture, "pi_stopped"),
            DepositState::Captured {
                amount_minor: 4_000
            },
            "{case}: stopped before the refund"
        );

        poll_host_feed_at(&fixture, &bookings, replay_sequence, true, "v3", NOW + 180)
            .expect("host feed poll");
        assert_eq!(
            state_of(&fixture, "pi_stopped"),
            DepositState::RefundDue {
                amount_minor: 4_000
            },
            "{case}: the next poll repairs the host cancel's refund"
        );
    }
}

#[cfg(oneiron_test_support)]
#[test]
fn a_visitor_cancel_after_the_host_cancel_keeps_the_full_refund() {
    // 09:00 start, cancels at 08:02: the visitor's own late cancel refunds
    // nothing, the host's refunds it all.
    let fixture = std::sync::Arc::new(Fixture::open(Some(two_hour_terms())));
    fixture.enable_host_feed();
    let mut provider = RecordingProvider::default();
    let booked = paid_booking(
        &fixture,
        SessionKey::derive(b"host-then-visitor"),
        "pi_host_then_visitor",
        9,
    );
    settle_booking_deposit(
        &fixture.vault,
        &booked.calendar.event_ref,
        &mut provider,
        NOW + 50,
    )
    .expect("capture");
    let bookings = [(&booked, MONDAY + 9 * 3_600)];
    poll_host_feed(&fixture, &bookings, false, "v1", NOW + 60);

    // The visitor's cancel lands between the host cancel's two commits.
    let racing = std::sync::Arc::clone(&fixture);
    let token = booked.cancel_token.clone();
    oneiron::test_doors::host_cancel_refund::between_next_host_cancel_commits(Box::new(
        move || {
            racing
                .cancel(&token, NOW + 120)
                .expect("the visitor's cancel");
        },
    ));
    poll_host_feed(&fixture, &bookings, true, "v2", NOW + 120);
    assert_eq!(
        state_of(&fixture, "pi_host_then_visitor"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the host's cancel came first: the whole deposit goes back"
    );
}
