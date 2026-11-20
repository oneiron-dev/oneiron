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
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test booking_deposit_settlement`.

mod booking_host_seat_support;
#[path = "booking_deposit_support/fixture.rs"]
mod fixture;

use std::sync::Mutex;

use booking_host_seat_support::{Seat, SeatChange};
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
use oneiron::calendar::claims::{CalendarStatusBasis, PREDICATE_CALENDAR_STATUS};
use oneiron::calendar::connectors::{CalendarConnectorError, RemoteWriteReceipt};
use oneiron::calendar::ingest::{
    IcsFeedFetcher, IcsFeedPollConfig, IcsFetchResponse, run_ics_feed_poll,
};
use oneiron::{ClaimLifecycleStatus, EntityId};

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

/// The host's own calendar, as its seat system names it: the calendar each
/// booking below is written to before its first pull.
const HOST_SEAT_SYSTEM: &str = "host-seat";

/// A seat the booking was never written to, for the foreign-tombstone test.
const SHARED_SEAT_SYSTEM: &str = "shared-seat";

/// A feed the booking was never written to, for the foreign-cancel test.
const VISITOR_FEED_SYSTEM: &str = "visitor-calendar";

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

/// One pull of a seat with each booking at its slot and at `sequence`,
/// cancelled or not. Each booking was written to the seat before its first
/// pull, so each resource rides the href its write returned.
fn pull_seat(
    seat: &Seat,
    fixture: &Fixture,
    bookings: &[(&RemoteWriteReceipt, u64)],
    sequence: u32,
    cancelled: bool,
    now: u64,
) -> Result<(), CalendarConnectorError> {
    let changes: Vec<SeatChange> = bookings
        .iter()
        .map(|(wrote, start)| {
            SeatChange::upsert(wrote, *start, *start + 30 * 60, sequence, cancelled)
        })
        .collect();
    seat.pull(&fixture.vault, &changes, now).map(|_| ())
}

/// One poll of the visitor's feed with the booking at its slot and at
/// `sequence`, cancelled or not.
fn poll_visitor_feed(
    fixture: &Fixture,
    booked: &ConfirmReceipt,
    start: u64,
    sequence: u32,
    cancelled: bool,
    etag: &str,
    now: u64,
) {
    let mut body =
        String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//oneiron//test//EN\r\n");
    body.push_str("BEGIN:VEVENT\r\n");
    body.push_str(&format!("UID:{}\r\n", booked.calendar.uid));
    body.push_str("DTSTAMP:20260302T070000Z\r\n");
    body.push_str(&format!("DTSTART:{}\r\n", ics_utc(start)));
    body.push_str(&format!("DTEND:{}\r\n", ics_utc(start + 30 * 60)));
    body.push_str(&format!("SEQUENCE:{sequence}\r\n"));
    body.push_str("SUMMARY:intro-call\r\n");
    if cancelled {
        body.push_str("STATUS:CANCELLED\r\n");
    }
    body.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    let fetcher = ScriptedFeed(Mutex::new(Some(IcsFetchResponse::Complete {
        etag: Some(etag.to_owned()),
        body: body.into_bytes(),
    })));
    let config = IcsFeedPollConfig {
        secret_ref: format!("ics-feed:{VISITOR_FEED_SYSTEM}"),
        system: VISITOR_FEED_SYSTEM.to_owned(),
        cadence_min_seconds: 300,
        cadence_max_seconds: 900,
    };
    run_ics_feed_poll(&fixture.vault, &fetcher, &config, now, 7).expect("visitor feed poll");
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
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);

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

    // Both bookings are written to the host's seat before its first pull.
    let hosted_wrote = seat.write(&fixture.vault, hosted.calendar.event_ref, NOW + 55);
    let visited_wrote = seat.write(&fixture.vault, visited.calendar.event_ref, NOW + 55);
    let bookings = [
        (&hosted_wrote, MONDAY + 9 * 3_600),
        (&visited_wrote, MONDAY + 10 * 3_600),
    ];
    pull_seat(&seat, &fixture, &bookings, 0, false, NOW + 60).expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_host"),
        DepositState::Captured {
            amount_minor: 4_000
        }
    );

    // The host cancels both in their own calendar.
    pull_seat(&seat, &fixture, &bookings, 1, true, NOW + 120).expect("seat pull");
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

/// How many live `calendar.status` heads on `event` read cancelled with
/// `basis`. An `imported_cancel` head is a calendar's explicit cancellation,
/// the evidence CAL-07 observes; an omission writes `imported_absence`.
fn cancel_statuses(fixture: &Fixture, event: &EntityId, basis: CalendarStatusBasis) -> usize {
    fixture
        .vault
        .claims_for_subject(event)
        .expect("claims of the EVENT")
        .into_iter()
        .filter_map(|id| fixture.vault.get_claim(&id).expect("read the claim"))
        .filter(|body| {
            body.predicate == PREDICATE_CALENDAR_STATUS
                && body.lifecycle == ClaimLifecycleStatus::Active
        })
        .filter(|body| {
            let entries = body.value.as_map().expect("a status value is a map");
            let field = |name: &str| {
                entries
                    .iter()
                    .find(|(key, _)| key.as_str() == Some(name))
                    .and_then(|(_, value)| value.as_str())
            };
            field("status") == Some("cancelled")
                && field("basis").and_then(CalendarStatusBasis::parse) == Some(basis)
        })
        .count()
}

/// A captured booking at 09:00 under [`two_hour_terms`], written live to the
/// host's seat, which is the only calendar that carries it: no feed or seat
/// the booking was imported from holds a passport for its UID.
fn written_only_booking(
    fixture: &Fixture,
    seat: &Seat,
    key: &[u8],
    payment: &str,
) -> ConfirmReceipt {
    let mut provider = RecordingProvider::default();
    let booked = paid_booking(fixture, SessionKey::derive(key), payment, 9);
    settle_booking_deposit(
        &fixture.vault,
        &booked.calendar.event_ref,
        &mut provider,
        NOW + 50,
    )
    .expect("capture");
    seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    assert_eq!(
        state_of(fixture, payment),
        DepositState::Captured {
            amount_minor: 4_000
        }
    );
    booked
}

#[test]
fn a_host_delete_of_a_booking_written_only_to_the_seat_refunds_the_whole_deposit() {
    // CAL-SEAT-DELETE-OF-WRITTEN-ONLY-EVENT-CANCELS-NOTHING (RULING A, Engine
    // 20 Nov 22:41): a seat reports a resource the host deleted as a
    // tombstone (CalDAV's sync answers 404 for it). The booking was only ever
    // written to the host's seat, so no inbound source votes on its EVENT;
    // the delete in the calendar it was written to is the host's cancel. A
    // visitor's own cancel this late would refund nothing.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = written_only_booking(&fixture, &seat, b"written-only-delete", "pi_written_only");

    seat.pull(
        &fixture.vault,
        &[SeatChange::tombstone(&booked.calendar.uid)],
        NOW + 120,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_written_only"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the host's delete of a booking written only to their calendar refunds it whole"
    );
    assert_eq!(
        cancel_statuses(
            &fixture,
            &booked.calendar.event_ref,
            CalendarStatusBasis::ImportedCancel
        ),
        1,
        "the EVENT reads cancelled by the host's calendar"
    );

    // The provider reports the tombstone again: nothing is written twice.
    seat.pull(
        &fixture.vault,
        &[SeatChange::tombstone(&booked.calendar.uid)],
        NOW + 180,
    )
    .expect("seat pull");
    assert_eq!(
        cancel_statuses(
            &fixture,
            &booked.calendar.event_ref,
            CalendarStatusBasis::ImportedCancel
        ),
        1,
        "a tombstone sent again writes no second cancellation"
    );
    let mut provider = RecordingProvider::default();
    let pass = drain(&fixture, &mut provider, NOW + 190);
    assert_eq!(pass.refunded, 1);
    assert_eq!(
        state_of(&fixture, "pi_written_only"),
        DepositState::Refunded {
            amount_minor: 4_000
        }
    );
}

#[test]
fn a_tombstone_of_the_engine_s_own_cancelled_write_is_no_host_cancel() {
    // The visitor cancels late (their rule keeps the deposit), and the engine
    // writes the cancelled EVENT to the host's seat. A provider that keeps a
    // cancelled event as a deleted one then reports that write as a
    // tombstone: the engine's own cancel coming back, never the host's, so it
    // records no imported cancellation and moves no money.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = written_only_booking(&fixture, &seat, b"own-cancel-echo", "pi_own_cancel_echo");
    fixture
        .cancel(&booked.cancel_token, NOW + 60)
        .expect("the visitor cancels");
    seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 70);

    seat.pull(
        &fixture.vault,
        &[SeatChange::tombstone(&booked.calendar.uid)],
        NOW + 120,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_own_cancel_echo"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the tombstone of the engine's own cancelled write moves no money"
    );
    assert_eq!(
        cancel_statuses(
            &fixture,
            &booked.calendar.event_ref,
            CalendarStatusBasis::ImportedCancel
        ),
        0,
        "the tombstone of the engine's own cancelled write is no host cancel"
    );
}

#[test]
fn a_tombstone_while_the_engine_s_cancelled_write_is_in_flight_is_no_host_cancel() {
    // As above, but the provider stores the cancelled write and its answer is
    // lost, so the write is still in flight when the pull reports it as a
    // tombstone. The tombstone stays owed until the write settles, and is
    // then the engine's own cancel.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = written_only_booking(
        &fixture,
        &seat,
        b"in-flight-cancel-tombstone",
        "pi_in_flight_tombstone",
    );
    fixture
        .cancel(&booked.cancel_token, NOW + 60)
        .expect("the visitor cancels");
    let stored = seat.write_with_lost_answer(&fixture.vault, booked.calendar.event_ref, NOW + 70);

    seat.pull(
        &fixture.vault,
        &[SeatChange::tombstone(&booked.calendar.uid)],
        NOW + 80,
    )
    .expect("seat pull");
    assert_eq!(
        cancel_statuses(
            &fixture,
            &booked.calendar.event_ref,
            CalendarStatusBasis::ImportedCancel
        ),
        0,
        "a tombstone of the cancelled write before it settles is no host cancel"
    );

    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 90);
    assert_eq!(
        wrote.sequence, stored,
        "the next write resumes the one in flight"
    );
    seat.pull(
        &fixture.vault,
        &[SeatChange::tombstone(&booked.calendar.uid)],
        NOW + 120,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_in_flight_tombstone"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the tombstone of the engine's own cancelled write moves no money"
    );
    assert_eq!(
        cancel_statuses(
            &fixture,
            &booked.calendar.event_ref,
            CalendarStatusBasis::ImportedCancel
        ),
        0,
        "a tombstone of the cancelled write after it settled is no host cancel"
    );
}

#[test]
fn a_host_delete_waits_while_a_calendar_the_booking_was_not_written_to_shows_it() {
    // Only an EVENT no inbound source carries is cancelled by the written-to
    // calendar's tombstone alone. Here a seat the booking was never written
    // to still shows it, so the host's delete waits on that calendar, as the
    // multi-source law says, and settles, dated by the host's delete, once
    // that calendar leaves the EVENT out too.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let shared = Seat::install(&fixture.vault, SHARED_SEAT_SYSTEM);
    let booked = written_only_booking(&fixture, &seat, b"delete-waits", "pi_delete_waits");
    let start = MONDAY + 9 * 3_600;
    shared
        .pull(
            &fixture.vault,
            &[SeatChange::foreign(
                &shared,
                &booked.calendar.uid,
                start,
                start + 30 * 60,
                0,
                false,
            )],
            NOW + 60,
        )
        .expect("seat pull");

    seat.pull(
        &fixture.vault,
        &[SeatChange::tombstone(&booked.calendar.uid)],
        NOW + 120,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_delete_waits"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the host's delete waits while another calendar shows the booking"
    );
    assert_eq!(
        cancel_statuses(
            &fixture,
            &booked.calendar.event_ref,
            CalendarStatusBasis::ImportedCancel
        ),
        0,
        "the EVENT another calendar still shows reads live"
    );

    shared
        .pull(
            &fixture.vault,
            &[SeatChange::tombstone(&booked.calendar.uid)],
            NOW + 180,
        )
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_delete_waits"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "once no calendar shows the booking, the host's delete refunds it whole"
    );
}

#[test]
fn an_omission_of_a_booking_written_only_to_the_seat_cancels_nothing() {
    // A complete listing that leaves the booking out is no cancellation
    // evidence, and a calendar the booking was only written to casts no
    // absence vote: the EVENT stays live and the deposit stands.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = written_only_booking(&fixture, &seat, b"written-only-omission", "pi_omission");

    seat.pull(
        &fixture.vault,
        &[SeatChange::omitted(&booked.calendar.uid)],
        NOW + 120,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_omission"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "an omission moves no money"
    );
    for basis in [
        CalendarStatusBasis::ImportedCancel,
        CalendarStatusBasis::ImportedAbsence,
    ] {
        assert_eq!(
            cancel_statuses(&fixture, &booked.calendar.event_ref, basis),
            0,
            "an omission of a written-only booking cancels nothing ({basis:?})"
        );
    }
}

#[test]
fn a_resource_the_host_moves_to_a_new_href_is_no_host_cancel() {
    // A CalDAV sync answer reports a resource the host moved to a new href
    // as the old href's 404 beside the new href's live copy of the same UID.
    // The booking was written only to the host's seat, where a tombstone
    // alone cancels it, but the live copy in the same answer says the host
    // moved the resource and kept the booking: nothing is cancelled and no
    // money moves.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = written_only_booking(&fixture, &seat, b"moved-resource", "pi_moved_resource");
    let uid = &booked.calendar.uid;
    let start = MONDAY + 9 * 3_600;
    let moved = SeatChange::Upsert {
        href: format!("{}-moved", seat.resource_locator(uid).href),
        uid: uid.clone(),
        start,
        end: start + 30 * 60,
        sequence: seat.staged_sequence(&fixture.vault, uid),
        cancelled: false,
    };

    seat.pull(
        &fixture.vault,
        &[SeatChange::tombstone(uid), moved],
        NOW + 120,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_moved_resource"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a resource moved to a new href moves no money"
    );
    assert_eq!(
        cancel_statuses(
            &fixture,
            &booked.calendar.event_ref,
            CalendarStatusBasis::ImportedCancel
        ),
        0,
        "a resource moved to a new href is no host cancel"
    );
}

#[test]
fn a_host_delete_held_behind_a_refused_cancelled_write_refunds_at_the_full_listing() {
    // A calendar the booking was never written to cancels it and then leaves
    // it out, which moves no money, and the engine writes the cancelled EVENT
    // to the host's seat. The host deletes the booking in their calendar
    // before its start, and a pull while that write is out holds the
    // tombstone back. The provider refuses the write's first call on its
    // precondition, storing nothing, so the tombstone was the host's.
    // CalDAV's full listing can only leave the gone resource out; that
    // omission settles the held tombstone, dated by its first sighting, and
    // the deposit is refunded whole.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let shared = Seat::install(&fixture.vault, SHARED_SEAT_SYSTEM);
    let booked = written_only_booking(
        &fixture,
        &seat,
        b"held-delete-refused-write",
        "pi_held_delete_refused",
    );
    let uid = &booked.calendar.uid;
    let start = MONDAY + 9 * 3_600;
    for (sequence, cancelled, now) in [(0, false, NOW + 60), (1, true, NOW + 62)] {
        shared
            .pull(
                &fixture.vault,
                &[SeatChange::foreign(
                    &shared,
                    uid,
                    start,
                    start + 30 * 60,
                    sequence,
                    cancelled,
                )],
                now,
            )
            .expect("seat pull");
    }
    shared
        .pull(&fixture.vault, &[SeatChange::omitted(uid)], NOW + 64)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_held_delete_refused"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a calendar the booking was never written to moves no money"
    );

    seat.write_refused_after_pull(
        &fixture.vault,
        booked.calendar.event_ref,
        &SeatChange::tombstone(uid),
        NOW + 80,
        NOW + 70,
    );
    assert_eq!(
        state_of(&fixture, "pi_held_delete_refused"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the tombstone read while the cancelled write was out is held"
    );

    seat.pull(&fixture.vault, &[SeatChange::omitted(uid)], NOW + 100)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_held_delete_refused"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the full listing settles the held tombstone as the host's cancel, refunded whole"
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
    // The pull stops after the cancellation's passport commits and before
    // its refund does (on the old order, after its status did too). The next
    // pull reads the same seat (the passport skips it) or the cancellation
    // sent again at a higher SEQUENCE.
    for (case, replay_sequence) in [("same seat", 1), ("sent again", 2)] {
        let fixture = Fixture::open(Some(two_hour_terms()));
        fixture.enable_host_feed();
        let mut provider = RecordingProvider::default();
        let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
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
        let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
        let bookings = [(&wrote, MONDAY + 9 * 3_600)];
        pull_seat(&seat, &fixture, &bookings, 0, false, NOW + 60).expect("seat pull");

        oneiron::test_doors::host_cancel_refund::stop_before_next_host_cancel_refund();
        let stopped = pull_seat(&seat, &fixture, &bookings, 1, true, NOW + 120);
        assert!(stopped.is_err(), "{case}: the door stops the pull");
        assert_eq!(
            state_of(&fixture, "pi_stopped"),
            DepositState::Captured {
                amount_minor: 4_000
            },
            "{case}: stopped before the refund"
        );

        pull_seat(&seat, &fixture, &bookings, replay_sequence, true, NOW + 180).expect("seat pull");
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
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
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
    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    let bookings = [(&wrote, MONDAY + 9 * 3_600)];
    pull_seat(&seat, &fixture, &bookings, 0, false, NOW + 60).expect("seat pull");

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
    pull_seat(&seat, &fixture, &bookings, 1, true, NOW + 120).expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_host_then_visitor"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the host's cancel came first: the whole deposit goes back"
    );
}

#[test]
fn a_cancel_from_a_feed_the_booking_was_not_written_to_keeps_the_deposit() {
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
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);

    let booked = paid_booking(
        &fixture,
        SessionKey::derive(b"foreign-cancel"),
        "pi_foreign_cancel",
        9,
    );
    settle_booking_deposit(
        &fixture.vault,
        &booked.calendar.event_ref,
        &mut provider,
        NOW + 50,
    )
    .expect("capture");
    assert_eq!(
        state_of(&fixture, "pi_foreign_cancel"),
        DepositState::Captured {
            amount_minor: 4_000
        }
    );
    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);

    // A feed the booking was never written to carries its UID live, then
    // cancelled: the calendar records the cancellation, the deposit stands.
    let start = MONDAY + 9 * 3_600;
    poll_visitor_feed(&fixture, &booked, start, 0, false, "v1", NOW + 60);
    poll_visitor_feed(&fixture, &booked, start, 1, true, "v2", NOW + 120);
    assert_eq!(
        state_of(&fixture, "pi_foreign_cancel"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a cancel from a feed the booking was not written to moves no money"
    );

    // The host seat's own cancel of the same booking still refunds it whole.
    pull_seat(&seat, &fixture, &[(&wrote, start)], 1, true, NOW + 180).expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_foreign_cancel"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the written-to seat's cancel refunds the whole deposit"
    );
}

#[test]
fn a_cancelled_booking_the_owner_wrote_and_the_seat_echoed_keeps_the_deposit() {
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let mut provider = RecordingProvider::default();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);

    let booked = paid_booking(
        &fixture,
        SessionKey::derive(b"written-echo"),
        "pi_written_echo",
        9,
    );
    settle_booking_deposit(
        &fixture.vault,
        &booked.calendar.event_ref,
        &mut provider,
        NOW + 50,
    )
    .expect("capture");

    // A feed the booking was never written to cancels it: the EVENT reads
    // cancelled, the deposit stands.
    let start = MONDAY + 9 * 3_600;
    poll_visitor_feed(&fixture, &booked, start, 0, false, "v1", NOW + 60);
    poll_visitor_feed(&fixture, &booked, start, 1, true, "v2", NOW + 120);
    assert_eq!(
        state_of(&fixture, "pi_written_echo"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a cancel from a feed the booking was not written to moves no money"
    );

    // The owner then writes the cancelled EVENT to their own calendar, and
    // its next pull returns the written bytes unchanged: the owner's own
    // write coming back, not a cancellation made in that calendar.
    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 150);
    seat.pull_own_write(&fixture.vault, &wrote, NOW + 180)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_written_echo"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the echo of the owner's own write moves no money"
    );
}

/// The owner's write of an EVENT a feed the booking was not written to
/// cancelled: the booking is paid and captured, the visitor's feed cancels
/// it, then the owner writes the cancelled EVENT to the host seat. Returns
/// the booking and that write's receipt.
fn owner_writes_a_foreign_cancel(
    fixture: &Fixture,
    seat: &Seat,
    key: &[u8],
    payment: &str,
) -> (ConfirmReceipt, RemoteWriteReceipt) {
    let mut provider = RecordingProvider::default();
    let booked = paid_booking(fixture, SessionKey::derive(key), payment, 9);
    settle_booking_deposit(
        &fixture.vault,
        &booked.calendar.event_ref,
        &mut provider,
        NOW + 50,
    )
    .expect("capture");
    let start = MONDAY + 9 * 3_600;
    poll_visitor_feed(fixture, &booked, start, 0, false, "v1", NOW + 60);
    poll_visitor_feed(fixture, &booked, start, 1, true, "v2", NOW + 120);
    assert_eq!(
        state_of(fixture, payment),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a cancel from a feed the booking was not written to moves no money"
    );
    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 150);
    (booked, wrote)
}

#[test]
fn a_cancelled_booking_the_owner_wrote_and_the_seat_rewrote_keeps_the_deposit() {
    // BK-DEPOSIT-REWRITTEN-ECHO-OF-OWNER-WRITE-REFUNDS: a provider that
    // rewrites the stored resource sends the owner's own cancelled write back
    // as a new version; that is still no host cancel.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let (_, wrote) =
        owner_writes_a_foreign_cancel(&fixture, &seat, b"rewritten-echo", "pi_rewritten_echo");

    seat.pull_rewritten_own_write(&fixture.vault, &wrote, wrote.sequence, NOW + 180)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_rewritten_echo"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a rewrite of the owner's own cancelled write at its SEQUENCE moves no money"
    );

    seat.pull_rewritten_own_write(&fixture.vault, &wrote, wrote.sequence + 1, NOW + 240)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_rewritten_echo"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a later rewrite at a higher SEQUENCE is still the owner's own write"
    );
}

#[test]
fn a_seat_that_shows_the_owner_written_cancel_live_and_then_cancels_refunds() {
    // The mark of the owner's cancelled write ends when the seat shows the
    // EVENT uncancelled: a cancel made in that calendar after it is the
    // host's, and refunds whole (RULING DEPOSIT-HOST-CANCEL-SOURCE = A).
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let (_, wrote) =
        owner_writes_a_foreign_cancel(&fixture, &seat, b"written-then-live", "pi_written_live");
    let start = MONDAY + 9 * 3_600;

    pull_seat(
        &seat,
        &fixture,
        &[(&wrote, start)],
        wrote.sequence + 1,
        false,
        NOW + 180,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_written_live"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the seat showing the EVENT live moves no money"
    );

    pull_seat(
        &seat,
        &fixture,
        &[(&wrote, start)],
        wrote.sequence + 2,
        true,
        NOW + 240,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_written_live"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the written-to seat's own cancel refunds the whole deposit"
    );
}

#[test]
fn a_second_owner_write_after_the_seat_rewrote_the_first_keeps_the_deposit() {
    // Review of #9704: the seat's rewrite of the owner's cancelled write
    // dates that cancellation on the seat's passport. The owner's next
    // cancelled write keeps the mark, so the seat's rewrite of that one is
    // still the owner's own write and moves no money either.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let (booked, first) =
        owner_writes_a_foreign_cancel(&fixture, &seat, b"second-write", "pi_second_write");

    seat.pull_rewritten_own_write(&fixture.vault, &first, first.sequence, NOW + 180)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_second_write"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a rewrite of the owner's first cancelled write moves no money"
    );

    let second = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 200);
    seat.pull_rewritten_own_write(&fixture.vault, &second, second.sequence, NOW + 240)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_second_write"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a rewrite of the owner's second cancelled write moves no money"
    );
}

#[test]
fn a_seat_pull_of_the_owner_cancelled_write_still_in_flight_keeps_the_deposit() {
    // Review of #9704: the seat holds the booking live from the owner's
    // earlier write. A feed the booking was not written to cancels it, and
    // the owner writes the cancelled EVENT to the seat; the provider stores
    // it, but its answer is lost, so the write is still in flight when a
    // pull reads the stored copy back.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let mut provider = RecordingProvider::default();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = paid_booking(
        &fixture,
        SessionKey::derive(b"in-flight-cancel"),
        "pi_in_flight_cancel",
        9,
    );
    settle_booking_deposit(
        &fixture.vault,
        &booked.calendar.event_ref,
        &mut provider,
        NOW + 50,
    )
    .expect("capture");
    let live = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    let start = MONDAY + 9 * 3_600;
    poll_visitor_feed(&fixture, &booked, start, 0, false, "v1", NOW + 60);
    poll_visitor_feed(&fixture, &booked, start, 1, true, "v2", NOW + 120);
    assert_eq!(
        state_of(&fixture, "pi_in_flight_cancel"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a cancel from a feed the booking was not written to moves no money"
    );

    let stored = seat.write_with_lost_answer(&fixture.vault, booked.calendar.event_ref, NOW + 150);
    seat.pull_rewritten_own_write(&fixture.vault, &live, stored, NOW + 160)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_in_flight_cancel"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a pull of the owner's cancelled write before it settles moves no money"
    );

    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 170);
    assert_eq!(
        wrote.sequence, stored,
        "the next write resumes the one in flight"
    );
    seat.pull_rewritten_own_write(&fixture.vault, &wrote, wrote.sequence, NOW + 180)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_in_flight_cancel"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a pull of the owner's cancelled write after it settled moves no money"
    );
}

/// A captured booking the owner wrote live to the host seat, then a feed
/// the booking was not written to cancelled (no money moves). Returns the
/// booking, the live write's receipt and the booking's start.
fn written_live_then_cancelled_elsewhere(
    fixture: &Fixture,
    seat: &Seat,
    key: &[u8],
    payment: &str,
) -> (ConfirmReceipt, RemoteWriteReceipt, u64) {
    let mut provider = RecordingProvider::default();
    let booked = paid_booking(fixture, SessionKey::derive(key), payment, 9);
    settle_booking_deposit(
        &fixture.vault,
        &booked.calendar.event_ref,
        &mut provider,
        NOW + 50,
    )
    .expect("capture");
    let live = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);
    let start = MONDAY + 9 * 3_600;
    poll_visitor_feed(fixture, &booked, start, 0, false, "v1", NOW + 60);
    poll_visitor_feed(fixture, &booked, start, 1, true, "v2", NOW + 120);
    assert_eq!(
        state_of(fixture, payment),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a cancel from a feed the booking was not written to moves no money"
    );
    (booked, live, start)
}

#[test]
fn a_replayed_cancelled_write_refused_over_its_own_stored_copy_keeps_the_deposit() {
    // Review round 2 of #9704: the provider stores the owner's cancelled
    // write, rewrites it and moves its ETag, but the answer is lost. A pull
    // holds the copy back while the write is in flight; the write sent again
    // fails its precondition on the copy's new ETag. That copy is still the
    // owner's own write, so the seat's report of it moves no money.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let (booked, live, _) = written_live_then_cancelled_elsewhere(
        &fixture,
        &seat,
        b"replay-refused-own-copy",
        "pi_replay_own_copy",
    );

    let stored = seat.write_with_lost_answer(&fixture.vault, booked.calendar.event_ref, NOW + 150);
    seat.pull_rewritten_own_write(&fixture.vault, &live, stored, NOW + 160)
        .expect("seat pull");
    seat.replay_refused_over_rewritten_own_write(
        &fixture.vault,
        booked.calendar.event_ref,
        &live,
        stored,
        NOW + 170,
    );
    assert_eq!(
        state_of(&fixture, "pi_replay_own_copy"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the refused replay moves no money"
    );

    seat.pull_rewritten_own_write(&fixture.vault, &live, stored, NOW + 180)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_replay_own_copy"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the seat's report of the owner's own stored copy moves no money"
    );
}

#[test]
fn an_owner_write_over_a_cancel_the_seat_read_before_it_was_written_to_keeps_the_deposit() {
    // Review round 2 of #9704: the host seat holds the booking's UID before
    // the booking was ever written to it, and reports it cancelled: an
    // Inbound passport, no money. The owner then writes the cancelled EVENT
    // to that seat, which turns its passport TwoWay. The seat's rewrite of
    // that write is the owner's own write coming back, not a host cancel.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let mut provider = RecordingProvider::default();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = paid_booking(
        &fixture,
        SessionKey::derive(b"read-before-written"),
        "pi_read_before_written",
        9,
    );
    settle_booking_deposit(
        &fixture.vault,
        &booked.calendar.event_ref,
        &mut provider,
        NOW + 50,
    )
    .expect("capture");
    let start = MONDAY + 9 * 3_600;
    seat.pull(
        &fixture.vault,
        &[SeatChange::foreign(
            &seat,
            &booked.calendar.uid,
            start,
            start + 30 * 60,
            0,
            true,
        )],
        NOW + 60,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_read_before_written"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a cancel from a seat the booking was not written to moves no money"
    );

    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 150);
    seat.pull_rewritten_own_write(&fixture.vault, &wrote, wrote.sequence, NOW + 180)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_read_before_written"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a rewrite of the owner's cancelled write moves no money"
    );
}

#[test]
fn a_host_cancel_after_a_live_restore_read_before_the_owner_write_settled_refunds() {
    // Review round 2 of #9704: the provider stores the owner's cancelled
    // write, but before its answer is settled the host restores the booking
    // live at a higher SEQUENCE, and a pull reads it. The write then settles;
    // it replaces neither that newer version nor its passport, so the host's
    // own cancel after it is a host cancel and refunds whole.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let (booked, live, start) = written_live_then_cancelled_elsewhere(
        &fixture,
        &seat,
        b"restored-before-settled",
        "pi_restored_before_settled",
    );

    let wrote = seat.write_settled_after_restore(
        &fixture.vault,
        booked.calendar.event_ref,
        &live,
        (start, start + 30 * 60),
        NOW + 160,
        NOW + 150,
    );
    assert_eq!(
        state_of(&fixture, "pi_restored_before_settled"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the host's restore and the late settlement move no money"
    );

    pull_seat(
        &seat,
        &fixture,
        &[(&live, start)],
        wrote.sequence + 2,
        true,
        NOW + 180,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_restored_before_settled"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the host's cancel after the restore refunds the whole deposit"
    );
}

#[test]
fn a_host_cancel_held_back_by_a_refused_owner_write_refunds_by_its_first_sighting() {
    // Review round 2 of #9704: the host cancels the booking in the seat
    // just before the owner's cancelled write is sent; that write's first
    // call never reaches the provider. A pull before the start reads the
    // host's cancellation while the write is in flight, so it is held back.
    // After the start the write is sent again and refused on the ETag the
    // host's change took, and the next pull reads the cancellation: it is
    // dated by its first sighting, before the start, and refunds whole.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let (booked, live, start) = written_live_then_cancelled_elsewhere(
        &fixture,
        &seat,
        b"held-host-cancel",
        "pi_held_host_cancel",
    );
    let host_cancel = SeatChange::upsert(&live, start, start + 30 * 60, live.sequence, true);

    seat.write_unsent(&fixture.vault, booked.calendar.event_ref, NOW + 150);
    seat.pull(
        &fixture.vault,
        std::slice::from_ref(&host_cancel),
        NOW + 160,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_held_host_cancel"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the cancellation held back while the owner's write is in flight moves no money yet"
    );

    seat.replay_refused_over(
        &fixture.vault,
        booked.calendar.event_ref,
        &host_cancel,
        start + 60,
    );
    seat.pull(
        &fixture.vault,
        std::slice::from_ref(&host_cancel),
        start + 120,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_held_host_cancel"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the host's cancellation first seen before the start refunds the whole deposit"
    );
}

#[test]
fn a_host_cancel_that_keeps_an_earlier_write_marker_refunds_after_the_refused_replay() {
    // BK-ECHO-MARK-TAKES-HOST-CANCEL-AT-STAGED-SEQUENCE: the owner's
    // cancelled write never reaches the provider. The host cancels the
    // booking in a client over the seat's live copy, at the SEQUENCE the
    // owner's write staged, and the client keeps the marker of an earlier
    // write. A pull before the start holds the cancel back; after the start
    // the replay is refused on it. The copy carries another write's marker,
    // so it is the host's cancel, dated by its first sighting: it refunds
    // whole.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let (booked, live, start) = written_live_then_cancelled_elsewhere(
        &fixture,
        &seat,
        b"host-cancel-earlier-marker",
        "pi_host_cancel_earlier_marker",
    );

    seat.write_unsent(&fixture.vault, booked.calendar.event_ref, NOW + 150);
    let staged = seat.staged_sequence(&fixture.vault, &booked.calendar.uid);
    let host_cancel = seat.host_cancel_of_own_write(&live, staged);
    seat.pull(
        &fixture.vault,
        std::slice::from_ref(&host_cancel),
        NOW + 160,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_host_cancel_earlier_marker"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the cancellation held back while the owner's write is in flight moves no money yet"
    );

    seat.replay_refused_over(
        &fixture.vault,
        booked.calendar.event_ref,
        &host_cancel,
        start + 60,
    );
    seat.pull(
        &fixture.vault,
        std::slice::from_ref(&host_cancel),
        start + 120,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_host_cancel_earlier_marker"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the host's cancel at the staged SEQUENCE under another write's marker refunds the whole deposit"
    );
}

#[test]
fn a_replay_refused_over_its_stored_copy_without_the_write_marker_keeps_the_deposit() {
    // ASK BK-ECHO-UNMARKED-SAME-SHAPE-COPY: the provider stores the owner's
    // cancelled write, rewrites it and drops the properties it does not
    // know, the write's marker with them; the answer is lost, and the replay
    // is refused on the rewritten copy. Nothing tells a copy with no marker
    // from the host's cancel at the same SEQUENCE, so it reads as the
    // owner's own write and moves no money.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let (booked, live, _) = written_live_then_cancelled_elsewhere(
        &fixture,
        &seat,
        b"replay-stripped-own-copy",
        "pi_replay_stripped_own_copy",
    );

    let stored = seat.write_with_lost_answer(&fixture.vault, booked.calendar.event_ref, NOW + 150);
    let copy = seat.stripped_rewrite_of_own_write(&live, stored, NOW + 160);
    seat.replay_refused_over(&fixture.vault, booked.calendar.event_ref, &copy, NOW + 170);
    seat.pull(&fixture.vault, std::slice::from_ref(&copy), NOW + 180)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_replay_stripped_own_copy"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the seat's report of the owner's own copy with its marker dropped moves no money"
    );
}

#[test]
fn a_replay_whose_reconcile_read_failed_keeps_the_deposit_when_the_seat_reports_its_copy() {
    // BK-ECHO-RECONCILE-FAILURE-RELEASES-UNMARKED-COPY: the provider stores
    // the owner's cancelled write, rewrites it, and the answer is lost. The
    // replay is refused on the rewritten copy's ETag, and its reconciliation
    // pull fails, so the write reads no copy. The seat's next pull proves
    // the copy the owner's own before it admits it: no money moves.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let (booked, live, _) = written_live_then_cancelled_elsewhere(
        &fixture,
        &seat,
        b"replay-unread-own-copy",
        "pi_replay_unread_own_copy",
    );

    let stored = seat.write_with_lost_answer(&fixture.vault, booked.calendar.event_ref, NOW + 150);
    seat.replay_refused_unread(&fixture.vault, booked.calendar.event_ref, NOW + 170);
    assert_eq!(
        state_of(&fixture, "pi_replay_unread_own_copy"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the refused replay moves no money"
    );

    seat.pull_rewritten_own_write(&fixture.vault, &live, stored, NOW + 180)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_replay_unread_own_copy"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the seat's report of the owner's own stored copy moves no money"
    );
    seat.pull_rewritten_own_write(&fixture.vault, &live, stored, NOW + 190)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_replay_unread_own_copy"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a later report of the owner's own stored copy moves no money"
    );
}

#[test]
fn a_stale_live_copy_read_after_the_owner_cancelled_write_settled_keeps_the_deposit() {
    // Review round 1 of #9841: the owner's cancelled write settles at the
    // SEQUENCE after the seat's live copy. A pull read before the write
    // landed then delivers that live copy: a stale replay, which leaves the
    // write's mark. The provider's rewrite of the owner's cancellation
    // before the start is still the owner's own write and moves no money.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let (booked, live, start) = written_live_then_cancelled_elsewhere(
        &fixture,
        &seat,
        b"stale-live-after-settled-cancel",
        "pi_stale_live_after_settled_cancel",
    );

    let wrote = seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 150);
    seat.pull(
        &fixture.vault,
        &[SeatChange::upsert(
            &live,
            start,
            start + 30 * 60,
            live.sequence,
            false,
        )],
        NOW + 160,
    )
    .expect("seat pull");
    seat.pull_rewritten_own_write(&fixture.vault, &wrote, wrote.sequence + 1, NOW + 170)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_stale_live_after_settled_cancel"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the provider's rewrite of the owner's cancel after a stale live copy moves no money"
    );
}

#[test]
fn a_stale_live_copy_read_while_a_replay_awaits_its_proof_keeps_the_deposit() {
    // Review round 1 of #9841: the provider stores the owner's cancelled
    // write, rewrites it, and the answer is lost; the replay is refused and
    // its reconciliation pull fails, so the proof waits for the seat's next
    // pull. A pull read before the write landed then delivers the seat's
    // live copy at the earlier SEQUENCE: it proves nothing, and the proof
    // still waits. The seat's report of the owner's own copy moves no money.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let (booked, live, start) = written_live_then_cancelled_elsewhere(
        &fixture,
        &seat,
        b"stale-live-before-proof",
        "pi_stale_live_before_proof",
    );

    let stored = seat.write_with_lost_answer(&fixture.vault, booked.calendar.event_ref, NOW + 150);
    seat.replay_refused_unread(&fixture.vault, booked.calendar.event_ref, NOW + 170);
    seat.pull(
        &fixture.vault,
        &[SeatChange::upsert(
            &live,
            start,
            start + 30 * 60,
            live.sequence,
            false,
        )],
        NOW + 175,
    )
    .expect("seat pull");
    seat.pull_rewritten_own_write(&fixture.vault, &live, stored, NOW + 180)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_stale_live_before_proof"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the seat's report of the owner's own copy after a stale live copy moves no money"
    );
}

#[test]
fn a_host_cancel_after_a_restore_read_during_the_refused_replay_refunds() {
    // BK-ECHO-MARK-OVER-NEWER-LIVE-RESTORE: the provider stores the owner's
    // cancelled write, rewrites it, and the answer is lost. The replay is
    // refused; its reconciliation reads the rewritten copy, but before the
    // write takes the copy in, a pull reads the host's live restore at the
    // next SEQUENCE. The copy is the owner's, yet the newer restore takes no
    // mark, so the host's cancel after it refunds whole.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let (booked, live, start) = written_live_then_cancelled_elsewhere(
        &fixture,
        &seat,
        b"restore-during-replay",
        "pi_restore_during_replay",
    );

    let stored = seat.write_with_lost_answer(&fixture.vault, booked.calendar.event_ref, NOW + 150);
    let copy = seat.rewrite_of_own_write(&live, stored, NOW + 160);
    let restore = SeatChange::upsert(&live, start, start + 30 * 60, stored + 1, false);
    seat.replay_refused_over_while_restored(
        &fixture.vault,
        booked.calendar.event_ref,
        &copy,
        &restore,
        NOW + 165,
        NOW + 170,
    );
    assert_eq!(
        state_of(&fixture, "pi_restore_during_replay"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the refused replay and the host's restore move no money"
    );

    pull_seat(
        &seat,
        &fixture,
        &[(&live, start)],
        stored + 2,
        true,
        NOW + 180,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_restore_during_replay"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the host's cancel after the restore refunds the whole deposit"
    );
}

#[test]
fn a_host_cancel_after_a_restore_read_before_the_first_write_settled_refunds() {
    // BK-ECHO-NEWER-RESTORE-DROPS-WRITTEN-DIRECTION: the seat holds the
    // booking only as read (Inbound), from its own cancel before the
    // booking was written to it. The owner writes the cancelled EVENT to
    // the seat; the provider stores it, but before the answer settles the
    // host restores the booking live at the next SEQUENCE and a pull reads
    // that. The settlement keeps the restore, yet the write landed, so the
    // seat is a calendar the booking was written to: the host's cancel
    // after the restore refunds whole.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let mut provider = RecordingProvider::default();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = paid_booking(
        &fixture,
        SessionKey::derive(b"inbound-seat-restored"),
        "pi_inbound_seat_restored",
        9,
    );
    settle_booking_deposit(
        &fixture.vault,
        &booked.calendar.event_ref,
        &mut provider,
        NOW + 50,
    )
    .expect("capture");
    let start = MONDAY + 9 * 3_600;
    seat.pull(
        &fixture.vault,
        &[SeatChange::foreign(
            &seat,
            &booked.calendar.uid,
            start,
            start + 30 * 60,
            0,
            true,
        )],
        NOW + 60,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_inbound_seat_restored"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a cancel from a seat the booking was not written to moves no money"
    );

    let locator = seat.resource_locator(&booked.calendar.uid);
    let wrote = seat.write_settled_after_restore(
        &fixture.vault,
        booked.calendar.event_ref,
        &locator,
        (start, start + 30 * 60),
        NOW + 160,
        NOW + 150,
    );
    assert_eq!(
        state_of(&fixture, "pi_inbound_seat_restored"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the host's restore and the late settlement move no money"
    );

    pull_seat(
        &seat,
        &fixture,
        &[(&locator, start)],
        wrote.sequence + 2,
        true,
        NOW + 180,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_inbound_seat_restored"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the host's cancel after the restore refunds the whole deposit"
    );
}

#[test]
fn a_host_cancel_after_a_first_write_replayed_over_its_stored_copy_refunds() {
    // BK-ECHO-NEWER-RESTORE-DROPS-WRITTEN-DIRECTION: the seat holds no
    // passport of the booking. A feed the booking was not written to
    // cancels it, and the owner writes the cancelled EVENT to the seat; the
    // provider stores it and rewrites it, but the answer is lost, and the
    // replay is refused on the rewritten copy, which proves the owner's
    // own. The seat now holds a booking written to it: its report of the
    // copy moves no money, and the host's cancel after a live restore
    // refunds whole.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let mut provider = RecordingProvider::default();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let booked = paid_booking(
        &fixture,
        SessionKey::derive(b"first-write-replayed"),
        "pi_first_write_replayed",
        9,
    );
    settle_booking_deposit(
        &fixture.vault,
        &booked.calendar.event_ref,
        &mut provider,
        NOW + 50,
    )
    .expect("capture");
    let start = MONDAY + 9 * 3_600;
    poll_visitor_feed(&fixture, &booked, start, 0, false, "v1", NOW + 60);
    poll_visitor_feed(&fixture, &booked, start, 1, true, "v2", NOW + 120);

    let locator = seat.resource_locator(&booked.calendar.uid);
    let stored = seat.write_with_lost_answer(&fixture.vault, booked.calendar.event_ref, NOW + 150);
    seat.replay_refused_over_rewritten_own_write(
        &fixture.vault,
        booked.calendar.event_ref,
        &locator,
        stored,
        NOW + 170,
    );
    seat.pull_rewritten_own_write(&fixture.vault, &locator, stored, NOW + 180)
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_first_write_replayed"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the seat's report of the owner's own stored copy moves no money"
    );

    pull_seat(
        &seat,
        &fixture,
        &[(&locator, start)],
        stored + 1,
        false,
        NOW + 190,
    )
    .expect("seat pull");
    pull_seat(
        &seat,
        &fixture,
        &[(&locator, start)],
        stored + 2,
        true,
        NOW + 200,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_first_write_replayed"),
        DepositState::RefundDue {
            amount_minor: 4_000
        },
        "the host's cancel after the restore refunds the whole deposit"
    );
}

#[test]
fn a_host_cancel_first_seen_after_the_start_keeps_the_deposit_after_a_live_echo_withdrew_a_held_one()
 {
    // BK-ECHO-DEFERRED-SIGHTING-OUTLIVES-ECHO-RESTORE: the owner's cancelled
    // write is out when a pull before the start reads a cancellation from
    // the seat and holds it back. The provider refuses the write on its
    // precondition, storing nothing, and the seat then shows the booking
    // live again, byte for byte as the owner's last live write. That
    // withdraws the held sighting: a cancel the seat reports after the
    // start is first seen then, and keeps the deposit.
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let (booked, live, start) = written_live_then_cancelled_elsewhere(
        &fixture,
        &seat,
        b"held-sighting-withdrawn",
        "pi_held_sighting_withdrawn",
    );

    let held = SeatChange::upsert(&live, start, start + 30 * 60, live.sequence, true);
    seat.write_refused_after_pull(
        &fixture.vault,
        booked.calendar.event_ref,
        &held,
        NOW + 160,
        NOW + 150,
    );
    assert_eq!(
        state_of(&fixture, "pi_held_sighting_withdrawn"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "the cancellation held back while the owner's write is out moves no money"
    );

    seat.pull_own_write(&fixture.vault, &live, NOW + 180)
        .expect("seat pull");
    pull_seat(
        &seat,
        &fixture,
        &[(&live, start)],
        live.sequence + 3,
        true,
        start + 60,
    )
    .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_held_sighting_withdrawn"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a cancel first seen after the start keeps the deposit"
    );
}

#[test]
fn a_tombstone_from_a_seat_the_booking_was_not_written_to_keeps_the_deposit() {
    let fixture = Fixture::open(Some(two_hour_terms()));
    fixture.enable_host_feed();
    let mut provider = RecordingProvider::default();
    let seat = Seat::install(&fixture.vault, HOST_SEAT_SYSTEM);
    let shared = Seat::install(&fixture.vault, SHARED_SEAT_SYSTEM);

    let booked = paid_booking(
        &fixture,
        SessionKey::derive(b"shared-tombstone"),
        "pi_shared_tombstone",
        9,
    );
    settle_booking_deposit(
        &fixture.vault,
        &booked.calendar.event_ref,
        &mut provider,
        NOW + 50,
    )
    .expect("capture");
    assert_eq!(
        state_of(&fixture, "pi_shared_tombstone"),
        DepositState::Captured {
            amount_minor: 4_000
        }
    );
    seat.write(&fixture.vault, booked.calendar.event_ref, NOW + 55);

    // A seat the booking was never written to pulls its UID live, then pulls
    // a tombstone for it: the EVENT reads cancelled, the deposit stands.
    let start = MONDAY + 9 * 3_600;
    shared
        .pull(
            &fixture.vault,
            &[SeatChange::foreign(
                &shared,
                &booked.calendar.uid,
                start,
                start + 30 * 60,
                0,
                false,
            )],
            NOW + 60,
        )
        .expect("seat pull");
    shared
        .pull(
            &fixture.vault,
            &[SeatChange::tombstone(&booked.calendar.uid)],
            NOW + 120,
        )
        .expect("seat pull");
    assert_eq!(
        state_of(&fixture, "pi_shared_tombstone"),
        DepositState::Captured {
            amount_minor: 4_000
        },
        "a tombstone from a seat the booking was not written to moves no money"
    );
}
