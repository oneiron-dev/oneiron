//! A home move carries the booking rows, and the deposits' money with them
//! (FIX [BK-LIFECYCLE-ROWS-NOT-CARRIED-BY-HOME-MOVE]; lead ruling
//! BK-HOME-MOVE-CARRIES-BOOKINGS = A, 21 Nov 06:2x: "Money follows the home,
//! and a move must never silently strand a visitor's link or a deposit"). The
//! lifecycle writes on the home alone, and a home move carried none of its
//! node-local rows: on the new home a visitor's link to a booking confirmed
//! before the move did not resolve, and the old home went on settling the
//! deposit. Now:
//! - a visitor cancels on the new home a booking the old home confirmed and
//!   captured: the refund is owed and paid there, and the old home moves no
//!   money;
//! - a capture owed at the move is asked by the new home alone: it queues
//!   the settle row itself, and the old home's queued row ends with no call;
//! - a visitor who held and paid on the old home confirms on the new home,
//!   and the old home starts no new checkout;
//! - the confirmation's parties travel apart under the booker's key:
//!   withheld, the receipt lands as its facts alone, and the cancel works;
//! - a provider cancellation the old home hears after its freeze is deferred
//!   there, writing nothing, and voids the deposit on the new home; a capture
//!   the provider answers with nothing captured (the payment stands
//!   cancelled) voids it too.
//!
//! The two machines are copies of one vault, as
//! `tests/room_pins_concurrent_merge.rs` makes them, so the bookings' EVENTs
//! and claims stand on both, as sync leaves them. The door
//! `drop_node_local_booking_rows` empties the new home's node-local booking
//! rows, which no sync carries, and `move_booking_home` freezes the old home
//! and carries each booking section the build registers.
//!
//! Red on main 315a7f87ba6a, where no booking section is registered and the
//! move carries nothing: the new home refuses the cancel ("token does not
//! resolve to a booking") and the confirm, holds no deposit to capture, and
//! the old home's drain captures after the freeze; the old home applies a
//! provider event after the freeze.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test booking_home_move_carries_deposit`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

#[path = "booking_deposit_support/fixture.rs"]
mod fixture;

use std::sync::Arc;

use fixture::{Fixture, MONDAY, NOW, event_type, slot_of};
use oneiron::VaultConfig;
use oneiron::booking::lifecycle::{
    DepositCheckoutLease, DepositCheckoutStart, DepositProviderEvent, DepositProviderEventKind,
    DepositProviderEventOutcome, DepositProviderFailure, DepositSettleMove, DepositSettleRequest,
    DepositSettlementPort, DepositState, begin_deposit_checkout, booking_confirmation_context,
    booking_deposit_for_payment, record_deposit_provider_event, run_booking_deposit_settlement,
    settle_booking_deposit,
};
use oneiron::booking::{
    BookingError, ConfirmReceipt, DepositRefundRule, DepositTerms, HoldLeaseSpec, HoldReceipt,
    SessionKey,
};
use oneiron::test_doors::booking_home_move::{drop_node_local_booking_rows, move_booking_home};
use oneiron_store::ports::manual_clock::ManualClock;

const DEPOSIT_MINOR: u64 = 4_000;

/// A provider that does every move and records each one.
#[derive(Default)]
struct RecordingProvider {
    moves: Vec<(String, DepositSettleMove)>,
}

impl DepositSettlementPort for RecordingProvider {
    fn settle(
        &mut self,
        request: &DepositSettleRequest<'_>,
    ) -> Result<u64, DepositProviderFailure> {
        self.moves
            .push((request.payment_id.to_owned(), request.movement));
        Ok(match request.movement {
            DepositSettleMove::Capture { amount_minor }
            | DepositSettleMove::Refund { amount_minor } => amount_minor,
            DepositSettleMove::Void => 0,
        })
    }
}

/// A full refund up to two hours before the start.
fn terms() -> DepositTerms {
    DepositTerms {
        amount_minor: DEPOSIT_MINOR,
        currency: "usd".to_owned(),
        refund: DepositRefundRule {
            full_refund_notice_secs: 2 * 3_600,
            late_cancel_refund_percent: 0,
        },
    }
}

/// A vault config whose store clock reads `clock`, so the rows a move
/// stamps (a hold's liveness at export, a settle row's queueing) read the
/// fixture's Monday.
fn config(clock: &Arc<ManualClock>) -> VaultConfig {
    let mut config = VaultConfig::default();
    config.store_clock = clock.bundle();
    config
}

/// One machine with the deposit fixture, its clock at the fixture's `NOW`.
fn seed() -> (Fixture, Arc<ManualClock>) {
    let clock = ManualClock::new(NOW);
    let machine = Fixture::open_in(
        tempfile::tempdir().expect("temp dir"),
        config(&clock),
        Some(terms()),
    );
    (machine, clock)
}

/// The seed's two copies: the old home, and the new home with none of the
/// old home's node-local booking rows.
fn old_and_new_home(seed: Fixture, clock: &Arc<ManualClock>) -> (Fixture, Fixture) {
    let (old_home, new_home) = seed.into_machines(|| config(clock));
    drop_node_local_booking_rows(&new_home.vault).expect("FIXTURE: the new home's own rows");
    (old_home, new_home)
}

fn checkout(
    machine: &Fixture,
    session: SessionKey,
    payment_id: &str,
    now: u64,
) -> Result<DepositCheckoutLease, BookingError> {
    begin_deposit_checkout(
        &machine.vault,
        &DepositCheckoutStart {
            page_ref: machine.page,
            event_type: event_type(),
            session_key: session,
            terms: terms(),
            payment_id: payment_id.to_owned(),
        },
        now,
    )
}

/// Checkout, a hold on its lease and the provider's authorization, for the
/// slot that starts at `hour` UTC on the fixture Monday.
fn paid_hold(machine: &Fixture, session: SessionKey, payment_id: &str, hour: u64) -> HoldReceipt {
    let slot = machine
        .offered_slots()
        .into_iter()
        .find(|slot| slot.start_utc == MONDAY + hour * 3_600)
        .expect("FIXTURE: the slot is offered");
    let lease = checkout(machine, session, payment_id, NOW).expect("FIXTURE: checkout");
    let hold = machine
        .hold(
            session,
            slot_of(&slot),
            HoldLeaseSpec::CheckoutExtension {
                server_issued_lease: lease.lease.clone(),
            },
            NOW,
        )
        .expect("FIXTURE: a hold on the checkout lease");
    assert_eq!(
        record_deposit_provider_event(
            &machine.vault,
            &DepositProviderEvent {
                event_id: format!("evt-auth-{payment_id}"),
                payment_id: payment_id.to_owned(),
                kind: DepositProviderEventKind::Authorized {
                    amount_minor: DEPOSIT_MINOR,
                    currency: "usd".to_owned(),
                },
            },
            NOW + 30,
        )
        .expect("FIXTURE: the provider's authorization"),
        DepositProviderEventOutcome::Applied(DepositState::Authorized)
    );
    hold
}

/// [`paid_hold`], confirmed: the capture is due.
fn paid_booking(machine: &Fixture, session: SessionKey, payment_id: &str) -> ConfirmReceipt {
    let hold = paid_hold(machine, session, payment_id, 12);
    machine
        .confirm(&hold, session, NOW + 40)
        .expect("FIXTURE: the confirm on the authorized deposit")
}

fn state_of(machine: &Fixture, payment_id: &str) -> Option<DepositState> {
    booking_deposit_for_payment(&machine.vault, payment_id)
        .expect("read the deposit")
        .map(|deposit| deposit.state)
}

/// Every move `machine`'s settle drain asks of its provider at `now`.
fn drained_moves(machine: &Fixture, now: u64) -> Vec<(String, DepositSettleMove)> {
    let mut provider = RecordingProvider::default();
    run_booking_deposit_settlement(
        &machine.vault,
        "deposit-settle-worker",
        &mut provider,
        16,
        now,
    )
    .expect("drain the settle rows");
    provider.moves
}

#[test]
fn a_visitor_cancel_on_the_new_home_owes_and_pays_the_refund_there() {
    let (seed, clock) = seed();
    let booking = paid_booking(&seed, SessionKey::derive(b"move-cancel"), "pi_move_cancel");
    settle_booking_deposit(
        &seed.vault,
        &booking.calendar.event_ref,
        &mut RecordingProvider::default(),
        NOW + 50,
    )
    .expect("FIXTURE: the capture on the old home");
    let captured = Some(DepositState::Captured {
        amount_minor: DEPOSIT_MINOR,
    });
    assert_eq!(state_of(&seed, "pi_move_cancel"), captured);
    let (old_home, new_home) = old_and_new_home(seed, &clock);
    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("the home move"),
        "every booking section applies"
    );

    assert!(
        booking_confirmation_context(&new_home.vault, &booking.calendar.event_ref)
            .expect("read the confirmation")
            .is_some_and(|context| context.booker_ref == old_home.booker.to_hex()),
        "the confirmation's parties came with the booker's part"
    );
    new_home
        .cancel(&booking.cancel_token, NOW + 60)
        .expect("the visitor's cancel link resolves on the new home");
    assert_eq!(
        state_of(&new_home, "pi_move_cancel"),
        Some(DepositState::RefundDue {
            amount_minor: DEPOSIT_MINOR
        }),
        "the cancel four hours ahead owes the whole deposit back on the new home"
    );
    assert_eq!(
        drained_moves(&new_home, NOW + 70),
        vec![(
            "pi_move_cancel".to_owned(),
            DepositSettleMove::Refund {
                amount_minor: DEPOSIT_MINOR
            }
        )],
        "the new home pays the refund once"
    );
    assert_eq!(
        state_of(&new_home, "pi_move_cancel"),
        Some(DepositState::Refunded {
            amount_minor: DEPOSIT_MINOR
        })
    );

    assert!(
        drained_moves(&old_home, NOW + 70).is_empty(),
        "the old home moves no money"
    );
    assert_eq!(
        state_of(&old_home, "pi_move_cancel"),
        captured,
        "the old home keeps its row as history"
    );
}

#[test]
fn a_capture_owed_at_the_move_is_asked_by_the_new_home_alone() {
    let (seed, clock) = seed();
    paid_booking(
        &seed,
        SessionKey::derive(b"move-capture"),
        "pi_move_capture",
    );
    let capture_due = Some(DepositState::CaptureDue {
        amount_minor: DEPOSIT_MINOR,
    });
    assert_eq!(state_of(&seed, "pi_move_capture"), capture_due);
    let (old_home, new_home) = old_and_new_home(seed, &clock);
    assert!(
        drained_moves(&new_home, NOW + 45).is_empty(),
        "FIXTURE: the new home's copies of the old home's settle rows find no deposit and end"
    );
    assert!(move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("the home move"));

    assert!(
        drained_moves(&old_home, NOW + 50).is_empty(),
        "the old home's queued capture ends with no provider call after the freeze"
    );
    assert_eq!(state_of(&old_home, "pi_move_capture"), capture_due);
    assert_eq!(
        drained_moves(&new_home, NOW + 50),
        vec![(
            "pi_move_capture".to_owned(),
            DepositSettleMove::Capture {
                amount_minor: DEPOSIT_MINOR
            }
        )],
        "the new home queued the owed capture itself and asks it once"
    );
    assert_eq!(
        state_of(&new_home, "pi_move_capture"),
        Some(DepositState::Captured {
            amount_minor: DEPOSIT_MINOR
        })
    );
}

/// A provider that answers every capture with nothing captured: the payment
/// stands cancelled at the provider, as Stripe's port answers a refused
/// capture of a cancelled PaymentIntent.
struct CancelledPaymentProvider;

impl DepositSettlementPort for CancelledPaymentProvider {
    fn settle(
        &mut self,
        request: &DepositSettleRequest<'_>,
    ) -> Result<u64, DepositProviderFailure> {
        match request.movement {
            DepositSettleMove::Capture { .. } | DepositSettleMove::Void => Ok(0),
            DepositSettleMove::Refund { amount_minor } => Ok(amount_minor),
        }
    }
}

#[test]
fn a_provider_cancel_during_the_move_is_applied_where_the_deposit_landed() {
    let (seed, clock) = seed();
    paid_booking(&seed, SessionKey::derive(b"move-void"), "pi_move_void");
    let capture_due = Some(DepositState::CaptureDue {
        amount_minor: DEPOSIT_MINOR,
    });
    let (old_home, new_home) = old_and_new_home(seed, &clock);
    assert!(move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("the home move"));

    let cancel = DepositProviderEvent {
        event_id: "evt-cancel-pi_move_void".to_owned(),
        payment_id: "pi_move_void".to_owned(),
        kind: DepositProviderEventKind::Canceled,
    };
    let on_old_home = record_deposit_provider_event(&old_home.vault, &cancel, NOW + 50)
        .expect("the old home answers the event");
    // By its name, so the red run on main, which has no such answer, fails
    // on this assert rather than to compile.
    assert_eq!(
        format!("{on_old_home:?}"),
        "Deferred",
        "the frozen old home defers the event, so the provider delivers it again"
    );
    assert_eq!(
        state_of(&old_home, "pi_move_void"),
        capture_due,
        "the old home's history is unchanged"
    );
    assert_eq!(
        record_deposit_provider_event(&new_home.vault, &cancel, NOW + 55)
            .expect("the new home applies the event"),
        DepositProviderEventOutcome::Applied(DepositState::Voided),
        "the redelivered cancellation voids the carried deposit on the new home"
    );
    assert!(
        drained_moves(&new_home, NOW + 60).is_empty(),
        "the new home's queued capture finds nothing owed"
    );
}

#[test]
fn a_capture_of_a_cancelled_payment_on_the_new_home_voids_the_deposit() {
    let (seed, clock) = seed();
    paid_booking(&seed, SessionKey::derive(b"move-gone"), "pi_move_gone");
    let (old_home, new_home) = old_and_new_home(seed, &clock);
    assert!(move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("the home move"));

    let drained = run_booking_deposit_settlement(
        &new_home.vault,
        "deposit-settle-worker",
        &mut CancelledPaymentProvider,
        16,
        NOW + 50,
    )
    .expect("drain the new home's settle rows");
    assert_eq!(drained.captured, 1, "the carried capture was asked once");
    assert_eq!(
        state_of(&new_home, "pi_move_gone"),
        Some(DepositState::Voided),
        "a capture that captured nothing leaves no capture owed: the deposit voids"
    );
}

#[test]
fn a_visitor_who_paid_on_the_old_home_confirms_on_the_new_home() {
    let (seed, clock) = seed();
    let session = SessionKey::derive(b"move-confirm");
    let hold = paid_hold(&seed, session, "pi_move_confirm", 12);
    let (old_home, new_home) = old_and_new_home(seed, &clock);
    assert!(move_booking_home(&old_home.vault, &new_home.vault, &[]).expect("the home move"));

    new_home
        .confirm(&hold, session, NOW + 40)
        .expect("the hold, its lease and the authorized deposit came with the home");
    assert_eq!(
        state_of(&new_home, "pi_move_confirm"),
        Some(DepositState::CaptureDue {
            amount_minor: DEPOSIT_MINOR
        })
    );
    assert!(
        checkout(
            &old_home,
            SessionKey::derive(b"after-the-move"),
            "pi_after_the_move",
            NOW + 50
        )
        .is_err(),
        "the old home starts no checkout once it froze its booking rows"
    );
    assert_eq!(state_of(&old_home, "pi_after_the_move"), None);
}

#[test]
fn a_withheld_booker_part_lands_the_receipt_as_its_facts_and_the_cancel_works() {
    let (seed, clock) = seed();
    let booking = paid_booking(
        &seed,
        SessionKey::derive(b"move-withheld"),
        "pi_move_withheld",
    );
    let (old_home, new_home) = old_and_new_home(seed, &clock);
    assert!(
        booking_confirmation_context(&old_home.vault, &booking.calendar.event_ref)
            .expect("read the confirmation")
            .is_some(),
        "FIXTURE: the old home holds the confirmation's parties"
    );
    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[old_home.booker])
            .expect("the home move"),
        "a part that does not open is no Conflict"
    );

    assert_eq!(
        booking_confirmation_context(&new_home.vault, &booking.calendar.event_ref)
            .expect("read the confirmation"),
        None,
        "the booker's part withheld: the receipt lands as its facts alone"
    );
    new_home
        .cancel(&booking.cancel_token, NOW + 60)
        .expect("the cancel needs none of the parties");
    assert_eq!(
        state_of(&new_home, "pi_move_withheld"),
        Some(DepositState::VoidDue),
        "the cancel before the capture releases the authorization on the new home"
    );
}
