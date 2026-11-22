//! A seat's replay that reads the owner's cancelled write as its own, on the
//! old home after a booking home move, still notes the cancel Oneiron cannot
//! attribute on the new home's deposit (FIX
//! [BK-REPLAY-NOTE-NOT-CARRIED-TO-NEW-HOME]; Engine ANSWER
//! BK-REPLAY-NOTE-DELIVERY = A, 21 Nov 08:16: "a synced, typed
//! replay-evidence claim per cancelled member, read where the live deposit
//! is").
//!
//! The replay runs where the seat's outbox row is, which a home move does not
//! carry: the old home. Its proof writer wrote the note on that node's
//! deposit row, which the move froze, so the write refused, the proof stayed
//! owed, and the new home, which holds the deposit, never read the note. Now
//! the proof records the replay as a `calendar.replay_cancel_evidence` claim
//! on the EVENT, claims sync, and the new home reads it for its live deposit:
//! the held deposit's row there names the unattributed cancel at the write's
//! SEQUENCE, and the frozen old home names none.
//!
//! The two machines are copies of one vault, as
//! `tests/booking_home_move_carries_deposit.rs` makes them. The test carries
//! the replay's evidence claim from the old home to the new one with the
//! public claim put, as the live mirror carries a claim.
//!
//! Red on the base d84b3b9eb84c: the old home's replay proof refuses on its
//! frozen deposit row ("this node froze its booking rows for a home move"),
//! so the seat's replayed write ends in that error, not in its precondition
//! refusal, and the new home's row carries no note. The claim's provenance
//! ref is red on #10166's head 7cdc5c16ca1e: it is the seat write's passport
//! ref, which names the seat's calendar ref (a CalDAV seat's collection
//! href) and the booking's UID, and the claim syncs.
//!
//! A proof claim is signed for the EVENT it names, and a `claim_of` edge is
//! any writer's: a proof linked to another booking's EVENT notes no cancel
//! on that booking (review round 2 of #10166). Red on #10166's head
//! 91d09f814167: the lookup follows the edge, so the other booking's
//! captured deposit names the cancel and asks for a refund by hand.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test booking_home_move_replay_note`.
#![cfg(all(oneiron_test_support, feature = "sync"))]

mod booking_host_seat_support;
#[path = "booking_deposit_support/fixture.rs"]
mod fixture;

use std::sync::Arc;

use booking_host_seat_support::{Seat, SeatChange, seat_owner};
use fixture::{Fixture, MONDAY, NOW, event_type, slot_of};
use oneiron::booking::lifecycle::{
    BOOKING_HELD_DEPOSIT_ITEM_PREFIX, DepositCheckoutStart, DepositProviderEvent,
    DepositProviderEventKind, DepositProviderEventOutcome, DepositProviderFailure,
    DepositSettleMove, DepositSettleRequest, DepositSettlementPort, DepositState,
    begin_deposit_checkout, booking_deposit_for_payment, record_deposit_provider_event,
    settle_booking_deposit,
};
use oneiron::booking::{
    ConfirmReceipt, DEFAULT_INTRO_DURATION_MIN, DepositRefundRule, DepositTerms, HoldLeaseSpec,
    SessionKey,
};
use oneiron::calendar::claims::PREDICATE_CALENDAR_STATUS;
use oneiron::memory::{
    ClaimProposalReviewRequest, ClaimSettleDecision, ClaimSettleRequest, ClaimSettlementVerdict,
};
use oneiron::test_doors::booking_home_move::{
    booking_inbox_row_version, drop_node_local_booking_rows, move_booking_home,
};
use oneiron::{
    ClaimApprovalStatus, ClaimLifecycleStatus, EdgeActorClass, EdgeKind, EntityId, TimeRange,
    Vault, VaultConfig,
};
use oneiron_store::ports::manual_clock::ManualClock;

const DEPOSIT_MINOR: u64 = 4_000;
const PAYMENT: &str = "pi_replay_note_moved";
/// The payment of a second booking, which no write of the seat cancelled.
const OTHER_PAYMENT: &str = "pi_replay_note_other";
/// The host's own calendar, the seat the booking is written to.
const HOST_SEAT_SYSTEM: &str = "host-seat";
/// The visitor's calendar, which the booking was never written to.
const VISITOR_SEAT_SYSTEM: &str = "visitor-seat";
/// The predicate of the replay's evidence claim, spelled out so this file
/// builds on the base, which has no such claim.
const REPLAY_CANCEL_EVIDENCE: &str = "calendar.replay_cancel_evidence";

/// A provider that does every move.
struct Provider;

impl DepositSettlementPort for Provider {
    fn settle(
        &mut self,
        request: &DepositSettleRequest<'_>,
    ) -> Result<u64, DepositProviderFailure> {
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

fn config(clock: &Arc<ManualClock>) -> VaultConfig {
    let mut config = VaultConfig::default();
    config.store_clock = clock.bundle();
    config
}

/// The booking's slot: 09:00 UTC on the fixture Monday.
fn slot() -> TimeRange {
    let start = MONDAY + 9 * 3_600;
    TimeRange {
        start,
        end: start + u64::from(DEFAULT_INTRO_DURATION_MIN) * 60,
    }
}

/// Checkout, a hold on its lease, the provider's authorization and the
/// confirm, then the capture: the deposit stands captured.
fn captured_booking(machine: &Fixture) -> ConfirmReceipt {
    captured_booking_of(machine, b"replay-note-moved", PAYMENT, NOW, |start| {
        start == slot().start
    })
}

/// [`captured_booking`] for the session `seed` paid by `payment`, from `at`,
/// in the first offered slot whose start `pick` takes.
fn captured_booking_of(
    machine: &Fixture,
    seed: &[u8],
    payment: &str,
    at: u64,
    pick: impl Fn(u64) -> bool,
) -> ConfirmReceipt {
    let session = SessionKey::derive(seed);
    let offered = machine
        .offered_slots()
        .into_iter()
        .find(|offered| pick(offered.start_utc))
        .expect("FIXTURE: the slot is offered");
    let lease = begin_deposit_checkout(
        &machine.vault,
        &DepositCheckoutStart {
            page_ref: machine.page,
            event_type: event_type(),
            session_key: session,
            terms: terms(),
            payment_id: payment.to_owned(),
        },
        at,
    )
    .expect("FIXTURE: checkout");
    let hold = machine
        .hold(
            session,
            slot_of(&offered),
            HoldLeaseSpec::CheckoutExtension {
                server_issued_lease: lease.lease.clone(),
            },
            at,
        )
        .expect("FIXTURE: a hold on the checkout lease");
    assert_eq!(
        record_deposit_provider_event(
            &machine.vault,
            &DepositProviderEvent {
                event_id: format!("evt-auth-{payment}"),
                payment_id: payment.to_owned(),
                kind: DepositProviderEventKind::Authorized {
                    amount_minor: DEPOSIT_MINOR,
                    currency: "usd".to_owned(),
                },
            },
            at + 30,
        )
        .expect("FIXTURE: the provider's authorization"),
        DepositProviderEventOutcome::Applied(DepositState::Authorized)
    );
    let booked = machine
        .confirm(&hold, session, at + 40)
        .expect("FIXTURE: the confirm on the authorized deposit");
    settle_booking_deposit(
        &machine.vault,
        &booked.calendar.event_ref,
        &mut Provider,
        at + 50,
    )
    .expect("FIXTURE: the capture");
    booked
}

fn state_of(machine: &Fixture) -> Option<DepositState> {
    booking_deposit_for_payment(&machine.vault, PAYMENT)
        .expect("read the deposit")
        .map(|deposit| deposit.state)
}

/// The visitor's calendar, which the booking was never written to, carries
/// `booked` cancelled at `now`, and the owner approves that cancellation, so
/// the booking reads cancelled with its deposit held
/// (DEPOSIT-HOST-CANCEL-SOURCE = A).
fn cancel_on_unwritten_calendar(machine: &Fixture, booked: &ConfirmReceipt, now: u64) {
    let slot = slot();
    let visitor = Seat::install(&machine.vault, VISITOR_SEAT_SYSTEM);
    for (sequence, cancelled, at) in [(0, false, now - 30), (1, true, now)] {
        visitor
            .pull(
                &machine.vault,
                &[SeatChange::foreign(
                    &visitor,
                    &booked.calendar.uid,
                    slot.start,
                    slot.end,
                    sequence,
                    cancelled,
                )],
                at,
            )
            .expect("FIXTURE: the visitor calendar's pull");
    }
    approve_imported_status(&machine.vault, booked.calendar.event_ref);
}

/// The owner reviews and approves every proposed `calendar.status` import on
/// `event`: a pulled calendar's cancellation lands Proposed, and a booking
/// reads only surfaceable heads.
fn approve_imported_status(vault: &Vault, event: EntityId) {
    let (id, owner) = seat_owner(vault);
    let memory = vault.memory(id, EdgeActorClass::Human);
    for claim in vault
        .claims_for_subject(&event)
        .expect("claims on the EVENT")
    {
        let body = vault.get_claim(&claim).expect("read claim").expect("claim");
        if body.predicate != PREDICATE_CALENDAR_STATUS
            || body.approval != ClaimApprovalStatus::Proposed
            || body.lifecycle != ClaimLifecycleStatus::Active
        {
            continue;
        }
        let review = memory
            .claim_review_as_owner(
                &owner,
                &ClaimProposalReviewRequest {
                    claim_ref: claim.to_hex(),
                    grant_ref: None,
                },
            )
            .expect("FIXTURE: the owner reviews the imported status");
        let settled = memory
            .claim_settle_as_owner(
                &owner,
                &ClaimSettleRequest {
                    claim_ref: claim.to_hex(),
                    review_id: review.review_id,
                    decision: ClaimSettleDecision::Approve,
                    grant_ref: None,
                },
            )
            .expect("FIXTURE: the owner approves the imported status");
        assert_eq!(settled.verdict, ClaimSettlementVerdict::Landed);
    }
}

/// Puts on `to` each replay-evidence claim on `event` that `from` holds and
/// `to` does not, as the live mirror carries a claim between machines.
/// Returns how many it carried.
fn carry_replay_evidence(from: &Vault, to: &Vault, event: EntityId, now: u64) -> usize {
    let held = to.claims_for_subject(&event).expect("claims on the EVENT");
    let mut carried = 0;
    for claim in from
        .claims_for_subject(&event)
        .expect("claims on the EVENT")
    {
        if held.contains(&claim) {
            continue;
        }
        let body = from.get_claim(&claim).expect("read claim").expect("claim");
        if body.predicate != REPLAY_CANCEL_EVIDENCE {
            continue;
        }
        to.put_claim(
            &claim,
            &body,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .expect("the new home stores the carried claim");
        carried += 1;
    }
    carried
}

/// Asserts that `vault` holds one replay-evidence claim on `event` and that
/// it names none of `withheld` (the seat's calendar ref, which for a CalDAV
/// seat is its collection href, and the booking's UID): the claim syncs, and
/// carries no ICS, href or payment data (BK-REPLAY-NOTE-DELIVERY = A; review
/// round 1 of #10166).
fn assert_replay_evidence_withholds(vault: &Vault, event: EntityId, withheld: &[&str]) {
    let mut recorded = 0;
    for claim in vault
        .claims_for_subject(&event)
        .expect("claims on the EVENT")
    {
        let body = vault.get_claim(&claim).expect("read claim").expect("claim");
        if body.predicate != REPLAY_CANCEL_EVIDENCE {
            continue;
        }
        recorded += 1;
        let stored = format!("{body:?}");
        for needle in withheld {
            assert!(
                !stored.contains(needle),
                "the synced replay-evidence claim names {needle:?}: {stored}"
            );
        }
    }
    assert_eq!(recorded, 1, "the replay recorded one evidence claim");
}

#[test]
fn a_replay_on_the_old_home_after_a_move_notes_the_unattributed_cancel_on_the_new_home() {
    let clock = ManualClock::new(NOW);
    let seed = Fixture::open_in(
        tempfile::tempdir().expect("temp dir"),
        config(&clock),
        Some(terms()),
    );
    seed.enable_host_feed();
    let seat = Seat::install(&seed.vault, HOST_SEAT_SYSTEM);
    let booked = captured_booking(&seed);
    let event = booked.calendar.event_ref;
    let slot = slot();
    let live = seat.write(&seed.vault, event, NOW + 55);
    seat.pull(
        &seed.vault,
        &[SeatChange::upsert(&live, slot.start, slot.end, 0, false)],
        NOW + 60,
    )
    .expect("FIXTURE: the seat's first pull");
    cancel_on_unwritten_calendar(&seed, &booked, NOW + 120);
    // The owner's cancelled write lands on the seat, but its answer is lost,
    // and the provider stores it rewritten without the write's marker.
    let stored = seat.write_with_lost_answer(&seed.vault, event, NOW + 150);
    let copy = seat.stripped_rewrite_of_own_write(&live, stored, NOW + 160);

    let (old_home, new_home) = seed.into_machines(|| config(&clock));
    drop_node_local_booking_rows(&new_home.vault).expect("FIXTURE: the new home's own rows");
    assert!(
        move_booking_home(&old_home.vault, &new_home.vault, &[])
            .expect("the move carries the booking rows"),
        "every booking section is applied on the new home"
    );
    assert_eq!(
        state_of(&new_home),
        Some(DepositState::Captured {
            amount_minor: DEPOSIT_MINOR
        }),
        "the captured deposit moved to the new home"
    );
    let row = format!("{BOOKING_HELD_DEPOSIT_ITEM_PREFIX}{}", event.to_hex());
    assert_eq!(
        booking_inbox_row_version(&new_home.vault, &row).expect("read the new home's row"),
        None,
        "no unattributed cancel is noted before the replay"
    );

    // The seat's outbox row stayed on the old home: the replay runs there,
    // and reads the stored copy as the owner's own write.
    seat.replay_refused_over(&old_home.vault, event, &copy, NOW + 170);
    assert_eq!(
        booking_inbox_row_version(&old_home.vault, &row).expect("read the old home's row"),
        None,
        "the old home froze its deposit for the move and notes nothing on it"
    );
    assert_replay_evidence_withholds(
        &old_home.vault,
        event,
        &[&format!("{HOST_SEAT_SYSTEM}-calendar"), &live.uid],
    );

    assert_eq!(
        carry_replay_evidence(&old_home.vault, &new_home.vault, event, NOW + 175),
        1,
        "the replay recorded one evidence claim on the EVENT"
    );
    assert_eq!(
        booking_inbox_row_version(&new_home.vault, &row).expect("read the new home's row"),
        Some(format!("unattributed_cancel:{stored}")),
        "the new home's held deposit names the cancel Oneiron cannot attribute, at the write's \
         SEQUENCE"
    );
    assert_eq!(
        state_of(&new_home),
        Some(DepositState::Captured {
            amount_minor: DEPOSIT_MINOR
        }),
        "the note moves no money"
    );
}

#[test]
fn a_replay_proof_linked_to_another_booking_notes_no_cancel_there() {
    let clock = ManualClock::new(NOW);
    let machine = Fixture::open_in(
        tempfile::tempdir().expect("temp dir"),
        config(&clock),
        Some(terms()),
    );
    machine.enable_host_feed();
    let seat = Seat::install(&machine.vault, HOST_SEAT_SYSTEM);
    let booked = captured_booking(&machine);
    let event = booked.calendar.event_ref;
    let slot = slot();
    let live = seat.write(&machine.vault, event, NOW + 55);
    seat.pull(
        &machine.vault,
        &[SeatChange::upsert(&live, slot.start, slot.end, 0, false)],
        NOW + 60,
    )
    .expect("FIXTURE: the seat's first pull");
    cancel_on_unwritten_calendar(&machine, &booked, NOW + 120);
    let stored = seat.write_with_lost_answer(&machine.vault, event, NOW + 150);
    let copy = seat.stripped_rewrite_of_own_write(&live, stored, NOW + 160);
    seat.replay_refused_over(&machine.vault, event, &copy, NOW + 170);
    let row = |event: EntityId| format!("{BOOKING_HELD_DEPOSIT_ITEM_PREFIX}{}", event.to_hex());
    assert_eq!(
        booking_inbox_row_version(&machine.vault, &row(event)).expect("read the booking's row"),
        Some(format!("unattributed_cancel:{stored}")),
        "FIXTURE: the replay notes the cancel on the booking its write cancelled"
    );

    let other = captured_booking_of(
        &machine,
        b"replay-note-other",
        OTHER_PAYMENT,
        NOW + 200,
        |start| start != slot.start,
    )
    .calendar
    .event_ref;
    let proofs: Vec<EntityId> = machine
        .vault
        .claims_for_subject(&event)
        .expect("claims on the EVENT")
        .into_iter()
        .filter(|claim| {
            machine
                .vault
                .get_claim(claim)
                .expect("read claim")
                .is_some_and(|body| body.predicate == REPLAY_CANCEL_EVIDENCE)
        })
        .collect();
    assert_eq!(proofs.len(), 1, "FIXTURE: the replay recorded one proof");
    machine
        .vault
        .put_edge(&proofs[0], EdgeKind::ClaimOf, &other, 1.0)
        .expect("FIXTURE: link the proof to the other booking's EVENT");
    assert!(
        machine
            .vault
            .claims_for_subject(&other)
            .expect("claims on the other EVENT")
            .contains(&proofs[0]),
        "FIXTURE: the other booking's EVENT now lists the proof"
    );
    assert_eq!(
        booking_inbox_row_version(&machine.vault, &row(other)).expect("read the other row"),
        None,
        "a proof signed for one booking notes no cancel on another booking it is linked to \
         (#10166's head 91d09f814167 names the cancel there)"
    );
    assert_eq!(
        booking_deposit_for_payment(&machine.vault, OTHER_PAYMENT)
            .expect("read the other deposit")
            .map(|deposit| deposit.state),
        Some(DepositState::Captured {
            amount_minor: DEPOSIT_MINOR
        }),
        "the other booking's deposit stands captured"
    );
}
