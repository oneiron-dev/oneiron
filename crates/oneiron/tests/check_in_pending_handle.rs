//! ROLES-CHECKIN P2.2, piece 2b (Engine rulings PR2-SPLIT = B and P22-SHAPE
//! Q1, Q2, Q8, Q9 = A): when `check_in` answers Wait, the caller opens a
//! pending check-in that stores its asker, grant, verb, act class, scope,
//! effect digest and rungs, and it survives a reopen. Opening it runs
//! nothing. Only a person pinned on the current rung answers it, over the
//! exact effect digest; the first valid answer lands, and every other holder
//! reads who gave it. Each transition writes one `check_in` receipt in its
//! own transaction.
//!
//! On #7090's head this file does not build: there is no pending check-in,
//! no `check_in` receipt kind and no `test_doors::check_in`.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_pending_handle`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/fixture.rs"]
mod fixture;

use fixture::{DAY, DIGEST, Fixture, T0, people, request};
use oneiron::EntityId;
use oneiron::check_in::{
    ActClass, CheckInAnswer, CheckInMode, CheckInRequest, HolderAnswer, PendingState, RolePreset,
    Rung, UnsureTest, WaitSource, check_in,
};
use oneiron::receipt::ReceiptKind;
use oneiron::test_doors::check_in::{FixedChain, answer, open};

struct NoModel;

impl UnsureTest for NoModel {
    fn is_sure(&self) -> oneiron::error::Result<bool> {
        Ok(false)
    }
}

#[test]
fn a_wait_opens_a_pending_check_in_that_survives_a_reopen() {
    let fixture = Fixture::open();
    let (holder, _) = fixture.person();
    let asker = EntityId::now();
    let checked = check_in(
        &CheckInRequest {
            act: ActClass::MemberRemove,
            role: RolePreset::Deputy,
            holds_power: true,
            explicit_mode: None,
            standing_row: None,
        },
        &NoModel,
    );
    let CheckInAnswer::Wait(reason) = checked else {
        panic!("a Deputy's member removal waits (R3 = B): {checked:?}");
    };
    let mut ask = request(asker, ActClass::MemberRemove);
    ask.reason = reason;
    let chain = FixedChain::default().with(Rung::Grantor, people(&[holder]));
    let opened = open(&fixture.vault, ask, &chain).expect("open");

    assert_eq!(opened.state, PendingState::Open);
    assert_eq!(opened.asker, asker);
    assert_eq!(opened.grant_ref, "grant:asker");
    assert_eq!(opened.act, ActClass::MemberRemove);
    assert_eq!(opened.effect_digest, DIGEST);
    assert_eq!(opened.opened_at, T0);
    let rung = opened.current_rung().expect("on a rung");
    assert_eq!(rung.rung, Rung::Grantor);
    assert_eq!(rung.holders.len(), 1);
    assert_eq!(rung.holders[0].principal, holder);
    let wait = rung.wait.as_ref().expect("a person rung waits");
    assert_eq!(wait.secs, DAY, "24 hours per person rung (R2)");
    assert_eq!(wait.floor.source, WaitSource::ShippedDefault);
    assert_eq!(rung.due_at(), T0 + DAY);
    assert_eq!(opened.next_due_at(), Some(T0 + DAY));

    let id = opened.id;
    let fixture = fixture.reopen();
    assert_eq!(fixture.row(&id), opened, "the row survives a reopen");
}

#[test]
fn opening_runs_nothing_and_receipts_the_open_and_the_climb() {
    let fixture = Fixture::open();
    let (holder, _) = fixture.person();
    let asker = EntityId::now();
    let chain = FixedChain::default().with(Rung::Grantor, people(&[holder]));
    let opened = open(&fixture.vault, request(asker, ActClass::Spawn), &chain).expect("open");

    assert_eq!(
        ReceiptKind::parse("check_in"),
        Some(ReceiptKind::CheckIn),
        "the receipt kind's token"
    );
    assert_eq!(fixture.outcomes(&opened.id), ["opened", "climbed"]);
    let receipts = fixture.receipts(&opened.id);
    assert_eq!(receipts[0].actor.as_deref(), Some(asker.to_hex().as_str()));
    assert_eq!(receipts[0].fields["act_class"], "spawn");
    assert_eq!(receipts[0].fields["verb"], "vault.agents.spawn");
    assert_eq!(receipts[0].fields["mode"], "manual");
    assert_eq!(receipts[1].actor, None, "the climb is the engine's");
    assert_eq!(receipts[1].fields["rung"], "grantor");
    assert_eq!(receipts[1].fields["holders"], holder.to_hex());
    assert_eq!(receipts[1].fields["wait_secs"], DAY.to_string());
    assert_eq!(receipts[1].fields["floor_source"], "shipped_default");
    assert_eq!(
        fixture.row(&opened.id).state,
        PendingState::Open,
        "nothing answered it and nothing ran"
    );
}

#[test]
fn an_answer_over_another_effect_settles_nothing() {
    let fixture = Fixture::open();
    let (holder, proof) = fixture.person();
    let chain = FixedChain::default().with(Rung::Grantor, people(&[holder]));
    let opened = open(
        &fixture.vault,
        request(EntityId::now(), ActClass::Spawn),
        &chain,
    )
    .expect("open");

    let other = [0x77; 32];
    assert!(
        answer(
            &fixture.vault,
            &proof,
            &opened.id,
            &other,
            HolderAnswer::Approve
        )
        .is_err(),
        "an answer over another effect is refused"
    );
    assert_eq!(fixture.row(&opened.id), opened, "and changes nothing");

    let answered = answer(
        &fixture.vault,
        &proof,
        &opened.id,
        &DIGEST,
        HolderAnswer::Approve,
    )
    .expect("answer");
    assert_eq!(
        answered.state,
        PendingState::Answered {
            answer: HolderAnswer::Approve,
            by: Some(holder),
            rung: Rung::Grantor,
            at: T0,
        }
    );
    assert_eq!(
        fixture.outcomes(&opened.id),
        ["opened", "climbed", "answered"]
    );
    let receipt = fixture
        .receipts(&opened.id)
        .pop()
        .expect("the answer's receipt");
    assert_eq!(receipt.fields["by"], holder.to_hex());
    assert_eq!(receipt.fields["answer"], "approve");
}

#[test]
fn only_a_person_pinned_on_the_current_rung_answers() {
    let fixture = Fixture::open();
    let (holder, _) = fixture.person();
    let (_, outsider) = fixture.person();
    let chain = FixedChain::default().with(Rung::Grantor, people(&[holder]));
    let opened = open(
        &fixture.vault,
        request(EntityId::now(), ActClass::Spawn),
        &chain,
    )
    .expect("open");
    assert!(
        answer(
            &fixture.vault,
            &outsider,
            &opened.id,
            &DIGEST,
            HolderAnswer::Approve
        )
        .is_err(),
        "a person the rung did not pin is refused"
    );
    assert_eq!(fixture.row(&opened.id).state, PendingState::Open);
}

#[test]
fn the_first_valid_answer_lands_and_the_others_read_who_gave_it() {
    let fixture = Fixture::open();
    let (first, first_proof) = fixture.person();
    let (second, second_proof) = fixture.person();
    let chain = FixedChain::default().with(Rung::Grantor, people(&[first, second]));
    let opened = open(
        &fixture.vault,
        request(EntityId::now(), ActClass::Spawn),
        &chain,
    )
    .expect("open");

    answer(
        &fixture.vault,
        &first_proof,
        &opened.id,
        &DIGEST,
        HolderAnswer::Deny,
    )
    .expect("deny");
    assert!(
        answer(
            &fixture.vault,
            &second_proof,
            &opened.id,
            &DIGEST,
            HolderAnswer::Approve
        )
        .is_err(),
        "a second answer is refused"
    );
    let PendingState::Answered {
        answer: word, by, ..
    } = fixture.row(&opened.id).state
    else {
        panic!("answered");
    };
    assert_eq!(word, HolderAnswer::Deny);
    assert_eq!(by, Some(first), "the other holder reads who answered");
    assert_ne!(by, Some(second));
}

#[test]
fn a_never_ask_act_and_a_window_its_act_does_not_accept_open_nothing() {
    let fixture = Fixture::open();
    let (holder, _) = fixture.person();
    let chain = FixedChain::default().with(Rung::Grantor, people(&[holder]));
    let mut never = request(EntityId::now(), ActClass::Spawn);
    never.mode = CheckInMode::NeverAsk;
    assert!(open(&fixture.vault, never, &chain).is_err());

    let mut window = request(EntityId::now(), ActClass::Delete);
    window.delay_window = Some(oneiron::check_in::DelayWindowOpen {
        notice_at: T0,
        ends_at: T0 + 7 * DAY,
    });
    assert!(
        open(&fixture.vault, window, &chain).is_err(),
        "a delete accepts no delay window"
    );

    let mut plan = request(EntityId::now(), ActClass::MemberRemove);
    plan.undo_plan = Some("undo:member".to_owned());
    assert!(
        open(&fixture.vault, plan, &chain).is_err(),
        "an undo plan needs an undoable act"
    );
    assert!(
        fixture.every_receipt().is_empty(),
        "a refused open writes no receipt"
    );
}
