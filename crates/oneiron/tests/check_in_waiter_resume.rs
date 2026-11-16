//! ROLES-CHECKIN P2.3a, piece 2e (ARCH-0082 #waits and "When nobody
//! answers"; Engine ruling P23-SHAPE Q2-Q5 = A): the host wakes a due
//! check-in, and a settled one lets its act run once.
//!
//! - A housekeeping pass climbs a rung whose wait is over, after a restart
//!   too; a second pass at the same instant makes no second transition, and
//!   the next rung's wait starts at its entry.
//! - The due index holds each open row once, at its next due time: an
//!   extension moves it, a settlement drops it, and a stopped vault wakes at
//!   the first due rung.
//! - A held row stays held, pass after pass, while another row climbs.
//! - An approved act runs once: the spend commits with the act, an aborted
//!   act keeps nothing of it, a replay and another effect are refused.
//! - Only an approval, an undoable unsure act proceeding with its undo, and
//!   a delay window passed in silence make the act eligible, each on its own
//!   basis; a denial, a let-go, a hold, a standing objection or an open ask
//!   never does.
//!
//! On main this file does not build: there are no `due_rows`, `consume` or
//! `consume_then_abort` doors and no `EligibleBasis`.
//!
//! Needs the doors:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test check_in_waiter_resume`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/fixture.rs"]
mod fixture;
#[path = "check_in/ladder.rs"]
mod ladder;

use fixture::{DAY, DIGEST, Fixture, HOUR, T0, people, request};
use ladder::Ladder;
use oneiron::EntityId;
use oneiron::check_in::{
    ActClass, CheckInMode, CheckInTransition, DelayWindowOpen, EligibleBasis, HolderAnswer,
    PendingCheckIn, PendingState, Rung, WaitReason,
};
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::test_doors::check_in::{
    FixedChain, advance, answer, answer_verified, consume, consume_then_abort, due_rows,
    extend_verified, object, open,
};

/// One housekeeping pass, as the host's tick runs it.
fn pass(fx: &Fixture) {
    fx.vault
        .housekeeping(HousekeepingBudget::unbounded())
        .expect("housekeeping");
}

fn rung(row: &PendingCheckIn) -> Rung {
    row.current_rung().expect("a rung").rung
}

fn due(row: &PendingCheckIn) -> u64 {
    row.current_rung().expect("a rung").due_at()
}

/// The agent's ask to add a member: not undoable, so an exhausted chain
/// holds it.
fn add_member(l: &Ladder) -> PendingCheckIn {
    l.open(l.ask(l.delegate, ActClass::MemberAdd, "org:add-member"))
}

#[test]
fn a_due_rung_climbs_on_a_housekeeping_pass_after_a_restart() {
    let l = Ladder::new();
    let row = add_member(&l);
    let ends = due(&row);
    l.fx.at(ends - 1);
    pass(&l.fx);
    assert_eq!(
        rung(&l.fx.row(&row.id)),
        Rung::Grantor,
        "a second before its wait ends the rung stays"
    );

    let l = l.reopen();
    l.fx.at(ends);
    pass(&l.fx);
    let climbed = l.fx.row(&row.id);
    assert_eq!(
        rung(&climbed),
        Rung::ChainHolders,
        "the first pass after the restart climbs the due rung"
    );
    assert_eq!(l.fx.outcomes(&row.id), ["opened", "climbed", "climbed"]);
}

#[test]
fn a_second_pass_at_the_same_instant_makes_no_second_transition() {
    let l = Ladder::new();
    let row = add_member(&l);
    let ends = due(&row);
    l.fx.at(ends);
    pass(&l.fx);
    pass(&l.fx);
    assert_eq!(l.fx.outcomes(&row.id), ["opened", "climbed", "climbed"]);
    assert_eq!(
        due(&l.fx.row(&row.id)),
        ends + DAY,
        "the next rung's wait starts when the ask enters it"
    );
}

#[test]
fn the_due_index_holds_each_open_row_once_at_its_next_due_time() {
    let l = Ladder::new();
    let row = add_member(&l);
    let ends = due(&row);
    assert_eq!(due_rows(&l.fx.vault).expect("index"), [(ends, row.id)]);

    extend_verified(&l.fx.vault, &l.first_admin.1, &row.id, ends + HOUR)
        .expect("the grantor asks for an hour more");
    assert_eq!(
        due_rows(&l.fx.vault).expect("index"),
        [(ends + HOUR, row.id)],
        "an extension moves the entry"
    );

    answer_verified(
        &l.fx.vault,
        &l.first_admin.1,
        &row.id,
        &DIGEST,
        HolderAnswer::Approve,
    )
    .expect("the grantor approves");
    assert_eq!(
        due_rows(&l.fx.vault).expect("index"),
        [],
        "a settled row leaves the index"
    );
}

#[test]
fn a_stopped_vault_wakes_at_the_first_due_rung() {
    let l = Ladder::new();
    let before = l.fx.vault.housekeeping_wake_at().expect("wake");
    let row = add_member(&l);
    let ends = due(&row);
    assert!(
        before.is_none_or(|at| at > ends),
        "nothing else wakes this vault before the rung ends: {before:?}"
    );
    assert_eq!(l.fx.vault.housekeeping_wake_at().expect("wake"), Some(ends));
}

#[test]
fn a_held_row_stays_held_while_another_row_climbs() {
    let l = Ladder::new();
    let held = add_member(&l);
    l.fx.at(T0 + DAY);
    pass(&l.fx);
    l.fx.at(T0 + 2 * DAY);
    pass(&l.fx);
    assert_eq!(rung(&l.fx.row(&held.id)), Rung::Owner);
    let climbing = add_member(&l);

    l.fx.at(T0 + 3 * DAY);
    pass(&l.fx);
    assert_eq!(
        l.fx.row(&held.id).state,
        PendingState::Held { at: T0 + 3 * DAY },
        "past the Owner rung an act that may not proceed on silence holds"
    );
    assert_eq!(
        rung(&l.fx.row(&climbing.id)),
        Rung::ChainHolders,
        "the same pass climbs the other row"
    );

    l.fx.at(T0 + 9 * DAY);
    pass(&l.fx);
    assert_eq!(
        l.fx.outcomes(&held.id),
        ["opened", "climbed", "climbed", "climbed", "held"],
        "a held row takes no further transition"
    );
    assert!(consume(&l.fx.vault, &held.id, &DIGEST).is_err());
}

#[test]
fn an_approved_act_runs_once_and_an_aborted_run_keeps_nothing() {
    let l = Ladder::new();
    let row = add_member(&l);
    answer_verified(
        &l.fx.vault,
        &l.first_admin.1,
        &row.id,
        &DIGEST,
        HolderAnswer::Approve,
    )
    .expect("the grantor approves");

    assert!(
        consume(&l.fx.vault, &row.id, &[0x0f; 32]).is_err(),
        "another effect cannot spend the approval"
    );
    assert_eq!(
        consume_then_abort(&l.fx.vault, &row.id, &DIGEST).expect("spent, then aborted"),
        EligibleBasis::Approved
    );
    assert_eq!(
        l.fx.row(&row.id).consumed_at,
        None,
        "an act that failed keeps nothing of the spend"
    );

    assert_eq!(
        consume(&l.fx.vault, &row.id, &DIGEST).expect("the act runs"),
        EligibleBasis::Approved
    );
    assert!(
        consume(&l.fx.vault, &row.id, &DIGEST).is_err(),
        "a replay finds the act already ran"
    );
    assert_eq!(l.fx.row(&row.id).consumed_at, Some(T0));
    assert_eq!(
        l.fx.outcomes(&row.id),
        ["opened", "climbed", "answered", "consumed"]
    );
    let spent = l.fx.receipts(&row.id).pop().expect("receipt");
    assert_eq!(spent.fields["basis"], "approved");
}

#[test]
fn only_an_approval_an_undo_or_a_silent_window_makes_the_act_eligible() {
    let fx = Fixture::open();
    let (holder, holder_proof) = fx.person();
    let (objector, _) = fx.person();
    let chain = FixedChain::default().with(Rung::Owner, people(&[holder]));
    let opened = |ask| open(&fx.vault, ask, &chain).expect("open").id;

    let approved = opened(request(EntityId::now(), ActClass::Spawn));
    let denied = opened(request(EntityId::now(), ActClass::Spawn));
    for (id, word) in [
        (approved, HolderAnswer::Approve),
        (denied, HolderAnswer::Deny),
    ] {
        answer(&fx.vault, &holder_proof, &id, &DIGEST, word).expect("answer");
    }
    let still_open = opened(request(EntityId::now(), ActClass::Spawn));
    let let_go = opened({
        let mut ask = request(EntityId::now(), ActClass::Spawn);
        ask.until = Some(T0 + HOUR);
        ask
    });
    let held = opened(request(EntityId::now(), ActClass::MemberRemove));
    let proceeds = opened({
        let mut ask = request(EntityId::now(), ActClass::ReversibleWork);
        ask.mode = CheckInMode::AskWhenUnsure;
        ask.reason = WaitReason::Unsure;
        ask.undo_plan = Some("undo:restore-version".to_owned());
        ask
    });
    let windowed = || {
        let mut ask = request(EntityId::now(), ActClass::OutboundSend);
        ask.delay_window = Some(DelayWindowOpen {
            notice_at: T0,
            ends_at: T0 + 7 * DAY,
        });
        opened(ask)
    };
    let silent = windowed();
    let objected = windowed();
    object(&fx.vault, &objected, objector).expect("objection");

    let tick = |id: &EntityId| advance(&fx.vault, id, &chain).expect("tick");
    fx.at(T0 + HOUR);
    assert_eq!(tick(&let_go), Some(CheckInTransition::LetGo));
    fx.at(T0 + DAY);
    assert_eq!(tick(&held), Some(CheckInTransition::Held));
    assert_eq!(tick(&proceeds), Some(CheckInTransition::ProceedWithUndo));
    for id in [silent, objected] {
        assert_eq!(tick(&id), Some(CheckInTransition::AwaitsWindow));
    }
    fx.at(T0 + 7 * DAY);
    assert_eq!(tick(&silent), Some(CheckInTransition::WindowPassed));
    assert_eq!(tick(&objected), Some(CheckInTransition::ObjectionHeld));

    for (id, basis) in [
        (approved, EligibleBasis::Approved),
        (proceeds, EligibleBasis::ProceedWithUndo),
        (silent, EligibleBasis::WindowPassed),
    ] {
        assert_eq!(fx.row(&id).eligible_basis(), Some(basis));
        assert_eq!(consume(&fx.vault, &id, &DIGEST).expect("eligible"), basis);
        let spent = fx.receipts(&id).pop().expect("receipt");
        assert_eq!(
            (spent.outcome.as_str(), spent.fields["basis"].as_str()),
            ("consumed", basis.as_str())
        );
    }
    for (id, what) in [
        (denied, "a denial"),
        (still_open, "an open ask"),
        (let_go, "a let-go"),
        (held, "a hold"),
        (objected, "a standing objection"),
    ] {
        assert_eq!(fx.row(&id).eligible_basis(), None, "{what}");
        assert!(
            consume(&fx.vault, &id, &DIGEST).is_err(),
            "{what} never lets the act run"
        );
        assert_eq!(fx.row(&id).consumed_at, None, "{what}");
    }
}
