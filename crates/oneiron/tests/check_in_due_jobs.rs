//! DESIGN 15-setting-primitive, stage 5b-2: each open pending check-in is a row of the
//! `check_in.due` job, a one-time job at the row's next due time, and the schedule's due index is
//! the only index of open rows (`CHECK_IN_DUE` is gone).
//! - opening a check-in arms its row at the first rung's end, an extension moves it, and a
//!   settlement disarms it;
//! - a pass runs the due row: the rung climbs and the row stays armed at the next rung's end; a
//!   second pass at the same instant runs nothing; a row that holds past the last rung is final,
//!   and its row is disarmed.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test check_in_due_jobs`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "check_in/fixture.rs"]
mod fixture;
#[path = "check_in/ladder.rs"]
mod ladder;

use fixture::{DIGEST, Fixture, HOUR};
use ladder::Ladder;
use oneiron::EntityId;
use oneiron::check_in::{ActClass, HolderAnswer, PendingCheckIn, PendingState, Rung};
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::test_doors::check_in::{answer_verified, extend_verified};
use oneiron::test_doors::schedule::due_at;

/// The job each open pending check-in arms.
const JOB: &str = "check_in.due";

/// One housekeeping pass, as the host's tick runs it.
fn pass(fx: &Fixture) {
    fx.vault
        .housekeeping(HousekeepingBudget::unbounded())
        .expect("housekeeping");
}

/// When the check-in `id`'s row of the job is next due, or `None` when it is not armed.
fn armed(l: &Ladder, id: &EntityId) -> Option<u64> {
    due_at(&l.fx.vault, JOB, Some(*id)).expect("schedule")
}

fn rung(row: &PendingCheckIn) -> Rung {
    row.current_rung().expect("a rung").rung
}

fn rung_ends(row: &PendingCheckIn) -> u64 {
    row.current_rung().expect("a rung").due_at()
}

/// The agent's ask to add a member: not undoable, so an exhausted chain holds it.
fn add_member(l: &Ladder) -> PendingCheckIn {
    l.open(l.ask(l.delegate, ActClass::MemberAdd, "org:add-member"))
}

#[test]
fn an_open_check_in_arms_its_row_at_its_next_due_time_until_it_settles() {
    let l = Ladder::new();
    let row = add_member(&l);
    let ends = rung_ends(&row);
    assert_eq!(
        armed(&l, &row.id),
        Some(ends),
        "opening arms the row at the first rung's end"
    );

    extend_verified(&l.fx.vault, &l.first_admin.1, &row.id, ends + HOUR)
        .expect("the grantor asks for an hour more");
    assert_eq!(
        armed(&l, &row.id),
        Some(ends + HOUR),
        "an extension moves the row"
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
        armed(&l, &row.id),
        None,
        "a settled check-in disarms its row"
    );
}

#[test]
fn a_pass_runs_the_due_row_which_stays_armed_at_the_next_rung_until_the_ask_holds() {
    let l = Ladder::new();
    let row = add_member(&l);
    let ends = rung_ends(&row);

    l.fx.at(ends);
    pass(&l.fx);
    let climbed = l.fx.row(&row.id);
    assert_eq!(
        rung(&climbed),
        Rung::ChainHolders,
        "the pass climbs the due rung"
    );
    let next = rung_ends(&climbed);
    assert!(next > ends, "the next rung's wait starts at its entry");
    assert_eq!(
        armed(&l, &row.id),
        Some(next),
        "the run leaves the row armed at the next rung's end"
    );

    pass(&l.fx);
    assert_eq!(
        l.fx.outcomes(&row.id),
        ["opened", "climbed", "climbed"],
        "a second pass at the same instant makes no transition"
    );
    assert_eq!(
        armed(&l, &row.id),
        Some(next),
        "and leaves the row as it was"
    );

    l.fx.at(next);
    pass(&l.fx);
    let owner_rung = l.fx.row(&row.id);
    assert_eq!(rung(&owner_rung), Rung::Owner);
    let last = rung_ends(&owner_rung);
    assert_eq!(armed(&l, &row.id), Some(last));

    l.fx.at(last);
    pass(&l.fx);
    assert_eq!(
        l.fx.row(&row.id).state,
        PendingState::Held { at: last },
        "past the Owner rung an act that may not proceed on silence holds"
    );
    assert_eq!(
        armed(&l, &row.id),
        None,
        "a held check-in is final: its row is disarmed"
    );
}
