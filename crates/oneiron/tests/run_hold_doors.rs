//! RUN-HOLD through the test doors (`oneiron::test_doors::run_hold`):
//! - a hook hold's override releases the hold and grants nothing: the saved
//!   wait stays, so the next claim meets the hook boundary on the same ask,
//!   and no override record is kept for it;
//! - the annotation override record goes with its row;
//! - an actor's erase, through the scrubs the override tables register,
//!   leaves every release (annotation, budget, fan-out) without that actor.
//!
//! The doors build only under the test cfg:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test run_hold_doors`.
#![cfg(oneiron_test_support)]

#[path = "run_hold/fixture.rs"]
mod fixture;

use fixture::{
    HeldWave, KIND, WORKER, annotation_held_row, claim, claimed, enqueued, held_wave_planner,
    last_note, open, person, read, resume, unix_now,
};
use oneiron::agent_dispatch::{AgentDispatcher, BudgetHoldLease, BudgetHoldState};
use oneiron::attempt_queue::{
    AttemptInterventionEffect, AttemptQueue, AttemptResumePoint, EnqueueAttempt, PauseKind,
    RunState,
};
use oneiron::test_doors::run_hold;

/// The erased actor's name in a record that keeps its row.
const ERASED: &str = "erased";

/// The lead's condition 3: an override never grants hook consent.
#[test]
fn raw_resume_of_hook_hold_keeps_the_saved_wait_and_grants_nothing() {
    let (_dir, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let now = unix_now();
    let operator = person(&vault, now).to_hex();
    let row = enqueued(
        queue
            .enqueue(EnqueueAttempt {
                kind: KIND.to_owned(),
                payload: b"turn".to_vec(),
                dedupe_key: None,
                run_id: None,
                now,
            })
            .expect("enqueue"),
    );
    let leased = claimed(claim(&queue, KIND, now + 1));
    let invocation = [0x7A; 16];
    let mut wait = AttemptResumePoint::new("turn-action:host-hook:1", now + 2);
    wait.artifact_ref = Some(format!("hook-ask:{}:{}", "7a".repeat(16), "5c".repeat(16)));
    run_hold::hold_for_hook(
        &vault,
        leased.id,
        WORKER,
        leased.attempt_count,
        invocation,
        wait.clone(),
        now + 2,
    )
    .expect("the hook hold is admitted");
    assert_eq!(
        RunState::of(&read(&queue, row.id)),
        RunState::Paused(PauseKind::Hook)
    );

    let resumed = resume(&queue, row.id, &operator, now + 3);
    assert_eq!(resumed.effect, AttemptInterventionEffect::Resumed);
    assert_eq!(
        last_note(&resumed.record),
        Some("override of the hook hold")
    );
    assert_eq!(
        run_hold::hold_override_actor(&vault, row.id).expect("override read"),
        None,
        "a hook override records no release"
    );

    let again = claimed(claim(&queue, KIND, now + 4));
    assert_eq!(again.id, row.id);
    let point = again
        .cancel_state
        .resume_point
        .as_ref()
        .expect("the saved wait stays on the row");
    assert_eq!(
        point.marker, wait.marker,
        "the next run meets the same hook boundary"
    );
    assert_eq!(point.artifact_ref, wait.artifact_ref, "on the same ask");
}

/// The lead's condition 2: the override record joins the row's deletion and
/// the actor erasure.
#[test]
fn annotation_override_goes_with_its_row_and_loses_an_erased_actor() {
    let (_dir, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let now = unix_now();
    let (row, actor_id) = annotation_held_row(&vault, &queue, now);
    let operator = person(&vault, now);
    resume(&queue, row.id, &operator.to_hex(), now + 6);
    assert_eq!(
        run_hold::hold_override_actor(&vault, row.id).expect("override read"),
        Some(operator.to_hex()),
        "the override names its actor"
    );

    // Another actor's erasure leaves it; the operator's erasure scrubs it.
    assert_eq!(
        run_hold::erase_actor_in_run_hold_tables(&vault, &actor_id).expect("erase"),
        3,
        "each override table registers its actor scrub"
    );
    assert_eq!(
        run_hold::hold_override_actor(&vault, row.id).expect("override read"),
        Some(operator.to_hex())
    );
    run_hold::erase_actor_in_run_hold_tables(&vault, &operator).expect("erase");
    assert_eq!(
        run_hold::hold_override_actor(&vault, row.id).expect("override read"),
        Some(ERASED.to_owned()),
        "the release stands without the erased actor"
    );

    // The row's deletion takes the record with it.
    assert_eq!(run_hold::drop_kind(&vault, KIND).expect("drop"), 1);
    assert!(queue.get(row.id).expect("get").is_none());
    assert_eq!(
        run_hold::hold_override_actor(&vault, row.id).expect("override read"),
        None,
        "the override record is gone with its row"
    );
}

/// Review round 1 of #6895: the budget and fan-out records that name an
/// override's actor lose an erased actor too; the releases stand.
#[test]
fn budget_and_fanout_overrides_lose_an_erased_actor() {
    let (_dir, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let now = unix_now();
    let operator = person(&vault, now);

    // A budget hold, released by the operator's override.
    let row = enqueued(
        queue
            .enqueue(EnqueueAttempt {
                kind: KIND.to_owned(),
                payload: b"run".to_vec(),
                dedupe_key: None,
                run_id: None,
                now,
            })
            .expect("enqueue"),
    );
    let leased = claimed(claim(&queue, KIND, now + 1));
    dispatcher
        .hold_for_budget(
            row.id,
            BudgetHoldLease {
                attempt: leased.id,
                lease_owner: WORKER.to_owned(),
                attempt_count: leased.attempt_count,
                resume_point: AttemptResumePoint::new("step-3", now + 2),
            },
            None,
            "spend cap",
            now + 2,
        )
        .expect("the budget hold is admitted");
    resume(&queue, row.id, &operator.to_hex(), now + 3);

    // A fan-out hold, released by the operator's override.
    let HeldWave {
        row: planner,
        launch,
        ..
    } = held_wave_planner(&vault, &queue, now + 4);
    resume(&queue, planner.id, &operator.to_hex(), now + 8);
    assert_eq!(
        run_hold::launch_override_actors(&vault, launch).expect("launch read"),
        vec![operator.to_hex()]
    );

    run_hold::erase_actor_in_run_hold_tables(&vault, &operator).expect("erase");
    let hold = dispatcher
        .plan_hold(row.id)
        .expect("plan hold")
        .expect("the hold record stays");
    assert_eq!(hold.state, BudgetHoldState::Resumed, "the resume stands");
    assert_eq!(hold.resumed_by.as_deref(), Some(ERASED));
    assert_eq!(
        run_hold::launch_override_actors(&vault, launch).expect("launch read"),
        vec![ERASED.to_owned()],
        "the planner's release stands without the erased actor"
    );
}
