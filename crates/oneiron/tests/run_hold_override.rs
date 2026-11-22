//! RUN-HOLD (lead 18:5x, shape agreed 20:44): a generic Resume of a row an
//! engine hold paused moves the hold's own record in the same transaction,
//! so the row and the hold agree afterwards. Before the change, the Resume
//! cleared the row's pause and left the hold's record as it was: the budget
//! hold stayed Held and still owed its held notice, and the next claim or
//! apply parked the annotation and fan-out rows again.
//!
//! Public paths only, so this file builds on the slice's base (5.0c) as on
//! its head:
//! `cargo test --locked -p oneiron --all-features --test run_hold_override`.

#[path = "run_hold/fixture.rs"]
mod fixture;

use fixture::{
    HeldWave, KIND, WORKER, annotation_held_row, claim, claimed, enqueued, held_wave_planner,
    last_note, open, person, read, resume, unix_now, wave_plan,
};
use oneiron::EdgeActorClass;
use oneiron::agent_dispatch::{AgentDispatcher, BudgetHoldLease, BudgetHoldState};
use oneiron::attempt_queue::{
    AttemptInterventionEffect, AttemptQueue, AttemptResumePoint, AttemptState, ClaimOutcome,
    EnqueueAttempt, PauseKind, RunState,
};
use oneiron::wave_orchestration::{WAVE_PLAN_ATTEMPT_KIND, WaveApplyOutcome};

/// The audit's case: a person resumes a run the spend cap parked. The plan
/// hold reads Resumed under that person and owes no held Ask any more.
#[test]
fn raw_resume_of_budget_hold_does_not_diverge_hold_record() {
    let (_dir, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let now = unix_now();
    let operator = person(&vault, now).to_hex();
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
    let held = dispatcher
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
            None,
        )
        .expect("the budget hold is admitted");
    assert_eq!(held.state, BudgetHoldState::Held);
    assert_eq!(
        RunState::of(&read(&queue, row.id)),
        RunState::Paused(PauseKind::Budget)
    );

    let resumed = resume(&queue, row.id, &operator, now + 3);
    assert_eq!(resumed.effect, AttemptInterventionEffect::Resumed);
    assert_eq!(resumed.record.state, AttemptState::Queued);
    let hold = dispatcher
        .plan_hold(row.id)
        .expect("plan hold")
        .expect("the hold record stays");
    assert_eq!(
        hold.state,
        BudgetHoldState::Resumed,
        "the hold follows the row"
    );
    assert!(hold.held.is_empty(), "no attempt is left on the hold");
    assert_eq!(hold.resumed_at, Some(now + 3));
    assert_eq!(hold.resumed_by.as_deref(), Some(operator.as_str()));
    assert!(
        dispatcher
            .deliver_budget_notice(row.id)
            .expect("deliver")
            .is_none(),
        "no held Ask goes out after the override"
    );
    assert_eq!(
        last_note(&resumed.record),
        Some("override of the budget hold"),
        "the Resume event names the override"
    );
}

/// A person resumes a comment's task that the claim parked while its comment
/// is unattached. The next claim leases it instead of parking it again.
#[test]
fn raw_resume_of_annotation_hold_is_not_parked_again() {
    let (_dir, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let now = unix_now();
    let (row, actor_id) = annotation_held_row(&vault, &queue, now);
    let resumed = resume(&queue, row.id, &actor_id.to_hex(), now + 6);
    assert_eq!(resumed.effect, AttemptInterventionEffect::Resumed);
    let leased = claim(&queue, KIND, now + 7);
    assert!(
        matches!(&leased, ClaimOutcome::Claimed(record) if record.id == row.id),
        "the released row is leased, not parked again: {:?}",
        RunState::of(&read(&queue, row.id))
    );
    assert_eq!(
        last_note(&resumed.record),
        Some("override of the annotation hold")
    );
}

/// A person resumes a wave's planning attempt that waits on the fan-out
/// approval. Its next apply completes it instead of parking it again; the
/// cut itself still waits for the owner.
#[test]
fn raw_resume_of_fanout_hold_completes_the_planner() {
    let (_dir, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let now = unix_now();
    let HeldWave {
        row,
        launch,
        actor,
        epic,
    } = held_wave_planner(&vault, &queue, now);

    let resumed = resume(&queue, row.id, &actor.to_hex(), now + 3);
    assert_eq!(resumed.effect, AttemptInterventionEffect::Resumed);

    let second = claimed(claim(&queue, WAVE_PLAN_ATTEMPT_KIND, now + 4));
    assert_eq!(second.id, row.id);
    let outcome = vault
        .apply_wave_plan_attempt_gated(
            actor,
            EdgeActorClass::Human,
            &second,
            wave_plan(epic),
            None,
            now + 5,
        )
        .expect("the gated apply again");
    assert!(
        matches!(&outcome, WaveApplyOutcome::Paused(receipt) if receipt.launch_ref == launch),
        "the cut still waits for the owner"
    );
    assert_eq!(
        read(&queue, row.id).state,
        AttemptState::Completed,
        "the released planner completes instead of parking again"
    );
    assert_eq!(
        last_note(&resumed.record),
        Some("override of the fan-out hold")
    );
}
