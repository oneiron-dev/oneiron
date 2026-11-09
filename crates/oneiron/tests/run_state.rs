//! The run state (untangle slice 5.0c): [`RunState::of`] derives the state a
//! run reports from its attempt row, and the run tree's status token follows
//! from it. Public paths only:
//! `cargo test --locked -p oneiron --all-features --test run_state`.

use std::time::{SystemTime, UNIX_EPOCH};

use oneiron::attempt_queue::run_tree_view::RunTreeStatus;
use oneiron::attempt_queue::{
    AttemptInterventionKind, AttemptQueue, AttemptRecord, AttemptResumePoint, ClaimAttempt,
    ClaimOutcome, EnqueueAttempt, EnqueueOutcome, HoldAttemptForBudget, InterveneAttempt,
    PauseKind, RetryAttempt, RetryOutcome, RunState,
};
use oneiron::{Vault, VaultConfig};

const KIND: &str = "test.run_state";
const WORKER: &str = "worker:run-state";

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

fn claim(queue: &AttemptQueue<'_>, now: u64) -> AttemptRecord {
    let outcome = queue
        .claim_kind(
            KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now,
            },
        )
        .expect("claim");
    let ClaimOutcome::Claimed(record) = outcome else {
        panic!("the ready row is claimed");
    };
    record
}

fn intervene(
    queue: &AttemptQueue<'_>,
    record: &AttemptRecord,
    kind: AttemptInterventionKind,
    now: u64,
) -> AttemptRecord {
    queue
        .intervene(InterveneAttempt {
            id: record.id,
            kind,
            actor: "person:operator".to_owned(),
            note: None,
            now,
        })
        .expect("the intervention is admitted")
        .record
}

#[test]
fn a_run_reports_the_state_its_row_holds() {
    let dir = tempfile::tempdir().expect("temp dir");
    let vault = Vault::open(dir.path(), VaultConfig::device()).expect("vault opens");
    let queue = AttemptQueue::new(&vault);
    let now = unix_now();
    let EnqueueOutcome::Enqueued(row) = queue
        .enqueue(EnqueueAttempt {
            kind: KIND.to_owned(),
            payload: b"run".to_vec(),
            dedupe_key: None,
            run_id: None,
            now,
        })
        .expect("enqueue")
    else {
        panic!("a fresh row is enqueued");
    };

    assert_eq!(RunState::of(&row), RunState::Ready);
    assert_eq!(RunState::of(&row).tree_status(), RunTreeStatus::Queued);

    let paused = intervene(&queue, &row, AttemptInterventionKind::Pause, now + 1);
    assert_eq!(RunState::of(&paused), RunState::Paused(PauseKind::Person));
    assert_eq!(RunState::of(&paused).tree_status(), RunTreeStatus::Paused);
    intervene(&queue, &row, AttemptInterventionKind::Resume, now + 2);

    let leased = claim(&queue, now + 3);
    assert_eq!(RunState::of(&leased), RunState::Running);
    assert_eq!(RunState::of(&leased).with_park(true), RunState::Parked);
    assert_eq!(RunState::of(&leased).with_park(false), RunState::Running);
    assert_eq!(
        RunState::of(&leased).with_park(true).tree_status(),
        RunTreeStatus::Running
    );

    let held = queue
        .hold_for_budget(HoldAttemptForBudget {
            id: leased.id,
            lease_owner: WORKER.to_owned(),
            attempt_count: leased.attempt_count,
            resume_point: AttemptResumePoint::new("step-1", now + 4),
            now: now + 4,
        })
        .expect("the budget hold is admitted");
    assert_eq!(RunState::of(&held), RunState::Paused(PauseKind::Budget));
    // The parked flag reads only a running row.
    assert_eq!(
        RunState::of(&held).with_park(true),
        RunState::Paused(PauseKind::Budget)
    );
    let taken = intervene(&queue, &held, AttemptInterventionKind::Pause, now + 5);
    assert_eq!(RunState::of(&taken), RunState::Paused(PauseKind::Person));
    intervene(&queue, &taken, AttemptInterventionKind::Resume, now + 6);

    let leased = claim(&queue, now + 7);
    let RetryOutcome::Retried(next) = queue
        .retry(RetryAttempt {
            id: leased.id,
            lease_owner: WORKER.to_owned(),
            attempt_count: leased.attempt_count,
            backoff_until: now + 3_600,
            last_error: Some("again".to_owned()),
            now: now + 8,
        })
        .expect("retry")
    else {
        panic!("the retry schedules a new try");
    };
    assert_eq!(RunState::of(&next), RunState::Deferred);
    assert_eq!(RunState::of(&next).tree_status(), RunTreeStatus::Paused);
    let source = queue.get(leased.id).expect("get").expect("row");
    assert_eq!(RunState::of(&source), RunState::Failed);

    let cancelled = intervene(&queue, &next, AttemptInterventionKind::Cancel, now + 9);
    assert_eq!(RunState::of(&cancelled), RunState::Cancelled);
    assert_eq!(
        RunState::of(&cancelled).tree_status(),
        RunTreeStatus::Cancelled
    );
}
