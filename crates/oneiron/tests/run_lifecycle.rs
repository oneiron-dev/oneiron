//! The run lifecycle (untangle slice 5.0c): the interventions, the budget
//! hold and lease reclaim move an attempt row exactly as they did before
//! their writers consulted one transition table. The slice changes no
//! behaviour, so this file passes on the commit before the table and on the
//! slice's head. It uses only public paths, so it builds without the
//! library's own test modules. On the testkit: each test opens a copy of the
//! empty fixture vault and reads the fake clock, so every run sees the same
//! times:
//! `cargo test --locked -p oneiron --all-features --test run_lifecycle`.

use std::collections::HashSet;

use oneiron::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue, AttemptRecord,
    AttemptResumePoint, AttemptState, BUDGET_HOLD_ACTOR, ClaimAttempt, ClaimOutcome,
    CleanupAttemptLeases, EnqueueAttempt, EnqueueOutcome, HoldAttemptForBudget, InterveneAttempt,
    InterveneOutcome, RetryAttempt, RetryOutcome,
};
use oneiron::Vault;
use oneiron_testkit::{FixtureVault, VaultCopy, fixture_cache};

const KIND: &str = "test.run_lifecycle";
const WORKER: &str = "worker:run-lifecycle";
const PERSON: &str = "person:operator";

fn open() -> (VaultCopy, Vault) {
    let copy = FixtureVault::empty(&fixture_cache!())
        .expect("the empty fixture")
        .copy()
        .expect("a private copy");
    let vault = copy.open().expect("vault opens");
    (copy, vault)
}

fn enqueue(queue: &AttemptQueue<'_>, now: u64) -> AttemptRecord {
    let outcome = queue
        .enqueue(EnqueueAttempt {
            kind: KIND.to_owned(),
            payload: b"run".to_vec(),
            dedupe_key: None,
            run_id: None,
            now,
        })
        .expect("enqueue");
    let EnqueueOutcome::Enqueued(record) = outcome else {
        panic!("a fresh row is enqueued");
    };
    record
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

fn claims_nothing(queue: &AttemptQueue<'_>, now: u64) -> bool {
    matches!(
        queue
            .claim_kind(
                KIND,
                ClaimAttempt {
                    lease_owner: WORKER.to_owned(),
                    now,
                },
            )
            .expect("claim"),
        ClaimOutcome::Empty
    )
}

fn intervene(
    queue: &AttemptQueue<'_>,
    id: AttemptId,
    kind: AttemptInterventionKind,
    actor: &str,
    now: u64,
) -> oneiron::Result<InterveneOutcome> {
    queue.intervene(InterveneAttempt {
        id,
        kind,
        actor: actor.to_owned(),
        note: None,
        now,
    })
}

fn effect(
    queue: &AttemptQueue<'_>,
    id: AttemptId,
    kind: AttemptInterventionKind,
    now: u64,
) -> (AttemptInterventionEffect, AttemptState) {
    let outcome = intervene(queue, id, kind, PERSON, now).expect("the intervention is admitted");
    (outcome.effect, outcome.record.state)
}

fn budget_hold(record: &AttemptRecord, now: u64) -> HoldAttemptForBudget {
    HoldAttemptForBudget {
        id: record.id,
        lease_owner: WORKER.to_owned(),
        attempt_count: record.attempt_count,
        resume_point: AttemptResumePoint::new("step-3", now),
        now,
    }
}

#[test]
fn interventions_and_the_budget_hold_follow_the_table() {
    use AttemptInterventionEffect as E;
    use AttemptInterventionKind as K;
    use AttemptState as S;
    let (copy, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let now = copy.clock().now();
    let row = enqueue(&queue, now);
    let id = row.id;

    // Queued: a note is recorded, a resume is already done.
    assert_eq!(
        effect(&queue, id, K::Interrupt, now + 1),
        (E::Interrupted, S::Queued)
    );
    assert_eq!(
        effect(&queue, id, K::Resume, now + 2),
        (E::AlreadyResumed, S::Queued)
    );
    // A person's pause takes the row out of the ready index.
    assert_eq!(
        effect(&queue, id, K::Pause, now + 3),
        (E::Paused, S::Paused)
    );
    assert_eq!(
        effect(&queue, id, K::Pause, now + 4),
        (E::AlreadyPaused, S::Paused)
    );
    assert!(
        claims_nothing(&queue, now + 5),
        "a paused row is not claimable"
    );
    assert_eq!(
        effect(&queue, id, K::Resume, now + 6),
        (E::Resumed, S::Queued)
    );

    // Leased: no pause and no cancel; a resume is already done; a note is
    // recorded.
    let leased = claim(&queue, now + 7);
    assert_eq!(leased.state, S::Leased);
    assert!(intervene(&queue, id, K::Pause, PERSON, now + 8).is_err());
    assert!(intervene(&queue, id, K::Cancel, PERSON, now + 8).is_err());
    assert_eq!(
        effect(&queue, id, K::Resume, now + 9),
        (E::AlreadyResumed, S::Leased)
    );
    assert_eq!(
        effect(&queue, id, K::Interrupt, now + 10),
        (E::Interrupted, S::Leased)
    );

    // The budget hold: the lease holder parks its row Paused and releases the
    // lease; the same hold again changes nothing.
    let held = queue
        .hold_for_budget(budget_hold(&leased, now + 11))
        .expect("the budget hold is admitted");
    assert_eq!(held.state, S::Paused);
    assert!(held.budget_hold());
    assert_eq!(held.lease_owner, None);
    let again = queue
        .hold_for_budget(budget_hold(&leased, now + 12))
        .expect("the same hold again is admitted");
    assert_eq!(
        again.updated_at, held.updated_at,
        "a repeated hold writes nothing"
    );
    assert!(intervene(&queue, id, K::Pause, BUDGET_HOLD_ACTOR, now + 13).is_err());

    // A person's pause takes over the hold (FIX 9579).
    let taken = intervene(&queue, id, K::Pause, PERSON, now + 14).expect("pause");
    assert_eq!(taken.effect, E::Paused);
    assert_eq!(taken.record.state, S::Paused);
    assert!(!taken.record.budget_hold());
    assert_eq!(
        effect(&queue, id, K::Resume, now + 15),
        (E::Resumed, S::Queued)
    );

    // Cancelled: terminal; a second cancel is already done, everything else is
    // refused, and the hold no longer applies.
    assert_eq!(
        effect(&queue, id, K::Cancel, now + 16),
        (E::Cancelled, S::Cancelled)
    );
    assert_eq!(
        effect(&queue, id, K::Cancel, now + 17),
        (E::AlreadyCancelled, S::Cancelled)
    );
    for kind in [K::Resume, K::Pause, K::Interrupt] {
        assert!(intervene(&queue, id, kind, PERSON, now + 18).is_err());
    }
    assert!(
        queue
            .hold_for_budget(budget_hold(&leased, now + 19))
            .is_err()
    );
}

#[test]
fn a_deferred_row_resumes_deferred() {
    use AttemptInterventionEffect as E;
    use AttemptInterventionKind as K;
    use AttemptState as S;
    let (copy, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let now = copy.clock().now();
    enqueue(&queue, now);
    let leased = claim(&queue, now + 1);
    let due = now + 3_600;
    let outcome = queue
        .retry(RetryAttempt {
            id: leased.id,
            lease_owner: WORKER.to_owned(),
            attempt_count: leased.attempt_count,
            backoff_until: due,
            last_error: Some("again".to_owned()),
            now: now + 2,
        })
        .expect("retry");
    let RetryOutcome::Retried(next) = outcome else {
        panic!("the retry schedules a new try");
    };
    assert_eq!(next.state, S::Scheduled);
    assert_eq!(
        effect(&queue, next.id, K::Pause, now + 3),
        (E::Paused, S::Paused)
    );
    let resumed = intervene(&queue, next.id, K::Resume, PERSON, now + 4).expect("resume");
    assert_eq!(resumed.effect, E::Resumed);
    assert_eq!(
        resumed.record.state,
        S::Scheduled,
        "a resume restores the schedule"
    );
    assert_eq!(resumed.record.scheduled_at, Some(due));
    assert!(intervene(&queue, leased.id, K::Resume, PERSON, now + 5).is_err());
}

#[test]
fn reclaim_keeps_a_held_lease_and_requeues_an_expired_one() {
    let (copy, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let now = copy.clock().now();
    let row = enqueue(&queue, now);
    let leased = claim(&queue, now + 1);
    let read = |id| queue.get(id).expect("get").expect("row");

    // Not yet expired: the lease stays.
    queue
        .cleanup_leases(CleanupAttemptLeases {
            now: leased.updated_at + 1,
            lease_timeout_secs: 10,
        })
        .expect("cleanup");
    assert_eq!(read(row.id).state, AttemptState::Leased);

    // Expired but held (a parked row): the lease stays.
    let later = leased.updated_at + 100;
    queue
        .cleanup_leases_except(
            CleanupAttemptLeases {
                now: later,
                lease_timeout_secs: 10,
            },
            &HashSet::from([row.id]),
        )
        .expect("cleanup");
    assert_eq!(read(row.id).state, AttemptState::Leased);

    // Expired and not held: the same try goes back to the queue.
    let report = queue
        .cleanup_leases(CleanupAttemptLeases {
            now: later,
            lease_timeout_secs: 10,
        })
        .expect("cleanup");
    assert_eq!(report.stale_requeued, 1);
    let back = read(row.id);
    assert_eq!(back.state, AttemptState::Queued);
    assert_eq!(back.lease_owner, None);
    assert_eq!(back.last_error.as_deref(), Some("lease_timeout"));
    assert_eq!(back.lease_expirations.len(), 1);
}
