//! FIX RUN-LEASE: an attempt parked on its signal keeps its lease until the
//! signal resumes it, so no lease rung touches it. The lease-warning sweep
//! and the single-row warning door ask it to land under no caller, and the
//! public reclaim doors (`cleanup_leases`, `cleanup_kind_leases`) requeue
//! it under no caller, as the maintenance sweep already did. A leased
//! attempt with no park beside it is warned and reclaimed as before, in the
//! same call. Public paths only, so the file builds without the library's
//! own test modules:
//! `cargo test --locked -p oneiron --all-features --test run_lease_parked`.

use oneiron::Vault;
use oneiron::attempt_queue::{
    AttemptId, AttemptQueue, AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome,
    CleanupAttemptLeases, LeaseWarningOutcome, WarnAttemptLeaseExpiry, WarnExpiringAttemptLeases,
};
use oneiron::dreamer_runner::{
    DREAMER_RUNNER_ATTEMPT_KIND, DreamerParkCause, DreamerRunnerStore, EnqueueDreamerAttempt,
    EnqueueDreamerAttemptOutcome, ParkDreamerAttempt,
};
use oneiron_testkit::{FixtureVault, TestVault, fixture_cache};

const WORKER: &str = "worker:run-lease-parked";
/// The lease timeout every call here passes; the warning window opens at
/// 80 % of it.
const TIMEOUT: u64 = 100;

fn open() -> (TestVault, Vault) {
    let copy = FixtureVault::empty(&fixture_cache!())
        .expect("the empty fixture")
        .copy()
        .expect("a private copy");
    let vault = copy.open().expect("vault opens");
    (copy, vault)
}

fn enqueue(runner: &DreamerRunnerStore<'_>, name: &str, now: u64) -> AttemptId {
    let outcome = runner
        .enqueue(EnqueueDreamerAttempt {
            attempt_type: name.to_owned(),
            input: rmpv::Value::from(format!("input:{name}")),
            parent_attempt: None,
            dedupe_key: None,
            run_id: None,
            now,
        })
        .expect("enqueue");
    let EnqueueDreamerAttemptOutcome::Enqueued(status) = outcome else {
        panic!("a fresh Dreamer attempt is enqueued");
    };
    status.attempt.id
}

fn claim(queue: &AttemptQueue<'_>, now: u64) -> AttemptRecord {
    let outcome = queue
        .claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now,
            },
        )
        .expect("claim");
    let ClaimOutcome::Claimed(record) = outcome else {
        panic!("the ready Dreamer attempt is claimed");
    };
    record
}

fn park_on_signal(runner: &DreamerRunnerStore<'_>, id: AttemptId, now: u64) {
    runner
        .park_attempt(ParkDreamerAttempt {
            attempt_id: id,
            reason: "waits on its signal".to_owned(),
            cause: DreamerParkCause::Signal,
            park_owner: WORKER.to_owned(),
            carried_spend: None,
            now,
        })
        .expect("park");
}

fn read(queue: &AttemptQueue<'_>, id: AttemptId) -> AttemptRecord {
    queue.get(id).expect("get").expect("row")
}

/// Two leased Dreamer attempts claimed at one instant; the first is parked
/// on its signal. Returns (parked, running, the instant of both leases).
fn two_leases(vault: &Vault, now: u64) -> (AttemptId, AttemptId, u64) {
    let runner = DreamerRunnerStore::new(vault);
    let queue = AttemptQueue::new(vault);
    let parked = enqueue(&runner, "parked", now);
    let running = enqueue(&runner, "running", now);
    let first = claim(&queue, now + 1);
    let second = claim(&queue, now + 1);
    assert_eq!(
        [first.id, second.id]
            .into_iter()
            .collect::<std::collections::HashSet<_>>(),
        [parked, running].into_iter().collect(),
        "both attempts are leased"
    );
    park_on_signal(&runner, parked, now + 2);
    let leased_at = read(&queue, parked).updated_at;
    assert_eq!(read(&queue, running).updated_at, leased_at);
    assert_eq!(read(&queue, parked).state, AttemptState::Leased);
    (parked, running, leased_at)
}

#[test]
fn lease_warning_sweep_skips_parked_attempts() {
    let (copy, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let (parked, running, leased_at) = two_leases(&vault, copy.clock().now());

    // Inside the warning window, before expiry.
    let report = queue
        .warn_expiring_leases(WarnExpiringAttemptLeases {
            now: leased_at + 90,
            lease_timeout_secs: TIMEOUT,
        })
        .expect("warning sweep");
    assert_eq!(
        report.warned, 1,
        "only the running lease is asked to land: {report:?}"
    );
    assert_eq!(
        read(&queue, parked).cancel_state.pressure.pending,
        0,
        "the parked attempt records no landing request"
    );
    assert_eq!(read(&queue, running).cancel_state.pressure.pending, 1);
}

#[test]
fn single_lease_warning_leaves_a_parked_attempt() {
    let (copy, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let (parked, _running, leased_at) = two_leases(&vault, copy.clock().now());

    let outcome = queue
        .warn_lease_expiry(WarnAttemptLeaseExpiry {
            id: parked,
            lease_timeout_secs: TIMEOUT,
            now: leased_at + 90,
        })
        .expect("warning door");
    assert!(
        !matches!(outcome, LeaseWarningOutcome::LandingRequested(_)),
        "a parked attempt is not asked to land: {outcome:?}"
    );
    assert_eq!(read(&queue, parked).cancel_state.pressure.pending, 0);
}

#[test]
fn lease_reclaim_keeps_a_parked_lease() {
    let (copy, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let (parked, running, leased_at) = two_leases(&vault, copy.clock().now());

    // Both leases are long expired; no caller names any row held.
    let report = queue
        .cleanup_leases(CleanupAttemptLeases {
            now: leased_at + 10 * TIMEOUT,
            lease_timeout_secs: TIMEOUT,
        })
        .expect("cleanup");
    assert_eq!(
        report.stale_requeued, 1,
        "only the running lease is reclaimed: {report:?}"
    );
    let kept = read(&queue, parked);
    assert_eq!(kept.state, AttemptState::Leased, "the parked lease stays");
    assert_eq!(kept.lease_owner.as_deref(), Some(WORKER));
    assert!(kept.lease_expirations.is_empty());
    assert_eq!(read(&queue, running).state, AttemptState::Queued);
}

#[test]
fn kind_lease_reclaim_keeps_a_parked_lease() {
    let (copy, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let (parked, running, leased_at) = two_leases(&vault, copy.clock().now());

    let report = queue
        .cleanup_kind_leases(
            DREAMER_RUNNER_ATTEMPT_KIND,
            CleanupAttemptLeases {
                now: leased_at + 10 * TIMEOUT,
                lease_timeout_secs: TIMEOUT,
            },
        )
        .expect("kind cleanup")
        .expect("the running lease of this kind expired");
    assert_eq!(
        report.stale_requeued, 1,
        "only the running lease is reclaimed: {report:?}"
    );
    let kept = read(&queue, parked);
    assert_eq!(kept.state, AttemptState::Leased, "the parked lease stays");
    assert_eq!(kept.lease_owner.as_deref(), Some(WORKER));
    assert_eq!(read(&queue, running).state, AttemptState::Queued);
}
