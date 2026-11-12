//! FIX RUN-SETTLE-RECIPE: every terminal door of the attempt queue settles its
//! row through one commit (`AttemptQueue::commit_terminal_in_txn`), which
//! clears the backoff, writes the error text and the settle instant, stores
//! the row, stamps its pack receipt and retires its dedupe entry. The commit
//! changes no behaviour, so this file is a pin, not a failing-first test: it
//! passes on the commit before the shared commit and on its head.
//!
//! Each test runs ONE door on a row that carries a dedupe key and a manifest
//! row (so its pack receipt is stamped) and reads back the stored row, the
//! receipt, and whether the key admits a fresh enqueue. The hard cancel's
//! owner authority comes from `oneiron::test_doors::run_lifecycle`, built
//! only under `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test run_terminal_commit`.
#![cfg(oneiron_test_support)]

use oneiron::Vault;
use oneiron::attempt_queue::{
    ATTEMPT_RUNTIME_ACTOR, AbandonAttempt, AbandonOutcome, AcceptAttemptLanding, AttemptId,
    AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue, AttemptRecord,
    AttemptResultRef, AttemptState, ClaimAttempt, ClaimOutcome, CleanupAttemptLeases,
    CompleteAttempt, CompleteOutcome, EnqueueAttempt, EnqueueOutcome, FailAttempt, FailOutcome,
    FinishAttemptLanding, FinishLandingOutcome, ForceAttemptCancel, ForceCancelOutcome,
    InterveneAttempt, LandingOutcome, LandingTrigger, ManifestEntry, ManifestKind, RetryAttempt,
    RetryOutcome,
};
use oneiron::receipt::{attempt_pack_receipt, attempt_pack_receipt_id};
use oneiron::test_doors::run_lifecycle::force_cancel_authority;
use oneiron_testkit::{FixtureVault, TestVault, fixture_cache};

const KIND: &str = "test.run_terminal_commit";
const KEY: &str = "terminal-commit-key";
const WORKER: &str = "worker:terminal-commit";
const OWNER: &str = "person:terminal-commit-owner";
/// The lease timeout of the lease-expiry test.
const TIMEOUT: u64 = 100;

fn open() -> (TestVault, Vault) {
    let copy = FixtureVault::empty(&fixture_cache!())
        .expect("the empty fixture")
        .copy()
        .expect("a private copy");
    let vault = copy.open().expect("vault opens");
    (copy, vault)
}

fn enqueue_keyed(queue: &AttemptQueue<'_>, now: u64) -> EnqueueOutcome {
    queue
        .enqueue(EnqueueAttempt {
            kind: KIND.to_owned(),
            payload: b"terminal".to_vec(),
            dedupe_key: Some(KEY.to_owned()),
            run_id: None,
            now,
        })
        .expect("enqueue")
}

/// A fresh keyed row with one manifest row, so its terminal door stamps a
/// pack receipt.
fn enqueue(queue: &AttemptQueue<'_>, now: u64) -> AttemptRecord {
    let EnqueueOutcome::Enqueued(record) = enqueue_keyed(queue, now) else {
        panic!("a fresh row is enqueued");
    };
    queue
        .append_manifest_entry(
            record.id,
            ManifestEntry::new(ManifestKind::SkillIndex, "index-terminal-commit", "1", now),
        )
        .expect("manifest row");
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

fn accept_landing(queue: &AttemptQueue<'_>, leased: &AttemptRecord, now: u64) -> AttemptRecord {
    let outcome = queue
        .accept_landing(AcceptAttemptLanding {
            id: leased.id,
            lease_owner: WORKER.to_owned(),
            attempt_count: leased.attempt_count,
            trigger: LandingTrigger::CancelRequest,
            status: None,
            resume_point: None,
            request_sequence: None,
            now,
        })
        .expect("accept landing");
    let LandingOutcome::Landing(record) = outcome else {
        panic!("the leased row enters landing: {outcome:?}");
    };
    record
}

/// What one terminal door left behind.
struct Settled<'a> {
    state: AttemptState,
    last_error: Option<&'a str>,
    /// Whom the pack receipt names.
    receipt_actor: &'a str,
    /// The settle instant, for the doors that take the caller's; complete,
    /// fail and retry take the store's recorded clock instead.
    at: Option<u64>,
}

fn assert_settled(vault: &Vault, id: AttemptId, expected: &Settled<'_>) {
    let row = AttemptQueue::new(vault)
        .get(id)
        .expect("get")
        .expect("the settled row");
    assert_eq!(row.state, expected.state, "state");
    assert_eq!(row.backoff_until, None, "backoff cleared");
    assert_eq!(row.last_error.as_deref(), expected.last_error, "error text");
    if let Some(at) = expected.at {
        assert_eq!(row.updated_at, at, "settle instant");
    }
    let receipt = attempt_pack_receipt(vault, &attempt_pack_receipt_id(&id))
        .expect("receipt read")
        .expect("the terminal door stamps the pack receipt");
    assert_eq!(
        receipt.actor.as_deref(),
        Some(expected.receipt_actor),
        "receipt actor"
    );
    assert_eq!(receipt.occurred_at, row.updated_at, "receipt time");
    assert_eq!(receipt.outcome, expected.state.as_str(), "receipt outcome");
}

/// The settled row no longer holds the key: a fresh enqueue under it mints a
/// new row.
fn assert_key_free(queue: &AttemptQueue<'_>, now: u64) {
    assert!(
        matches!(enqueue_keyed(queue, now), EnqueueOutcome::Enqueued(_)),
        "the settled row retired its dedupe entry"
    );
}

#[test]
fn complete_commits_the_settled_row() {
    let (copy, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let queued = enqueue(&queue, t);
    let leased = claim(&queue, t + 1);
    let outcome = queue
        .complete(CompleteAttempt {
            id: queued.id,
            lease_owner: WORKER.to_owned(),
            attempt_count: leased.attempt_count,
            now: t + 5,
        })
        .expect("complete");
    assert!(
        matches!(outcome, CompleteOutcome::Completed(_)),
        "{outcome:?}"
    );
    assert_settled(
        &vault,
        queued.id,
        &Settled {
            state: AttemptState::Completed,
            last_error: None,
            receipt_actor: WORKER,
            at: None,
        },
    );
    assert_key_free(&queue, t + 6);
}

#[test]
fn fail_commits_the_settled_row() {
    let (copy, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let queued = enqueue(&queue, t);
    let leased = claim(&queue, t + 1);
    let outcome = queue
        .fail(FailAttempt {
            id: queued.id,
            lease_owner: WORKER.to_owned(),
            attempt_count: leased.attempt_count,
            reason: "the step broke".to_owned(),
            now: t + 5,
        })
        .expect("fail");
    assert!(matches!(outcome, FailOutcome::Failed(_)), "{outcome:?}");
    assert_settled(
        &vault,
        queued.id,
        &Settled {
            state: AttemptState::Failed,
            last_error: Some("the step broke"),
            receipt_actor: WORKER,
            at: None,
        },
    );
    assert_key_free(&queue, t + 6);
}

#[test]
fn retry_commits_the_source_and_moves_its_key() {
    let (copy, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let queued = enqueue(&queue, t);
    let leased = claim(&queue, t + 1);
    let outcome = queue
        .retry(RetryAttempt {
            id: queued.id,
            lease_owner: WORKER.to_owned(),
            attempt_count: leased.attempt_count,
            backoff_until: t + 50,
            last_error: Some("transient".to_owned()),
            now: t + 5,
        })
        .expect("retry");
    let RetryOutcome::Retried(next) = outcome else {
        panic!("the leased row is retried: {outcome:?}");
    };
    assert_settled(
        &vault,
        queued.id,
        &Settled {
            state: AttemptState::Failed,
            last_error: Some("transient"),
            receipt_actor: WORKER,
            at: None,
        },
    );
    // The successor holds the key now.
    let EnqueueOutcome::Existing(holder) = enqueue_keyed(&queue, t + 6) else {
        panic!("the successor holds the dedupe entry");
    };
    assert_eq!(holder.id, next.id);
}

#[test]
fn intervention_cancel_commits_the_settled_row() {
    let (copy, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let queued = enqueue(&queue, t);
    let outcome = queue
        .intervene(InterveneAttempt {
            id: queued.id,
            kind: AttemptInterventionKind::Cancel,
            actor: OWNER.to_owned(),
            note: None,
            now: t + 5,
        })
        .expect("cancel");
    assert_eq!(outcome.effect, AttemptInterventionEffect::Cancelled);
    assert_settled(
        &vault,
        queued.id,
        &Settled {
            state: AttemptState::Cancelled,
            last_error: None,
            receipt_actor: OWNER,
            at: Some(t + 5),
        },
    );
    assert_key_free(&queue, t + 6);
}

#[test]
fn landing_finish_commits_the_settled_row() {
    let (copy, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let queued = enqueue(&queue, t);
    let leased = claim(&queue, t + 1);
    let landing = accept_landing(&queue, &leased, t + 2);
    let outcome = queue
        .finish_landing(FinishAttemptLanding {
            id: queued.id,
            lease_owner: WORKER.to_owned(),
            attempt_count: landing.attempt_count,
            hand_off: false,
            scheduled_at: None,
            now: t + 5,
        })
        .expect("finish landing");
    assert!(
        matches!(outcome, FinishLandingOutcome::Landed(_)),
        "{outcome:?}"
    );
    // The receipt names the actor of the cancellation the row stores: the
    // worker that landed it.
    assert_settled(
        &vault,
        queued.id,
        &Settled {
            state: AttemptState::Cancelled,
            last_error: None,
            receipt_actor: WORKER,
            at: Some(t + 5),
        },
    );
    assert_key_free(&queue, t + 6);
}

#[test]
fn force_cancel_commits_the_settled_row() {
    let (copy, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let queued = enqueue(&queue, t);
    let _leased = claim(&queue, t + 1);
    let outcome = queue
        .force_cancel(ForceAttemptCancel {
            id: queued.id,
            authority: force_cancel_authority(OWNER).expect("owner authority"),
            reason: Some("the owner stops it".to_owned()),
            now: t + 5,
        })
        .expect("force cancel");
    assert!(
        matches!(outcome, ForceCancelOutcome::Cancelled(_)),
        "{outcome:?}"
    );
    // The reason rides the cancellation receipt, not the row's error text.
    assert_settled(
        &vault,
        queued.id,
        &Settled {
            state: AttemptState::Cancelled,
            last_error: None,
            receipt_actor: OWNER,
            at: Some(t + 5),
        },
    );
    assert_key_free(&queue, t + 6);
}

#[test]
fn abandon_commits_the_settled_row() {
    let (copy, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let queued = enqueue(&queue, t);
    let leased = claim(&queue, t + 1);
    let outcome = queue
        .abandon(AbandonAttempt {
            id: queued.id,
            lease_owner: WORKER.to_owned(),
            attempt_count: leased.attempt_count,
            result_ref: AttemptResultRef::new("artifact:terminal-commit").expect("result ref"),
            reason: "nothing left to do".to_owned(),
            now: t + 5,
        })
        .expect("abandon");
    assert!(
        matches!(outcome, AbandonOutcome::Abandoned(_)),
        "{outcome:?}"
    );
    assert_settled(
        &vault,
        queued.id,
        &Settled {
            state: AttemptState::Abandoned,
            last_error: Some("nothing left to do"),
            receipt_actor: WORKER,
            at: Some(t + 5),
        },
    );
    assert_key_free(&queue, t + 6);
}

#[test]
fn expired_landing_reclaim_commits_the_settled_row() {
    let (copy, vault) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let queued = enqueue(&queue, t);
    let leased = claim(&queue, t + 1);
    let _landing = accept_landing(&queue, &leased, t + 2);
    let now = t + 2 + 10 * TIMEOUT;
    let report = queue
        .cleanup_leases(CleanupAttemptLeases {
            now,
            lease_timeout_secs: TIMEOUT,
        })
        .expect("cleanup");
    assert_eq!(report.landing_force_cancelled, 1, "{report:?}");
    // The runtime authors the force cancellation of an expired landing.
    assert_settled(
        &vault,
        queued.id,
        &Settled {
            state: AttemptState::Cancelled,
            last_error: None,
            receipt_actor: ATTEMPT_RUNTIME_ACTOR,
            at: Some(now),
        },
    );
    assert_key_free(&queue, now + 1);
}
