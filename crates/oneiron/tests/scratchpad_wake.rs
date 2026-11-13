//! OF-548 (ARCH-0032 #scratchpad-one-store; agent-mind-design-v1: "There is
//! one per wake and one per fork. The engine seals it at the terminal
//! receipt and records `scratch_ref` on the receipt."): each wake of an
//! agent writes a fresh scratchpad, and the wake's terminal write seals it
//! and names it on the terminal receipt, so the Dreamer's after-seal review
//! reads every wake's pad. A wake is an attempt and ends at its terminal
//! receipt (done, failed or abandoned; a retried try ends, and its next try
//! is a new wake); a pause is not an end. Two live runs of one agent on one
//! label never share a pad ("forks never share writes"). An unbound label (a
//! sitting, a manual label) keeps its one pad and its seal.
//!
//! A pumped run's code run is its attempt, so each test binds the agent's
//! writes to the attempt's id through `oneiron::test_doors::scratchpad_wake`,
//! built only under `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test scratchpad_wake`.
#![cfg(oneiron_test_support)]

use oneiron::attempt_queue::{
    AbandonAttempt, AbandonOutcome, AttemptId, AttemptQueue, AttemptRecord, AttemptResultRef,
    AttemptResumePoint, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome,
    EnqueueAttempt, EnqueueOutcome, FailAttempt, FailOutcome, HoldAttemptForBudget, ManifestEntry,
    ManifestKind, RetryAttempt, RetryOutcome,
};
use oneiron::memory::MEMORY_CODE_INVALID_STATE;
use oneiron::receipt::{attempt_pack_receipt, attempt_pack_receipt_id};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::temporal::TimeRange;
use oneiron::test_doors::scratchpad_wake::run_bound_memory;
use oneiron::{EdgeActorClass, EntityId, Vault};
use oneiron_testkit::{FixtureVault, TestVault, fixture_cache};

const KIND: &str = "test.scratchpad_wake";
const WORKER: &str = "worker:scratchpad-wake";
/// The one session label every wake in a test writes on.
const LABEL: &str = "wake-label";
/// The receipt field that names the pads a wake's terminal write sealed,
/// spelled here so this file also builds on a tree without the stamp.
const SCRATCH_REF: &str = "scratch_ref";

/// A private vault copy and an agent PERSON that writes pads in it.
fn open() -> (TestVault, Vault, EntityId) {
    let copy = FixtureVault::empty(&fixture_cache!())
        .expect("the empty fixture")
        .copy()
        .expect("a private copy");
    let vault = copy.open().expect("vault opens");
    let agent = EntityId::now();
    vault
        .put_entity(
            &agent,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"agent",
        )
        .expect("agent PERSON");
    (copy, vault, agent)
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
        panic!("a ready row is claimed");
    };
    record
}

/// The durable code run a pumped attempt runs as: its own id.
fn run_of(record: &AttemptRecord) -> EntityId {
    EntityId::from_bytes(*record.id.as_bytes()).expect("an attempt id is an entity id")
}

/// One wake: a fresh row with one manifest row, so its terminal write
/// stamps a pack receipt, claimed by the worker. Answers the leased row and
/// the code run it runs as.
fn wake(queue: &AttemptQueue<'_>, now: u64) -> (AttemptRecord, EntityId) {
    let outcome = queue
        .enqueue(EnqueueAttempt {
            kind: KIND.to_owned(),
            payload: b"wake".to_vec(),
            dedupe_key: None,
            run_id: None,
            now,
        })
        .expect("enqueue");
    let EnqueueOutcome::Enqueued(record) = outcome else {
        panic!("a fresh row is enqueued: {outcome:?}");
    };
    queue
        .append_manifest_entry(
            record.id,
            ManifestEntry::new(ManifestKind::SkillIndex, "index-scratchpad-wake", "1", now),
        )
        .expect("manifest row");
    let leased = claim(queue, now + 1);
    assert_eq!(leased.id, record.id, "the claim leases this wake's row");
    let run = run_of(&leased);
    (leased, run)
}

/// Appends `text` on [`LABEL`] as `agent`'s writes bound to `run`. Answers
/// the pad the line landed in and whether the line opened it.
fn write_line(vault: &Vault, agent: EntityId, run: EntityId, text: &str) -> (EntityId, bool) {
    let receipt = run_bound_memory(vault, agent, run)
        .expect("run-bound memory")
        .scratchpad_append(LABEL, text, None, false)
        .expect("the line lands");
    (receipt.pad, receipt.opened)
}

fn sealed(vault: &Vault, pad: EntityId) -> bool {
    vault.scratchpad_sealed(pad).expect("seal read")
}

/// The `scratch_ref` field of attempt `id`'s terminal pack receipt.
fn scratch_ref(vault: &Vault, id: AttemptId) -> Option<String> {
    attempt_pack_receipt(vault, &attempt_pack_receipt_id(&id))
        .expect("receipt read")
        .expect("the terminal write stamps the pack receipt")
        .fields
        .get(SCRATCH_REF)
        .cloned()
}

fn complete(queue: &AttemptQueue<'_>, leased: &AttemptRecord, now: u64) {
    let outcome = queue
        .complete(CompleteAttempt {
            id: leased.id,
            lease_owner: WORKER.to_owned(),
            attempt_count: leased.attempt_count,
            now,
        })
        .expect("complete");
    assert!(
        matches!(outcome, CompleteOutcome::Completed(_)),
        "{outcome:?}"
    );
}

#[test]
fn a_completed_wake_seals_its_pad_and_names_it_on_the_receipt() {
    let (copy, vault, agent) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let (leased, run) = wake(&queue, t);
    let (pad, opened) = write_line(&vault, agent, run, "the wake's first line");
    assert!(opened, "the wake's first line opens its pad");
    assert!(!sealed(&vault, pad), "a running wake's pad is live");
    complete(&queue, &leased, t + 5);
    assert!(
        sealed(&vault, pad),
        "the completed wake's terminal write seals its pad"
    );
    assert_eq!(
        scratch_ref(&vault, leased.id),
        Some(pad.to_hex()),
        "the terminal receipt names the sealed pad"
    );
}

#[test]
fn a_failed_wake_seals_its_pad() {
    let (copy, vault, agent) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let (leased, run) = wake(&queue, t);
    let (pad, _) = write_line(&vault, agent, run, "the line before the failure");
    let outcome = queue
        .fail(FailAttempt {
            id: leased.id,
            lease_owner: WORKER.to_owned(),
            attempt_count: leased.attempt_count,
            reason: "the step broke".to_owned(),
            now: t + 5,
        })
        .expect("fail");
    assert!(matches!(outcome, FailOutcome::Failed(_)), "{outcome:?}");
    assert!(
        sealed(&vault, pad),
        "the failed wake's terminal write seals its pad"
    );
    assert_eq!(scratch_ref(&vault, leased.id), Some(pad.to_hex()));
}

#[test]
fn an_abandoned_wake_seals_its_pad() {
    let (copy, vault, agent) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let (leased, run) = wake(&queue, t);
    let (pad, _) = write_line(&vault, agent, run, "the line before the abandon");
    let outcome = queue
        .abandon(AbandonAttempt {
            id: leased.id,
            lease_owner: WORKER.to_owned(),
            attempt_count: leased.attempt_count,
            result_ref: AttemptResultRef::new("artifact:scratchpad-wake").expect("result ref"),
            reason: "nothing left to do".to_owned(),
            now: t + 5,
        })
        .expect("abandon");
    assert!(
        matches!(outcome, AbandonOutcome::Abandoned(_)),
        "{outcome:?}"
    );
    assert!(
        sealed(&vault, pad),
        "the abandoned wake's terminal write seals its pad"
    );
    assert_eq!(scratch_ref(&vault, leased.id), Some(pad.to_hex()));
}

#[test]
fn a_retried_try_seals_its_pad_and_the_next_try_opens_a_fresh_one() {
    let (copy, vault, agent) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let (leased, run) = wake(&queue, t);
    let (first, _) = write_line(&vault, agent, run, "the first try's line");
    let outcome = queue
        .retry(RetryAttempt {
            id: leased.id,
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
    assert_ne!(next.id, leased.id, "a retry is a fresh attempt");
    assert!(
        sealed(&vault, first),
        "the retried try's terminal write seals its pad"
    );
    assert_eq!(scratch_ref(&vault, leased.id), Some(first.to_hex()));
    let next_leased = claim(&queue, t + 60);
    assert_eq!(next_leased.id, next.id, "the claim leases the next try");
    let (second, opened) = write_line(&vault, agent, run_of(&next_leased), "the next try's line");
    assert!(opened, "the next try's first line opens a pad");
    assert_ne!(second, first, "the next try writes a fresh pad");
    assert!(!sealed(&vault, second), "the next try's pad is live");
}

#[test]
fn a_later_wake_on_a_sealed_label_opens_a_fresh_pad() {
    let (copy, vault, agent) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let (first_wake, first_run) = wake(&queue, t);
    let (first, _) = write_line(&vault, agent, first_run, "the first wake's line");
    complete(&queue, &first_wake, t + 5);
    let (_second_wake, second_run) = wake(&queue, t + 10);
    let (second, opened) = write_line(&vault, agent, second_run, "the second wake's line");
    assert!(opened, "the later wake's first line opens a pad");
    assert_ne!(
        second, first,
        "the later wake writes a fresh pad, not the first wake's"
    );
    assert!(sealed(&vault, first), "the first wake's pad stays sealed");
    assert!(!sealed(&vault, second), "the later wake's pad is live");
}

#[test]
fn a_second_live_run_on_a_label_writes_its_own_pad() {
    let (copy, vault, agent) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let (first_wake, first_run) = wake(&queue, t);
    let (second_wake, second_run) = wake(&queue, t + 2);
    let (first, _) = write_line(&vault, agent, first_run, "the first run's line");
    let (second, opened) = write_line(&vault, agent, second_run, "the second run's line");
    assert!(opened, "the second run's first line opens its own pad");
    assert_ne!(
        second, first,
        "two live runs on one label never share a pad"
    );
    complete(&queue, &first_wake, t + 5);
    assert!(
        sealed(&vault, first),
        "the first run's end seals its own pad"
    );
    assert!(
        !sealed(&vault, second),
        "the first run's end leaves the second run's pad live"
    );
    assert_eq!(
        scratch_ref(&vault, first_wake.id),
        Some(first.to_hex()),
        "the first run's receipt names only its own pad"
    );
    complete(&queue, &second_wake, t + 6);
    assert!(sealed(&vault, second), "the second run's end seals its pad");
}

#[test]
fn a_run_end_leaves_the_unbound_pad_of_its_label_live() {
    let (copy, vault, agent) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let unbound = vault
        .memory(agent, EdgeActorClass::Agent)
        .scratchpad_append(LABEL, "an unbound line", None, false)
        .expect("the unbound line opens its pad")
        .pad;
    let (leased, run) = wake(&queue, t);
    let (pad, opened) = write_line(&vault, agent, run, "the run's line");
    assert!(opened, "the run's first line opens the run's own pad");
    assert_ne!(pad, unbound, "a run never writes the label's unbound pad");
    complete(&queue, &leased, t + 5);
    assert!(sealed(&vault, pad), "the run's end seals the run's pad");
    assert!(
        !sealed(&vault, unbound),
        "the run's end leaves the label's unbound pad live"
    );
}

#[test]
fn a_paused_wake_keeps_its_live_pad() {
    let (copy, vault, agent) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let (leased, run) = wake(&queue, t);
    let (pad, _) = write_line(&vault, agent, run, "the line before the pause");
    queue
        .hold_for_budget(HoldAttemptForBudget {
            id: leased.id,
            lease_owner: WORKER.to_owned(),
            attempt_count: leased.attempt_count,
            resume_point: AttemptResumePoint::new("step-1", t + 4),
            now: t + 4,
        })
        .expect("the budget hold is admitted");
    assert!(
        !sealed(&vault, pad),
        "a pause is not a wake's end: its pad stays live"
    );
    let (again, opened) = write_line(&vault, agent, run, "the line after the pause");
    assert!(!opened, "the paused wake's next line opens no pad");
    assert_eq!(again, pad, "the paused wake's next line lands in its pad");
}

#[test]
fn a_wake_that_sealed_its_own_pad_gets_no_second_pad() {
    let (copy, vault, agent) = open();
    let queue = AttemptQueue::new(&vault);
    let t = copy.clock().now();
    let (_leased, run) = wake(&queue, t);
    let memory = run_bound_memory(&vault, agent, run).expect("run-bound memory");
    let pad = memory
        .scratchpad_append(LABEL, "the only line", None, false)
        .expect("the first line opens the pad")
        .pad;
    assert_eq!(
        memory
            .scratchpad_seal(LABEL)
            .expect("the wake seals its pad"),
        Some(pad)
    );
    let refused = memory
        .scratchpad_append(LABEL, "a line after the seal", None, false)
        .expect_err("a wake's own sealed pad takes no line and opens no other");
    assert_eq!(refused.code, MEMORY_CODE_INVALID_STATE, "{refused:?}");
}

#[test]
fn an_unbound_label_stays_closed_after_its_seal() {
    let (_copy, vault, agent) = open();
    let memory = vault.memory(agent, EdgeActorClass::Agent);
    let pad = memory
        .scratchpad_append(LABEL, "an unbound line", None, false)
        .expect("the first line opens the pad")
        .pad;
    assert_eq!(
        memory
            .scratchpad_seal(LABEL)
            .expect("the label seals its pad"),
        Some(pad)
    );
    let refused = memory
        .scratchpad_append(LABEL, "a line after the seal", None, false)
        .expect_err("an unbound label's sealed pad takes no line");
    assert_eq!(refused.code, MEMORY_CODE_INVALID_STATE, "{refused:?}");
}
