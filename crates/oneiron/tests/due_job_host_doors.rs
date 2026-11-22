//! DESIGN 15-setting-primitive, stage 5b-4: two host loops keep serving their own job sooner than
//! the housekeeping tick, now through the schedule's runner (OPUS-SETTING's answer Q1 = B to ASK
//! SETTING-SCHEDULE-5B4-DREAMER-AND-WAIT-DUES):
//! - the model-seat watcher's door, `Vault::release_due_model_seats`, runs the due rows of
//!   `dreamer_runner.seat_reset`;
//! - the resident pump's outage step, `Vault::resume_due_outage_parks`, runs the due rows of
//!   `dreamer_runner.outage_resume`.
//!
//! Each door runs its own job's due rows alone: another job's row due at the same time waits for
//! the pass. While a housekeeping pass holds the runner a door runs nothing, and the rows wait.
//!
//! Red at a scratch whose runner door runs every due row and does not take the runner: each case
//! fails.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test due_job_host_doors`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent,
};
use oneiron::attempt_queue::{ClaimAttempt, ClaimOutcome};
use oneiron::dreamer_runner::{
    AGENT_RUNS_PARK_OWNER, DREAMER_RUNNER_ATTEMPT_KIND, DreamerRunnerStore, ModelSeatAvailability,
    ModelSeatId, ParkDreamerAttempt, outage_park_reason,
};
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::schedule::Trigger;
use oneiron::test_doors::schedule::{arm_as_engine, due_at, runs, while_a_pass_holds_the_runner};
use oneiron::test_doors::seat_park_model_step::park_try_on_seat;
use oneiron::{AttemptId, AttemptQueue, DreamerParkCause, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;

/// The instant every test opens at, in vault-clock seconds.
const T0: u64 = 4_000_000_000;
/// The job an outage park's retry hint arms.
const OUTAGE_JOB: &str = "dreamer_runner.outage_resume";
/// The job a seat's reported reset arms.
const SEAT_JOB: &str = "dreamer_runner.seat_reset";
/// Another job, whose row is due at the same time as the door's own.
const OTHER_JOB: &str = "test.count";
/// The lease owner this test claims rows as.
const WORKER: &str = "due-job-host-doors";

/// A vault on a clock the test moves, opened as an embedded owner opens it.
struct Fixture {
    vault: Vault,
    clock: Arc<ManualClock>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn open() -> Self {
        let clock = ManualClock::new(T0);
        let mut config = VaultConfig::device();
        config.map_size = 32 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        config.store_clock = clock.bundle();
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::open_owned(dir.path(), config).expect("open vault");
        Self {
            vault,
            clock,
            _dir: dir,
        }
    }

    fn at(&self, now: u64) {
        self.clock.set(now);
    }

    /// One housekeeping pass, as the host's tick runs it.
    fn pass(&self) {
        self.vault
            .housekeeping(HousekeepingBudget::unbounded())
            .expect("housekeeping");
    }

    /// When `job`'s row about `subject` is next due, or `None` when it is not armed.
    fn armed(&self, job: &str, subject: EntityId) -> Option<u64> {
        due_at(&self.vault, job, Some(subject)).expect("schedule")
    }

    /// Arms a row of the other job about `subject`, due at `at`.
    fn arm_other(&self, subject: EntityId, at: u64) {
        arm_as_engine(&self.vault, OTHER_JOB, Some(subject), Trigger::At { at })
            .expect("arm the other job");
    }

    fn seat_available(&self, seat: ModelSeatId) -> bool {
        self.vault
            .model_seat_state(seat)
            .expect("seat")
            .expect("the seat's row")
            .availability
            == ModelSeatAvailability::Available
    }
}

fn subject(attempt: AttemptId) -> EntityId {
    EntityId::from_bytes(*attempt.as_bytes()).expect("an attempt id is an entity id")
}

/// A root run of the seeded default agent under `run`.
fn root_run(vault: &Vault, run: &str) -> AttemptId {
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)
        .expect("agent definitions")
        .expect("the default agent is seeded");
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some(run.to_owned()),
                now: T0,
            },
            AgentSpawnContext::default().with_depth_remaining(1),
        )
        .expect("dispatch")
    else {
        panic!("expected one fresh root run");
    };
    status.attempt.id
}

/// Leases `id` to this test's worker.
fn claim(vault: &Vault, id: AttemptId) {
    let queue = AttemptQueue::new(vault);
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue
            .claim_kind(
                DREAMER_RUNNER_ATTEMPT_KIND,
                ClaimAttempt {
                    lease_owner: WORKER.to_owned(),
                    now: u64::MAX,
                },
            )
            .expect("claim")
        else {
            break;
        };
        if row.id == id {
            return;
        }
    }
    panic!("the attempt is ready to claim");
}

/// A leased agent run parked on a provider outage under the agent-run pump's owner, with the
/// provider's hint `retry_after`: its attempt.
fn outage_park(vault: &Vault, run: &str, retry_after: u64) -> AttemptId {
    let attempt = root_run(vault, run);
    claim(vault, attempt);
    DreamerRunnerStore::new(vault)
        .park_attempt(ParkDreamerAttempt {
            attempt_id: attempt,
            reason: outage_park_reason(Some(retry_after)),
            cause: DreamerParkCause::ProviderUnavailable,
            park_owner: AGENT_RUNS_PARK_OWNER.to_owned(),
            carried_spend: None,
            now: T0,
        })
        .expect("outage park");
    attempt
}

#[test]
fn the_seat_door_runs_the_due_seat_rows_alone_ahead_of_the_pass() {
    let fx = Fixture::open();
    let seat = ModelSeatId::from_bytes([0x6a; 16]).expect("seat id");
    let reset = T0 + 600;
    let attempt =
        park_try_on_seat(&fx.vault, seat, Some(reset), "seat-door", T0).expect("seat park");
    let other = EntityId::from_bytes([0x6b; 16]).expect("subject");
    fx.arm_other(other, reset);
    let store = DreamerRunnerStore::new(&fx.vault);

    fx.at(reset - 1);
    assert!(
        fx.vault
            .release_due_model_seats()
            .expect("seat door")
            .is_empty(),
        "before the reset the door releases nothing"
    );
    assert_eq!(fx.armed(SEAT_JOB, seat), Some(reset));

    fx.at(reset);
    assert_eq!(
        fx.vault.release_due_model_seats().expect("seat door"),
        vec![seat],
        "at the reset the door releases the seat"
    );
    assert!(fx.seat_available(seat), "the seat is available");
    assert!(
        store.parked_attempt(attempt).expect("park").is_none(),
        "the seat's available write resumes its park"
    );
    assert_eq!(fx.armed(SEAT_JOB, seat), None, "the write disarms the row");
    assert_eq!(
        fx.armed(OTHER_JOB, other),
        Some(reset),
        "another job's row due at the reset waits for the pass"
    );
    assert_eq!(
        runs(OTHER_JOB, Some(other)),
        0,
        "the door runs no other job"
    );

    fx.pass();
    assert_eq!(
        runs(OTHER_JOB, Some(other)),
        1,
        "the pass runs the other job"
    );
}

#[test]
fn the_outage_door_runs_the_due_outage_rows_alone_ahead_of_the_pass() {
    let fx = Fixture::open();
    let attempt = outage_park(&fx.vault, "run-outage-door", 30);
    let other = EntityId::from_bytes([0x6c; 16]).expect("subject");
    fx.arm_other(other, T0 + 30);
    let store = DreamerRunnerStore::new(&fx.vault);

    fx.at(T0 + 29);
    assert_eq!(
        fx.vault.resume_due_outage_parks().expect("outage door"),
        0,
        "before the hint the door runs nothing"
    );
    assert!(store.parked_attempt(attempt).expect("park").is_some());

    fx.at(T0 + 30);
    assert_eq!(
        fx.vault.resume_due_outage_parks().expect("outage door"),
        1,
        "at the hint the door runs the park's row"
    );
    assert!(
        store.parked_attempt(attempt).expect("park").is_none(),
        "the run resumes the park"
    );
    assert_eq!(
        fx.armed(OUTAGE_JOB, subject(attempt)),
        None,
        "the resume disarms the row"
    );
    assert_eq!(
        fx.armed(OTHER_JOB, other),
        Some(T0 + 30),
        "another job's row due at the hint waits for the pass"
    );
    assert_eq!(
        runs(OTHER_JOB, Some(other)),
        0,
        "the door runs no other job"
    );
}

#[test]
fn the_seat_door_runs_nothing_while_a_housekeeping_pass_holds_the_runner() {
    let fx = Fixture::open();
    let seat = ModelSeatId::from_bytes([0x6d; 16]).expect("seat id");
    let reset = T0 + 60;
    let attempt =
        park_try_on_seat(&fx.vault, seat, Some(reset), "held-seat", T0).expect("seat park");
    let store = DreamerRunnerStore::new(&fx.vault);

    fx.at(reset);
    let released = while_a_pass_holds_the_runner(&fx.vault, || {
        fx.vault.release_due_model_seats().expect("seat door")
    });
    assert!(
        released.is_empty(),
        "the door releases nothing while a pass holds the runner"
    );
    assert!(!fx.seat_available(seat), "the seat stays unavailable");
    assert!(
        store.parked_attempt(attempt).expect("park").is_some(),
        "its park stays"
    );
    assert_eq!(
        fx.armed(SEAT_JOB, seat),
        Some(reset),
        "the due row waits for a run"
    );

    assert_eq!(
        fx.vault.release_due_model_seats().expect("seat door"),
        vec![seat],
        "once the runner is free the door releases the seat"
    );
}

#[test]
fn the_outage_door_runs_nothing_while_a_housekeeping_pass_holds_the_runner() {
    let fx = Fixture::open();
    let attempt = outage_park(&fx.vault, "run-held-outage", 30);
    let store = DreamerRunnerStore::new(&fx.vault);

    fx.at(T0 + 30);
    let ran = while_a_pass_holds_the_runner(&fx.vault, || {
        fx.vault.resume_due_outage_parks().expect("outage door")
    });
    assert_eq!(
        ran, 0,
        "the door runs nothing while a pass holds the runner"
    );
    assert!(
        store.parked_attempt(attempt).expect("park").is_some(),
        "the park stays"
    );
    assert_eq!(
        fx.armed(OUTAGE_JOB, subject(attempt)),
        Some(T0 + 30),
        "the due row waits for a run"
    );

    assert_eq!(
        fx.vault.resume_due_outage_parks().expect("outage door"),
        1,
        "once the runner is free the door runs the row"
    );
    assert!(
        store.parked_attempt(attempt).expect("park").is_none(),
        "the run resumes the park"
    );
}
