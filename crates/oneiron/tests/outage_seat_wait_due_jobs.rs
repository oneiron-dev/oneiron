//! DESIGN 15-setting-primitive, stage 5b-4: three more due indexes become rows of the schedule's
//! jobs, and the schedule's runner releases them on the host's housekeeping pass.
//! - `DREAMER_OUTAGE_DUE` goes: an agent run's outage park with a retry hint arms one row of
//!   `dreamer_runner.outage_resume` at its parked time plus the hint; the pass at that time
//!   resumes the park, and the resume disarms the row. A park with no hint arms nothing.
//! - `MODEL_SEAT_RESET_DUE` goes: a seat refusal with a reported reset arms one row of
//!   `dreamer_runner.seat_reset` about the seat; the pass at the reset writes the seat available
//!   and resumes its park, and the write disarms the row.
//! - The agent child-wait's `d` rows go: a wait with an `until` arms one row of
//!   `agent_dispatch.child_wait_until` at its `until` rounded up to a second; the pass then
//!   answers the wait `cutoff`, and settling disarms the row; an early quorum disarms it too.
//! - FIX SETTING-5B-WALL-CLOCK-WAIT-INDEXES: a wait reduces on the recording clock, which the
//!   runner reads, and not the wall clock. The vault's clock here is decades past the wall
//!   clock, so an `until` it has passed is still ahead on the wall clock.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features --test outage_seat_wait_due_jobs`.
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    AgentWaitSetResult, DEFAULT_BASE_LOGICAL_ID, DispatchAgent, agent_dispatch_actor,
};
use oneiron::attempt_queue::{AttemptRecord, AttemptState, ClaimAttempt, ClaimOutcome};
use oneiron::code_run::{HostSelfDispatcher, TaskWaitAgentsRequest, WaitDeliveries};
use oneiron::dreamer_runner::{
    AGENT_RUNS_PARK_OWNER, DREAMER_RUNNER_ATTEMPT_KIND, DreamerRunnerStore, ModelSeatAvailability,
    ModelSeatId, ParkDreamerAttempt, outage_park_reason,
};
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::test_doors::schedule::due_at;
use oneiron::test_doors::seat_park_model_step::park_try_on_seat;
use oneiron::{AttemptId, AttemptQueue, DreamerParkCause, EntityId, Vault, VaultConfig};
use oneiron_store::ports::manual_clock::ManualClock;

/// The instant every test opens at, in vault-clock seconds: far past the wall clock, so the
/// recording clock and the wall clock disagree on every deadline here.
const T0: u64 = 4_000_000_000;
/// The job an outage park's retry hint arms.
const OUTAGE_JOB: &str = "dreamer_runner.outage_resume";
/// The job a seat's reported reset arms.
const SEAT_JOB: &str = "dreamer_runner.seat_reset";
/// The job an agent wait's `until` arms.
const WAIT_JOB: &str = "agent_dispatch.child_wait_until";
/// The lease owner this test claims rows as.
const WORKER: &str = "outage-seat-wait-due-jobs";
/// The run every attempt of one test's tree belongs to.
const RUN: &str = "run-outage-seat-wait-due-jobs";

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
}

fn subject(attempt: AttemptId) -> EntityId {
    EntityId::from_bytes(*attempt.as_bytes()).expect("an attempt id is an entity id")
}

fn hex(id: AttemptId) -> String {
    id.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A root run of the seeded default agent under `run`, with one level of delegation left: its
/// attempt and the actor it runs as.
fn root_run(vault: &Vault, run: &str) -> (AttemptId, oneiron::WriteActor) {
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
    (
        status.attempt.id,
        agent_dispatch_actor(&status.input).expect("the run's actor"),
    )
}

/// A child of `parent`, spawned as the run's dispatcher spawns one, keyed by `key`.
fn spawn_child(vault: &Vault, parent: AttemptId, run: &str, key: &str) -> AttemptId {
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_default_base(Some(parent), Some(key.to_owned()), Some(run.to_owned()), T0)
        .expect("spawn")
    else {
        panic!("expected one fresh child");
    };
    status.attempt.id
}

/// Leases `id` to this test's worker and answers its row.
fn claim(vault: &Vault, id: AttemptId) -> AttemptRecord {
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
            return queue
                .get(id)
                .expect("read")
                .expect("a claimed row reads back");
        }
    }
    panic!("the attempt is ready to claim");
}

/// Parks the leased agent run `attempt` on a provider outage under the agent-run pump's owner,
/// as the pump's settlement does, with `retry_after` as the provider's hint.
fn park_on_outage(vault: &Vault, attempt: AttemptId, retry_after: Option<u64>) {
    DreamerRunnerStore::new(vault)
        .park_attempt(ParkDreamerAttempt {
            attempt_id: attempt,
            reason: outage_park_reason(retry_after),
            cause: DreamerParkCause::ProviderUnavailable,
            park_owner: AGENT_RUNS_PARK_OWNER.to_owned(),
            carried_spend: None,
            now: T0,
        })
        .expect("outage park");
}

fn state(vault: &Vault, attempt: AttemptId) -> AttemptState {
    AttemptQueue::new(vault)
        .get(attempt)
        .expect("read")
        .expect("the attempt's row")
        .state
}

/// The host door's input for a wait over `agents` with `until` and, when given, a quorum.
fn wait_on(
    agents: &[AttemptId],
    n_of: Option<u32>,
    until: u64,
    key: &str,
) -> TaskWaitAgentsRequest {
    serde_json::from_value(serde_json::json!({
        "agents": agents.iter().copied().map(hex).collect::<Vec<_>>(),
        "n_of": n_of,
        "until": until,
        "step_key": key,
    }))
    .expect("wait input")
}

/// The reply delivered for `wait`; `None` while it is not done.
fn delivered(vault: &Vault, wait: &str) -> Option<AgentWaitSetResult> {
    WaitDeliveries::canonical(vault)
        .settled(EntityId::from_hex(wait).expect("wait id"))
        .expect("deliveries")
        .map(|delivery| serde_json::from_str(&delivery.reply).expect("reply"))
}

/// A leased root run with two children: the run's host door and the two children.
fn run_with_children(fx: &Fixture) -> (HostSelfDispatcher<'_>, AttemptId, AttemptId) {
    let (parent, actor) = root_run(&fx.vault, RUN);
    let leased = claim(&fx.vault, parent);
    let first = spawn_child(&fx.vault, parent, RUN, "first");
    let second = spawn_child(&fx.vault, parent, RUN, "second");
    let host =
        HostSelfDispatcher::for_leased_agent_attempt(&fx.vault, actor, &leased).expect("host");
    (host, first, second)
}

#[test]
fn an_outage_park_with_a_retry_hint_is_a_row_the_pass_at_the_hint_resumes() {
    let fx = Fixture::open();
    let (hinted, _) = root_run(&fx.vault, "run-hinted");
    claim(&fx.vault, hinted);
    let (unhinted, _) = root_run(&fx.vault, "run-unhinted");
    claim(&fx.vault, unhinted);
    park_on_outage(&fx.vault, hinted, Some(30));
    park_on_outage(&fx.vault, unhinted, None);
    assert_eq!(
        fx.armed(OUTAGE_JOB, subject(hinted)),
        Some(T0 + 30),
        "the hinted park arms its row at its parked time plus the hint"
    );
    assert_eq!(
        fx.armed(OUTAGE_JOB, subject(unhinted)),
        None,
        "a park with no hint arms nothing"
    );

    fx.at(T0 + 29);
    fx.pass();
    let store = DreamerRunnerStore::new(&fx.vault);
    assert!(
        store.parked_attempt(hinted).expect("park").is_some(),
        "the pass before the hint leaves the park"
    );
    assert_eq!(fx.armed(OUTAGE_JOB, subject(hinted)), Some(T0 + 30));

    fx.at(T0 + 30);
    fx.pass();
    assert!(
        store.parked_attempt(hinted).expect("park").is_none(),
        "the pass at the hint resumes the park"
    );
    assert_ne!(
        state(&fx.vault, hinted),
        AttemptState::Leased,
        "the resumed try is no longer held by its park"
    );
    assert_eq!(
        fx.armed(OUTAGE_JOB, subject(hinted)),
        None,
        "the resume disarms the row"
    );
    assert!(
        store.parked_attempt(unhinted).expect("park").is_some(),
        "a park with no hint waits for recovery or restart"
    );
}

#[test]
fn a_seat_refusal_with_a_reset_is_a_row_the_pass_at_the_reset_releases() {
    let fx = Fixture::open();
    let seat = ModelSeatId::from_bytes([0x5a; 16]).expect("seat id");
    let reset = T0 + 600;
    let attempt =
        park_try_on_seat(&fx.vault, seat, Some(reset), "seat-reset", T0).expect("seat park");
    assert_eq!(
        fx.armed(SEAT_JOB, seat),
        Some(reset),
        "the refusal arms the seat's row at its reset"
    );
    assert_eq!(
        fx.vault.next_model_seat_reset_due().expect("next reset"),
        Some(reset),
        "the next reset reads the armed row"
    );

    fx.at(reset - 1);
    fx.pass();
    let store = DreamerRunnerStore::new(&fx.vault);
    assert!(
        store.parked_attempt(attempt).expect("park").is_some(),
        "the pass before the reset leaves the park"
    );
    assert_eq!(
        fx.vault
            .model_seat_state(seat)
            .expect("seat")
            .expect("row")
            .availability,
        ModelSeatAvailability::Unavailable
    );

    fx.at(reset);
    fx.pass();
    assert_eq!(
        fx.vault
            .model_seat_state(seat)
            .expect("seat")
            .expect("row")
            .availability,
        ModelSeatAvailability::Available,
        "the pass at the reset writes the seat available"
    );
    assert!(
        store.parked_attempt(attempt).expect("park").is_none(),
        "the seat's available write resumes its park"
    );
    assert_eq!(fx.armed(SEAT_JOB, seat), None, "the write disarms the row");
    assert_eq!(
        fx.vault.next_model_seat_reset_due().expect("next reset"),
        None
    );
}

#[test]
fn a_wait_until_is_a_row_the_pass_at_its_second_answers_cutoff() {
    let fx = Fixture::open();
    let (host, first, second) = run_with_children(&fx);
    let until = (T0 + 10) * 1_000 + 500;
    let open = host
        .wait_agents_from_host(wait_on(&[first, second], None, until, "bounded"))
        .expect("wait");
    assert!(!open.done, "its until is still to come");
    let wait = EntityId::from_hex(&open.wait).expect("wait id");
    assert_eq!(
        fx.armed(WAIT_JOB, wait),
        Some(T0 + 11),
        "the wait arms its row at its until, rounded up to a second"
    );

    fx.at(T0 + 10);
    fx.pass();
    assert_eq!(
        delivered(&fx.vault, &open.wait),
        None,
        "the pass before its row's second answers nothing"
    );

    fx.at(T0 + 11);
    fx.pass();
    let cut = delivered(&fx.vault, &open.wait).expect("the pass at its second delivers the reply");
    assert!(cut.done);
    assert_eq!(cut.reason.as_deref(), Some("cutoff"));
    assert_eq!(cut.pending, vec![hex(first), hex(second)]);
    assert_eq!(fx.armed(WAIT_JOB, wait), None, "settling disarms the row");
}

#[test]
fn a_wait_whose_quorum_is_met_before_its_until_disarms_its_row() {
    let fx = Fixture::open();
    let (host, first, second) = run_with_children(&fx);
    let until = (T0 + 3_600) * 1_000;
    let open = host
        .wait_agents_from_host(wait_on(&[first, second], Some(1), until, "quorum"))
        .expect("wait");
    let wait = EntityId::from_hex(&open.wait).expect("wait id");
    assert_eq!(fx.armed(WAIT_JOB, wait), Some(T0 + 3_600));

    let row = claim(&fx.vault, first);
    AttemptQueue::new(&fx.vault)
        .complete(oneiron::attempt_queue::CompleteAttempt {
            id: first,
            lease_owner: WORKER.to_owned(),
            attempt_count: row.attempt_count,
            now: row.updated_at,
        })
        .expect("complete");
    let done = delivered(&fx.vault, &open.wait).expect("the quorum settles the wait");
    assert_eq!(done.reason.as_deref(), Some("quorum"));
    assert_eq!(
        fx.armed(WAIT_JOB, wait),
        None,
        "the write that settles the wait disarms its row"
    );
}

#[test]
fn a_wait_whose_until_the_recording_clock_has_passed_is_cutoff_when_it_opens() {
    let fx = Fixture::open();
    let (host, first, second) = run_with_children(&fx);
    // Passed on the vault's clock, decades ahead on the wall clock.
    let until = T0 * 1_000 - 1;
    let open = host
        .wait_agents_from_host(wait_on(&[first, second], None, until, "passed"))
        .expect("wait");
    assert!(
        open.done,
        "the reduction reads the recording clock, which has passed its until"
    );
    assert_eq!(open.reason.as_deref(), Some("cutoff"));
    let wait = EntityId::from_hex(&open.wait).expect("wait id");
    assert_eq!(
        fx.armed(WAIT_JOB, wait),
        None,
        "a wait settled in the write that opens it leaves no row"
    );
}

#[test]
fn a_wait_until_comes_due_on_the_recording_clock_the_runner_reads() {
    let fx = Fixture::open();
    let (host, first, second) = run_with_children(&fx);
    let until = (T0 + 60) * 1_000;
    let open = host
        .wait_agents_from_host(wait_on(&[first, second], None, until, "exact"))
        .expect("wait");
    let wait = EntityId::from_hex(&open.wait).expect("wait id");
    assert_eq!(
        fx.armed(WAIT_JOB, wait),
        Some(T0 + 60),
        "an until on a whole second is due at that second"
    );
    fx.at(T0 + 60);
    fx.pass();
    let cut = delivered(&fx.vault, &open.wait).expect("the pass at its until delivers the reply");
    assert_eq!(cut.reason.as_deref(), Some("cutoff"));
}
