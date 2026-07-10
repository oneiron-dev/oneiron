use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::config::VaultConfig;
use crate::dreamer_runner::{DreamerHomeNodeCandidate, DreamerJobStatus};
use crate::job_queue::{CleanupJobLeases, InterveneJob, JobInterventionKind, JobQueue, JobState};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::write_envelope::{WriteActor, WriteProvenance};
use crate::{EdgeActorClass, EntityId, Vault};

use super::*;

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("wake-pass future unexpectedly pending"),
    }
}

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

fn occurred(at: u64) -> TimeRange {
    TimeRange { start: at, end: at }
}

fn milestone_author(vault: &Vault, now: u64) -> Result<WakeMilestoneAuthor> {
    let actor = EntityId::now();
    let subject = EntityId::now();
    vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred(now), now, b"actor")?;
    vault.put_entity(&subject, ENTITY_TYPE_PERSON, occurred(now), now, b"subject")?;
    Ok(WakeMilestoneAuthor {
        subject,
        envelope: WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Human),
            ClaimSource::UserStated,
            WriteProvenance::new(Value::from("dreamer-wake-test"))?,
            ClaimApprovalStatus::Approved,
        ),
    })
}

fn enqueue_micro(store: &DreamerRunnerStore<'_>, tag: &str, now: u64) -> Result<DreamerJobStatus> {
    match store.enqueue_consolidation(EnqueueDreamerConsolidationJob {
        scope: DreamerConsolidationScope::Micro,
        input: Value::from(format!("input:{tag}")),
        parent_job: None,
        dedupe_key: Some(tag.to_owned()),
        run_id: None,
        now,
    })? {
        EnqueueDreamerJobOutcome::Enqueued(status) | EnqueueDreamerJobOutcome::Existing(status) => {
            Ok(status)
        }
    }
}

fn frozen_deadline(elapsed_ms: u64, ceiling_ms: u64) -> WakePassDeadline {
    let elapsed = Arc::new(AtomicU64::new(elapsed_ms));
    WakePassDeadline::with_clock(ceiling_ms, Arc::new(move || elapsed.load(Ordering::SeqCst)))
}

fn run_input(scope: DreamerConsolidationScope, local_node_id: u64, now: u64) -> RunWakePass {
    RunWakePass {
        trigger: WakeTrigger::Compaction,
        scope,
        local_node_id,
        lease_owner: "wake-worker".to_owned(),
        budget_total_units: 10_000,
        reserve_units: 100,
        now,
    }
}

struct CompletingExecutor {
    completed_units: u64,
    executed: u32,
}

impl DreamerJobExecutor for CompletingExecutor {
    async fn execute(
        &mut self,
        _job: &DreamerAdmittedJob,
        _ctx: &mut WakeJobContext<'_>,
    ) -> Result<DreamerJobExecution> {
        self.executed += 1;
        Ok(DreamerJobExecution::Completed {
            completed_units: self.completed_units,
        })
    }
}

struct ParkingExecutor {
    reason: String,
    park_via_store_first: bool,
}

impl DreamerJobExecutor for ParkingExecutor {
    async fn execute(
        &mut self,
        job: &DreamerAdmittedJob,
        ctx: &mut WakeJobContext<'_>,
    ) -> Result<DreamerJobExecution> {
        if self.park_via_store_first {
            // Simulates the step layer's trap flow: the step layer is the
            // one park-owner; the executor still surfaces Park.
            DreamerRunnerStore::new(ctx.vault).park_job(ParkDreamerJob {
                job_id: job.status.job.id,
                reason: self.reason.clone(),
                park_owner: "step-layer".to_owned(),
                now: ctx.now_ms / 1_000,
            })?;
        }
        Ok(DreamerJobExecution::Park {
            reason: self.reason.clone(),
        })
    }
}

#[test]
fn wake_pass_drains_queue_until_empty() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let author = milestone_author(&vault, 5)?;
    let jobs = [
        enqueue_micro(&store, "a", 10)?,
        enqueue_micro(&store, "b", 11)?,
        enqueue_micro(&store, "c", 12)?,
    ];
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000))
        .with_milestone_author(author);
    let mut exec = CompletingExecutor {
        completed_units: 40,
        executed: 0,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut exec,
    ))?;

    assert_eq!(report.admitted, 3);
    assert_eq!(report.completed, 3);
    assert_eq!(report.failed, 0);
    assert_eq!(report.parked, 0);
    assert_eq!(report.stop, WakePassStop::QueueEmpty);
    assert_eq!(exec.executed, 3);

    // Budget settled per job: 3 x 40 actual units spent, reservations gone.
    let budget = store.budget("wake")?.expect("budget row");
    assert_eq!(budget.remaining_units, 10_000 - 3 * 40);
    assert_eq!(budget.reserved_units, 0);

    // Done milestones are durable and readable back per job.
    for job in &jobs {
        let milestone = store
            .latest_durable_milestone(job.job.id)?
            .expect("durable milestone");
        assert_eq!(milestone.kind, DreamerMilestoneKind::Done);
        let status = store.status(job.job.id)?.expect("job status");
        assert_eq!(status.job.state, JobState::Completed);
    }
    Ok(())
}

#[test]
fn wake_pass_stops_on_budget_exhausted() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    enqueue_micro(&store, "a", 10)?;
    enqueue_micro(&store, "b", 11)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let mut exec = CompletingExecutor {
        completed_units: 100,
        executed: 0,
    };
    let mut input = run_input(DreamerConsolidationScope::Micro, node_id, 20);
    input.budget_total_units = 150;
    input.reserve_units = 100;
    let report = block_on_ready(driver.run_wake_pass(input, &mut exec))?;

    // First job admits (reserve 100 of 150) and spends 100; the second
    // reservation (100 > remaining 50) is denied.
    assert_eq!(report.admitted, 1);
    assert_eq!(report.completed, 1);
    assert_eq!(report.stop, WakePassStop::BudgetExhausted);
    assert_eq!(exec.executed, 1);
    let budget = store.budget("wake")?.expect("budget row");
    assert_eq!(budget.remaining_units, 50);
    Ok(())
}

#[test]
fn wake_pass_macro_requires_home_node() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;
    enqueue_micro(&store, "macro-blocked", 10)?;

    // No designation at all: MACRO admission refuses with NoHomeNode.
    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let mut exec = CompletingExecutor {
        completed_units: 10,
        executed: 0,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Macro, node_id, 20),
        &mut exec,
    ))?;
    assert_eq!(report.stop, WakePassStop::NoHomeNode);
    assert_eq!(report.admitted, 0);

    // A foreign home-node designation: this node must refuse MACRO work.
    let foreign = if node_id == u64::MAX { 1 } else { node_id + 1 };
    store.elect_home_node(
        &[DreamerHomeNodeCandidate {
            node_id: foreign,
            cloud: true,
            attached: true,
            always_on_local: false,
            primary_device: false,
        }],
        30,
    )?;
    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Macro, node_id, 40),
        &mut exec,
    ))?;
    assert_eq!(report.stop, WakePassStop::NotHomeNode);
    assert_eq!(report.admitted, 0);
    assert_eq!(exec.executed, 0, "zero admissions means zero executions");
    Ok(())
}

#[test]
fn wake_pass_deadline_stops_admission() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "past-deadline", 10)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    // Injected clock already past the ceiling: no admissions at all.
    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(180_001, 180_000));
    let mut exec = CompletingExecutor {
        completed_units: 10,
        executed: 0,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut exec,
    ))?;
    assert_eq!(report.stop, WakePassStop::DeadlineHardCut);
    assert_eq!(report.admitted, 0);
    assert_eq!(exec.executed, 0);
    let status = store.status(queued.job.id)?.expect("job status");
    assert_eq!(status.job.state, JobState::Queued, "job never claimed");
    Ok(())
}

#[test]
fn wake_pass_deadline_reads() {
    let elapsed = Arc::new(AtomicU64::new(0));
    let clock = Arc::clone(&elapsed);
    let deadline =
        WakePassDeadline::with_clock(180_000, Arc::new(move || clock.load(Ordering::SeqCst)));
    assert_eq!(deadline.remaining_ms(), 180_000);
    assert_eq!(deadline.elapsed_percent(), 0);
    assert!(!deadline.expired());

    elapsed.store(144_000, Ordering::SeqCst);
    assert_eq!(deadline.remaining_ms(), 36_000);
    assert_eq!(deadline.elapsed_percent(), 80);
    assert!(!deadline.expired());

    elapsed.store(180_000, Ordering::SeqCst);
    assert_eq!(deadline.remaining_ms(), 0);
    assert_eq!(deadline.elapsed_percent(), 100);
    assert!(deadline.expired());
}

#[test]
fn park_and_resume_roundtrip() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "parkable", 10)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let mut parker = ParkingExecutor {
        reason: "await consent".to_owned(),
        park_via_store_first: false,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut parker,
    ))?;
    assert_eq!(report.admitted, 1);
    assert_eq!(report.parked, 1);
    assert_eq!(report.completed, 0);
    let parked = store.parked_job(queued.job.id)?.expect("parked row");
    assert_eq!(parked.reason, "await consent");
    // The reservation was refunded, not spent.
    let budget = store.budget("wake")?.expect("budget row");
    assert_eq!(budget.remaining_units, 10_000);
    assert_eq!(budget.reserved_units, 0);

    // Resume clears the parked row and is idempotent on re-call. The driver
    // parked under its lease owner, so resume must present the same token.
    let resumed = store
        .resume_parked(queued.job.id, "wake-worker", 30)?
        .expect("resumed status");
    assert_eq!(resumed.job.id, queued.job.id);
    assert!(store.parked_job(queued.job.id)?.is_none());
    assert!(
        store
            .resume_parked(queued.job.id, "wake-worker", 31)?
            .is_none()
    );

    // Expire the stale lease so normal admission can re-claim the job.
    let queue = JobQueue::new(&vault);
    queue.cleanup_leases(CleanupJobLeases {
        now: 120,
        lease_timeout_secs: 10,
    })?;

    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let mut completer = CompletingExecutor {
        completed_units: 25,
        executed: 0,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 130),
        &mut completer,
    ))?;
    assert_eq!(report.admitted, 1);
    assert_eq!(report.completed, 1);
    assert_eq!(report.stop, WakePassStop::QueueEmpty);
    let status = store.status(queued.job.id)?.expect("job status");
    assert_eq!(status.job.state, JobState::Completed);
    Ok(())
}

#[test]
fn park_owner_step_layer_respected() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "pre-parked", 10)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let mut parker = ParkingExecutor {
        reason: "durable step budget exhausted".to_owned(),
        park_via_store_first: true,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut parker,
    ))?;
    assert_eq!(report.parked, 1);
    // The step layer's park row survives untouched (one park-owner): the
    // driver never re-parks, so the original parked_at stamp is preserved.
    let parked = store.parked_job(queued.job.id)?.expect("parked row");
    assert_eq!(parked.reason, "durable step budget exhausted");
    assert_eq!(parked.parked_at, 20);
    Ok(())
}

#[test]
fn paused_job_not_admitted() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "paused", 10)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    let queue = JobQueue::new(&vault);
    queue.intervene(InterveneJob {
        id: queued.job.id,
        kind: JobInterventionKind::Pause,
        actor: "operator".to_owned(),
        note: Some("hold".to_owned()),
        now: 15,
    })?;

    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let mut exec = CompletingExecutor {
        completed_units: 10,
        executed: 0,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut exec,
    ))?;
    assert_eq!(report.admitted, 0, "paused job is skipped by admission");
    assert_eq!(report.stop, WakePassStop::QueueEmpty);
    assert_eq!(exec.executed, 0);
    Ok(())
}

#[test]
fn wake_trigger_default_scopes() {
    assert_eq!(
        WakeTrigger::Compaction.default_scope(),
        DreamerConsolidationScope::Micro
    );
    assert_eq!(
        WakeTrigger::SessionEnd.default_scope(),
        DreamerConsolidationScope::Meso
    );
    assert_eq!(
        WakeTrigger::Timer.default_scope(),
        DreamerConsolidationScope::Macro
    );
    assert_eq!(
        WakeTrigger::Event.default_scope(),
        DreamerConsolidationScope::Micro
    );
}

#[test]
fn request_wake_enqueues_with_advisory_dedupe() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let payload = DreamerJobPayload {
        job_type: String::new(), // enqueue derives job_type from the scope
        input: Value::from("compaction summary"),
        parent_job: None,
    };

    let first = request_wake(
        &store,
        WakeTrigger::Compaction,
        WakeTrigger::Compaction.default_scope(),
        payload.clone(),
        Some("wake:compaction:1".to_owned()),
        None,
        10,
    )?;
    assert!(matches!(first, EnqueueDreamerJobOutcome::Enqueued(_)));

    // Advisory dedupe: re-requesting the same wake coalesces.
    let second = request_wake(
        &store,
        WakeTrigger::Compaction,
        WakeTrigger::Compaction.default_scope(),
        payload,
        Some("wake:compaction:1".to_owned()),
        None,
        11,
    )?;
    assert!(matches!(second, EnqueueDreamerJobOutcome::Existing(_)));
    Ok(())
}

fn injected_clock(start_ms: u64) -> (Arc<AtomicU64>, WakePassDeadline) {
    let elapsed = Arc::new(AtomicU64::new(start_ms));
    let clock = Arc::clone(&elapsed);
    let deadline = WakePassDeadline::with_clock(
        DREAMER_WAKE_PASS_WALL_CLOCK_CEILING_MS,
        Arc::new(move || clock.load(Ordering::SeqCst)),
    );
    (elapsed, deadline)
}

/// Completes jobs while advancing the injected pass clock, simulating work
/// that consumes wall time.
struct ClockAdvancingExecutor {
    clock: Arc<AtomicU64>,
    advance_by_ms: u64,
    completed_units: u64,
    executed: u32,
}

impl DreamerJobExecutor for ClockAdvancingExecutor {
    async fn execute(
        &mut self,
        _job: &DreamerAdmittedJob,
        _ctx: &mut WakeJobContext<'_>,
    ) -> Result<DreamerJobExecution> {
        self.executed += 1;
        self.clock.fetch_add(self.advance_by_ms, Ordering::SeqCst);
        Ok(DreamerJobExecution::Completed {
            completed_units: self.completed_units,
        })
    }
}

#[test]
fn wake_pass_never_exceeds_ceiling() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    enqueue_micro(&store, "one", 10)?;
    let second = enqueue_micro(&store, "two", 11)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    // The first job eats the whole ceiling; the pass must hard-stop without
    // admitting the second.
    let (clock, deadline) = injected_clock(0);
    let mut driver = DreamerWakeDriver::new(&vault, "wake", deadline);
    let mut exec = ClockAdvancingExecutor {
        clock: Arc::clone(&clock),
        advance_by_ms: DREAMER_WAKE_PASS_WALL_CLOCK_CEILING_MS + 1,
        completed_units: 10,
        executed: 0,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut exec,
    ))?;

    assert_eq!(report.stop, WakePassStop::DeadlineHardCut);
    assert_eq!(report.admitted, 1, "no admission past the ceiling");
    assert_eq!(report.completed, 1);
    assert_eq!(exec.executed, 1);
    let status = store.status(second.job.id)?.expect("second job status");
    assert_eq!(status.job.state, JobState::Queued, "never claimed");
    Ok(())
}

#[test]
fn wrap_notice_fires_exactly_once_counter_first() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    enqueue_micro(&store, "a", 10)?;
    enqueue_micro(&store, "b", 11)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    // Pre-consume the wake-budget counter to 85%: the counter crosses the
    // notice threshold while the clock is far from it.
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake-pass",
        1_000,
        100,
        crate::BudgetExhaustionPolicy::Suspend,
    );
    let admission = guard.admit_reserve(850).expect("pre-spend admission");
    guard
        .settle_absolute(&admission.lease, 850)
        .expect("pre-spend settle");

    let (_clock, deadline) = injected_clock(0);
    let mut driver = DreamerWakeDriver::new(&vault, "wake", deadline).with_budget_guard(guard);
    let mut exec = CompletingExecutor {
        completed_units: 10,
        executed: 0,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut exec,
    ))?;
    assert_eq!(report.completed, 2, "notice does not stop the pass");

    let plans: Vec<_> = driver
        .steering_signals()
        .iter()
        .filter(|signal| signal.threshold == crate::BudgetThreshold::Plan80)
        .collect();
    assert_eq!(plans.len(), 1, "exactly one PLAN signal per pass");
    assert_eq!(plans[0].template_id, crate::BUDGET_PLAN_PROMPT_TEMPLATE_ID);
    Ok(())
}

#[test]
fn wrap_notice_fires_exactly_once_clock_first() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    enqueue_micro(&store, "a", 10)?;
    enqueue_micro(&store, "b", 11)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    // Clock at 80% of the ceiling (144s), counter fresh: the clock side of
    // the trigger fires. 144s is below the 165s finalize threshold, so the
    // pass still admits and completes work.
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake-pass",
        1_000_000,
        100,
        crate::BudgetExhaustionPolicy::Suspend,
    );
    let (_clock, deadline) = injected_clock(144_000);
    let mut driver = DreamerWakeDriver::new(&vault, "wake", deadline).with_budget_guard(guard);
    let mut exec = CompletingExecutor {
        completed_units: 10,
        executed: 0,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut exec,
    ))?;
    assert_eq!(report.completed, 2);

    let plans: Vec<_> = driver
        .steering_signals()
        .iter()
        .filter(|signal| signal.threshold == crate::BudgetThreshold::Plan80)
        .collect();
    assert_eq!(plans.len(), 1, "exactly one PLAN signal per pass");
    Ok(())
}

#[test]
fn graceful_wrap_then_hard_cut_sequencing() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "wrapped", 10)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;
    let author = milestone_author(&vault, 5)?;

    // Segment 1 — finalize window (165s..180s): the driver enters finalize
    // ONCE, emits ONE LAND signal, and admits nothing.
    let (_clock, deadline) = injected_clock(170_000);
    let mut driver = DreamerWakeDriver::new(&vault, "wake", deadline);
    let mut exec = CompletingExecutor {
        completed_units: 10,
        executed: 0,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut exec,
    ))?;
    assert_eq!(report.admitted, 0, "finalize admits no new jobs");
    assert_eq!(report.stop, WakePassStop::DeadlineHardCut);
    let lands: Vec<_> = driver
        .steering_signals()
        .iter()
        .filter(|signal| signal.threshold == crate::BudgetThreshold::Land95)
        .collect();
    assert_eq!(lands.len(), 1, "exactly one LAND signal");
    assert_eq!(lands[0].template_id, crate::BUDGET_LAND_PROMPT_TEMPLATE_ID);

    // The envelope carries the finalize deadline in the window.
    let (_clock2, deadline2) = injected_clock(170_000);
    let guard = crate::BudgetGuard::with_reserve_units(
        "wake-pass",
        1_000,
        100,
        crate::BudgetExhaustionPolicy::Suspend,
    );
    let envelope = current_legibility(&guard.read(), &deadline2);
    assert!(envelope.wrap_up);
    assert_eq!(envelope.finalize_by_ms, Some(10_000));

    // Segment 2 — hard cut: the step layer parks the running job at the
    // ceiling; the driver honors the park, writes the CheckpointReached
    // milestone, and stops DeadlineHardCut.
    let (clock, deadline) = injected_clock(100_000);
    let mut driver = DreamerWakeDriver::new(&vault, "wake", deadline).with_milestone_author(author);
    struct HardCutExecutor {
        clock: Arc<AtomicU64>,
    }
    impl DreamerJobExecutor for HardCutExecutor {
        async fn execute(
            &mut self,
            job: &DreamerAdmittedJob,
            ctx: &mut WakeJobContext<'_>,
        ) -> Result<DreamerJobExecution> {
            // Simulates the ONE-1305 step-layer deadline race: the step
            // layer parks at the ceiling and surfaces Park.
            self.clock.store(180_001, Ordering::SeqCst);
            DreamerRunnerStore::new(ctx.vault).park_job(ParkDreamerJob {
                job_id: job.status.job.id,
                reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
                park_owner: DREAMER_HARD_CUT_PARK_OWNER.to_owned(),
                now: ctx.now_ms / 1_000,
            })?;
            Ok(DreamerJobExecution::Park {
                reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
            })
        }
    }
    let mut exec = HardCutExecutor {
        clock: Arc::clone(&clock),
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 30),
        &mut exec,
    ))?;
    assert_eq!(report.admitted, 1);
    assert_eq!(report.parked, 1);
    assert_eq!(report.stop, WakePassStop::DeadlineHardCut);
    let parked = store.parked_job(queued.job.id)?.expect("parked row");
    assert_eq!(parked.reason, DREAMER_HARD_CUT_PARK_REASON);
    let milestone = store
        .latest_durable_milestone(queued.job.id)?
        .expect("durable milestone");
    assert_eq!(milestone.kind, DreamerMilestoneKind::CheckpointReached);
    Ok(())
}

#[test]
fn monotonic_clock_immune_to_wall_jump() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    enqueue_micro(&store, "wall-jump", 10)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    // The deadline reads only its injected monotonic source: wildly
    // different wall-clock `now` inputs do not move it.
    let (_clock, deadline) = injected_clock(1_000);
    assert_eq!(deadline.remaining_ms(), 179_000);
    let mut driver = DreamerWakeDriver::new(&vault, "wake", deadline);
    let mut exec = CompletingExecutor {
        completed_units: 10,
        executed: 0,
    };
    let mut input = run_input(DreamerConsolidationScope::Micro, node_id, 20);
    input.now = 9_999_999_999; // wall clock jumped far forward
    let report = block_on_ready(driver.run_wake_pass(input, &mut exec))?;
    assert_eq!(report.completed, 1);
    assert_eq!(report.stop, WakePassStop::QueueEmpty);
    assert_eq!(
        driver.deadline().remaining_ms(),
        179_000,
        "wall input never moves the monotonic deadline"
    );
    Ok(())
}
