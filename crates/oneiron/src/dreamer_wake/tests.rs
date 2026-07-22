use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use crate::attempt_queue::{
    AttemptInterventionKind, AttemptQueue, AttemptState, CleanupAttemptLeases, InterveneAttempt,
};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::config::VaultConfig;
use crate::dreamer_runner::{DreamerAttemptStatus, DreamerHomeNodeCandidate};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::write_envelope::{WriteActor, WriteProvenance};
use crate::{EdgeActorClass, EntityId, Vault};

use super::*;

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    // The pass self-wakes and pends once per attempt boundary (the ONE-1683
    // shutdown-observability yield), so polling again immediately is
    // correct; the bound catches a future pending on anything else.
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("wake-pass future pending on something other than an attempt-boundary yield");
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

fn enqueue_micro(
    store: &DreamerRunnerStore<'_>,
    tag: &str,
    now: u64,
) -> Result<DreamerAttemptStatus> {
    match store.enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
        scope: DreamerConsolidationScope::Micro,
        input: Value::from(format!("input:{tag}")),
        parent_attempt: None,
        dedupe_key: Some(tag.to_owned()),
        run_id: None,
        now,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => Ok(status),
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

impl DreamerAttemptExecutor for CompletingExecutor {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        self.executed += 1;
        Ok(DreamerAttemptExecution::Completed {
            completed_units: self.completed_units,
        })
    }
}

struct ParkingExecutor {
    reason: String,
    park_via_store_first: bool,
}

impl DreamerAttemptExecutor for ParkingExecutor {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        if self.park_via_store_first {
            // Simulates the step layer's trap flow: the step layer is the
            // one park-owner; the executor still surfaces Park.
            DreamerRunnerStore::new(ctx.vault).park_attempt(ParkDreamerAttempt {
                attempt_id: attempt.status.attempt.id,
                reason: self.reason.clone(),
                park_owner: "step-layer".to_owned(),
                now: ctx.now_ms / 1_000,
            })?;
        }
        Ok(DreamerAttemptExecution::Park {
            reason: self.reason.clone(),
        })
    }
}

#[test]
fn wake_pass_drains_queue_until_empty() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let author = milestone_author(&vault, 5)?;
    let attempts = [
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
        &WakeCancellation::new(),
    ))?;

    assert_eq!(report.admitted, 3);
    assert_eq!(report.completed, 3);
    assert_eq!(report.failed, 0);
    assert_eq!(report.parked, 0);
    assert_eq!(report.stop, WakePassStop::QueueEmpty);
    assert_eq!(exec.executed, 3);

    // Budget settled per attempt: 3 x 40 actual units spent, reservations gone.
    let budget = store.budget("wake")?.expect("budget row");
    assert_eq!(budget.remaining_units, 10_000 - 3 * 40);
    assert_eq!(budget.reserved_units, 0);

    // Done milestones are durable and readable back per attempt.
    for attempt in &attempts {
        let milestone = store
            .latest_durable_milestone(attempt.attempt.id)?
            .expect("durable milestone");
        assert_eq!(milestone.kind, DreamerMilestoneKind::Done);
        let status = store.status(attempt.attempt.id)?.expect("attempt status");
        assert_eq!(status.attempt.state, AttemptState::Completed);
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
    let report = block_on_ready(driver.run_wake_pass(input, &mut exec, &WakeCancellation::new()))?;

    // First attempt admits (reserve 100 of 150) and spends 100; the second
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
        &WakeCancellation::new(),
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
        &WakeCancellation::new(),
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
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.stop, WakePassStop::DeadlineHardCut);
    assert_eq!(report.admitted, 0);
    assert_eq!(exec.executed, 0);
    let status = store.status(queued.attempt.id)?.expect("attempt status");
    assert_eq!(
        status.attempt.state,
        AttemptState::Queued,
        "attempt never claimed"
    );
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
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.admitted, 1);
    assert_eq!(report.parked, 1);
    assert_eq!(report.completed, 0);
    let parked = store
        .parked_attempt(queued.attempt.id)?
        .expect("parked row");
    assert_eq!(parked.reason, "await consent");
    // The reservation was refunded, not spent.
    let budget = store.budget("wake")?.expect("budget row");
    assert_eq!(budget.remaining_units, 10_000);
    assert_eq!(budget.reserved_units, 0);

    // Resume clears the parked row and is idempotent on re-call. The driver
    // parked under its lease owner, so resume must present the same token.
    let resumed = store
        .resume_parked(queued.attempt.id, "wake-worker", 30)?
        .expect("resumed status");
    assert_eq!(resumed.attempt.id, queued.attempt.id);
    assert!(store.parked_attempt(queued.attempt.id)?.is_none());
    assert!(
        store
            .resume_parked(queued.attempt.id, "wake-worker", 31)?
            .is_none()
    );

    // Expire the stale lease so normal admission can re-claim the attempt.
    let queue = AttemptQueue::new(&vault);
    queue.cleanup_leases(CleanupAttemptLeases {
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
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.admitted, 1);
    assert_eq!(report.completed, 1);
    assert_eq!(report.stop, WakePassStop::QueueEmpty);
    let status = store.status(queued.attempt.id)?.expect("attempt status");
    assert_eq!(status.attempt.state, AttemptState::Completed);
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
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.parked, 1);
    // The step layer's park row survives untouched (one park-owner): the
    // driver never re-parks, so the original parked_at stamp is preserved.
    let parked = store
        .parked_attempt(queued.attempt.id)?
        .expect("parked row");
    assert_eq!(parked.reason, "durable step budget exhausted");
    assert_eq!(parked.parked_at, 20);
    Ok(())
}

#[test]
fn paused_attempt_not_admitted() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "paused", 10)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    let queue = AttemptQueue::new(&vault);
    queue.intervene(InterveneAttempt {
        id: queued.attempt.id,
        kind: AttemptInterventionKind::Pause,
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
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.admitted, 0, "paused attempt is skipped by admission");
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
    let payload = DreamerAttemptPayload {
        attempt_type: String::new(), // enqueue derives attempt_type from the scope
        input: Value::from("compaction summary"),
        parent_attempt: None,
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
    assert!(matches!(first, EnqueueDreamerAttemptOutcome::Enqueued(_)));

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
    assert!(matches!(second, EnqueueDreamerAttemptOutcome::Existing(_)));
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

/// Completes attempts while advancing the injected pass clock, simulating work
/// that consumes wall time.
struct ClockAdvancingExecutor {
    clock: Arc<AtomicU64>,
    advance_by_ms: u64,
    completed_units: u64,
    executed: u32,
}

impl DreamerAttemptExecutor for ClockAdvancingExecutor {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        self.executed += 1;
        self.clock.fetch_add(self.advance_by_ms, Ordering::SeqCst);
        Ok(DreamerAttemptExecution::Completed {
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

    // The first attempt eats the whole ceiling; the pass must hard-stop without
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
        &WakeCancellation::new(),
    ))?;

    assert_eq!(report.stop, WakePassStop::DeadlineHardCut);
    assert_eq!(report.admitted, 1, "no admission past the ceiling");
    assert_eq!(report.completed, 1);
    assert_eq!(exec.executed, 1);
    let status = store
        .status(second.attempt.id)?
        .expect("second attempt status");
    assert_eq!(status.attempt.state, AttemptState::Queued, "never claimed");
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
        &WakeCancellation::new(),
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
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.completed, 2);

    let plans = driver
        .steering_signals()
        .iter()
        .filter(|signal| signal.threshold == crate::BudgetThreshold::Plan80)
        .count();
    assert_eq!(plans, 1, "exactly one PLAN signal per pass");
    Ok(())
}

#[test]
fn graceful_wrap_then_hard_cut_sequencing() -> Result<()> {
    struct HardCutExecutor {
        clock: Arc<AtomicU64>,
    }
    impl DreamerAttemptExecutor for HardCutExecutor {
        async fn execute(
            &mut self,
            attempt: &DreamerAdmittedAttempt,
            ctx: &mut WakeAttemptContext<'_>,
        ) -> Result<DreamerAttemptExecution> {
            // Simulates the ONE-1305 step-layer deadline race exactly: the
            // step layer parks at the ceiling under its hard-cut owner, then
            // the error (not Park) escapes the executor.
            self.clock.store(180_001, Ordering::SeqCst);
            DreamerRunnerStore::new(ctx.vault).park_attempt(ParkDreamerAttempt {
                attempt_id: attempt.status.attempt.id,
                reason: DREAMER_HARD_CUT_PARK_REASON.to_owned(),
                park_owner: DREAMER_HARD_CUT_PARK_OWNER.to_owned(),
                now: ctx.now_ms / 1_000,
            })?;
            Err(crate::Error::InvariantViolation(
                "durable step hard cut at the wake-pass deadline",
            ))
        }
    }

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
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.admitted, 0, "finalize admits no new attempts");
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

    // Segment 2 — hard cut through the ERROR path: the step layer parks the
    // running attempt at the ceiling and its DeadlineHardCut error is propagated
    // by the executor (a host that does not map it to Park). The driver must
    // still run the whole release sequence — budget-reservation refund,
    // park/publish bookkeeping, and the CheckpointReached milestone — and
    // stop DeadlineHardCut instead of bailing with the error.
    let (clock, deadline) = injected_clock(100_000);
    let mut driver = DreamerWakeDriver::new(&vault, "wake", deadline).with_milestone_author(author);
    let mut exec = HardCutExecutor {
        clock: Arc::clone(&clock),
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 30),
        &mut exec,
        &WakeCancellation::new(),
    ))
    .expect("hard-cut pass reports instead of erroring");
    assert_eq!(report.admitted, 1);
    assert_eq!(report.parked, 1);
    assert_eq!(report.stop, WakePassStop::DeadlineHardCut);
    let parked = store
        .parked_attempt(queued.attempt.id)?
        .expect("parked row");
    assert_eq!(parked.reason, DREAMER_HARD_CUT_PARK_REASON);
    assert_eq!(parked.park_owner, DREAMER_HARD_CUT_PARK_OWNER);

    // Budget refund: the admission reservation was aborted, not leaked.
    assert!(
        store
            .budget_reservation("wake", queued.attempt.id)?
            .is_none(),
        "hard cut must refund the runner budget reservation"
    );
    let budget = store.budget("wake")?.expect("budget row");
    assert_eq!(budget.reserved_units, 0);
    assert_eq!(budget.remaining_units, 10_000);

    // Checkpoint: the deadline-cut park left a durable resume point.
    let milestone = store
        .latest_durable_milestone(queued.attempt.id)?
        .expect("durable milestone");
    assert_eq!(milestone.kind, DreamerMilestoneKind::CheckpointReached);

    // Queue-lease cleanup: the cut attempt's stale lease is reclaimable through
    // the normal path, so the attempt re-queues for the next pass.
    let queue = AttemptQueue::new(&vault);
    let cleaned = queue.cleanup_leases(CleanupAttemptLeases {
        now: 200,
        lease_timeout_secs: 10,
    })?;
    assert_eq!(cleaned.stale_requeued, 1, "hard-cut lease reclaimed");
    let status = store.status(queued.attempt.id)?.expect("attempt status");
    assert_eq!(status.attempt.state, AttemptState::Queued);
    Ok(())
}

#[test]
fn reused_driver_fires_wrap_notice_each_pass() -> Result<()> {
    let (_dir, vault) = open_vault();
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    // Pass 1 at 83% elapsed: the clock-side wrap notice fires.
    let (clock, deadline) = injected_clock(150_000);
    let mut driver = DreamerWakeDriver::new(&vault, "wake", deadline);
    let mut exec = CompletingExecutor {
        completed_units: 10,
        executed: 0,
    };
    block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut exec,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(
        driver.steering_signals().len(),
        1,
        "pass 1 fires its wrap notice"
    );

    // Pass 2 on the SAME driver, below the notice threshold: the buffer is
    // per-pass — pass 1's signal must not linger, and nothing new fires.
    clock.store(10_000, Ordering::SeqCst);
    block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 30),
        &mut exec,
        &WakeCancellation::new(),
    ))?;
    assert!(
        driver.steering_signals().is_empty(),
        "pass 2 below threshold carries no stale pass-1 signal"
    );

    // Pass 3 back over the threshold: the notice fires AGAIN — per-pass
    // state, not per-driver state.
    clock.store(150_000, Ordering::SeqCst);
    block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 40),
        &mut exec,
        &WakeCancellation::new(),
    ))?;
    let plans = driver
        .steering_signals()
        .iter()
        .filter(|signal| signal.threshold == crate::BudgetThreshold::Plan80)
        .count();
    assert_eq!(plans, 1, "pass 3 fires its own wrap notice");
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
    let report = block_on_ready(driver.run_wake_pass(input, &mut exec, &WakeCancellation::new()))?;
    assert_eq!(report.completed, 1);
    assert_eq!(report.stop, WakePassStop::QueueEmpty);
    assert_eq!(
        driver.deadline().remaining_ms(),
        179_000,
        "wall input never moves the monotonic deadline"
    );
    Ok(())
}

/// Fails every attempt with a non-deadline error (the ONE-1683 leak site: the
/// attempt is NOT step-layer-parked and the deadline has NOT expired).
struct FailingExecutor;

impl DreamerAttemptExecutor for FailingExecutor {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        Err(crate::Error::InvariantViolation(
            "executor exploded mid-attempt",
        ))
    }
}

#[test]
fn executor_error_parks_attempt_and_refunds_reservation() -> Result<()> {
    // ONE-1683 H-S5/R2: a non-deadline executor error must park the admitted
    // attempt and refund its budget reservation BEFORE the error propagates —
    // the old path returned Err with the attempt stuck leased and the
    // reservation held.
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "erroring", 10)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let mut exec = FailingExecutor;
    let result = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut exec,
        &WakeCancellation::new(),
    ));
    assert!(result.is_err(), "a non-deadline error still propagates");

    // The attempt row is parked under the error reason, not orphaned-leased.
    let parked = store
        .parked_attempt(queued.attempt.id)?
        .expect("parked row");
    assert!(
        parked
            .reason
            .starts_with(DREAMER_EXECUTOR_ERROR_PARK_REASON),
        "park reason carries the executor error class: {}",
        parked.reason
    );
    assert_eq!(parked.park_owner, "wake-worker");

    // The budget reservation was refunded, not leaked.
    assert!(
        store
            .budget_reservation("wake", queued.attempt.id)?
            .is_none(),
        "the error path must abort the runner budget reservation"
    );
    let budget = store.budget("wake")?.expect("budget row");
    assert_eq!(budget.reserved_units, 0);
    assert_eq!(budget.remaining_units, 10_000);

    // The parked attempt resumes through the normal path — nothing is stuck.
    assert!(
        store
            .resume_parked(queued.attempt.id, "wake-worker", 30)?
            .is_some()
    );
    Ok(())
}

#[test]
fn cancel_before_pass_admits_nothing() -> Result<()> {
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "never-admitted", 10)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    let cancel = WakeCancellation::new();
    cancel.cancel();
    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let mut exec = CompletingExecutor {
        completed_units: 10,
        executed: 0,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut exec,
        &cancel,
    ))?;
    assert_eq!(report.stop, WakePassStop::Cancelled);
    assert_eq!(
        report.admitted, 0,
        "an already-cancelled pass admits nothing"
    );
    assert_eq!(exec.executed, 0);
    let status = store.status(queued.attempt.id)?.expect("attempt status");
    assert_eq!(status.attempt.state, AttemptState::Queued, "never claimed");
    Ok(())
}

/// Completes its attempt normally but raises the cancellation flag while
/// executing — simulating a supervisor shutdown landing mid-pass.
struct CancellingExecutor {
    cancel: WakeCancellation,
    executed: u32,
}

impl DreamerAttemptExecutor for CancellingExecutor {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        self.executed += 1;
        self.cancel.cancel();
        Ok(DreamerAttemptExecution::Completed {
            completed_units: 40,
        })
    }
}

#[test]
fn cancel_mid_pass_finishes_in_flight_attempt_then_stops() -> Result<()> {
    // H-S5/R2: a cancel raised while an attempt is executing is honored only at
    // the NEXT attempt boundary — the in-flight attempt runs to completion and
    // settles (never aborted mid-write); the second attempt is never admitted.
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let first = enqueue_micro(&store, "in-flight", 10)?;
    let second = enqueue_micro(&store, "never-started", 11)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    let cancel = WakeCancellation::new();
    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let mut exec = CancellingExecutor {
        cancel: cancel.clone(),
        executed: 0,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut exec,
        &cancel,
    ))?;
    assert_eq!(report.stop, WakePassStop::Cancelled);
    assert_eq!(report.admitted, 1);
    assert_eq!(
        report.completed, 1,
        "the in-flight attempt settles normally"
    );
    assert_eq!(exec.executed, 1);

    // Attempt 1 fully settled: spent, no reservation held.
    let status = store
        .status(first.attempt.id)?
        .expect("first attempt status");
    assert_eq!(status.attempt.state, AttemptState::Completed);
    let budget = store.budget("wake")?.expect("budget row");
    assert_eq!(budget.remaining_units, 10_000 - 40);
    assert_eq!(budget.reserved_units, 0);

    // Attempt 2 untouched — ready for the next pass.
    let status = store
        .status(second.attempt.id)?
        .expect("second attempt status");
    assert_eq!(status.attempt.state, AttemptState::Queued, "never claimed");
    Ok(())
}

#[test]
fn clamp_park_reason_is_utf8_boundary_safe() {
    // 1 ASCII byte then 3-byte chars: the 512 ceiling lands mid-character,
    // so the cut must step back to the previous boundary (511) instead of
    // panicking in `String::truncate`.
    let clamped = clamp_park_reason(format!("x{}", "語".repeat(400)));
    assert_eq!(clamped.len(), 511);
    assert!(clamped.len() <= MAX_WAKE_PARK_REASON_BYTES);

    // At or under the ceiling nothing changes.
    assert_eq!(clamp_park_reason("short".to_owned()), "short");
    let exact = "a".repeat(MAX_WAKE_PARK_REASON_BYTES);
    assert_eq!(clamp_park_reason(exact.clone()), exact);
}

/// Fails every attempt with an error whose Display exceeds the store's park
/// reason ceiling (the qodo ONE-1683 review finding: the unclamped reason
/// used to fail park validation, leaving the admitted attempt leased).
struct OversizedErrorExecutor;

impl DreamerAttemptExecutor for OversizedErrorExecutor {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        Err(crate::Error::AnalyzerError(format!(
            "x{}",
            "語".repeat(400)
        )))
    }
}

#[test]
fn executor_error_with_oversized_display_still_parks() -> Result<()> {
    // Also pins the MAX_WAKE_PARK_REASON_BYTES mirror against the store's
    // real validation: if the store ceiling ever shrank below the mirror,
    // the park here would fail and so would this test.
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "oversized-error", 10)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let mut exec = OversizedErrorExecutor;
    let result = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut exec,
        &WakeCancellation::new(),
    ));
    let error = result.expect_err("the executor error still propagates");
    assert!(
        error.to_string().len() > MAX_WAKE_PARK_REASON_BYTES,
        "the propagated error keeps its full Display"
    );

    // The attempt is parked under the clamped reason, not orphaned-leased.
    let parked = store
        .parked_attempt(queued.attempt.id)?
        .expect("parked row");
    assert!(
        parked
            .reason
            .starts_with(DREAMER_EXECUTOR_ERROR_PARK_REASON),
        "clamping keeps the reason prefix: {}",
        parked.reason
    );
    assert!(parked.reason.len() <= MAX_WAKE_PARK_REASON_BYTES);

    // The budget reservation was refunded, not leaked.
    assert!(
        store
            .budget_reservation("wake", queued.attempt.id)?
            .is_none(),
        "the error path must abort the runner budget reservation"
    );
    let budget = store.budget("wake")?.expect("budget row");
    assert_eq!(budget.reserved_units, 0);
    assert_eq!(budget.remaining_units, 10_000);
    Ok(())
}

#[test]
fn oversized_executor_park_reason_is_clamped() -> Result<()> {
    // The ordinary Park arm gets the same clamp: an over-limit
    // executor-authored reason failing park validation would propagate
    // after the refund but before the park, leaving the attempt leased.
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "long-park", 10)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let mut parker = ParkingExecutor {
        reason: format!("x{}", "語".repeat(400)),
        park_via_store_first: false,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut parker,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.parked, 1);
    assert_eq!(report.stop, WakePassStop::QueueEmpty, "the pass continues");
    let parked = store
        .parked_attempt(queued.attempt.id)?
        .expect("parked row");
    assert!(parked.reason.len() <= MAX_WAKE_PARK_REASON_BYTES);
    assert!(parked.reason.starts_with('x'));
    let budget = store.budget("wake")?.expect("budget row");
    assert_eq!(budget.reserved_units, 0);
    Ok(())
}

/// Panics on every attempt — the codex ONE-1683 P1 leak site: an unwind past
/// the driver used to skip the park/refund bookkeeping entirely, leaving
/// the attempt leased and the reservation held.
struct PanickingExecutor;

impl DreamerAttemptExecutor for PanickingExecutor {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        panic!("executor exploded mid-attempt");
    }
}

#[test]
fn executor_panic_parks_attempt_and_refunds_reservation() -> Result<()> {
    // A panic inside exec.execute is contained at the per-attempt boundary and
    // routed through the executor-error arm: the admitted attempt is parked,
    // its reservation refunded, and the pass returns Err instead of
    // unwinding past the driver with the lease still held.
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "panicking", 10)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let mut exec = PanickingExecutor;
    let result = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut exec,
        &WakeCancellation::new(),
    ));
    assert!(
        result.is_err(),
        "the contained panic surfaces as a pass error"
    );

    let parked = store
        .parked_attempt(queued.attempt.id)?
        .expect("parked row");
    assert!(
        parked
            .reason
            .starts_with(DREAMER_EXECUTOR_ERROR_PARK_REASON),
        "the panic parks through the executor-error arm: {}",
        parked.reason
    );
    assert!(
        parked.reason.contains("panicked"),
        "the reason names the panic: {}",
        parked.reason
    );
    assert!(
        store
            .budget_reservation("wake", queued.attempt.id)?
            .is_none(),
        "the panic path must abort the runner budget reservation"
    );
    let budget = store.budget("wake")?.expect("budget row");
    assert_eq!(budget.reserved_units, 0);
    assert_eq!(budget.remaining_units, 10_000);

    // The parked attempt resumes through the normal path — nothing is stuck.
    assert!(
        store
            .resume_parked(queued.attempt.id, "wake-worker", 30)?
            .is_some()
    );
    Ok(())
}

#[test]
fn pass_yields_at_each_attempt_boundary_for_cancellation() -> Result<()> {
    // ONE-1683: run_wake_pass must yield once per attempt boundary so a
    // supervisor's biased select! is re-polled between attempts — and can raise
    // the cancellation flag in time — even when every executor completes
    // synchronously.
    let (_dir, vault) = open_vault();
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "boundary", 10)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    let cancel = WakeCancellation::new();
    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let mut exec = CompletingExecutor {
        completed_units: 10,
        executed: 0,
    };
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let future = driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, 20),
        &mut exec,
        &cancel,
    );
    let mut future = pin!(future);

    // The first poll parks on the loop-top yield BEFORE any admission.
    assert!(
        future.as_mut().poll(&mut cx).is_pending(),
        "attempt-boundary yield"
    );
    let status = store.status(queued.attempt.id)?.expect("attempt status");
    assert_eq!(
        status.attempt.state,
        AttemptState::Queued,
        "nothing admitted before the yield"
    );

    // A cancellation raised while parked at the yield is honored before
    // the admission — the supervisor's shutdown window.
    cancel.cancel();
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(Ok(report)) => {
            assert_eq!(report.stop, WakePassStop::Cancelled);
            assert_eq!(report.admitted, 0);
        }
        other => panic!("expected the cancelled pass to finish: {other:?}"),
    }
    Ok(())
}
