use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

use crate::attempt_queue::{
    AttemptLandingReserve, AttemptQueue, AttemptState, CancelMode, CancelStanding,
    CleanupAttemptLeases, CompleteAttempt, LANDING_RESERVE_PERCENT, RequestAttemptCancel,
};
use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::config::VaultConfig;
use crate::dreamer_runner::DreamerAttemptStatus;
use crate::registry::ENTITY_TYPE_PERSON;
use crate::write_envelope::{WriteActor, WriteProvenance};
use crate::{EdgeActorClass, EntityId, Vault};

use super::*;

mod cleanup_lane;

pub(crate) fn block_on_ready<F: Future>(future: F) -> F::Output {
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
        host_scope: None,
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
fn park_and_resume_roundtrip() -> Result<()> {
    let store_clock = crate::ports::ManualClock::new(10);
    let mut config = VaultConfig::device();
    config.store_clock = store_clock.bundle();
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let store = DreamerRunnerStore::new(&vault);
    let queued = enqueue_micro(&store, "parkable", 10)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let mut parker = ParkingExecutor {
        reason: "await consent".to_owned(),
        park_via_store_first: false,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, {
            store_clock.set(20);
            20
        }),
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
        run_input(DreamerConsolidationScope::Micro, node_id, {
            store_clock.set(130);
            130
        }),
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

fn injected_clock(start_ms: u64) -> (Arc<AtomicU64>, WakePassDeadline) {
    let elapsed = Arc::new(AtomicU64::new(start_ms));
    let clock = Arc::clone(&elapsed);
    let deadline = WakePassDeadline::with_clock(
        DREAMER_WAKE_PASS_WALL_CLOCK_CEILING_MS,
        Arc::new(move || clock.load(Ordering::SeqCst)),
    );
    (elapsed, deadline)
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
            // Simulates an executor error after an already-recorded hard-cut
            // park. This checks recovery of that error path, not LLM preemption.
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

    let store_clock = crate::ports::ManualClock::new(10);
    let mut config = VaultConfig::device();
    config.store_clock = store_clock.bundle();
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
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
        run_input(DreamerConsolidationScope::Micro, node_id, {
            store_clock.set(20);
            20
        }),
        &mut exec,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.admitted, 0, "finalize admits no new attempts");
    assert_eq!(report.stop, WakePassStop::DeadlineHardCut);
    let lands: Vec<_> = driver
        .steering_signals()
        .iter()
        .filter(|signal| signal.threshold == crate::llm::BudgetThreshold::Land95)
        .collect();
    assert_eq!(lands.len(), 1, "exactly one LAND signal");
    assert_eq!(
        lands[0].template_id,
        crate::llm::BUDGET_LAND_PROMPT_TEMPLATE_ID
    );

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

    // Segment 2 — hard cut through an executor ERROR after an existing park.
    // The driver still refunds the reservation, publishes the park, and writes
    // CheckpointReached instead of bailing with the error.
    let (clock, deadline) = injected_clock(100_000);
    let mut driver = DreamerWakeDriver::new(&vault, "wake", deadline).with_milestone_author(author);
    let mut exec = HardCutExecutor {
        clock: Arc::clone(&clock),
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, {
            store_clock.set(30);
            30
        }),
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
    assert!(matches!(result, Err(crate::Error::InvariantViolation(_))));

    // The attempt row is parked, not orphaned-leased.
    let parked = store
        .parked_attempt(queued.attempt.id)?
        .expect("parked row");
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
        Err(crate::Error::Store(
            crate::error::StoreError::AnalyzerError(format!("x{}", "語".repeat(400))),
        ))
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
    let crate::Error::Store(crate::error::StoreError::AnalyzerError(payload)) = error else {
        panic!("expected the executor's AnalyzerError");
    };
    assert_eq!(payload, format!("x{}", "語".repeat(400)));

    // The attempt is parked under the clamped reason, not orphaned-leased.
    let parked = store
        .parked_attempt(queued.attempt.id)?
        .expect("parked row");
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
    assert!(matches!(result, Err(crate::Error::InvariantViolation(_))));

    store
        .parked_attempt(queued.attempt.id)?
        .expect("parked row");
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

/// A cooperative ONE-1896 worker: it polls for an outstanding stop at its own
/// step boundary and answers by LANDING, leaving a resume point behind.
struct LandingExecutor {
    /// A peer's soft `cancel.request`, issued mid-execution by the test to
    /// stand in for a real requester.
    peer_request: bool,
    reserve_units: u64,
    hand_off: bool,
    observed: Option<LandingRequestNotice>,
}

impl DreamerAttemptExecutor for LandingExecutor {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        let attempt_id = attempt.status.attempt.id;
        if self.peer_request {
            AttemptQueue::new(ctx.vault).request_cancel(RequestAttemptCancel {
                id: attempt_id,
                actor: "peer-1".to_owned(),
                standing: CancelStanding::PeerAgent,
                trigger: LandingTrigger::CancelRequest,
                reason: Some("the owner wants the slot back".to_owned()),
                now: ctx.now_ms / 1_000,
            })?;
        }
        self.observed = ctx.landing_request(attempt_id)?;
        let Some(notice) = self.observed.as_ref() else {
            return Ok(DreamerAttemptExecution::Completed { completed_units: 1 });
        };
        Ok(DreamerAttemptExecution::Landed {
            completed_units: 3,
            reserve_units: self.reserve_units.min(notice.reserve_units),
            status: Some("green + pushed + packet-only".to_owned()),
            resume_point: Some(AttemptResumePoint::new("partition-3/of-7", 20)),
            hand_off: self.hand_off,
        })
    }
}

/// ONE-1896 §4: the real worker path. A cooperative executor observes the ask,
/// lands, spends only its reserve, records where a successor resumes, and is
/// never reported completed.
#[test]
fn a_cooperative_worker_lands_through_the_driver_and_is_not_reported_completed() -> Result<()> {
    let store_clock = crate::ports::ManualClock::new(10);
    let mut config = VaultConfig::device();
    config.store_clock = store_clock.bundle();
    let (_dir, vault) = crate::test_util::open_test_vault_with(config);
    let store = DreamerRunnerStore::new(&vault);
    enqueue_micro(&store, "landing-a", 10)?;
    let node_id = crate::identity::load_or_mint_client_id(&vault)?;

    let (_clock, deadline) = injected_clock(0);
    let mut driver = DreamerWakeDriver::new(&vault, "wake", deadline);
    let mut exec = LandingExecutor {
        peer_request: true,
        reserve_units: 4,
        hand_off: true,
        observed: None,
    };
    let report = block_on_ready(driver.run_wake_pass(
        run_input(DreamerConsolidationScope::Micro, node_id, {
            store_clock.set(20);
            20
        }),
        &mut exec,
        &WakeCancellation::new(),
    ))?;

    assert_eq!(report.admitted, 1);
    assert_eq!(report.landed, 1);
    assert_eq!(
        report.completed, 0,
        "a landing delivered no result and is never counted as one"
    );
    assert_eq!(report.parked, 0);
    let notice = exec.observed.expect("the worker observed the ask");
    assert_eq!(notice.trigger, LandingTrigger::CancelRequest);
    assert_eq!(notice.requested_by, "peer-1");
    assert_eq!(
        notice.reserve_units,
        AttemptLandingReserve::dialed(100, LANDING_RESERVE_PERCENT).reserve_units,
        "admission dialed the attempt's landing reserve out of its reserved units"
    );

    let queue = AttemptQueue::new(&vault);
    let rows = queue.list()?;
    let landed = rows
        .iter()
        .find(|row| row.state == AttemptState::Cancelled)
        .expect("the landed row");
    let cancellation = landed.cancellation().expect("terminal receipt");
    assert_eq!(cancellation.mode, CancelMode::Landed);
    assert_eq!(cancellation.trigger, Some(LandingTrigger::CancelRequest));
    assert_eq!(cancellation.reserve_spent_units, 4);
    assert_eq!(
        landed.resume_point().expect("resume point").marker,
        "partition-3/of-7"
    );
    assert_eq!(
        landed.landing().expect("landing").status.as_deref(),
        Some("green + pushed + packet-only")
    );
    // The successor carries the exact point and is ordinary claimable work.
    let successor = rows
        .iter()
        .find(|row| row.retry_of == Some(landed.id))
        .expect("handoff successor");
    assert_eq!(
        successor.state,
        AttemptState::Scheduled,
        "the successor is next-pass work, not work this pressured pass re-admits"
    );
    assert_eq!(
        successor.resume_point().expect("point").marker,
        "partition-3/of-7"
    );
    // Duplicate/stale completion stays typed and idempotent.
    let err = queue
        .complete(CompleteAttempt {
            id: landed.id,
            lease_owner: "wake-worker".to_owned(),
            attempt_count: landed.attempt_count,
            now: 30,
        })
        .expect_err("a landed row cannot also complete");
    assert!(matches!(
        err,
        crate::Error::Artifact(crate::error::ArtifactError::InvalidAttemptQueueTransition { action, state })
            if action == "complete" && state == "cancelled"
    ));
    Ok(())
}
