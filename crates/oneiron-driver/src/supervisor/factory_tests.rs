//! Factory, planner-routing, and attempt-fixture tests.
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::tick::PushTick;
use oneiron::attempt_queue::AttemptState;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, DREAMER_EXECUTOR_ERROR_PARK_REASON,
    DREAMER_GRACEFUL_WRAP_WINDOW_MS, DreamerAttemptExecution, DreamerAttemptExecutor,
    DreamerClaimAuthoringStrategy, DreamerConsolidationScope, DreamerRunnerStore, Result,
    WakeAttemptContext, WakePassDeadline, WakeTrigger, WriteActor,
};

#[test]
fn config_validate_rejects_zero_reserve_units_and_bad_lease_owner() {
    // P2 (codex r6): reserve_units==0 / empty / overlong lease_owner
    // passed validate but admission rejected before mutating rows,
    // surfacing as Failed (tick consumed). Fail-fast in validate.
    let mut config = test_config();
    assert!(config.validate().is_ok());

    config.reserve_units = 0;
    let error = config.validate().expect_err("reserve_units=0 must reject");
    assert!(matches!(error, oneiron::Error::InvalidConfig(_)));
    config.reserve_units = 100;
    assert!(config.validate().is_ok());

    config.lease_owner.clear();
    let error = config
        .validate()
        .expect_err("empty lease_owner must reject");
    assert!(matches!(error, oneiron::Error::InvalidConfig(_)));

    config.lease_owner = "x".repeat(MAX_RUNNER_LEASE_OWNER_LEN + 1);
    let error = config
        .validate()
        .expect_err("overlong lease_owner must reject");
    assert!(matches!(error, oneiron::Error::InvalidConfig(_)));

    config.lease_owner = "x".repeat(MAX_RUNNER_LEASE_OWNER_LEN);
    assert!(
        config.validate().is_ok(),
        "exactly MAX_RUNNER_LEASE_OWNER_LEN is allowed"
    );
}

/// Pins the mirrored lease-owner ceiling against the real attempt queue:
/// a claim with an owner of `MAX_RUNNER_LEASE_OWNER_LEN` must be
/// accepted at the validation boundary, and one byte more must fail.
#[test]
fn widest_lease_owner_fits_attempt_queue_ceiling() {
    use oneiron::DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND;
    use oneiron::attempt_queue::{AttemptQueue, ClaimAttempt, ClaimOutcome};

    let (_dir, vault) = open_vault();
    enqueue_micro(&vault, "lease-owner-ceiling", 10);
    let queue = AttemptQueue::new(&vault);

    let ok_owner = "o".repeat(MAX_RUNNER_LEASE_OWNER_LEN);
    let claimed = queue
        .claim_kind(
            DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: ok_owner,
                now: 20,
            },
        )
        .expect("claim with max-length owner must validate");
    assert!(
        matches!(claimed, ClaimOutcome::Claimed(_)),
        "max-length lease_owner must be admissible"
    );

    // Overlong fails validation before scanning — no need for another attempt.
    let over = "o".repeat(MAX_RUNNER_LEASE_OWNER_LEN + 1);
    let err = queue
        .claim_kind(
            DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: over,
                now: 21,
            },
        )
        .expect_err("overlong lease_owner must fail attempt-queue validation");
    assert!(
        matches!(err, oneiron::Error::InvalidAttemptQueueRecord(_)),
        "expected InvalidAttemptQueueRecord, got {err:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn setup_panic_before_admission_redrives_push_tick() {
    // P2 (codex r6 / 3585850170): factory panic before admission on a
    // PushTick-only supervisor. Single wake, panics once → redrive after
    // backoff completes the attempt (no second push).
    let (_dir, vault) = open_vault();
    let attempt = enqueue_micro(&vault, "factory-panic-redrive", 10);

    let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
    wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
        .expect("open channel");
    drop(wake);
    drop(hint);

    let factory = TestExecFactory {
        panics_left: 0,
        factory_panics_left: 1,
        factory_errors_left: 0,
        completed_units: 40,
    };
    let mut config = test_config();
    config.backoff = RestartBackoffConfig {
        initial: Duration::from_millis(10),
        max: Duration::from_millis(10),
    };
    let supervisor = WakeSupervisor::new(&vault, push, factory, config);
    let report = supervisor.run().await;

    assert_eq!(report.passes_panicked, 1, "one setup panic counted");
    assert_eq!(
        report.passes_completed, 1,
        "redrive after backoff must complete a pass"
    );
    assert_eq!(report.attempts_completed, 1);
    assert_eq!(report.passes_failed, 0);

    let status = DreamerRunnerStore::new(&vault)
        .status(attempt)
        .expect("status read")
        .expect("status");
    assert_eq!(status.attempt.state, AttemptState::Completed);
}

#[tokio::test(start_paused = true)]
async fn in_pass_failure_with_backlog_redrives_without_second_push() {
    // P2 (codex r6 / 3585850187): single wake, two queued attempts; first
    // pass fails after admitting attempt 1 (executor panic → park+Failed).
    // Redrive drains attempt 2 without a second push.
    let (_dir, vault) = open_vault();
    let first = enqueue_micro(&vault, "fail-after-admit-1", 10);
    let second = enqueue_micro(&vault, "fail-after-admit-2", 11);

    let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
    wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
        .expect("open channel");
    drop(wake);
    drop(hint);

    let factory = TestExecFactory {
        panics_left: 1,
        factory_panics_left: 0,
        factory_errors_left: 0,
        completed_units: 40,
    };
    let mut config = test_config();
    config.backoff = RestartBackoffConfig {
        initial: Duration::from_millis(10),
        max: Duration::from_millis(10),
    };
    let supervisor = WakeSupervisor::new(&vault, push, factory, config);
    let report = supervisor.run().await;

    assert_eq!(report.passes_failed, 1, "in-pass failure counted once");
    assert_eq!(
        report.passes_completed, 1,
        "redrive completes the backlog pass"
    );
    assert_eq!(
        report.attempts_completed, 1,
        "attempt 2 completed on redrive"
    );
    assert_eq!(report.passes_panicked, 0);

    let store = DreamerRunnerStore::new(&vault);
    let parked = store
        .parked_attempt(first)
        .expect("parked read")
        .expect("attempt 1 parked");
    assert!(
        parked
            .reason
            .starts_with(DREAMER_EXECUTOR_ERROR_PARK_REASON),
        "attempt 1 park reason: {}",
        parked.reason
    );
    let status = store
        .status(second)
        .expect("status read")
        .expect("attempt 2 status");
    assert_eq!(status.attempt.state, AttemptState::Completed);
}

#[tokio::test(start_paused = true)]
async fn empty_completed_pass_redrives_then_completes_without_second_push() {
    // P2 (codex r6 / 3585850199): single wake, first pass zero-progress
    // DeadlineHardCut (admitted == 0) → backoff + redrive; second pass
    // admits and completes without a second push.
    //
    // Ceiling WRAP+50 → finalize opens at 50ms. First factory call sleeps
    // 60ms (past finalize); redrive call does not sleep so the pass has
    // ~50ms of wall budget — enough to admit one scripted attempt.
    let (_dir, vault) = open_vault();
    let attempt = enqueue_micro(&vault, "empty-then-complete", 10);

    let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
    wake.push_wake(WakeTrigger::Compaction, DreamerConsolidationScope::Micro)
        .expect("open channel");
    drop(wake);
    drop(hint);

    let factory = DelayedHardCutFactory {
        completed_units: 40,
        delay: Duration::from_millis(60),
        delays_left: 1,
    };
    let mut config = test_config();
    config.pass_ceiling_ms = DREAMER_GRACEFUL_WRAP_WINDOW_MS + 50;
    config.backoff = RestartBackoffConfig {
        initial: Duration::from_millis(10),
        max: Duration::from_millis(10),
    };
    let supervisor = WakeSupervisor::new(&vault, push, factory, config);
    let report = supervisor.run().await;

    assert_eq!(
        report.passes_completed, 2,
        "one empty hard-cut + one productive redrive"
    );
    assert_eq!(report.attempts_completed, 1);
    assert_eq!(report.passes_failed, 0);
    assert_eq!(report.passes_panicked, 0);

    let status = DreamerRunnerStore::new(&vault)
        .status(attempt)
        .expect("status read")
        .expect("status");
    assert_eq!(status.attempt.state, AttemptState::Completed);
}

/// A backend that fails loudly if reached. The commitment-wake arm is
/// synchronous and deterministic by contract, so a model call from it is
/// the defect, not a cost.
struct UnusedBackend;

impl oneiron::LlmBackend for UnusedBackend {
    fn generate<'a>(
        &'a self,
        _request: oneiron::LlmRequest,
        _lease: &'a oneiron::BudgetLease,
    ) -> oneiron::LlmGenerateFuture<'a> {
        Box::pin(async { panic!("the commitment wake path must never call a model") })
    }

    fn stream<'a>(
        &'a self,
        _request: oneiron::LlmRequest,
        _lease: &'a oneiron::BudgetLease,
    ) -> oneiron::LlmStreamResult<'a> {
        panic!("the commitment wake path must never stream")
    }
}

#[derive(Default)]
struct CountingPlanner {
    plans: Arc<std::sync::atomic::AtomicUsize>,
}

impl oneiron::CommitmentWakeProposalPlanner for CountingPlanner {
    fn plan(
        &mut self,
        _event: &oneiron::CommitmentWakeEvent,
        _commitment: &oneiron::commitment::CommitmentRecord,
    ) -> Result<oneiron::CommitmentWakeProposalDraft> {
        self.plans.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(oneiron::CommitmentWakeProposalDraft {
            verb: "call".to_owned(),
            channel: "voice".to_owned(),
            target: "+15551234567".to_owned(),
            on_behalf_of: None,
            content_ref: None,
            dedupe_key: None,
        })
    }
}

fn consolidation_factory(actor: WriteActor) -> ConsolidationExecutorFactory {
    ConsolidationExecutorFactory::new(
        Arc::new(UnusedBackend),
        DreamerClaimAuthoringStrategy::SinglePass,
        actor,
        oneiron::ModelId::new("test/model@v1").expect("model id"),
        Box::new(UnusedSink),
    )
}

/// The DEFAULT factory always returns the wrapper — including behind a
/// legal System-class actor with no planner. A tagged event then completes
/// as the typed no-planner skip instead of reaching the partition decoder,
/// which is the whole reason the wrapper is unconditional.
#[test]
fn default_factory_installs_commitment_wrapper_without_planner() {
    let (_dir, vault) = open_vault();
    let system = seed_actor(&vault, 0x5C, oneiron::registry::ENTITY_TYPE_MACHINE);
    let mut factory =
        consolidation_factory(WriteActor::new(system, oneiron::EdgeActorClass::System));
    let guard = BudgetGuard::new("wake".to_owned(), 10_000, BudgetExhaustionPolicy::Suspend);

    let executor = factory.executor(&guard);
    assert!(
        executor.is_ok(),
        "a planner-less wrapper never reads the actor, so a System host composes"
    );
    // The associated type IS the wrapper: the default wiring cannot hand
    // back a bare consolidation executor.
    let _typed: ConsolidationExecutorFactory = factory;
}

/// With a planner installed, the factory's executor routes a tagged
/// commitment event to the planner and still hands an ordinary partition
/// attempt to the inner consolidation executor.
#[tokio::test]
async fn factory_planner_routes_tagged_attempt_and_delegates_partition() {
    let (_dir, vault) = open_vault();
    let agent = seed_actor(&vault, 0x5D, oneiron::registry::ENTITY_TYPE_PERSON);
    let plans = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let factory = consolidation_factory(WriteActor::new(agent, oneiron::EdgeActorClass::Agent));
    let mut factory = factory
        .with_commitment_wake_planner(Box::new(CountingPlanner {
            plans: Arc::clone(&plans),
        }))
        .expect("an agent actor may install a planner");
    let guard = BudgetGuard::new("wake".to_owned(), 10_000, BudgetExhaustionPolicy::Suspend);
    let mut executor = factory.executor(&guard).expect("wrapped executor");

    // A tagged event whose instance does not resolve: the wrapper answers
    // with a typed skip and a zero-unit completion — never a decode error.
    let event = oneiron::CommitmentWakeEvent {
        schema_version: 1,
        instance_id: oneiron::EntityId::from_bytes([0x5E; 16]).expect("instance id"),
        phase: oneiron::CommitmentWakePhase::Lead,
        fire_at: 900,
        due_at: 1_000,
    };
    let tagged = oneiron::encode_commitment_wake_event(&event).expect("encode");
    let tagged_id = enqueue_input(&vault, tagged, "cmt-tagged", 10);
    let admitted = admit(&vault, 11);
    assert_eq!(admitted.status.attempt.id, tagged_id);
    let deadline = WakePassDeadline::new(180_000);
    let mut ctx = WakeAttemptContext {
        vault: &vault,
        deadline: &deadline,
        budget_id: "wake",
        now_ms: 11_000,
    };
    assert_eq!(
        executor.execute(&admitted, &mut ctx).await.expect("tagged"),
        DreamerAttemptExecution::Completed { completed_units: 0 },
        "a tagged event never reaches the partition decoder"
    );
    assert_eq!(
        plans.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "an unresolvable instance is skipped before the planner is asked"
    );

    // An ordinary payload IS delegated: the failure that surfaces is the
    // inner partition decoder's, which is exactly what delegation means.
    let _ordinary = enqueue_input(&vault, rmpv::Value::from("not-a-partition"), "ord", 12);
    let admitted = admit(&vault, 13);
    assert!(
        executor.execute(&admitted, &mut ctx).await.is_err(),
        "an ordinary payload reaches the inner consolidation executor"
    );
}

/// Installing a planner is FALLIBLE and rejects a non-Agent actor at
/// configuration time, rather than once per pass inside `executor()`.
#[test]
fn planner_builder_rejects_non_agent_actor() {
    let (_dir, vault) = open_vault();
    let system = seed_actor(&vault, 0x5F, oneiron::registry::ENTITY_TYPE_MACHINE);
    let plans = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let error = consolidation_factory(WriteActor::new(system, oneiron::EdgeActorClass::System))
        .with_commitment_wake_planner(Box::new(CountingPlanner { plans }))
        .err()
        .expect("a System actor may not author gated proposals");
    assert!(matches!(error, oneiron::Error::InvalidClaimBody(_)));
}
