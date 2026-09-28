//! Factory, planner-routing, and attempt-fixture tests.
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::tick::PushTick;
use crate::{WaveDispatchRoute, WaveHandoffOutcome, WaveHandoffReceipt};
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
        matches!(
            err,
            oneiron::Error::Artifact(oneiron::error::ArtifactError::InvalidAttemptQueueRecord(_))
        ),
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

#[derive(Clone, Default)]
struct HostMirror {
    events: Arc<std::sync::Mutex<Vec<oneiron::LinearIssueChange>>>,
    remote: Arc<std::sync::Mutex<std::collections::BTreeMap<String, oneiron::MirroredTaskFields>>>,
}

impl oneiron::LinearChangeSource for HostMirror {
    fn changes_since(
        &mut self,
        _cursor: Option<&str>,
    ) -> oneiron::LinearSyncResult<oneiron::LinearChangePage> {
        Ok(oneiron::LinearChangePage {
            changes: std::mem::take(&mut *self.events.lock().expect("source events")),
            next_cursor: None,
        })
    }
}

impl oneiron::LinearEgress for HostMirror {
    fn create_issue(
        &mut self,
        _operation_id: [u8; 32],
        task: oneiron::EntityId,
        fields: &oneiron::MirroredTaskFields,
    ) -> oneiron::LinearSyncResult<oneiron::LinearIssueChange> {
        self.remote
            .lock()
            .expect("remote state")
            .insert(task.to_hex(), fields.clone());
        Ok(oneiron::LinearIssueChange {
            event_id: format!("create-{}", task.to_hex()),
            issue: oneiron::LinearIssueRef {
                issue_id: task.to_hex(),
                team_id: "team".into(),
                identifier: task.to_hex(),
            },
            updated_at_ms: 1000,
            fields: fields.clone(),
        })
    }

    fn update_issue_conditional(
        &mut self,
        _operation_id: [u8; 32],
        issue: &oneiron::LinearIssueRef,
        expected_base: &std::collections::BTreeMap<String, [u8; 32]>,
        fields: &oneiron::MirroredTaskFields,
    ) -> oneiron::LinearSyncResult<oneiron::LinearIssueChange> {
        let mut remote = self.remote.lock().expect("remote state");
        if remote
            .get(&issue.issue_id)
            .map(oneiron::MirroredTaskFields::field_hashes)
            .as_ref()
            != Some(expected_base)
        {
            return Err(oneiron::LinearSyncError::RemoteChanged);
        }
        remote.insert(issue.issue_id.clone(), fields.clone());
        Ok(oneiron::LinearIssueChange {
            event_id: format!("update-{}", issue.issue_id),
            issue: issue.clone(),
            updated_at_ms: 2000,
            fields: fields.clone(),
        })
    }
}

struct HostCutPlanner {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl oneiron::WavePlanner for HostCutPlanner {
    fn cut_plan(
        &self,
        request: oneiron::WavePlanRequest,
    ) -> oneiron::WaveResult<oneiron::WavePlan> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(oneiron::WavePlan {
            schema_version: oneiron::wave_orchestration::WAVE_PLAN_SCHEMA_VERSION,
            plan_ref: "host-cut".into(),
            epic_task_ref: request.epic_task_ref,
            tasks: vec![
                oneiron::PlannedTask {
                    local_key: "first".into(),
                    label: "First".into(),
                    spec: serde_json::json!({"work": 1}),
                    assignee_ref: None,
                    blocked_by: vec![],
                },
                oneiron::PlannedTask {
                    local_key: "second".into(),
                    label: "Second".into(),
                    spec: serde_json::json!({"work": 2}),
                    assignee_ref: None,
                    blocked_by: vec!["first".into()],
                },
            ],
        })
    }
}

#[tokio::test]
async fn running_supervisor_claims_plan_and_dispatches_only_live_ready_tasks() {
    use oneiron::attempt_queue::{AttemptQueue, AttemptState};
    use oneiron::task_verb::{
        TaskAssignee, TaskCreateSpec, TaskResultInput, TaskTerminalDisposition,
    };
    use oneiron::{LinearSyncAdapter, LinearTaskStore};

    let (_dir, vault) = open_vault();
    let actor = seed_actor(&vault, 0x91, oneiron::registry::ENTITY_TYPE_PERSON);
    let epic = vault
        .memory(actor, oneiron::EdgeActorClass::Human)
        .tasks_create(
            &TaskCreateSpec::new(rmpv::Value::from("epic"), None, None, Some(100))
                .with_assignee(TaskAssignee::Peer { actor_ref: actor }),
        )
        .expect("epic")
        .task_ref
        .expect("epic id");
    let queued = vault
        .enqueue_wave_plan(epic, "agent cuts this", serde_json::Value::Null, 100)
        .expect("enqueue");
    let attempt = match queued {
        oneiron::attempt_queue::EnqueueOutcome::Enqueued(row)
        | oneiron::attempt_queue::EnqueueOutcome::Existing(row) => row,
        _ => panic!("unexpected wave enqueue outcome"),
    };
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (sent, mut claimed_tasks) = tokio::sync::mpsc::unbounded_channel();
    let factory = consolidation_factory(WriteActor::new(actor, oneiron::EdgeActorClass::Human))
        .with_wave_planner(
            Arc::new(HostCutPlanner {
                calls: Arc::clone(&calls),
            }),
            Box::new(move |vault, candidate| {
                let WaveDispatchRoute::Attempt { id, generation } = candidate.route else {
                    unreachable!()
                };
                let Some(_row) = vault.claim_wave_dispatch_attempt(
                    candidate.task,
                    id,
                    generation,
                    "executor",
                    u64::MAX,
                )?
                else {
                    return Ok(WaveHandoffOutcome::NoLongerCurrent);
                };
                sent.send(candidate.task).map_err(|_| {
                    oneiron::Error::InvalidConfig("dispatch observer closed".into())
                })?;
                Ok(WaveHandoffOutcome::Accepted(WaveHandoffReceipt::Local {
                    lease_owner: "executor".into(),
                }))
            }),
        );
    let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
    let supervisor = WakeSupervisor::new(&vault, push, factory, test_config());
    let stop = supervisor.shutdown_handle();
    let (report, (first, second)) = tokio::time::timeout(Duration::from_secs(12), async {
        tokio::join!(supervisor.run(), async {
            let first = tokio::time::timeout(Duration::from_secs(5), claimed_tasks.recv())
                .await
                .expect("initial dispatch timeout")
                .expect("initial dispatch");
            assert_ne!(first, epic);
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert_eq!(
                AttemptQueue::new(&vault)
                    .get(attempt.id)
                    .expect("attempt")
                    .unwrap()
                    .state,
                AttemptState::Completed
            );
            // Keep the supervisor alive. A TASK terminal write must wake its
            // durable rescan and hand the dependent to the SAME dispatcher.
            vault
                .memory(actor, oneiron::EdgeActorClass::Human)
                .land_task_result(
                    first,
                    &TaskResultInput {
                        result_ref: actor,
                        disposition: TaskTerminalDisposition::Completed,
                        finished_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .expect("clock")
                            .as_secs()
                            + 1,
                    },
                )
                .expect("complete blocker");
            let second = tokio::time::timeout(Duration::from_secs(5), claimed_tasks.recv())
                .await
                .expect("dependent dispatch timeout")
                .expect("dependent dispatch");
            assert_ne!(second, first);
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "no second plan was needed to wake the dependent"
            );
            stop.shutdown();
            (first, second)
        })
    })
    .await
    .expect("supervisor and dispatch must finish within twelve seconds");
    drop(wake);
    drop(hint);
    assert_eq!(report.passes_completed, 0, "planning is not a Dreamer pass");

    // Same running-host flow crosses the durable TASK outbox and the
    // normalized Linear source: a wave TASK pushes, then a later poll applies.
    let mirror = HostMirror::default();
    let mut sync = LinearSyncAdapter::new(
        oneiron::linear_sync::VaultLinearTaskStore::new(&vault),
        mirror.clone(),
        mirror.clone(),
    );
    let (pushed, _) = sync.synchronize(200, 64).expect("wave TASKs push");
    assert!(pushed.iter().any(|receipt| receipt.task_ref == first));
    assert!(pushed.iter().any(|receipt| receipt.task_ref == second));
    let link = sync
        .tasks()
        .link(second)
        .expect("link read")
        .expect("linked issue");
    let mut from_tracker = sync.tasks().task_snapshot(second).expect("snapshot").fields;
    from_tracker.description = Some("tracker handoff".into());
    mirror
        .events
        .lock()
        .expect("source events")
        .push(oneiron::LinearIssueChange {
            event_id: "inbound-wave-edit".into(),
            issue: link.issue,
            updated_at_ms: 3000,
            fields: from_tracker.clone(),
        });
    let (_, pulled) = sync.synchronize(201, 64).expect("scheduled source poll");
    assert_eq!(pulled.applied, 1);
    assert_eq!(
        sync.tasks()
            .task_snapshot(second)
            .expect("after poll")
            .fields
            .description,
        from_tracker.description
    );
}

#[tokio::test]
async fn supervisor_recovers_committed_wave_and_retries_failed_handoff() {
    use oneiron::task_verb::{
        TaskAssignee, TaskCreateSpec, TaskResultInput, TaskTerminalDisposition,
    };

    let (_dir, vault) = open_vault();
    let actor = seed_actor(&vault, 0x92, oneiron::registry::ENTITY_TYPE_PERSON);
    let epic = vault
        .memory(actor, oneiron::EdgeActorClass::Human)
        .tasks_create(
            &TaskCreateSpec::new(rmpv::Value::from("epic"), None, None, Some(100))
                .with_assignee(TaskAssignee::Peer { actor_ref: actor }),
        )
        .expect("epic")
        .task_ref
        .expect("epic id");
    vault
        .enqueue_wave_plan(epic, "recover on startup", serde_json::Value::Null, 100)
        .expect("enqueue");
    let plans = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // This returns AFTER the cut and planning attempt committed. The new
    // supervisor must find the TASKs without any pending wave.plan attempt.
    let landed = crate::WaveHost::new(
        &vault,
        HostCutPlanner {
            calls: Arc::clone(&plans),
        },
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .run_plan_once("pre-crash", 100)
    .expect("plan")
    .expect("cut");
    let first = landed.task_refs["first"];
    let second = landed.task_refs["second"];
    let handoffs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let attempts = Arc::clone(&handoffs);
    let (sent, mut delivered) = tokio::sync::mpsc::unbounded_channel();
    let factory = consolidation_factory(WriteActor::new(actor, oneiron::EdgeActorClass::Human))
        .with_wave_planner(
            Arc::new(HostCutPlanner {
                calls: Arc::clone(&plans),
            }),
            Box::new(move |vault, candidate| {
                if attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    return Err(oneiron::Error::InvalidConfig(
                        "one transient handoff failure".into(),
                    ));
                }
                let WaveDispatchRoute::Attempt { id, generation } = candidate.route else {
                    unreachable!()
                };
                let Some(_row) = vault.claim_wave_dispatch_attempt(
                    candidate.task,
                    id,
                    generation,
                    "executor",
                    u64::MAX,
                )?
                else {
                    return Ok(WaveHandoffOutcome::NoLongerCurrent);
                };
                sent.send(candidate.task)
                    .map_err(|_| oneiron::Error::InvalidConfig("observer closed".into()))?;
                Ok(WaveHandoffOutcome::Accepted(WaveHandoffReceipt::Local {
                    lease_owner: "executor".into(),
                }))
            }),
        );
    let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
    let mut config = test_config();
    config.backoff = RestartBackoffConfig {
        initial: Duration::from_millis(10),
        max: Duration::from_millis(10),
    };
    let supervisor = WakeSupervisor::new(&vault, push, factory, config);
    let stop = supervisor.shutdown_handle();
    let (report, ()) = tokio::time::timeout(Duration::from_secs(12), async {
        tokio::join!(supervisor.run(), async {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), delivered.recv())
                    .await
                    .expect("failed callback retry timeout")
                    .expect("first delivery"),
                first
            );
            assert_eq!(
                plans.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "restart must not replan a completed cut"
            );
            vault
                .memory(actor, oneiron::EdgeActorClass::Human)
                .land_task_result(
                    first,
                    &TaskResultInput {
                        result_ref: actor,
                        disposition: TaskTerminalDisposition::Completed,
                        finished_at: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .expect("clock")
                            .as_secs()
                            + 1,
                    },
                )
                .expect("complete blocker");
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), delivered.recv())
                    .await
                    .expect("dependent delivery timeout")
                    .expect("dependent"),
                second
            );
            stop.shutdown();
        })
    })
    .await
    .expect("supervisor and dispatch must finish within twelve seconds");
    drop(wake);
    drop(hint);
    assert_eq!(report.passes_completed, 0);
    assert!(
        handoffs.load(std::sync::atomic::Ordering::SeqCst) >= 3,
        "failed first handoff, retry, and newly ready dependent"
    );
}

#[tokio::test]
async fn successful_wave_handoff_reopens_on_retry_and_reclaimed_lease() {
    use oneiron::attempt_queue::{AttemptQueue, CleanupAttemptLeases, RetryAttempt, RetryOutcome};
    use oneiron::task_verb::{TaskAssignee, TaskCreateSpec};

    let (_dir, vault) = open_vault();
    let actor = seed_actor(&vault, 0x93, oneiron::registry::ENTITY_TYPE_PERSON);
    let epic = vault
        .memory(actor, oneiron::EdgeActorClass::Human)
        .tasks_create(
            &TaskCreateSpec::new(rmpv::Value::from("epic"), None, None, Some(100))
                .with_assignee(TaskAssignee::Peer { actor_ref: actor }),
        )
        .expect("epic")
        .task_ref
        .expect("epic id");
    vault
        .enqueue_wave_plan(epic, "retry work", serde_json::Value::Null, 100)
        .expect("plan");
    let (sent, mut claims) = tokio::sync::mpsc::unbounded_channel();
    let factory = consolidation_factory(WriteActor::new(actor, oneiron::EdgeActorClass::Human))
        .with_wave_planner(
            Arc::new(HostCutPlanner {
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }),
            Box::new(move |vault, candidate| {
                let WaveDispatchRoute::Attempt { id, generation } = candidate.route else {
                    unreachable!()
                };
                let Some(row) = vault.claim_wave_dispatch_attempt(
                    candidate.task,
                    id,
                    generation,
                    "executor",
                    u64::MAX,
                )?
                else {
                    return Ok(WaveHandoffOutcome::NoLongerCurrent);
                };
                sent.send(row)
                    .map_err(|_| oneiron::Error::InvalidConfig("observer closed".into()))?;
                Ok(WaveHandoffOutcome::Accepted(WaveHandoffReceipt::Local {
                    lease_owner: "executor".into(),
                }))
            }),
        );
    let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
    let supervisor = WakeSupervisor::new(&vault, push, factory, test_config());
    let stop = supervisor.shutdown_handle();
    let (report, ()) = tokio::time::timeout(Duration::from_secs(12), async {
        tokio::join!(supervisor.run(), async {
            let first = tokio::time::timeout(Duration::from_secs(5), claims.recv())
                .await
                .expect("initial handoff timeout")
                .expect("initial claim");
            let queue = AttemptQueue::new(&vault);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_secs();
            let RetryOutcome::Retried(successor) = queue
                .retry(RetryAttempt {
                    id: first.id,
                    lease_owner: "executor".into(),
                    attempt_count: first.attempt_count,
                    now,
                    backoff_until: now + 1,
                    last_error: Some("retry".into()),
                })
                .expect("schedule retry")
            else {
                panic!("retry outcome");
            };
            let second = tokio::time::timeout(Duration::from_secs(5), claims.recv())
                .await
                .expect("scheduled retry handoff timeout")
                .expect("retry claim");
            assert_eq!(second.id, successor.id);
            assert_eq!(second.task_ref, first.task_ref);
            assert_eq!(second.retry_of, Some(first.id));
            assert!(
                claims.try_recv().is_err(),
                "claim notification cannot re-dispatch a leased attempt"
            );
            queue
                .cleanup_leases(CleanupAttemptLeases {
                    now: u64::MAX,
                    lease_timeout_secs: 1,
                })
                .expect("reclaim expired lease");
            let third = tokio::time::timeout(Duration::from_secs(5), claims.recv())
                .await
                .expect("reclaimed lease handoff timeout")
                .expect("reclaimed claim");
            assert_eq!(third.id, second.id, "reclaim reuses the same row");
            assert!(
                third.attempt_count > second.attempt_count,
                "reclaim raises the lease generation"
            );
            assert_eq!(third.task_ref, first.task_ref);
            stop.shutdown();
        })
    })
    .await
    .expect("supervisor and dispatch must finish within twelve seconds");
    drop(wake);
    drop(hint);
    assert_eq!(report.passes_completed, 0);
}

struct IndependentWavePlanner {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl oneiron::WavePlanner for IndependentWavePlanner {
    fn cut_plan(
        &self,
        request: oneiron::WavePlanRequest,
    ) -> oneiron::WaveResult<oneiron::WavePlan> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(oneiron::WavePlan {
            schema_version: oneiron::wave_orchestration::WAVE_PLAN_SCHEMA_VERSION,
            plan_ref: format!("independent-{}", request.epic_task_ref.to_hex()),
            epic_task_ref: request.epic_task_ref,
            tasks: ["a", "b"]
                .into_iter()
                .map(|key| oneiron::PlannedTask {
                    local_key: key.into(),
                    label: key.into(),
                    spec: serde_json::json!({"work": key}),
                    assignee_ref: None,
                    blocked_by: vec![],
                })
                .collect(),
        })
    }
}

#[tokio::test]
async fn rejected_wave_item_does_not_block_sibling_tick_or_new_plan() {
    use oneiron::task_verb::{TaskAssignee, TaskCreateSpec};
    let (_dir, vault) = open_vault();
    let actor = seed_actor(&vault, 0x24, oneiron::registry::ENTITY_TYPE_PERSON);
    let epic = |label: &str| {
        vault
            .memory(actor, oneiron::EdgeActorClass::Human)
            .tasks_create(
                &TaskCreateSpec::new(rmpv::Value::from(label), None, None, Some(100))
                    .with_assignee(TaskAssignee::Peer { actor_ref: actor }),
            )
            .expect("epic")
            .task_ref
            .expect("epic id")
    };
    vault
        .enqueue_wave_plan(epic("first epic"), "first", serde_json::Value::Null, 100)
        .expect("first plan");
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let rejected = Arc::new(std::sync::Mutex::new(None));
    let rejection = Arc::clone(&rejected);
    let refusals = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let refused = Arc::clone(&refusals);
    let (sent, mut accepted) = tokio::sync::mpsc::unbounded_channel();
    let factory = consolidation_factory(WriteActor::new(actor, oneiron::EdgeActorClass::Human))
        .with_wave_planner(
            Arc::new(IndependentWavePlanner {
                calls: Arc::clone(&calls),
            }),
            Box::new(move |vault, candidate| {
                let first = *rejection
                    .lock()
                    .expect("rejected lock")
                    .get_or_insert(candidate.task);
                if candidate.task == first {
                    // A refuses forever: once by deferral, then by host error.
                    if refused.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                        return Ok(WaveHandoffOutcome::Deferred);
                    }
                    return Err(oneiron::Error::InvalidConfig("executor refused A".into()));
                }
                let WaveDispatchRoute::Attempt { id, generation } = candidate.route else {
                    unreachable!()
                };
                let Some(row) = vault.claim_wave_dispatch_attempt(
                    candidate.task,
                    id,
                    generation,
                    "executor",
                    u64::MAX,
                )?
                else {
                    return Ok(WaveHandoffOutcome::NoLongerCurrent);
                };
                assert_eq!(row.id, id, "only this candidate can be leased");
                assert_eq!(
                    row.task_ref.as_deref(),
                    Some(candidate.task.to_hex().as_str())
                );
                sent.send(candidate.task).expect("observer");
                Ok(WaveHandoffOutcome::Accepted(WaveHandoffReceipt::Local {
                    lease_owner: "executor".into(),
                }))
            }),
        );
    let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
    let mut config = test_config();
    config.backoff = RestartBackoffConfig {
        initial: Duration::from_millis(10),
        max: Duration::from_millis(10),
    };
    let supervisor = WakeSupervisor::new(&vault, push, factory, config).with_wave_dispatch_limits(
        crate::WaveDispatchLimits {
            page_size: 1,
            retry_quantum: 1,
            retry_initial: Duration::from_millis(500),
            retry_max: Duration::from_secs(60),
        },
    );
    let stop = supervisor.shutdown_handle();
    let (report, ()) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(supervisor.run(), async {
            let sibling = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
                .await
                .expect("B did not pass A")
                .expect("B delivery");
            assert_ne!(Some(sibling), *rejected.lock().expect("rejected lock"));
            wake.push_wake(
                oneiron::WakeTrigger::Compaction,
                oneiron::DreamerConsolidationScope::Micro,
            )
            .expect("ordinary wake");
            vault
                .enqueue_wave_plan(epic("second epic"), "second", serde_json::Value::Null, 100)
                .expect("new plan");
            let next = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
                .await
                .expect("new plan blocked by A")
                .expect("new delivery");
            assert_ne!(next, sibling);
            // A stays retryable after the scan moved past it, and each retry
            // keeps failing without pinning the arbiter.
            tokio::time::timeout(Duration::from_secs(6), async {
                while refusals.load(std::sync::atomic::Ordering::SeqCst) < 3 {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("A retried after its host errors");
            stop.shutdown();
        })
    })
    .await
    .expect("wave breaker closed");
    drop(wake);
    drop(hint);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert!(
        report.passes_completed >= 1,
        "ordinary wake must run amid deferred wave item"
    );
}

#[tokio::test]
async fn wave_scan_reaches_later_pages_despite_notifications() {
    use oneiron::task_verb::{TaskAssignee, TaskCreateSpec};
    let (_dir, vault) = open_vault();
    let actor = seed_actor(&vault, 0x26, oneiron::registry::ENTITY_TYPE_PERSON);
    let memory = vault.memory(actor, oneiron::EdgeActorClass::Human);
    for i in 0..260 {
        memory
            .tasks_create(
                &TaskCreateSpec::new(
                    rmpv::Value::from(format!("nonwave-{i}")),
                    None,
                    None,
                    Some(100),
                )
                .with_assignee(TaskAssignee::Peer { actor_ref: actor }),
            )
            .expect("non-wave TASK");
    }
    let epic = memory
        .tasks_create(
            &TaskCreateSpec::new(rmpv::Value::from("epic"), None, None, Some(100))
                .with_assignee(TaskAssignee::Peer { actor_ref: actor }),
        )
        .expect("epic")
        .task_ref
        .expect("epic ref");
    vault
        .enqueue_wave_plan(epic, "later page", serde_json::Value::Null, 100)
        .expect("queue plan");
    let (sent, mut received) = tokio::sync::mpsc::unbounded_channel();
    let factory = consolidation_factory(WriteActor::new(actor, oneiron::EdgeActorClass::Human))
        .with_wave_planner(
            Arc::new(IndependentWavePlanner {
                calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }),
            Box::new(move |vault, candidate| {
                let WaveDispatchRoute::Attempt { id, generation } = candidate.route else {
                    unreachable!()
                };
                let Some(_row) = vault.claim_wave_dispatch_attempt(
                    candidate.task,
                    id,
                    generation,
                    "executor",
                    u64::MAX,
                )?
                else {
                    return Ok(WaveHandoffOutcome::NoLongerCurrent);
                };
                // Claim notifications land while the raw cursor is active; both
                // work items must still reach the host, beyond page one.
                sent.send(candidate.task).expect("observer");
                Ok(WaveHandoffOutcome::Accepted(WaveHandoffReceipt::Local {
                    lease_owner: "executor".into(),
                }))
            }),
        );
    let (push, wake, hint) = PushTick::channel(crate::DEFAULT_SESSION_IDLE_FLOOR_SECS * 1_000);
    let supervisor = WakeSupervisor::new(&vault, push, factory, test_config())
        .with_wave_dispatch_limits(crate::WaveDispatchLimits {
            page_size: 256,
            retry_quantum: 1,
            retry_initial: Duration::from_millis(500),
            retry_max: Duration::from_secs(60),
        });
    let stop = supervisor.shutdown_handle();
    let (report, ()) = tokio::time::timeout(Duration::from_secs(12), async {
        tokio::join!(supervisor.run(), async {
            let first = tokio::time::timeout(Duration::from_secs(8), received.recv())
                .await
                .expect("later page timed out")
                .expect("first");
            let second = tokio::time::timeout(Duration::from_secs(8), received.recv())
                .await
                .expect("claim notification stranded later page")
                .expect("second");
            assert_ne!(first, second);
            stop.shutdown();
        })
    })
    .await
    .expect("later page pump timeout");
    drop(wake);
    drop(hint);
    assert_eq!(report.passes_completed, 0);
}

#[test]
fn wave_point_claim_never_claims_neighbor_or_stale_generation() {
    use oneiron::task_verb::{TaskAssignee, TaskCreateSpec, WaveDispatchGeneration};
    let (_dir, vault) = open_vault();
    let actor = seed_actor(&vault, 0x25, oneiron::registry::ENTITY_TYPE_PERSON);
    let epic = vault
        .memory(actor, oneiron::EdgeActorClass::Human)
        .tasks_create(
            &TaskCreateSpec::new(rmpv::Value::from("epic"), None, None, Some(100))
                .with_assignee(TaskAssignee::Peer { actor_ref: actor }),
        )
        .expect("epic")
        .task_ref
        .expect("epic id");
    vault
        .enqueue_wave_plan(epic, "claim", serde_json::Value::Null, 100)
        .expect("plan");
    let result = crate::WaveHost::new(
        &vault,
        IndependentWavePlanner {
            calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        },
        actor,
        oneiron::EdgeActorClass::Human,
    )
    .run_plan_once("planner", 100)
    .expect("run")
    .expect("receipt");
    let a = result.task_refs["a"];
    let b = result.task_refs["b"];
    let Some(WaveDispatchGeneration::Attempt { id, generation }) =
        vault.wave_dispatch_generation(a, 101).expect("generation")
    else {
        panic!("local A route")
    };
    assert!(
        vault
            .claim_wave_dispatch_attempt(b, id, generation, "worker", u64::MAX)
            .expect("wrong task")
            .is_none()
    );
    assert!(
        vault
            .claim_wave_dispatch_attempt(a, id, generation + 1, "worker", u64::MAX)
            .expect("stale generation")
            .is_none()
    );
    let claim = vault
        .claim_wave_dispatch_attempt(a, id, generation, "worker", u64::MAX)
        .expect("point claim")
        .expect("claimed");
    assert_eq!(claim.id, id);
    assert_eq!(claim.task_ref.as_deref(), Some(a.to_hex().as_str()));
    assert!(matches!(
        vault
            .wave_dispatch_generation(b, 101)
            .expect("B still queued"),
        Some(WaveDispatchGeneration::Attempt { .. })
    ));
}

#[test]
fn mirror_pushes_working_state_before_task_settles() {
    use oneiron::task_verb::{TaskAssignee, TaskCreateSpec};
    use oneiron::{LinearMirrorStatus, LinearSyncAdapter, LinearTaskStore};

    let (_dir, vault) = open_vault();
    let actor = seed_actor(&vault, 0x94, oneiron::registry::ENTITY_TYPE_PERSON);
    let task = vault
        .memory(actor, oneiron::EdgeActorClass::Human)
        .tasks_create(
            &TaskCreateSpec::new(
                rmpv::Value::from("work"),
                Some("Work".into()),
                None,
                Some(100),
            )
            .with_assignee(TaskAssignee::Peer { actor_ref: actor }),
        )
        .expect("task")
        .task_ref
        .expect("task id");
    let mirror = HostMirror::default();
    let mut adapter = LinearSyncAdapter::new(
        oneiron::linear_sync::VaultLinearTaskStore::new(&vault),
        mirror.clone(),
        mirror.clone(),
    );
    adapter.synchronize(100, 64).expect("initial queued mirror");
    assert_eq!(
        mirror.remote.lock().expect("remote")[&task.to_hex()].status,
        "queued"
    );
    vault
        .memory(actor, oneiron::EdgeActorClass::Human)
        .mark_task_started(task, 101)
        .expect("start work");
    assert_eq!(
        adapter
            .tasks()
            .task_snapshot(task)
            .expect("working snapshot")
            .fields
            .status,
        "working"
    );
    let (pushed, _) = adapter
        .synchronize(102, 64)
        .expect("publish working status");
    assert_eq!(pushed.len(), 1);
    assert_eq!(pushed[0].status, LinearMirrorStatus::Applied);
    assert_eq!(
        mirror.remote.lock().expect("remote")[&task.to_hex()].status,
        "working"
    );
    assert!(adapter.tasks().dirty_tasks().expect("outbox").is_empty());
}

#[test]
fn mirror_resolves_original_title_under_remote_cas_with_and_without_later_event() {
    use oneiron::task_verb::{TaskAssignee, TaskCreateSpec};
    use oneiron::{LinearMirrorStatus, LinearSyncAdapter, LinearTaskStore};
    for unrelated in [false, true] {
        let (_dir, vault) = open_vault();
        let actor = seed_actor(
            &vault,
            if unrelated { 0x96 } else { 0x95 },
            oneiron::registry::ENTITY_TYPE_PERSON,
        );
        let task = vault
            .memory(actor, oneiron::EdgeActorClass::Human)
            .tasks_create(
                &TaskCreateSpec::new(
                    rmpv::Value::from("work"),
                    Some("Base".into()),
                    None,
                    Some(100),
                )
                .with_assignee(TaskAssignee::Peer { actor_ref: actor }),
            )
            .expect("task")
            .task_ref
            .expect("task id");
        let mirror = HostMirror::default();
        let mut adapter = LinearSyncAdapter::new(
            oneiron::linear_sync::VaultLinearTaskStore::new(&vault),
            mirror.clone(),
            mirror.clone(),
        );
        adapter.synchronize(100, 64).expect("initial Base link");
        let link = adapter.tasks().link(task).expect("link").expect("linked");
        let mut local = adapter
            .tasks()
            .task_snapshot(task)
            .expect("snapshot")
            .fields;
        local.title = "Engine".into();
        let old_revision = adapter
            .tasks()
            .task_snapshot(task)
            .expect("revision")
            .revision;
        adapter
            .tasks_mut()
            .apply_issue_fields(task, old_revision, &local, 101)
            .expect("local edit");
        let mut tracker = local.clone();
        tracker.title = "Tracker".into();
        mirror
            .remote
            .lock()
            .expect("remote")
            .insert(task.to_hex(), tracker.clone());
        mirror
            .events
            .lock()
            .expect("events")
            .push(oneiron::LinearIssueChange {
                event_id: "conflict".into(),
                issue: link.issue.clone(),
                updated_at_ms: 1500,
                fields: tracker.clone(),
            });
        let (push, pull) = adapter.synchronize(102, 64).expect("surface conflict");
        assert_eq!(push[0].status, LinearMirrorStatus::Conflict);
        assert_eq!(pull.conflicts.len(), 1);
        let mut original = adapter
            .tasks()
            .task_snapshot(task)
            .expect("conflicted")
            .fields;
        original.title = "Base".into();
        let current = adapter
            .tasks()
            .task_snapshot(task)
            .expect("revision")
            .revision;
        adapter
            .tasks_mut()
            .apply_issue_fields(task, current, &original, 103)
            .expect("restore original title");
        if unrelated {
            tracker.status = "in_review".into();
            mirror
                .remote
                .lock()
                .expect("remote")
                .insert(task.to_hex(), tracker.clone());
            mirror
                .events
                .lock()
                .expect("events")
                .push(oneiron::LinearIssueChange {
                    event_id: "unrelated-status".into(),
                    issue: link.issue,
                    updated_at_ms: 1600,
                    fields: tracker,
                });
        }
        let (pushed, _) = adapter
            .synchronize(104, 64)
            .expect("conditional resolution");
        assert_eq!(pushed.len(), 1);
        assert_eq!(pushed[0].status, LinearMirrorStatus::Applied);
        assert_eq!(
            mirror.remote.lock().expect("remote")[&task.to_hex()].title,
            "Base"
        );
        assert_eq!(
            adapter
                .tasks()
                .task_snapshot(task)
                .expect("local resolution")
                .fields
                .title,
            "Base"
        );
        assert!(
            adapter
                .tasks()
                .link(task)
                .expect("settled link")
                .expect("link")
                .unresolved_conflicts
                .is_empty()
        );
        assert!(adapter.tasks().dirty_tasks().expect("outbox").is_empty());
    }
}
