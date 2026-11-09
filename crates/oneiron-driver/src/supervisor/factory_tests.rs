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

#[tokio::test(start_paused = true)]
async fn setup_panic_before_admission_redrives_push_tick() {
    // P2 (codex r6 / 3585850170): factory panic before admission on a
    // PushTick-only supervisor. Single wake, panics once → redrive after
    // backoff completes the attempt (no second push).
    let (_dir, vault) = open_vault();
    let attempt = enqueue_micro(&vault, "factory-panic-redrive", 10);

    let (push, wake, hint) = PushTick::channel(crate::TEST_SESSION_IDLE_FLOOR_SECS * 1_000);
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

    let (push, wake, hint) = PushTick::channel(crate::TEST_SESSION_IDLE_FLOOR_SECS * 1_000);
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
        oneiron::llm::HostInferenceBinding::Advertised {
            model: oneiron::ModelId::new("test/model@v1").expect("host model"),
            locality: oneiron::ModelLocality::OwnServer,
            keyless: false,
        },
        Some(Arc::new(|_: &oneiron::LlmRequest| true)),
        Box::new(UnusedSink),
    )
}

/// Installing a planner is FALLIBLE and rejects a non-Agent actor at
/// configuration time, rather than once per pass inside `executor()`.
#[test]
fn planner_builder_accepts_system_actor_but_refuses_human() {
    let (_dir, vault) = open_vault();
    let plans = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    assert!(
        consolidation_factory(vault.dreamer_authority().expect("Dreamer"))
            .with_commitment_wake_planner(Box::new(CountingPlanner {
                plans: Arc::clone(&plans)
            }))
            .is_ok()
    );
    let human = seed_actor(&vault, 0x5F, oneiron::registry::ENTITY_TYPE_PERSON);
    let error = consolidation_factory(WriteActor::new(human, oneiron::EdgeActorClass::Human))
        .with_commitment_wake_planner(Box::new(CountingPlanner { plans }))
        .err()
        .expect("a Human actor may not author Dreamer proposals");
    assert!(matches!(error, oneiron::Error::InvalidClaimBody(_)));
}

#[tokio::test]
async fn production_factory_system_dreamer_plans_live_commitment() -> Result<()> {
    use oneiron::commitment::{
        CommitmentBirthKind, CommitmentBirthProvenance, CommitmentContent, CommitmentObligor,
        CommitmentObligorKind, CommitmentRecord, CommitmentStatus, CommitmentStrength,
    };
    use oneiron::commitment_schedule::{CommitmentSchedulePayload, Schedule};
    use oneiron::write_envelope::WriteProvenance;
    use oneiron::{
        ClaimApprovalStatus, ClaimSource, CommitmentWakeDue, CommitmentWakeFireOutcome,
        EdgeActorClass, EntityId, TimeRange, WriteEnvelope,
    };
    let (_dir, vault) = open_vault();
    let owner = EntityId::from_bytes([0x61; 16])?;
    let beneficiary = EntityId::from_bytes([0x62; 16])?;
    let series = EntityId::from_bytes([0x63; 16])?;
    let at = TimeRange { start: 1, end: 1 };
    for id in [owner, beneficiary] {
        vault.put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            at,
            1,
            b"fixture person",
        )?;
    }
    let projector = oneiron::commitment_schedule::commitment_projection_actor()?;
    vault.put_entity(
        &projector.entity_ref(),
        oneiron::registry::ENTITY_TYPE_MACHINE,
        at,
        1,
        b"commitment projector",
    )?;
    let record = CommitmentRecord::new(
        CommitmentObligor::new(CommitmentObligorKind::Owner, owner),
        beneficiary,
        CommitmentContent::new("ring the beneficiary", None)?,
        CommitmentSchedulePayload::series(Schedule::Once { due: 1_000 }, Some(100)).encode()?,
        CommitmentStrength::Commitment,
        CommitmentStatus::Open,
        CommitmentBirthProvenance::new(CommitmentBirthKind::RunTreeNode, "run:factory")?,
    )?;
    let envelope = WriteEnvelope::new(
        WriteActor::new(owner, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(rmpv::Value::from("factory fixture"))?,
        ClaimApprovalStatus::Auto,
    );
    vault.put_commitment_series(
        &series,
        &record,
        &envelope,
        TimeRange {
            start: 1,
            end: 11_000,
        },
        1,
    )?;
    vault.reconcile_commitment_schedule(900)?;
    let due = CommitmentWakeDue::from_due_entry(
        &vault
            .next_actionable_wake_phase()?
            .expect("projected lead phase"),
    )?
    .expect("actionable phase");
    assert!(matches!(
        oneiron::fire_due_commitment_wake(&vault, due, 900)?,
        CommitmentWakeFireOutcome::Enqueued { .. }
    ));
    let admitted = admit(&vault, 901);
    let plans = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let actor = vault.dreamer_authority()?;
    let mut factory =
        consolidation_factory(actor).with_commitment_wake_planner(Box::new(CountingPlanner {
            plans: Arc::clone(&plans),
        }))?;
    let guard = BudgetGuard::new("wake", 10_000, BudgetExhaustionPolicy::Suspend);
    let mut executor = factory.executor(&guard)?;
    let deadline = WakePassDeadline::new(180_000);
    let mut ctx = WakeAttemptContext {
        vault: &vault,
        deadline: &deadline,
        cancel: None,
        device_cancel: None,
        budget_id: "wake",
        now_ms: 901_000,
        prepared_wake: None,
        prepared_attempt: None,
        spend_meter: None,
    };
    assert!(matches!(
        executor.execute(&admitted, &mut ctx).await?,
        DreamerAttemptExecution::Completed {
            completed_units: 0,
            ..
        }
    ));
    assert_eq!(plans.load(std::sync::atomic::Ordering::SeqCst), 1);
    let proposal = oneiron::commitment_wake_proposal_claim_id(admitted.status.attempt.id);
    let body = vault
        .get_claim(&proposal)?
        .expect("the planner wrote a proposal");
    assert_eq!(body.approval, ClaimApprovalStatus::Proposed);
    let rmpv::Value::Map(entries) = body.evidence.expect("stamped evidence") else {
        panic!("evidence map");
    };
    assert!(
        entries
            .iter()
            .any(|(key, value)| key.as_str() == Some("actor_class")
                && value.as_u64() == Some(u64::from(EdgeActorClass::System as u8)))
    );
    Ok(())
}

struct TestWeaveRuntime;
impl oneiron::dreamer_wake::WeaveRecipeRuntime for TestWeaveRuntime {
    fn executor(&self) -> Result<&str> {
        Ok("test-weave-runtime@1")
    }
    fn draft(
        &mut self,
        markdown: &str,
        evidence: &[u8],
    ) -> Result<oneiron::dreamer_wake::WeaveRecipeDraft> {
        let predicate = markdown
            .lines()
            .find_map(|line| line.strip_prefix("PREDICATE: "))
            .ok_or(oneiron::Error::InvalidClaimBody("no recipe predicate"))?;
        Ok(oneiron::dreamer_wake::WeaveRecipeDraft {
            predicate: predicate.into(),
            value: rmpv::decode::read_value(&mut &evidence[..])
                .map_err(|_| oneiron::Error::InvalidClaimBody("invalid TURN"))?
                .as_map()
                .and_then(|fields| {
                    fields.iter().find_map(|(key, value)| {
                        (key.as_str() == Some("txt"))
                            .then(|| value.as_str())
                            .flatten()
                    })
                })
                .ok_or(oneiron::Error::InvalidClaimBody("TURN text missing"))?
                .into(),
            confidence: 0.8,
        })
    }
}

#[tokio::test]
async fn production_factory_executes_owner_admitted_agent_authored_recipe() -> Result<()> {
    use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
    use oneiron::dreamer_wake::{
        DreamerWakeDriver, RunWakePass, WakeCancellation, WakePassDeadline, WakeTrigger,
    };
    use oneiron::skill::{SkillGovernanceTier, SkillLifecycle, SkillRecord};
    use oneiron::skill_hub::HubFile;
    use oneiron::store::GateDecisionId;
    use oneiron::{EdgeActorClass, EntityId, TimeRange};

    let (_dir, vault) = open_vault();
    let agent = EntityId::from_bytes([0x64; 16])?;
    let owner = vault.ensure_embedded_owner_actor().expect("vault owner");
    let subject = EntityId::from_bytes([0x66; 16])?;
    let evidence = EntityId::from_bytes([0x67; 16])?;
    for (id, body) in [
        (agent, b"agent".as_slice()),
        (owner, b"owner".as_slice()),
        (subject, b"subject".as_slice()),
    ] {
        vault.put_entity(
            &id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            body,
        )?;
    }
    let mut turn = Vec::new();
    rmpv::encode::write_value(
        &mut turn,
        &rmpv::Value::Map(vec![
            ("txt".into(), "evidence".into()),
            ("spkr".into(), "user".into()),
        ]),
    )
    .map_err(|_| oneiron::Error::InvalidClaimBody("TURN fixture encode"))?;
    vault.put_entity(
        &evidence,
        oneiron::registry::ENTITY_TYPE_TURN,
        TimeRange { start: 1, end: 1 },
        1,
        &turn,
    )?;
    vault.install_read_permit_for_test(vault.dreamer_authority()?)?;
    let skill = EntityId::from_bytes([0x68; 16])?;
    let proposed = SkillRecord::new(
        "weave.recipe",
        "host-supplied per-vault workflow",
        "v1",
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        Vec::new(),
        rmpv::Value::Map(vec![("ask".into(), "weave the evidence".into())]),
    )
    .with_governance_tier(SkillGovernanceTier::Standard);
    vault
        .memory(agent, EdgeActorClass::Agent)
        .skill_save_with_source(
            skill,
            &proposed,
            vec![HubFile::new(
                "SKILL.md",
                b"---\nname: weave.recipe\n---\nPREDICATE: profile.weave_note\n",
            )],
            None,
            2,
        )
        .expect("agent authors the candidate with source custody");
    let owner = vault.authenticate_owner(
        owner,
        "principal:factory-recipe",
        true,
        GateDecisionId::now(),
    )?;
    let status = vault.admit_and_enqueue_weave_recipe(&owner, skill, subject, evidence, 3)?;
    let (oneiron::dreamer_runner::EnqueueDreamerAttemptOutcome::Enqueued(status)
    | oneiron::dreamer_runner::EnqueueDreamerAttemptOutcome::Existing(status)) = status
    else {
        panic!("unexpected recipe enqueue outcome")
    };
    let factory = consolidation_factory(vault.dreamer_authority()?)
        .with_weave_recipe_runtime(Box::new(TestWeaveRuntime));
    let mut factory = factory;
    let guard = BudgetGuard::new("weave", 10_000, BudgetExhaustionPolicy::Suspend);
    let mut exec = factory.executor(&guard)?;
    let mut driver = DreamerWakeDriver::new(&vault, "weave", WakePassDeadline::new(180_000));
    let report = driver
        .run_wake_pass(
            RunWakePass {
                trigger: WakeTrigger::Event,
                scope: DreamerConsolidationScope::Micro,
                local_node_id: 1,
                lease_owner: "factory".into(),
                budget_total_units: 10_000,
                reserve_units: 100,
                now: 4,
                host_scope: None,
                destination_bound: None,
            },
            &mut exec,
            &WakeCancellation::new(),
        )
        .await?;
    assert_eq!(report.completed, 1);
    assert_eq!(
        DreamerRunnerStore::new(&vault)
            .status(status.attempt.id)?
            .unwrap()
            .attempt
            .state,
        AttemptState::Completed
    );
    let claim = vault
        .claims_for_subject(&subject)?
        .into_iter()
        .find(|id| {
            vault
                .get_claim(id)
                .ok()
                .flatten()
                .is_some_and(|body| body.predicate == "profile.weave_note")
        })
        .expect("host interpreter's output must pass the engine Gate");
    let receipt = vault.receipts(
        oneiron::receipt::ReceiptQuery::new(100).with_kind(oneiron::receipt::ReceiptKind::Gate),
    )?;
    let actor_hex = vault.dreamer_authority()?.entity_ref().to_hex();
    assert!(
        receipt
            .iter()
            .any(|row| row.actor.as_deref() == Some(actor_hex.as_str())
                && row.fields.get("predicate").map(String::as_str) == Some("profile.weave_note"))
    );
    assert_eq!(
        vault.get_claim(&claim)?.unwrap().value.as_str(),
        Some("evidence")
    );
    Ok(())
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

