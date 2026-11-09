//! Factory, planner-routing, and attempt-fixture tests.
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::tick::PushTick;
use oneiron::attempt_queue::AttemptState;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, DREAMER_EXECUTOR_ERROR_PARK_REASON,
    DreamerAttemptExecution, DreamerAttemptExecutor, DreamerClaimAuthoringStrategy,
    DreamerConsolidationScope, DreamerRunnerStore, Result, WakeAttemptContext, WakePassDeadline,
    WakeTrigger, WriteActor,
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
