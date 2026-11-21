#![cfg(oneiron_test_support)]

//! The owner's Stop of a held turn program settles the ended try's budget
//! and retires its paid-step receipts through the real program release door.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use oneiron::attempt_queue::AttemptId;
use oneiron::dreamer_runner::{
    ArmTurnProgram, DreamerParkedAttemptRecord, ProgramHoldReleaseAction, ProgramTrigger,
    ReleaseTurnProgramHoldRequest, ReserveDreamerBudget,
};
use oneiron::housekeeping::HousekeepingBudget;
use oneiron::llm;
use oneiron::schedule::JobOutcome;
use oneiron::skill::{
    SkillCallContract, SkillLifecycle, SkillRecord, SkillRole, canonical_skill_tree_hash,
};
use oneiron::test_doors::turn_programs as program_doors;
use oneiron::test_doors::wake_d1_park_release as doors;
use oneiron::{
    ClaimApprovalStatus, ClaimSource, DreamerRunnerStore, EdgeActorClass, EntityId, Result,
    TimeRange, Vault, VaultConfig,
};
use oneiron_store::ports::manual_clock::ManualClock;

/// The fixture's recording clock and the one-shot timer's due time.
const T0: u64 = 4_000_000_000;

/// The job an actor's timer programs arm (stage 5b-3).
const TIMER_JOB: &str = "dreamer_runner.program_timer";

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    // The pass self-wakes and pends once per attempt boundary, so polling
    // again immediately is correct; the bound catches a future pending on
    // anything else.
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("wake-pass future pending on something other than an attempt-boundary yield");
}

/// A temporary vault opened with `config` and a process-memory device
/// keystore, as the crate's test opener opens one (it keeps the seeded
/// default policy, which holds the shipped bytes that opener's tests read).
fn open_vault_with(config: VaultConfig) -> Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    // The owner exists before any park, so a park's notice has its owner to name.
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    Ok((dir, vault))
}

/// The vault's embedded owner, authenticated: what an owner door takes.
fn embedded_owner_proof(vault: &Vault) -> oneiron::consent::AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("owner proof")
}

/// An active callable SKILL, enough to arm: arming pins the record and never loads its source.
fn active_callable_skill(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    let files: [(&str, &[u8]); 2] = [
        (
            "SKILL.md",
            b"---\nname: fixture.callable\ndescription: Increment a number\nversion: 1\nrole: callable\ncall:\n  reference: scripts/call.js\n  arguments: {\"value\":\"integer\"}\n  returns: {\"result\":\"integer\"}\n---\nAn executable fixture.\n",
        ),
        (
            "scripts/call.js",
            b"finish(JSON.stringify({result:skillArgs.value + 1}));",
        ),
    ];
    let hash = canonical_skill_tree_hash(files).expect("hash the fixture tree");
    let mut record = SkillRecord::new(
        "fixture.callable",
        "Increment a number",
        "1",
        ClaimApprovalStatus::Approved,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        vec![],
        rmpv::Value::Map(vec![(
            rmpv::Value::from("source"),
            rmpv::Value::from("fixture"),
        )]),
    )
    .with_role(
        SkillRole::Callable,
        Some(SkillCallContract {
            reference: "scripts/call.js".into(),
            arguments: serde_json::json!({"value": "integer"}),
            returns: serde_json::json!({"result": "integer"}),
        }),
    )
    .with_content_hash(hash);
    vault
        .put_skill_record(&id, &record, TimeRange { start: 1, end: 1 }, 1)
        .expect("put the callable candidate");
    record.lifecycle_status = SkillLifecycle::Active;
    vault
        .update_skill_record(&id, &record, TimeRange { start: 2, end: 2 }, 2)
        .expect("activate the callable");
    id
}

/// The vault's owner and active callable, armed through the public surface.
struct Fixture {
    owner: EntityId,
    skill: EntityId,
}

impl Fixture {
    fn new(vault: &Vault) -> Self {
        Self {
            owner: vault.ensure_embedded_owner_actor().expect("owner"),
            skill: active_callable_skill(vault),
        }
    }

    fn input(&self, conversation: Option<EntityId>, trigger: ProgramTrigger) -> ArmTurnProgram {
        ArmTurnProgram {
            skill: self.skill,
            executor: "fixture.executor@1".into(),
            args: serde_json::json!({"value": 41}),
            conversation,
            trigger,
        }
    }

    fn arm(&self, vault: &Vault, trigger: ProgramTrigger) -> EntityId {
        vault
            .memory(self.owner, EdgeActorClass::Human)
            .arm_turn_program(&self.input(None, trigger))
            .expect("arm")
            .registration
    }
}

/// Admission queues and stamps a real program try. An unbound wake pass
/// cannot select it, so the test door claims it and uses the runtime's hold.
fn held_program(vault: &Vault) -> Result<(AttemptId, DreamerParkedAttemptRecord)> {
    let fixture = Fixture::new(vault);
    let registration = fixture.arm(
        vault,
        ProgramTrigger::Timer {
            first_at: T0,
            every_secs: 0,
        },
    );
    // The clock stands at T0: one run of the actor's timer job records the wake it owes.
    let timer_runs = vault
        .run_due(HousekeepingBudget::unbounded())?
        .runs
        .iter()
        .filter(|run| run.job == TIMER_JOB && run.outcome == JobOutcome::Done)
        .count();
    assert_eq!(timer_runs, 1);
    let drain = vault.wake_turn_programs(T0)?;
    assert_eq!((drain.admitted, drain.refused, drain.held), (1, 0, 0));
    let (attempt, parked) = program_doors::hold_admitted_program_try(vault, registration, T0)?;
    let status = DreamerRunnerStore::new(vault)
        .status(attempt)?
        .expect("the held program try");
    assert_eq!(
        status.attempt.kind,
        oneiron::dreamer_runner::DREAMER_TURN_PROGRAM_ATTEMPT_KIND
    );
    assert_eq!(
        parked.park_owner,
        oneiron::dreamer_runner::TURN_PROGRAM_PARK_OWNER
    );
    assert_eq!(parked.cause, oneiron::DreamerParkCause::Other);
    Ok((attempt, parked))
}

struct SettlementStepBackend;
impl llm::LlmBackend for SettlementStepBackend {
    fn generate<'a>(
        &'a self,
        _request: llm::LlmRequest,
        _lease: &'a llm::BudgetLease,
    ) -> llm::LlmGenerateFuture<'a> {
        Box::pin(async {
            let mut usage = llm::LlmUsage::zero();
            usage.input.total = 37;
            usage.output.total = 1;
            usage.output.text = 1;
            Ok(llm::LlmResponse {
                message: llm::LlmMessage {
                    role: llm::LlmMessageRole::Assistant,
                    content: vec![llm::ContentPart::Text {
                        text: "paid".into(),
                        signature: None,
                    }],
                },
                usage,
                finish_reason: llm::FinishReason::Stop,
                reply_assertions: Default::default(),
                token_scores: None,
            })
        })
    }
    fn stream<'a>(
        &'a self,
        _request: llm::LlmRequest,
        _lease: &'a llm::BudgetLease,
    ) -> llm::LlmStreamResult<'a> {
        Err(llm::LlmError::Fatal(llm::FatalLlmError::InvalidRequest))
    }
}

/// One model request for the scripted backend: a text step of the consolidation purpose.
fn paid_step_request() -> llm::LlmRequest {
    llm::LlmRequest {
        model: llm::ModelId::new("test/model@r1").expect("model id"),
        envelope: llm::CallEnvelope {
            scope: llm::Scope::default(),
            purpose: llm::CallPurpose::Consolidation,
            class: llm::CallClass::BestEffort,
            tier: llm::TierPrecedence::for_purpose(
                &llm::CallPurpose::Consolidation,
                llm::ModelTierRef("default".into()),
            ),
            response_format: llm::ResponseFormat::Text,
            locality: llm::ModelLocality::OwnServer,
            host_keyless: false,
            host_paid: false,
            seat_effort: None,
        },
        messages: vec![llm::LlmMessage {
            role: llm::LlmMessageRole::User,
            content: vec![llm::ContentPart::Text {
                text: "paid step".into(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: Default::default(),
        provider_options: Default::default(),
        host_segments: None,
    }
}

/// Stop settles measured usage retained on this held program's reservation.
#[test]
fn the_program_hold_stop_settles_the_stopped_trys_owed_charge() -> Result<()> {
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let (_dir, vault) = open_vault_with(config)?;
    let (attempt, parked) = held_program(&vault)?;
    let store = DreamerRunnerStore::new(&vault);
    let budget_id = "program-hold-stop-owed";
    // Plant the failed-settlement state through the existing park-stop door;
    // no program runtime or model provider runs in this fixture.
    doors::retain_owed_charge(
        &vault,
        ReserveDreamerBudget {
            budget_id: budget_id.to_owned(),
            child_attempt: attempt,
            budget_total_units: 1_000,
            reserve_units: 100,
            now: T0 + 1,
        },
        37,
    )?;
    let retained = store
        .budget_reservation(budget_id, attempt)?
        .expect("retained reservation");
    assert_eq!(retained.owed_units, 37, "the measured usage is still owed");
    assert_eq!(doors::attempt_budget_reservation_count(&vault, attempt)?, 1);
    let before = store.budget(budget_id)?.expect("the budget line");
    assert_eq!(
        (
            before.spent_units(),
            before.remaining_units,
            before.reserved_units
        ),
        (Some(0), 900, 100)
    );

    clock.set(T0 + 2);
    let owner_proof = embedded_owner_proof(&vault);
    let view = oneiron::dreamer_runner::release_turn_program_hold_as_owner(
        &vault,
        &owner_proof,
        &ReleaseTurnProgramHoldRequest {
            attempt: EntityId::from_bytes(*attempt.as_bytes())?.to_hex(),
            reason: parked.reason,
            parked_at: parked.parked_at,
            action: ProgramHoldReleaseAction::Stop,
            note: Some("the owner stops this run".to_owned()),
        },
    )?;
    assert_eq!(
        view.state, "cancelled",
        "FAILBEFORE program-hold-stop settlement: Stop cancels the held program try"
    );
    assert!(
        view.effected,
        "FAILBEFORE program-hold-stop settlement: Stop ends the held program try"
    );
    let after = store
        .budget(budget_id)?
        .expect("FAILBEFORE program-hold-stop settlement: the budget line survives Stop");
    assert_eq!(
        (
            doors::attempt_budget_reservation_count(&vault, attempt)?,
            after.spent_units(),
            after.remaining_units,
            after.reserved_units,
            after.overdraft_units,
        ),
        (0, Some(37), 963, 0, 0),
        "FAILBEFORE program-hold-stop settlement: Stop retires every reservation and charges its owed units"
    );
    Ok(())
}

/// Stop retires a paid terminal memo's receipt without erasing the program's STEP table.
#[test]
fn the_program_hold_stop_retires_the_stopped_trys_step_receipts() -> Result<()> {
    let clock = ManualClock::new(T0);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let (_dir, vault) = open_vault_with(config)?;
    let (attempt, parked) = held_program(&vault)?;
    // Use the park-stop test's backend and request through its existing door;
    // this plants a paid receipt without running the program's pinned entry.
    let step_hash = block_on_ready(doors::settle_paid_step(
        &vault,
        attempt,
        &SettlementStepBackend,
        paid_step_request(),
        T0 + 1,
    ))?;
    assert!(
        doors::step_charged(&vault, attempt, &step_hash)?,
        "the terminal memo reads charged immediately before Stop"
    );

    clock.set(T0 + 2);
    let owner_proof = embedded_owner_proof(&vault);
    let view = oneiron::dreamer_runner::release_turn_program_hold_as_owner(
        &vault,
        &owner_proof,
        &ReleaseTurnProgramHoldRequest {
            attempt: EntityId::from_bytes(*attempt.as_bytes())?.to_hex(),
            reason: parked.reason,
            parked_at: parked.parked_at,
            action: ProgramHoldReleaseAction::Stop,
            note: Some("the owner stops this run".to_owned()),
        },
    )?;
    assert_eq!(
        view.state, "cancelled",
        "FAILBEFORE program-hold-stop settlement: Stop cancels the held program try"
    );
    assert!(
        view.effected,
        "FAILBEFORE program-hold-stop settlement: Stop ends the held program try"
    );
    assert!(
        !doors::step_charged(&vault, attempt, &step_hash)?,
        "FAILBEFORE program-hold-stop settlement: Stop retires the try's paid-step receipt"
    );
    Ok(())
}
