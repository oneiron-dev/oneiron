//! Primitive D, slice 6.5c: a live agent run submits model steps under its
//! own lease (`ai.steps.submit`, `ai.steps.receipt`).
//!
//! - The run's own actor on its live lease is admitted, and the step spends
//!   on the line its host gives it. The engine books nothing on the run's
//!   spend scope itself: the host's live lease books the physical calls.
//! - A repeated step key replays the saved result: no model call, no spend.
//! - Another actor, a run whose lease ended, and a run its host no longer
//!   holds attached are refused the same way. A run let go while its call
//!   ran saves no result.
//! - A call's admission the host denies is no model failure: a durable
//!   step's deterministic fallback does not answer it, and the key's next
//!   call asks the model.
//! - A step key belongs to one run: no other run of the agent and no owner
//!   step shares it.
//! - A fresh call is held to the model list of the run's definition; a
//!   saved step answers without it.
//!
//! On the base `RunStepCaller` and the run actor's step doors do not exist,
//! so this file does not compile there. Public paths only:
//! `cargo test --locked -p oneiron --all-features --test run_steps`.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use oneiron::agent_def::{AgentDefinition, AgentModel};
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, SpendScopeId, agent_dispatch_actor,
};
use oneiron::attempt_queue::{AttemptRecord, ClaimAttempt, ClaimOutcome, CompleteAttempt};
use oneiron::code_run::HostSelfDispatcher;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::llm::model_step::{
    ModelStepReceipt, ModelStepReceiptRequest, ModelStepResult, ModelStepRetryPolicy,
    ModelStepSubmit, RunStepCaller, receipt_as_owner, receipt_as_run_actor,
    resume_saved_as_run_actor, submit_as_run_actor,
};
use oneiron::llm::{BudgetDenied, Scope};
use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_NOT_FOUND, MemoryError};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::HostBinding;
use oneiron::{
    AttemptId, AttemptQueue, BudgetExhaustionPolicy, BudgetGuard, BudgetLease, CallClass,
    CallEnvelope, CallPurpose, ContentPart, DeterministicFallback, EdgeActorClass, FatalLlmError,
    FinishReason, LlmBackend, LlmCapability, LlmError, LlmGenerateFuture, LlmInputUsage,
    LlmMessage, LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse, LlmResult,
    LlmStreamResult, LlmUsage, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence, UnsupportedCapability, Vault, VaultConfig, WriteActor,
};

type TestError = Box<dyn std::error::Error>;
type TestResult = Result<(), TestError>;

const WORKER: &str = "run-steps";
const SCOPE_UNITS: u64 = 20_000;
const STEP_UNITS: u64 = 8;
const RUN_ACTOR_REFUSAL: &str = "a run's model step needs the run's own actor on its live lease";

fn attached() -> bool {
    true
}

/// A run its host still holds attached.
static ATTACHED: fn() -> bool = attached;

/// Drives one test's steps on a current-thread runtime. This crate's tokio
/// carries no `macros` feature, so `#[tokio::test]` is not available.
fn block_on(steps: impl Future<Output = TestResult>) -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(steps)
}

fn open_vault(dir: &std::path::Path) -> Result<Vault, TestError> {
    let mut config = VaultConfig::device();
    config.map_size = 32 * 1024 * 1024;
    config.dimensions = 4;
    config.embedding_model = None;
    Ok(Vault::open_owned(dir, config)?)
}

struct LeasedRun {
    actor: WriteActor,
    definition: AgentDefinition,
    lease: HostBinding,
    attempt: AttemptRecord,
}

impl LeasedRun {
    fn caller(&self) -> RunStepCaller<'_> {
        RunStepCaller {
            actor: self.actor,
            lease: &self.lease,
            definition: &self.definition,
            attached: &ATTACHED,
        }
    }
}

fn claim(vault: &Vault, id: AttemptId) -> Result<AttemptRecord, TestError> {
    let queue = AttemptQueue::new(vault);
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now: u64::MAX,
            },
        )?
        else {
            break;
        };
        if row.id == id {
            return Ok(queue.get(id)?.ok_or("a claimed attempt reads back")?);
        }
    }
    Err("the agent attempt is ready to claim".into())
}

fn leased_run(vault: &Vault, run: &str, budget: Option<u64>) -> Result<LeasedRun, TestError> {
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or("the default agent is seeded")?;
    let mut spawn = AgentSpawnContext::default().with_depth_remaining(1);
    if let Some(units) = budget {
        spawn = spawn.with_budget(units);
    }
    let AgentDispatchOutcome::Dispatched(status) = AgentDispatcher::new(vault)
        .dispatch_with_context(
            DispatchAgent {
                target: AgentDispatchTarget::Custom(agent),
                parent_attempt: None,
                dedupe_key: None,
                run_id: Some(run.to_owned()),
                now: 1,
            },
            spawn,
        )?
    else {
        return Err("expected one fresh agent run".into());
    };
    let actor = agent_dispatch_actor(&status.input)?;
    let attempt = claim(vault, status.attempt.id)?;
    let host = HostSelfDispatcher::for_leased_agent_attempt(vault, actor, &attempt)?;
    let lease = host
        .task_host_binding()?
        .ok_or("the agent run has a lease")?;
    Ok(LeasedRun {
        actor,
        definition: status.input.definition,
        lease,
        attempt,
    })
}

fn spend_scope(vault: &Vault, run: &LeasedRun) -> Result<SpendScopeId, TestError> {
    Ok(AgentDispatcher::new(vault)
        .spend_scope_for_attempt(run.attempt.id)?
        .ok_or("the budgeted attempt has a spend scope")?)
}

fn host_guard() -> BudgetGuard {
    BudgetGuard::with_reserve_units(
        "run-steps-host",
        SCOPE_UNITS,
        500,
        BudgetExhaustionPolicy::Suspend,
    )
}

struct ScriptedBackend {
    script: Mutex<VecDeque<LlmResult<LlmResponse>>>,
    calls: AtomicUsize,
    /// The host's attachment, which a call ends when one is given.
    ends: Option<Arc<AtomicBool>>,
}

impl ScriptedBackend {
    fn new(responses: usize) -> Self {
        Self {
            script: Mutex::new((0..responses).map(|_| Ok(response())).collect()),
            calls: AtomicUsize::new(0),
            ends: None,
        }
    }

    /// A backend whose every call ends `attachment` before it answers.
    fn ending(responses: usize, attachment: &Arc<AtomicBool>) -> Self {
        Self {
            ends: Some(Arc::clone(attachment)),
            ..Self::new(responses)
        }
    }

    /// A backend whose one call ends `attachment` and is answered as a host
    /// answers a physical admission it denies.
    fn denied(attachment: &Arc<AtomicBool>) -> Self {
        Self {
            script: Mutex::new(VecDeque::from([Err(BudgetDenied::AdmissionDenied.into())])),
            calls: AtomicUsize::new(0),
            ends: Some(Arc::clone(attachment)),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl LlmBackend for ScriptedBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(attachment) = &self.ends {
            attachment.store(false, Ordering::SeqCst);
        }
        let next = self
            .script
            .lock()
            .expect("script mutex")
            .pop_front()
            .expect("scripted backend exhausted");
        Box::pin(async move { next })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(LlmError::Fatal(FatalLlmError::Unsupported(
            UnsupportedCapability {
                capability: LlmCapability::Streaming,
                model: None,
                reason: None,
            },
        )))
    }
}

fn response() -> LlmResponse {
    LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content: vec![ContentPart::Text {
                text: "the model step finished".to_owned(),
                signature: None,
            }],
        },
        usage: LlmUsage {
            input: LlmInputUsage {
                total: 3,
                cache_read: 0,
                cache_write: 0,
            },
            output: LlmOutputUsage {
                total: 5,
                text: 5,
                reasoning: 0,
            },
            raw_provider: serde_json::Value::Null,
            call_metadata: None,
        },
        finish_reason: FinishReason::Stop,
        reply_assertions: Default::default(),
        token_scores: None,
    }
}

fn step_input(key: &str) -> ModelStepSubmit {
    ModelStepSubmit {
        step_key: key.to_owned(),
        request: LlmRequest {
            model: ModelId::new("test/model@r1").expect("model id"),
            envelope: CallEnvelope {
                seat_effort: None,
                scope: Scope::default(),
                purpose: CallPurpose::Consolidation,
                class: CallClass::BestEffort,
                tier: TierPrecedence::for_purpose(
                    &CallPurpose::Consolidation,
                    ModelTierRef("default".into()),
                ),
                response_format: ResponseFormat::Text,
                locality: ModelLocality::OwnServer,
                host_keyless: false,
                host_paid: false,
            },
            messages: vec![LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: "finish this model step".to_owned(),
                    signature: None,
                }],
            }],
            tools: Vec::new(),
            params: std::collections::BTreeMap::new(),
            provider_options: std::collections::BTreeMap::new(),
            host_segments: None,
        },
        retry: ModelStepRetryPolicy { max_attempts: 1 },
    }
}

fn receipt_request(key: &str) -> ModelStepReceiptRequest {
    ModelStepReceiptRequest {
        live_run: None,
        step_key: key.to_owned(),
    }
}

fn finished_claim(receipt: &ModelStepReceipt, expected_memoized: bool) -> &str {
    match receipt.result.as_ref() {
        Some(ModelStepResult::Finished {
            memoized,
            claim_ref,
            ..
        }) => {
            assert_eq!(*memoized, expected_memoized);
            assert!(!claim_ref.is_empty());
            claim_ref
        }
        other => panic!("expected a finished model step, got {other:?}"),
    }
}

fn assert_run_actor_refused(error: MemoryError) {
    assert_eq!(error.code, MEMORY_CODE_FORBIDDEN);
    assert_eq!(error.message, RUN_ACTOR_REFUSAL);
}

#[test]
fn an_agent_step_is_admitted_on_its_live_run_and_spends_on_its_hosts_line() -> TestResult {
    block_on(async {
        let dir = tempfile::tempdir()?;
        let vault = open_vault(dir.path())?;
        let run = leased_run(&vault, "scoped-run", Some(SCOPE_UNITS))?;
        let scope = spend_scope(&vault, &run)?;
        let dispatcher = AgentDispatcher::new(&vault);
        assert_eq!(dispatcher.available_units(&scope)?, SCOPE_UNITS);
        let backend = ScriptedBackend::new(1);
        let line = host_guard();

        let receipt =
            submit_as_run_actor(&vault, run.caller(), step_input("k"), &backend, &line).await?;
        finished_claim(&receipt, false);
        assert_eq!(backend.call_count(), 1);

        // The host's line pays the response's three input and five output
        // tokens. The engine books nothing on the scope beside the host's
        // live lease, which books the physical calls.
        assert_eq!(line.read().used_units, STEP_UNITS);
        assert_eq!(dispatcher.spend_read(&scope)?.spent_units, 0);
        assert_eq!(dispatcher.available_units(&scope)?, SCOPE_UNITS);
        Ok(())
    })
}

#[test]
fn a_repeated_step_key_replays_with_no_model_call_and_no_spend() -> TestResult {
    block_on(async {
        let dir = tempfile::tempdir()?;
        let vault = open_vault(dir.path())?;
        let run = leased_run(&vault, "replayed-run", Some(SCOPE_UNITS))?;
        let input = step_input("k");
        let backend = ScriptedBackend::new(1);
        let line = host_guard();
        let first =
            submit_as_run_actor(&vault, run.caller(), input.clone(), &backend, &line).await?;
        let claim_ref = finished_claim(&first, false).to_owned();
        assert_eq!(backend.call_count(), 1);
        assert_eq!(line.read().used_units, STEP_UNITS);

        // Replaying the saved key preserves both references without paying again.
        let replay =
            submit_as_run_actor(&vault, run.caller(), input.clone(), &backend, &line).await?;
        assert_eq!(finished_claim(&replay, true), claim_ref);
        assert_eq!(replay.step_ref, first.step_ref);
        assert_eq!(backend.call_count(), 1);
        assert_eq!(line.read().used_units, STEP_UNITS);

        let resumed = resume_saved_as_run_actor(&vault, run.caller(), &input)
            .await?
            .ok_or("the finished step resumes from its saved result")?;
        assert_eq!(resumed.step_ref, first.step_ref);
        assert_eq!(finished_claim(&resumed, true), claim_ref);
        let receipt = receipt_as_run_actor(&vault, run.caller(), &receipt_request("k"))?;
        assert_eq!(receipt.step_ref, first.step_ref);
        assert_eq!(backend.call_count(), 1);
        assert_eq!(line.read().used_units, STEP_UNITS);
        Ok(())
    })
}

#[test]
fn another_actor_is_refused_on_the_runs_lease() -> TestResult {
    block_on(async {
        let dir = tempfile::tempdir()?;
        let vault = open_vault(dir.path())?;
        let run = leased_run(&vault, "own-run", Some(SCOPE_UNITS))?;
        let (other_agent, _) = vault
            .get_seeded_agent_definition_by_logical_id("sys.scout")?
            .ok_or("the other agent is seeded")?;
        let other_actor = WriteActor::new(other_agent, EdgeActorClass::Agent);
        assert_ne!(other_actor, run.actor);
        let caller = RunStepCaller {
            actor: other_actor,
            ..run.caller()
        };
        let backend = ScriptedBackend::new(0);
        let line = host_guard();
        let input = step_input("k");

        // Holding a lease does not let another agent use its run's step doors.
        assert_run_actor_refused(
            submit_as_run_actor(&vault, caller, input.clone(), &backend, &line)
                .await
                .expect_err("another actor cannot submit"),
        );
        assert_run_actor_refused(
            resume_saved_as_run_actor(&vault, caller, &input)
                .await
                .expect_err("another actor cannot resume"),
        );
        assert_run_actor_refused(
            receipt_as_run_actor(&vault, caller, &receipt_request("k"))
                .expect_err("another actor cannot read the receipt"),
        );
        assert_eq!(backend.call_count(), 0);
        Ok(())
    })
}

#[test]
fn a_second_run_of_the_agent_does_not_share_the_first_runs_step() -> TestResult {
    block_on(async {
        let dir = tempfile::tempdir()?;
        let vault = open_vault(dir.path())?;
        let first_run = leased_run(&vault, "first-run", Some(SCOPE_UNITS))?;
        let second_run = leased_run(&vault, "second-run", Some(SCOPE_UNITS))?;
        assert_eq!(first_run.actor, second_run.actor);
        assert_ne!(first_run.attempt.id, second_run.attempt.id);
        assert_eq!(first_run.attempt.retry_of, None);
        assert_eq!(second_run.attempt.retry_of, None);
        let backend = ScriptedBackend::new(2);
        let line = host_guard();
        let input = step_input("k");
        let first =
            submit_as_run_actor(&vault, first_run.caller(), input.clone(), &backend, &line).await?;
        let first_claim = finished_claim(&first, false).to_owned();
        assert_eq!(backend.call_count(), 1);

        // The same agent's other launch has no receipt under this key yet.
        let missing = receipt_as_run_actor(&vault, second_run.caller(), &receipt_request("k"))
            .expect_err("the other run has not submitted this key");
        assert_eq!(missing.code, MEMORY_CODE_NOT_FOUND);
        let second =
            submit_as_run_actor(&vault, second_run.caller(), input, &backend, &line).await?;
        assert_ne!(second.step_ref, first.step_ref);
        assert_ne!(finished_claim(&second, false), first_claim);
        assert_eq!(backend.call_count(), 2);
        Ok(())
    })
}

#[test]
fn the_owner_and_a_run_do_not_share_a_step_key() -> TestResult {
    block_on(async {
        let dir = tempfile::tempdir()?;
        let vault = open_vault(dir.path())?;
        let owner_actor = vault.ensure_embedded_owner_actor()?;
        let owner = vault.authenticate_owner(
            owner_actor,
            "principal:owner",
            true,
            GateDecisionId::now(),
        )?;
        let run = leased_run(&vault, "owner-separated-run", Some(SCOPE_UNITS))?;
        let backend = ScriptedBackend::new(1);
        let line = host_guard();
        let receipt =
            submit_as_run_actor(&vault, run.caller(), step_input("k"), &backend, &line).await?;
        finished_claim(&receipt, false);

        // The owner's valid proof does not read a run's key as an owner step.
        let missing = receipt_as_owner(&vault, &owner, &receipt_request("k"))
            .expect_err("the owner has not submitted this key");
        assert_eq!(missing.code, MEMORY_CODE_NOT_FOUND);
        assert_eq!(backend.call_count(), 1);
        Ok(())
    })
}

#[test]
fn a_model_the_runs_definition_does_not_list_is_refused() -> TestResult {
    block_on(async {
        let dir = tempfile::tempdir()?;
        let vault = open_vault(dir.path())?;
        let run = leased_run(&vault, "listed-model-run", Some(SCOPE_UNITS))?;
        let mut definition = run.definition.clone();
        definition.models = vec![AgentModel {
            model_ref: ModelId::new("test/other-model@r1").expect("model id"),
            when: "all model steps".to_owned(),
        }];
        let caller = RunStepCaller {
            definition: &definition,
            ..run.caller()
        };
        let backend = ScriptedBackend::new(1);
        let line = host_guard();

        // A live lease cannot admit a fresh call outside its definition's list.
        let refused = submit_as_run_actor(&vault, caller, step_input("k"), &backend, &line)
            .await
            .expect_err("the requested model is not listed");
        assert!(refused.message.contains("is not in agent"));
        assert_eq!(backend.call_count(), 0);
        assert_eq!(line.read().used_units, 0);
        let unsaved = receipt_as_run_actor(&vault, run.caller(), &receipt_request("k"))
            .expect_err("the refused call wrote no step");
        assert_eq!(unsaved.code, MEMORY_CODE_NOT_FOUND);

        // A step saved while its model was listed still answers, with no
        // model call, once the list no longer names that model.
        let saved =
            submit_as_run_actor(&vault, run.caller(), step_input("saved"), &backend, &line).await?;
        let claim_ref = finished_claim(&saved, false).to_owned();
        assert_eq!(backend.call_count(), 1);
        let replay =
            submit_as_run_actor(&vault, caller, step_input("saved"), &backend, &line).await?;
        assert_eq!(finished_claim(&replay, true), claim_ref);
        assert_eq!(backend.call_count(), 1);
        Ok(())
    })
}

#[test]
fn a_run_whose_lease_ended_is_refused() -> TestResult {
    block_on(async {
        let dir = tempfile::tempdir()?;
        let vault = open_vault(dir.path())?;
        let run = leased_run(&vault, "completed-run", Some(SCOPE_UNITS))?;
        let backend = ScriptedBackend::new(1);
        let line = host_guard();
        let input = step_input("k");
        let receipt =
            submit_as_run_actor(&vault, run.caller(), input.clone(), &backend, &line).await?;
        finished_claim(&receipt, false);
        assert_eq!(backend.call_count(), 1);
        AttemptQueue::new(&vault).complete(CompleteAttempt {
            id: run.attempt.id,
            lease_owner: WORKER.to_owned(),
            attempt_count: run.attempt.attempt_count,
            now: run.attempt.updated_at,
        })?;

        // Even a saved result cannot be replayed or read through an ended lease.
        assert_run_actor_refused(
            submit_as_run_actor(&vault, run.caller(), input.clone(), &backend, &line)
                .await
                .expect_err("an ended run cannot submit"),
        );
        assert_run_actor_refused(
            receipt_as_run_actor(&vault, run.caller(), &receipt_request("k"))
                .expect_err("an ended run cannot read the receipt"),
        );
        assert_run_actor_refused(
            resume_saved_as_run_actor(&vault, run.caller(), &input)
                .await
                .expect_err("an ended run cannot resume"),
        );
        assert_eq!(backend.call_count(), 1);
        Ok(())
    })
}

#[test]
fn a_run_its_host_no_longer_holds_attached_is_refused_and_saves_no_result() -> TestResult {
    block_on(async {
        let dir = tempfile::tempdir()?;
        let vault = open_vault(dir.path())?;
        let run = leased_run(&vault, "detached-run", Some(SCOPE_UNITS))?;
        let attachment = Arc::new(AtomicBool::new(false));
        let watch = || attachment.load(Ordering::SeqCst);
        let caller = RunStepCaller {
            attached: &watch,
            ..run.caller()
        };
        let line = host_guard();
        let input = step_input("k");

        // The lease still holds, yet a run its host let go reaches no door.
        let unsent = ScriptedBackend::new(0);
        assert_run_actor_refused(
            submit_as_run_actor(&vault, caller, input.clone(), &unsent, &line)
                .await
                .expect_err("a detached run cannot submit"),
        );
        assert_run_actor_refused(
            resume_saved_as_run_actor(&vault, caller, &input)
                .await
                .expect_err("a detached run cannot resume"),
        );
        assert_run_actor_refused(
            receipt_as_run_actor(&vault, caller, &receipt_request("k"))
                .expect_err("a detached run cannot read a receipt"),
        );
        assert_eq!(unsent.call_count(), 0);

        // A run let go while its call ran is refused its answer, and no
        // result is saved under the standing it lost.
        attachment.store(true, Ordering::SeqCst);
        let ending = ScriptedBackend::ending(1, &attachment);
        assert_run_actor_refused(
            submit_as_run_actor(&vault, caller, input.clone(), &ending, &line)
                .await
                .expect_err("a run let go during its call gets no answer"),
        );
        assert_eq!(ending.call_count(), 1);
        attachment.store(true, Ordering::SeqCst);
        let unfinished = receipt_as_run_actor(&vault, caller, &receipt_request("k"))?;
        assert!(unfinished.result.is_none());

        // Attached again, the key's next call resumes the same step and
        // finishes it.
        let backend = ScriptedBackend::new(1);
        let finished = submit_as_run_actor(&vault, caller, input, &backend, &line).await?;
        assert_eq!(finished.step_ref, unfinished.step_ref);
        assert!(matches!(
            finished.result,
            Some(ModelStepResult::Finished { .. })
        ));
        Ok(())
    })
}

#[test]
fn an_admission_the_host_denies_is_no_model_failure_and_saves_no_fallback_answer() -> TestResult {
    block_on(async {
        let dir = tempfile::tempdir()?;
        let vault = open_vault(dir.path())?;
        let run = leased_run(&vault, "denied-admission-run", Some(SCOPE_UNITS))?;
        let attachment = Arc::new(AtomicBool::new(true));
        let watch = || attachment.load(Ordering::SeqCst);
        let caller = RunStepCaller {
            attached: &watch,
            ..run.caller()
        };
        let line = host_guard();
        // A durable step: its deterministic fallback answers a model failure.
        let mut input = step_input("k");
        input.request.envelope.class = CallClass::Durable {
            fallback: DeterministicFallback {
                name: "fail_closed_to_proposed".to_owned(),
                config: None,
            },
        };

        // The host lets the run go and denies the call's admission. That is
        // no model failure: no fallback answers it and no result is saved.
        let denied = ScriptedBackend::denied(&attachment);
        assert_run_actor_refused(
            submit_as_run_actor(&vault, caller, input.clone(), &denied, &line)
                .await
                .expect_err("a run let go before its call was sent gets no answer"),
        );
        assert_eq!(denied.call_count(), 1);
        attachment.store(true, Ordering::SeqCst);
        let unfinished = receipt_as_run_actor(&vault, caller, &receipt_request("k"))?;
        assert!(unfinished.result.is_none());

        // Attached again, the key's next call asks the model itself.
        let backend = ScriptedBackend::new(1);
        let finished = submit_as_run_actor(&vault, caller, input, &backend, &line).await?;
        assert_eq!(finished.step_ref, unfinished.step_ref);
        assert_eq!(backend.call_count(), 1);
        assert!(matches!(
            finished.result,
            Some(ModelStepResult::Finished {
                memoized: false,
                fallback_source: None,
                ..
            })
        ));
        Ok(())
    })
}
