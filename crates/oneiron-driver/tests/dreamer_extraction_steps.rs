//! Exercises the production extraction step lender without switching native extraction jobs.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-driver --all-features --test dreamer_extraction_steps` (the driver's dev dependency turns on the engine's `test-support` feature).
#![cfg(oneiron_test_support)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use oneiron::dreamer_consolidation::{DREAMER_EXTRACTION_ROLE, DREAMER_VERDICT_ROLE, RoleBackend};
use oneiron::dreamer_promotion::AttemptPromotionSink;
use oneiron::memory::MEMORY_CODE_MODEL_UNAVAILABLE;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_verdict::ExtractionVerdictFixture;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::{
    BudgetLease, DreamerClaimAuthoringStrategy, FatalLlmError, LlmBackend, LlmCapability, LlmError,
    LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId, UnsupportedCapability, Vault,
    VaultConfig, WakeAttemptContext,
};
use oneiron_driver::{ConsolidationExecutorFactory, ExtractionDecisionGate, PassExecutorFactory};
use oneiron_testkit::{ScriptedBackend, Step};
use serde_json::json;

/// Returns fixture failures without hiding their source.
type ExtractionStepTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Lets the test withdraw step permission while retaining the verdict permission.
struct SwitchableExtractionStepGate {
    /// Records whether the host currently admits a step loan.
    step_open: AtomicBool,
    /// Records whether the host currently admits a verdict loan.
    verdict_open: AtomicBool,
    /// Counts every live step permission check, including a refused loan.
    step_calls: AtomicUsize,
    /// Counts every live verdict permission check, including a refused loan.
    verdict_calls: AtomicUsize,
}

impl ExtractionDecisionGate for SwitchableExtractionStepGate {
    /// Reads the test host's verdict permission at each verdict loan.
    fn admits(&self) -> oneiron::Result<bool> {
        self.verdict_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.verdict_open.load(Ordering::SeqCst))
    }

    /// Reads the test host's step permission at each step loan.
    fn admits_step(&self) -> oneiron::Result<bool> {
        self.step_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.step_open.load(Ordering::SeqCst))
    }
}

/// Admits verdict reads while refusing generation steps through the default step refusal.
struct VerdictOnlyExtractionGate {
    /// Counts every live verdict permission check.
    calls: AtomicUsize,
}

impl ExtractionDecisionGate for VerdictOnlyExtractionGate {
    /// Admits every verdict loan while counting the check.
    fn admits(&self) -> oneiron::Result<bool> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(true)
    }
}

/// Uses the same request-matched scripted backend as the engine step fixture test.
struct CountingExtractionStepBackend {
    /// Counts the actual generations observed by the scripted backend.
    calls: AtomicUsize,
}

impl LlmBackend for CountingExtractionStepBackend {
    /// Admits every capability the fixture's fixed model asks about.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    /// Answers the step with the fixed plain-text reply and declares its terminal usage.
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let backend = ScriptedBackend::new(vec![
                Step::text(
                    "extraction-step",
                    ScriptedBackend::digest_of(&request),
                    "owen keeps tea warm",
                )
                .buffered()
                .usage(100, 50),
            ])
            .map_err(|error| {
                LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                    message: format!("the step scripted backend did not build: {error}"),
                    code: None,
                })
            })?;
            let response = backend.generate(request, lease).await;
            let seen = backend.finish();
            self.calls.fetch_add(seen.len(), Ordering::SeqCst);
            response
        })
    }

    /// Refuses streaming because this fixture only generates a buffered step.
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

/// Counts verdict calls the step test must never make and fails loudly when one arrives.
struct RefusingVerdictBackend {
    /// Counts the verdict generations observed, which must stay at zero.
    calls: AtomicUsize,
}

impl LlmBackend for RefusingVerdictBackend {
    /// Admits every capability so a misrouted call reaches the loud refusal below.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    /// Counts the call and refuses it because the step route must serve every step.
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            Err(LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                message: "the step test must never call its verdict backend".to_owned(),
                code: None,
            }))
        })
    }

    /// Refuses streaming because this fixture never serves a verdict call.
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

/// Answers one bound step while admitted, then refuses the same binding after the step gate closes.
#[test]
fn extraction_step_loan_rechecks_its_step_gate_each_call() -> ExtractionStepTestResult<()> {
    let directory = tempfile::tempdir()?;
    drop(open_dreamer_vault(directory.path(), "owen")?);
    let vault = Vault::open_owned(directory.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let vault = Arc::new(vault);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (attempt, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, 1_000)?;
    let binding = vault.bind_dreamer_attempt(&admitted)?;
    let attempt_hex: String = attempt
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let page = binding.invoke(
        "vault.consolidation.extraction.inputs.page",
        json!({"attempt": attempt_hex}),
        None,
    )?;
    let turns = page["value"]["turns"]
        .as_array()
        .ok_or("the extraction inputs page serves its turns")?;
    assert_eq!(turns.len(), 2);
    let request = json!({
        "evidence": [
            {"turn": turns[0]["turn"], "version": turns[0]["version"]},
            {"turn": turns[1]["turn"], "version": turns[1]["version"]},
        ],
    });
    let step_backend = Arc::new(CountingExtractionStepBackend {
        calls: AtomicUsize::new(0),
    });
    let verdict_backend = Arc::new(RefusingVerdictBackend {
        calls: AtomicUsize::new(0),
    });
    let fixture = ExtractionVerdictFixture::new(verdict_backend.clone())?;
    let pass = fixture.pass_resources();
    let verdict = pass
        .roles
        .get(DREAMER_VERDICT_ROLE)
        .ok_or("the fixture routes its verdict role")?;
    let (_, extraction_model, extraction_binding) = fixture.extraction_route();
    let step_route: Arc<dyn LlmBackend> = step_backend.clone();
    let roles = pass.roles.clone().with(
        DREAMER_EXTRACTION_ROLE,
        RoleBackend {
            backend: step_route,
            model: extraction_model,
            binding: extraction_binding,
            sourced: None,
        },
    );
    let gate = Arc::new(SwitchableExtractionStepGate {
        step_open: AtomicBool::new(true),
        verdict_open: AtomicBool::new(true),
        step_calls: AtomicUsize::new(0),
        verdict_calls: AtomicUsize::new(0),
    });
    let mut factory = ConsolidationExecutorFactory::new(
        Arc::clone(&verdict.backend),
        DreamerClaimAuthoringStrategy::SinglePass,
        binding.actor(),
        verdict.model.clone(),
        verdict.binding.clone(),
        Some(Arc::new(|_: &LlmRequest| true)),
        Box::new(AttemptPromotionSink::new(Arc::clone(&vault))),
    )
    .with_role_backends(roles)
    .with_decisions(pass.decisions.clone())
    .with_dreamer_job_vault(Arc::clone(&vault))
    .with_extraction_decisions(gate.clone(), pass.runtime.clone());
    let executor = factory.executor(&pass.guard)?;
    let context = WakeAttemptContext {
        vault: &vault,
        deadline: &pass.deadline,
        cancel: None,
        device_cancel: None,
        budget_id: "extraction-inputs",
        now_ms: pass.now_ms,
        prepared_wake: None,
        prepared_attempt: None,
        spend_meter: None,
    };
    let lender = executor
        .extraction_lender(&context)
        .ok_or("the production factory prepares an extraction lender")?;
    let binding = binding.lend_decisions(lender.clone());
    let before = pass.guard.read().used_units;
    let opened = binding.invoke("ai.steps.submit", request.clone(), None);
    assert!(
        opened.is_ok(),
        "ExtractionAttemptLender::lend_extraction_step must lend the open step, not MODEL_UNAVAILABLE: {opened:?}"
    );
    let answer = opened?;
    assert_eq!(answer["result"]["status"], json!("finished"));
    assert_eq!(
        answer["result"]["memoized"],
        json!(false),
        "the first lent step finishes without a memo; without a loan the base returns MODEL_UNAVAILABLE"
    );
    let response = serde_json::to_string(&answer["result"]["response"])?;
    assert!(
        response.contains("owen keeps tea warm"),
        "the finished step answers its scripted output: {response}"
    );
    let step_reference = answer["step_ref"]
        .as_str()
        .ok_or("the submit answers its step reference")?
        .to_owned();
    assert_eq!(step_backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(verdict_backend.calls.load(Ordering::SeqCst), 0);
    assert_eq!(pass.guard.read().used_units - before, 150);
    {
        let charges = lender
            .charges()
            .lock()
            .map_err(|_| "the charge sink is poisoned")?;
        assert_eq!(charges.units(), 150);
        assert_eq!(charges.step_bindings().len(), 1);
        assert_eq!(charges.step_bindings()[0].attempt_id, attempt);
        let observations = charges.spent_observations();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].usage.input.total, 100);
        assert_eq!(observations[0].usage.output.total, 50);
        assert!(!observations[0].memoized);
    }
    gate.step_open.store(false, Ordering::SeqCst);
    let closed = binding
        .invoke("ai.steps.submit", request, None)
        .expect_err("a closed step gate withholds the next loan on the same binding");
    assert_eq!(closed.code, MEMORY_CODE_MODEL_UNAVAILABLE);
    assert_eq!(gate.step_calls.load(Ordering::SeqCst), 2);
    assert_eq!(gate.verdict_calls.load(Ordering::SeqCst), 0);
    assert_eq!(step_backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(verdict_backend.calls.load(Ordering::SeqCst), 0);
    assert_eq!(pass.guard.read().used_units - before, 150);
    {
        let charges = lender
            .charges()
            .lock()
            .map_err(|_| "the charge sink is poisoned")?;
        assert_eq!(charges.units(), 150);
        assert_eq!(charges.step_bindings().len(), 1);
        assert_eq!(charges.spent_observations().len(), 1);
    }
    let receipt = binding.invoke(
        "ai.steps.receipt",
        json!({"step_key": step_reference}),
        None,
    )?;
    assert_eq!(receipt["result"]["status"], json!("finished"));
    assert_eq!(receipt["result"]["memoized"], json!(true));
    assert_eq!(receipt["progression"], json!("finished"));
    assert_eq!(gate.step_calls.load(Ordering::SeqCst), 2);
    assert_eq!(gate.verdict_calls.load(Ordering::SeqCst), 0);
    assert_eq!(step_backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(verdict_backend.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

/// A verdict-only gate never lends a generation step and never consults its verdict permission.
#[test]
fn a_verdict_only_gate_never_lends_a_step() -> ExtractionStepTestResult<()> {
    let directory = tempfile::tempdir()?;
    drop(open_dreamer_vault(directory.path(), "owen")?);
    let vault = Vault::open_owned(directory.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let vault = Arc::new(vault);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea", "owen likes coffee"])?;
    let (attempt, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, 1_000)?;
    let binding = vault.bind_dreamer_attempt(&admitted)?;
    let attempt_hex: String = attempt
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let page = binding.invoke(
        "vault.consolidation.extraction.inputs.page",
        json!({"attempt": attempt_hex}),
        None,
    )?;
    let turns = page["value"]["turns"]
        .as_array()
        .ok_or("the extraction inputs page serves its turns")?;
    assert_eq!(turns.len(), 2);
    let request = json!({
        "evidence": [
            {"turn": turns[0]["turn"], "version": turns[0]["version"]},
            {"turn": turns[1]["turn"], "version": turns[1]["version"]},
        ],
    });
    let step_backend = Arc::new(CountingExtractionStepBackend {
        calls: AtomicUsize::new(0),
    });
    let verdict_backend = Arc::new(RefusingVerdictBackend {
        calls: AtomicUsize::new(0),
    });
    let fixture = ExtractionVerdictFixture::new(verdict_backend.clone())?;
    let pass = fixture.pass_resources();
    let verdict = pass
        .roles
        .get(DREAMER_VERDICT_ROLE)
        .ok_or("the fixture routes its verdict role")?;
    let (_, extraction_model, extraction_binding) = fixture.extraction_route();
    let step_route: Arc<dyn LlmBackend> = step_backend.clone();
    let roles = pass.roles.clone().with(
        DREAMER_EXTRACTION_ROLE,
        RoleBackend {
            backend: step_route,
            model: extraction_model,
            binding: extraction_binding,
            sourced: None,
        },
    );
    let gate = Arc::new(VerdictOnlyExtractionGate {
        calls: AtomicUsize::new(0),
    });
    let mut factory = ConsolidationExecutorFactory::new(
        Arc::clone(&verdict.backend),
        DreamerClaimAuthoringStrategy::SinglePass,
        binding.actor(),
        verdict.model.clone(),
        verdict.binding.clone(),
        Some(Arc::new(|_: &LlmRequest| true)),
        Box::new(AttemptPromotionSink::new(Arc::clone(&vault))),
    )
    .with_role_backends(roles)
    .with_decisions(pass.decisions.clone())
    .with_dreamer_job_vault(Arc::clone(&vault))
    .with_extraction_decisions(gate.clone(), pass.runtime.clone());
    let executor = factory.executor(&pass.guard)?;
    let context = WakeAttemptContext {
        vault: &vault,
        deadline: &pass.deadline,
        cancel: None,
        device_cancel: None,
        budget_id: "extraction-inputs",
        now_ms: pass.now_ms,
        prepared_wake: None,
        prepared_attempt: None,
        spend_meter: None,
    };
    let lender = executor
        .extraction_lender(&context)
        .ok_or("the production factory prepares an extraction lender")?;
    let binding = binding.lend_decisions(lender.clone());
    let before = pass.guard.read().used_units;
    let refused = binding
        .invoke("ai.steps.submit", request, None)
        .expect_err("a verdict-only gate never lends a generation step");
    assert_eq!(refused.code, MEMORY_CODE_MODEL_UNAVAILABLE);
    assert_eq!(step_backend.calls.load(Ordering::SeqCst), 0);
    assert_eq!(verdict_backend.calls.load(Ordering::SeqCst), 0);
    assert_eq!(gate.calls.load(Ordering::SeqCst), 0);
    assert_eq!(pass.guard.read().used_units - before, 0);
    let charges = lender
        .charges()
        .lock()
        .map_err(|_| "the charge sink is poisoned")?;
    assert_eq!(charges.units(), 0);
    assert_eq!(charges.step_bindings().len(), 0);
    assert_eq!(charges.spent_observations().len(), 0);
    Ok(())
}
