//! Exercises the production merged-value step lender without switching native extraction jobs.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-driver --all-features --test dreamer_merged_value_loan` (the driver's dev dependency turns on the engine's `test-support` feature).
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
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{
    BudgetLease, DreamerClaimAuthoringStrategy, EntityId, FatalLlmError, LlmBackend, LlmCapability,
    LlmError, LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId, UnsupportedCapability,
    Vault, VaultConfig, WakeAttemptContext,
};
use oneiron_driver::{ConsolidationExecutorFactory, ExtractionDecisionGate, PassExecutorFactory};
use oneiron_testkit::{ScriptedBackend, Step};
use serde_json::json;

/// Returns fixture failures without hiding their source.
type MergedValueLoanTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Lets the test withdraw the verdict route or the step permission while retaining the binding.
struct SwitchableMergedValueGate {
    /// Records whether the host currently admits the verdict route.
    verdict_open: AtomicBool,
    /// Records whether the host currently admits a generation step.
    step_open: AtomicBool,
    /// Counts every live verdict route check, including a refused loan.
    verdict_calls: AtomicUsize,
    /// Counts every live step permission check, including a refused loan.
    step_calls: AtomicUsize,
}

impl ExtractionDecisionGate for SwitchableMergedValueGate {
    /// Reads the test host's verdict route permission at each loan.
    fn admits(&self) -> oneiron::Result<bool> {
        self.verdict_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.verdict_open.load(Ordering::SeqCst))
    }

    /// Reads the test host's step permission at each loan.
    fn admits_step(&self) -> oneiron::Result<bool> {
        self.step_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.step_open.load(Ordering::SeqCst))
    }
}

/// Answers every generation on the verdict route with one merged value.
struct CountingMergedValueBackend {
    /// Counts the actual generations observed by the scripted backend.
    calls: AtomicUsize,
}

impl LlmBackend for CountingMergedValueBackend {
    /// Admits every capability the fixture's fixed model asks about.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    /// Answers the step with one merged value and declares its terminal usage.
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let backend = ScriptedBackend::new(vec![
                Step::text(
                    "merged-value",
                    ScriptedBackend::digest_of(&request),
                    json!({"value": "tea and coffee"}).to_string(),
                )
                .buffered()
                .usage(100, 50),
            ])
            .map_err(|error| {
                LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                    message: format!("the merged-value scripted backend did not build: {error}"),
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

/// Counts extraction calls the merged-value test must never make and fails loudly when one arrives.
struct RefusingExtractionBackend {
    /// Counts the extraction generations observed, which must stay at zero.
    calls: AtomicUsize,
}

impl LlmBackend for RefusingExtractionBackend {
    /// Admits every capability so a misrouted call reaches the loud refusal below.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    /// Counts the call and refuses it because the verdict route must serve the merged value.
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            Err(LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                message: "the merged-value test must never call its extraction backend".to_owned(),
                code: None,
            }))
        })
    }

    /// Refuses streaming because this fixture never serves an extraction call.
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

/// Lends one merged-value step on the verdict route while both permissions hold, then withholds
/// the same binding's next loan once the verdict route closes, and again once the step gate closes.
#[test]
fn merged_value_step_loan_rechecks_the_verdict_route_and_the_step_gate()
-> MergedValueLoanTestResult<()> {
    let directory = tempfile::tempdir()?;
    drop(open_dreamer_vault(directory.path(), "owen")?);
    let vault = Vault::open_owned(directory.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let vault = Arc::new(vault);
    let actor = dreamer(&vault)?;
    stand_steward_grant(&vault, actor, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
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
    let candidates = turns
        .iter()
        .zip(["tea", "coffee"])
        .map(|(turn, value)| {
            json!({
                "subject": subject.to_hex(),
                "predicate": "profile.hobby",
                "value": value,
                "evidence": [{"turn": turn["turn"], "version": turn["version"]}],
            })
        })
        .collect::<Vec<_>>();
    let request = json!({
        "resolution": "merge",
        "candidates": candidates,
        "priors": [],
    });
    let verdict_backend = Arc::new(CountingMergedValueBackend {
        calls: AtomicUsize::new(0),
    });
    let extraction_backend = Arc::new(RefusingExtractionBackend {
        calls: AtomicUsize::new(0),
    });
    let fixture = ExtractionVerdictFixture::new(verdict_backend.clone())?;
    let pass = fixture.pass_resources();
    let verdict = pass
        .roles
        .get(DREAMER_VERDICT_ROLE)
        .ok_or("the fixture routes its verdict role")?;
    let (_, extraction_model, extraction_binding) = fixture.extraction_route();
    let extraction_route: Arc<dyn LlmBackend> = extraction_backend.clone();
    let roles = pass.roles.clone().with(
        DREAMER_EXTRACTION_ROLE,
        RoleBackend {
            backend: extraction_route,
            model: extraction_model,
            binding: extraction_binding,
            sourced: None,
        },
    );
    let gate = Arc::new(SwitchableMergedValueGate {
        verdict_open: AtomicBool::new(true),
        step_open: AtomicBool::new(true),
        verdict_calls: AtomicUsize::new(0),
        step_calls: AtomicUsize::new(0),
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
        "ExtractionAttemptLender::lend_merged_value_step must lend the open step; the base refuses the request shape: {opened:?}"
    );
    let answer = opened?;
    assert_eq!(answer["result"]["status"], json!("finished"));
    assert_eq!(answer["result"]["memoized"], json!(false));
    assert_eq!(answer["result"]["json"], json!({"value": "tea and coffee"}));
    assert_eq!(verdict_backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(extraction_backend.calls.load(Ordering::SeqCst), 0);
    assert_eq!(gate.verdict_calls.load(Ordering::SeqCst), 1);
    assert_eq!(gate.step_calls.load(Ordering::SeqCst), 1);
    assert_eq!(pass.guard.read().used_units - before, 150);
    {
        let charges = lender
            .charges()
            .lock()
            .map_err(|_| "the charge sink is poisoned")?;
        assert_eq!(charges.units(), 150);
        assert_eq!(charges.step_bindings().len(), 1);
        assert_eq!(charges.step_bindings()[0].attempt_id, attempt);
    }
    gate.verdict_open.store(false, Ordering::SeqCst);
    let closed = binding
        .invoke("ai.steps.submit", request.clone(), None)
        .expect_err("a closed verdict route withholds the next merged-value loan");
    assert_eq!(closed.code, MEMORY_CODE_MODEL_UNAVAILABLE);
    assert_eq!(gate.verdict_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        gate.step_calls.load(Ordering::SeqCst),
        1,
        "a refused verdict route ends the loan before the step gate is asked"
    );
    gate.verdict_open.store(true, Ordering::SeqCst);
    gate.step_open.store(false, Ordering::SeqCst);
    let withheld = binding
        .invoke("ai.steps.submit", request, None)
        .expect_err("a closed step gate withholds a generation on the verdict route");
    assert_eq!(withheld.code, MEMORY_CODE_MODEL_UNAVAILABLE);
    assert_eq!(gate.verdict_calls.load(Ordering::SeqCst), 3);
    assert_eq!(gate.step_calls.load(Ordering::SeqCst), 2);
    assert_eq!(verdict_backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(extraction_backend.calls.load(Ordering::SeqCst), 0);
    assert_eq!(pass.guard.read().used_units - before, 150);
    let charges = lender
        .charges()
        .lock()
        .map_err(|_| "the charge sink is poisoned")?;
    assert_eq!(charges.units(), 150);
    assert_eq!(charges.step_bindings().len(), 1);
    Ok(())
}
