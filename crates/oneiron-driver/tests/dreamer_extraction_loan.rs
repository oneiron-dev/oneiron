//! Exercises the production extraction lender without switching native extraction jobs.
//!
//! The driver test requires the engine's test-support feature and oneiron_test_support.
#![cfg(oneiron_test_support)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use oneiron::dreamer_consolidation::DREAMER_VERDICT_ROLE;
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
type ExtractionLoanTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Lets the test withdraw permission while retaining the same binding.
struct SwitchableExtractionGate {
    /// Records whether the host currently admits a loan.
    open: AtomicBool,
    /// Counts every live permission check, including a refused loan.
    calls: AtomicUsize,
}

impl ExtractionDecisionGate for SwitchableExtractionGate {
    /// Reads the test host's permission at each loan.
    fn admits(&self) -> oneiron::Result<bool> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.open.load(Ordering::SeqCst))
    }
}

/// Uses the same request-matched scripted backend as the engine parity fixture test.
struct MatchingExtractionReasoner {
    /// Counts the actual generations observed by the scripted backend.
    calls: AtomicUsize,
}

impl LlmBackend for MatchingExtractionReasoner {
    /// Admits every capability the fixture's fixed model asks about.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    /// Answers both questions in one generation and declares its terminal usage.
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let reply = json!({
                "Q1": {"merge": 0.05, "supersede": 0.05, "accumulate": 0.85, "escalate": 0.05},
                "Q2": {"none": 0.7, "C1": 0.2, "C2": 0.1},
            })
            .to_string();
            let backend = ScriptedBackend::new(vec![
                Step::text(
                    "extraction-pack",
                    ScriptedBackend::digest_of(&request),
                    reply,
                )
                .buffered()
                .usage(100, 50),
            ])
            .map_err(|error| {
                LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                    message: format!("the extraction scripted backend did not build: {error}"),
                    code: None,
                })
            })?;
            let response = backend.generate(request, lease).await;
            let seen = backend.finish();
            self.calls.fetch_add(seen.len(), Ordering::SeqCst);
            response
        })
    }

    /// Refuses streaming because this fixture only generates a buffered pack.
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

/// Answers a whole pack while admitted, then refuses the same binding after withdrawal.
#[test]
fn extraction_loan_rechecks_its_gate_each_call() -> ExtractionLoanTestResult<()> {
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
    let options = json!(["merge", "supersede", "accumulate", "escalate"]);
    let request = json!({
        "question": "resolution",
        "contract": {"kind": "choice", "options": options},
        "evidence": [],
        "state": {
            "read": "resolution",
            "part": {"kind": "whole"},
            "candidates": candidates,
            "listed": [],
            "priors": [],
            "questions": [
                {"key": ["resolution"], "options": options},
                {"key": ["identity", "0"], "options": ["none", "candidate:0", "candidate:1"]},
            ],
            "earlier": [],
        },
        "ceiling": "big",
        "reversibility": "reversible_read",
        "routine": false,
        "misses": 0,
    });
    let reasoner = Arc::new(MatchingExtractionReasoner {
        calls: AtomicUsize::new(0),
    });
    let fixture = ExtractionVerdictFixture::new(reasoner.clone())?;
    let pass = fixture.pass_resources();
    let verdict = pass
        .roles
        .get(DREAMER_VERDICT_ROLE)
        .ok_or("the fixture routes its verdict role")?;
    let gate = Arc::new(SwitchableExtractionGate {
        open: AtomicBool::new(true),
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
    .with_role_backends(pass.roles.clone())
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
    let opened = binding.invoke("ai.verdict", request.clone(), None);
    assert!(
        opened.is_ok(),
        "an open extraction gate must lend the production pack read, not MODEL_UNAVAILABLE: {opened:?}"
    );
    let answer = opened?["value"].clone();
    let pack = answer["pack"]
        .as_array()
        .ok_or("the admitted extraction read answers the whole pack")?;
    assert_eq!(pack.len(), 2);
    assert_eq!(pack[0]["key"], json!(["resolution"]));
    assert_eq!(pack[1]["key"], json!(["identity", "0"]));
    assert_eq!(
        pack[0]["answer"],
        json!({"kind": "choice", "value": "accumulate"})
    );
    assert_eq!(
        pack[1]["answer"],
        json!({"kind": "choice", "value": "none"})
    );
    for field in ["answer", "p", "rung", "receipt"] {
        assert_eq!(answer[field], pack[0][field]);
    }
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
    gate.open.store(false, Ordering::SeqCst);
    let closed = binding
        .invoke("ai.verdict", request, None)
        .expect_err("a closed gate withholds the next loan on the same binding");
    assert_eq!(closed.code, MEMORY_CODE_MODEL_UNAVAILABLE);
    assert_eq!(gate.calls.load(Ordering::SeqCst), 2);
    assert_eq!(reasoner.calls.load(Ordering::SeqCst), 1);
    assert_eq!(pass.guard.read().used_units - before, 150);
    let charges = lender
        .charges()
        .lock()
        .map_err(|_| "the charge sink is poisoned")?;
    assert_eq!(charges.units(), 150);
    assert_eq!(charges.step_bindings().len(), 1);
    assert_eq!(charges.spent_observations().len(), 1);
    Ok(())
}
