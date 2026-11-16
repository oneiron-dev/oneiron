//! Exercises the production extraction lender's auto-checker loan.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-driver --all-features --test dreamer_checker_loan` (the driver's dev dependency turns on the engine's `test-support` feature).
#![cfg(oneiron_test_support)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use oneiron::claim_check::AutoCheckNotes;
use oneiron::dreamer_consolidation::DREAMER_VERDICT_ROLE;
use oneiron::dreamer_promotion::AttemptPromotionSink;
use oneiron::dreamer_runner::DreamerDecisionLender;
use oneiron::llm::decision::{
    DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionCall, DecisionDial, DecisionProvider,
    DecisionRung, HeldLadder, ProviderDecision, ProviderPin,
};
use oneiron::llm::{AutoCheckCandidate, AutoCheckDecisions, BoundedAutoChecker};
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
type CheckerLoanTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Lets the test observe whether a loan rechecks the verdict route.
struct CountingCheckerGate {
    /// Records whether the host currently admits the verdict route.
    open: AtomicBool,
    /// Counts every live permission check.
    calls: AtomicUsize,
}

impl ExtractionDecisionGate for CountingCheckerGate {
    /// Reads the test host's permission at each loan.
    fn admits(&self) -> oneiron::Result<bool> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.open.load(Ordering::SeqCst))
    }
}

/// The host's decision head on the checker's Big rung: it allows every auto check.
struct AllowingCheckerHead;

impl DecisionProvider for AllowingCheckerHead {
    fn pin(&self) -> ProviderPin {
        ProviderPin {
            rung: DecisionRung::Big,
            model: "host-checker".into(),
            version: "1".into(),
        }
    }

    fn decide(&self, _call: &DecisionCall<'_>) -> Result<ProviderDecision, oneiron::Error> {
        Ok(ProviderDecision {
            answer: DecisionAnswer::Choice("allow".to_owned()),
            probability: Some(0.99),
            paired: None,
            person: None,
            served: None,
            cost_per_thousand: None,
        })
    }
}

/// The test checker's hold reasons, never read on the allow path.
struct CheckerTestNotes;

impl AutoCheckNotes for CheckerTestNotes {
    fn hold_reasons(
        &self,
        _candidate: &AutoCheckCandidate<'_>,
        _due: Instant,
    ) -> Result<Vec<String>, oneiron::Error> {
        Ok(vec!["checker: hedged verdict".to_owned()])
    }
}

/// The host's bounded checker over one allowing head, assembled as a host assembles it.
fn test_checker() -> BoundedAutoChecker {
    BoundedAutoChecker::new(AutoCheckDecisions {
        ladder: HeldLadder {
            big: Some(Arc::new(AllowingCheckerHead) as Arc<dyn DecisionProvider>),
            ..HeldLadder::unstaffed()
        },
        principal: EntityId::from_bytes([0x51; 16]).expect("test id"),
        dial: DecisionDial {
            first: DecisionRung::Big,
            ceiling: DecisionRung::Big,
            band: DecisionBand::default(),
        },
        bands: DecisionBandPolicy::default(),
        wording: "May this write land without the owner's review?".to_owned(),
        notes: Arc::new(CheckerTestNotes),
        calibrated: None,
        world_hold: None,
    })
}

/// The production lender lends the checker its resources hold, with no gate recheck, and none
/// when they hold none. The loaned deadline cannot be observed: `BoundedAutoChecker` exposes
/// no deadline accessor, so no door is added for it.
#[test]
fn production_lender_lends_the_checker_its_resources_hold() -> CheckerLoanTestResult<()> {
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
    let (_attempt, admitted) =
        enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, 1_000)?;
    let binding = vault.bind_dreamer_attempt(&admitted)?;
    let reasoner = Arc::new(ScriptedVerdictBackend);
    let fixture = ExtractionVerdictFixture::new(reasoner)?;
    let pass = fixture.pass_resources();
    let verdict = pass
        .roles
        .get(DREAMER_VERDICT_ROLE)
        .ok_or("the fixture routes its verdict role")?;
    let gate = Arc::new(CountingCheckerGate {
        open: AtomicBool::new(true),
        calls: AtomicUsize::new(0),
    });
    let mut holding = pass.decisions.clone();
    holding.checker = Some(test_checker());
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
    .with_decisions(holding)
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
    let loaned = lender.lend_auto_checker()?;
    assert!(
        loaned.is_some(),
        "the production lender lends the checker its resources hold"
    );
    assert_eq!(
        gate.calls.load(Ordering::SeqCst),
        0,
        "the checker loan rechecks no gate"
    );
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
    let lender = executor
        .extraction_lender(&context)
        .ok_or("the production factory prepares an extraction lender")?;
    assert!(
        lender.lend_auto_checker()?.is_none(),
        "the production lender lends none when its resources hold none"
    );
    assert_eq!(
        gate.calls.load(Ordering::SeqCst),
        0,
        "the empty loan rechecks no gate either"
    );
    Ok(())
}

/// Answers the fixture's verdict-role generations so the pass resources build.
struct ScriptedVerdictBackend;

impl LlmBackend for ScriptedVerdictBackend {
    /// Admits every capability the fixture's fixed model asks about.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    /// Answers from a per-request scripted backend.
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let backend = ScriptedBackend::new(vec![
                Step::text(
                    "verdict",
                    ScriptedBackend::digest_of(&request),
                    json!({"value": "tea"}).to_string(),
                )
                .buffered()
                .usage(100, 50),
            ])
            .map_err(|error| {
                LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                    message: format!("the verdict scripted backend did not build: {error}"),
                    code: None,
                })
            })?;
            backend.generate(request, lease).await
        })
    }

    /// Refuses streaming because this fixture only lends a checker.
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
