//! The production extraction lender states the destination bound of the wake its attempt
//! context carries (FIX row BOUND-PACK-AND-PAGE-DESTINATION-NO-TEST). The engine rebuilds every
//! lent extraction listing for the bound the lender states, so the lent step, the observations
//! page and the verdict pack check list what the pass's native extraction listed only while the
//! lender copies the bound the wake's listings were read for
//! (`supervisor/extraction_decisions.rs` `ExtractionAttemptLender::new`). No driver test built a
//! wake for a bound, so the copy was right by reading only. The core door
//! `test_doors::extraction_wake::prepare_extraction_wake_for_bound` prepares one.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-driver --all-features --test dreamer_extraction_lender_destination`.
#![cfg(oneiron_test_support)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use oneiron::dreamer_consolidation::{DREAMER_VERDICT_ROLE, PreparedWake};
use oneiron::dreamer_promotion::AttemptPromotionSink;
use oneiron::dreamer_runner::{DreamerAdmittedAttempt, DreamerDecisionLender};
use oneiron::settings::ReadDestination;
use oneiron::test_doors::consolidation::open_dreamer_vault;
use oneiron::test_doors::extraction_inputs::{
    enqueue_admitted_extraction_attempt, witness_extraction_turns,
};
use oneiron::test_doors::extraction_verdict::ExtractionVerdictFixture;
use oneiron::test_doors::extraction_wake::prepare_extraction_wake_for_bound;
use oneiron::test_doors::steward::{STEWARD_VERBS, dreamer, stand_steward_grant};
use oneiron::test_doors::untangle_regressions::seed_named_person;
use oneiron::{
    AttemptId, BudgetLease, DreamerClaimAuthoringStrategy, EntityId, FatalLlmError, LlmBackend,
    LlmCapability, LlmError, LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId,
    UnsupportedCapability, Vault, VaultConfig, WakeAttemptContext,
};
use oneiron_driver::{ConsolidationExecutorFactory, ExtractionDecisionGate, PassExecutorFactory};

/// Returns fixture failures without hiding their source.
type LenderDestinationTestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Admits every extraction loan: the lender is built, never lent here.
struct OpenExtractionGate {
    /// Records that the gate stays open.
    open: AtomicBool,
}

impl ExtractionDecisionGate for OpenExtractionGate {
    /// Admits a loan while open.
    fn admits(&self) -> oneiron::Result<bool> {
        Ok(self.open.load(Ordering::SeqCst))
    }
}

/// Refuses every generation: building a lender asks no model.
struct RefusingVerdictBackend;

impl LlmBackend for RefusingVerdictBackend {
    /// Admits every capability the fixture's fixed model asks about.
    fn supports(&self, _model: &ModelId, _capability: LlmCapability) -> bool {
        true
    }

    /// Refuses the generation by name.
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            Err(LlmError::Fatal(FatalLlmError::InvalidRequestDetail {
                message: "building an extraction lender must never call its verdict backend"
                    .to_owned(),
                code: None,
            }))
        })
    }

    /// Refuses streaming.
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

/// One admitted Meso extraction attempt over one witnessed turn that names owen.
struct AdmittedFixture {
    /// Owns the temporary directory for the lifetime of the vault.
    _directory: tempfile::TempDir,
    /// Holds the vault the wake and the factory read.
    vault: Arc<Vault>,
    /// Holds the admitted attempt's id.
    attempt: AttemptId,
    /// Holds the admission the binding binds from.
    admitted: DreamerAdmittedAttempt,
}

/// Opens a Dreamer vault, stands the Steward grant, seeds owen, witnesses one turn and admits
/// one Meso attempt over it.
fn admitted_fixture() -> LenderDestinationTestResult<AdmittedFixture> {
    let directory = tempfile::tempdir()?;
    drop(open_dreamer_vault(directory.path(), "owen")?);
    let vault = Vault::open_owned(directory.path(), VaultConfig::device())?;
    oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_embedded_owner_actor()?;
    let vault = Arc::new(vault);
    stand_steward_grant(&vault, dreamer(&vault)?, &STEWARD_VERBS)?;
    let subject = EntityId::now();
    seed_named_person(&vault, &subject, "owen", vault.now_recorded_at())?;
    let witnessed = witness_extraction_turns(&vault, &["owen likes tea"])?;
    let (attempt, admitted) = enqueue_admitted_extraction_attempt(&vault, &witnessed.turns, 1_000)?;
    Ok(AdmittedFixture {
        _directory: directory,
        vault,
        attempt,
        admitted,
    })
}

/// The bounds one attempt context and the lender built for it state.
struct StatedBounds {
    /// Holds the bound the attempt context reads from its wake.
    context: Option<ReadDestination>,
    /// Holds the bound the production extraction lender states.
    lender: Option<ReadDestination>,
}

/// Builds the production extraction lender for an attempt context that carries `wake`, and
/// returns the bound the context states beside the one the lender states.
fn stated_bounds(
    fixture: &AdmittedFixture,
    wake: Option<&PreparedWake>,
) -> LenderDestinationTestResult<StatedBounds> {
    let binding = fixture.vault.bind_dreamer_attempt(&fixture.admitted)?;
    let verdict_fixture = ExtractionVerdictFixture::new(Arc::new(RefusingVerdictBackend))?;
    let pass = verdict_fixture.pass_resources();
    let verdict = pass
        .roles
        .get(DREAMER_VERDICT_ROLE)
        .ok_or("FIXTURE: the fixture routes its verdict role")?;
    let gate = Arc::new(OpenExtractionGate {
        open: AtomicBool::new(true),
    });
    let mut factory = ConsolidationExecutorFactory::new(
        Arc::clone(&verdict.backend),
        DreamerClaimAuthoringStrategy::SinglePass,
        binding.actor(),
        verdict.model.clone(),
        verdict.binding.clone(),
        Some(Arc::new(|_: &LlmRequest| true)),
        Box::new(AttemptPromotionSink::new(Arc::clone(&fixture.vault))),
    )
    .with_role_backends(pass.roles.clone())
    .with_decisions(pass.decisions.clone())
    .with_dreamer_job_vault(Arc::clone(&fixture.vault))
    .with_extraction_decisions(gate, pass.runtime.clone());
    let executor = factory.executor(&pass.guard)?;
    let context = WakeAttemptContext {
        vault: &fixture.vault,
        deadline: &pass.deadline,
        cancel: None,
        device_cancel: None,
        budget_id: "extraction-inputs",
        now_ms: pass.now_ms,
        prepared_wake: wake,
        prepared_attempt: None,
        spend_meter: None,
    };
    let lender = executor
        .extraction_lender(&context)
        .ok_or("FIXTURE: the production factory prepares an extraction lender")?;
    Ok(StatedBounds {
        context: context.destination_bound().cloned(),
        lender: DreamerDecisionLender::destination_bound(&*lender),
    })
}

/// A wake prepared for this device: the lender states this device, the bound its listings were
/// read for.
#[test]
fn the_extraction_lender_states_the_bound_of_its_wake() -> LenderDestinationTestResult<()> {
    let fixture = admitted_fixture()?;
    let on_device = ReadDestination::on_device();
    let wake =
        prepare_extraction_wake_for_bound(&fixture.vault, fixture.attempt, Some(&on_device))?;
    let stated = stated_bounds(&fixture, Some(&wake))?;
    assert_eq!(
        stated.context,
        Some(on_device.clone()),
        "FIXTURE: the context reads this device from its wake"
    );
    assert_eq!(
        stated.lender,
        Some(on_device),
        "the lender states the bound its wake's listings were read for"
    );
    Ok(())
}

/// A wake prepared with no stated bound, and a context with no wake: the lender states none.
#[test]
fn the_extraction_lender_states_no_bound_without_one_on_its_wake() -> LenderDestinationTestResult<()>
{
    let fixture = admitted_fixture()?;
    let wake = prepare_extraction_wake_for_bound(&fixture.vault, fixture.attempt, None)?;
    let unbound = stated_bounds(&fixture, Some(&wake))?;
    assert_eq!(unbound.context, None, "FIXTURE: the wake states no bound");
    assert_eq!(
        unbound.lender, None,
        "a wake that states no bound gives the lender none"
    );
    assert_eq!(
        stated_bounds(&fixture, None)?.lender,
        None,
        "a context with no wake gives the lender none"
    );
    Ok(())
}
