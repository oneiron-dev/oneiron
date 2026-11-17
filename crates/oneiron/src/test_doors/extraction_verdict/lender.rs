//! Provides the extraction verdict parity fixture, which lends scripted extraction
//! resources to one admitted attempt and runs the native oracle leg the parity test
//! compares against the bound verdict.
//!
//! The fixture owns the pass resources both legs share: a current-thread tokio runtime
//! driving the read futures, the pass guard, the shipped consolidation decisions, the
//! verdict model with its advertised host binding, the injected reasoner backend, the
//! frozen pass deadline and clock, and the shared native charge tally recording both
//! legs' spend. The lender resolves the verdict role the native way and runs the
//! engine's callback; it never fabricates a decision. The native leg builds a
//! consolidation executor over the same parts and runs the native resolution oracle over
//! the same pack operands, returning plain answers the test compares against the bound
//! pack entries.
//!
//! Production hosts lend an independent live multi-thread runtime. The fixture's
//! current-thread runtime only drives the zero-latency scripted backend on the engine's
//! scoped read thread and on the test thread for the native leg, sequentially; it never
//! enters a runtime on a calling thread that already runs one.

use std::sync::{Arc, Mutex, PoisonError};

use serde_json::Value;
use tokio::runtime::{Builder, Runtime};

use crate::dreamer_consolidation::{
    ConsolidationDecisions, ConsolidationExecutor, DREAMER_VERDICT_ROLE, NativeFixtureMember,
    NativeResolutionFixture, RoleBackend, RoleBackends, RoleCall, StepChargeTally,
    native_resolution_pack_for_test,
};
use crate::dreamer_promotion::{DreamerRunContext, PromotionWriterSink};
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptBinding, DreamerConsolidationScope,
    DreamerDecisionLender, ExtractionDecisionLoan,
};
use crate::dreamer_wake::WakePassDeadline;
use crate::edge::EdgeActorClass;
use crate::entity_id::{EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::llm::decision::{DecisionBandPolicy, DecisionLadder, TypedDecision};
use crate::llm::{HostInferenceBinding, HostInferenceContext};
use crate::memory::MemoryResult;
use crate::model_step_error::DurableStepError;
use crate::vault::Vault;
use crate::verbs::{AiVerdict, ExtractionPack};
use crate::write_envelope::WriteActor;
use crate::{
    BudgetExhaustionPolicy, BudgetGuard, DreamerClaimAuthoringStrategy, LlmBackend, LlmRequest,
    ModelId, ModelLocality,
};

/// Holds one admitted extraction attempt's parity fixture: the pass resources both legs
/// share.
pub struct ExtractionVerdictFixture {
    /// Drives the read futures and lends its handle to the loan.
    runtime: Runtime,
    /// Guards the attempt's pass, as the consolidation door guards its pass.
    guard: BudgetGuard,
    /// Reads both legs under the shipped ladder, dial, bands and wording.
    decisions: ConsolidationDecisions,
    /// Names the verdict model both legs use.
    model: ModelId,
    /// Admits both legs under the advertised host binding.
    binding: HostInferenceBinding,
    /// Routes the verdict role to the scripted reasoner.
    reasoner: Arc<dyn LlmBackend>,
    /// Bounds both legs with the attempt's frozen pass deadline.
    deadline: WakePassDeadline,
    /// Freezes the attempt's Unix time in milliseconds for both legs.
    now_ms: u64,
    /// Records both legs' spend in the attempt's shared native tally.
    charges: Mutex<StepChargeTally>,
}

/// Shares the parity fixture's prepared pass resources with a host-lender integration test.
pub struct ExtractionVerdictPassResources {
    /// Holds the fixture's actual native decisions and wording.
    pub decisions: ConsolidationDecisions,
    /// Routes the verdict role to the fixture's injected scripted backend.
    pub roles: RoleBackends,
    /// Shares the fixture pass's original budget state.
    pub guard: BudgetGuard,
    /// Preserves the fixture attempt's original clock and finalize window.
    pub deadline: WakePassDeadline,
    /// Holds the fixture attempt's frozen Unix time in milliseconds.
    pub now_ms: u64,
    /// Borrows runtime ownership from the fixture retained by the test.
    pub runtime: tokio::runtime::Handle,
}

impl ExtractionVerdictFixture {
    /// Shares the existing fixture's resources without installing its fixture lender.
    #[must_use]
    pub fn pass_resources(&self) -> ExtractionVerdictPassResources {
        ExtractionVerdictPassResources {
            decisions: self.decisions.clone(),
            roles: RoleBackends::default().with(
                DREAMER_VERDICT_ROLE,
                RoleBackend {
                    backend: Arc::clone(&self.reasoner),
                    model: self.model.clone(),
                    binding: self.binding.clone(),
                    sourced: None,
                },
            ),
            guard: self.guard.clone(),
            deadline: self.deadline.clone(),
            now_ms: self.now_ms,
            runtime: self.runtime.handle().clone(),
        }
    }

    /// Builds the fixture around `reasoner` and shares it for the lender to own: a
    /// current-thread runtime, the pass guard, the shipped decisions, the fixture model
    /// with its advertised binding, the frozen pass clock and an empty shared tally.
    ///
    /// # Errors
    ///
    /// A runtime that does not build, shipped wording that does not read, or a fixture
    /// model id that does not parse.
    pub fn new(reasoner: Arc<dyn LlmBackend>) -> Result<Arc<Self>> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| {
                Error::InvalidConfig(format!(
                    "the verdict fixture runtime did not build: {error}"
                ))
            })?;
        let guard = BudgetGuard::with_reserve_units(
            "extraction-inputs",
            10_000,
            100,
            BudgetExhaustionPolicy::Suspend,
        );
        let decisions = ConsolidationDecisions::shipped()?;
        let model = ModelId::new("test/model@r1").map_err(|_| {
            Error::InvalidConfig("the verdict fixture model id did not parse".into())
        })?;
        let binding = HostInferenceBinding::Advertised {
            model: model.clone(),
            locality: ModelLocality::OwnServer,
            keyless: false,
        };
        let deadline = WakePassDeadline::with_clock(180_000, Arc::new(|| 0));
        Ok(Arc::new(Self {
            runtime,
            guard,
            decisions,
            model,
            binding,
            reasoner,
            deadline,
            now_ms: 1_000_000,
            charges: Mutex::new(StepChargeTally::new()),
        }))
    }
}

/// Carries one native pack answer in pack order, as JSON the test compares field by
/// field.
#[derive(Debug, Clone, PartialEq)]
pub struct NativePackAnswer {
    /// Numbers the answer's pack position, starting at zero.
    pub question_index: usize,
    /// Holds the ladder answer on the question contract.
    pub answer: Value,
    /// Holds the answer probability, none when the question abstained.
    pub p: Option<f64>,
    /// Holds the rung whose answer stands, none when the question abstained.
    pub rung: Value,
    /// Names the typed question answered, as 32 lowercase hexadecimal digits.
    pub question_id: String,
    /// Holds the native decision receipt for the question.
    pub receipt: Value,
}

/// Carries one spent generation in plain form: its request hash, durable binding, memo
/// flag and usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePackSpent {
    /// Holds the spent request hash, as 64 lowercase hexadecimal digits.
    pub request_hash_hex: String,
    /// Holds the durable step hash claimed, as 64 lowercase hexadecimal digits, when one
    /// was claimed.
    pub step_hash_hex: Option<String>,
    /// Holds the attempt the spend claimed under, as 32 lowercase hexadecimal digits,
    /// when one was claimed.
    pub attempt_hex: Option<String>,
    /// Records whether the spend replayed a memoized response.
    pub memoized: bool,
    /// Holds the spent call's input token total.
    pub input_total: u64,
    /// Holds the spent call's output token total.
    pub output_total: u64,
}

/// Carries what the native oracle leg read: every pack answer in order with the parsed
/// outcome, and the spend the native leg accounted.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractionVerdictNativePack {
    /// Holds every kept answer in pack order.
    pub answers: Vec<NativePackAnswer>,
    /// Holds the resolution the pack read, when it read one.
    pub resolution: Option<String>,
    /// Holds the identity a merge or supersede keeps, as 32 lowercase hexadecimal
    /// digits, when one was asked.
    pub identity: Option<String>,
    /// Holds the spend the native leg accounted, in order.
    pub spent: Vec<NativePackSpent>,
    /// Holds the units the shared tally charged after the native leg.
    pub tally_units: u64,
    /// Holds the terminal step binding count the shared tally held after the native leg.
    pub tally_bindings: usize,
}

/// Lends the fixture's resources to extraction reads: it resolves the verdict role the
/// native way and runs the engine's callback with the fixture's borrowed resources.
struct FixtureExtractionLender {
    /// Owns the fixture holding the lent resources.
    fixture: Arc<ExtractionVerdictFixture>,
}

impl DreamerDecisionLender for FixtureExtractionLender {
    /// Refuses settlement lends: the fixture lends extraction reads only.
    fn lend(
        &self,
        _decide: &mut dyn FnMut(
            &DecisionLadder<'_>,
            &DecisionBandPolicy,
        ) -> crate::Result<TypedDecision>,
    ) -> crate::Result<TypedDecision> {
        Err(Error::InvalidConfig(
            "the verdict fixture lends extraction reads only".into(),
        ))
    }

    /// Resolves the verdict role through the native role routing and runs the engine's
    /// read with the fixture's borrowed resources.
    fn lend_extraction(
        &self,
        decide: &mut dyn FnMut(ExtractionDecisionLoan<'_>) -> MemoryResult<AiVerdict>,
    ) -> MemoryResult<Option<AiVerdict>> {
        let fixture = &*self.fixture;
        let roles = RoleBackends::default().with(
            DREAMER_VERDICT_ROLE,
            RoleBackend {
                backend: Arc::clone(&fixture.reasoner),
                model: fixture.model.clone(),
                binding: fixture.binding.clone(),
                sourced: None,
            },
        );
        let call = RoleCall::resolve(
            &roles,
            DREAMER_VERDICT_ROLE,
            fixture.reasoner.as_ref(),
            &fixture.model,
            &fixture.binding,
            Some(&allow_extraction_verdict_egress),
        );
        decide(ExtractionDecisionLoan {
            decisions: &fixture.decisions,
            call,
            guard: &fixture.guard,
            deadline: &fixture.deadline,
            now_ms: fixture.now_ms,
            charges: &fixture.charges,
            runtime: fixture.runtime.handle(),
        })
        .map(Some)
    }
}

/// Lends the fixture's extraction resources to `binding` for its verdict calls.
pub fn attach_extraction_verdict_lender(
    binding: DreamerAttemptBinding,
    fixture: &Arc<ExtractionVerdictFixture>,
) -> DreamerAttemptBinding {
    binding.lend_decisions(Arc::new(FixtureExtractionLender {
        fixture: Arc::clone(fixture),
    }))
}

/// Runs the native resolution oracle for `pack`'s operands on `admitted` and returns
/// every kept answer in pack order with the parsed outcome. The oracle assembles each
/// operand with the shared native candidate assembly and id law, verifies it against
/// the native branch opened for the attempt, and decides the one conflict through the
/// native wrapper. The pack carries the spend the native leg accounted: the spent
/// entries, units and binding count read from the shared tally immediately after the
/// native leg, before the bound leg replays the same generation from its memo.
///
/// The pack carries same-predicate operands with no relationship, topic, corrected
/// claim, priors or listed claims, as the parity fixture witnesses it.
///
/// # Errors
///
/// A pack that is not an extraction pack, operands outside the fixture shape, an
/// attempt without recorded authority or run, the native read's own failures, or a
/// trapped read. A trapped read parks without an answer and fails the parity comparison
/// honestly.
pub fn run_extraction_verdict_native_pack(
    vault: &Vault,
    admitted: &DreamerAdmittedAttempt,
    pack: &Value,
    fixture: &ExtractionVerdictFixture,
) -> Result<ExtractionVerdictNativePack> {
    let pack: ExtractionPack = serde_json::from_value(pack.clone()).map_err(|error| {
        Error::InvalidConfig(format!(
            "the parity fixture pack is not an extraction pack: {error}"
        ))
    })?;
    if !pack.priors.is_empty() || !pack.listed.is_empty() {
        return Err(Error::InvalidConfig(
            "the parity fixture pack names no priors or listed claims".into(),
        ));
    }
    let mut members = Vec::with_capacity(pack.candidates.len());
    for candidate in &pack.candidates {
        if candidate.rel.is_some() || candidate.topic.is_some() || candidate.corrects.is_some() {
            return Err(Error::InvalidConfig(
                "the parity fixture candidates carry no relationship, topic or corrected claim"
                    .into(),
            ));
        }
        let subject = EntityId::from_hex(&candidate.subject).map_err(|_| {
            Error::InvalidConfig("the parity fixture subject is not 32 lowercase hex digits".into())
        })?;
        if candidate.evidence.is_empty() {
            return Err(Error::InvalidConfig(
                "each parity fixture candidate cites a turn".into(),
            ));
        }
        let mut turns = Vec::with_capacity(candidate.evidence.len());
        for cited in &candidate.evidence {
            turns.push(EntityId::from_hex(&cited.turn).map_err(|_| {
                Error::InvalidConfig(
                    "the parity fixture turn reference is not 32 lowercase hex digits".into(),
                )
            })?);
        }
        members.push(NativeFixtureMember {
            subject,
            predicate: candidate.predicate.clone(),
            value: candidate.value.clone(),
            turns,
        });
    }
    if members.is_empty() {
        return Err(Error::InvalidConfig(
            "the parity fixture pack names no members".into(),
        ));
    }
    let attempt = admitted.status.attempt.id;
    let run = admitted.status.attempt.run_id.clone();
    let actor = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        vault
            .dreamer_attempt_authority_in_txn(&txn, attempt)?
            .ok_or_else(|| {
                Error::InvalidConfig("the parity fixture attempt has no recorded authority".into())
            })?
            .actor
    };
    let actor = WriteActor::new(actor, EdgeActorClass::System);
    let mut sink = PromotionWriterSink::new(
        vault,
        DreamerRunContext {
            run_id: run.clone().ok_or_else(|| {
                Error::InvalidConfig("the parity fixture attempt has no recorded run".into())
            })?,
            attempt_id: attempt,
            agent_actor: actor,
            now_ms: fixture.now_ms,
        },
    );
    let roles = RoleBackends::default().with(
        DREAMER_VERDICT_ROLE,
        RoleBackend {
            backend: Arc::clone(&fixture.reasoner),
            model: fixture.model.clone(),
            binding: fixture.binding.clone(),
            sourced: None,
        },
    );
    let inference = HostInferenceContext {
        binding: fixture.binding.clone(),
        extraction_egress: Some(&allow_extraction_verdict_egress),
    };
    let executor = ConsolidationExecutor {
        roles,
        backend: fixture.reasoner.as_ref(),
        guard: &fixture.guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor,
        model: fixture.model.clone(),
        inference,
        sink: &mut sink,
        scope: None,
        decisions: fixture.decisions.clone(),
    };
    let params = NativeResolutionFixture {
        vault,
        executor: &executor,
        attempt,
        run,
        actor,
        scope: DreamerConsolidationScope::Meso,
        pass: &fixture.deadline,
        now_ms: fixture.now_ms,
        members,
        prior_ids: Vec::new(),
    };
    // The native oracle holds the tally across its read, as a native pass holds its own;
    // the test owns the fixture alone, so no other thread contends for this lock.
    let mut charges = fixture
        .charges
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let outcome = fixture
        .runtime
        .handle()
        .block_on(native_resolution_pack_for_test(params, &mut charges));
    drop(charges);
    let outcome = match outcome {
        Ok(Some(outcome)) => outcome,
        Ok(None) => {
            return Err(Error::InvalidConfig(
                "the native parity pack trapped without an answer".into(),
            ));
        }
        Err(DurableStepError::Engine(error)) => return Err(error),
        Err(error) => {
            return Err(Error::InvalidConfig(format!(
                "the native parity pack failed: {error}"
            )));
        }
    };
    let mut answers = Vec::with_capacity(outcome.decisions.len());
    for (index, kept) in outcome.decisions.into_iter().enumerate() {
        let decision = kept.decision;
        let rung = decision
            .receipt
            .time
            .as_ref()
            .and_then(|time| time.answered);
        answers.push(NativePackAnswer {
            question_index: index,
            answer: serde_json::to_value(&decision.answer).map_err(|error| {
                Error::InvalidConfig(format!("the native parity answer did not encode: {error}"))
            })?,
            p: decision.probability,
            rung: serde_json::to_value(&rung).map_err(|error| {
                Error::InvalidConfig(format!("the native parity rung did not encode: {error}"))
            })?,
            question_id: decision.receipt.question.to_hex(),
            receipt: serde_json::to_value(&decision.receipt).map_err(|error| {
                Error::InvalidConfig(format!("the native parity receipt did not encode: {error}"))
            })?,
        });
    }
    let spent = fixture_spent_observations(fixture);
    let tally_units = fixture_charge_units(fixture);
    let tally_bindings = fixture_charge_binding_count(fixture);
    Ok(ExtractionVerdictNativePack {
        answers,
        resolution: outcome.resolution,
        identity: outcome.identity.map(|id| id.to_hex()),
        spent,
        tally_units,
        tally_bindings,
    })
}

/// Returns every spent generation both legs accounted, in order: the native spend
/// first, then the bound spend replaying it.
pub fn fixture_spent_observations(fixture: &ExtractionVerdictFixture) -> Vec<NativePackSpent> {
    fixture
        .charges
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .spent_observations()
        .iter()
        .map(|observed| NativePackSpent {
            request_hash_hex: bytes_to_hex_lower(&observed.hash),
            step_hash_hex: observed
                .binding
                .map(|binding| bytes_to_hex_lower(&binding.step_hash)),
            attempt_hex: observed
                .binding
                .map(|binding| bytes_to_hex_lower(binding.attempt_id.as_bytes())),
            memoized: observed.memoized,
            input_total: observed.usage.input.total,
            output_total: observed.usage.output.total,
        })
        .collect()
}

/// Returns the units the fixture's shared tally charged.
pub fn fixture_charge_units(fixture: &ExtractionVerdictFixture) -> u64 {
    fixture
        .charges
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .units()
}

/// Counts the terminal step bindings the fixture's shared tally holds.
pub fn fixture_charge_binding_count(fixture: &ExtractionVerdictFixture) -> usize {
    fixture
        .charges
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .step_bindings()
        .len()
}

/// Lets the fixture verdict run on this server: every request is admitted.
fn allow_extraction_verdict_egress(_: &LlmRequest) -> bool {
    true
}
