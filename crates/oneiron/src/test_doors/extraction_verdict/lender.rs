//! Provides the extraction verdict parity fixture for the base red run: the same public
//! API as the head door, compiled against the base tree with the red native adapter
//! snapshot.
//!
//! The base tree lends no extraction loan and observes no tally spend, so the lender
//! attaches through the base trait only and the spent and charge readers return empty.
//! The native leg still runs the real native oracle through the snapshot adapter with
//! its owned tally. The parity test fails at the bound leg with model unavailable.

use std::sync::Arc;

use serde_json::Value;
use tokio::runtime::{Builder, Runtime};

use crate::dreamer_consolidation::{
    ConsolidationDecisions, ConsolidationExecutor, DREAMER_VERDICT_ROLE, NativeFixtureMember,
    NativeResolutionFixture, RoleBackend, RoleBackends, native_resolution_snapshot_for_test,
};
use crate::dreamer_promotion::{DreamerRunContext, PromotionWriterSink};
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerAttemptBinding, DreamerConsolidationScope, DreamerDecisionLender,
};
use crate::dreamer_wake::WakePassDeadline;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::decision::{DecisionBandPolicy, DecisionLadder, TypedDecision};
use crate::llm::{HostInferenceBinding, HostInferenceContext};
use crate::model_step_error::DurableStepError;
use crate::vault::Vault;
use crate::verbs::ExtractionPack;
use crate::write_envelope::WriteActor;
use crate::{
    BudgetExhaustionPolicy, BudgetGuard, DreamerClaimAuthoringStrategy, LlmBackend, LlmRequest,
    ModelId, ModelLocality,
};

/// Holds one admitted extraction attempt's parity fixture for the base red run: the pass
/// resources the native leg reads under. The base tree shares no tally, so the fixture
/// holds none.
pub struct ExtractionVerdictFixture {
    /// Drives the read futures for the native leg.
    runtime: Runtime,
    /// Guards the attempt's pass, as the consolidation door guards its pass.
    guard: BudgetGuard,
    /// Reads the native leg under the shipped ladder, dial, bands and wording.
    decisions: ConsolidationDecisions,
    /// Names the verdict model the native leg uses.
    model: ModelId,
    /// Admits the native leg under the advertised host binding.
    binding: HostInferenceBinding,
    /// Routes the verdict role to the scripted reasoner.
    reasoner: Arc<dyn LlmBackend>,
    /// Bounds the native leg with the attempt's frozen pass deadline.
    deadline: WakePassDeadline,
    /// Freezes the attempt's Unix time in milliseconds for the native leg.
    now_ms: u64,
}

impl ExtractionVerdictFixture {
    /// Builds the fixture around `reasoner` and shares it with the test: a
    /// current-thread runtime, the pass guard, the shipped decisions, the fixture model
    /// with its advertised binding and the frozen pass clock.
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
/// outcome. The base tree shares no tally, so the pack carries no spend.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractionVerdictNativePack {
    /// Holds every kept answer in pack order.
    pub answers: Vec<NativePackAnswer>,
    /// Holds the resolution the pack read, when it read one.
    pub resolution: Option<String>,
    /// Holds the identity a merge or supersede keeps, as 32 lowercase hexadecimal
    /// digits, when one was asked.
    pub identity: Option<String>,
    /// Holds no spend: the native snapshot's spend stays unobserved without a shared
    /// tally.
    pub spent: Vec<NativePackSpent>,
    /// Holds zero: the base tree shares no tally.
    pub tally_units: u64,
    /// Holds zero: the base tree shares no tally.
    pub tally_bindings: usize,
}

/// Attaches through the base lender trait only: the base tree lends no extraction loan.
struct FixtureExtractionLender;

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
}

/// Attaches `binding` under the base lender trait: the base tree lends no extraction
/// loan, so the bound leg refuses model unavailable.
pub fn attach_extraction_verdict_lender(
    binding: DreamerAttemptBinding,
    _fixture: &Arc<ExtractionVerdictFixture>,
) -> DreamerAttemptBinding {
    binding.lend_decisions(Arc::new(FixtureExtractionLender))
}

/// Runs the native resolution oracle for `pack`'s operands on `admitted` and returns
/// every kept answer in pack order with the parsed outcome. The oracle assembles each
/// operand with the shared native candidate assembly and id law, verifies it against
/// the native branch opened for the attempt, and decides the one conflict through the
/// native wrapper. The snapshot adapter records the spend into its owned tally; the base
/// tree shares no tally, so the test reads no observations here.
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
    let outcome = fixture
        .runtime
        .handle()
        .block_on(native_resolution_snapshot_for_test(params));
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
    Ok(ExtractionVerdictNativePack {
        answers,
        resolution: outcome.resolution,
        identity: outcome.identity.map(|id| id.to_hex()),
        spent: Vec::new(),
        tally_units: 0,
        tally_bindings: 0,
    })
}

/// Returns no observations: the base tally records none, and the parity test fails at
/// the bound leg before reading any.
pub fn fixture_spent_observations(_fixture: &ExtractionVerdictFixture) -> Vec<NativePackSpent> {
    Vec::new()
}

/// Returns zero: the base tree shares no tally, and the parity test fails at the bound
/// leg before reading any charge.
pub fn fixture_charge_units(_fixture: &ExtractionVerdictFixture) -> u64 {
    0
}

/// Returns zero: the base tree shares no tally, and the parity test fails at the bound
/// leg before reading any charge.
pub fn fixture_charge_binding_count(_fixture: &ExtractionVerdictFixture) -> usize {
    0
}

/// Lets the fixture verdict run on this server: every request is admitted.
fn allow_extraction_verdict_egress(_: &LlmRequest) -> bool {
    true
}
