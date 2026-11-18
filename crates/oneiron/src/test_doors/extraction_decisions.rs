//! Native extraction decision oracle door for the decision parity test.
//!
//! Runs one reply's corrections, assembly and conflict packs through native code and returns plain answers the test compares against the crate's decisions.

use std::sync::PoisonError;

use serde_json::Value;

use super::extraction_verdict::{
    ExtractionVerdictFixture, ExtractionVerdictPassResources, NativePackAnswer, NativePackSpent,
    fixture_charge_binding_count, fixture_charge_units, fixture_spent_observations,
};
use crate::LlmRequest;
use crate::dreamer_consolidation::{
    ConsolidationExecutor, KeptDecision, NativeDecisionsFixture, NativeDecisionsOutcome,
    native_extraction_decisions_for_test,
};
use crate::dreamer_promotion::{DreamerRunContext, PromotionWriterSink};
use crate::dreamer_runner::{
    DreamerAdmittedAttempt, DreamerClaimAuthoringStrategy, DreamerConsolidationScope,
};
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::HostInferenceContext;
use crate::model_step_error::DurableStepError;
use crate::vault::Vault;
use crate::verbs::CandidateOperand;
use crate::write_envelope::WriteActor;

/// Carries one operand's native correction in operand order.
pub struct NativeOperandCorrection {
    /// Holds the operand position in the complete array.
    pub position: usize,
    /// Holds the listed head it corrects as 32 lowercase hex digits, when it corrects one.
    pub corrects: Option<String>,
    /// Holds its correction pack answers in pack order.
    pub decisions: Vec<NativePackAnswer>,
}

/// Carries one assembled candidate in ready order.
pub struct NativeAssembledCandidate {
    /// Holds the assembled position in ready order.
    pub position: usize,
    /// Holds the native claim as 32 lowercase hex digits.
    pub claim: String,
}

/// Carries one conflict's native outcome.
pub enum NativeSetOutcome {
    /// Records a no-model skip with which rules hold.
    Skipped {
        /// Tells whether the single-valued fast path holds.
        fast_path: bool,
        /// Tells whether the bound correction holds.
        bound_correction: bool,
    },
    /// Records a decided pack.
    Decided {
        /// Holds the resolution the pack read, when it read one.
        resolution: Option<String>,
        /// Holds the kept identity as 32 lowercase hex digits, when one was asked.
        identity: Option<String>,
        /// Holds every kept answer in pack order.
        decisions: Vec<NativePackAnswer>,
    },
}

/// Carries one conflict in assembled order.
pub struct NativeConflictOutcome {
    /// Holds the member claims as 32 lowercase hex digits in conflict order.
    pub members: Vec<String>,
    /// Holds the prior heads as 32 lowercase hex digits in native order.
    pub prior_heads: Vec<String>,
    /// Holds the single prior head as 32 lowercase hex digits, when exactly one exists.
    pub prior_head: Option<String>,
    /// Holds the skipped or decided outcome.
    pub outcome: NativeSetOutcome,
}

/// Carries what the native oracle decided for one reply with the spend it accounted.
pub struct NativeExtractionDecisions {
    /// Holds one correction per operand in operand order.
    pub corrections: Vec<NativeOperandCorrection>,
    /// Holds the assembled candidates in ready order.
    pub assembled: Vec<NativeAssembledCandidate>,
    /// Holds every conflict in assembled order.
    pub conflicts: Vec<NativeConflictOutcome>,
    /// Holds the spend the native leg accounted, in order.
    pub spent: Vec<NativePackSpent>,
    /// Holds the units the shared tally charged after the native leg.
    pub tally_units: u64,
    /// Holds the terminal step binding count the shared tally held after the native leg.
    pub tally_bindings: usize,
}

/// Runs the native decision oracle for `operands` on `admitted` and returns every correction, assembled candidate and conflict with the native spend.
///
/// The operands are the complete array without corrections, as the crate's decision operands give them. The oracle opens the attempt's native branch, decides corrections, builds and assembles, then decides each conflict through the real skip checks and pack. It changes no stored claim.
///
/// # Errors
///
/// Operands that do not decode, carry a correction, name no operand, an attempt without recorded authority or run, the native reads' own failures, or a trapped read.
pub fn run_native_extraction_decisions(
    vault: &Vault,
    admitted: &DreamerAdmittedAttempt,
    operands: &[Value],
    now_ms: u64,
    fixture: &ExtractionVerdictFixture,
) -> Result<NativeExtractionDecisions> {
    let typed = decode_operands(operands)?;
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
    let ExtractionVerdictPassResources {
        decisions,
        roles,
        guard,
        deadline,
        runtime,
        ..
    } = fixture.pass_resources();
    let (reasoner, model, binding) = fixture.extraction_route();
    let mut sink = PromotionWriterSink::new(
        vault,
        DreamerRunContext {
            run_id: run.clone().ok_or_else(|| {
                Error::InvalidConfig("the parity fixture attempt has no recorded run".into())
            })?,
            attempt_id: attempt,
            agent_actor: actor,
            now_ms,
        },
    );
    let executor = ConsolidationExecutor {
        roles,
        backend: reasoner.as_ref(),
        guard: &guard,
        strategy: DreamerClaimAuthoringStrategy::SinglePass,
        actor,
        model,
        inference: HostInferenceContext {
            binding,
            extraction_egress: Some(&allow_native_decisions_egress),
        },
        sink: &mut sink,
        scope: None,
        decisions,
    };
    let params = NativeDecisionsFixture {
        vault,
        executor: &executor,
        attempt,
        run,
        actor,
        scope: DreamerConsolidationScope::Meso,
        pass: &deadline,
        now_ms,
        operands: typed,
    };
    // The native oracle holds the tally across its reads, as a native pass holds its own;
    // the test owns the fixture alone, so no other thread contends for this lock.
    let mut charges = fixture
        .charges()
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let outcome = runtime.block_on(native_extraction_decisions_for_test(params, &mut charges));
    drop(charges);
    let outcome = match outcome {
        Ok(Some(outcome)) => outcome,
        Ok(None) => {
            return Err(Error::InvalidConfig(
                "the native parity decisions trapped without an answer".into(),
            ));
        }
        Err(DurableStepError::Engine(error)) => return Err(error),
        Err(error) => {
            return Err(Error::InvalidConfig(format!(
                "the native parity decisions failed: {error}"
            )));
        }
    };
    plain_outcome(outcome, fixture)
}

/// Decodes the complete operand array, refusing an empty one and any operand that already carries a correction.
fn decode_operands(operands: &[Value]) -> Result<Vec<CandidateOperand>> {
    let mut typed = Vec::with_capacity(operands.len());
    for operand in operands {
        let decoded: CandidateOperand =
            serde_json::from_value(operand.clone()).map_err(|error| {
                Error::InvalidConfig(format!(
                    "the parity fixture operand is not an operand: {error}"
                ))
            })?;
        if decoded.corrects.is_some() {
            return Err(Error::InvalidConfig(
                "the parity fixture operands carry no corrections".into(),
            ));
        }
        typed.push(decoded);
    }
    if typed.is_empty() {
        return Err(Error::InvalidConfig(
            "the parity fixture names no operands".into(),
        ));
    }
    Ok(typed)
}

/// Converts the oracle outcome to plain rows beside the spend the fixture accounted: ids as 32 lowercase hex digits, kept decisions as pack answers.
fn plain_outcome(
    outcome: NativeDecisionsOutcome,
    fixture: &ExtractionVerdictFixture,
) -> Result<NativeExtractionDecisions> {
    let mut corrections = Vec::with_capacity(outcome.corrections.len());
    for row in outcome.corrections {
        corrections.push(NativeOperandCorrection {
            position: row.position,
            corrects: row.corrects.map(|id| id.to_hex()),
            decisions: pack_answers(row.decisions)?,
        });
    }
    let assembled = outcome
        .assembled
        .into_iter()
        .map(|row| NativeAssembledCandidate {
            position: row.position,
            claim: row.claim.to_hex(),
        })
        .collect();
    let mut conflicts = Vec::with_capacity(outcome.conflicts.len());
    for row in outcome.conflicts {
        let outcome = match row.outcome {
            crate::dreamer_consolidation::NativeSetOutcome::Skipped {
                fast_path,
                bound_correction,
            } => NativeSetOutcome::Skipped {
                fast_path,
                bound_correction,
            },
            crate::dreamer_consolidation::NativeSetOutcome::Decided {
                resolution,
                identity,
                decisions,
            } => NativeSetOutcome::Decided {
                resolution,
                identity: identity.map(|id| id.to_hex()),
                decisions: pack_answers(decisions)?,
            },
        };
        conflicts.push(NativeConflictOutcome {
            members: row.members.iter().map(EntityId::to_hex).collect(),
            prior_heads: row.prior_heads.iter().map(EntityId::to_hex).collect(),
            prior_head: row.prior_head.map(|id| id.to_hex()),
            outcome,
        });
    }
    Ok(NativeExtractionDecisions {
        corrections,
        assembled,
        conflicts,
        spent: fixture_spent_observations(fixture),
        tally_units: fixture_charge_units(fixture),
        tally_bindings: fixture_charge_binding_count(fixture),
    })
}

/// Converts kept decisions to pack answers in order, as the verdict native pack does.
fn pack_answers(decisions: Vec<KeptDecision>) -> Result<Vec<NativePackAnswer>> {
    let mut answers = Vec::with_capacity(decisions.len());
    for (index, kept) in decisions.into_iter().enumerate() {
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
    Ok(answers)
}

/// Lets the fixture verdict run on this server: every request is admitted.
fn allow_native_decisions_egress(_: &LlmRequest) -> bool {
    true
}
