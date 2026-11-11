//! Public standing-answer work keeps the actual caller and the measured frontier.

use super::*;
use crate::claim::ScopedRead;
use crate::llm::decision::questions::{GraphQuestionInput, GraphQuestionRef, GraphUnitContext};

/// Read an explicit standing-question source set before external provider work.
/// The caller's live lane conjoins the saved principal and writing holder in
/// the same snapshot. The returned frontier is data, never authority.
pub fn prepare_standing_answer(
    caller: &ScopedRead<'_>,
    reference: GraphQuestionRef,
    actor: WriteActor,
    input: &GraphQuestionInput,
) -> Result<(QuestionRecord, GraphUnitContext, [u8; 32])> {
    let vault = caller.vault();
    vault.store.authorization_now()?;
    let txn = vault.store.env.read_txn()?;
    let (_, record) = standing_record(
        vault,
        &txn,
        actor.entity_ref(),
        reference.id,
        reference.version,
    )?;
    if !record.definition.units.contains(&input.unit) {
        return Err(Error::EntityNotFound);
    }
    let (frontier, _, sources) = sources_with_caller_in_txn(
        vault,
        &txn,
        &record,
        actor,
        input.unit,
        &input.evidence,
        &[],
        Some(caller),
        None,
    )?;
    Ok((
        record,
        GraphUnitContext {
            unit: input.unit,
            sources,
            omitted: Vec::new(),
        },
        frontier,
    ))
}

/// Admit the provider's full decision over a previously prepared source set.
/// The landing writer rechecks the version, all three readers, the frontier
/// and the submitted body hashes. It never replaces measured pins with new ones.
pub fn admit_standing_answer(
    caller: &ScopedRead<'_>,
    reference: GraphQuestionRef,
    actor: WriteActor,
    input: GraphQuestionInput,
    source_frontier: [u8; 32],
    decision: TypedDecision,
    now: u64,
) -> Result<AnswerRecord> {
    let answer = StandingAnswer {
        unit: input.unit,
        answer: decision.answer.clone(),
        probability: decision.probability,
        evidence: input.evidence,
        providers: decision.receipt.providers.clone(),
        paired: decision.receipt.paired.clone(),
        rule: decision.receipt.rule.clone(),
        source_frontier,
    };
    backfill_answer_with_caller(
        caller.vault(),
        actor.entity_ref(),
        reference.id,
        reference.version,
        actor,
        answer,
        Measured::Admitted(Box::new(decision)),
        &[],
        Some(caller),
        now,
        None,
        None,
    )
}
