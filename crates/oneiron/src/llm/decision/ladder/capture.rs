//! One native captured request, retaining its settlements before interpreting its result.

use super::{
    CapturedDecisionPack, DecisionCallContext, DecisionPack, DecisionProvider, DecisionReadOutcome,
    PairedAnswer, ProviderDecision, ProviderPin, Read, Readings, StopCause, ask, asked, joined,
    record_attempted_provider, take,
};
use crate::llm::decision::{DecisionAnswer, DecisionQuestion};
use crate::llm::run_admission::RunReceipt;
use crate::{Result, llm::decision::types::invalid};

/// The caller's native capture context and the inventory it retains even on error.
pub(super) struct Capture<'call, 'context> {
    pub context: &'call DecisionCallContext<'context>,
    pub receipts: &'call mut Vec<RunReceipt>,
}

/// The ordinary and captured modes share every native request boundary.
pub(super) fn read(
    provider: &dyn DecisionProvider,
    pin: &ProviderPin,
    pack: &DecisionPack<'_>,
    person: Option<&DecisionQuestion>,
    capture: Option<&mut Capture<'_, '_>>,
    readings: &mut [Readings],
) -> Result<Vec<Read>> {
    let Some(capture) = capture else {
        return take(pin, pack, ask(provider, pack, person), readings);
    };
    captured_read(
        provider,
        pin,
        pack,
        person,
        capture.context,
        &mut *capture.receipts,
        readings,
    )
    .unwrap_or_else(|| {
        Ok(pack
            .questions
            .iter()
            .map(|_| Read::NotStarted(StopCause::CaptureUnsupported))
            .collect())
    })
}

/// Keeps the ordinary single, native pack and appended-person request shapes. Unsupported
/// applies only to this request; the caller still owns any earlier reads and settlements.
fn captured_read(
    provider: &dyn DecisionProvider,
    pin: &ProviderPin,
    pack: &DecisionPack<'_>,
    person: Option<&DecisionQuestion>,
    context: &DecisionCallContext<'_>,
    receipts: &mut Vec<RunReceipt>,
    readings: &mut [Readings],
) -> Option<Result<Vec<Read>>> {
    let captured = match (person, pack.call(0)) {
        (None, Some(call)) if pack.questions.len() == 1 => {
            let captured = provider.decide_captured(&call, context)?;
            CapturedDecisionPack {
                result: captured.result.map(|answer| vec![answer]),
                receipts: captured.receipts,
            }
        }
        (None, _) => provider.decide_pack_captured(pack, context)?,
        (Some(_), _) => {
            let questions = asked(pack, person);
            provider.decide_pack_captured(
                &DecisionPack {
                    questions: &questions,
                    ..*pack
                },
                context,
            )?
        }
    };
    receipts.extend(captured.receipts);
    Some(take_captured(pin, pack, captured.result, person, readings))
}

/// Complete answers keep the ordinary join, clock and validation order. A mixed pack
/// keeps each unstarted ordinal apart from the provider reads that actually answered.
fn take_captured(
    pin: &ProviderPin,
    pack: &DecisionPack<'_>,
    answered: Result<Vec<DecisionReadOutcome<ProviderDecision>>>,
    person: Option<&DecisionQuestion>,
    readings: &mut [Readings],
) -> Result<Vec<Read>> {
    let mut answers = match answered {
        Ok(answers) => answers,
        Err(error) => return take(pin, pack, Err(error), readings),
    };
    if answers
        .iter()
        .all(|answer| matches!(answer, DecisionReadOutcome::Answered(_)))
    {
        let answers = answers
            .into_iter()
            .filter_map(|answer| match answer {
                DecisionReadOutcome::Answered(answer) => Some(answer),
                DecisionReadOutcome::NotStarted | DecisionReadOutcome::Stopped => None,
            })
            .collect();
        return take(
            pin,
            pack,
            joined(answers, pack.questions.len(), person),
            readings,
        );
    }
    let count = pack.questions.len();
    if answers.len() != count + usize::from(person.is_some()) {
        return Err(invalid("a pack answers every question"));
    }
    let mut person_incomplete = false;
    if let Some(person) = person {
        let reading = match answers.pop().expect("the person question's outcome") {
            DecisionReadOutcome::NotStarted | DecisionReadOutcome::Stopped => {
                person_incomplete = true;
                None
            }
            DecisionReadOutcome::Answered(answer) => {
                // The ordinary join validates this question before the answer clock.
                answer.validate(person)?;
                match (&answer.answer, answer.probability) {
                    (DecisionAnswer::Noul(_), Some(probability)) => Some(PairedAnswer {
                        question: person.id,
                        question_version: person.version,
                        probability,
                    }),
                    _ => None,
                }
            }
        };
        for answer in &mut answers {
            if let DecisionReadOutcome::Answered(answer) = answer {
                answer.person = reading;
            }
        }
    }
    let late = pack.deadline.answer_due();
    let mut reads = Vec::with_capacity(count);
    for ((question, answer), readings) in pack.questions.iter().zip(answers).zip(readings) {
        let answer = match answer {
            DecisionReadOutcome::Answered(answer) => answer,
            DecisionReadOutcome::NotStarted => {
                reads.push(Read::NotStarted(StopCause::GenerationAllowance));
                continue;
            }
            DecisionReadOutcome::Stopped => {
                reads.push(Read::Cut(StopCause::GenerationAllowance));
                continue;
            }
        };
        if late {
            record_attempted_provider(
                pin,
                std::slice::from_ref(&answer),
                std::slice::from_mut(readings),
            );
            reads.push(Read::Cut(StopCause::Deadline));
            continue;
        }
        answer.validate(question)?;
        let pin = answer.answered_pin(pin)?;
        if person_incomplete {
            readings.pins.push(pin);
            reads.push(Read::Cut(StopCause::GenerationAllowance));
            continue;
        }
        if let Some(reading) = answer.paired {
            readings.paired.push(reading.bind(pin.clone()));
        }
        if let Some(reading) = answer.person {
            readings.person.push(reading.bind(pin.clone()));
        }
        readings.pins.push(pin);
        reads.push(Read::Answer(answer));
    }
    Ok(reads)
}
