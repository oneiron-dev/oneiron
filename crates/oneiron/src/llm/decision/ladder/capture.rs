//! One native captured request, retaining its settlements before interpreting its result.

use super::{
    CapturedDecisionPack, DecisionCallContext, DecisionPack, DecisionProvider, DecisionReadOutcome,
    PairedAnswer, ProviderDecision, ProviderPin, Read, Readings, StopCause, asked, joined,
    record_attempted_provider, take,
};
use crate::llm::decision::{DecisionAnswer, DecisionQuestion};
use crate::llm::run_admission::RunReceipt;
use crate::{Result, llm::decision::types::invalid};

/// Keeps the ordinary single, native pack and appended-person request shapes. Unsupported
/// applies only to this request; the caller still owns any earlier reads and settlements.
pub(super) fn read(
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
                DecisionReadOutcome::NotStarted => None,
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
    let mut person_unstarted = false;
    if let Some(person) = person {
        let reading = match answers.pop().expect("the person question's outcome") {
            DecisionReadOutcome::NotStarted => {
                person_unstarted = true;
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
        let DecisionReadOutcome::Answered(answer) = answer else {
            reads.push(Read::NotStarted(StopCause::GenerationAllowance));
            continue;
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
        if person_unstarted {
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
