//! A choice wider than a provider's option bound, read as a tournament (FIX 11235).
//!
//! A rung whose provider takes fewer options than a choice question offers is not skipped:
//! the options split into as few chunks as its bound allows, sized evenly, and each chunk
//! is one read through [`ask`], its pin on the question's receipt. A chunk's choice is its
//! winner; a chunk that abstains sends none on. One winner stands with its chunk's answer.
//! Two or more meet in a final read among the winners, with the person question beside it
//! when the call asks one, in rounds while they are still more than the bound. The bound
//! sets the chunk count; nothing caps it. A score question, or a provider whose bound
//! cannot make a round smaller, still skips the rung.

use super::{DecisionPack, DecisionProvider, Read, Readings, ask, take};
use crate::Result;
use crate::llm::decision::types::invalid;
use crate::llm::decision::{AnswerContract, DecisionAnswer, DecisionQuestion, ProviderPin};

/// The fewest options a provider must take for a tournament to read a wider choice: a
/// chunk of one cannot narrow the field.
pub(super) const MIN_TOURNAMENT_CHUNK_OPTIONS: usize = 2;

/// Whether `provider` reads `question` as a tournament: a choice wider than its option
/// bound, which takes at least [`MIN_TOURNAMENT_CHUNK_OPTIONS`].
pub(super) fn chunks(provider: &dyn DecisionProvider, question: &DecisionQuestion) -> bool {
    let bound = provider.capability().max_options;
    matches!(&question.contract, AnswerContract::Choice { options } if options.len() > bound)
        && bound >= MIN_TOURNAMENT_CHUNK_OPTIONS
}

/// One read per `pack` question, as [`take`] gives them: a question `provider` takes whole
/// is one plain read, with `person` beside it; a wider choice is a tournament.
pub(super) fn read_pack(
    provider: &dyn DecisionProvider,
    pin: &ProviderPin,
    pack: &DecisionPack<'_>,
    person: Option<&DecisionQuestion>,
    readings: &mut [Readings],
) -> Result<Vec<Read>> {
    let mut reads = Vec::with_capacity(pack.questions.len());
    for (question, readings) in pack.questions.iter().zip(readings.iter_mut()) {
        let one = DecisionPack {
            questions: std::slice::from_ref(question),
            ..*pack
        };
        let read = if chunks(provider, question) {
            tournament(provider, pin, &one, person, readings)?
        } else {
            let answered = ask(provider, &one, person);
            take(pin, &one, answered, std::slice::from_mut(readings))?.remove(0)
        };
        reads.push(read);
    }
    Ok(reads)
}

/// `pack`'s one choice question read in rounds of chunks within `provider`'s bound.
fn tournament(
    provider: &dyn DecisionProvider,
    pin: &ProviderPin,
    pack: &DecisionPack<'_>,
    person: Option<&DecisionQuestion>,
    readings: &mut Readings,
) -> Result<Read> {
    let question = pack.questions[0];
    let AnswerContract::Choice { options } = &question.contract else {
        return Err(invalid("a tournament reads a choice question"));
    };
    let bound = provider.capability().max_options;
    let mut field = options.clone();
    let mut started = false;
    loop {
        if field.len() <= bound {
            return read_chunk(provider, pin, pack, &field, person, readings, started);
        }
        let count = field.len().div_ceil(bound);
        let size = field.len().div_ceil(count);
        let mut winners = Vec::new();
        let mut abstained = None;
        for chunk in field.chunks(size) {
            let read = read_chunk(provider, pin, pack, chunk, None, readings, started)?;
            started = true;
            let Read::Answer(answer) = read else {
                return Ok(read);
            };
            match answer.answer.clone() {
                DecisionAnswer::Choice(winner) => winners.push((winner, answer)),
                _ => abstained = Some(answer),
            }
        }
        match winners.len() {
            0 => return Ok(abstained.map_or(Read::Cut, Read::Answer)),
            1 => return Ok(Read::Answer(winners.remove(0).1)),
            _ => field = winners.into_iter().map(|(winner, _)| winner).collect(),
        }
    }
}

/// One read of `pack`'s question over `options` alone. A read past the first that finds
/// no work time left is the tournament's cut: earlier ones went out.
fn read_chunk(
    provider: &dyn DecisionProvider,
    pin: &ProviderPin,
    pack: &DecisionPack<'_>,
    options: &[String],
    person: Option<&DecisionQuestion>,
    readings: &mut Readings,
    started: bool,
) -> Result<Read> {
    if started && !pack.deadline.decision_may_start() {
        return Ok(Read::Cut);
    }
    let mut question = pack.questions[0].clone();
    question.contract = AnswerContract::Choice {
        options: options.to_vec(),
    };
    let questions = [&question];
    let chunk = DecisionPack {
        questions: &questions,
        ..*pack
    };
    let answered = ask(provider, &chunk, person);
    Ok(take(pin, &chunk, answered, std::slice::from_mut(readings))?.remove(0))
}
