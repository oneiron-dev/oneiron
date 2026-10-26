//! Host-injected, one-step decision ladder. The engine owns routing and receipts.

use super::policy::{
    BandMode, DecisionBandPolicy, LearnedBand, PersonThreshold, Reversibility, ThinkThreshold,
};
use super::types::invalid;
use super::{
    DecisionAnswer, DecisionAudio, DecisionDial, DecisionImage, DecisionQuestion, DecisionRung,
    HostRuleRef, ImagePin, PairedReading, ProviderPin, ReasoningCause,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Result};
use serde_json::Value;

mod providers;
mod roles;
mod runner;

pub use providers::{
    DecisionCall, DecisionModel, DecisionPack, DecisionProvider, MAX_DECISION_STATE_BYTES,
    ModelDecisionProvider, PairedAnswer, ProviderCapability, ProviderDecision,
    RuleDecisionProvider,
};
pub use roles::{
    AskAct, AskRole, AskRoleResolver, AskTo, HolderKind, HumanDecisionQueue, HumanDecisionRequest,
    ResolvedRole, RoleHolder, RoleRank,
};

/// Whether `provider` can take `question` over `images` and `audio`. A call carrying both
/// needs a provider that reads both; the ladder never drops one to fit.
fn takes(
    provider: &dyn DecisionProvider,
    question: &DecisionQuestion,
    images: &[DecisionImage],
    audio: &[DecisionAudio],
) -> bool {
    provider.capability().takes(question)
        && (images.is_empty() || provider.reads_images())
        && (audio.is_empty() || provider.reads_audio())
}

/// Slots are fixed. A step up skips a rung with no provider, up to the dial's
/// ceiling, and the receipt's pins name every rung that ran. The last rung is a
/// queue, not a model-produced human answer.
pub struct DecisionLadder<'a> {
    pub rule: Option<&'a dyn DecisionProvider>,
    pub local: Option<&'a dyn DecisionProvider>,
    pub system_one: Option<&'a dyn DecisionProvider>,
    pub escalation: Option<&'a dyn DecisionProvider>,
    pub big: Option<&'a dyn DecisionProvider>,
    pub human: &'a dyn HumanDecisionQueue,
    pub human_pin: ProviderPin,
    /// Who the person rung's ask goes to; none is the vault's owners ([`AskTo::owner`]).
    /// The caller binds it from trusted context, never the model.
    pub ask_to: Option<&'a AskTo>,
    /// The host's versioned paired question ("does this need more thinking?"). A provider
    /// that reads it jointly (the house read) holds its own; a generated read asks it
    /// beside each of the call's questions in the same generation.
    pub paired: Option<&'a DecisionQuestion>,
    /// The host's versioned person question ("ask a person?"). When the dial reaches the
    /// person and the policy has a person row, every read asks it beside the call's
    /// questions as its own typed question.
    pub person: Option<&'a DecisionQuestion>,
    /// The host's versioned presence question ("is the target in the image?"). A Box or
    /// Point call through [`Self::run_located`] asks it first.
    pub presence: Option<&'a DecisionQuestion>,
    /// The work this call decides, as the caller names it (one conflict, one correction
    /// pack). The ask its person rung queues carries it, so two calls over the same
    /// question, principal and evidence that decide different work keep apart asks. The
    /// caller binds it from trusted context, never the model.
    pub correlation: Option<EntityId>,
}

/// What one provider request, `answered`, gave each pack question on the call's clock. A
/// failure once the work time is spent, or a reply after the answer's time, is the cut; a
/// failure with time left fails the call. A cut read still went out, so its rung stays on
/// the receipt (FIX 9907).
pub(super) fn take(
    pin: &ProviderPin,
    pack: &DecisionPack<'_>,
    answered: Result<Vec<ProviderDecision>>,
    readings: &mut [Readings],
) -> Result<Vec<Read>> {
    let count = pack.questions.len();
    let answers = match answered {
        Ok(answers) => answers,
        Err(_) if !pack.deadline.decision_may_start() => {
            record_attempted_provider(pin, &[], readings);
            return Ok((0..count).map(|_| Read::Cut).collect());
        }
        Err(error) => return Err(error),
    };
    if pack.deadline.answer_due() {
        record_attempted_provider(pin, &answers, readings);
        return Ok((0..count).map(|_| Read::Cut).collect());
    }
    let mut reads = Vec::with_capacity(answers.len());
    for ((question, answer), readings) in pack.questions.iter().zip(answers).zip(readings) {
        answer.validate(question)?;
        // The model that served the answer measured it (FIX 2730).
        let pin = answer.answered_pin(pin)?;
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

/// A cut read's rung on each question's receipt: the model a late reply names as served,
/// when that name is valid, else the pin the read went out to. The late reply's answer and
/// readings stay off the receipt; an unfinished reply is not an answer.
fn record_attempted_provider(
    pin: &ProviderPin,
    late: &[ProviderDecision],
    readings: &mut [Readings],
) {
    for (index, readings) in readings.iter_mut().enumerate() {
        let served = late
            .get(index)
            .and_then(|answer| answer.answered_pin(pin).ok());
        readings.pins.push(served.unwrap_or_else(|| pin.clone()));
    }
}

/// The person question's read shape, the one seam for it (test 6b: a separate read, not
/// joint). It is its own typed question in the same pack as the call's questions, and its
/// P(yes) joins every answer as the person reading; an abstained person read is no
/// reading, never P(yes) = 0. One question with no person question is one plain call.
fn ask(
    provider: &dyn DecisionProvider,
    pack: &DecisionPack<'_>,
    person: Option<&DecisionQuestion>,
) -> Result<Vec<ProviderDecision>> {
    let answers = match (person, pack.call(0)) {
        (None, Some(call)) if pack.questions.len() == 1 => vec![provider.decide(&call)?],
        (None, _) => provider.decide_pack(pack)?,
        (Some(_), _) => {
            let questions = asked(pack, person);
            provider.decide_pack(&DecisionPack {
                questions: &questions,
                ..*pack
            })?
        }
    };
    joined(answers, pack.questions.len(), person)
}

/// The questions one read asks: the pack's, then the person question when there is one.
pub(super) fn asked<'q>(
    pack: &DecisionPack<'q>,
    person: Option<&'q DecisionQuestion>,
) -> Vec<&'q DecisionQuestion> {
    pack.questions.iter().copied().chain(person).collect()
}

/// `answers` to [`asked`]'s questions as the pack's `count` answers, the person question's
/// P(yes) joined to each as its person reading.
pub(super) fn joined(
    mut answers: Vec<ProviderDecision>,
    count: usize,
    person: Option<&DecisionQuestion>,
) -> Result<Vec<ProviderDecision>> {
    if let Some(person) = person {
        if answers.len() != count + 1 {
            return Err(invalid("a pack answers every question"));
        }
        let asked = answers.pop().expect("the person question's answer");
        asked.validate(person)?;
        let reading = match (&asked.answer, asked.probability) {
            (DecisionAnswer::Noul(_), Some(probability)) => Some(PairedAnswer {
                question: person.id,
                question_version: person.version,
                probability,
            }),
            _ => None,
        };
        for answer in &mut answers {
            answer.person = reading;
        }
    }
    if answers.len() != count {
        return Err(invalid("a pack answers every question"));
    }
    Ok(answers)
}

/// One pack's checked routing inputs, shared by its questions.
pub(super) struct OpenPack<'a> {
    questions: &'a [&'a DecisionQuestion],
    principal: EntityId,
    evidence: &'a [EntityId],
    images: &'a [DecisionImage],
    audio: &'a [DecisionAudio],
    state: &'a Value,
    dial: DecisionDial,
    rows: Vec<LearnedBand>,
    person_row: Option<PersonThreshold>,
    /// The paired question, asked beside each of the pack's by a generated read.
    pub(super) paired: Option<&'a DecisionQuestion>,
    /// The person question, asked beside the pack's when the dial reaches the person.
    pub(super) person: Option<&'a DecisionQuestion>,
    policy: &'a DecisionBandPolicy,
    reversibility: Reversibility,
    deadline: &'a RetrievalDeadline,
}

impl OpenPack<'_> {
    /// One empty reading record per question.
    pub(super) fn readings(&self) -> Vec<Readings> {
        self.questions.iter().map(|_| Readings::default()).collect()
    }
}

/// One question's routing inputs, shared by its reads.
#[derive(Clone, Copy)]
struct Route<'a> {
    question: &'a DecisionQuestion,
    principal: EntityId,
    evidence: &'a [EntityId],
    images: &'a [DecisionImage],
    audio: &'a [DecisionAudio],
    state: &'a Value,
    dial: DecisionDial,
    row: LearnedBand,
    person_row: Option<PersonThreshold>,
    person: Option<&'a DecisionQuestion>,
    policy: &'a DecisionBandPolicy,
    reversibility: Reversibility,
    deadline: &'a RetrievalDeadline,
}

/// A state is a JSON object that serializes. Its size is no refusal here (Rule 5): the
/// producer that holds the vault measures it before it calls the ladder.
fn validate_state(state: &Value) -> Result<()> {
    serde_json::to_vec(state).map_err(|_| invalid("invalid decision state"))?;
    if !state.is_object() {
        return Err(invalid("invalid decision state"));
    }
    Ok(())
}

/// What one provider read gave the call.
pub(super) enum Read {
    Answer(ProviderDecision),
    /// No work time was left to start it.
    NotStarted,
    /// Its client gave up once the work time was spent, or its reply came after the
    /// answer's time: an unfinished reply is not an answer.
    Cut,
}

fn abstained() -> ProviderDecision {
    ProviderDecision {
        answer: DecisionAnswer::Abstain,
        probability: None,
        paired: None,
        person: None,
        served: None,
    }
}

/// Why a read needs more thinking: a small margin under an enforced band, or a paired
/// reading at its row. A missing paired reading is no reading, never P(yes) = 0.
fn step_cause(
    answer: &ProviderDecision,
    in_band: bool,
    mode: BandMode,
    think: Option<ThinkThreshold>,
) -> Option<ReasoningCause> {
    if in_band && mode == BandMode::Enforce {
        return Some(ReasoningCause::SmallMargin);
    }
    think
        .zip(answer.paired)
        .is_some_and(|(row, paired)| paired.probability >= row.threshold)
        .then_some(ReasoningCause::PairedHigh)
}

pub(super) fn millis(time: std::time::Duration) -> u64 {
    u64::try_from(time.as_millis()).unwrap_or(u64::MAX)
}

/// What a run's measurements leave on the receipt.
#[derive(Default)]
pub(super) struct Readings {
    pins: Vec<ProviderPin>,
    paired: Vec<PairedReading>,
    person: Vec<PairedReading>,
    images: Vec<ImagePin>,
    /// The rule row the Rule rung answered from, when it did.
    rule: Option<HostRuleRef>,
}

/// A missing person reading never asks; it is not P(yes) = 0, it is no reading.
fn asks_person(answer: &ProviderDecision, row: Option<PersonThreshold>) -> bool {
    row.zip(answer.person)
        .is_some_and(|(row, person)| person.probability >= row.threshold)
}

fn next_rung(rung: DecisionRung) -> DecisionRung {
    match rung {
        DecisionRung::Rule => DecisionRung::Local,
        DecisionRung::Local => DecisionRung::SystemOne,
        DecisionRung::SystemOne => DecisionRung::Escalation,
        DecisionRung::Escalation => DecisionRung::Big,
        DecisionRung::Big | DecisionRung::Human => DecisionRung::Human,
    }
}

pub(super) fn validate_pin(pin: &ProviderPin, rung: DecisionRung) -> Result<()> {
    if pin.rung != rung
        || pin.model.trim().is_empty()
        || pin.version.trim().is_empty()
        || pin.model.len() > 256
        || pin.version.len() > 256
    {
        return Err(invalid("invalid provider pin"));
    }
    Ok(())
}
