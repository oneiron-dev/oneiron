//! Host-injected, one-step decision ladder. The engine owns routing and receipts.

use super::policy::{
    BandMode, DecisionBandPolicy, LearnedBand, PersonThreshold, Reversibility, ThinkThreshold,
};
use super::types::{invalid, paired_valid};
use super::{
    AnswerContract, DecisionAnswer, DecisionDial, DecisionQuestion, DecisionReceipt, DecisionRung,
    DecisionTime, HumanAskReason, PairedReading, PersonChangedAnswer, ProviderPin, Reasoning,
    ReasoningCause, StopCause, TypedDecision,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderDecision {
    pub answer: DecisionAnswer,
    pub probability: Option<f64>,
    /// The paired question's reading from the same measurement, when the provider takes one.
    pub paired: Option<PairedAnswer>,
    /// The person question's reading ("ask a person?") from that same measurement.
    pub person: Option<PairedAnswer>,
}

/// A yes/no reading beside the answer ("does this need more thinking?" or "ask a
/// person?"). It is never an answer option.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PairedAnswer {
    pub question: EntityId,
    pub question_version: u32,
    /// P(yes).
    pub probability: f64,
}

impl PairedAnswer {
    /// The engine binds a reading to the provider that measured it.
    pub(crate) fn bind(self, provider: ProviderPin) -> PairedReading {
        PairedReading {
            provider,
            question: self.question,
            question_version: self.question_version,
            probability: self.probability,
        }
    }
}

impl ProviderDecision {
    pub(crate) fn validate(&self, question: &DecisionQuestion) -> Result<()> {
        if !question.contract.accepts(&self.answer)
            || match self.answer {
                DecisionAnswer::Abstain => self.probability.is_some(),
                _ => !self
                    .probability
                    .is_some_and(|p| p.is_finite() && (0.0..=1.0).contains(&p)),
            }
            || [self.paired, self.person]
                .into_iter()
                .flatten()
                .any(|reading| {
                    !paired_valid(
                        question.id,
                        reading.question,
                        reading.question_version,
                        reading.probability,
                    )
                })
            || self
                .paired
                .zip(self.person)
                .is_some_and(|(paired, person)| paired.question == person.question)
        {
            return Err(invalid("invalid provider decision"));
        }
        Ok(())
    }
}

/// The state bound every provider is held to.
pub const MAX_DECISION_STATE_BYTES: usize = 65_536;

/// One prepared call: the question, its access-checked evidence, the bounded state the host
/// built from that evidence, and the call's one clock. Every provider gets the same call.
#[derive(Clone, Copy)]
pub struct DecisionCall<'a> {
    pub question: &'a DecisionQuestion,
    pub evidence: &'a [EntityId],
    /// A JSON object of at most [`MAX_DECISION_STATE_BYTES`]; never an implicit vault dump.
    pub state: &'a Value,
    /// A provider with a native deadline gets [`RetrievalDeadline::decision_time_left`], and
    /// its client waits no longer.
    pub deadline: &'a RetrievalDeadline,
}

/// Several typed questions asked as one request over one state. Each question carries its
/// own text (its description) and its own contract; the state is their shared prefix.
#[derive(Clone, Copy)]
pub struct DecisionPack<'a> {
    pub questions: &'a [&'a DecisionQuestion],
    pub evidence: &'a [EntityId],
    pub state: &'a Value,
    pub deadline: &'a RetrievalDeadline,
}

impl<'a> DecisionPack<'a> {
    /// The pack's `index`th question as a single call over the same state.
    pub fn call(&self, index: usize) -> Option<DecisionCall<'a>> {
        self.questions.get(index).map(|&question| DecisionCall {
            question,
            evidence: self.evidence,
            state: self.state,
            deadline: self.deadline,
        })
    }
}

/// What a provider can take. The ladder skips a rung whose provider cannot take a question,
/// as it skips an empty slot; it never trims a question to fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderCapability {
    /// The most options one choice question may offer (the engine's contract allows 64).
    pub max_options: usize,
    /// Whether it answers score questions.
    pub score: bool,
}

impl Default for ProviderCapability {
    fn default() -> Self {
        Self {
            max_options: 64,
            score: true,
        }
    }
}

impl ProviderCapability {
    pub fn takes(&self, question: &DecisionQuestion) -> bool {
        match &question.contract {
            AnswerContract::Noul => true,
            AnswerContract::Choice { options } => options.len() <= self.max_options,
            AnswerContract::Score { .. } => self.score,
        }
    }
}

/// Providers see only caller-prepared, access-checked evidence references and the state the
/// host built from them. Their outputs contain no authority fields, receipt, or provenance
/// label. The identity contract: `pin` names the exact model and revision that answers, and
/// a provider checks it against what it serves before it answers; `capability` says what it
/// can take.
pub trait DecisionProvider: Send + Sync {
    fn pin(&self) -> ProviderPin;
    fn capability(&self) -> ProviderCapability {
        ProviderCapability::default()
    }
    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision>;
    /// The pack as one request, one answer per question in order. The default asks each
    /// question over the same state in turn, so a server's prompt cache carries the shared
    /// prefix; a provider with a native multi-question call overrides it.
    fn decide_pack(&self, pack: &DecisionPack<'_>) -> Result<Vec<ProviderDecision>> {
        (0..pack.questions.len())
            .filter_map(|index| pack.call(index))
            .map(|call| self.decide(&call))
            .collect()
    }
}

/// Deterministic offline answer table, scoped by exact question version.
pub struct RuleDecisionProvider {
    pin: ProviderPin,
    rows: BTreeMap<(EntityId, u32), ProviderDecision>,
}

impl RuleDecisionProvider {
    pub fn new(model: String, version: String) -> Result<Self> {
        let pin = ProviderPin {
            rung: DecisionRung::Rule,
            model,
            version,
        };
        validate_pin(&pin, DecisionRung::Rule)?;
        Ok(Self {
            pin,
            rows: BTreeMap::new(),
        })
    }

    pub fn insert(
        &mut self,
        question: &DecisionQuestion,
        decision: ProviderDecision,
    ) -> Result<()> {
        question.validate()?;
        decision.validate(question)?;
        self.rows.insert((question.id, question.version), decision);
        Ok(())
    }
}

impl DecisionProvider for RuleDecisionProvider {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        self.rows
            .get(&(call.question.id, call.question.version))
            .cloned()
            .ok_or_else(|| invalid("no matching offline rule"))
    }
}

/// Host adapter for the local head, the System One rung or the big model. Model access,
/// budget admission, egress, and evidence reads stay with the host.
pub trait DecisionModel: Send + Sync {
    fn capability(&self) -> ProviderCapability {
        ProviderCapability::default()
    }
    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision>;
    /// See [`DecisionProvider::decide_pack`].
    fn decide_pack(&self, pack: &DecisionPack<'_>) -> Result<Vec<ProviderDecision>> {
        (0..pack.questions.len())
            .filter_map(|index| pack.call(index))
            .map(|call| self.decide(&call))
            .collect()
    }
}

pub struct ModelDecisionProvider {
    pin: ProviderPin,
    model: Arc<dyn DecisionModel>,
}

impl ModelDecisionProvider {
    pub fn new(pin: ProviderPin, model: Arc<dyn DecisionModel>) -> Result<Self> {
        if !matches!(
            pin.rung,
            DecisionRung::Local | DecisionRung::SystemOne | DecisionRung::Big
        ) {
            return Err(invalid("not a model decision rung"));
        }
        validate_pin(&pin, pin.rung)?;
        Ok(Self { pin, model })
    }
}

impl DecisionProvider for ModelDecisionProvider {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }
    fn capability(&self) -> ProviderCapability {
        self.model.capability()
    }
    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        self.model.decide(call)
    }
    fn decide_pack(&self, pack: &DecisionPack<'_>) -> Result<Vec<ProviderDecision>> {
        self.model.decide_pack(pack)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HumanDecisionRequest {
    pub question: DecisionQuestion,
    pub principal: EntityId,
    pub evidence: Vec<EntityId>,
    pub reason: HumanAskReason,
    pub prior: Option<ProviderDecision>,
    /// The provider that read `prior`; the engine sets it with the prior.
    pub prior_provider: Option<ProviderPin>,
    /// Host-issued versioned queue identity; the host renders its own text.
    pub queue_pin: ProviderPin,
}

impl HumanDecisionRequest {
    /// The record of the person's answer changing the model's. None when there was no model
    /// answer to change or the person gave the same one.
    pub fn changed_by(&self, person: DecisionAnswer) -> Result<Option<PersonChangedAnswer>> {
        if person == DecisionAnswer::Abstain || !self.question.contract.accepts(&person) {
            return Err(invalid("invalid person answer"));
        }
        let Some(prior) = self
            .prior
            .as_ref()
            .filter(|prior| prior.answer != DecisionAnswer::Abstain && prior.answer != person)
        else {
            return Ok(None);
        };
        let provider = self
            .prior_provider
            .clone()
            .ok_or_else(|| invalid("a prior without its provider"))?;
        Ok(Some(PersonChangedAnswer {
            question: self.question.id,
            question_version: self.question.version,
            principal: self.principal,
            reason: self.reason,
            prior: prior.answer.clone(),
            prior_probability: prior.probability,
            prior_paired: prior.paired.map(|reading| reading.bind(provider.clone())),
            prior_person: prior.person.map(|reading| reading.bind(provider.clone())),
            prior_provider: provider,
            person,
            queue_pin: self.queue_pin.clone(),
        }))
    }
}

pub trait HumanDecisionQueue: Send + Sync {
    fn queue(&self, request: HumanDecisionRequest) -> Result<()>;
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
    /// The host's versioned person question ("ask a person?"). When the dial reaches the
    /// person and the policy has a person row, every read asks it beside the call's
    /// questions as its own typed question.
    pub person: Option<&'a DecisionQuestion>,
}

impl DecisionLadder<'_> {
    /// One typed decision under one clock, `deadline` (an anytime budget, or a raw
    /// deadline): [`Self::run_pack`] with one question.
    #[expect(
        clippy::too_many_arguments,
        reason = "the call's state and clock join the question, its scope, the dial and the policy"
    )]
    pub fn run(
        &self,
        question: &DecisionQuestion,
        principal: EntityId,
        evidence: &[EntityId],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<TypedDecision> {
        let mut decisions = self.run_pack(
            &[question],
            principal,
            evidence,
            state,
            dial,
            policy,
            reversibility,
            deadline,
        )?;
        Ok(decisions.remove(0))
    }

    /// Several typed questions over one state, asked as one pack under one clock. The first
    /// permitted rung reads them in one request (several in turn past the policy's
    /// questions-per-call row), with the person question ("ask a person?")
    /// beside them as its own typed question when the dial reaches the person. Then each
    /// answer routes on its own to its own receipt: a stronger rung starts only while work
    /// time is left, and only for a cause: a small margin under an enforced band, or a
    /// paired reading at its row. A step skips a rung with no provider, or one that cannot
    /// take the question, up to the ceiling; with none left the call abstains. At a cut a
    /// reversible step takes the answer it holds and an irreversible one abstains and asks;
    /// with no answer, or an answer inside its band, the call abstains. The last quarter of
    /// the time stays the answer's.
    #[expect(
        clippy::too_many_arguments,
        reason = "the call's state and clock join the questions, their scope, dial and policy"
    )]
    pub fn run_pack(
        &self,
        questions: &[&DecisionQuestion],
        principal: EntityId,
        evidence: &[EntityId],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<Vec<TypedDecision>> {
        if questions.is_empty() {
            return Err(invalid("invalid decision pack"));
        }
        for (index, question) in questions.iter().enumerate() {
            question.validate()?; // Provenance cannot reach any provider or queue.
            if questions[..index].iter().any(|earlier| earlier.id == question.id) {
                return Err(invalid("invalid decision pack"));
            }
        }
        validate_state(state)?;
        dial.band.validate()?;
        if dial.first > dial.ceiling {
            return Err(invalid("invalid decision dial"));
        }
        // Only a surface whose dial reaches the person rung routes on a person reading.
        let person_row = policy
            .person_threshold()
            .filter(|_| dial.ceiling == DecisionRung::Human);
        let person = self.person.filter(|_| person_row.is_some());
        if let Some(person) = person {
            person.validate()?;
            if person.contract != AnswerContract::Noul
                || questions.iter().any(|question| question.id == person.id)
            {
                return Err(invalid("invalid person question"));
            }
        }
        let rows = questions
            .iter()
            .map(|question| policy.resolve(question, reversibility, dial.band))
            .collect::<Result<Vec<_>>>()?;
        let mut readings = questions
            .iter()
            .map(|_| Readings::default())
            .collect::<Vec<_>>();
        let mut first = Vec::with_capacity(questions.len());
        if dial.first == DecisionRung::Human {
            first.extend(questions.iter().map(|_| None));
        } else {
            // Past the questions-per-call row the pack goes as several requests in turn.
            let per_call = policy.questions_per_call();
            for (chunk, readings) in questions.chunks(per_call).zip(readings.chunks_mut(per_call)) {
                let pack = DecisionPack {
                    questions: chunk,
                    evidence,
                    state,
                    deadline,
                };
                first.extend(self.read(dial.first, &pack, person, readings)?.into_iter().map(Some));
            }
        }
        questions
            .iter()
            .zip(rows)
            .zip(first)
            .zip(readings)
            .map(|(((&question, row), first), readings)| {
                let route = Route {
                    question,
                    principal,
                    evidence,
                    state,
                    dial,
                    row,
                    person_row,
                    person,
                    policy,
                    reversibility,
                    deadline,
                };
                self.route(&route, first, readings)
            })
            .collect()
    }

    /// One question's routing after the first read, `first` (none when the dial starts at
    /// the person).
    fn route(
        &self,
        call: &Route<'_>,
        first: Option<Read>,
        mut readings: Readings,
    ) -> Result<TypedDecision> {
        let Route {
            question,
            principal,
            evidence,
            state,
            dial,
            row,
            person_row,
            person,
            policy,
            reversibility,
            deadline,
        } = *call;
        let mut rung = dial.first;
        let mut prior = None;
        let mut answered = None;
        let mut in_band = false;
        let mut needs_person = false;
        let mut unavailable = false;
        let mut stop = StopCause::Done;
        let mut reasoning = Reasoning::NotNeeded;
        match first {
            None => {}
            Some(Read::NotStarted | Read::Cut) => stop = StopCause::Deadline,
            Some(Read::Answer(answer)) => {
                in_band = answer.probability.is_some_and(|p| row.band.contains(p));
                needs_person = asks_person(&answer, person_row);
                let cause = step_cause(&answer, in_band, row.mode, policy.think_threshold())
                    .filter(|_| rung < dial.ceiling);
                prior = Some(answer);
                answered = Some(rung);
                if needs_person {
                    rung = DecisionRung::Human;
                } else if let Some(cause) = cause {
                    // A stronger rung, the person's included, starts only while work
                    // time is left.
                    match self.next_available(rung, dial.ceiling, question) {
                        None => {
                            unavailable = true;
                            reasoning = Reasoning::Skipped(cause);
                        }
                        Some(_) if !deadline.decision_may_start() => {
                            stop = StopCause::Deadline;
                            reasoning = Reasoning::Skipped(cause);
                        }
                        Some(DecisionRung::Human) => rung = DecisionRung::Human,
                        Some(next) => {
                            let questions = [question];
                            let pack = DecisionPack {
                                questions: &questions,
                                evidence,
                                state,
                                deadline,
                            };
                            let read = self
                                .read(next, &pack, person, std::slice::from_mut(&mut readings))?
                                .remove(0);
                            match read {
                                Read::NotStarted => {
                                    stop = StopCause::Deadline;
                                    reasoning = Reasoning::Skipped(cause);
                                }
                                Read::Cut => {
                                    stop = StopCause::Deadline;
                                    reasoning = Reasoning::Cut(cause);
                                }
                                Read::Answer(answer) => {
                                    reasoning = Reasoning::Ran(cause);
                                    rung = next;
                                    answered = Some(next);
                                    if asks_person(&answer, person_row) {
                                        needs_person = true;
                                        rung = DecisionRung::Human;
                                    }
                                    prior = Some(answer);
                                }
                            }
                        }
                    }
                }
            }
        }
        // At a cut an irreversible step never takes an unfinished answer, and no step
        // takes an answer the call does not have, or one inside its band, enforced or
        // in shadow (packet rule 5: an in-band answer is not eligible).
        let abstains_at_cut = stop == StopCause::Deadline
            && (prior.is_none() || reversibility == Reversibility::OutboundEffect || in_band);
        if abstains_at_cut && dial.ceiling == DecisionRung::Human {
            rung = DecisionRung::Human;
        }
        let mut human_ask = None;
        let outcome = if rung == DecisionRung::Human {
            validate_pin(&self.human_pin, DecisionRung::Human)?;
            let reason = if needs_person {
                HumanAskReason::NeedsPerson
            } else if abstains_at_cut {
                HumanAskReason::Deadline
            } else if prior.is_some() {
                HumanAskReason::Uncertain
            } else {
                HumanAskReason::OwnerSelected
            };
            self.human.queue(HumanDecisionRequest {
                question: question.clone(),
                principal,
                evidence: evidence.to_vec(),
                reason,
                // The prior is the last provider read's answer.
                prior_provider: prior.as_ref().and(readings.pins.last().cloned()),
                prior,
                queue_pin: self.human_pin.clone(),
            })?;
            readings.pins.push(self.human_pin.clone());
            human_ask = Some(reason);
            abstained()
        } else if abstains_at_cut {
            human_ask = Some(HumanAskReason::Deadline);
            abstained()
        } else if unavailable {
            // No rung up to the ceiling can take the step: a typed abstention.
            human_ask = Some(HumanAskReason::ProviderUnavailable);
            abstained()
        } else {
            prior.expect("a non-human rung has an answer")
        };
        // A rung that abstained answered nothing.
        let answered = answered.filter(|_| outcome.answer != DecisionAnswer::Abstain);
        Ok(TypedDecision {
            answer: outcome.answer,
            probability: outcome.probability,
            evidence: evidence.to_vec(),
            in_band,
            human_ask,
            receipt: DecisionReceipt {
                question: question.id,
                question_version: question.version,
                principal,
                providers: readings.pins,
                band: row.band,
                band_version: row.version,
                evidence_versions: Vec::new(),
                cost_per_thousand: None,
                paired: readings.paired,
                person: readings.person,
                time: Some(DecisionTime {
                    budget_ms: millis(deadline.budget()),
                    used_ms: millis(deadline.used()),
                    stop,
                    answered,
                    reasoning,
                }),
            },
        })
    }

    fn slot(&self, rung: DecisionRung) -> Option<&dyn DecisionProvider> {
        match rung {
            DecisionRung::Rule => self.rule,
            DecisionRung::Local => self.local,
            DecisionRung::SystemOne => self.system_one,
            DecisionRung::Escalation => self.escalation,
            DecisionRung::Big => self.big,
            DecisionRung::Human => None,
        }
    }

    /// The next rung above `rung` that can answer `question`, up to `ceiling`. The person's
    /// queue is always present (ARCH-0076 #posture: no house model sends the step to the
    /// big model or the person).
    fn next_available(
        &self,
        mut rung: DecisionRung,
        ceiling: DecisionRung,
        question: &DecisionQuestion,
    ) -> Option<DecisionRung> {
        while rung < ceiling {
            rung = next_rung(rung);
            if rung == DecisionRung::Human
                || self
                    .slot(rung)
                    .is_some_and(|provider| provider.capability().takes(question))
            {
                return Some(rung);
            }
        }
        None
    }

    /// One provider request on the call's clock, one read per pack question. Routing skips
    /// an empty slot, so only the dial's own first rung reaches here empty or unable to take
    /// a question, and it fails even with no time left. A failure with time left still
    /// fails the call.
    fn read(
        &self,
        rung: DecisionRung,
        pack: &DecisionPack<'_>,
        person: Option<&DecisionQuestion>,
        readings: &mut [Readings],
    ) -> Result<Vec<Read>> {
        let provider = self
            .slot(rung)
            .ok_or_else(|| invalid("decision provider unavailable"))?;
        let pin = provider.pin();
        validate_pin(&pin, rung)?;
        let capability = provider.capability();
        if !pack.questions.iter().all(|question| capability.takes(question)) {
            return Err(invalid("decision provider cannot take the question"));
        }
        let count = pack.questions.len();
        if !pack.deadline.decision_may_start() {
            return Ok((0..count).map(|_| Read::NotStarted).collect());
        }
        let answers = match ask(provider, pack, person) {
            Ok(answers) => answers,
            Err(_) if !pack.deadline.decision_may_start() => {
                return Ok((0..count).map(|_| Read::Cut).collect());
            }
            Err(error) => return Err(error),
        };
        if pack.deadline.answer_due() {
            return Ok((0..count).map(|_| Read::Cut).collect());
        }
        let mut reads = Vec::with_capacity(answers.len());
        for ((question, answer), readings) in pack.questions.iter().zip(answers).zip(readings) {
            answer.validate(question)?;
            if let Some(reading) = answer.paired {
                readings.paired.push(reading.bind(pin.clone()));
            }
            if let Some(reading) = answer.person {
                readings.person.push(reading.bind(pin.clone()));
            }
            readings.pins.push(pin.clone());
            reads.push(Read::Answer(answer));
        }
        Ok(reads)
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
        (Some(person), _) => {
            let questions = pack.questions.iter().copied().chain([person]).collect::<Vec<_>>();
            let mut answers = provider.decide_pack(&DecisionPack {
                questions: &questions,
                ..*pack
            })?;
            if answers.len() != questions.len() {
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
            answers
        }
    };
    if answers.len() != pack.questions.len() {
        return Err(invalid("a pack answers every question"));
    }
    Ok(answers)
}

/// One question's routing inputs, shared by its reads.
#[derive(Clone, Copy)]
struct Route<'a> {
    question: &'a DecisionQuestion,
    principal: EntityId,
    evidence: &'a [EntityId],
    state: &'a Value,
    dial: DecisionDial,
    row: LearnedBand,
    person_row: Option<PersonThreshold>,
    person: Option<&'a DecisionQuestion>,
    policy: &'a DecisionBandPolicy,
    reversibility: Reversibility,
    deadline: &'a RetrievalDeadline,
}

fn validate_state(state: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(state).map_err(|_| invalid("invalid decision state"))?;
    if !state.is_object() || bytes.len() > MAX_DECISION_STATE_BYTES {
        return Err(invalid("invalid decision state"));
    }
    Ok(())
}

/// What one provider read gave the call.
enum Read {
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
struct Readings {
    pins: Vec<ProviderPin>,
    paired: Vec<PairedReading>,
    person: Vec<PairedReading>,
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
