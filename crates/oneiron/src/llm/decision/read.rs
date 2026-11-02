//! The escalation rung's decision read: the house model reads the pack's questions over the
//! same state in one request. Each question is read jointly with the paired "does this need
//! more thinking?" question (ARCH-0076 `#ask-a-person`: Q1 and Q2 stay joint): one readout over
//! single-token (option, paired answer) labels, normalized once, whose marginals are the answer
//! and that answer's own paired reading. The person question ("ask a person?") is the ladder's
//! own typed question, the pack's last; the host binds it here, and it is read separately.

use super::ladder::{
    DecisionCall, DecisionPack, DecisionProvider, PairedAnswer, ProviderCapability,
    ProviderDecision, level_score, score_levels_in, validate_pin,
};
use super::questions::QuestionCriteria;
use super::types::invalid;
use super::{AnswerContract, DecisionAnswer, DecisionQuestion, DecisionRung, ProviderPin};
use crate::Result;
use crate::llm::{
    BudgetGuard, BudgetLease, LabelReadModel, LabelReadRequest, LabelReadResponse, LabelReadout,
    LabelSet, LlmResult, LlmUsage, joint_marginals,
};
use crate::retrieval_depth::RetrievalDeadline;
use std::time::Instant;

/// A read's label probabilities sum to one within this tolerance.
const DISTRIBUTION_TOLERANCE: f64 = 1e-6;

/// How one decision read ended, for its gate to settle.
pub enum GatedRead {
    /// Admission waited past the work time, so the read never started.
    NotStarted,
    Read(LlmResult<LabelReadResponse>),
}

/// Admits one decision read, lends `read` its lease and settles what it returns: nothing
/// spent when it never started, its reply's usage, or a failed read's reservation. A bare
/// meter is one; a host that admits model calls as runs brings its own. `deadline` is the
/// caller's own clock (FIX 9526): a gate whose admission waits stops waiting when its work
/// time ends, and returns [`GatedRead::NotStarted`]; it never starts a clock of its own.
pub trait DecisionReadGate: Send + Sync {
    fn read(
        &self,
        deadline: &RetrievalDeadline,
        read: &mut dyn FnMut(&BudgetLease) -> GatedRead,
    ) -> Result<GatedRead>;
}

/// A bare meter admits at once: the read's own pre-send check is its clock.
impl DecisionReadGate for BudgetGuard {
    fn read(
        &self,
        _deadline: &RetrievalDeadline,
        read: &mut dyn FnMut(&BudgetLease) -> GatedRead,
    ) -> Result<GatedRead> {
        let lease = self
            .admit()
            .map_err(|_| invalid("decision read refused by the budget"))?
            .lease;
        let gated = read(&lease);
        match &gated {
            GatedRead::NotStarted => self.settle_per_call(&lease, &LlmUsage::zero()),
            GatedRead::Read(Ok(read)) => self.settle_per_call(&lease, &read.usage),
            GatedRead::Read(Err(_)) => self.settle_reserved(&lease),
        }
        .map_err(|_| invalid("decision read settlement refused"))?;
        Ok(gated)
    }
}

/// Fills the escalation slot. It reads only the call's state, admits and settles each read
/// through its gate, and returns no authority, receipt or provenance.
pub struct DecisionReadProvider<'a> {
    pin: ProviderPin,
    reader: &'a dyn LabelReadModel,
    gate: &'a dyn DecisionReadGate,
    paired: &'a DecisionQuestion,
    person: Option<&'a DecisionQuestion>,
}

impl<'a> DecisionReadProvider<'a> {
    /// `pin` names the model the route bound, and the reader must serve exactly that model
    /// and revision. `gate` admits and settles each read. `paired` is the host's versioned
    /// yes/no question, and `person` the ladder's person question when the host binds one.
    pub fn new(
        pin: ProviderPin,
        reader: &'a dyn LabelReadModel,
        gate: &'a dyn DecisionReadGate,
        paired: &'a DecisionQuestion,
        person: Option<&'a DecisionQuestion>,
    ) -> Result<Self> {
        validate_pin(&pin, DecisionRung::Escalation)?;
        if pin.model != reader.model() || pin.version != reader.revision() {
            return Err(invalid("decision reader serves another model"));
        }
        paired.validate()?;
        if paired.contract != AnswerContract::Noul
            || person.is_some_and(|person| {
                person.validate().is_err()
                    || person.contract != AnswerContract::Noul
                    || person.id == paired.id
            })
        {
            return Err(invalid("invalid paired or person question"));
        }
        Ok(Self {
            pin,
            reader,
            gate,
            paired,
            person,
        })
    }
}

impl DecisionProvider for DecisionReadProvider<'_> {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    /// A question's options are read two joint labels each. A score is read as a choice
    /// over the caller's levels (FIX 3269); a score with none abstains.
    fn capability(&self) -> ProviderCapability {
        ProviderCapability {
            max_options: self.reader.max_labels() / 2,
            score: true,
        }
    }

    /// The reader's own price, as its host knows it (FIX 11305).
    fn cost_per_thousand(&self) -> Option<f64> {
        self.reader.cost_per_thousand()
    }

    /// A pack of one.
    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        let mut answers = self.decide_pack(&DecisionPack {
            questions: &[call.question],
            evidence: call.evidence,
            images: call.images,
            audio: call.audio,
            state: call.state,
            deadline: call.deadline,
        })?;
        answers
            .pop()
            .ok_or_else(|| invalid("malformed decision read"))
    }

    /// One read of the pack's questions in order: each jointly with the paired question, the
    /// person question alone. Each answer carries its own paired P(yes).
    fn decide_pack(&self, pack: &DecisionPack<'_>) -> Result<Vec<ProviderDecision>> {
        let DecisionPack {
            questions: asked,
            state,
            deadline,
            ..
        } = *pack;
        if asked.is_empty() {
            return Err(invalid("invalid decision pack"));
        }
        let max_levels = self.capability().max_options;
        let levels: Vec<Option<Vec<String>>> = asked
            .iter()
            .map(|question| score_levels_in(question, state))
            .collect();
        // A question that is no yes/no reads its criteria in its own form after its text
        // (FIX 2181); a yes/no keeps its label descriptions.
        let texts: Vec<Option<String>> = asked
            .iter()
            .map(|question| match question.contract {
                AnswerContract::Noul => None,
                _ => QuestionCriteria::rubric_in(state, &question.contract)
                    .map(|rubric| format!("{}\n\n{rubric}", question.text)),
            })
            .collect();
        // Each asked question's place among the read ones; `None` abstains.
        let mut slots = Vec::with_capacity(asked.len());
        let mut questions = Vec::with_capacity(asked.len());
        let mut read_asked = Vec::with_capacity(asked.len());
        for (index, question) in asked.iter().enumerate() {
            if question.id == self.paired.id {
                return Err(invalid("invalid paired question"));
            }
            let labels = match &question.contract {
                AnswerContract::Noul => LabelSet::Noul,
                AnswerContract::Choice { options } => LabelSet::Choice(options),
                AnswerContract::Score { .. } => match &levels[index] {
                    Some(levels) if levels.len() <= max_levels => LabelSet::Choice(levels),
                    _ => {
                        slots.push(None);
                        continue;
                    }
                },
                AnswerContract::Box | AnswerContract::Point => {
                    return Err(invalid("a decision read takes no box or point question"));
                }
            };
            let person = self.person.is_some_and(|person| person.id == question.id);
            slots.push(Some(questions.len()));
            read_asked.push(*question);
            questions.push(LabelReadout {
                text: texts[index].as_deref().unwrap_or(&question.text),
                labels,
                paired: (!person).then_some(self.paired.text.as_str()),
            });
        }
        let abstained = || ProviderDecision {
            answer: DecisionAnswer::Abstain,
            probability: None,
            paired: None,
            person: None,
            served: None,
        };
        if questions.is_empty() {
            return Ok(slots.iter().map(|_| abstained()).collect());
        }
        let gated = self.gate.read(deadline, &mut |lease| {
            // Admission may wait; a read admitted after the work time is spent never starts.
            if !deadline.decision_may_start() {
                return GatedRead::NotStarted;
            }
            let request = LabelReadRequest {
                state,
                questions: &questions,
                // An instant, not a duration, so the reader's own preparation spends it too.
                work_until: Some(Instant::now() + deadline.decision_time_left()),
            };
            GatedRead::Read(self.reader.read(&request, lease))
        })?;
        let read = match gated {
            GatedRead::NotStarted => {
                return Err(invalid("decision read admitted after the work time"));
            }
            GatedRead::Read(Ok(read)) => read,
            GatedRead::Read(Err(error)) => {
                return Err(invalid(&format!("decision read failed: {error}")));
            }
        };
        let unit = |p: &f64| p.is_finite() && (0.0..=1.0).contains(p);
        let distribution = |(readout, question): (&Vec<f64>, &LabelReadout<'_>)| {
            readout.len() == question.width()
                && readout.iter().all(unit)
                && (readout.iter().sum::<f64>() - 1.0).abs() <= DISTRIBUTION_TOLERANCE
        };
        if read.readouts.len() != questions.len()
            || !read.readouts.iter().zip(&questions).all(distribution)
        {
            return Err(invalid("malformed decision read"));
        }
        let decisions: Vec<ProviderDecision> = questions
            .iter()
            .zip(&read.readouts)
            .zip(&read_asked)
            .map(|((question, readout), asked)| {
                // A joint readout's marginals: the labels', then this answer's paired P(yes).
                let (labels, paired) = match question.paired {
                    Some(_) => {
                        let (labels, paired) = joint_marginals(readout);
                        let paired = PairedAnswer {
                            question: self.paired.id,
                            question_version: self.paired.version,
                            probability: paired.clamp(0.0, 1.0),
                        };
                        (labels, Some(paired))
                    }
                    None => (readout.clone(), None),
                };
                // The first label wins a tie, so a tied noul reads yes.
                let mut top = 0;
                for (i, p) in labels.iter().enumerate() {
                    if *p > labels[top] {
                        top = i;
                    }
                }
                // Each readout reports yes first.
                let probability = |p: f64| p.clamp(0.0, 1.0);
                let (answer, probability) = match (question.labels, &asked.contract) {
                    // A noul's probability is P(yes), whichever way it reads.
                    (LabelSet::Noul, _) => (DecisionAnswer::Noul(top == 0), probability(labels[0])),
                    // A score's level stands for its place on the score's scale.
                    (LabelSet::Choice(levels), AnswerContract::Score { min, max }) => (
                        DecisionAnswer::Score(level_score(*min, *max, top, levels.len())),
                        probability(labels[top]),
                    ),
                    (LabelSet::Choice(options), _) => (
                        DecisionAnswer::Choice(options[top].clone()),
                        probability(labels[top]),
                    ),
                };
                ProviderDecision {
                    answer,
                    probability: Some(probability),
                    paired,
                    person: None,
                    served: None,
                }
            })
            .collect();
        Ok(slots
            .into_iter()
            .map(|slot| slot.map_or_else(abstained, |index| decisions[index].clone()))
            .collect())
    }
}
