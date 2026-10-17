//! The escalation rung's decision read: the house model reads the pack's questions over the
//! same state in one request. Each question is read jointly with the paired "does this need
//! more thinking?" question (ARCH-0076 `#ask-a-person`: Q1 and Q2 stay joint): one readout over
//! single-token (option, paired answer) labels, normalized once, whose marginals are the answer
//! and that answer's own paired reading. The person question ("ask a person?") is the ladder's
//! own typed question, the pack's last; the host binds it here, and it is read separately.

use super::ladder::{
    DecisionCall, DecisionPack, DecisionProvider, PairedAnswer, ProviderCapability,
    ProviderDecision, validate_pin,
};
use super::types::invalid;
use super::{AnswerContract, DecisionAnswer, DecisionQuestion, DecisionRung, ProviderPin};
use crate::Result;
use crate::llm::{
    BudgetGuard, LabelReadModel, LabelReadRequest, LabelReadout, LabelSet, LlmUsage,
    joint_marginals,
};
use std::time::Instant;

/// A read's label probabilities sum to one within this tolerance.
const DISTRIBUTION_TOLERANCE: f64 = 1e-6;
/// Fills the escalation slot. It reads only the call's state, admits and settles one lease per
/// read, and returns no authority, receipt or provenance.
pub struct DecisionReadProvider<'a> {
    pin: ProviderPin,
    reader: &'a dyn LabelReadModel,
    guard: &'a BudgetGuard,
    paired: &'a DecisionQuestion,
    person: Option<&'a DecisionQuestion>,
}

impl<'a> DecisionReadProvider<'a> {
    /// `pin` names the model the route bound, and the reader must serve exactly that model
    /// and revision. `paired` is the host's versioned yes/no question, and `person` the
    /// ladder's person question when the host binds one.
    pub fn new(
        pin: ProviderPin,
        reader: &'a dyn LabelReadModel,
        guard: &'a BudgetGuard,
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
            guard,
            paired,
            person,
        })
    }
}

impl DecisionProvider for DecisionReadProvider<'_> {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    /// A question's options are read two joint labels each.
    fn capability(&self) -> ProviderCapability {
        ProviderCapability {
            max_options: self.reader.max_labels() / 2,
            score: false,
        }
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
        let mut questions = Vec::with_capacity(asked.len());
        for question in asked {
            if question.id == self.paired.id {
                return Err(invalid("invalid paired question"));
            }
            let labels = match &question.contract {
                AnswerContract::Noul => LabelSet::Noul,
                AnswerContract::Choice { options } => LabelSet::Choice(options),
                AnswerContract::Score { .. } | AnswerContract::Box => {
                    return Err(invalid("a decision read takes noul and choice questions"));
                }
            };
            let person = self.person.is_some_and(|person| person.id == question.id);
            questions.push(LabelReadout {
                text: &question.text,
                labels,
                paired: (!person).then_some(self.paired.text.as_str()),
            });
        }
        let lease = self
            .guard
            .admit()
            .map_err(|_| invalid("decision read refused by the budget"))?
            .lease;
        // Admission may wait; a read admitted after the work time is spent never starts.
        if !deadline.decision_may_start() {
            self.guard
                .settle_per_call(&lease, &LlmUsage::zero())
                .map_err(|_| invalid("decision read settlement refused"))?;
            return Err(invalid("decision read admitted after the work time"));
        }
        let request = LabelReadRequest {
            state,
            questions: &questions,
            // An instant, not a duration, so the reader's own preparation spends it too.
            work_until: Some(Instant::now() + deadline.decision_time_left()),
        };
        let read = match self.reader.read(&request, &lease) {
            Ok(read) => {
                self.guard
                    .settle_per_call(&lease, &read.usage)
                    .map_err(|_| invalid("decision read settlement refused"))?;
                read
            }
            Err(error) => {
                self.guard
                    .settle_reserved(&lease)
                    .map_err(|_| invalid("decision read settlement refused"))?;
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
        Ok(questions
            .iter()
            .zip(&read.readouts)
            .map(|(question, readout)| {
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
                let (answer, probability) = match question.labels {
                    // A noul's probability is P(yes), whichever way it reads.
                    LabelSet::Noul => (DecisionAnswer::Noul(top == 0), probability(labels[0])),
                    LabelSet::Choice(options) => (
                        DecisionAnswer::Choice(options[top].clone()),
                        probability(labels[top]),
                    ),
                };
                ProviderDecision {
                    answer,
                    probability: Some(probability),
                    paired,
                    person: None,
                }
            })
            .collect())
    }
}
