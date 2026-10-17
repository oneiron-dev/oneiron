//! The escalation rung's decision read: the house model reads the paired "does this need more
//! thinking?" question and the pack's questions as one pack: each its own question over the
//! same state, in one request, normalized apart (idle-fold test 6b). The person question ("ask
//! a person?") is the ladder's own typed question, the pack's last, so it is the last readout.

use super::ladder::{
    DecisionCall, DecisionPack, DecisionProvider, PairedAnswer, ProviderCapability,
    ProviderDecision, validate_pin,
};
use super::types::invalid;
use super::{AnswerContract, DecisionAnswer, DecisionQuestion, DecisionRung, ProviderPin};
use crate::Result;
use crate::llm::{BudgetGuard, LabelReadModel, LabelReadRequest, LabelReadout, LabelSet, LlmUsage};
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
}

impl<'a> DecisionReadProvider<'a> {
    /// `pin` names the model the route bound, and the reader must serve exactly that model
    /// and revision. `paired` is the host's versioned yes/no question.
    pub fn new(
        pin: ProviderPin,
        reader: &'a dyn LabelReadModel,
        guard: &'a BudgetGuard,
        paired: &'a DecisionQuestion,
    ) -> Result<Self> {
        validate_pin(&pin, DecisionRung::Escalation)?;
        if pin.model != reader.model() || pin.version != reader.revision() {
            return Err(invalid("decision reader serves another model"));
        }
        paired.validate()?;
        if paired.contract != AnswerContract::Noul {
            return Err(invalid("invalid paired question"));
        }
        Ok(Self {
            pin,
            reader,
            guard,
            paired,
        })
    }
}

impl DecisionProvider for DecisionReadProvider<'_> {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    fn capability(&self) -> ProviderCapability {
        ProviderCapability {
            max_options: self.reader.max_labels(),
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

    /// One read: the paired question, then the pack's questions in order. The paired P(yes)
    /// joins every answer.
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
        let mut questions = Vec::with_capacity(asked.len() + 1);
        questions.push(LabelReadout {
            text: &self.paired.text,
            labels: LabelSet::Noul,
        });
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
            questions.push(LabelReadout {
                text: &question.text,
                labels,
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
            readout.len() == question.labels.len()
                && readout.iter().all(unit)
                && (readout.iter().sum::<f64>() - 1.0).abs() <= DISTRIBUTION_TOLERANCE
        };
        if read.readouts.len() != questions.len()
            || !read.readouts.iter().zip(&questions).all(distribution)
        {
            return Err(invalid("malformed decision read"));
        }
        // Each readout reports yes first.
        let paired = PairedAnswer {
            question: self.paired.id,
            question_version: self.paired.version,
            probability: read.readouts[0][0],
        };
        Ok(questions[1..]
            .iter()
            .zip(&read.readouts[1..])
            .map(|(question, readout)| {
                // The first label wins a tie, so a tied noul reads yes.
                let mut top = 0;
                for (i, p) in readout.iter().enumerate() {
                    if *p > readout[top] {
                        top = i;
                    }
                }
                let (answer, probability) = match question.labels {
                    // A noul's probability is P(yes), whichever way it reads.
                    LabelSet::Noul => (DecisionAnswer::Noul(top == 0), readout[0]),
                    LabelSet::Choice(options) => {
                        (DecisionAnswer::Choice(options[top].clone()), readout[top])
                    }
                };
                ProviderDecision {
                    answer,
                    probability: Some(probability),
                    paired: Some(paired),
                    person: None,
                }
            })
            .collect())
    }
}
