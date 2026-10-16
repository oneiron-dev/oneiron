//! The escalation rung's decision read: the house model scores the question's labels and the
//! paired "does this need more thinking?" question in one forward evaluation. The person
//! question ("ask a person?") is its own typed question in the ladder's pack, read apart.

use super::ladder::{
    DecisionCall, DecisionProvider, PairedAnswer, ProviderCapability, ProviderDecision,
    validate_pin,
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
            score: false,
            ..ProviderCapability::default()
        }
    }

    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        let DecisionCall {
            question,
            state,
            deadline,
            ..
        } = *call;
        if question.id == self.paired.id {
            return Err(invalid("invalid paired question"));
        }
        let labels = match &question.contract {
            AnswerContract::Noul => LabelSet::Noul,
            AnswerContract::Choice { options } => LabelSet::Choice(options),
            AnswerContract::Score { .. } => {
                return Err(invalid("a decision read takes noul and choice questions"));
            }
        };
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
            primary: LabelReadout {
                text: &question.text,
                labels,
            },
            paired: &self.paired.text,
            // The ladder asks the person question as its own typed question.
            person: None,
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
        let count = match labels {
            LabelSet::Noul => 2,
            LabelSet::Choice(options) => options.len(),
        };
        let unit = |p: &f64| p.is_finite() && (0.0..=1.0).contains(p);
        if read.primary.len() != count
            || !read.primary.iter().all(unit)
            || (read.primary.iter().sum::<f64>() - 1.0).abs() > DISTRIBUTION_TOLERANCE
            || !unit(&read.paired_yes)
            || read.person_yes.is_some()
        {
            return Err(invalid("malformed decision read"));
        }
        // The first label wins a tie, so a tied noul reads yes.
        let mut top = 0;
        for (i, p) in read.primary.iter().enumerate() {
            if *p > read.primary[top] {
                top = i;
            }
        }
        let (answer, probability) = match labels {
            // A noul's probability is P(yes), whichever way it reads.
            LabelSet::Noul => (DecisionAnswer::Noul(top == 0), read.primary[0]),
            LabelSet::Choice(options) => (
                DecisionAnswer::Choice(options[top].clone()),
                read.primary[top],
            ),
        };
        Ok(ProviderDecision {
            answer,
            probability: Some(probability),
            paired: Some(PairedAnswer {
                question: self.paired.id,
                question_version: self.paired.version,
                probability: read.paired_yes,
            }),
            person: None,
        })
    }
}
