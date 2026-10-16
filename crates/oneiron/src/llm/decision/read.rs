//! The escalation rung's decision read: the house model scores the question's labels, the
//! paired "does this need more thinking?" question and, when the host asks it, the person
//! question ("ask a person?") in one forward evaluation.

use super::ladder::{DecisionProvider, PairedAnswer, ProviderDecision, validate_pin};
use super::types::invalid;
use super::{AnswerContract, DecisionAnswer, DecisionQuestion, DecisionRung, ProviderPin};
use crate::llm::{BudgetGuard, LabelReadModel, LabelReadRequest, LabelReadout, LabelSet, LlmUsage};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Result};
use serde_json::Value;
use std::time::Instant;

/// A read's label probabilities sum to one within this tolerance.
const DISTRIBUTION_TOLERANCE: f64 = 1e-6;
/// The remote seat's state bound.
const MAX_STATE_BYTES: usize = 65_536;

/// One prepared call: the question, its access-checked evidence, and the bounded state the
/// host built from that evidence.
#[derive(Debug, Clone, Copy)]
pub struct DecisionReadCall<'a> {
    pub question: &'a DecisionQuestion,
    pub evidence: &'a [EntityId],
    pub state: &'a Value,
}

/// Fills the escalation slot. It is built per prepared call, reads only that call's state,
/// admits and settles one lease per read, and returns no authority, receipt or provenance.
pub struct DecisionReadProvider<'a> {
    pin: ProviderPin,
    reader: &'a dyn LabelReadModel,
    guard: &'a BudgetGuard,
    paired: &'a DecisionQuestion,
    person: Option<&'a DecisionQuestion>,
    call: DecisionReadCall<'a>,
}

impl<'a> DecisionReadProvider<'a> {
    /// `pin` names the model the route bound, and the reader must serve exactly that model
    /// and revision. `paired` is the host's versioned yes/no question.
    pub fn new(
        pin: ProviderPin,
        reader: &'a dyn LabelReadModel,
        guard: &'a BudgetGuard,
        paired: &'a DecisionQuestion,
        call: DecisionReadCall<'a>,
    ) -> Result<Self> {
        validate_pin(&pin, DecisionRung::Escalation)?;
        if pin.model != reader.model() || pin.version != reader.revision() {
            return Err(invalid("decision reader serves another model"));
        }
        call.question.validate()?;
        paired.validate()?;
        if paired.contract != AnswerContract::Noul || paired.id == call.question.id {
            return Err(invalid("invalid paired question"));
        }
        let state_bytes =
            serde_json::to_vec(call.state).map_err(|_| invalid("invalid decision read state"))?;
        if !call.state.is_object() || state_bytes.len() > MAX_STATE_BYTES {
            return Err(invalid("invalid decision read state"));
        }
        Ok(Self {
            pin,
            reader,
            guard,
            paired,
            person: None,
            call,
        })
    }

    /// Reads the host's versioned person question in the same evaluation.
    pub fn with_person(mut self, person: &'a DecisionQuestion) -> Result<Self> {
        person.validate()?;
        if person.contract != AnswerContract::Noul
            || person.id == self.call.question.id
            || person.id == self.paired.id
        {
            return Err(invalid("invalid person question"));
        }
        self.person = Some(person);
        Ok(self)
    }
}

impl DecisionProvider for DecisionReadProvider<'_> {
    fn pin(&self) -> ProviderPin {
        self.pin.clone()
    }

    fn decide(
        &self,
        question: &DecisionQuestion,
        evidence: &[EntityId],
        deadline: &RetrievalDeadline,
    ) -> Result<ProviderDecision> {
        if question != self.call.question || evidence != self.call.evidence {
            return Err(invalid("decision read prepared for another call"));
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
            state: self.call.state,
            primary: LabelReadout {
                text: &question.text,
                labels,
            },
            paired: &self.paired.text,
            person: self.person.map(|person| person.text.as_str()),
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
            || read.person_yes.is_some() != self.person.is_some()
            || !read.person_yes.iter().all(unit)
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
            person: self
                .person
                .zip(read.person_yes)
                .map(|(person, probability)| PairedAnswer {
                    question: person.id,
                    question_version: person.version,
                    probability,
                }),
        })
    }
}
