//! Host-injected, one-step decision ladder. The engine owns routing and receipts.

use super::policy::{BandMode, DecisionBandPolicy, PersonThreshold, Reversibility};
use super::types::{invalid, paired_valid};
use super::{
    DecisionAnswer, DecisionDial, DecisionQuestion, DecisionReceipt, DecisionRung, HumanAskReason,
    PairedReading, PersonChangedAnswer, ProviderPin, TypedDecision,
};
use crate::{EntityId, Result};
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

/// Providers see only caller-prepared, access-checked evidence references.
/// Their outputs contain no authority fields, receipt, or provenance label.
pub trait DecisionProvider: Send + Sync {
    fn pin(&self) -> ProviderPin;
    fn decide(
        &self,
        question: &DecisionQuestion,
        evidence: &[EntityId],
    ) -> Result<ProviderDecision>;
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

    fn decide(
        &self,
        question: &DecisionQuestion,
        _evidence: &[EntityId],
    ) -> Result<ProviderDecision> {
        self.rows
            .get(&(question.id, question.version))
            .cloned()
            .ok_or_else(|| invalid("no matching offline rule"))
    }
}

/// Host adapter for the local head, the System One rung or the big model. Model access,
/// budget admission, egress, and evidence reads stay with the host.
pub trait DecisionModel: Send + Sync {
    fn decide(
        &self,
        question: &DecisionQuestion,
        evidence: &[EntityId],
    ) -> Result<ProviderDecision>;
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
    fn decide(
        &self,
        question: &DecisionQuestion,
        evidence: &[EntityId],
    ) -> Result<ProviderDecision> {
        self.model.decide(question, evidence)
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
}

impl DecisionLadder<'_> {
    pub fn run(
        &self,
        question: &DecisionQuestion,
        principal: EntityId,
        evidence: &[EntityId],
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
    ) -> Result<TypedDecision> {
        question.validate()?; // Provenance cannot reach any provider or queue.
        dial.band.validate()?;
        if dial.first > dial.ceiling {
            return Err(invalid("invalid decision dial"));
        }
        let row = policy.resolve(question, reversibility, dial.band)?;
        // Only a surface whose dial reaches the person rung routes on a person reading.
        let person_row = policy
            .person_threshold()
            .filter(|_| dial.ceiling == DecisionRung::Human);
        let mut readings = Readings::default();
        let mut rung = dial.first;
        let mut prior = None;
        let mut in_band = false;
        let mut needs_person = false;
        let mut unavailable = false;
        if rung != DecisionRung::Human {
            let answer = self.run_provider(rung, question, evidence, &mut readings)?;
            in_band = answer.probability.is_some_and(|p| row.band.contains(p));
            needs_person = asks_person(&answer, person_row);
            prior = Some(answer);
            if needs_person {
                rung = DecisionRung::Human;
            } else if in_band && row.mode == BandMode::Enforce && rung < dial.ceiling {
                match self.next_available(rung, dial.ceiling) {
                    None => unavailable = true,
                    Some(DecisionRung::Human) => rung = DecisionRung::Human,
                    Some(next) => {
                        rung = next;
                        let answer = self.run_provider(rung, question, evidence, &mut readings)?;
                        if asks_person(&answer, person_row) {
                            needs_person = true;
                            rung = DecisionRung::Human;
                        }
                        prior = Some(answer);
                    }
                }
            }
        }
        let mut human_ask = None;
        let outcome = if unavailable {
            // No rung up to the ceiling can take the step: a typed abstention.
            human_ask = Some(HumanAskReason::ProviderUnavailable);
            ProviderDecision {
                answer: DecisionAnswer::Abstain,
                probability: None,
                paired: None,
                person: None,
            }
        } else if rung == DecisionRung::Human {
            validate_pin(&self.human_pin, DecisionRung::Human)?;
            let reason = if needs_person {
                HumanAskReason::NeedsPerson
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
            ProviderDecision {
                answer: DecisionAnswer::Abstain,
                probability: None,
                paired: None,
                person: None,
            }
        } else {
            prior.expect("a non-human rung has an answer")
        };
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

    /// The next rung above `rung` that can answer, up to `ceiling`. The person's
    /// queue is always present (ARCH-0076 #posture: no house model sends the step
    /// to the big model or the person).
    fn next_available(
        &self,
        mut rung: DecisionRung,
        ceiling: DecisionRung,
    ) -> Option<DecisionRung> {
        while rung < ceiling {
            rung = next_rung(rung);
            if rung == DecisionRung::Human || self.slot(rung).is_some() {
                return Some(rung);
            }
        }
        None
    }

    fn run_provider(
        &self,
        rung: DecisionRung,
        question: &DecisionQuestion,
        evidence: &[EntityId],
        readings: &mut Readings,
    ) -> Result<ProviderDecision> {
        let provider = self
            .slot(rung)
            .ok_or_else(|| invalid("decision provider unavailable"))?;
        let pin = provider.pin();
        validate_pin(&pin, rung)?;
        let answer = provider.decide(question, evidence)?;
        answer.validate(question)?;
        if let Some(reading) = answer.paired {
            readings.paired.push(reading.bind(pin.clone()));
        }
        if let Some(reading) = answer.person {
            readings.person.push(reading.bind(pin.clone()));
        }
        readings.pins.push(pin);
        Ok(answer)
    }
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
