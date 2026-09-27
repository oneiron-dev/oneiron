//! Host-injected, one-step decision ladder. The engine owns routing and receipts.

use super::policy::{BandMode, DecisionBandPolicy, Reversibility};
use super::types::invalid;
use super::{
    DecisionAnswer, DecisionDial, DecisionQuestion, DecisionReceipt, DecisionRung, HumanAskReason,
    ProviderPin, TypedDecision,
};
use crate::{EntityId, Result};
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderDecision {
    pub answer: DecisionAnswer,
    pub probability: Option<f64>,
}

impl ProviderDecision {
    fn validate(&self, question: &DecisionQuestion) -> Result<()> {
        if !question.contract.accepts(&self.answer)
            || match self.answer {
                DecisionAnswer::Abstain => self.probability.is_some(),
                _ => !self
                    .probability
                    .is_some_and(|p| p.is_finite() && (0.0..=1.0).contains(&p)),
            }
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

/// Host adapter for local head, Jev (SystemOne), or big model. Model access,
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
    /// Host-issued versioned queue identity; the host renders its own text.
    pub queue_pin: ProviderPin,
}

pub trait HumanDecisionQueue: Send + Sync {
    fn queue(&self, request: HumanDecisionRequest) -> Result<()>;
}

/// Slots are fixed and cannot silently skip a missing rung. The fifth rung is
/// a queue, not a model-produced human answer.
pub struct DecisionLadder<'a> {
    pub rule: Option<&'a dyn DecisionProvider>,
    pub local: Option<&'a dyn DecisionProvider>,
    pub jev: Option<&'a dyn DecisionProvider>,
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
        let mut pins = Vec::new();
        let mut rung = dial.first;
        let mut prior = None;
        let mut in_band = false;
        if rung != DecisionRung::Human {
            let answer = self.run_provider(rung, question, evidence, &mut pins)?;
            in_band = answer.probability.is_some_and(|p| row.band.contains(p));
            prior = Some(answer);
            if in_band && row.mode == BandMode::Enforce && rung < dial.ceiling {
                rung = next_rung(rung);
            }
        }
        let mut human_ask = None;
        let outcome = if rung == DecisionRung::Human {
            validate_pin(&self.human_pin, DecisionRung::Human)?;
            let reason = if prior.is_some() {
                HumanAskReason::Uncertain
            } else {
                HumanAskReason::OwnerSelected
            };
            self.human.queue(HumanDecisionRequest {
                question: question.clone(),
                principal,
                evidence: evidence.to_vec(),
                reason,
                prior,
                queue_pin: self.human_pin.clone(),
            })?;
            pins.push(self.human_pin.clone());
            human_ask = Some(reason);
            ProviderDecision {
                answer: DecisionAnswer::Abstain,
                probability: None,
            }
        } else if rung == dial.first {
            prior.expect("non-human first rung has an answer")
        } else {
            self.run_provider(rung, question, evidence, &mut pins)?
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
                providers: pins,
                band: row.band,
                band_version: row.version,
            },
        })
    }

    fn run_provider(
        &self,
        rung: DecisionRung,
        question: &DecisionQuestion,
        evidence: &[EntityId],
        pins: &mut Vec<ProviderPin>,
    ) -> Result<ProviderDecision> {
        let provider = match rung {
            DecisionRung::Rule => self.rule,
            DecisionRung::Local => self.local,
            DecisionRung::SystemOne => self.jev,
            DecisionRung::Big => self.big,
            DecisionRung::Human => None,
        }
        .ok_or_else(|| invalid("decision provider unavailable"))?;
        let pin = provider.pin();
        validate_pin(&pin, rung)?;
        let answer = provider.decide(question, evidence)?;
        answer.validate(question)?;
        pins.push(pin);
        Ok(answer)
    }
}

fn next_rung(rung: DecisionRung) -> DecisionRung {
    match rung {
        DecisionRung::Rule => DecisionRung::Local,
        DecisionRung::Local => DecisionRung::SystemOne,
        DecisionRung::SystemOne => DecisionRung::Big,
        DecisionRung::Big | DecisionRung::Human => DecisionRung::Human,
    }
}

fn validate_pin(pin: &ProviderPin, rung: DecisionRung) -> Result<()> {
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
