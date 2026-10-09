//! Fixed-label local decision seat; runtime/model loading stays with the host.

use super::{
    AnswerContract, DecisionAnswer, DecisionDial, DecisionQuestion, DecisionReceipt, DecisionRung,
    HumanAskReason, ProviderPin, TypedDecision, types::invalid,
};
use crate::{EntityId, Result};

/// A loaded GLiNER-class head supplies calibrated per-label probabilities.
/// It cannot select labels, invent a question, or write a verdict receipt.
pub trait LabelClassifier: Send + Sync {
    fn pin(&self) -> ProviderPin;
    fn scores(&self, question: &str, unit: &str, labels: &[String]) -> Result<Vec<f64>>;
}

/// An exact, versioned question and exact unit text are required for a rule.
/// An arithmetic rule uses operands supplied in this anchored row, not numbers
/// parsed or guessed by a classifier.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionRule {
    pub question: DecisionQuestion,
    pub unit: String,
    pub expression: RuleExpression,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuleExpression {
    Exact(DecisionAnswer),
    Ratio { numerator: f64, denominator: f64 },
}

impl DecisionRule {
    fn evaluate(&self, question: &DecisionQuestion, unit: &str) -> Result<Option<DecisionAnswer>> {
        if &self.question != question || self.unit != unit {
            return Ok(None);
        }
        let answer = match &self.expression {
            RuleExpression::Exact(answer) => answer.clone(),
            RuleExpression::Ratio {
                numerator,
                denominator,
            } => {
                if !numerator.is_finite() || !denominator.is_finite() || *denominator == 0.0 {
                    return Err(invalid("invalid decision ratio"));
                }
                let score = numerator / denominator;
                if !score.is_finite() {
                    return Err(invalid("invalid decision ratio"));
                }
                DecisionAnswer::Score(score)
            }
        };
        if matches!(answer, DecisionAnswer::Abstain) || !question.contract.accepts(&answer) {
            return Err(invalid("rule answer violates decision contract"));
        }
        Ok(Some(answer))
    }
}

/// A seat returns an engine-owned receipt; it cannot grant access or write a claim.
pub trait DecisionSeat {
    fn answer(&self, input: DecisionInput<'_>) -> Result<TypedDecision>;
}

pub struct DecisionInput<'a> {
    pub question: &'a DecisionQuestion,
    pub principal: EntityId,
    pub unit: &'a str,
    /// Already-scoped source references, supplied by the caller's read door.
    pub evidence: &'a [EntityId],
    pub owner: DecisionDial,
    pub resident: DecisionDial,
}

/// No checkpoint is bundled with the engine. The host injects an already-loaded
/// head; absent head and absent matching rule produce an explicit abstention.
pub struct LocalDecisionSeat<H> {
    pub head: Option<H>,
    pub rules: Vec<DecisionRule>,
}

impl<H: LabelClassifier> DecisionSeat for LocalDecisionSeat<H> {
    fn answer(&self, input: DecisionInput<'_>) -> Result<TypedDecision> {
        input.question.validate()?;
        let dial = input.owner.narrow(input.resident)?;
        let mut providers = Vec::new();
        let mut probability = None;
        let mut reason = HumanAskReason::ProviderUnavailable;
        let mut answer = DecisionAnswer::Abstain;

        if dial.first <= DecisionRung::Rule && dial.ceiling >= DecisionRung::Rule {
            for rule in &self.rules {
                if let Some(found) = rule.evaluate(input.question, input.unit)? {
                    probability = rule_probability(&found);
                    answer = found;
                    break;
                }
            }
        }
        if matches!(answer, DecisionAnswer::Abstain)
            && dial.first <= DecisionRung::Local
            && dial.ceiling >= DecisionRung::Local
            && let Some(head) = &self.head
        {
            let pin = head.pin();
            if pin.rung != DecisionRung::Local
                || pin.model.trim().is_empty()
                || pin.version.trim().is_empty()
            {
                return Err(invalid("invalid local classifier pin"));
            }
            if let Some(labels) = labels(&input.question.contract) {
                providers.push(pin);
                if let Ok(scores) = head.scores(&input.question.text, input.unit, &labels)
                    && scores.len() == labels.len()
                    && scores
                        .iter()
                        .all(|v| v.is_finite() && (0.0..=1.0).contains(v))
                {
                    // A valid head response is evidence of uncertainty, not an outage,
                    // even when its winning labels tie or disagree with p(yes).
                    reason = HumanAskReason::Uncertain;
                    let best = scores.iter().enumerate().max_by(|a, b| a.1.total_cmp(b.1));
                    if let Some((index, &confidence)) = best {
                        probability =
                            Some(if matches!(input.question.contract, AnswerContract::Noul) {
                                scores[0]
                            } else {
                                confidence
                            });
                        if scores.iter().filter(|&&score| score == confidence).count() == 1 {
                            answer = if matches!(input.question.contract, AnswerContract::Noul) {
                                // The two label scores need not sum to one. The answer
                                // follows p(yes) and the owner's (possibly asymmetric)
                                // band, but only when the winning label agrees.
                                match index {
                                    0 if scores[0] > dial.band.high => DecisionAnswer::Noul(true),
                                    1 if scores[0] < dial.band.low => DecisionAnswer::Noul(false),
                                    _ => DecisionAnswer::Abstain,
                                }
                            } else {
                                DecisionAnswer::Choice(labels[index].clone())
                            };
                        }
                    }
                }
            }
        }
        let in_band = probability.is_some_and(|p| dial.band.contains(p));
        // A head's uncalibrated or weak label is never an affirmative answer.
        // A confident accept-type negative needs a second measurement (not this seat).
        if in_band
            || (matches!(answer, DecisionAnswer::Choice(_))
                && probability.is_some_and(|p| p < dial.band.low))
            || (input.question.accept_type && answer == DecisionAnswer::Noul(false))
        {
            answer = DecisionAnswer::Abstain;
            reason = HumanAskReason::Uncertain;
        }
        Ok(TypedDecision {
            human_ask: matches!(answer, DecisionAnswer::Abstain).then_some(reason),
            answer,
            probability,
            evidence: input.evidence.to_vec(),
            in_band,
            receipt: DecisionReceipt {
                question: input.question.id,
                question_version: input.question.version,
                principal: input.principal,
                providers,
                band: dial.band,
                band_version: 0,
                evidence_versions: Vec::new(),
                cost_per_thousand: None,
            },
        })
    }
}

fn labels(contract: &AnswerContract) -> Option<Vec<String>> {
    match contract {
        AnswerContract::Noul => Some(vec!["yes".into(), "no".into()]),
        AnswerContract::Choice { options } => Some(options.clone()),
        AnswerContract::Score { .. } => None, // Numeric verdicts require an exact arithmetic rule.
    }
}

fn rule_probability(answer: &DecisionAnswer) -> Option<f64> {
    match answer {
        DecisionAnswer::Noul(true) => Some(1.0),
        DecisionAnswer::Noul(false) => Some(0.0),
        DecisionAnswer::Choice(_) => Some(1.0),
        DecisionAnswer::Score(_) | DecisionAnswer::Abstain => None,
    }
}
