//! Provider answer values, capabilities, and score-level rules.

use super::{
    AnswerContract, DecisionAnswer, DecisionQuestion, DecisionRung, PairedReading, ProviderPin,
    invalid, paired_valid,
};
use oneiron_contracts::{EntityId, Result};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderDecision {
    pub answer: DecisionAnswer,
    pub probability: Option<f64>,
    /// The paired question's reading from the same measurement, when the provider takes one.
    pub paired: Option<PairedAnswer>,
    /// The person question's reading ("ask a person?") from that same measurement.
    pub person: Option<PairedAnswer>,
    /// The model that answered when the provider's pin names a seat rather than one
    /// model: a seat rung that served the call, its fallback included (FIX 2730). It
    /// keeps the provider pin's rung and version, and the receipt names it instead.
    pub served: Option<ProviderPin>,
    /// Cost per thousand units from this answer's own measurement. An outer `None`
    /// uses the provider's rate; `Some(None)` records an unknown measured cost and
    /// must not fall back to a rate for a different model.
    pub cost_per_thousand: Option<Option<f64>>,
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
    pub fn bind(self, provider: ProviderPin) -> PairedReading {
        PairedReading {
            provider,
            question: self.question,
            question_version: self.question_version,
            probability: self.probability,
        }
    }
}

impl ProviderDecision {
    pub fn validate(&self, question: &DecisionQuestion) -> Result<()> {
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

    /// The pin this answer's receipt names, of a provider pinned `pin`: the model that
    /// served it on `pin`'s rung and version, else `pin`.
    pub fn answered_pin(&self, pin: &ProviderPin) -> Result<ProviderPin> {
        let Some(served) = &self.served else {
            return Ok(pin.clone());
        };
        if served.version != pin.version {
            return Err(invalid("a served pin keeps its provider's version"));
        }
        validate_pin(served, pin.rung)?;
        Ok(served.clone())
    }
}

/// The state size a host that fits its own state fits it to. The ladder refuses no state by
/// its size: a producer measures it at `limits.maintenance_text_bytes`.
pub const MAX_DECISION_STATE_BYTES: usize = 65_536;

/// The state field a caller names a score question's levels in (FIX 3269), as its criteria
/// ride in `criteria`: labels in ascending order, at least two.
pub const SCORE_LEVELS_FIELD: &str = "score_levels";

/// The most bytes one score level's label holds, as a seat request takes it.
pub const MAX_SCORE_LEVEL_BYTES: usize = 256;

/// The caller's levels for `question` over `state`, so a rung that reads a score as levels
/// (System One, the house label read) takes it: `None` for a question that is no score, or a
/// state whose `score_levels` is not at least two nonempty labels of at most
/// [`MAX_SCORE_LEVEL_BYTES`]. Such a rung abstains on a score with none.
#[must_use]
pub fn score_levels_in(question: &DecisionQuestion, state: &Value) -> Option<Vec<String>> {
    if !matches!(question.contract, AnswerContract::Score { .. }) {
        return None;
    }
    let levels: Vec<String> =
        serde_json::from_value(state.get(SCORE_LEVELS_FIELD)?.clone()).ok()?;
    (levels.len() >= 2
        && levels
            .iter()
            .all(|level| !level.trim().is_empty() && level.len() <= MAX_SCORE_LEVEL_BYTES))
    .then_some(levels)
}

/// The score level `index` of `count` stands for on a `min`..`max` scale: the ends exact,
/// the levels between evenly spaced.
#[must_use]
pub fn level_score(min: f64, max: f64, index: usize, count: usize) -> f64 {
    let ceiling = count.saturating_sub(1).max(1) as f64;
    let t = index as f64 / ceiling;
    if t <= 0.0 {
        min
    } else if t >= 1.0 {
        max
    } else {
        ((1.0 - t) * min + t * max).clamp(min, max)
    }
}

/// What a provider can take. The ladder skips a rung whose provider cannot take a question,
/// as it skips an empty slot; it never trims a question to fit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderCapability {
    /// The most options one choice question may offer it. A choice's contract sets no
    /// count: a wider one is never cut to fit (FIX 9908); it is read in chunks within this
    /// bound and a final read among their winners (FIX 11235).
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
            // A box or a point is found in an image: the ladder also asks the provider
            // whether it reads images.
            AnswerContract::Box | AnswerContract::Point => true,
        }
    }
}

pub fn validate_pin(pin: &ProviderPin, rung: DecisionRung) -> Result<()> {
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
