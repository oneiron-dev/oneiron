//! Decision ladder providers and the calls they answer.
//! Entry: ProviderDecision.
//! Definitions: this module; the parent re-exports the old paths.

use super::{abstained, validate_pin};
use crate::llm::decision::types::{invalid, paired_valid};
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionAudio, DecisionImage, DecisionQuestion, DecisionRung,
    HostRuleRef, PairedReading, ProviderPin,
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
    /// The model that answered when the provider's pin names a seat rather than one
    /// model: a seat rung that served the call, its fallback included (FIX 2730). It
    /// keeps the provider pin's rung and version, and the receipt names it instead.
    pub served: Option<ProviderPin>,
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

    /// The pin this answer's receipt names, of a provider pinned `pin`: the model that
    /// served it on `pin`'s rung and version, else `pin`.
    pub(crate) fn answered_pin(&self, pin: &ProviderPin) -> Result<ProviderPin> {
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

/// One prepared call: the question, its access-checked evidence, the bounded state the host
/// built from that evidence, and the call's one clock. Every provider gets the same call.
#[derive(Clone, Copy)]
pub struct DecisionCall<'a> {
    pub question: &'a DecisionQuestion,
    pub evidence: &'a [EntityId],
    /// Images the question reads, each filling the state field of its name. Only a
    /// provider that reads images gets a call with any.
    pub images: &'a [DecisionImage],
    /// Audio clips the question reads, each filling the state field of its name. Only a
    /// provider that reads audio gets a call with any.
    pub audio: &'a [DecisionAudio],
    /// A JSON object its producer measured; never an implicit vault dump.
    pub state: &'a Value,
    /// A provider with a native deadline gets [`RetrievalDeadline::decision_time_left`], and
    /// its client waits no longer.
    pub deadline: &'a RetrievalDeadline,
}

impl DecisionCall<'_> {
    /// The caller's score levels this call carries ([`score_levels_in`]).
    #[must_use]
    pub fn score_levels(&self) -> Option<Vec<String>> {
        score_levels_in(self.question, self.state)
    }
}

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

/// Several typed questions asked as one request over one state. Each question carries its
/// own text (its description) and its own contract; the state is their shared prefix.
#[derive(Clone, Copy)]
pub struct DecisionPack<'a> {
    pub questions: &'a [&'a DecisionQuestion],
    pub evidence: &'a [EntityId],
    pub images: &'a [DecisionImage],
    pub audio: &'a [DecisionAudio],
    pub state: &'a Value,
    pub deadline: &'a RetrievalDeadline,
}

impl<'a> DecisionPack<'a> {
    /// The pack's `index`th question as a single call over the same state.
    pub fn call(&self, index: usize) -> Option<DecisionCall<'a>> {
        self.questions.get(index).map(|&question| DecisionCall {
            question,
            evidence: self.evidence,
            images: self.images,
            audio: self.audio,
            state: self.state,
            deadline: self.deadline,
        })
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
    /// Whether it reads images. The ladder skips a provider that does not for a call with
    /// images, and so for every Box or Point question.
    fn reads_images(&self) -> bool {
        false
    }
    /// The long edge it fits each image to before sending it; none when it sends the
    /// pixels as handed in. The receipt pins what each measurement was sent.
    fn image_edge(&self) -> Option<u32> {
        None
    }
    /// Whether it hears audio clips. The ladder skips a provider that does not for a call
    /// with any.
    fn reads_audio(&self) -> bool {
        false
    }
    /// Whether its calls send unit text off the host: a remote seat, or a model on a
    /// third-party route. [`DecisionLadder::under_posture`](super::DecisionLadder::under_posture) empties its slot where the
    /// posture keeps the text local.
    fn leaves_host(&self) -> bool {
        false
    }
    /// What it costs per thousand units at its rung, as its host knows it (its registered
    /// price over the units it reads); none when the host knows none. The receipt of an
    /// answer it gives carries it (ARCH-0076, "Cost").
    fn cost_per_thousand(&self) -> Option<f64> {
        None
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
    /// The stored rule row that gave `decision` for `call`, for a provider that answers
    /// from rule rows: the receipt names it as id@revision (ARCH-0040, "a rule row as
    /// id@version"). None for every other provider.
    fn rule_row(
        &self,
        _call: &DecisionCall<'_>,
        _decision: &ProviderDecision,
    ) -> Option<HostRuleRef> {
        None
    }
}

/// Deterministic offline answer table, scoped by exact question version. A question with
/// no row has no rule here: the table abstains, and the ladder takes it to the next rung.
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
        Ok(self
            .rows
            .get(&(call.question.id, call.question.version))
            .cloned()
            .unwrap_or_else(abstained))
    }
}

/// Host adapter for the local head, the System One rung or the big model. Model access,
/// budget admission, egress, and evidence reads stay with the host.
pub trait DecisionModel: Send + Sync {
    fn capability(&self) -> ProviderCapability {
        ProviderCapability::default()
    }
    /// See [`DecisionProvider::reads_images`].
    fn reads_images(&self) -> bool {
        false
    }
    /// See [`DecisionProvider::image_edge`].
    fn image_edge(&self) -> Option<u32> {
        None
    }
    /// See [`DecisionProvider::reads_audio`].
    fn reads_audio(&self) -> bool {
        false
    }
    /// See [`DecisionProvider::leaves_host`].
    fn leaves_host(&self) -> bool {
        false
    }
    /// See [`DecisionProvider::cost_per_thousand`].
    fn cost_per_thousand(&self) -> Option<f64> {
        None
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
    fn reads_images(&self) -> bool {
        self.model.reads_images()
    }
    fn image_edge(&self) -> Option<u32> {
        self.model.image_edge()
    }
    fn reads_audio(&self) -> bool {
        self.model.reads_audio()
    }
    fn leaves_host(&self) -> bool {
        self.model.leaves_host()
    }
    fn cost_per_thousand(&self) -> Option<f64> {
        self.model.cost_per_thousand()
    }
    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        self.model.decide(call)
    }
    fn decide_pack(&self, pack: &DecisionPack<'_>) -> Result<Vec<ProviderDecision>> {
        self.model.decide_pack(pack)
    }
}
