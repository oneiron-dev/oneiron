//! Decision ladder providers and the calls they answer.
//! Entry: ProviderDecision.
//! Definitions: this module; the parent re-exports the old paths.

use super::{abstained, validate_pin};
use crate::llm::decision::types::invalid;
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionAudio, DecisionImage, DecisionQuestion, DecisionRung,
    HostRuleRef, PairedReading, ProviderPin,
};
use crate::llm::run_admission::{RunAdmission, RunReceipt};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Result};
use oneiron_model::llm::{CallPurpose, ExtractionEgressPredicate};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

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
    /// The caller's run, when the call is metered on it (FIX 10443): a provider that
    /// spends admits on this run, sourced with the call's evidence, instead of a run of
    /// its own. `None` keeps today's own mint/carry behavior.
    pub run: Option<&'a RunAdmission>,
}

impl DecisionCall<'_> {
    /// The caller's score levels this call carries ([`score_levels_in`]).
    #[must_use]
    pub fn score_levels(&self) -> Option<Vec<String>> {
        score_levels_in(self.question, self.state)
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
    /// The caller's run, when the pack is metered on it (FIX 10443): as
    /// [`DecisionCall::run`], carried into each question's call.
    pub run: Option<&'a RunAdmission>,
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
            run: self.run,
        })
    }
}

/// The original host purpose and egress predicate of a prepared read.
/// The provider still resolves its own model binding; this carries no caller binding.
pub struct DecisionCallContext<'a> {
    pub purpose: &'a CallPurpose,
    pub extraction_egress: Option<&'a dyn ExtractionEgressPredicate>,
    /// The caller's per-invocation allowance, checked at each native generation start.
    pub generation: Option<&'a dyn DecisionGenerationAdmission>,
}

/// Admission for one logical generation, not one returned receipt or whole pack.
/// A native packed provider checks this once per request; a sequential provider
/// checks it before each of its requests. A memo replay starts no generation.
pub trait DecisionGenerationAdmission: Send + Sync {
    /// False keeps this generation unstarted; it is not a provider failure.
    fn admit(&self) -> bool;
}

impl DecisionCallContext<'_> {
    /// Checks the caller's allowance after native preflights, before a request starts.
    pub fn admit_generation(&self) -> bool {
        self.generation
            .is_none_or(DecisionGenerationAdmission::admit)
    }
}

/// Whether a native read started, apart from its provider result. An unstarted
/// stronger read leaves the ladder's prior answer available for its normal cut rule.
pub enum DecisionReadOutcome<T> {
    NotStarted,
    Answered(T),
}

impl<T> DecisionReadOutcome<T> {
    /// Transforms only a returned answer, never an unstarted read.
    pub fn map<U>(self, answer: impl FnOnce(T) -> U) -> DecisionReadOutcome<U> {
        match self {
            Self::NotStarted => DecisionReadOutcome::NotStarted,
            Self::Answered(value) => DecisionReadOutcome::Answered(answer(value)),
        }
    }
}

/// A provider read's original result beside copies of its native settlements.
/// Receipt usage stays optional; neither an empty inventory nor a receipt count
/// establishes token use or a number of logical generations.
pub struct CapturedDecision {
    pub result: Result<DecisionReadOutcome<ProviderDecision>>,
    pub receipts: Vec<RunReceipt>,
}

/// A native pack's original result and every settlement in its paid prefix,
/// including when a later request fails. Usage remains optional on each receipt.
pub struct CapturedDecisionPack {
    pub result: Result<Vec<DecisionReadOutcome<ProviderDecision>>>,
    pub receipts: Vec<RunReceipt>,
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
    /// The provider's own wire budget for the call's serialized state, in bytes,
    /// when the provider itself reports one; else `None` (unknown). A provider
    /// that knows only tokens answers `None`: bytes convert to nothing here.
    fn state_budget_bytes(&self) -> Option<usize> {
        None
    }
    /// A read with its native settlement inventory, when this provider can capture it.
    /// `None` means unsupported and MUST return before any read or send. A supported
    /// read retains its original result, including an error after paid work.
    fn decide_captured(
        &self,
        _call: &DecisionCall<'_>,
        _context: &DecisionCallContext<'_>,
    ) -> Option<CapturedDecision> {
        None
    }
    /// A pack with its native settlement inventory. Unsupported returns `None`
    /// before any request. Implementations preserve their ordinary pack shape and
    /// check `context`'s allowance before EACH native generation, retaining every
    /// settled prefix if a later generation fails. Never probe support by sending
    /// individual questions or replace a native packed call with a fanout.
    fn decide_pack_captured(
        &self,
        _pack: &DecisionPack<'_>,
        _context: &DecisionCallContext<'_>,
    ) -> Option<CapturedDecisionPack> {
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
    /// See [`DecisionProvider::state_budget_bytes`].
    fn state_budget_bytes(&self) -> Option<usize> {
        None
    }
    /// See [`DecisionProvider::decide_captured`].
    fn decide_captured(
        &self,
        _call: &DecisionCall<'_>,
        _context: &DecisionCallContext<'_>,
    ) -> Option<CapturedDecision> {
        None
    }
    /// See [`DecisionProvider::decide_pack_captured`].
    fn decide_pack_captured(
        &self,
        _pack: &DecisionPack<'_>,
        _context: &DecisionCallContext<'_>,
    ) -> Option<CapturedDecisionPack> {
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
    fn state_budget_bytes(&self) -> Option<usize> {
        self.model.state_budget_bytes()
    }
    fn decide_captured(
        &self,
        call: &DecisionCall<'_>,
        context: &DecisionCallContext<'_>,
    ) -> Option<CapturedDecision> {
        self.model.decide_captured(call, context)
    }
    fn decide_pack_captured(
        &self,
        pack: &DecisionPack<'_>,
        context: &DecisionCallContext<'_>,
    ) -> Option<CapturedDecisionPack> {
        self.model.decide_pack_captured(pack, context)
    }
    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        self.model.decide(call)
    }
    fn decide_pack(&self, pack: &DecisionPack<'_>) -> Result<Vec<ProviderDecision>> {
        self.model.decide_pack(pack)
    }
}

pub use crate::model_decision::{
    MAX_DECISION_STATE_BYTES, MAX_SCORE_LEVEL_BYTES, PairedAnswer, ProviderCapability,
    ProviderDecision, SCORE_LEVELS_FIELD, level_score, score_levels_in,
};
