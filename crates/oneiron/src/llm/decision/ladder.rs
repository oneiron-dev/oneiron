//! Host-injected, one-step decision ladder. The engine owns routing and receipts.

use super::policy::{
    BandMode, DecisionBandPolicy, LearnedBand, PersonThreshold, Reversibility, ThinkThreshold,
};
use super::types::{invalid, paired_valid};
use super::{
    AnswerContract, DecisionAnswer, DecisionAudio, DecisionDial, DecisionImage, DecisionQuestion,
    DecisionReceipt, DecisionRung, DecisionTime, HumanAskReason, ImagePin, PairedReading,
    PersonChangedAnswer, ProviderPin, Reasoning, ReasoningCause, StopCause, TypedDecision,
};
use crate::retrieval_depth::RetrievalDeadline;
use crate::{EntityId, Result};
use serde::{Deserialize, Serialize};
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

/// The state bound every provider is held to.
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
    /// A JSON object of at most [`MAX_DECISION_STATE_BYTES`]; never an implicit vault dump.
    pub state: &'a Value,
    /// A provider with a native deadline gets [`RetrievalDeadline::decision_time_left`], and
    /// its client waits no longer.
    pub deadline: &'a RetrievalDeadline,
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
    /// The most options one choice question may offer (the engine's contract allows 64).
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

/// Whether `provider` can take `question` over `images` and `audio`. A call carrying both
/// needs a provider that reads both; the ladder never drops one to fit.
fn takes(
    provider: &dyn DecisionProvider,
    question: &DecisionQuestion,
    images: &[DecisionImage],
    audio: &[DecisionAudio],
) -> bool {
    provider.capability().takes(question)
        && (images.is_empty() || provider.reads_images())
        && (audio.is_empty() || provider.reads_audio())
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
    /// third-party route. [`DecisionLadder::under_posture`] empties its slot where the
    /// posture keeps the text local.
    fn leaves_host(&self) -> bool {
        false
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
    fn decide(&self, call: &DecisionCall<'_>) -> Result<ProviderDecision> {
        self.model.decide(call)
    }
    fn decide_pack(&self, pack: &DecisionPack<'_>) -> Result<Vec<ProviderDecision>> {
        self.model.decide_pack(pack)
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
    /// Who the ask goes to, as the caller bound it ([`DecisionLadder::ask_to`]).
    pub to: AskTo,
    /// The work the ask decides, as the caller named it ([`DecisionLadder::correlation`]).
    pub correlation: Option<EntityId>,
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

/// A role an ask can go to (Q3 by role). A role names authority, not a person: the host
/// resolves who holds it when the ask is queued, and the answer door rechecks it. The
/// model asks for escalation; it never names the role or the actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum AskRole {
    /// The actor responsible for what the question is over (a schedule's, a question's or
    /// a unit's), as the caller binds it; with a project, the chain then walks that
    /// project's boards.
    Responsible {
        #[serde(with = "super::codec::entity")]
        actor: EntityId,
        #[serde(default, with = "super::codec::optional_entity")]
        project: Option<EntityId>,
    },
    /// A project's effective board; the chain then walks its parents' boards.
    Board {
        #[serde(with = "super::codec::entity")]
        project: EntityId,
    },
    /// The vault's live owners, where every chain ends.
    Owner,
}

impl AskRole {
    /// Where the role sits on a chain.
    #[must_use]
    pub fn rank(&self) -> RoleRank {
        match self {
            Self::Responsible { .. } => RoleRank::Responsible,
            Self::Board { .. } => RoleRank::Board,
            Self::Owner => RoleRank::Owner,
        }
    }
}

/// How far up a chain a role sits: an ask climbs from its role toward the owners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleRank {
    Responsible,
    Board,
    Owner,
}

/// What an answer to an ask authorises. An e-signature or a person-authorised payment
/// resolves only to a natural person, whoever else holds the role.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AskAct {
    #[default]
    Judgment,
    ESignature,
    Payment,
}

impl AskAct {
    /// Whether only a natural person may answer.
    #[must_use]
    pub fn person_only(self) -> bool {
        matches!(self, Self::ESignature | Self::Payment)
    }
}

/// Who a call's ask goes to: bound by the caller from trusted context, never from
/// model-authored state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AskTo {
    /// The role asked first.
    pub role: AskRole,
    /// The highest rank the ask may climb to.
    pub ceiling: RoleRank,
    pub act: AskAct,
}

impl AskTo {
    /// The vault's owners, for a judgment: where an ask goes when its caller names no role.
    #[must_use]
    pub fn owner() -> Self {
        Self {
            role: AskRole::Owner,
            ceiling: RoleRank::Owner,
            act: AskAct::Judgment,
        }
    }

    /// A role at or under its ceiling.
    pub fn validate(&self) -> Result<()> {
        if self.role.rank() > self.ceiling {
            return Err(invalid("an ask's role is above its ceiling"));
        }
        Ok(())
    }
}

/// Whether a role holder is a natural person or a bound agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HolderKind {
    Person,
    Agent,
}

/// A live actor holding a role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleHolder {
    #[serde(with = "super::codec::entity")]
    pub actor: EntityId,
    pub kind: HolderKind,
}

/// A role on an ask's chain and the live actors who held it, as resolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedRole {
    pub role: AskRole,
    /// Never empty.
    pub holders: Vec<RoleHolder>,
}

/// The host's role chain (Q3 by role): the next role an ask goes to.
pub trait AskRoleResolver: Send + Sync {
    /// The first role on `to`'s chain after `after` (from `to.role` when none), up to
    /// `to.ceiling`, with a live holder who may answer for `to.act`. None when no role up
    /// to the ceiling has one: the ask stays unresolved, never with wider authority.
    fn next_role(&self, to: &AskTo, after: Option<&AskRole>) -> Result<Option<ResolvedRole>>;
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
    /// Who the person rung's ask goes to; none is the vault's owners ([`AskTo::owner`]).
    /// The caller binds it from trusted context, never the model.
    pub ask_to: Option<&'a AskTo>,
    /// The host's versioned paired question ("does this need more thinking?"). A provider
    /// that reads it jointly (the house read) holds its own; a generated read asks it
    /// beside each of the call's questions in the same generation.
    pub paired: Option<&'a DecisionQuestion>,
    /// The host's versioned person question ("ask a person?"). When the dial reaches the
    /// person and the policy has a person row, every read asks it beside the call's
    /// questions as its own typed question.
    pub person: Option<&'a DecisionQuestion>,
    /// The host's versioned presence question ("is the target in the image?"). A Box or
    /// Point call through [`Self::run_located`] asks it first.
    pub presence: Option<&'a DecisionQuestion>,
    /// The work this call decides, as the caller names it (one conflict, one correction
    /// pack). The ask its person rung queues carries it, so two calls over the same
    /// question, principal and evidence that decide different work keep apart asks. The
    /// caller binds it from trusted context, never the model.
    pub correlation: Option<EntityId>,
}

impl DecisionLadder<'_> {
    /// One typed decision under one clock, `deadline` (an anytime budget, or a raw
    /// deadline): [`Self::run_pack`] with one question.
    #[expect(
        clippy::too_many_arguments,
        reason = "the call's state and clock join the question, its scope, the dial and the policy"
    )]
    pub fn run(
        &self,
        question: &DecisionQuestion,
        principal: EntityId,
        evidence: &[EntityId],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<TypedDecision> {
        let mut decisions = self.run_pack(
            &[question],
            principal,
            evidence,
            state,
            dial,
            policy,
            reversibility,
            deadline,
        )?;
        Ok(decisions.remove(0))
    }

    /// [`Self::run`] over images the question reads, as in "where is `mug` in
    /// `camera`?". Only providers that read images take it.
    #[expect(
        clippy::too_many_arguments,
        reason = "the call's images, state and clock join the question, its scope, the dial and the policy"
    )]
    pub fn run_images(
        &self,
        question: &DecisionQuestion,
        principal: EntityId,
        evidence: &[EntityId],
        images: &[DecisionImage],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<TypedDecision> {
        self.run_media(
            question,
            principal,
            evidence,
            images,
            &[],
            state,
            dial,
            policy,
            reversibility,
            deadline,
        )
    }

    /// [`Self::run`] over the images and audio clips the question reads. Only providers
    /// that read every medium the call carries take it.
    #[expect(
        clippy::too_many_arguments,
        reason = "the call's media, state and clock join the question, its scope, the dial and the policy"
    )]
    pub fn run_media(
        &self,
        question: &DecisionQuestion,
        principal: EntityId,
        evidence: &[EntityId],
        images: &[DecisionImage],
        audio: &[DecisionAudio],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<TypedDecision> {
        let mut decisions = self.run_pack_media(
            &[question],
            principal,
            evidence,
            images,
            audio,
            state,
            dial,
            policy,
            reversibility,
            deadline,
        )?;
        Ok(decisions.remove(0))
    }

    /// Several typed questions over one state, asked as one pack under one clock. The first
    /// permitted rung reads them in one request (several in turn past the policy's
    /// questions-per-call row), with the person question ("ask a person?")
    /// beside them as its own typed question when the dial reaches the person. Then each
    /// answer routes on its own to its own receipt: a stronger rung starts only while work
    /// time is left, and only for a cause: a rung that abstained, or once, for the first
    /// answer, a small margin under an enforced band or a paired reading at its row. A step
    /// skips a rung with no provider, or one that cannot take the question, up to the
    /// ceiling; with none left the call abstains. At a cut a
    /// reversible step takes the answer it holds and an irreversible one abstains and asks;
    /// with no answer, or an answer inside its band, the call abstains. The last quarter of
    /// the time stays the answer's.
    #[expect(
        clippy::too_many_arguments,
        reason = "the call's state and clock join the questions, their scope, dial and policy"
    )]
    pub fn run_pack(
        &self,
        questions: &[&DecisionQuestion],
        principal: EntityId,
        evidence: &[EntityId],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<Vec<TypedDecision>> {
        self.run_pack_images(
            questions,
            principal,
            evidence,
            &[],
            state,
            dial,
            policy,
            reversibility,
            deadline,
        )
    }

    /// [`Self::run_pack`] over images the questions read. Each image fills the state field
    /// of its name, and each receipt keeps every image's evidence ref and version, never
    /// its pixels. A Box question needs at least one image.
    #[expect(
        clippy::too_many_arguments,
        reason = "the call's images, state and clock join the questions, their scope, dial and policy"
    )]
    pub fn run_pack_images(
        &self,
        questions: &[&DecisionQuestion],
        principal: EntityId,
        evidence: &[EntityId],
        images: &[DecisionImage],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<Vec<TypedDecision>> {
        self.run_pack_media(
            questions,
            principal,
            evidence,
            images,
            &[],
            state,
            dial,
            policy,
            reversibility,
            deadline,
        )
    }

    /// [`Self::run_pack_images`] over audio clips as well. A clip fills the state field of
    /// its name like an image, and each receipt keeps every clip's evidence ref and
    /// version, never its samples.
    #[expect(
        clippy::too_many_arguments,
        reason = "the call's media, state and clock join the questions, their scope, dial and policy"
    )]
    pub fn run_pack_media(
        &self,
        questions: &[&DecisionQuestion],
        principal: EntityId,
        evidence: &[EntityId],
        images: &[DecisionImage],
        audio: &[DecisionAudio],
        state: &Value,
        dial: DecisionDial,
        policy: &DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &RetrievalDeadline,
    ) -> Result<Vec<TypedDecision>> {
        let pack = self.open(
            questions,
            principal,
            evidence,
            images,
            audio,
            state,
            dial,
            policy,
            reversibility,
            deadline,
        )?;
        let mut readings = pack.readings();
        let mut first = Vec::with_capacity(questions.len());
        if dial.first == DecisionRung::Human {
            first.extend(questions.iter().map(|_| None));
        } else {
            // Past the questions-per-call row the pack goes as several requests in turn.
            let per_call = policy.questions_per_call();
            for (chunk, readings) in questions
                .chunks(per_call)
                .zip(readings.chunks_mut(per_call))
            {
                let call = DecisionPack {
                    questions: chunk,
                    evidence,
                    images,
                    audio,
                    state,
                    deadline,
                };
                first.extend(
                    self.read(dial.first, &call, pack.person, readings)?
                        .into_iter()
                        .map(Some),
                );
            }
        }
        self.close(&pack, first, readings)
    }

    /// A pack's checked routing inputs, before its first read.
    #[expect(
        clippy::too_many_arguments,
        reason = "the inputs of run_pack_media, checked once for every first read"
    )]
    pub(super) fn open<'a>(
        &'a self,
        questions: &'a [&'a DecisionQuestion],
        principal: EntityId,
        evidence: &'a [EntityId],
        images: &'a [DecisionImage],
        audio: &'a [DecisionAudio],
        state: &'a Value,
        dial: DecisionDial,
        policy: &'a DecisionBandPolicy,
        reversibility: Reversibility,
        deadline: &'a RetrievalDeadline,
    ) -> Result<OpenPack<'a>> {
        if questions.is_empty() {
            return Err(invalid("invalid decision pack"));
        }
        for (index, question) in questions.iter().enumerate() {
            question.validate()?; // Provenance cannot reach any provider or queue.
            if questions[..index]
                .iter()
                .any(|earlier| earlier.id == question.id)
            {
                return Err(invalid("invalid decision pack"));
            }
        }
        validate_state(state)?;
        DecisionImage::check_call(
            images,
            state,
            questions.iter().any(|question| question.contract.locates()),
        )
        .map_err(|_| invalid("invalid decision images"))?;
        DecisionAudio::check_call(audio, images, state)
            .map_err(|_| invalid("invalid decision audio"))?;
        dial.band.validate()?;
        if dial.first > dial.ceiling {
            return Err(invalid("invalid decision dial"));
        }
        // Only a surface whose dial reaches the person rung routes on a person reading.
        let person_row = policy
            .person_threshold()
            .filter(|_| dial.ceiling == DecisionRung::Human);
        let person = self.person.filter(|_| person_row.is_some());
        if let Some(person) = person {
            person.validate()?;
            if person.contract != AnswerContract::Noul
                || questions.iter().any(|question| question.id == person.id)
            {
                return Err(invalid("invalid person question"));
            }
        }
        if let Some(paired) = self.paired {
            paired.validate()?;
            if paired.contract != AnswerContract::Noul
                || questions.iter().any(|question| question.id == paired.id)
                || person.is_some_and(|person| person.id == paired.id)
            {
                return Err(invalid("invalid paired question"));
            }
        }
        let rows = questions
            .iter()
            .map(|question| policy.resolve(question, reversibility, dial.band))
            .collect::<Result<Vec<_>>>()?;
        Ok(OpenPack {
            questions,
            principal,
            evidence,
            images,
            audio,
            state,
            dial,
            rows,
            person_row,
            paired: self.paired,
            person,
            policy,
            reversibility,
            deadline,
        })
    }

    /// Each question's routing after its first read, `first` (none when the dial starts at
    /// the person).
    pub(super) fn close(
        &self,
        pack: &OpenPack<'_>,
        first: Vec<Option<Read>>,
        readings: Vec<Readings>,
    ) -> Result<Vec<TypedDecision>> {
        pack.questions
            .iter()
            .zip(&pack.rows)
            .zip(first)
            .zip(readings)
            .map(|(((&question, &row), first), readings)| {
                let route = Route {
                    question,
                    principal: pack.principal,
                    evidence: pack.evidence,
                    images: pack.images,
                    audio: pack.audio,
                    state: pack.state,
                    dial: pack.dial,
                    row,
                    person_row: pack.person_row,
                    person: pack.person,
                    policy: pack.policy,
                    reversibility: pack.reversibility,
                    deadline: pack.deadline,
                };
                self.route(&route, first, readings)
            })
            .collect()
    }

    /// One question's routing after the first read, `first` (none when the dial starts at
    /// the person).
    fn route(
        &self,
        call: &Route<'_>,
        first: Option<Read>,
        mut readings: Readings,
    ) -> Result<TypedDecision> {
        let Route {
            question,
            principal,
            evidence,
            images,
            audio,
            state,
            dial,
            row,
            person_row,
            person,
            policy,
            reversibility,
            deadline,
        } = *call;
        let mut rung = dial.first;
        let mut prior = None;
        let mut answered = None;
        let mut in_band = false;
        let mut needs_person = false;
        let mut unavailable = false;
        let mut stop = StopCause::Done;
        let mut reasoning = Reasoning::NotNeeded;
        // Whether the first answer has been weighed for the one step up, and the cause of
        // the read in hand when it is that step.
        let mut weighed = false;
        let mut stepping = None;
        let mut next_read = first;
        while let Some(read) = next_read.take() {
            let answer = match read {
                Read::Answer(answer) => answer,
                Read::NotStarted => {
                    stop = StopCause::Deadline;
                    if let Some(cause) = stepping {
                        reasoning = Reasoning::Skipped(cause);
                    }
                    break;
                }
                Read::Cut => {
                    stop = StopCause::Deadline;
                    if let Some(cause) = stepping {
                        reasoning = Reasoning::Cut(cause);
                    }
                    break;
                }
            };
            if let Some(cause) = stepping.take() {
                reasoning = Reasoning::Ran(cause);
            }
            answered = Some(rung);
            needs_person = asks_person(&answer, person_row);
            // A rung that abstains answered nothing, so the question goes on to the next
            // rung that can take it (ARCH-0076 #fit-ask: rules first, then the local head,
            // ending at the next authorised role). The first answer may step up once more.
            let passes = answer.answer == DecisionAnswer::Abstain;
            let cause = if passes || weighed {
                None
            } else {
                weighed = true;
                in_band = answer.probability.is_some_and(|p| row.band.contains(p));
                step_cause(&answer, in_band, row.mode, policy.think_threshold())
            };
            prior = Some(answer);
            if needs_person {
                rung = DecisionRung::Human;
                break;
            }
            if (!passes && cause.is_none()) || rung >= dial.ceiling {
                break;
            }
            // A stronger rung, the person's included, starts only while work time is left.
            match self.next_available(rung, dial.ceiling, question, images, audio) {
                None => {
                    unavailable = true;
                    if let Some(cause) = cause {
                        reasoning = Reasoning::Skipped(cause);
                    }
                }
                Some(_) if !deadline.decision_may_start() => {
                    stop = StopCause::Deadline;
                    if let Some(cause) = cause {
                        reasoning = Reasoning::Skipped(cause);
                    }
                }
                Some(DecisionRung::Human) => rung = DecisionRung::Human,
                Some(next) => {
                    let questions = [question];
                    let pack = DecisionPack {
                        questions: &questions,
                        evidence,
                        images,
                        audio,
                        state,
                        deadline,
                    };
                    next_read = Some(
                        self.read(next, &pack, person, std::slice::from_mut(&mut readings))?
                            .remove(0),
                    );
                    rung = next;
                    stepping = cause;
                }
            }
        }
        // At a cut an irreversible step never takes an unfinished answer, and no step
        // takes an answer the call does not have, or one inside its band, enforced or
        // in shadow (packet rule 5: an in-band answer is not eligible).
        let abstains_at_cut = stop == StopCause::Deadline
            && (prior
                .as_ref()
                .is_none_or(|prior| prior.answer == DecisionAnswer::Abstain)
                || reversibility == Reversibility::OutboundEffect
                || in_band);
        if abstains_at_cut && dial.ceiling == DecisionRung::Human {
            rung = DecisionRung::Human;
        }
        let mut human_ask = None;
        let outcome = if rung == DecisionRung::Human {
            validate_pin(&self.human_pin, DecisionRung::Human)?;
            let reason = if needs_person {
                HumanAskReason::NeedsPerson
            } else if abstains_at_cut {
                HumanAskReason::Deadline
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
                to: self.ask_to.cloned().unwrap_or_else(AskTo::owner),
                correlation: self.correlation,
            })?;
            readings.pins.push(self.human_pin.clone());
            human_ask = Some(reason);
            abstained()
        } else if abstains_at_cut {
            human_ask = Some(HumanAskReason::Deadline);
            abstained()
        } else if unavailable {
            // No rung up to the ceiling can take the step: a typed abstention.
            human_ask = Some(HumanAskReason::ProviderUnavailable);
            abstained()
        } else {
            prior.expect("a non-human rung has an answer")
        };
        // A rung that abstained answered nothing.
        let answered = answered.filter(|_| outcome.answer != DecisionAnswer::Abstain);
        let evidence_versions = images
            .iter()
            .map(|image| image.evidence.clone())
            .chain(audio.iter().map(|clip| clip.evidence.clone()))
            .collect();
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
                evidence_versions,
                cost_per_thousand: None,
                paired: readings.paired,
                person: readings.person,
                time: Some(DecisionTime {
                    budget_ms: millis(deadline.budget()),
                    used_ms: millis(deadline.used()),
                    stop,
                    answered,
                    reasoning,
                }),
                images: readings.images,
            },
        })
    }

    /// The first rung from `first` up to `ceiling` whose provider reads images when
    /// `images` and audio when `audio`, for a host that starts a media call there. `None`
    /// when no rung in that span reads every medium the call carries: the host abstains
    /// rather than drop one.
    #[must_use]
    pub fn first_media_reader(
        &self,
        first: DecisionRung,
        ceiling: DecisionRung,
        images: bool,
        audio: bool,
    ) -> Option<DecisionRung> {
        let mut rung = first;
        loop {
            if self.slot(rung).is_some_and(|provider| {
                (!images || provider.reads_images()) && (!audio || provider.reads_audio())
            }) {
                return Some(rung);
            }
            if rung >= ceiling || rung == DecisionRung::Human {
                return None;
            }
            rung = next_rung(rung);
        }
    }

    /// The ladder with every slot whose provider leaves the host emptied, when `posture`
    /// keeps unit text local. Text leaves only under MANAGED posture or an explicit
    /// `remote_opt_in`, and never under RELAY ([`super::SeatRequest::validate_remote`]'s
    /// rule; ARCH-0076 #posture). A step up skips an emptied slot as it skips any absent
    /// one.
    #[must_use]
    pub fn under_posture(
        mut self,
        posture: crate::HostingPrivacyPosture,
        remote_opt_in: bool,
    ) -> Self {
        use crate::HostingPrivacyPosture::{Hosted, Relay};
        if (posture == Hosted || remote_opt_in) && posture != Relay {
            return self;
        }
        for slot in [
            &mut self.rule,
            &mut self.local,
            &mut self.system_one,
            &mut self.escalation,
            &mut self.big,
        ] {
            if slot.is_some_and(|provider| provider.leaves_host()) {
                *slot = None;
            }
        }
        self
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

    /// The first rung from `dial.first` to its ceiling, short of the person, whose provider
    /// takes `question` over `images`. The ladder fails a call whose first rung cannot take
    /// it, so a caller with images starts there, or asks without them and says so.
    pub fn first_taking(
        &self,
        question: &DecisionQuestion,
        dial: DecisionDial,
        images: &[DecisionImage],
    ) -> Option<DecisionRung> {
        self.first_taking_media(question, dial, images, &[])
    }

    /// [`DecisionLadder::first_taking`] over `images` and `audio` both.
    pub fn first_taking_media(
        &self,
        question: &DecisionQuestion,
        dial: DecisionDial,
        images: &[DecisionImage],
        audio: &[DecisionAudio],
    ) -> Option<DecisionRung> {
        let mut rung = dial.first;
        while rung <= dial.ceiling && rung != DecisionRung::Human {
            if self
                .slot(rung)
                .is_some_and(|provider| takes(provider, question, images, audio))
            {
                return Some(rung);
            }
            rung = next_rung(rung);
        }
        None
    }

    /// The next rung above `rung` that can answer `question`, up to `ceiling`. The person's
    /// queue is always present (ARCH-0076 #posture: no house model sends the step to the
    /// big model or the person).
    fn next_available(
        &self,
        mut rung: DecisionRung,
        ceiling: DecisionRung,
        question: &DecisionQuestion,
        images: &[DecisionImage],
        audio: &[DecisionAudio],
    ) -> Option<DecisionRung> {
        while rung < ceiling {
            rung = next_rung(rung);
            if rung == DecisionRung::Human
                || self
                    .slot(rung)
                    .is_some_and(|provider| takes(provider, question, images, audio))
            {
                return Some(rung);
            }
        }
        None
    }

    /// One provider request on the call's clock, one read per pack question. Routing skips
    /// an empty slot, so only the dial's own first rung reaches here empty or unable to take
    /// a question, and it fails even with no time left. A failure with time left still
    /// fails the call.
    fn read(
        &self,
        rung: DecisionRung,
        pack: &DecisionPack<'_>,
        person: Option<&DecisionQuestion>,
        readings: &mut [Readings],
    ) -> Result<Vec<Read>> {
        let provider = self
            .slot(rung)
            .ok_or_else(|| invalid("decision provider unavailable"))?;
        let pin = provider.pin();
        validate_pin(&pin, rung)?;
        if !pack
            .questions
            .iter()
            .all(|question| takes(provider, question, pack.images, pack.audio))
        {
            return Err(invalid("decision provider cannot take the question"));
        }
        if !pack.deadline.decision_may_start() {
            return Ok((0..pack.questions.len())
                .map(|_| Read::NotStarted)
                .collect());
        }
        let reads = take(&pin, pack, ask(provider, pack, person), readings)?;
        // Each measurement that answered pins what it was sent of every image.
        if !pack.images.is_empty() {
            let edge = provider.image_edge();
            for (read, readings) in reads.iter().zip(readings.iter_mut()) {
                if !matches!(read, Read::Answer(_)) {
                    continue;
                }
                for image in pack.images {
                    if readings
                        .images
                        .iter()
                        .any(|row| row.provider == pin && row.name == image.name)
                    {
                        continue;
                    }
                    let row = image
                        .pin(pin.clone(), edge)
                        .map_err(|_| invalid("invalid decision images"))?;
                    readings.images.push(row);
                }
            }
        }
        Ok(reads)
    }
}

/// What one provider request, `answered`, gave each pack question on the call's clock. A
/// failure once the work time is spent, or a reply after the answer's time, is the cut; a
/// failure with time left fails the call.
pub(super) fn take(
    pin: &ProviderPin,
    pack: &DecisionPack<'_>,
    answered: Result<Vec<ProviderDecision>>,
    readings: &mut [Readings],
) -> Result<Vec<Read>> {
    let count = pack.questions.len();
    let answers = match answered {
        Ok(answers) => answers,
        Err(_) if !pack.deadline.decision_may_start() => {
            return Ok((0..count).map(|_| Read::Cut).collect());
        }
        Err(error) => return Err(error),
    };
    if pack.deadline.answer_due() {
        return Ok((0..count).map(|_| Read::Cut).collect());
    }
    let mut reads = Vec::with_capacity(answers.len());
    for ((question, answer), readings) in pack.questions.iter().zip(answers).zip(readings) {
        answer.validate(question)?;
        if let Some(reading) = answer.paired {
            readings.paired.push(reading.bind(pin.clone()));
        }
        if let Some(reading) = answer.person {
            readings.person.push(reading.bind(pin.clone()));
        }
        readings.pins.push(pin.clone());
        reads.push(Read::Answer(answer));
    }
    Ok(reads)
}

/// The person question's read shape, the one seam for it (test 6b: a separate read, not
/// joint). It is its own typed question in the same pack as the call's questions, and its
/// P(yes) joins every answer as the person reading; an abstained person read is no
/// reading, never P(yes) = 0. One question with no person question is one plain call.
fn ask(
    provider: &dyn DecisionProvider,
    pack: &DecisionPack<'_>,
    person: Option<&DecisionQuestion>,
) -> Result<Vec<ProviderDecision>> {
    let answers = match (person, pack.call(0)) {
        (None, Some(call)) if pack.questions.len() == 1 => vec![provider.decide(&call)?],
        (None, _) => provider.decide_pack(pack)?,
        (Some(_), _) => {
            let questions = asked(pack, person);
            provider.decide_pack(&DecisionPack {
                questions: &questions,
                ..*pack
            })?
        }
    };
    joined(answers, pack.questions.len(), person)
}

/// The questions one read asks: the pack's, then the person question when there is one.
pub(super) fn asked<'q>(
    pack: &DecisionPack<'q>,
    person: Option<&'q DecisionQuestion>,
) -> Vec<&'q DecisionQuestion> {
    pack.questions.iter().copied().chain(person).collect()
}

/// `answers` to [`asked`]'s questions as the pack's `count` answers, the person question's
/// P(yes) joined to each as its person reading.
pub(super) fn joined(
    mut answers: Vec<ProviderDecision>,
    count: usize,
    person: Option<&DecisionQuestion>,
) -> Result<Vec<ProviderDecision>> {
    if let Some(person) = person {
        if answers.len() != count + 1 {
            return Err(invalid("a pack answers every question"));
        }
        let asked = answers.pop().expect("the person question's answer");
        asked.validate(person)?;
        let reading = match (&asked.answer, asked.probability) {
            (DecisionAnswer::Noul(_), Some(probability)) => Some(PairedAnswer {
                question: person.id,
                question_version: person.version,
                probability,
            }),
            _ => None,
        };
        for answer in &mut answers {
            answer.person = reading;
        }
    }
    if answers.len() != count {
        return Err(invalid("a pack answers every question"));
    }
    Ok(answers)
}

/// One pack's checked routing inputs, shared by its questions.
pub(super) struct OpenPack<'a> {
    questions: &'a [&'a DecisionQuestion],
    principal: EntityId,
    evidence: &'a [EntityId],
    images: &'a [DecisionImage],
    audio: &'a [DecisionAudio],
    state: &'a Value,
    dial: DecisionDial,
    rows: Vec<LearnedBand>,
    person_row: Option<PersonThreshold>,
    /// The paired question, asked beside each of the pack's by a generated read.
    pub(super) paired: Option<&'a DecisionQuestion>,
    /// The person question, asked beside the pack's when the dial reaches the person.
    pub(super) person: Option<&'a DecisionQuestion>,
    policy: &'a DecisionBandPolicy,
    reversibility: Reversibility,
    deadline: &'a RetrievalDeadline,
}

impl OpenPack<'_> {
    /// One empty reading record per question.
    pub(super) fn readings(&self) -> Vec<Readings> {
        self.questions.iter().map(|_| Readings::default()).collect()
    }
}

/// One question's routing inputs, shared by its reads.
#[derive(Clone, Copy)]
struct Route<'a> {
    question: &'a DecisionQuestion,
    principal: EntityId,
    evidence: &'a [EntityId],
    images: &'a [DecisionImage],
    audio: &'a [DecisionAudio],
    state: &'a Value,
    dial: DecisionDial,
    row: LearnedBand,
    person_row: Option<PersonThreshold>,
    person: Option<&'a DecisionQuestion>,
    policy: &'a DecisionBandPolicy,
    reversibility: Reversibility,
    deadline: &'a RetrievalDeadline,
}

fn validate_state(state: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(state).map_err(|_| invalid("invalid decision state"))?;
    if !state.is_object() || bytes.len() > MAX_DECISION_STATE_BYTES {
        return Err(invalid("invalid decision state"));
    }
    Ok(())
}

/// What one provider read gave the call.
pub(super) enum Read {
    Answer(ProviderDecision),
    /// No work time was left to start it.
    NotStarted,
    /// Its client gave up once the work time was spent, or its reply came after the
    /// answer's time: an unfinished reply is not an answer.
    Cut,
}

fn abstained() -> ProviderDecision {
    ProviderDecision {
        answer: DecisionAnswer::Abstain,
        probability: None,
        paired: None,
        person: None,
    }
}

/// Why a read needs more thinking: a small margin under an enforced band, or a paired
/// reading at its row. A missing paired reading is no reading, never P(yes) = 0.
fn step_cause(
    answer: &ProviderDecision,
    in_band: bool,
    mode: BandMode,
    think: Option<ThinkThreshold>,
) -> Option<ReasoningCause> {
    if in_band && mode == BandMode::Enforce {
        return Some(ReasoningCause::SmallMargin);
    }
    think
        .zip(answer.paired)
        .is_some_and(|(row, paired)| paired.probability >= row.threshold)
        .then_some(ReasoningCause::PairedHigh)
}

pub(super) fn millis(time: std::time::Duration) -> u64 {
    u64::try_from(time.as_millis()).unwrap_or(u64::MAX)
}

/// What a run's measurements leave on the receipt.
#[derive(Default)]
pub(super) struct Readings {
    pins: Vec<ProviderPin>,
    paired: Vec<PairedReading>,
    person: Vec<PairedReading>,
    images: Vec<ImagePin>,
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
