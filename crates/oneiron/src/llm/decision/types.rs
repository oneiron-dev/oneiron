//! Closed answer contracts and engine-owned decision receipts.

use super::{AskAct, AskRole, AskTo, DecisionAsk, HolderKind, RoleRank};
use crate::EntityId;
use crate::error::Error;
use crate::memory::PixelRegion;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DecisionRung {
    Rule,
    Local,
    SystemOne,
    /// The house model in decision-read mode, between the precision rung and the big model.
    Escalation,
    Big,
    Human,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DecisionClass {
    Retrieval,
    Contradiction,
    Triage,
    Judgment,
    UsefulUpstream,
    Preference,
    Provenance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AnswerContract {
    /// Yes or no, with P(yes).
    Noul,
    /// One of `options`.
    Choice { options: Vec<String> },
    /// One number from `min` to `max` (both included, `min` below `max`), in the units and
    /// direction the question names.
    Score { min: f64, max: f64 },
    /// Where the target the question names sits in an image the call carries: one box,
    /// or none when the target is absent.
    Box,
    /// Where the target sits as one point, or none when it is absent.
    Point,
}

impl AnswerContract {
    pub fn validate(&self) -> crate::error::Result<()> {
        match self {
            Self::Choice { options }
                if options.is_empty()
                    || options.iter().any(|s| s.is_empty() || s.len() > 256)
                    || options
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        != options.len() =>
            {
                Err(invalid("invalid choice options"))
            }
            Self::Score { min, max } if !min.is_finite() || !max.is_finite() || min >= max => {
                Err(invalid("invalid score range"))
            }
            _ => Ok(()),
        }
    }

    pub fn accepts(&self, answer: &DecisionAnswer) -> bool {
        match (self, answer) {
            (_, DecisionAnswer::Abstain) | (Self::Noul, DecisionAnswer::Noul(_)) => true,
            (Self::Choice { options }, DecisionAnswer::Choice(value)) => options.contains(value),
            (Self::Score { min, max }, DecisionAnswer::Score(value)) => {
                value.is_finite() && value >= min && value <= max
            }
            (Self::Box, DecisionAnswer::Box(found)) => found.is_none_or(ImageBox::is_valid),
            (Self::Point, DecisionAnswer::Point(found)) => found.is_none_or(ImagePoint::is_valid),
            _ => false,
        }
    }

    /// Whether it finds its target in an image (a Box or a Point): the call carries at
    /// least one, and a presence question may go first.
    pub fn locates(&self) -> bool {
        matches!(self, Self::Box | Self::Point)
    }

    /// Its found absence: none for a Box or a Point; no other contract has one.
    pub fn absent(&self) -> Option<DecisionAnswer> {
        match self {
            Self::Box => Some(DecisionAnswer::Box(None)),
            Self::Point => Some(DecisionAnswer::Point(None)),
            Self::Noul | Self::Choice { .. } | Self::Score { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum DecisionAnswer {
    Noul(bool),
    Choice(String),
    Score(f64),
    /// The target's box, or none when the target is absent: a found absence, not an
    /// abstain.
    Box(Option<ImageBox>),
    /// The target's point, or none when it is absent, as for a box.
    Point(Option<ImagePoint>),
    Abstain,
}

/// A box in an image, as fractions from its top-left corner: `left` and `right` of its
/// width, `top` and `bottom` of its height. Fractions hold at any size the image is
/// drawn, so a box read on a downscaled copy places the target on the original.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImageBox {
    pub top: f64,
    pub bottom: f64,
    pub left: f64,
    pub right: f64,
}

impl ImageBox {
    /// Every edge inside the image, and the edges strictly in order: a box has area.
    pub fn is_valid(self) -> bool {
        [self.top, self.bottom, self.left, self.right]
            .iter()
            .all(|edge| edge.is_finite() && (0.0..=1.0).contains(edge))
            && self.top < self.bottom
            && self.left < self.right
    }

    /// The box's centre as `(x, y)` fractions: the point answer, for a caller that
    /// wants one.
    pub fn centre(self) -> (f64, f64) {
        (
            (self.left + self.right) / 2.0,
            (self.top + self.bottom) / 2.0,
        )
    }

    /// The box's centre as a Point answer.
    pub fn point(self) -> ImagePoint {
        let (x, y) = self.centre();
        ImagePoint { x, y }
    }
}

/// A point in an image, as fractions from its top-left corner: `x` of its width, `y` of
/// its height. Like a box, it holds at any size the image is drawn.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImagePoint {
    pub x: f64,
    pub y: f64,
}

impl ImagePoint {
    /// Both coordinates inside the image.
    pub fn is_valid(self) -> bool {
        [self.x, self.y]
            .iter()
            .all(|coordinate| coordinate.is_finite() && (0.0..=1.0).contains(coordinate))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionQuestion {
    #[serde(with = "super::codec::entity")]
    #[schemars(with = "String")]
    pub id: EntityId,
    pub version: u32,
    pub text: String,
    pub class: DecisionClass,
    pub contract: AnswerContract,
    /// Confident negative accept-type judgments require a second measurement.
    pub accept_type: bool,
}

impl DecisionQuestion {
    pub fn validate(&self) -> crate::error::Result<()> {
        if self.version == 0 || self.text.trim().is_empty() || self.text.len() > 16_384 {
            return Err(invalid("invalid typed question"));
        }
        if self.class == DecisionClass::Provenance {
            return Err(invalid("provenance is not model-decided"));
        }
        self.contract.validate()
    }
}

/// A typed question as its author writes it (FIX 1586): everything but the
/// id and version, which the engine owns and mints when it stores the
/// question. It names neither, and its serde refuses either.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionQuestionInput {
    pub text: String,
    pub class: DecisionClass,
    pub contract: AnswerContract,
    /// Confident negative accept-type judgments require a second measurement.
    pub accept_type: bool,
}

impl DecisionQuestionInput {
    /// The stored question: this one under the `id` and `version` the engine
    /// minted for it.
    #[must_use]
    pub fn with_identity(self, id: EntityId, version: u32) -> DecisionQuestion {
        DecisionQuestion {
            id,
            version,
            text: self.text,
            class: self.class,
            contract: self.contract,
            accept_type: self.accept_type,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderPin {
    pub rung: DecisionRung,
    pub model: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionBand {
    pub low: f64,
    pub high: f64,
}

impl Default for DecisionBand {
    fn default() -> Self {
        Self {
            low: 0.35,
            high: 0.65,
        }
    }
}

impl DecisionBand {
    pub fn validate(self) -> crate::error::Result<()> {
        if !self.low.is_finite()
            || !self.high.is_finite()
            || self.low < 0.0
            || self.high > 1.0
            || self.low >= self.high
        {
            return Err(invalid("invalid decision band"));
        }
        Ok(())
    }
    pub fn contains(self, probability: f64) -> bool {
        (self.low..=self.high).contains(&probability)
    }
}

/// Owner ceiling; a resident can select a cheaper rung but never widen it.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionDial {
    pub first: DecisionRung,
    pub ceiling: DecisionRung,
    pub band: DecisionBand,
}

impl DecisionDial {
    /// `resident` inside this dial: its rungs between this one's, and its
    /// band a valid band inside this one's (FIX 1587), so
    /// `host.low <= resident.low < resident.high <= host.high`. An equal band
    /// stays inside.
    pub fn narrow(self, resident: Self) -> crate::error::Result<Self> {
        self.band.validate()?;
        resident.band.validate()?;
        if self.first > self.ceiling
            || resident.first < self.first
            || resident.ceiling > self.ceiling
            || resident.first > resident.ceiling
            || resident.band.low < self.band.low
            || resident.band.high > self.band.high
        {
            return Err(invalid("resident decision dial widens owner authority"));
        }
        Ok(resident)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionReceipt {
    #[serde(with = "super::codec::entity")]
    #[schemars(with = "String")]
    pub question: EntityId,
    pub question_version: u32,
    #[serde(with = "super::codec::entity")]
    #[schemars(with = "String")]
    pub principal: EntityId,
    pub providers: Vec<ProviderPin>,
    pub band: DecisionBand,
    /// Zero denotes the seed band in shadow; learned bands pin their version.
    #[serde(default)]
    pub band_version: u32,
    /// Exact source-body hashes used for this unit's inference.
    #[serde(default)]
    pub evidence_versions: Vec<EvidenceVersion>,
    /// Provider-reported cost at the answered rung, when known.
    #[serde(default)]
    pub cost_per_thousand: Option<f64>,
    /// One row per measurement that read the paired question. A measurement without one
    /// has no row; a missing reading never stands for P(yes) = 0.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paired: Vec<PairedReading>,
    /// One row per measurement that read the person question ("ask a person?"), kept
    /// whether or not it routed the decision. A missing reading has no row, as above.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub person: Vec<PairedReading>,
    /// The call's clock: its budget, the time used, why it stopped and the rung that
    /// answered. Absent on a receipt made off the decision clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<DecisionTime>,
    /// One row per measurement and image it read: what that provider was sent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub images: Vec<ImagePin>,
    /// The think-more row's version in force when the ladder routed this decision: set
    /// when the call asked the paired question under a ThinkThreshold row, else none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub think_row: Option<u32>,
    /// The ask-a-person row's version in force when the ladder routed this decision: set
    /// when the dial reached the person under a PersonThreshold row, else none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person_row: Option<u32>,
    /// The rule row whose answer stands, as id@revision: set when the Rule rung answered
    /// from a host rule row (ARCH-0040, "a rule row as id@version"), else none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<super::HostRuleRef>,
    /// The ask the decision went up as, or was answered by (ARCH-0076, "the role asked and
    /// the principal who answered, agent or person"): set when the person rung queued it,
    /// or when its caller read the ask back; none when no ask was put.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asked: Option<ReceiptAsk>,
    /// How the caller cut the call's state to fit the ladder's bound, and how much (FIX
    /// 1326): none when the state went whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_cut: Option<StateCut>,
}

/// How a caller cut a call's state to fit [`super::MAX_DECISION_STATE_BYTES`] (FIX 1326),
/// under the one cut order [`super::fit_reserve_state`] applies: the reserve sample first, at
/// whole items, then the long text, on a character boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StateCut {
    /// The reserve items the state kept: the first ones, in order.
    pub kept: u64,
    /// The reserve items the caller had.
    pub of: u64,
    /// The bytes the long text was cut to; none when it went whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_cut_at_bytes: Option<u64>,
}

impl DecisionReceipt {
    /// This receipt naming `ask`, the ask its decision went up as or was answered by: the
    /// role it is at, its route and, once one landed, who answered as which role.
    pub fn bind_ask(&mut self, ask: &DecisionAsk) {
        self.asked = Some(ReceiptAsk::of(ask));
    }
}

/// The ask a decision went up as, as its receipt keeps it: the role it was put to, the
/// route's ceiling and act, and the role and kind of who answered once one did. Kept
/// actor-free, as a kept ask is (FIX 4591): who answered, and the actor a responsible role
/// names, stay on the ask row, which an erase scrubs. A request never reads as a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceiptAsk {
    /// The ask's arrival number, when the queue numbered it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// The rank of the role it was put to: the role the vault resolved for it once read
    /// back, else the role its caller bound first.
    pub role: RoleRank,
    /// The project whose boards that role's chain walks, when it names one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "super::codec::optional_entity"
    )]
    #[schemars(with = "Option<String>")]
    pub project: Option<EntityId>,
    /// The highest rank the ask may climb to.
    pub ceiling: RoleRank,
    pub act: AskAct,
    /// Who answered, as which role; none while the ask waits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answered: Option<ReceiptAnswerer>,
}

/// Who answered an ask, as its receipt keeps it: the role it answered as and whether a
/// person or a bound agent, never the actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReceiptAnswerer {
    pub role: RoleRank,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "super::codec::optional_entity"
    )]
    #[schemars(with = "Option<String>")]
    pub project: Option<EntityId>,
    pub kind: HolderKind,
}

impl ReceiptAsk {
    /// The route `to` as the ladder queued it, numbered `seq` when the queue numbered it,
    /// before the vault resolved a role.
    pub(crate) fn queued(to: &AskTo, seq: Option<u64>) -> Self {
        let (role, project) = role_parts(&to.role);
        Self {
            seq,
            role,
            project,
            ceiling: to.ceiling,
            act: to.act,
            answered: None,
        }
    }

    /// `ask` as a receipt keeps it: the role it is at (its bound role while none
    /// resolved), its route, and its answer once one landed.
    #[must_use]
    pub fn of(ask: &DecisionAsk) -> Self {
        let at = ask.role.as_ref().map_or(&ask.to.role, |at| &at.role);
        let (role, project) = role_parts(at);
        Self {
            seq: Some(ask.seq),
            role,
            project,
            ceiling: ask.to.ceiling,
            act: ask.to.act,
            answered: ask.answer.as_ref().map(|answer| {
                let (role, project) = role_parts(&answer.role);
                ReceiptAnswerer {
                    role,
                    project,
                    kind: answer.kind,
                }
            }),
        }
    }
}

/// A role's rank and the project whose boards it walks, never the actor it names.
fn role_parts(role: &AskRole) -> (RoleRank, Option<EntityId>) {
    let project = match role {
        AskRole::Responsible { project, .. } => *project,
        AskRole::Board { project } => Some(*project),
        AskRole::Owner => None,
    };
    (role.rank(), project)
}

/// What one measurement read of one image: the pixels as handed in, where they sit in
/// the image they are of, and the size the provider was sent after it fit them to its
/// long edge. A box or point it answers is in fractions of what it was sent, which are
/// the same fractions of the pixels handed in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ImagePin {
    pub provider: ProviderPin,
    /// The state field the image filled.
    pub name: String,
    pub evidence: EvidenceVersion,
    /// The pixels as handed in.
    pub width: u32,
    pub height: u32,
    /// Where those pixels sit in the image `evidence` is; none is the whole image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame: Option<PixelRegion>,
    /// The provider's long edge; none when it states none and was sent the pixels as
    /// handed in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edge: Option<u32>,
    pub sent_width: u32,
    pub sent_height: u32,
}

/// What the decision deadline left on a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionTime {
    pub budget_ms: u64,
    pub used_ms: u64,
    pub stop: StopCause,
    /// The rung whose answer stands; none when the call abstained or asked a person.
    pub answered: Option<DecisionRung>,
    pub reasoning: Reasoning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StopCause {
    Done,
    /// The deadline cut work the call still wanted, or the caller took the answer early.
    Deadline,
    ProviderFailure,
}

/// Whether more thinking (a stronger rung, or a required second measurement) ran,
/// and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", content = "cause", rename_all = "snake_case")]
pub enum Reasoning {
    /// A clear answer stopped there.
    NotNeeded,
    Ran(ReasoningCause),
    /// It did not start: no time was left, no rung up to the ceiling could take it, or
    /// its admission was refused.
    Skipped(ReasoningCause),
    /// It started, and the deadline came before its answer.
    Cut(ReasoningCause),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningCause {
    /// The paired "does this need more thinking?" reading reached its row.
    PairedHigh,
    /// The answer fell inside an enforced band.
    SmallMargin,
    /// A confident negative on an accept-type question needs a second measurement.
    SecondMeasurement,
}

/// A yes/no reading taken with the answer ("does this need more thinking?" or "ask a
/// person?"), bound by the engine to the provider that measured it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PairedReading {
    pub provider: ProviderPin,
    #[serde(with = "super::codec::entity")]
    #[schemars(with = "String")]
    pub question: EntityId,
    pub question_version: u32,
    /// P(yes).
    pub probability: f64,
}

impl PairedReading {
    /// Rows a host hands in: at most one per measuring provider, each bound to one of
    /// the answer's own providers.
    pub(crate) fn rows_valid(rows: &[Self], answered: EntityId, providers: &[ProviderPin]) -> bool {
        rows.iter().enumerate().all(|(index, row)| {
            providers.contains(&row.provider)
                && rows[..index]
                    .iter()
                    .all(|earlier| earlier.provider != row.provider)
                && paired_valid(
                    answered,
                    row.question,
                    row.question_version,
                    row.probability,
                )
        })
    }

    /// A receipt's paired and person rows: each list valid, and no provider's person row
    /// reading the question its paired row read.
    pub(crate) fn readings_valid(
        paired: &[Self],
        person: &[Self],
        answered: EntityId,
        providers: &[ProviderPin],
    ) -> bool {
        Self::rows_valid(paired, answered, providers)
            && Self::rows_valid(person, answered, providers)
            && person.iter().all(|asked| {
                paired
                    .iter()
                    .all(|row| row.provider != asked.provider || row.question != asked.question)
            })
    }
}

/// A paired reading reads another question than the one answered, at a real version,
/// as a probability.
pub(crate) fn paired_valid(
    answered: EntityId,
    question: EntityId,
    question_version: u32,
    probability: f64,
) -> bool {
    question != answered
        && question_version != 0
        && probability.is_finite()
        && (0.0..=1.0).contains(&probability)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceVersion {
    #[serde(with = "super::codec::entity")]
    #[schemars(with = "String")]
    pub id: EntityId,
    /// Hex on a JSON wire, its bytes in storage (FIX 12262).
    #[serde(with = "oneiron_docedit::hex_digest")]
    #[schemars(with = "String")]
    pub body_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypedDecision {
    pub answer: DecisionAnswer,
    pub probability: Option<f64>,
    #[serde(with = "super::codec::entities")]
    #[schemars(with = "Vec<String>")]
    pub evidence: Vec<EntityId>,
    pub in_band: bool,
    pub receipt: DecisionReceipt,
    /// Structured explanation code. Hosts render their own localized text.
    pub human_ask: Option<HumanAskReason>,
}

/// A person answered differently from the model's prior: the Coach's tuning input for
/// the person threshold row and the bands.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonChangedAnswer {
    #[serde(with = "super::codec::entity")]
    pub question: EntityId,
    pub question_version: u32,
    #[serde(with = "super::codec::entity")]
    pub principal: EntityId,
    pub reason: HumanAskReason,
    pub prior: DecisionAnswer,
    pub prior_probability: Option<f64>,
    /// The model and revision that read the prior.
    pub prior_provider: ProviderPin,
    /// The prior read's "needs more thinking?" and "ask a person?" readings, when it took
    /// them, each with its question and version.
    pub prior_paired: Option<PairedReading>,
    pub prior_person: Option<PairedReading>,
    pub person: DecisionAnswer,
    pub queue_pin: ProviderPin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HumanAskReason {
    Disagreement,
    Uncertain,
    ProviderUnavailable,
    OwnerSelected,
    /// The read's P(ask a person) reached the owner's threshold row.
    NeedsPerson,
    /// The deadline cut the call, and its step cannot take an unfinished answer.
    Deadline,
    /// A run would pass its project goal's exploration slice.
    ExplorationBudget,
}

pub(super) fn invalid(message: &str) -> Error {
    Error::InvalidConfig(message.into())
}
