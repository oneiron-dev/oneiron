//! Moved from `crates/oneiron/src/llm/decision/types.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use crate::memory::asset_resolve::types::PixelRegion;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::model_decision::AskAct;
use oneiron_store::model_decision::DecisionAnswer;
use oneiron_store::model_decision::DecisionBand;
use oneiron_store::model_decision::DecisionTime;
use oneiron_store::model_decision::EvidenceVersion;
use oneiron_store::model_decision::HolderKind;
use oneiron_store::model_decision::HumanAskReason;
use oneiron_store::model_decision::PairedReading;
use oneiron_store::model_decision::ProviderPin;
use oneiron_store::model_decision::RoleRank;
use oneiron_store::model_decision::StateCut;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DecisionReceipt {
    #[serde(with = "oneiron_store::model_decision::codec::entity")]
    #[schemars(with = "String")]
    pub question: EntityId,
    pub question_version: u32,
    #[serde(with = "oneiron_store::model_decision::codec::entity")]
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
    pub rule: Option<oneiron_store::model_decision::HostRuleRef>,
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
        with = "oneiron_store::model_decision::codec::optional_entity"
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
        with = "oneiron_store::model_decision::codec::optional_entity"
    )]
    #[schemars(with = "Option<String>")]
    pub project: Option<EntityId>,
    pub kind: HolderKind,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TypedDecision {
    pub answer: DecisionAnswer,
    pub probability: Option<f64>,
    #[serde(with = "oneiron_store::model_decision::codec::entities")]
    #[schemars(with = "Vec<String>")]
    pub evidence: Vec<EntityId>,
    pub in_band: bool,
    pub receipt: DecisionReceipt,
    /// Structured explanation code. Hosts render their own localized text.
    pub human_ask: Option<HumanAskReason>,
}
