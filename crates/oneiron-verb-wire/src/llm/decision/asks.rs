//! Moved from `crates/oneiron/src/llm/decision/asks.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::llm::decision::asks::grant_draft::AskGrantDraft;
use oneiron_store::model_decision::AnswerActor;
use oneiron_store::model_decision::DecisionAnswer;
use oneiron_store::model_decision::HolderKind;
use oneiron_store::model_decision::HostRuleRef;
use oneiron_store::model_decision::PairedReading;
use oneiron_store::model_decision::ProviderPin;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::ops::Bound;
use std::sync::Arc;

/// The answer the ladder held when it asked, and the provider that read it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AskPrior {
    pub answer: DecisionAnswer,
    pub probability: Option<f64>,
    pub provider: ProviderPin,
    pub paired: Option<PairedReading>,
    pub person: Option<PairedReading>,
}

/// What a role's holder answered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AskAnswer {
    pub answer: DecisionAnswer,
    /// Vault clock seconds when the answer landed.
    pub answered_at: u64,
    /// The actor that answered, authenticated by its door; erased once that
    /// actor was erased (FIX 3520).
    #[serde(with = "super::codec::answer_actor")]
    #[schemars(with = "String")]
    pub by: AnswerActor,
    /// The role it answered as, and whether it is a person or a bound agent.
    pub role: AskRole,
    pub kind: HolderKind,
    /// Whether the answer changed the ladder's prior (kept for the Coach).
    pub changed: bool,
    /// The reason the owner typed with the answer, trimmed; none when none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The rule row that reason landed as, for the host's notice and its undo; none when
    /// it wrote none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<HostRuleRef>,
    /// The standing grant that reason drafted from the ask's consent effect (FIX 2975),
    /// Proposed until the owner confirms it; none when it drafted none.
    pub grant: Option<AskGrantDraft>,
}
pub mod grant_draft;
