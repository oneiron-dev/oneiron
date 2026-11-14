//! Moved from `crates/oneiron/src/llm/decision/asks.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::llm::decision::asks::grant_draft::AskGrantDraft;
use oneiron_store::model_decision::DecisionAnswer;
use oneiron_store::model_decision::PairedReading;
use oneiron_store::model_decision::ProviderPin;
use serde::Deserialize;
use serde::Serialize;

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
pub mod grant_draft;
