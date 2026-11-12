//! Moved from `crates/oneiron/src/pipeline/retrieval_policy.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::retrieval_policy::RetrievalPolicyAction;
pub use crate::store::retrieval_policy::RetrievalPolicyDecision;
pub use crate::store::retrieval_policy::RetrievalPolicyEnvelope;
pub use crate::store::retrieval_policy::RetrievalPolicyIdentity;
pub use crate::store::retrieval_policy::RetrievalPolicyTier;
pub use crate::store::retrieval_policy::RetrievalPolicyTrace;
use rand::Rng;
use serde::Deserialize;
use serde::Serialize;

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalIntent {
    #[default]
    Unknown = 0,
    FactRetrieval = 1,
    ComplexReasoning = 2,
    ContextualSummarize = 3,
    CreativeGeneration = 4,
}

impl RetrievalIntent {
    /// Cheap fallback classifier. A host's semantic classification takes precedence.
    pub fn classify(query: &str) -> Self {
        let query = query.to_lowercase();
        let words: Vec<_> = query.split(|c: char| !c.is_alphanumeric()).collect();
        let has = |terms: &[&str]| words.iter().any(|word| terms.contains(word));
        if has(&["summarize", "summary", "recap"]) {
            Self::ContextualSummarize
        } else if has(&["brainstorm", "imagine", "draft", "creative"]) {
            Self::CreativeGeneration
        } else if has(&["compare", "why", "relationship", "connect", "explain"]) {
            Self::ComplexReasoning
        } else {
            Self::FactRetrieval
        }
    }
}
