//! Host-enriched ASR observations over one owner-bound speculative recall session.
//! Labels, salient terms and vectors are observations supplied by the owner's
//! ASR host, not gate decisions or claims. Only the engine decides to fire/reuse.
use serde::{Deserialize, Serialize};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::asr::{
    AsrCloseRequest, AsrClosed, AsrFinalDecision, AsrFinalReceipt, AsrFireDecision,
    AsrHypothesisReceipt, AsrOpenRequest, AsrSession,
};

/// A strictly advancing revision within the server-minted handle. Cosmetic
/// transcript changes may advance the revision without changing the meaning.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AsrHypothesisRequest {
    pub handle: String,
    pub revision: u64,
    pub text: String,
    pub entity_labels: Vec<String>,
    pub salient_terms: Vec<String>,
    #[serde(default)]
    pub query_vector: Option<Vec<f32>>,
}

impl AsrHypothesisRequest {
    pub fn partial(&self) -> crate::speculative::SpeculativePartial<'_> {
        crate::speculative::SpeculativePartial {
            text: &self.text,
            entity_labels: &self.entity_labels,
            salient_terms: &self.salient_terms,
            query_vector: self.query_vector.as_deref(),
        }
    }

    pub fn validate(&self) -> crate::memory::MemoryResult<()> {
        if self.text.trim().is_empty() {
            return Err(crate::memory::MemoryError::bad_request(
                "ASR text must be nonempty",
            ));
        }
        Ok(())
    }
}
