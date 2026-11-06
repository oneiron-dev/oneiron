//! Core half of `vault::entity_revision::types`: its store-layer items live in `oneiron_store::vault::entity_revision::types` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::vault::entity_revision::types::*;

pub use crate::store::revision_ref::RevisionRef;
use crate::{EntityId, error::Result};
use serde::{Deserialize, Serialize};

/// Exact version handed to the embedding adapter at idle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedRevisionInput {
    pub entity: EntityId,
    /// The record's type byte at this revision.
    pub entity_type: u8,
    pub source_revision_ref: RevisionRef,
    pub body: Vec<u8>,
    pub fields: Vec<(String, String)>,
}

impl IndexedRevisionInput {
    /// What the embedder embeds for this revision: a CLAIM by the rule the
    /// pending worker leases by, any other record as its text fields joined
    /// by newlines.
    ///
    /// Idle publication asks the embedder only when this is `Some`. `None` —
    /// a text of whitespace and control characters alone — publishes the
    /// revision with no vector and drops the one it had.
    pub fn payload(&self) -> Option<crate::store::embedding::PendingEmbeddingPayload> {
        crate::embed::indexed_payload(self.entity_type, &self.body, &self.fields)
    }
}

/// Caller-owned embedding provider. It runs outside the LMDB transaction.
/// `InvalidConfig`, `DimensionMismatch` and `InvalidVector` reject only this
/// input. Other errors abort the pass; check provider-wide configuration before
/// starting a pass rather than returning it as an input refusal.
pub trait IndexedRevisionEmbedder {
    fn embed_revision(&self, input: &IndexedRevisionInput) -> Result<Vec<f32>>;
    /// The device and runtime that compute what [`Self::embed_revision`]
    /// returns, stored beside each vector. Unknown unless overridden.
    fn provenance(&self) -> crate::store::embedding::EmbeddingProvenance {
        crate::store::embedding::EmbeddingProvenance::unknown()
    }
    /// [`Self::embed_revision`] with the device and runtime that computed
    /// the vector. A provider whose answers name their own overrides this;
    /// any other marks it with [`Self::provenance`].
    fn embed_revision_marked(
        &self,
        input: &IndexedRevisionInput,
    ) -> Result<(Vec<f32>, crate::store::embedding::EmbeddingProvenance)> {
        Ok((self.embed_revision(input)?, self.provenance()))
    }
}
