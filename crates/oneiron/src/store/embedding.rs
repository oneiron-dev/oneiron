//! Core half of `store::embedding`: its store-layer items live in `oneiron_store::embedding` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::embedding::*;

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::settings::ReadDestination;
use oneiron_base::config::VectorEvidenceFloors;
use oneiron_base::machine_destination::PeerMachine;
pub use oneiron_store::embedding_vocabulary::InputKind;
pub(crate) use oneiron_store::embedding_vocabulary::TEXT_HASH_LEN;
pub use oneiron_store::embedding_vocabulary::{EmbeddingDevice, EmbeddingProvenance};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Where an embedder runs relative to the vault owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmbedderLocality {
    /// Runs on the same device as the vault.
    OnDevice,
    /// Runs on infrastructure controlled by the vault owner.
    OwnerServer,
    /// Runs on a third-party service.
    ThirdParty,
}

/// Host-injected retrieval embedder.
///
/// The engine owns queueing, leases, and vector storage. Implementations own
/// model execution and any locality-specific policy before returning vectors.
pub trait Embedder: Send + Sync {
    fn model_id(&self) -> &str;
    fn dimensions(&self) -> usize;
    fn locality(&self) -> EmbedderLocality;
    /// Where this embedder reads toward (FIX 5588): this device for an
    /// [`EmbedderLocality::OnDevice`] embedder, else a destination nobody
    /// proved. A host whose model sits behind a host-attested Mesh proof
    /// overrides this with that peer; locality alone never names one.
    fn endpoint(&self) -> ReadDestination {
        match self.locality() {
            EmbedderLocality::OnDevice => ReadDestination::on_device(),
            EmbedderLocality::OwnerServer | EmbedderLocality::ThirdParty => {
                ReadDestination::toward(PeerMachine::Unknown)
            }
        }
    }
    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> Result<Vec<Vec<f32>>>;
    /// The device and runtime that compute what [`Self::embed`] returns,
    /// stored beside each vector it fills. Unknown unless overridden.
    fn provenance(&self) -> EmbeddingProvenance {
        EmbeddingProvenance::unknown()
    }
    /// [`Self::embed`], each vector with the device and runtime that computed
    /// it. An embedder whose answers name their own (an endpoint that says)
    /// overrides this; any other marks each with [`Self::provenance`].
    fn embed_marked(
        &self,
        inputs: &[PendingEmbeddingInput],
    ) -> Result<Vec<(Vec<f32>, EmbeddingProvenance)>> {
        let provenance = self.provenance();
        Ok(self
            .embed(inputs)?
            .into_iter()
            .map(|vector| (vector, provenance.clone()))
            .collect())
    }

    /// [`Self::embed_marked`] for an embedder off this device: `release`
    /// judges the rows of each request it sends right before that request
    /// leaves, and a refusal sends nothing and fails the embed. One that
    /// sends a single request needs no more than this default.
    fn embed_released(
        &self,
        inputs: &[PendingEmbeddingInput],
        release: &dyn Fn(&[EntityId]) -> Result<()>,
    ) -> Result<Vec<(Vec<f32>, EmbeddingProvenance)>> {
        let rows: Vec<EntityId> = inputs.iter().map(|input| input.entity_id).collect();
        release(&rows)?;
        self.embed_marked(inputs)
    }

    /// [`Self::embed_marked`], each vector with its measured input-token count
    /// when the embedder counts the actual encoder input. An embedder that
    /// measures overrides this; any other marks each `None` via this default,
    /// which calls [`Self::embed_marked`] exactly once and never the model
    /// twice.
    fn embed_marked_measured(
        &self,
        inputs: &[PendingEmbeddingInput],
    ) -> Result<Vec<EmbeddedVector>> {
        Ok(self
            .embed_marked(inputs)?
            .into_iter()
            .map(|(vector, provenance)| EmbeddedVector {
                vector,
                provenance,
                input_tokens: None,
            })
            .collect())
    }

    /// [`Self::embed_released`], each vector with its measured input-token
    /// count when the embedder counts the actual encoder input. The default
    /// calls [`Self::embed_released`] exactly once (preserving every custom
    /// final-request release hook) and marks each `None`.
    fn embed_released_measured(
        &self,
        inputs: &[PendingEmbeddingInput],
        release: &dyn Fn(&[EntityId]) -> Result<()>,
    ) -> Result<Vec<EmbeddedVector>> {
        Ok(self
            .embed_released(inputs, release)?
            .into_iter()
            .map(|(vector, provenance)| EmbeddedVector {
                vector,
                provenance,
                input_tokens: None,
            })
            .collect())
    }
}

/// A configured non-OnDevice rung.
#[cfg(feature = "sync")]
pub struct RemoteRung {
    pub embedder: std::sync::Arc<dyn Embedder>,
    pub predicate: std::sync::Arc<dyn EgressPredicate>,
    pub lease_duration_ms: u64,
    /// The full `model@place` route id minted for this rung at build time
    /// (FIX 11768 seam for L05): `None` when built without one (tests,
    /// fixtures, primary rungs), in which case [`Self::offer_id`] is empty
    /// and no ordered world admits it (fail-closed).
    pub offer_id: Option<String>,
}

#[cfg(feature = "sync")]
impl RemoteRung {
    /// Builds a rung with the default remote lease window
    /// ([`DEFAULT_REMOTE_PENDING_EMBEDDING_LEASE_MS`]).
    #[must_use]
    pub fn new(
        embedder: std::sync::Arc<dyn Embedder>,
        predicate: std::sync::Arc<dyn EgressPredicate>,
    ) -> Self {
        Self {
            embedder,
            predicate,
            lease_duration_ms: DEFAULT_REMOTE_PENDING_EMBEDDING_LEASE_MS,
            offer_id: None,
        }
    }

    /// The full `model@place` route id carried from build time (FIX 11768
    /// seam for L05), or empty when none was carried: an unidentified rung
    /// matches no ordered world (fail-closed).
    #[must_use]
    pub fn offer_id(&self) -> String {
        self.offer_id.clone().unwrap_or_default()
    }

    /// Where this rung reads toward (FIX 5588): its embedder's endpoint. The
    /// rung carries no proof of its own, so this never narrows past what the
    /// embedder reports.
    #[must_use]
    pub fn endpoint(&self) -> ReadDestination {
        self.embedder.endpoint()
    }
}

/// A host model that embeds image and audio documents, and on the one-space preset text
/// documents, into one declared space.
pub trait MediaEmbedder: Send + Sync {
    /// The declared space this model's vectors belong to.
    fn space_id(&self) -> &str;
    /// The vector width the model emits; it must equal the space's.
    fn dimensions(&self) -> usize;
    /// Where the model runs. Media bytes leave for a third party from this door only as the
    /// host's egress gate admits each document ([`Vault::reconcile_media_embeddings_admitted`]).
    fn locality(&self) -> EmbedderLocality;
    /// Where this model reads toward (FIX 5588): this device for an
    /// [`EmbedderLocality::OnDevice`] model, else a destination nobody proved.
    /// A host whose model sits behind a host-attested Mesh proof overrides this with that
    /// peer; locality alone never names one.
    fn endpoint(&self) -> ReadDestination {
        match self.locality() {
            EmbedderLocality::OnDevice => ReadDestination::on_device(),
            EmbedderLocality::OwnerServer | EmbedderLocality::ThirdParty => {
                ReadDestination::toward(PeerMachine::Unknown)
            }
        }
    }
    /// One vector per input, in input order.
    fn embed_media(&self, inputs: &[MediaEmbeddingInput<'_>]) -> Result<Vec<Vec<f32>>>;
    /// One outcome per input, in input order: its vector with the device and runtime its
    /// answer names, or why the model refused that document by its content (a format it
    /// cannot read, a content filter), so the backfill skips it until its bytes change. An
    /// error refuses the whole call. The default refuses no single document and marks each
    /// vector unknown; a model whose answers name their device overrides it.
    fn embed_each(&self, inputs: &[MediaEmbeddingInput<'_>]) -> Result<Vec<MediaOutcome>> {
        Ok(self
            .embed_media(inputs)?
            .into_iter()
            .map(|vector| Ok((vector, EmbeddingProvenance::unknown())))
            .collect())
    }

    /// [`Self::embed_each`] for a model at a third party: `release` judges the documents of
    /// each request right before that request leaves, and a refusal sends nothing more and
    /// fails the call. One that sends a single request needs no more than this default; one
    /// that sends a request per document asks for each.
    fn embed_each_released(
        &self,
        inputs: &[MediaEmbeddingInput<'_>],
        release: &(dyn Fn(&[EntityId]) -> Result<()> + Sync),
    ) -> Result<Vec<MediaOutcome>> {
        let rows: Vec<EntityId> = inputs
            .iter()
            .flat_map(MediaEmbeddingInput::source_rows)
            .copied()
            .collect();
        release(&rows)?;
        self.embed_each(inputs)
    }
}
