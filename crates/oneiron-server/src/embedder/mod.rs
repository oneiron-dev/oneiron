//! The embedder provider slot.
//!
//! The engine owns the whole embedding contract — the queue, the leases, the
//! f16 rows, the `model_id` pin — and injects nothing. This module is the
//! host side of that seam: one slot, three providers, one trait object handed
//! to the reconciler.
//!
//! Everything except "run the forward" is shared, and shared on purpose: the
//! space id, the text projection, the query instruction, the numerics contract
//! on returned vectors. Two providers that differed in any of those would open
//! two embedding spaces inside one vault.

mod endpoint;
mod local;

use std::sync::{Arc, OnceLock};

use oneiron::embed::{Embedder, EmbedderLocality, PendingEmbeddingInput, payload_text};

use crate::config::{EmbedderConfig, EmbedderProvider};

/// An embedder that can also embed a QUERY.
///
/// The engine's [`Embedder`] covers the write path only: it embeds pending
/// rows. The read path needs the query side of the same model, with the
/// instruction prefix the model asks for, so the slot carries this narrower
/// trait and hands the engine the wider one.
pub(crate) trait QueryEmbedder: Embedder {
    fn embed_query(&self, text: &str) -> oneiron::Result<Vec<f32>>;
    /// Inputs the provider had to shorten since it started serving. The worker
    /// reports it per pass; an operator who sees it climb has their token cap
    /// set below their corpus.
    fn truncations(&self) -> u64;

    /// The endpoint provider, for the one thing only it has: a startup probe
    /// against a remote. Every other provider answers `None` and the probe is
    /// skipped, rather than the slot downcasting on a provider tag.
    fn as_endpoint(&self) -> Option<&endpoint::HttpEmbedder> {
        None
    }
}

/// Identity and numerics every provider shares.
#[derive(Clone, Debug)]
pub(crate) struct EmbedderCommon {
    /// `org/name@revision` — the vault's embedding space.
    pub(crate) model_id: String,
    pub(crate) dimensions: usize,
    pub(crate) query_instruction: String,
}

impl EmbedderCommon {
    fn from_config(config: &EmbedderConfig) -> Self {
        Self {
            model_id: config.model_id.clone(),
            dimensions: config.dimensions,
            query_instruction: config.query_instruction.clone(),
        }
    }

    /// The query text a provider actually embeds.
    fn query_text(&self, text: &str) -> String {
        format!("{}{text}", self.query_instruction)
    }

    /// The document text a provider actually embeds: the engine's canonical
    /// projection, with no instruction prefix. The model's instruction is a
    /// query-side asymmetry, and prefixing a document would put the corpus in
    /// a different place in the space than every bench measured.
    fn document_text(&self, input: &PendingEmbeddingInput) -> oneiron::Result<String> {
        let text = payload_text(&input.payload)?;
        if text.trim().is_empty() {
            // A pending row with no text has nothing to embed, and a zero
            // vector would be a lie that retrieval would then rank. The write
            // path is not supposed to mark such a row.
            return Err(oneiron::Error::InvariantViolation(
                "a pending embedding row projected to empty text",
            ));
        }
        Ok(text.into_owned())
    }

    /// The numerics contract on every vector leaving any provider.
    ///
    /// Exactly `dimensions` finite components, L2-normalised, and rounded
    /// through `f16` — which is what the engine stores, so a provider that
    /// returned unrounded values would report a vector the vault does not
    /// hold, and the row encoder would be the first to find out.
    fn finish_vector(&self, mut vector: Vec<f32>) -> oneiron::Result<Vec<f32>> {
        if vector.len() != self.dimensions {
            return Err(oneiron::Error::DimensionMismatch {
                expected: self.dimensions,
                got: vector.len(),
            });
        }
        for (index, &value) in vector.iter().enumerate() {
            if !value.is_finite() {
                return Err(oneiron::Error::InvalidVector { index, value });
            }
        }
        let norm = vector.iter().map(|v| v * v).sum::<f32>().sqrt();
        if !norm.is_finite() || norm <= 0.0 {
            return Err(oneiron::Error::InvalidVector {
                index: 0,
                value: norm,
            });
        }
        for value in &mut vector {
            let scaled = *value / norm;
            let narrowed = half::f16::from_f32(scaled);
            if !narrowed.is_finite() {
                return Err(oneiron::Error::InvalidVector {
                    index: 0,
                    value: scaled,
                });
            }
            *value = narrowed.to_f32();
        }
        Ok(vector)
    }
}

/// Why a query could not be embedded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EmbedQueryRefusal {
    /// No `[embedder]` section, or `provider = "none"`.
    NotConfigured,
    /// Configured, but the provider is not serving yet — the local model is
    /// still downloading, verifying or loading. Writes still land; vectors
    /// fill later (the two-tier write rule).
    NotReady,
    /// The provider is serving but this call failed. The cause is logged where
    /// it happened; the caller gets no detail about a remote or a device.
    Failed,
}

/// The slot on the server: what is configured, and whether it is serving yet.
pub(crate) struct EmbedderSlot {
    config: EmbedderConfig,
    /// Filled the first time a provider is ready.
    ///
    /// The local provider needs artifacts it may have to download, so it is
    /// built by the worker and not at boot: a vault whose model has never been
    /// fetched still opens, still answers BM25, and starts filling vectors when
    /// the fetch succeeds. A `OnceLock` FIELD, never a process static — the
    /// slot belongs to the server that owns the vault.
    ready: OnceLock<Arc<dyn QueryEmbedder>>,
}

impl EmbedderSlot {
    /// Builds the slot for a resolved section, or `None` at rung 0.
    ///
    /// The endpoint provider is ready on return: it holds an HTTP client and
    /// no artifacts. The local provider is not, by design.
    pub(crate) fn from_config(config: &EmbedderConfig) -> oneiron::Result<Option<Self>> {
        if !config.is_active() {
            return Ok(None);
        }
        let slot = Self {
            config: config.clone(),
            ready: OnceLock::new(),
        };
        if config.provider == EmbedderProvider::Endpoint {
            let embedder = endpoint::HttpEmbedder::from_config(config)?;
            let _ = slot.ready.set(embedder as Arc<dyn QueryEmbedder>);
        }
        Ok(Some(slot))
    }

    pub(crate) fn config(&self) -> &EmbedderConfig {
        &self.config
    }

    pub(crate) fn provider(&self) -> EmbedderProvider {
        self.config.provider
    }

    /// The provider, if it is serving.
    pub(crate) fn ready(&self) -> Option<&Arc<dyn QueryEmbedder>> {
        self.ready.get()
    }

    /// Truncations the serving provider has counted, or `None` before it serves.
    pub(crate) fn truncations(&self) -> Option<u64> {
        self.ready.get().map(|embedder| embedder.truncations())
    }

    /// Makes the provider ready, doing whatever that costs.
    ///
    /// For the local provider that is the first-use download, the sha256
    /// verification and the load-plus-quantise, so this blocks for seconds to
    /// minutes and belongs on a blocking thread. Idempotent: once ready, it
    /// returns the same provider.
    pub(crate) fn ensure_ready(&self) -> oneiron::Result<Arc<dyn QueryEmbedder>> {
        if let Some(ready) = self.ready.get() {
            return Ok(Arc::clone(ready));
        }
        let embedder = local::LocalEmbedder::load(&self.config)? as Arc<dyn QueryEmbedder>;
        let _ = self.ready.set(Arc::clone(&embedder));
        // `set` loses a race; the winner is the one every caller must see.
        Ok(self.ready.get().map_or(embedder, Arc::clone))
    }

    /// Embeds a query, or says why it cannot.
    pub(crate) fn embed_query(&self, text: &str) -> Result<Vec<f32>, EmbedQueryRefusal> {
        let Some(embedder) = self.ready.get() else {
            return Err(EmbedQueryRefusal::NotReady);
        };
        embedder.embed_query(text).map_err(|error| {
            tracing::warn!(?error, "query embedding failed");
            EmbedQueryRefusal::Failed
        })
    }
}

/// Maps a configured endpoint locality onto the engine's enum.
fn engine_locality(config: crate::config::EmbedderLocality) -> EmbedderLocality {
    match config {
        crate::config::EmbedderLocality::OnDevice => EmbedderLocality::OnDevice,
        crate::config::EmbedderLocality::OwnerServer => EmbedderLocality::OwnerServer,
    }
}

/// Builds the slot for a resolved serve configuration, probing an endpoint
/// provider before the listener binds.
///
/// A reachable remote that serves the wrong model or the wrong width stops
/// `serve`: filling one vault from two embedding spaces is not recoverable, so
/// it is refused before anything is written. An UNREACHABLE remote is logged and
/// started anyway — the vault answers lexical and graph reads meanwhile, which
/// is the two-tier write rule, not a degraded mode.
pub(crate) fn build_slot(config: Option<&EmbedderConfig>) -> anyhow::Result<Option<EmbedderSlot>> {
    let Some(config) = config else {
        return Ok(None);
    };
    let Some(slot) = EmbedderSlot::from_config(config)? else {
        tracing::info!("embedder provider is none; the vault serves at rung 0");
        return Ok(None);
    };
    if let Some(ready) = slot.ready()
        && let Some(http) = ready.as_endpoint()
    {
        match endpoint::probe_endpoint(http) {
            Ok(endpoint::ProbeOutcome::Ready) => {
                tracing::info!("endpoint embedder probe succeeded");
            }
            Ok(endpoint::ProbeOutcome::Unreachable(reason)) => {
                tracing::warn!(
                    reason,
                    "endpoint embedder is unreachable; starting at rung 0 and retrying in the worker"
                );
            }
            Err(error) => anyhow::bail!("{error}"),
        }
    }
    tracing::info!(
        provider = slot.provider().as_str(),
        model_id = %slot.config().model_id,
        dimensions = slot.config().dimensions,
        "embedder slot configured"
    );
    Ok(Some(slot))
}

#[cfg(test)]
mod tests;
