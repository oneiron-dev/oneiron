//! The hashing embedder: stable pseudo-vectors with no model.
//!
//! Each lower-cased word of the input lands, by its BLAKE3 hash, on one
//! dimension with a sign; the sum is L2-normalised. The same text always gives
//! the same vector on every host, and texts that share words lie closer than
//! texts that share none, so recall plumbing and gating are repeatable. It
//! measures nothing about quality; the scored quality cases do that.
//!
//! In process it is an [`oneiron::store::embedding::Embedder`]. For a server
//! in another process, [`crate::provider::ScriptedProvider`] serves the same
//! vectors on an OpenAI-compatible `/v1/embeddings` route.

use oneiron::Result;
use oneiron::store::embedding::{
    Embedder, EmbedderLocality, EmbeddingDevice, EmbeddingProvenance, PendingEmbeddingInput,
    PendingEmbeddingPayload,
};

/// The domain string each word's hash starts with, so these vectors never
/// collide with any other BLAKE3 use by construction.
const HASH_DOMAIN: &[u8] = b"oneiron-testkit/hashing-embedder/v1\0";

/// The runtime name stored beside each vector this embedder fills.
pub const HASHING_RUNTIME: &str = "oneiron-testkit-hashing/1";

/// A deterministic embedder of a fixed dimension. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashingEmbedder {
    dimensions: usize,
    model_id: String,
}

impl HashingEmbedder {
    /// An embedder of `dimensions` components (at least 1), whose model id
    /// is `oneiron-testkit-hashing-<dimensions>`.
    #[must_use]
    pub fn new(dimensions: usize) -> Self {
        let dimensions = dimensions.max(1);
        Self {
            dimensions,
            model_id: format!("oneiron-testkit-hashing-{dimensions}"),
        }
    }

    /// The model id a vault pins for these vectors.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model_id
    }

    /// The vector of `text`. Words are maximal runs of alphanumeric
    /// characters, lower-cased. A text with no word maps to the first unit
    /// vector, so no vector is ever zero.
    #[must_use]
    pub fn embed_text(&self, text: &str) -> Vec<f32> {
        let mut vector = vec![0.0_f32; self.dimensions];
        let mut words = 0_usize;
        for word in text
            .split(|c: char| !c.is_alphanumeric())
            .filter(|word| !word.is_empty())
        {
            let word = word.to_lowercase();
            let mut hasher = blake3::Hasher::new();
            hasher.update(HASH_DOMAIN);
            hasher.update(word.as_bytes());
            let hash = hasher.finalize();
            let bytes = hash.as_bytes();
            let mut index_bytes = [0_u8; 8];
            index_bytes.copy_from_slice(&bytes[..8]);
            let index = u64::from_le_bytes(index_bytes) % self.dimensions as u64;
            let sign = if bytes[8] & 1 == 0 { 1.0 } else { -1.0 };
            // `index` < `dimensions`, which is a usize.
            vector[usize::try_from(index).unwrap_or(0)] += sign;
            words += 1;
        }
        let norm = vector.iter().map(|value| value * value).sum::<f32>().sqrt();
        if words == 0 || norm == 0.0 {
            vector.iter_mut().for_each(|value| *value = 0.0);
            vector[0] = 1.0;
            return vector;
        }
        vector.iter_mut().for_each(|value| *value /= norm);
        vector
    }

    /// The vector of `bytes` read as lossy UTF-8: a MessagePack CLAIM body's
    /// strings become words and its framing bytes become separators.
    #[must_use]
    pub fn embed_bytes(&self, bytes: &[u8]) -> Vec<f32> {
        self.embed_text(&String::from_utf8_lossy(bytes))
    }

    /// The vector of one pending input, as the engine hands it over.
    #[must_use]
    pub fn embed_payload(&self, payload: &PendingEmbeddingPayload) -> Vec<f32> {
        match payload {
            PendingEmbeddingPayload::ClaimBody(bytes) => self.embed_bytes(bytes),
            PendingEmbeddingPayload::SummaryText(text)
            | PendingEmbeddingPayload::TurnText(text) => self.embed_text(text),
        }
    }
}

impl Embedder for HashingEmbedder {
    fn model_id(&self) -> &str {
        &self.model_id
    }

    fn dimensions(&self) -> usize {
        self.dimensions
    }

    fn locality(&self) -> EmbedderLocality {
        EmbedderLocality::OnDevice
    }

    fn embed(&self, inputs: &[PendingEmbeddingInput]) -> Result<Vec<Vec<f32>>> {
        Ok(inputs
            .iter()
            .map(|input| self.embed_payload(&input.payload))
            .collect())
    }

    fn provenance(&self) -> EmbeddingProvenance {
        EmbeddingProvenance::new(EmbeddingDevice::Cpu, HASHING_RUNTIME)
    }
}
