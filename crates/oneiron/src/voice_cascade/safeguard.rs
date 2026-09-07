//! Correlated sentence work. Policy decisions are made only by the existing engine.

use std::sync::Arc;

use crate::Vault;
use crate::error::{Error, Result};
use crate::llm::{BudgetLease, LlmBackend};
use crate::policy_model::{PolicyClassifyRequest, PolicyModelConfig, PolicyModelEnforcement};

use super::{GenerationEpoch, Safeguard, TtsCommand, TtsSeamClient};

/// A host-delimited completed sentence. The key is minted by the session and
/// returned with engine enforcement, so late/duplicate verdicts cannot kill a
/// newer sentence or generation. No public constructor or wire deserializer.
pub struct SafeguardRequest {
    pub(super) vault: Arc<Vault>,
    pub(super) generation: GenerationEpoch,
    pub(super) sentence: u64,
    pub(super) request: PolicyClassifyRequest,
}

impl std::fmt::Debug for SafeguardRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafeguardRequest")
            .field("generation", &self.generation)
            .field("sentence", &self.sentence)
            .finish_non_exhaustive()
    }
}

impl SafeguardRequest {
    #[must_use]
    pub fn generation(&self) -> GenerationEpoch {
        self.generation
    }

    #[must_use]
    pub fn request(&self) -> &PolicyClassifyRequest {
        &self.request
    }

    /// Pattern/config-only engine door. An unavailable model keeps the existing
    /// sovereign owner-plane behavior; this layer invents no outage policy.
    pub fn enforce(self, config: &PolicyModelConfig) -> Result<SentenceEnforcement> {
        let enforcement = self
            .vault
            .enforce_policy_model_with_config(self.request, config)?;
        Ok(SentenceEnforcement {
            generation: self.generation,
            sentence: self.sentence,
            enforcement,
        })
    }

    /// Real backend door, including current-policy revalidation and receipts.
    /// Run this outside the session lock, concurrently with TTS, then feed its
    /// result to `VoiceCascadeSession::apply_safeguard`.
    pub async fn enforce_with_backend(
        self,
        config: &PolicyModelConfig,
        backend: &dyn LlmBackend,
        lease: &BudgetLease,
    ) -> Result<SentenceEnforcement> {
        let enforcement = self
            .vault
            .enforce_policy_model_with_backend(self.request, config, backend, lease)
            .await?;
        Ok(SentenceEnforcement {
            generation: self.generation,
            sentence: self.sentence,
            enforcement,
        })
    }
}

#[derive(Debug)]
pub struct SentenceEnforcement {
    pub(super) generation: GenerationEpoch,
    pub(super) sentence: u64,
    pub(super) enforcement: PolicyModelEnforcement,
}

impl SentenceEnforcement {
    #[must_use]
    pub fn enforcement(&self) -> &PolicyModelEnforcement {
        &self.enforcement
    }
}

/// Both submissions are available in the same session transition. There is no
/// future to await before TTS and no synthetic policy warning in the text path.
#[must_use = "submit the sentence to TTS and its optional safeguard concurrently"]
#[derive(Debug)]
pub struct SentenceWork {
    pub(super) generation: GenerationEpoch,
    pub(super) text: String,
    pub(super) safeguard: Option<SafeguardRequest>,
}

impl SentenceWork {
    #[must_use]
    pub fn needs_safeguard(&self) -> bool {
        self.safeguard.is_some()
    }

    /// All methods enqueue work, not await model/audio completion. Even a failed
    /// TTS submission cannot skip safeguard. The host owns the scheduling proof
    /// and must end/flush on a submission error rather than leave a pending pass.
    pub fn dispatch(
        self,
        tts: &mut impl TtsSeamClient,
        safeguard: &mut impl Safeguard,
    ) -> Vec<Error> {
        let mut errors = Vec::new();
        if let Err(error) = tts.submit(TtsCommand::Text {
            generation: self.generation,
            text: self.text,
        }) {
            errors.push(error);
        }
        if let Err(error) = tts.submit(TtsCommand::Flush {
            generation: self.generation,
        }) {
            errors.push(error);
        }
        if let Some(request) = self.safeguard
            && let Err(error) = safeguard.submit(request)
        {
            errors.push(error);
        }
        errors
    }
}
