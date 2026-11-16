//! Typed host ports for file decoding, inference, routing and explicit import consent.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{AudioError, AudioResult};

/// Input bytes are copied into no engine store by the producer.
pub struct AudioFile<'a> {
    pub bytes: &'a [u8],
    pub source_name: &'a str,
    pub capture_started_at: Option<u64>,
    pub language_hint: Option<&'a str>,
}

/// Canonical decoded mono signed 16-bit PCM at 16 kHz.
#[derive(Debug, Clone)]
pub struct Pcm16 {
    pub samples: Vec<i16>,
}

impl Pcm16 {
    pub fn duration_ms(&self) -> AudioResult<u64> {
        let samples = u64::try_from(self.samples.len()).map_err(|_| AudioError::InvalidAudio)?;
        Ok(samples.div_ceil(16))
    }
}

#[doc(hidden)]
pub use oneiron_verb_wire::ingest::meeting_audio::types::{
    BulkImportBinding, BulkImportReceipt, SourceSpan, SpeakerTrack, SpeechSpan,
};

#[doc(hidden)]
pub use oneiron_records::ingest::meeting_audio::types::{
    AllowedWordCorrection, AsrRole, AsrRoute, BatchDefault, CleanupPolicy, InferenceExecution,
    InferenceProvenance, LanguageCorrectionRules, ProcessingTier, SpeechPack, TranscriptTurn,
    TranscriptWord,
};

#[derive(Debug, Clone)]
pub struct VadOutput {
    pub spans: Vec<SpeechSpan>,
    pub provenance: InferenceProvenance,
}

#[derive(Debug, Clone)]
pub struct ProducerOptions {
    /// Immutable domain data only. There is no previous-transcript input.
    pub glossary: Vec<String>,
    pub batch_default: BatchDefault,
    /// Expected OF-133 full-file diarizer; a different receipt must refuse.
    pub diarization_model_id: String,
    /// None means cosmetic-only; populated policy is resolved by the host.
    pub cleanup_policy: Option<CleanupPolicy>,
    pub local_only: bool,
    /// Resolved from the current vault table at route time; explicit local_only
    /// and the batch model pin still have higher priority.
    pub batch_asr_policy: Option<crate::llm::PurposeDefault>,
}

impl ProducerOptions {
    /// Snapshot the resident-editable batch ASR row before routing this file.
    pub fn with_vault_policy(mut self, vault: &crate::Vault) -> crate::Result<Self> {
        self.batch_asr_policy = Some(
            vault
                .purpose_default_table()?
                .voice(crate::llm::VoiceLane::AsrBatch)
                .clone(),
        );
        Ok(self)
    }
}

pub struct BatchAsrRequest<'a> {
    pub role: AsrRole,
    pub preferred_tier: ProcessingTier,
    pub local_only: bool,
    pub batch_default: &'a BatchDefault,
}

pub struct AsrPackRequest<'a> {
    pub route: &'a AsrRoute,
    pub pack: &'a SpeechPack,
    pub audio: &'a Pcm16,
    pub audio_sha256: &'a str,
    pub glossary: &'a [String],
    pub language_hint: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct AsrWord {
    pub start_ms: u64,
    pub end_ms: u64,
    pub text: String,
    pub confidence: Option<f64>,
    /// Acoustic alternatives from this pack's inference, never a cleanup
    /// model's assertion or a term copied from the glossary.
    pub acoustic_candidates: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AsrOutput {
    pub words: Vec<AsrWord>,
    pub aligner_model: String,
    pub provenance: InferenceProvenance,
}

#[derive(Debug, Clone)]
pub struct GlobalDiarization {
    pub exclusive_tracks: Vec<SpeakerTrack>,
    pub provenance: InferenceProvenance,
}

pub struct CleanupRequest<'a> {
    pub turns: &'a [TranscriptTurn],
    /// SHA-256 of serde_json encoding of the raw turns (the exact cleanup input).
    pub input_sha256: &'a str,
}

#[derive(Debug, Clone)]
pub struct CleanupOutput {
    pub texts: Vec<String>,
    pub provenance: InferenceProvenance,
}

/// Host supplies runtime code, models, and prompts; the engine supplies no
/// model dependencies or product prompt content. A specialized host can
/// refuse unsupported models; the generic producer checks the selected model.
pub trait MeetingAudioHost {
    /// Optional fail-fast host readiness check. It grants neither inference
    /// consent nor model-selection authority; every port still validates output.
    fn preflight_artifact(&mut self) -> AudioResult<()> {
        Ok(())
    }
    fn decode(&mut self, file: &AudioFile<'_>) -> AudioResult<Pcm16>;
    fn silero_vad(&mut self, audio: &Pcm16, sha256: &str) -> AudioResult<VadOutput>;
    fn route_batch_asr(&mut self, request: BatchAsrRequest<'_>) -> AudioResult<AsrRoute>;
    fn transcribe_pack(&mut self, request: AsrPackRequest<'_>) -> AudioResult<AsrOutput>;
    /// Called exactly once per successful producer run with the complete file.
    /// Return an exclusive track from the selected diarization model.
    fn diarize_full_file(&mut self, audio: &Pcm16, sha256: &str) -> AudioResult<GlobalDiarization>;
    /// One corrected string per turn, in the supplied order. The engine owns
    /// labels and source IDs and only allows an ASR-backed 1:1 word correction.
    fn cleanup_turns(&mut self, request: CleanupRequest<'_>) -> AudioResult<CleanupOutput>;
}

/// An authenticated host boundary, not a boolean supplied by transcript data.
/// Returning None represents missing, pending or denied owner approval.
/// This import consent is NOT permission to enroll a voiceprint or auto-admit claims.
pub trait BulkImportAuthorizer {
    /// A host instance must not serve another vault under this same scope.
    fn vault_scope(&self) -> &str;
    fn authorize_import(
        &mut self,
        binding: &BulkImportBinding,
    ) -> AudioResult<Option<BulkImportReceipt>>;
}
