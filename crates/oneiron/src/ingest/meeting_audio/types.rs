//! Typed host ports for file decoding, inference, routing and explicit import consent.

use serde::Serialize;

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

/// Times always use milliseconds. VAD and diarization use the full-file clock;
/// ASR uses the concatenated pack clock and is mapped by the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SpeechSpan {
    pub start_ms: u64,
    pub end_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceSpan {
    pub source_start_ms: u64,
    pub source_end_ms: u64,
    pub pack_start_ms: u64,
    pub pack_end_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpeechPack {
    pub pack_id: String,
    pub speech_ms: u64,
    pub audio_ms: u64,
    pub oversize_no_boundary: bool,
    pub source_spans: Vec<SourceSpan>,
}

/// Host-reported execution mode, not an engine attestation. Fixture mode must
/// never be cited as an E1/E3 result; measured mode still needs external receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceExecution {
    Fixture,
    Measured,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InferenceProvenance {
    /// Unique across the VAD, ASR and diarization calls of one run.
    pub invocation_id: String,
    pub model_id: String,
    pub input_sha256: String,
    pub execution: InferenceExecution,
}

#[derive(Debug, Clone)]
pub struct VadOutput {
    pub spans: Vec<SpeechSpan>,
    pub provenance: InferenceProvenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AsrRole {
    Asr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingTier {
    Local,
    HomeFleet,
    Hosted,
}

/// E1 evidence belongs to the host. A reference alone is never an engine claim
/// that a bake-off ran or that its preferred model won.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "basis", rename_all = "snake_case")]
pub enum BatchDefault {
    Provisional {
        model_id: String,
    },
    MeasuredE1 {
        model_id: String,
        evidence_ref: String,
    },
}

impl BatchDefault {
    pub fn model_id(&self) -> &str {
        match self {
            Self::Provisional { model_id } | Self::MeasuredE1 { model_id, .. } => model_id,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProducerOptions {
    /// Immutable domain data only. There is no previous-transcript input.
    pub glossary: Vec<String>,
    pub batch_default: BatchDefault,
    pub local_only: bool,
}

pub struct BatchAsrRequest<'a> {
    pub role: AsrRole,
    pub preferred_tier: ProcessingTier,
    pub local_only: bool,
    pub batch_default: &'a BatchDefault,
}

#[derive(Debug, Clone, Serialize)]
pub struct AsrRoute {
    pub role: AsrRole,
    pub model_id: String,
    pub tier: ProcessingTier,
    /// OF-133 host route receipt, including any tier fallback. A different
    /// model requires an explicit batch-default change, never silent drift.
    pub route_receipt_ref: String,
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
}

#[derive(Debug, Clone)]
pub struct AsrOutput {
    pub words: Vec<AsrWord>,
    pub aligner_model: String,
    pub provenance: InferenceProvenance,
}

/// The host must return community-1's exclusive track, not its overlapping
/// diarization track. Speaker labels must keep their full-file identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpeakerTrack {
    pub start_ms: u64,
    pub end_ms: u64,
    pub speaker_cluster: String,
}

#[derive(Debug, Clone)]
pub struct GlobalDiarization {
    pub exclusive_tracks: Vec<SpeakerTrack>,
    pub provenance: InferenceProvenance,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TranscriptWord {
    pub word_id: String,
    pub pack_id: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub text: String,
    pub confidence: Option<f64>,
    pub speaker_cluster: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TranscriptTurn {
    pub turn_id: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub text: String,
    pub source_word_ids: Vec<String>,
    pub speaker_cluster: String,
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
/// model dependencies or product prompt content. Method names pin the model
/// families at the inference boundary. The host still records exact versions.
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
    /// Called exactly once per successful producer run, with the entire decoded
    /// file (including silence). Return model_id `pyannote/speaker-diarization-community-1`.
    fn community1_exclusive_full_file(
        &mut self,
        audio: &Pcm16,
        sha256: &str,
    ) -> AudioResult<GlobalDiarization>;
    /// One corrected string per turn, in the supplied order. The engine owns
    /// labels and source IDs, and rejects added/deleted lexical content.
    fn cleanup_turns(&mut self, request: CleanupRequest<'_>) -> AudioResult<CleanupOutput>;
}

/// The consent request binds the complete artifact, not only an audio filename.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BulkImportBinding {
    /// Opaque vault/owner context supplied by the authenticated authorizer.
    pub vault_scope: String,
    pub source_id: String,
    pub recording_id: String,
    pub artifact_sha256: String,
    pub source_record_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BulkImportReceipt {
    pub binding: BulkImportBinding,
    pub receipt_ref: String,
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
