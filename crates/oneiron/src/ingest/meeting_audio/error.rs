//! Typed producer refusals; these pre-ingest errors do not alter the vault ABI.

use crate::ingest::IngestError;

pub type AudioResult<T> = Result<T, AudioError>;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum AudioError {
    #[error("empty or malformed audio")]
    InvalidAudio,
    #[error("invalid producer configuration")]
    InvalidOptions,
    #[error("invalid or unordered VAD spans")]
    InvalidVad,
    #[error("VAD found no speech")]
    NoSpeech,
    #[error("ASR route violated the batch or local-only contract")]
    InvalidRoute,
    #[error("invalid inference provenance")]
    InvalidProvenance,
    #[error("invalid or unordered ASR words")]
    InvalidWords,
    #[error("a speech pack yielded no words")]
    EmptyAsr,
    #[error("ASR word crosses a removed-silence seam")]
    WordCrossesPackSeam,
    #[error("diarization did not return a valid exclusive track")]
    NonExclusiveTracks,
    #[error("no speaker track intersects word {word_id}")]
    UnlabelledWord { word_id: String },
    #[error("cleanup changed lexical content")]
    CleanupInventedContent,
    #[error("cleanup changed the turn count")]
    CleanupChangedTurns,
    #[error("explicit bulk import approval is required")]
    BulkConsentRequired,
    #[error("bulk import receipt does not bind this artifact")]
    BulkConsentMismatch,
    #[error("invalid E1 selection receipt")]
    InvalidEvaluationReceipt,
    #[error("invalid evaluation cohort manifest")]
    InvalidCohortManifest,
    #[error("host stage {stage} failed: {code}")]
    Host { stage: String, code: String },
    #[error("artifact serialization failed")]
    Serialization,
    #[error(transparent)]
    Ingest(#[from] IngestError),
}
