//! Boundary-preserving batch meeting-audio producer for the existing ingest adapter.
//!
//! Hosts decode files, route ASR through OF-133, and run actual inference. This
//! module does not bundle models or claim that fixture callbacks are inference.
//! The immutable artifact is normalized by the existing meeting-transcript
//! source. Import consent is separate from recording or voiceprint consent.

mod alignment;
mod artifact;
mod cleanup;
mod error;
mod packing;
mod producer;
mod provenance;
mod types;

pub use alignment::align_words_to_speakers;
pub use artifact::{AuthorizedMeetingImport, ProducedMeetingTranscript};
pub use cleanup::validate_cleanup;
pub use error::{AudioError, AudioResult};
pub use packing::pack_speech;
pub use producer::produce_meeting_transcript;
pub use types::{
    AsrOutput, AsrPackRequest, AsrRole, AsrRoute, AsrWord, AudioFile, BatchAsrRequest,
    BatchDefault, BulkImportAuthorizer, BulkImportBinding, BulkImportReceipt, CleanupOutput,
    CleanupRequest,
    GlobalDiarization, InferenceExecution, InferenceProvenance, MeetingAudioHost,
    Pcm16, ProcessingTier, ProducerOptions, SourceSpan, SpeakerTrack, SpeechPack,
    SpeechSpan, TranscriptTurn, TranscriptWord, VadOutput,
};

#[cfg(test)]
mod tests;
