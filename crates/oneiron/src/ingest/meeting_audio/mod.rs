//! Boundary-preserving batch meeting-audio producer for the existing ingest adapter.
//!
//! Hosts decode files, route ASR through OF-133, and run actual inference. This
//! module does not bundle models or claim that fixture callbacks are inference.
//! The immutable artifact is normalized by the existing meeting-transcript
//! source. Import consent is separate from recording or voiceprint consent.

mod alignment;
mod artifact;
mod caller_import;
mod cleanup;
mod command;
mod error;
mod evaluation;
mod metrics;
mod note_import;
mod packing;
mod persistence;
mod producer;
mod provenance;
mod recorded_evaluation;
mod session_import;
mod session_input;
mod session_source;
mod types;

pub use alignment::align_words_to_speakers;
pub use artifact::{AuthorizedMeetingImport, ProducedMeetingTranscript};
pub use caller_import::{
    MeetingTranscriptCallerImportError, MeetingTranscriptCallerImportOutcome,
    MeetingTranscriptImportAttempt, OwnedMeetingTranscriptImportAttempt,
};
pub use cleanup::validate_cleanup;
pub use command::{
    CommandAudioConfig, CommandMeetingAudioHost, MeetingAudioSeats, NativeAudioCapabilities,
    UNIT_PROGRESS_TIMEOUT,
};
pub use error::{AudioError, AudioResult};
pub use evaluation::{CohortFile, CohortManifest, E1Arm, E1SelectionReceipt, WerCountsSerde};
pub use metrics::{
    E3Assignment, E3Score, WerAlignment, WerCounts, aggregate_wer, e3_score, wer_counts,
};
pub use note_import::{MEETING_TRANSCRIPT_NOTE_KIND, MeetingTranscriptNoteOutcome};
pub use packing::pack_speech;
pub use persistence::{MeetingTranscriptVersionPin, StoredMeetingTranscript};
pub use producer::produce_meeting_transcript;
pub use recorded_evaluation::{
    LabelledReference, RecordedArm, RecordedEvaluation, RecordedEvaluationRun, RecordedFile,
    ReferenceDocument, SpeakerScore, WordCluster, evaluate_recorded_audio,
};
pub use session_import::{MeetingTranscriptImportError, MeetingTranscriptImportOutcome};
pub use session_input::MeetingTranscriptSessionInput;
pub(crate) use session_source::MeetingImportProvenance;
pub use types::{
    AllowedWordCorrection, AsrOutput, AsrPackRequest, AsrRole, AsrRoute, AsrWord, AudioFile,
    BatchAsrRequest, BatchDefault, BulkImportAuthorizer, BulkImportBinding, BulkImportReceipt,
    CleanupOutput, CleanupPolicy, CleanupRequest, GlobalDiarization, InferenceExecution,
    InferenceProvenance, LanguageCorrectionRules, MeetingAudioHost, Pcm16, ProcessingTier,
    ProducerOptions, SourceSpan, SpeakerTrack, SpeechPack, SpeechSpan, TranscriptTurn,
    TranscriptWord, VadOutput,
};

#[cfg(test)]
mod tests;
