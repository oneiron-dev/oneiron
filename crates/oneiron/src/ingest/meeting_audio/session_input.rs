//! Exact native SESSION input derived from one immutable meeting artifact.

use serde::Deserialize;

use crate::calendar::transcript::{ParsedTranscript, ParsedTranscriptTurn};
use crate::ingest::{
    INGEST_SOURCE_REGISTRY, IngestError, MEETING_TRANSCRIPT_SOURCE_ID, NormalizedIngestNote,
};

use super::{AudioError, AudioResult, ProducedMeetingTranscript};

/// The ordered native transcript and its source identities. These are source
/// data, not PERSON identities, owner credentials or import consent.
#[derive(Debug, Clone)]
pub struct MeetingTranscriptSessionInput {
    pub transcript: ParsedTranscript,
    /// One exact source turn id per native turn, in the same order.
    pub source_record_ids: Vec<String>,
    /// The source thread shared by those turns.
    pub recording_id: String,
    /// Whole-batch fallback, retained even when turns are present.
    pub note_fallback: Option<NormalizedIngestNote>,
}

#[derive(Deserialize)]
struct Document {
    recording: Recording,
    turns: Vec<TurnOffsets>,
}

#[derive(Deserialize)]
struct Recording {
    capture_started_at: Option<u64>,
}

#[derive(Deserialize)]
struct TurnOffsets {
    start_ms: u64,
    end_ms: u64,
}

impl ProducedMeetingTranscript {
    /// Project structured turns without passing JSON through the FileDrop
    /// line parser. Source capture time is seconds; source offsets retain
    /// their millisecond precision. No capture time means no absolute claim.
    /// This pure projection neither imports nor closes a SESSION.
    pub fn session_input(&self) -> AudioResult<MeetingTranscriptSessionInput> {
        let batch = INGEST_SOURCE_REGISTRY.normalize(MEETING_TRANSCRIPT_SOURCE_ID, self.json())?;
        let document: Document =
            serde_json::from_str(self.json()).map_err(|_| AudioError::Serialization)?;
        let mut turns = Vec::with_capacity(batch.records.len());
        let mut source_record_ids = Vec::with_capacity(batch.records.len());
        for (ordinal, (record, offsets)) in
            batch.records.into_iter().zip(document.turns).enumerate()
        {
            let claimed = |offset| {
                document
                    .recording
                    .capture_started_at
                    .map(|capture| {
                        capture
                            .checked_mul(1_000)
                            .and_then(|base| base.checked_add(offset))
                            .ok_or_else(|| IngestError::TimestampOverflow {
                                source_id: MEETING_TRANSCRIPT_SOURCE_ID,
                                turn_id: record.source_record_id.clone(),
                            })
                    })
                    .transpose()
            };
            let claimed_start_ms = claimed(offsets.start_ms)?;
            let claimed_end_ms = claimed(offsets.end_ms)?;
            turns.push(ParsedTranscriptTurn {
                ordinal: u32::try_from(ordinal).map_err(|_| AudioError::Serialization)?,
                speaker_label: record.speaker,
                claimed_start_ms,
                claimed_end_ms,
                text: record.text,
            });
            source_record_ids.push(record.source_record_id);
        }
        Ok(MeetingTranscriptSessionInput {
            transcript: ParsedTranscript {
                claimed_started_ms: turns.iter().filter_map(|turn| turn.claimed_start_ms).min(),
                claimed_ended_ms: turns.iter().filter_map(|turn| turn.claimed_end_ms).max(),
                turns,
            },
            source_record_ids,
            recording_id: self.recording_id().to_owned(),
            note_fallback: batch.note_fallback,
        })
    }
}
