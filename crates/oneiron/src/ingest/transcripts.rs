//! Transcript sources: JSONL, file-drop, and meeting normalization plus document helpers.

use serde_json::{Map, Value};

use super::{
    IngestError, IngestResult, IngestSource, JSONL_TRANSCRIPT_SOURCE_ID,
    MEETING_TRANSCRIPT_SCHEMA_V1, MEETING_TRANSCRIPT_SOURCE_ID, NormalizedIngestBatch,
    NormalizedIngestNote, NormalizedIngestRecord,
};

pub struct JsonlTranscriptSource;

impl IngestSource for JsonlTranscriptSource {
    fn normalize(&self, input: &str) -> IngestResult<NormalizedIngestBatch> {
        let mut records = Vec::new();

        for (index, raw_line) in input.lines().enumerate() {
            let line = index + 1;
            let raw_line = raw_line.trim();
            if raw_line.is_empty() {
                continue;
            }

            let value: Value =
                serde_json::from_str(raw_line).map_err(|err| IngestError::InvalidJson {
                    source_id: JSONL_TRANSCRIPT_SOURCE_ID,
                    line,
                    message: err.to_string(),
                })?;
            let object = value.as_object().ok_or(IngestError::JsonLineNotObject {
                source_id: JSONL_TRANSCRIPT_SOURCE_ID,
                line,
            })?;

            records.push(normalize_transcript_object(object, line)?);
        }

        Ok(NormalizedIngestBatch {
            source_id: JSONL_TRANSCRIPT_SOURCE_ID,
            records,
            claims: Vec::new(),
            entities: Vec::new(),
            note_fallback: None,
        })
    }
}

/// Normalizes the `oneiron.meeting_transcript.v1` producer artifact.
///
/// Normalization stays pre-semantic: corrected turns become records, the
/// producer's structured cleanup stays producer metadata, and no claim is ever
/// emitted. Turn text is already corrected upstream, so this layer validates
/// and maps rather than interpreting.
pub struct MeetingTranscriptSource;

impl IngestSource for MeetingTranscriptSource {
    fn normalize(&self, input: &str) -> IngestResult<NormalizedIngestBatch> {
        let document: Value =
            serde_json::from_str(input).map_err(|err| IngestError::InvalidDocument {
                source_id: MEETING_TRANSCRIPT_SOURCE_ID,
                message: err.to_string(),
            })?;
        let document = document
            .as_object()
            .ok_or_else(|| document_field_error("<root>"))?;

        let schema = document_string(document, "schema")?;
        if schema != MEETING_TRANSCRIPT_SCHEMA_V1 {
            return Err(IngestError::UnsupportedSchema {
                source_id: MEETING_TRANSCRIPT_SOURCE_ID,
                expected: MEETING_TRANSCRIPT_SCHEMA_V1,
                found: schema.to_owned(),
            });
        }

        let recording = document_object(document, "recording")?;
        let recording_id = document_string(recording, "recording.recording_id")?;
        if recording_id.trim().is_empty() {
            return Err(document_field_error("recording.recording_id"));
        }
        let duration_ms = document_u64(recording, "recording.duration_ms")?;
        // Capture time anchors every turn into wall-clock; without it turns are
        // still ordered and offset-bearing, so they normalize with no
        // `occurred_at` rather than failing the batch.
        let capture_started_at = optional_document_u64(recording, "recording.capture_started_at")?;

        let word_ids = collect_word_ids(document)?;
        let turns = document_array(document, "turns")?;
        let mut records = Vec::with_capacity(turns.len());
        let mut seen_turn_ids = std::collections::HashSet::with_capacity(turns.len());
        let mut previous_end_ms = 0_u64;

        for (index, turn) in turns.iter().enumerate() {
            let turn = turn
                .as_object()
                .ok_or_else(|| document_field_error(&format!("turns[{index}]")))?;
            let turn_id = document_string(turn, &format!("turns[{index}].turn_id"))?;
            if turn_id.trim().is_empty() {
                return Err(document_field_error(&format!("turns[{index}].turn_id")));
            }
            if !seen_turn_ids.insert(turn_id.to_owned()) {
                return Err(IngestError::DuplicateId {
                    source_id: MEETING_TRANSCRIPT_SOURCE_ID,
                    kind: "turn",
                    id: turn_id.to_owned(),
                });
            }

            let start_ms = document_u64(turn, &format!("turns[{index}].start_ms"))?;
            let end_ms = document_u64(turn, &format!("turns[{index}].end_ms"))?;
            // Turns are time-ordered, non-overlapping, and inside the
            // recording: anything else means the producer's time mapping broke,
            // and mapped `occurred_at` values would silently lie.
            if end_ms < start_ms || start_ms < previous_end_ms || end_ms > duration_ms {
                return Err(IngestError::InvalidTurnTimestamps {
                    source_id: MEETING_TRANSCRIPT_SOURCE_ID,
                    turn_id: turn_id.to_owned(),
                });
            }
            previous_end_ms = end_ms;

            let text = normalize_space(document_string(turn, &format!("turns[{index}].text"))?);
            if text.is_empty() {
                return Err(document_field_error(&format!("turns[{index}].text")));
            }

            for word_ref in document_array(turn, &format!("turns[{index}].source_word_ids"))? {
                let word_ref = word_ref.as_str().ok_or_else(|| {
                    document_field_error(&format!("turns[{index}].source_word_ids"))
                })?;
                if !word_ids.contains(word_ref) {
                    return Err(IngestError::UnknownWordReference {
                        source_id: MEETING_TRANSCRIPT_SOURCE_ID,
                        turn_id: turn_id.to_owned(),
                        word_id: word_ref.to_owned(),
                    });
                }
            }

            records.push(NormalizedIngestRecord {
                source_record_id: turn_id.to_owned(),
                thread_id: Some(recording_id.to_owned()),
                // A resolved identity outranks the anonymous cluster that
                // produced it; with neither, the turn is speaker-less rather
                // than attributed to a guess.
                speaker: optional_document_string(turn, &format!("turns[{index}].speaker_ref"))?
                    .or(optional_document_string(
                        turn,
                        &format!("turns[{index}].speaker_cluster"),
                    )?)
                    .map(str::to_owned),
                occurred_at: capture_started_at
                    .map(|base| {
                        base.checked_add(start_ms / 1000).ok_or_else(|| {
                            IngestError::TimestampOverflow {
                                source_id: MEETING_TRANSCRIPT_SOURCE_ID,
                                turn_id: turn_id.to_owned(),
                            }
                        })
                    })
                    .transpose()?,
                text,
            });
        }

        Ok(NormalizedIngestBatch {
            source_id: MEETING_TRANSCRIPT_SOURCE_ID,
            records,
            claims: Vec::new(),
            entities: Vec::new(),
            note_fallback: note_fallback(document, recording_id, capture_started_at)?,
        })
    }
}

/// Collects word ids, rejecting duplicates so turn references stay unambiguous.
fn collect_word_ids(
    document: &Map<String, Value>,
) -> IngestResult<std::collections::HashSet<String>> {
    let words = document_array(document, "words")?;
    let mut ids = std::collections::HashSet::with_capacity(words.len());
    for (index, word) in words.iter().enumerate() {
        let word = word
            .as_object()
            .ok_or_else(|| document_field_error(&format!("words[{index}]")))?;
        let word_id = document_string(word, &format!("words[{index}].word_id"))?;
        if word_id.trim().is_empty() {
            return Err(document_field_error(&format!("words[{index}].word_id")));
        }
        if !ids.insert(word_id.to_owned()) {
            return Err(IngestError::DuplicateId {
                source_id: MEETING_TRANSCRIPT_SOURCE_ID,
                kind: "word",
                id: word_id.to_owned(),
            });
        }
    }
    Ok(ids)
}

fn note_fallback(
    document: &Map<String, Value>,
    recording_id: &str,
    capture_started_at: Option<u64>,
) -> IngestResult<Option<NormalizedIngestNote>> {
    let Some(note) = document.get("note_fallback") else {
        return Ok(None);
    };
    if note.is_null() {
        return Ok(None);
    }
    let note = note
        .as_object()
        .ok_or_else(|| document_field_error("note_fallback"))?;

    let title = normalize_space(document_string(note, "note_fallback.title")?);
    let text = document_string(note, "note_fallback.body")?
        .trim()
        .to_owned();
    if title.is_empty() || text.is_empty() {
        return Err(document_field_error("note_fallback"));
    }

    Ok(Some(NormalizedIngestNote {
        source_record_id: recording_id.to_owned(),
        occurred_at: capture_started_at,
        title,
        text,
    }))
}

fn document_field_error(path: &str) -> IngestError {
    IngestError::InvalidDocumentField {
        source_id: MEETING_TRANSCRIPT_SOURCE_ID,
        path: path.to_owned(),
    }
}

fn document_string<'a>(object: &'a Map<String, Value>, path: &str) -> IngestResult<&'a str> {
    object
        .get(leaf_key(path))
        .and_then(Value::as_str)
        .ok_or_else(|| document_field_error(path))
}

fn optional_document_string<'a>(
    object: &'a Map<String, Value>,
    path: &str,
) -> IngestResult<Option<&'a str>> {
    match object.get(leaf_key(path)) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(Some)
            .ok_or_else(|| document_field_error(path)),
    }
}

fn document_u64(object: &Map<String, Value>, path: &str) -> IngestResult<u64> {
    object
        .get(leaf_key(path))
        .and_then(Value::as_u64)
        .ok_or_else(|| document_field_error(path))
}

fn optional_document_u64(object: &Map<String, Value>, path: &str) -> IngestResult<Option<u64>> {
    match object.get(leaf_key(path)) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| document_field_error(path)),
    }
}

fn document_object<'a>(
    object: &'a Map<String, Value>,
    path: &str,
) -> IngestResult<&'a Map<String, Value>> {
    object
        .get(leaf_key(path))
        .and_then(Value::as_object)
        .ok_or_else(|| document_field_error(path))
}

fn document_array<'a>(object: &'a Map<String, Value>, path: &str) -> IngestResult<&'a Vec<Value>> {
    object
        .get(leaf_key(path))
        .and_then(Value::as_array)
        .ok_or_else(|| document_field_error(path))
}

/// The key to look up from a dotted diagnostic path (`turns[0].text` -> `text`).
///
/// Paths exist so an error names where in the document the problem is; lookup
/// only ever needs the last segment, because the caller already holds that
/// object.
fn leaf_key(path: &str) -> &str {
    path.rsplit('.').next().unwrap_or(path)
}

fn normalize_transcript_object(
    object: &Map<String, Value>,
    line: usize,
) -> IngestResult<NormalizedIngestRecord> {
    let source_record_id =
        required_string_field(object, line, "id", &["id", "message_id", "turn_id"])?.to_owned();
    let text = normalize_space(required_string_field(
        object,
        line,
        "text",
        &["text", "content"],
    )?);
    if text.is_empty() {
        return Err(IngestError::EmptyText {
            source_id: JSONL_TRANSCRIPT_SOURCE_ID,
            line,
        });
    }

    Ok(NormalizedIngestRecord {
        source_record_id,
        thread_id: optional_normalized_string_field(
            object,
            line,
            "thread_id",
            &["thread_id", "conversation_id", "session_id"],
        )?,
        speaker: optional_normalized_string_field(
            object,
            line,
            "speaker",
            &["speaker", "role", "author"],
        )?
        .map(|speaker| speaker.to_ascii_lowercase()),
        occurred_at: optional_u64_field(object, line, "occurred_at", &["occurred_at", "ts"])?,
        text,
    })
}

fn required_string_field<'a>(
    object: &'a Map<String, Value>,
    line: usize,
    canonical: &'static str,
    aliases: &[&str],
) -> IngestResult<&'a str> {
    for alias in aliases {
        if let Some(value) = object.get(*alias) {
            return value.as_str().ok_or(IngestError::InvalidStringField {
                source_id: JSONL_TRANSCRIPT_SOURCE_ID,
                line,
                field: canonical,
            });
        }
    }
    Err(IngestError::MissingField {
        source_id: JSONL_TRANSCRIPT_SOURCE_ID,
        line,
        field: canonical,
    })
}

fn optional_normalized_string_field(
    object: &Map<String, Value>,
    line: usize,
    canonical: &'static str,
    aliases: &[&str],
) -> IngestResult<Option<String>> {
    Ok(optional_string_field(object, line, canonical, aliases)?
        .map(normalize_space)
        .filter(|field| !field.is_empty()))
}

fn optional_string_field<'a>(
    object: &'a Map<String, Value>,
    line: usize,
    canonical: &'static str,
    aliases: &[&str],
) -> IngestResult<Option<&'a str>> {
    for alias in aliases {
        if let Some(value) = object.get(*alias) {
            if value.is_null() {
                continue;
            }
            return value
                .as_str()
                .map(Some)
                .ok_or(IngestError::InvalidStringField {
                    source_id: JSONL_TRANSCRIPT_SOURCE_ID,
                    line,
                    field: canonical,
                });
        }
    }
    Ok(None)
}

fn optional_u64_field(
    object: &Map<String, Value>,
    line: usize,
    canonical: &'static str,
    aliases: &[&str],
) -> IngestResult<Option<u64>> {
    for alias in aliases {
        if let Some(value) = object.get(*alias) {
            if value.is_null() {
                continue;
            }
            return value
                .as_u64()
                .map(Some)
                .ok_or(IngestError::InvalidU64Field {
                    source_id: JSONL_TRANSCRIPT_SOURCE_ID,
                    line,
                    field: canonical,
                });
        }
    }
    Ok(None)
}

fn normalize_space(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut saw_space = false;

    for ch in input.chars() {
        if ch.is_whitespace() {
            saw_space = true;
        } else {
            if saw_space && !out.is_empty() {
                out.push(' ');
            }
            out.push(ch);
            saw_space = false;
        }
    }

    out
}
