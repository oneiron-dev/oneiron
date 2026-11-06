//! Opt-in AG-UI event-dump normalization, without capture or outcome inference.

mod file;
mod observations;
pub use file::{
    AG_UI_FILE_PREDICATE, AgUiFileImport, AgUiFileRead, AgUiFileReadInput, AgUiFileReceipt,
    AgUiFileView,
};
pub use observations::{
    AgUiAppObservation, AgUiCustomMapping, AgUiObservationKind, AgUiRepairLink,
    AgUiRepairLinkStatus,
};

use std::collections::BTreeMap;

use serde_json::Value;

use super::{
    IngestError, IngestResult, IngestSource, NormalizedIngestBatch, NormalizedIngestRecord,
};

pub const AG_UI_SOURCE_ID: &str = "ag-ui";

// ag-ui-protocol/ag-ui@08eae9dc, spec/1.0/schema.json EventType.
const KNOWN_EVENT_TYPES: &[&str] = &[
    "TEXT_MESSAGE_START",
    "TEXT_MESSAGE_CONTENT",
    "TEXT_MESSAGE_END",
    "TEXT_MESSAGE_CHUNK",
    "TOOL_CALL_START",
    "TOOL_CALL_ARGS",
    "TOOL_CALL_END",
    "TOOL_CALL_CHUNK",
    "TOOL_CALL_RESULT",
    "STATE_SNAPSHOT",
    "STATE_DELTA",
    "MESSAGES_SNAPSHOT",
    "ACTIVITY_SNAPSHOT",
    "ACTIVITY_DELTA",
    "RAW",
    "CUSTOM",
    "RUN_STARTED",
    "RUN_FINISHED",
    "RUN_ERROR",
    "STEP_STARTED",
    "STEP_FINISHED",
    "REASONING_START",
    "REASONING_MESSAGE_START",
    "REASONING_MESSAGE_CONTENT",
    "REASONING_MESSAGE_END",
    "REASONING_MESSAGE_CHUNK",
    "REASONING_END",
    "REASONING_ENCRYPTED_VALUE",
    "SUBAGENT_STARTED",
    "SUBAGENT_FINISHED",
    "SUBAGENT_ERROR",
];

/// Direct string-valued protocol links, not resolved entities or authority.
/// Missing links stay missing; no stream state or timestamps supply them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AgUiEventLinks<'a> {
    pub thread_id: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub parent_run_id: Option<&'a str>,
    pub message_id: Option<&'a str>,
    pub tool_call_id: Option<&'a str>,
    pub parent_message_id: Option<&'a str>,
    pub subagent_run_id: Option<&'a str>,
    pub parent_subagent_run_id: Option<&'a str>,
    pub parent_tool_call_id: Option<&'a str>,
}

/// One event as supplied, with import-local bookkeeping separate from wire links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgUiDecodedEvent {
    source_record_id: String,
    line: usize,
    repeat_of: Option<usize>,
    raw: Value,
    raw_text: String,
}

impl AgUiDecodedEvent {
    /// A document fingerprint plus event ordinal, never a protocol event ID.
    pub fn source_record_id(&self) -> &str {
        &self.source_record_id
    }

    /// One-based input line, including blank lines in the count.
    pub fn line(&self) -> usize {
        self.line
    }

    /// First zero-based event ordinal with identical event-line bytes in this input.
    /// A repeated value is not proof of a duplicate delivery or a repair.
    pub fn repeat_of(&self) -> Option<usize> {
        self.repeat_of
    }

    pub fn raw(&self) -> &Value {
        &self.raw
    }

    /// Original event line, including its whitespace but not its line terminator.
    pub fn raw_text(&self) -> &str {
        &self.raw_text
    }

    pub fn event_type(&self) -> Option<&str> {
        self.raw.get("type").and_then(Value::as_str)
    }

    /// Unknown events and unregistered CUSTOM/RAW payloads are opaque evidence.
    pub fn is_opaque(&self) -> bool {
        match self.event_type() {
            None | Some("CUSTOM" | "RAW") => true,
            Some(kind) => !KNOWN_EVENT_TYPES.contains(&kind),
        }
    }

    /// Projects only direct, schema-declared ID fields for a recognized type.
    /// This is not full schema validation, a join, or an outcome classifier.
    pub fn links(&self) -> AgUiEventLinks<'_> {
        let mut links = AgUiEventLinks::default();
        if self.is_opaque() {
            return links;
        }
        let field = |name| self.raw.get(name).and_then(Value::as_str);
        let kind = self.event_type().unwrap_or_default();
        if !matches!(
            kind,
            "RUN_STARTED" | "RUN_FINISHED" | "RUN_ERROR" | "MESSAGES_SNAPSHOT"
        ) {
            links.subagent_run_id = field("subagentRunId");
        }
        match kind {
            "RUN_STARTED" => {
                links.thread_id = field("threadId");
                links.run_id = field("runId");
                links.parent_run_id = field("parentRunId");
            }
            "RUN_FINISHED" => {
                links.thread_id = field("threadId");
                links.run_id = field("runId");
            }
            "TEXT_MESSAGE_START"
            | "TEXT_MESSAGE_CONTENT"
            | "TEXT_MESSAGE_END"
            | "TEXT_MESSAGE_CHUNK"
            | "ACTIVITY_SNAPSHOT"
            | "ACTIVITY_DELTA"
            | "REASONING_START"
            | "REASONING_MESSAGE_START"
            | "REASONING_MESSAGE_CONTENT"
            | "REASONING_MESSAGE_END"
            | "REASONING_MESSAGE_CHUNK"
            | "REASONING_END" => {
                links.message_id = field("messageId");
            }
            "TOOL_CALL_START" | "TOOL_CALL_CHUNK" => {
                links.tool_call_id = field("toolCallId");
                links.parent_message_id = field("parentMessageId");
            }
            "TOOL_CALL_ARGS" | "TOOL_CALL_END" => {
                links.tool_call_id = field("toolCallId");
            }
            "TOOL_CALL_RESULT" => {
                links.message_id = field("messageId");
                links.tool_call_id = field("toolCallId");
            }
            "SUBAGENT_STARTED" => {
                links.parent_subagent_run_id = field("parentSubagentRunId");
                links.parent_tool_call_id = field("parentToolCallId");
                links.parent_message_id = field("parentMessageId");
            }
            _ => {}
        }
        links
    }
}

/// Reads newline-delimited AG-UI event objects. It does not open a live transport.
#[derive(Debug, Clone, Copy, Default)]
pub struct AgUiSource;

impl AgUiSource {
    /// Retains every object, including unknown or incomplete events. Invalid JSON
    /// and non-object lines use the ordinary ingest errors. This is an evidence
    /// decoder, not a complete AG-UI schema or event-order validator.
    pub fn decode(input: &str) -> IngestResult<Vec<AgUiDecodedEvent>> {
        let document = blake3::hash(input.as_bytes());
        let mut seen = BTreeMap::new();
        let mut events = Vec::new();
        for (index, line) in input.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let raw: Value =
                serde_json::from_str(line).map_err(|error| IngestError::InvalidJson {
                    source_id: AG_UI_SOURCE_ID,
                    line: index + 1,
                    message: error.to_string(),
                })?;
            if !raw.is_object() {
                return Err(IngestError::JsonLineNotObject {
                    source_id: AG_UI_SOURCE_ID,
                    line: index + 1,
                });
            }
            let ordinal = events.len();
            let fingerprint = *blake3::hash(line.as_bytes()).as_bytes();
            let repeat_of = seen.get(&fingerprint).copied();
            seen.entry(fingerprint).or_insert(ordinal);
            events.push(AgUiDecodedEvent {
                source_record_id: source_record_id(&document, ordinal),
                line: index + 1,
                repeat_of,
                raw,
                raw_text: line.to_owned(),
            });
        }
        Ok(events)
    }
}

fn source_record_id(document: &blake3::Hash, ordinal: usize) -> String {
    format!("agui:{}:{ordinal}", document.to_hex())
}

impl IngestSource for AgUiSource {
    fn normalize(&self, input: &str) -> IngestResult<NormalizedIngestBatch> {
        let records = Self::decode(input)?
            .into_iter()
            .map(|event| {
                let thread_id = event.links().thread_id.map(str::to_owned);
                NormalizedIngestRecord {
                    source_record_id: event.source_record_id,
                    thread_id,
                    speaker: None,
                    occurred_at: None,
                    text: event.raw_text,
                }
            })
            .collect();
        Ok(NormalizedIngestBatch {
            source_id: AG_UI_SOURCE_ID,
            records,
            claims: Vec::new(),
            entities: Vec::new(),
            note_fallback: None,
        })
    }
}
