//! Shared pre-semantic import shape. Source data cannot supply trust or approval.
use super::{IngestResult, NormalizedIngestBatch, NormalizedIngestRecord};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParsedMessage {
    pub message_id: String,
    pub conversation_id: String,
    pub platform_source: String,
    pub role: String,
    pub content: String,
    pub speaker_id: Option<String>,
    /// None means the source did not record a timestamp; never invent one.
    pub occurred_at: Option<u64>,
    pub recorded_at: u64,
    pub character_card: Option<Value>,
    pub is_group_chat: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedImport {
    pub messages: Vec<ParsedMessage>,
    pub normalized: NormalizedIngestBatch,
    /// Resource URIs are resolution requests, not trusted identity assignments.
    pub resource_uris: Vec<String>,
}

impl ParsedImport {
    pub(super) fn from_batch(batch: NormalizedIngestBatch, recorded_at: u64) -> IngestResult<Self> {
        let messages = batch
            .records
            .iter()
            .map(|record| ParsedMessage {
                message_id: record.source_record_id.clone(),
                conversation_id: record.thread_id.clone().unwrap_or_default(),
                platform_source: batch.source_id.to_owned(),
                role: record.speaker.clone().unwrap_or_else(|| "system".into()),
                content: record.text.clone(),
                speaker_id: record.speaker.clone(),
                occurred_at: record.occurred_at,
                recorded_at,
                character_card: None,
                is_group_chat: false,
            })
            .collect();
        Ok(Self {
            messages,
            normalized: batch,
            resource_uris: Vec::new(),
        })
    }
}

impl ParsedMessage {
    pub(super) fn record(&self) -> NormalizedIngestRecord {
        NormalizedIngestRecord {
            source_record_id: self.message_id.clone(),
            thread_id: Some(self.conversation_id.clone()),
            speaker: Some(self.role.clone()),
            occurred_at: self.occurred_at,
            text: self.content.clone(),
        }
    }
}
