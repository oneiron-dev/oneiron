//! Generic original-usage export over ctl (LC191311): one stored event's original JSON in framed chunks.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "position", rename_all = "snake_case")]
pub enum UsageExportCursor {
    After {
        key: String,
    },
    InEvent {
        key: String,
        offset: u64,
        digest: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageExportChunk {
    pub event_key: String,
    pub digest: String,
    pub offset: u64,
    pub json: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageExportPage {
    pub chunk: Option<UsageExportChunk>,
    pub next: Option<UsageExportCursor>,
}
