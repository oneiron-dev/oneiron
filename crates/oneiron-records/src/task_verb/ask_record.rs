//! Moved from `crates/oneiron/src/task_verb/ask_record.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AskMember {
    pub task: String,
    pub actor: String,
}

pub fn invalid() -> Error {
    Error::Record(RecordError::InvalidTaskBody("tasks.ask.fact"))
}
pub mod attendee_entry;
pub mod link_proof;
