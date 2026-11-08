//! Source metadata for the new meeting landing, not execution authority.

use serde::Serialize;

use crate::ingest::MEETING_TRANSCRIPT_SOURCE_ID;
use crate::{Error, Result};

use super::{BulkImportReceipt, StoredMeetingTranscript};

/// Stored once on the native CONVERSATION. TURNs keep their own source ids
/// and the existing ChildOf edge, without copying the whole batch per turn.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct MeetingImportProvenance {
    pub(crate) stored: StoredMeetingTranscript,
    pub(crate) receipt: BulkImportReceipt,
}

impl MeetingImportProvenance {
    pub(crate) fn conversation_body(&self) -> Result<Vec<u8>> {
        let body = serde_json::json!({
            (crate::memory::IMPORTED_SOURCE_KEY): MEETING_TRANSCRIPT_SOURCE_ID,
            "meeting_import": self,
        });
        rmp_serde::to_vec_named(&body)
            .map_err(|_| Error::InvariantViolation("meeting conversation provenance encode"))
    }

    pub(crate) fn stamp_turn(&self, body: &mut serde_json::Value, ordinal: usize) -> Result<()> {
        let source_record_id = self
            .receipt
            .binding
            .source_record_ids
            .get(ordinal)
            .ok_or(Error::InvariantViolation("meeting source turn ordinal"))?;
        let map = body
            .as_object_mut()
            .ok_or(Error::InvariantViolation("meeting TURN body"))?;
        map.insert(
            crate::memory::IMPORTED_SOURCE_KEY.to_owned(),
            MEETING_TRANSCRIPT_SOURCE_ID.into(),
        );
        map.insert(
            "source_record_id".to_owned(),
            source_record_id.clone().into(),
        );
        map.insert(
            "source_thread_id".to_owned(),
            self.receipt.binding.recording_id.clone().into(),
        );
        Ok(())
    }
}
