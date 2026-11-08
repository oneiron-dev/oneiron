//! Truthful results from the native Imported NOTE fallback.

use crate::EntityId;
use crate::note::ImportedNoteStanding;

/// Shipped NOTE kind for a meeting artifact's normalized fallback text.
pub const MEETING_TRANSCRIPT_NOTE_KIND: &str = "observation";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeetingTranscriptNoteOutcome {
    /// A new native Imported NOTE committed with this import.
    Landed { note_ref: EntityId },
    /// The selected version's NOTE was already imported or removed. Its
    /// native source standing is reported without replacing user edits or
    /// resurrecting an archived or deleted NOTE.
    Retained {
        note_ref: EntityId,
        standing: ImportedNoteStanding,
    },
}
