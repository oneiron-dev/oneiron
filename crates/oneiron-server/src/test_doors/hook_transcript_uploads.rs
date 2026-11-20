//! Door to the server's staged hook transcript uploads
//! (`server::hook_transcript_uploads`, FIX
//! HOOK-TRANSCRIPT-IMPORT-PAST-CARRIER), for the test of their bounds at
//! times the test names, with no wait.

use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::ingest::history::HookTranscriptPartRequest;
use oneiron::memory::MemoryResult;

use crate::server::hook_transcript_uploads::{
    HookTranscriptUploads, Staged, UPLOAD_IDLE, UPLOAD_LIFETIME, UPLOADS_MAX,
};

/// How long an upload is kept with no part taken.
pub const IDLE: Duration = UPLOAD_IDLE;

/// How long an upload is kept after it opened.
pub const LIFETIME: Duration = UPLOAD_LIFETIME;

/// The most uploads open at once.
pub const OPEN_MAX: usize = UPLOADS_MAX;

/// What one part left.
#[derive(Debug, PartialEq, Eq)]
pub enum StagedPart {
    /// The upload stays open, holding this many bytes of text.
    Open(u64),
    /// The last part came: the whole request's JSON text.
    Whole(String),
}

/// A server's uploads, on a clock that starts when they are made.
pub struct Uploads {
    uploads: HookTranscriptUploads,
    start: Instant,
}

impl Uploads {
    /// No upload open, the clock at its start.
    #[must_use]
    pub fn starting_now() -> Self {
        Self {
            uploads: HookTranscriptUploads::default(),
            start: Instant::now(),
        }
    }

    /// Takes `part` for `owner`, `after` the clock's start.
    ///
    /// # Errors
    ///
    /// The uploads' refusal of the part.
    pub fn stage(
        &self,
        after: Duration,
        owner: EntityId,
        part: &HookTranscriptPartRequest,
    ) -> MemoryResult<StagedPart> {
        Ok(
            match self.uploads.stage_at(self.start + after, owner, part)? {
                Staged::Open(staged) => StagedPart::Open(staged),
                Staged::Whole(text) => StagedPart::Whole(text),
            },
        )
    }
}
