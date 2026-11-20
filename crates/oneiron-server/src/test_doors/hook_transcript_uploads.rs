//! Door to the server's staged hook transcript uploads
//! (`server::hook_transcript_uploads`, FIX
//! HOOK-TRANSCRIPT-IMPORT-PAST-CARRIER), for the test of their bounds and
//! of a landing held on its hooks' ask, at times the test names, with no
//! wait.

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

/// What one part left, its landing held on its hooks' ask.
#[derive(Debug, PartialEq, Eq)]
pub enum HeldPart {
    /// The upload stays open, holding this many bytes of text.
    Open(u64),
    /// The last part came, now or again: the whole request's JSON text, and
    /// its call's invocation as 32 hex digits.
    Whole(String, String),
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

    /// Takes `part` for `owner`, `after` the clock's start; a landing it
    /// starts answers at once, which ends the upload.
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
                Staged::Whole(run) => {
                    let text = run.text.to_string();
                    run.answered(false);
                    StagedPart::Whole(text)
                }
            },
        )
    }

    /// [`Self::stage`], a landing it starts held on its hooks' ask, which
    /// keeps the upload for its last part sent again.
    ///
    /// # Errors
    ///
    /// The uploads' refusal of the part.
    pub fn stage_held(
        &self,
        after: Duration,
        owner: EntityId,
        part: &HookTranscriptPartRequest,
    ) -> MemoryResult<HeldPart> {
        Ok(
            match self.uploads.stage_at(self.start + after, owner, part)? {
                Staged::Open(staged) => HeldPart::Open(staged),
                Staged::Whole(run) => {
                    let whole = HeldPart::Whole(run.text.to_string(), run.invocation.to_hex());
                    run.answered(true);
                    whole
                }
            },
        )
    }
}
