//! Staged hook transcript imports (FIX HOOK-TRANSCRIPT-IMPORT-PAST-CARRIER):
//! the parts `vault.imports.hook_transcript_part` takes of one
//! `vault.imports.hook_transcript` request too long for one call over the
//! owner's socket, held in this process's memory until the last part hands
//! the whole request's JSON text to the door that lands it. Nothing reaches
//! the vault before then. Dropping the server drops every upload; a caller
//! whose upload is gone sends the request again under a new id.
//!
//! Bounds: one upload holds at most [`HOOK_TRANSCRIPT_STAGED_MAX_BYTES`] of
//! text, at most [`UPLOADS_MAX`] are open at once, and one that took no part
//! for [`UPLOAD_IDLE`], or opened [`UPLOAD_LIFETIME`] ago, is dropped at the
//! next part any upload takes. Only the owner who opened an upload adds to
//! it or ends it; to anyone else it is not there.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::ingest::history::{HOOK_TRANSCRIPT_STAGED_MAX_BYTES, HookTranscriptPartRequest};
use oneiron::memory::{
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult,
};

/// The most uploads open at once.
pub(crate) const UPLOADS_MAX: usize = 2;

/// How long an upload is kept with no part taken.
pub(crate) const UPLOAD_IDLE: Duration = Duration::from_secs(10 * 60);

/// How long an upload is kept after it opened, however its parts come.
pub(crate) const UPLOAD_LIFETIME: Duration = Duration::from_secs(30 * 60);

/// An upload's id that is not 32 lowercase hex digits.
const ERR_UPLOAD_ID: &str = "a hook transcript upload's id is not 32 lowercase hex digits";

/// A part with no text.
const ERR_EMPTY_PART: &str = "a hook transcript part carries no text";

/// A first part naming an upload that is open.
const ERR_OPEN_TWICE: &str = "a hook transcript upload with this id is open already";

/// A first part while [`UPLOADS_MAX`] uploads are open.
const ERR_BUSY: &str = "the most hook transcript uploads open at once (2) are open";

/// A later part naming no upload this owner holds.
const ERR_NO_UPLOAD: &str =
    "no hook transcript upload with this id is open: it was never opened, it expired, or it ended";

/// A later part that does not start where the upload's text ends.
const ERR_OFFSET: &str =
    "the hook transcript part does not start where the upload's staged text ends";

/// An upload past [`HOOK_TRANSCRIPT_STAGED_MAX_BYTES`].
const ERR_PAST_CAP: &str = "the hook transcript upload passes 64 MiB of request text (HOOK_TRANSCRIPT_STAGED_MAX_BYTES): it was dropped and nothing was imported";

/// What the caller of a lost upload does.
const HINT_RESEND: &str = "Send the request again from its first part under a new upload id.";

/// What the caller does while the uploads open are the most.
const HINT_BUSY: &str =
    "Send it again once an upload in flight lands or expires (10 minutes with no part).";

/// What the caller of a part out of place does.
const HINT_OFFSET: &str = "Send the part that starts where the last answer's staged count ends.";

/// What the caller of a request past the staged cap does.
const HINT_PAST_CAP: &str =
    "Import the session on the machine it ran on: oneiron import <source> <log>.";

/// The uploads open in this server, by id.
#[derive(Default)]
pub(crate) struct HookTranscriptUploads {
    open: Mutex<HashMap<String, StagedUpload>>,
}

/// One open upload.
struct StagedUpload {
    /// The owner who opened it.
    owner: EntityId,
    /// The request's JSON text its parts carried, in order.
    text: String,
    opened: Instant,
    /// When it last took a part.
    touched: Instant,
}

impl StagedUpload {
    /// Whether it is kept at `now`: a part taken within [`UPLOAD_IDLE`],
    /// and opened within [`UPLOAD_LIFETIME`].
    fn live(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.touched) < UPLOAD_IDLE
            && now.saturating_duration_since(self.opened) < UPLOAD_LIFETIME
    }
}

/// What one part leaves.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Staged {
    /// The upload stays open, holding this many bytes of text.
    Open(u64),
    /// The last part came: the whole request's JSON text, and the upload
    /// ended.
    Whole(String),
}

impl HookTranscriptUploads {
    /// Takes `part` for `owner` now ([`Self::stage_at`]).
    ///
    /// # Errors
    ///
    /// As [`Self::stage_at`].
    pub(crate) fn stage(
        &self,
        owner: EntityId,
        part: &HookTranscriptPartRequest,
    ) -> MemoryResult<Staged> {
        self.stage_at(Instant::now(), owner, part)
    }

    /// Takes `part` for `owner` at `now`, after dropping every upload no
    /// longer kept then: offset 0 opens its upload, a later part adds to
    /// the one `owner` opened where its text ends, and the last part ends
    /// the upload, handing back its whole text.
    ///
    /// # Errors
    ///
    /// An id that is not 32 lowercase hex digits or a part with no text; a
    /// first part naming an open upload, or while [`UPLOADS_MAX`] are open;
    /// a later part naming no upload `owner` holds, or not starting where
    /// its text ends; text past [`HOOK_TRANSCRIPT_STAGED_MAX_BYTES`], which
    /// also drops the upload.
    pub(crate) fn stage_at(
        &self,
        now: Instant,
        owner: EntityId,
        part: &HookTranscriptPartRequest,
    ) -> MemoryResult<Staged> {
        if !upload_id(&part.upload) {
            return Err(MemoryError::bad_request(ERR_UPLOAD_ID));
        }
        if part.text.is_empty() {
            return Err(MemoryError::bad_request(ERR_EMPTY_PART));
        }
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        open.retain(|_, upload| upload.live(now));
        if part.offset == 0 {
            if open.contains_key(&part.upload) {
                return Err(invalid_state(ERR_OPEN_TWICE, HINT_RESEND));
            }
            if open.len() >= UPLOADS_MAX {
                return Err(invalid_state(ERR_BUSY, HINT_BUSY));
            }
            if part.text.len() > HOOK_TRANSCRIPT_STAGED_MAX_BYTES {
                return Err(past_cap());
            }
            open.insert(
                part.upload.clone(),
                StagedUpload {
                    owner,
                    text: String::new(),
                    opened: now,
                    touched: now,
                },
            );
        }
        let Some(upload) = open
            .get_mut(&part.upload)
            .filter(|upload| upload.owner == owner)
        else {
            return Err(MemoryError::new(
                MEMORY_CODE_NOT_FOUND,
                ERR_NO_UPLOAD,
                &[HINT_RESEND],
            ));
        };
        if u64::try_from(upload.text.len()).ok() != Some(part.offset) {
            return Err(invalid_state(ERR_OFFSET, HINT_OFFSET));
        }
        if upload.text.len().saturating_add(part.text.len()) > HOOK_TRANSCRIPT_STAGED_MAX_BYTES {
            open.remove(&part.upload);
            return Err(past_cap());
        }
        upload.text.push_str(&part.text);
        upload.touched = now;
        let staged = u64::try_from(upload.text.len()).unwrap_or(u64::MAX);
        if part.last
            && let Some(upload) = open.remove(&part.upload)
        {
            return Ok(Staged::Whole(upload.text));
        }
        Ok(Staged::Open(staged))
    }
}

/// Whether `id` names an upload: 32 lowercase hex digits.
fn upload_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid_state(message: &str, hint: &str) -> MemoryError {
    MemoryError::new(MEMORY_CODE_INVALID_STATE, message, &[hint])
}

fn past_cap() -> MemoryError {
    MemoryError::bad_request_with(ERR_PAST_CAP, &[HINT_PAST_CAP])
}
