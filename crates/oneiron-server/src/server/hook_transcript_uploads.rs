//! Staged hook transcript imports (FIX HOOK-TRANSCRIPT-IMPORT-PAST-CARRIER):
//! the parts `vault.imports.hook_transcript_part` takes of one
//! `vault.imports.hook_transcript` request too long for one call over the
//! owner's socket, held in this process's memory until the last part hands
//! the whole request's JSON text to that verb's own call. Nothing reaches
//! the vault before then, and no part reaches a verb hook: the part row is
//! transport only, and the whole request's call crosses its verb's hooks
//! once. Dropping the server drops every upload; a caller whose upload is
//! gone sends the request again under a new id.
//!
//! The whole request's call runs under one invocation the upload mints
//! when its last part first comes ([`Landing`]). A call its hooks hold on an
//! ask keeps the upload, so the last part sent again runs that same call
//! again: its hooks find their ask, and the request lands at most once. Any
//! other answer ends the upload.
//!
//! Bounds: one upload holds at most [`HOOK_TRANSCRIPT_STAGED_MAX_BYTES`] of
//! text, at most [`UPLOADS_MAX`] are open at once, and one that took no part
//! for [`UPLOAD_IDLE`], or opened [`UPLOAD_LIFETIME`] ago, is dropped at the
//! next part any upload takes. An upload is its owner's: it is named by the
//! owner and its id, so only the owner who opened it adds to it or ends it,
//! and to anyone else it is not there, even when they open one of that id.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use oneiron::EntityId;
use oneiron::ingest::history::{HOOK_TRANSCRIPT_STAGED_MAX_BYTES, HookTranscriptPartRequest};
use oneiron::memory::{
    MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND, MemoryError, MemoryResult,
};
use oneiron::runtime_hooks::InvocationId;

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

/// A part other than its last, as it came, naming an upload whose last part
/// came.
const ERR_LANDING: &str = "the hook transcript upload's last part came: only that part, sent again as it was, runs its landing again";

/// The last part sent again while its landing runs.
const ERR_LANDING_RUNS: &str = "the hook transcript upload's landing is running";

/// An upload past [`HOOK_TRANSCRIPT_STAGED_MAX_BYTES`].
const ERR_PAST_CAP: &str = "the hook transcript upload passes 64 MiB of request text (HOOK_TRANSCRIPT_STAGED_MAX_BYTES): it was dropped and nothing was imported";

/// What the caller of a lost upload does.
const HINT_RESEND: &str = "Send the request again from its first part under a new upload id.";

/// What the caller does while the uploads open are the most.
const HINT_BUSY: &str =
    "Send it again once an upload in flight lands or expires (10 minutes with no part).";

/// What the caller of a part out of place does.
const HINT_OFFSET: &str = "Send the part that starts where the last answer's staged count ends.";

/// What the caller of a part after the last does.
const HINT_LANDING: &str = "Send the last part again as it was sent, or send the request again from its first part under a new upload id.";

/// What the caller of a landing that runs does.
const HINT_LANDING_RUNS: &str = "Send the last part again once its landing answers.";

/// What the caller of a request past the staged cap does.
const HINT_PAST_CAP: &str =
    "Import the session on the machine it ran on: oneiron import <source> <log>.";

/// The uploads open in this server, by the owner who opened each and its
/// id.
#[derive(Default)]
pub(crate) struct HookTranscriptUploads {
    open: Mutex<HashMap<(EntityId, String), StagedUpload>>,
}

/// One open upload.
struct StagedUpload {
    /// The request's JSON text its parts carried, in order, until its last
    /// part came.
    text: String,
    opened: Instant,
    /// When it last took a part.
    touched: Instant,
    /// Once its last part came: the whole request's landing.
    landing: Option<Landing>,
}

/// An upload whose last part came: the whole request, and the one call of
/// `vault.imports.hook_transcript` that lands it.
struct Landing {
    /// The request's whole JSON text.
    text: Arc<str>,
    /// Where the last part starts: only that part, sent again as it was,
    /// runs the landing again.
    last_offset: u64,
    /// The call's invocation, minted once for the upload: every run of the
    /// landing names it, so the call's hooks find the ask an earlier run
    /// left, and a call that ran is not run again.
    invocation: InvocationId,
    /// Whether a run of the landing has not answered yet: a second run
    /// would enter the same invocation inside the first, where its hooks
    /// pass through.
    running: bool,
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
pub(crate) enum Staged<'a> {
    /// The upload stays open, holding this many bytes of text.
    Open(u64),
    /// The last part came, now or again: the whole request's landing, to
    /// run once and answer ([`LandingRun::answered`]).
    Whole(LandingRun<'a>),
}

/// One run of an upload's landing: the whole request's JSON text, the bytes
/// it holds and the invocation its call runs under. The upload stays until
/// the run answers ([`Self::answered`]); a run dropped unanswered keeps it,
/// for its last part sent again.
pub(crate) struct LandingRun<'a> {
    uploads: &'a HookTranscriptUploads,
    key: (EntityId, String),
    /// The request's whole JSON text.
    pub(crate) text: Arc<str>,
    /// The call's invocation.
    pub(crate) invocation: InvocationId,
    answered: bool,
}

impl LandingRun<'_> {
    /// The bytes of the request's JSON text the upload held.
    pub(crate) fn staged(&self) -> u64 {
        u64::try_from(self.text.len()).unwrap_or(u64::MAX)
    }

    /// How the call answered: held on its hooks' ask (`held`), which keeps
    /// the upload for its last part sent again, or anything else, which
    /// ends it.
    pub(crate) fn answered(mut self, held: bool) {
        self.answered = true;
        self.uploads
            .landing_answered(&self.key, self.invocation, held);
    }
}

impl Drop for LandingRun<'_> {
    /// A run dropped before it answered (its caller went away) keeps the
    /// upload, as a held one does.
    fn drop(&mut self) {
        if !self.answered {
            self.uploads
                .landing_answered(&self.key, self.invocation, true);
        }
    }
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
    ) -> MemoryResult<Staged<'_>> {
        self.stage_at(Instant::now(), owner, part)
    }

    /// Takes `part` for `owner` at `now`, after dropping every upload no
    /// longer kept then: offset 0 opens its upload, a later part adds to
    /// the one `owner` opened where its text ends, and the last part starts
    /// the upload's landing, handing back the whole request. Once the last
    /// part came, only that part, sent again as it was, runs the landing
    /// again, under the same invocation.
    ///
    /// # Errors
    ///
    /// An id that is not 32 lowercase hex digits or a part with no text; a
    /// first part naming an upload `owner` holds open, or while
    /// [`UPLOADS_MAX`] are open;
    /// a later part naming no upload `owner` holds, or not starting where
    /// its text ends; text past [`HOOK_TRANSCRIPT_STAGED_MAX_BYTES`], which
    /// also drops the upload; after the last part, any other part, or the
    /// last again while its landing runs.
    pub(crate) fn stage_at(
        &self,
        now: Instant,
        owner: EntityId,
        part: &HookTranscriptPartRequest,
    ) -> MemoryResult<Staged<'_>> {
        if !upload_id(&part.upload) {
            return Err(MemoryError::bad_request(ERR_UPLOAD_ID));
        }
        if part.text.is_empty() {
            return Err(MemoryError::bad_request(ERR_EMPTY_PART));
        }
        let key = (owner, part.upload.clone());
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        open.retain(|_, upload| upload.live(now));
        if part.offset == 0 {
            match open.get(&key) {
                // A landing's last part sent again is judged below.
                Some(upload) if upload.landing.is_some() => {}
                Some(_) => return Err(invalid_state(ERR_OPEN_TWICE, HINT_RESEND)),
                None => {
                    if open.len() >= UPLOADS_MAX {
                        return Err(invalid_state(ERR_BUSY, HINT_BUSY));
                    }
                    if part.text.len() > HOOK_TRANSCRIPT_STAGED_MAX_BYTES {
                        return Err(past_cap());
                    }
                    open.insert(
                        key.clone(),
                        StagedUpload {
                            text: String::new(),
                            opened: now,
                            touched: now,
                            landing: None,
                        },
                    );
                }
            }
        }
        let Some(upload) = open.get_mut(&key) else {
            return Err(MemoryError::new(
                MEMORY_CODE_NOT_FOUND,
                ERR_NO_UPLOAD,
                &[HINT_RESEND],
            ));
        };
        if let Some(landing) = upload.landing.as_mut() {
            let again = part.last
                && part.offset == landing.last_offset
                && usize::try_from(part.offset)
                    .ok()
                    .and_then(|offset| landing.text.get(offset..))
                    == Some(part.text.as_str());
            if !again {
                return Err(invalid_state(ERR_LANDING, HINT_LANDING));
            }
            if landing.running {
                return Err(invalid_state(ERR_LANDING_RUNS, HINT_LANDING_RUNS));
            }
            landing.running = true;
            upload.touched = now;
            let (text, invocation) = (Arc::clone(&landing.text), landing.invocation);
            return Ok(Staged::Whole(self.run(key, text, invocation)));
        }
        if u64::try_from(upload.text.len()).ok() != Some(part.offset) {
            return Err(invalid_state(ERR_OFFSET, HINT_OFFSET));
        }
        if upload.text.len().saturating_add(part.text.len()) > HOOK_TRANSCRIPT_STAGED_MAX_BYTES {
            open.remove(&key);
            return Err(past_cap());
        }
        upload.text.push_str(&part.text);
        upload.touched = now;
        if !part.last {
            return Ok(Staged::Open(
                u64::try_from(upload.text.len()).unwrap_or(u64::MAX),
            ));
        }
        let text: Arc<str> = Arc::from(std::mem::take(&mut upload.text));
        let invocation = InvocationId::mint();
        upload.landing = Some(Landing {
            text: Arc::clone(&text),
            last_offset: part.offset,
            invocation,
            running: true,
        });
        Ok(Staged::Whole(self.run(key, text, invocation)))
    }

    /// One run of the landing of the upload `key` names.
    fn run(
        &self,
        key: (EntityId, String),
        text: Arc<str>,
        invocation: InvocationId,
    ) -> LandingRun<'_> {
        LandingRun {
            uploads: self,
            key,
            text,
            invocation,
            answered: false,
        }
    }

    /// A run of the landing under `invocation` of the upload `key` names
    /// answered: `held` keeps the upload, for its last part sent again;
    /// any other answer ends it. An upload of that name that is not the
    /// run's own (it expired, and another opened) is left alone.
    fn landing_answered(&self, key: &(EntityId, String), invocation: InvocationId, held: bool) {
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(upload) = open.get_mut(key) else {
            return;
        };
        let Some(landing) = upload.landing.as_mut() else {
            return;
        };
        if landing.invocation != invocation {
            return;
        }
        if held {
            landing.running = false;
            upload.touched = Instant::now();
        } else {
            open.remove(key);
        }
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
