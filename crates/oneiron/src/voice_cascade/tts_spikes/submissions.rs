//! One incremental Text's unsent rest (FIX 10213).
//! Entry: resume_text_submission.
//!
//! An incremental Text past [`super::MAX_TEXT_BYTES`] goes as several
//! submissions, in order. When the queue refuses one part-way, what it
//! already took stays taken and the rest is kept exactly: the next Text,
//! Flush or End sends it first, and a retry of the same Text resumes it
//! rather than sending its taken prefix again.

use super::{Adapter, GenerationEpoch, MAX_TEXT_BYTES, ProviderOperation, TransportQueue};
use crate::error::Result;
use crate::voice_cascade::speakable;

/// A Text the queue took part of: the whole text and how many of its bytes
/// the queue took. Only a Text with some of it taken is kept; one refused
/// at its first piece admitted nothing, and its caller holds it.
pub(super) struct PendingTextSubmission {
    text: String,
    cursor: usize,
}

impl PendingTextSubmission {
    /// `text`, none of it sent yet.
    pub(super) fn new(text: String) -> Self {
        Self { text, cursor: 0 }
    }

    /// Whether `text` is this one sent again: a retry, which resumes.
    pub(super) fn is_text(&self, text: &str) -> bool {
        self.text == text
    }

    /// Whether the queue took any of it.
    pub(super) fn started(&self) -> bool {
        self.cursor > 0
    }
}

/// Sends what `pending` has not sent, piece by piece, each at most
/// `max_bytes` and cut where speech allows. `send` submits one piece and
/// answers whether the queue took it; the cursor moves past a piece only
/// once it did, so a refusal leaves exactly the unsent rest. Ends `Ok` once
/// all of it went.
pub(super) fn resume_text_submission(
    pending: &mut PendingTextSubmission,
    max_bytes: usize,
    mut send: impl FnMut(String) -> Result<()>,
) -> Result<()> {
    while pending.cursor < pending.text.len() {
        let rest = &pending.text[pending.cursor..];
        let len = speakable::first_piece(rest, max_bytes);
        send(rest[..len].to_owned())?;
        pending.cursor += len;
    }
    Ok(())
}

impl<Q: TransportQueue> Adapter<Q> {
    /// Sends an incremental Text, every byte in order, as several
    /// submissions past [`MAX_TEXT_BYTES`]. What an earlier refused send
    /// left goes first; a retry of that same Text only resumes it. Each
    /// piece the queue takes counts as admitted text before its audio can
    /// come back (FIX 10213).
    pub(super) fn submit_text(&mut self, generation: GenerationEpoch, text: String) -> Result<()> {
        let retry = self
            .pending_text
            .as_ref()
            .is_some_and(|pending| pending.is_text(&text));
        self.resume_text(generation)?;
        if retry {
            return Ok(());
        }
        self.pending_text = Some(PendingTextSubmission::new(text));
        self.resume_text(generation)
    }

    /// Sends the kept rest of a Text the queue took part of. A refusal
    /// keeps what is still unsent; a Text refused at its first piece
    /// admitted nothing and is not kept.
    pub(super) fn resume_text(&mut self, generation: GenerationEpoch) -> Result<()> {
        let Some(mut pending) = self.pending_text.take() else {
            return Ok(());
        };
        let sent = resume_text_submission(&mut pending, MAX_TEXT_BYTES, |piece| {
            let bytes = piece.len();
            self.send(generation, ProviderOperation::Text(piece))?;
            self.text_bytes = self.text_bytes.saturating_add(bytes);
            self.dirty = true;
            Ok(())
        });
        if sent.is_err() && pending.started() {
            self.pending_text = Some(pending);
        }
        sent
    }
}
