//! A bound caller's read of the source it copies into a NOTE (FIX 9953). The
//! source, and the row the copy cites, are admitted under the caller's own
//! scoped read; another author's diary entry is admitted under that
//! author's diary gate as a NOTE read admits it (the caller's `diary.read`
//! Grant, its stated reason, the agent's configured review), all in the
//! copy's own writer, where the read's log lands with the copy or not at all.

use super::{invalid, note_core};
use crate::claim::ScopedRead;
use crate::federation::ActorContentTxn;
use crate::memory::{
    DiaryEntryAdmission, DiaryReadGate, DiaryReadHold, MEMORY_CODE_FORBIDDEN, MemoryError,
    MemoryResult,
};
use crate::note::NoteKind;
use crate::registry::ENTITY_TYPE_NOTE;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// The read a bound caller copies a source under.
pub(super) struct SourceRead<'r, 'v> {
    pub(super) reader: &'r ScopedRead<'v>,
    /// The reason the caller stated, for a source a diary gate reads.
    pub(super) reason: Option<&'r str>,
}

/// What a source read admits.
pub(super) enum SourceAdmission {
    /// The source is read; a diary gate, when one judged it, finishes in the
    /// copy's writer.
    Read(Option<DiaryReadGate>),
    /// A diary gate holds the source: the copy is refused with this
    /// refusal, and the gate still finishes, so a review it asks for stands.
    Held(DiaryReadGate, MemoryError),
}

/// Admits `text_source`, the row the copy reads its text from, and
/// `citation`, the row it cites, for `read` in `content`'s writer; a trusted
/// copy (`None`) reads as before. A row the read does not admit answers as
/// one that is not live. A NOTE of the diary kind its copier did not author
/// goes through its author's diary gate; every other source, the copier's
/// own diary included, needs no reason.
pub(super) fn admit_source_in(
    vault: &Vault,
    content: &ActorContentTxn<'_, '_, '_>,
    read: Option<&SourceRead<'_, '_>>,
    actor: WriteActor,
    text_source: EntityId,
    citation: EntityId,
) -> MemoryResult<SourceAdmission> {
    let Some(read) = read else {
        return Ok(SourceAdmission::Read(None));
    };
    let txn = content.read();
    let readable = read
        .reader
        .entities_readable_in_txn(txn, &[text_source, citation])?;
    if readable.contains(&false) {
        return Err(invalid("source is not live").into());
    }
    let is_note = vault
        .entity_header_in_txn(txn, &text_source)?
        .is_some_and(|header| header.entity_type == ENTITY_TYPE_NOTE);
    if !is_note {
        return Ok(SourceAdmission::Read(None));
    }
    let (_, core) = note_core(vault, txn, text_source)?;
    if core.kind != NoteKind::Diary || core.author_ref.is(actor.entity_ref()) {
        return Ok(SourceAdmission::Read(None));
    }
    // An erased diary author is no agent, so no Grant covers the entry: it
    // stays held, as a NOTE read holds it.
    let Some(author) = core.author_ref.id() else {
        return Err(held(DiaryReadHold::NotCovered));
    };
    let mut gate = DiaryReadGate::new(actor, read.reason.unwrap_or_default())?;
    Ok(match gate.admit(vault, txn, author, text_source)? {
        DiaryEntryAdmission::Read => SourceAdmission::Read(Some(gate)),
        DiaryEntryAdmission::Held(hold) => SourceAdmission::Held(gate, held(hold)),
    })
}

/// The refusal of a copy whose source a diary gate holds.
fn held(hold: DiaryReadHold) -> MemoryError {
    let (message, suggestion) = match hold {
        DiaryReadHold::PendingReview => (
            "the source diary entry's agent reviews this reason first",
            "Copy it once the agent answers.",
        ),
        DiaryReadHold::Declined => (
            "the source diary entry's agent declined this reason",
            "State another reason, or copy another source.",
        ),
        DiaryReadHold::NotCovered => (
            "no diary.read Grant of this caller covers the source diary entry",
            "Ask the owner for a diary.read Grant that covers it.",
        ),
    };
    MemoryError::new(MEMORY_CODE_FORBIDDEN, message, &[suggestion])
}
