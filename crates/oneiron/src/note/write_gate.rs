//! Stage 1 of the NOTE write gate (ARCH-0032 #write-gate): the cheap checks a
//! NOTE write meets before it lands, with no model and no value judgment.
//! The document's size, schema and title rules live with the document; this
//! module holds the floor an agent's NOTE birth meets at the agent-facing
//! doors and the NOTE laws the EntityDoc plane keeps when it writes a NOTE's
//! text.

use super::NoteKind;
use super::documents::invalid;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::{EntityId, Vault};

/// The fewest characters an agent's NOTE is born with: Unicode scalar values
/// of the trimmed markdown (OF-073 stage 1; CALLS "OF-073 auto-note
/// minimum"). A person's or the engine's own NOTE has no floor, and an edit
/// meets none.
pub(crate) const AUTO_NOTE_MIN_CHARS: usize = 16;

/// The floor `kind` sets on an agent's birth. The floor guards extraction, so
/// a kind that never feeds it (Disabled, private strategy) sets none, and a
/// session-sealed kind (the scratchpad) bounds its own lines.
fn auto_note_floor(descriptor: Option<&super::NoteKindDescriptor>) -> Option<usize> {
    use super::{ExtractionDefault, RetentionDefault};
    match descriptor {
        Some(descriptor)
            if descriptor.retention == RetentionDefault::SessionSealed
                || matches!(
                    descriptor.extraction,
                    ExtractionDefault::Disabled | ExtractionDefault::PrivateStrategyOnly
                ) =>
        {
            None
        }
        _ => Some(AUTO_NOTE_MIN_CHARS),
    }
}

impl Vault {
    /// Refuses an agent's NOTE birth whose markdown is under its kind's
    /// floor. The agent-facing doors call it; the engine's own births (a
    /// task's result, a file-drop fallback) do not.
    pub(crate) fn check_auto_note_birth(
        &self,
        kind: &NoteKind,
        actor_class: EdgeActorClass,
        markdown: &str,
    ) -> Result<()> {
        if actor_class != EdgeActorClass::Agent {
            return Ok(());
        }
        let chars = markdown.trim().chars().count();
        if chars >= AUTO_NOTE_MIN_CHARS {
            return Ok(());
        }
        let txn = self.store.env.read_txn()?;
        let descriptor = super::descriptor_in_txn(&self.store, &txn, &kind.as_str())?;
        match auto_note_floor(descriptor.as_ref()) {
            Some(floor) if chars < floor => {
                Err(invalid("an agent's NOTE body is under the minimum length"))
            }
            _ => Ok(()),
        }
    }
}

/// The NOTE laws an EntityDoc-plane commit of `note`'s text keeps: the NOTE
/// body bound, and a sealed NOTE's frozen document. `changes` answers whether
/// the commit moves the document; it is asked only of a sealed NOTE.
pub(crate) fn check_doc_plane_note_commit_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    text: &str,
    changes: impl FnOnce() -> Result<bool>,
) -> Result<()> {
    if text.len() > super::document::MAX_NOTE_BYTES {
        return Err(invalid("NOTE body exceeds bound"));
    }
    if super::lifecycle::note_sealed_in_txn(store, txn, note)? && changes()? {
        return Err(invalid(
            "this NOTE is sealed; its document is frozen and an edit opens a fork",
        ));
    }
    Ok(())
}
