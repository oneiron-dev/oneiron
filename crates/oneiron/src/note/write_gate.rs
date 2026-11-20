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

/// The fewest characters an agent's NOTE is born with by default: Unicode
/// scalar values of the trimmed markdown (OF-073 stage 1; CALLS "OF-073
/// auto-note minimum"); the owner's `note.birth.agent_min_chars` sets it. A
/// person's or the engine's own NOTE has no floor, and an edit meets none.
pub(crate) const AUTO_NOTE_MIN_CHARS: usize = 16;

/// The floor `kind` sets on an agent's birth, where the owner's floor is
/// `min_chars`. The floor guards extraction, so a kind that never feeds it
/// (Disabled, private strategy) sets none, and a session-sealed kind (the
/// scratchpad) bounds its own lines.
fn auto_note_floor(
    descriptor: Option<&super::NoteKindDescriptor>,
    min_chars: usize,
) -> Option<usize> {
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
        _ => Some(min_chars),
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
        let txn = self.store.env.read_txn()?;
        self.check_auto_note_birth_in_txn(&txn, kind, actor_class, markdown)
    }

    pub(crate) fn check_auto_note_birth_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        kind: &NoteKind,
        actor_class: EdgeActorClass,
        markdown: &str,
    ) -> Result<()> {
        if actor_class != EdgeActorClass::Agent {
            return Ok(());
        }
        let min_chars = super::setting_keys::AGENT_NOTE_MIN_CHARS
            .read_in_txn(self, txn, &[], None)?
            .value;
        let min_chars = usize::try_from(min_chars).unwrap_or(usize::MAX);
        let chars = markdown.trim().chars().count();
        if chars >= min_chars {
            return Ok(());
        }
        let descriptor = super::descriptor_in_txn(&self.store, txn, &kind.as_str())?;
        match auto_note_floor(descriptor.as_ref(), min_chars) {
            Some(floor) if chars < floor => {
                Err(invalid("an agent's NOTE body is under the minimum length"))
            }
            _ => Ok(()),
        }
    }
}

/// The NOTE law an EntityDoc-plane commit of `note`'s text keeps: a sealed
/// NOTE's frozen document. No body length refuses the commit (rule 5, FIX
/// 10345). `changes` answers whether the commit moves the document; it is
/// asked only of a sealed NOTE.
pub(crate) fn check_doc_plane_note_commit_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
    changes: impl FnOnce() -> Result<bool>,
) -> Result<()> {
    if super::lifecycle::note_sealed_in_txn(store, txn, note)? && changes()? {
        return Err(invalid(
            "this NOTE is sealed; its document is frozen and an edit opens a fork",
        ));
    }
    Ok(())
}
