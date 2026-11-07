//! Agent-facing NOTE verbs; actor identity is bound to the memory facade.
use super::{EntityRefReceipt, Memory, MemoryResult};
use crate::note::{NoteProgramEdit as NoteEdit, NoteProgramEditOutcome as NoteEditOutcome};

impl Memory<'_> {
    /// Creates any registered NOTE kind using its first edit as birth. An
    /// agent's birth meets its kind's minimum length (OF-073 stage 1).
    pub fn create_note(&self, kind: &str, markdown: &str) -> MemoryResult<EntityRefReceipt> {
        self.vault.check_auto_note_birth(
            &self.vault.note_kind(kind)?,
            self.actor_class,
            markdown,
        )?;
        let id = self.vault.create_note(kind, markdown, self.write_actor())?;
        self.entity_ref_receipt_of(&id, crate::registry::ENTITY_TYPE_NOTE)
    }
    pub fn edit_note(&self, note_ref: &str, edit: &NoteEdit) -> MemoryResult<NoteEditOutcome> {
        let id = self.resolve_ref(note_ref)?;
        let actor = self.write_actor();
        let result = self.with_actor_content_write_txn_as(actor, |content| {
            content.update_note(id, |txn, lane| {
                self.vault.edit_note_in_txn(txn, id, edit, actor, lane)
            })
        })?;
        #[cfg(feature = "sync")]
        self.vault.notify_note_document(id);
        Ok(result)
    }
    pub fn create_note_from_entity(
        &self,
        source_ref: &str,
        kind: &str,
    ) -> MemoryResult<EntityRefReceipt> {
        self.create_note_from_entity_for(source_ref, kind, None)
    }

    /// [`Self::create_note_from_entity`], the source read through this
    /// handle's own read lane in the copy's writer (FIX 9953): a source it
    /// does not read is not live, and another author's diary entry is read
    /// through that author's diary gate, stating `reason`, its read logged
    /// with the copy.
    pub fn create_note_from_entity_for(
        &self,
        source_ref: &str,
        kind: &str,
        reason: Option<&str>,
    ) -> MemoryResult<EntityRefReceipt> {
        let source = self.resolve_ref(source_ref)?;
        let lane = self.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
        let id = self.vault.create_from_entity_read_by(
            source,
            kind,
            self.write_actor(),
            &lane,
            reason,
        )?;
        self.entity_ref_receipt_of(&id, crate::registry::ENTITY_TYPE_NOTE)
    }
}
