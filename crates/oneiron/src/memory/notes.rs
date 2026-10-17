//! Agent-facing NOTE verbs; actor identity is bound to the memory facade.
use super::{EntityRefReceipt, Memory, MemoryResult};
use crate::note::{NoteProgramEdit as NoteEdit, NoteProgramEditOutcome as NoteEditOutcome};
use crate::write_envelope::WriteActor;

impl Memory<'_> {
    /// Creates any registered NOTE kind using its first edit as birth. An
    /// agent's birth meets its kind's minimum length (OF-073 stage 1).
    pub fn create_note(&self, kind: &str, markdown: &str) -> MemoryResult<EntityRefReceipt> {
        self.vault
            .check_auto_note_birth(&self.vault.note_kind(kind)?, self.actor_class, markdown)?;
        let id = self.vault.create_note(
            kind,
            markdown,
            WriteActor::new(self.actor, self.actor_class),
        )?;
        self.entity_ref_receipt_of(&id, crate::registry::ENTITY_TYPE_NOTE)
    }
    pub fn edit_note(&self, note_ref: &str, edit: &NoteEdit) -> MemoryResult<NoteEditOutcome> {
        let id = self.resolve_ref(note_ref)?;
        self.vault
            .edit_note(id, edit, WriteActor::new(self.actor, self.actor_class))
    }
    pub fn create_note_from_entity(
        &self,
        source_ref: &str,
        kind: &str,
    ) -> MemoryResult<EntityRefReceipt> {
        let source = self.resolve_ref(source_ref)?;
        let id = self.vault.create_from_entity(
            source,
            kind,
            WriteActor::new(self.actor, self.actor_class),
        )?;
        self.entity_ref_receipt_of(&id, crate::registry::ENTITY_TYPE_NOTE)
    }
}
