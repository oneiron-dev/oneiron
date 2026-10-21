//! Typed reads of a residence open, using the named connection's own vault.

use crate::authority::VerifiedSlip;
use crate::memory::MemoryResult;
use crate::note::{NoteReadSpan, NoteReadView};
use crate::settings::ReadDestination;
use crate::sync::{OpenedItem, TransportError};
use crate::{EntityId, WriteActor};

impl super::SyncConnection {
    /// Whether an open can use bytes this machine already holds, without
    /// contacting its home or opening any other item.
    pub fn item_is_local(&self, item: EntityId) -> Result<bool, TransportError> {
        Ok(self.thin_item(item)?.is_some()
            || self
                .manager
                .vault()
                .entity_exists(&item)
                .map_err(|error| TransportError::Storage(error.to_string()))?)
    }

    /// Projects only the item the owner's residence door already opened.
    /// The canonical read keeps the caller's proof and proved destination.
    pub fn opened_note_view(
        &self,
        opened: &OpenedItem,
        actor: WriteActor,
        proof: Option<&VerifiedSlip>,
        destination: &ReadDestination,
        reason: Option<&str>,
        spans: &[NoteReadSpan],
    ) -> MemoryResult<Option<NoteReadView>> {
        crate::note::opened_note_view(
            self.manager.vault(),
            opened,
            actor,
            proof,
            destination,
            reason,
            spans,
        )
    }
}
