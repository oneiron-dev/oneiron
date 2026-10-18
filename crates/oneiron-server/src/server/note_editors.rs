//! Explicit NOTE editor handles, owned by the principal that opened them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oneiron::EntityId;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::sync::documents::EntityDocument;

use crate::byte_line::HeldBytes;

struct HeldEditor {
    _document: Arc<EntityDocument>,
    _bytes: HeldBytes,
}

#[derive(Default)]
pub(crate) struct NoteEditors {
    held: Mutex<HashMap<(EntityId, EntityId), HeldEditor>>,
}

impl NoteEditors {
    /// The retained-memory charge of one binding, beside the document's own
    /// live-document permit. The map keeps ids and handles, never body copies.
    pub(crate) fn binding_bytes() -> usize {
        std::mem::size_of::<((EntityId, EntityId), HeldEditor)>()
    }

    pub(crate) fn bind(
        &self,
        actor: EntityId,
        document: Arc<EntityDocument>,
        bytes: HeldBytes,
    ) -> MemoryResult<String> {
        let binding = EntityId::now();
        self.held
            .lock()
            .map_err(|_| MemoryError::bad_request("NOTE editor registry poisoned"))?
            .insert(
                (actor, binding),
                HeldEditor {
                    _document: document,
                    _bytes: bytes,
                },
            );
        Ok(binding.to_hex())
    }

    pub(crate) fn close(&self, actor: EntityId, binding: &str) -> MemoryResult<bool> {
        let binding = EntityId::from_hex(binding)
            .map_err(|_| MemoryError::bad_request("invalid NOTE editor binding"))?;
        Ok(self
            .held
            .lock()
            .map_err(|_| MemoryError::bad_request("NOTE editor registry poisoned"))?
            .remove(&(actor, binding))
            .is_some())
    }
}
