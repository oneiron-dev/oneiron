//! Explicit NOTE editor handles, owned by the principal that opened them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use oneiron::EntityId;
use oneiron::memory::{MemoryError, MemoryResult};
use oneiron::off_record::RoomNoteHandle;
use oneiron::sync::documents::EntityDocument;

use crate::byte_line::HeldBytes;

/// What a binding holds: the vault document's live edit handle, or a room
/// NOTE's hold (FIX 4280; Engine 10-22: bind, read and close only), which
/// keeps nothing of its room alive and never enters the sync registry.
enum HeldNote {
    Canonical { _document: Arc<EntityDocument> },
    Room(RoomNoteHandle),
}

struct HeldEditor {
    note: HeldNote,
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
        self.hold(
            actor,
            HeldNote::Canonical {
                _document: document,
            },
            bytes,
        )
    }

    /// Binds `actor`'s editor to a room NOTE's hold: its reads are the room's,
    /// each on a fresh snapshot, and its close is the one close.
    pub(crate) fn bind_room(
        &self,
        actor: EntityId,
        room: RoomNoteHandle,
        bytes: HeldBytes,
    ) -> MemoryResult<String> {
        self.hold(actor, HeldNote::Room(room), bytes)
    }

    fn hold(&self, actor: EntityId, note: HeldNote, bytes: HeldBytes) -> MemoryResult<String> {
        let binding = EntityId::now();
        self.held
            .lock()
            .map_err(|_| MemoryError::bad_request("NOTE editor registry poisoned"))?
            .insert(
                (actor, binding),
                HeldEditor {
                    note,
                    _bytes: bytes,
                },
            );
        Ok(binding.to_hex())
    }

    /// The room NOTE hold `actor`'s binding `binding` keeps, if it keeps
    /// one: a close of it serves a room NOTE (FIX 4280), which keeps no
    /// durable call or hook record. `None` for a binding that holds a vault
    /// document, another actor's, a malformed id or none.
    pub(crate) fn room_hold(&self, actor: EntityId, binding: &str) -> Option<RoomNoteHandle> {
        let binding = EntityId::from_hex(binding).ok()?;
        match &self.held.lock().ok()?.get(&(actor, binding))?.note {
            HeldNote::Room(room) => Some(room.clone()),
            HeldNote::Canonical { .. } => None,
        }
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
