//! A room NOTE's reads (FIX 4280; Engine 10-22: bind, read and close only):
//! `vault.notes.read`, `vault.notes.history` and the editor's bind read a
//! NOTE an off-record room holds in that room, for a caller its surface
//! binds the room for and who is verified in it, on the key the surface
//! reads under. Content is the room's overlay over base; kind policy, grants
//! and the diary gate stay the vault's. Every other NOTE read, a vault NOTE
//! read inside a bound session included, is the vault's own, unchanged.
//!
//! The room and the NOTE resolve before the read's snapshot opens: inside
//! it only `_in_txn` reads run, on that snapshot (LMDB holds one read slot
//! per thread).

use super::documents::NoteDocument;
use super::reads::{NoteAccessRequest, NoteReadAt};
use crate::EntityId;
use crate::claim::{ClaimReadStatus, PointRead, ScopedReadActorKey, ScopedReadResult};
use crate::memory::{Memory, MemoryResult};
use crate::off_record::{OffRecordSession, RoomNote, RoomNoteHandle};
use crate::store::SessionStoreView;
use serde::Serialize;

impl Memory<'_> {
    /// The NOTE `note_ref` names in the off-record room this surface binds,
    /// when its principal is verified in that room and the room holds the
    /// row; `None` otherwise, and such a read is the vault's.
    ///
    /// # Errors
    ///
    /// Storage errors resolving the room's alias.
    pub(crate) fn room_note(&self, note_ref: &str) -> MemoryResult<Option<RoomNote<'_>>> {
        let Some((session_ref, principal)) = self.off_record_binding() else {
            return Ok(None);
        };
        Ok(self.vault().room_note(session_ref, principal, note_ref)?)
    }

    /// A live editor's hold on the room NOTE `note_ref` names for this
    /// surface ([`Self::room_note`]), or `None` when it names none: a host
    /// binds the editor to it rather than to a vault document, and the hold
    /// keeps nothing of the room alive.
    ///
    /// # Errors
    ///
    /// As [`Self::room_note`].
    pub fn room_note_editor(&self, note_ref: &str) -> MemoryResult<Option<RoomNoteHandle>> {
        Ok(self
            .room_note(note_ref)?
            .map(|room| room.session.note_handle(room.note)))
    }

    /// Whether this surface's call of row `verb` with `input` serves a room
    /// NOTE, and so keeps no durable call or hook record (FIX 4280):
    /// [`crate::Vault::room_note_call_for`] for the session this surface
    /// binds and the principal it binds it for. `held` is the room hold an
    /// editor's close names, as its host keeps it.
    #[must_use]
    pub(crate) fn room_note_call(
        &self,
        verb: &str,
        input: &serde_json::Value,
        held: Option<&RoomNoteHandle>,
    ) -> bool {
        let (session_ref, principal) = match self.off_record_binding() {
            Some((session_ref, principal)) => (Some(session_ref), principal),
            None => (None, None),
        };
        self.vault()
            .room_note_call_for(session_ref, principal, verb, Some(input), held)
    }

    /// [`Self::project_note_read`] of `room`'s NOTE, in the room, under this
    /// surface's read key.
    pub(super) fn project_room_note_read<T: Serialize + serde::de::DeserializeOwned>(
        &self,
        room: &RoomNote<'_>,
        input: &NoteAccessRequest,
        project: impl FnOnce(&heed::RoTxn<'_>, NoteDocument) -> MemoryResult<T>,
    ) -> MemoryResult<ScopedReadResult<Option<T>>> {
        let key = self.read_key()?;
        let view = room.session.read_view()?;
        self.project_note_read_in_room(&room.session, &view, key, room.note, input, project)
    }

    /// A NOTE read of `note`, a row `session`'s room holds, through `view`,
    /// one view of the room, under `key`: the same admission, projection and
    /// diary gate as the vault's NOTE read, its content the room's. Its size
    /// measurements wait with the room, never with the vault. A code run
    /// bound to the room reads a room NOTE through here (L11-B's opt-in).
    pub(crate) fn project_note_read_in_room<T: Serialize + serde::de::DeserializeOwned>(
        &self,
        session: &OffRecordSession<'_>,
        view: &SessionStoreView<'_>,
        key: ScopedReadActorKey,
        note: EntityId,
        input: &NoteAccessRequest,
        project: impl FnOnce(&heed::RoTxn<'_>, NoteDocument) -> MemoryResult<T>,
    ) -> MemoryResult<ScopedReadResult<Option<T>>> {
        let lane = self
            .vault()
            .scoped_read_in_session(key, view)
            .with_claim_status(ClaimReadStatus::Recorded);
        let store = lane.store_read();
        let at = NoteReadAt {
            note,
            store: &store,
            pending: session.pending_scan_checks(),
        };
        let result = lane.read_projected(&[PointRead::id(note)], None, |txn, rows| {
            self.project_admitted_note(txn, rows, &at, input, project)
        })?;
        self.finish_note_read(result)
    }
}
