//! A room's NOTEs where the room holds them (FIX 4280; Engine 10-22: bind,
//! read and close only): the stretch a surface's session names, bound only
//! for a principal verified in it; the room NOTE a ref names there; a live
//! editor's hold on one; and the one predicate that keeps a call serving a
//! room NOTE out of the vault's durable call and hook receipts.
//!
//! The verification is the one OF-063's anonymous check makes
//! ([`Vault::off_record_session_is_anonymous_for`]): the principal's own
//! created stretch, the stretch it entered, or a room on whose roster it is.
//! A session a call names is context, never authority: for a principal not
//! verified in it every NOTE read is the vault's, and its call keeps its
//! receipts.

use std::sync::{Arc, Weak};

use super::registry::{OffRecordSessionEntry, session_entry_state};
use super::session::{OffRecordSession, OffRecordSessionVault};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The rows that serve a room NOTE by its ref (Engine 10-22): no edit, fork,
/// cite or settle row reaches a room NOTE.
const ROOM_NOTE_READS: [&str; 3] = [
    "vault.notes.read",
    "vault.notes.history",
    "vault.notes.editor.bind",
];

/// The row that closes an editor's hold.
const ROOM_NOTE_CLOSE: &str = "vault.notes.editor.close";

/// A NOTE a room holds, and the stretch bound for the reader verified in it.
pub(crate) struct RoomNote<'vault> {
    pub(crate) session: OffRecordSession<'vault>,
    pub(crate) note: EntityId,
}

/// A live NOTE editor's hold on a room NOTE (FIX 4280; Engine 10-22): the
/// NOTE and the room instance it was bound in, held weakly. It holds no
/// document, body copy, writer or read lease, so a room's close never waits
/// on it, and every read of the NOTE takes a fresh snapshot of the room.
/// Once that instance closes the hold is dead; a name taken again names
/// another instance, which this hold never reaches. Only the engine mints
/// one, for a room NOTE its reader is verified in
/// ([`crate::Memory::room_note_editor`]).
#[derive(Clone)]
pub struct RoomNoteHandle {
    note: EntityId,
    instance: Weak<OffRecordSessionEntry>,
}

impl RoomNoteHandle {
    /// The room NOTE this hold names.
    #[must_use]
    pub fn note(&self) -> EntityId {
        self.note
    }

    /// Whether the room instance this hold was bound in still lives.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.instance.upgrade().is_some_and(|entry| {
            session_entry_state(&entry)
                .is_ok_and(|state| !state.gone && !state.overlay_closed && !state.record.closing)
        })
    }
}

impl<'vault> OffRecordSessionVault<'vault> {
    /// The live stretch `session_ref` names, bound for `principal` only when
    /// it is verified in it: its own created stretch, the one it entered, or
    /// a room on whose roster it is now. `None` for no principal, a stretch
    /// it is not verified in, one that is closing, or none at all.
    pub(crate) fn bind_verified(
        &self,
        session_ref: &str,
        principal: Option<EntityId>,
    ) -> Option<OffRecordSession<'vault>> {
        let principal = principal?;
        let session_ref = session_ref.trim();
        let created = self
            .vault
            .store
            .off_record_sessions
            .created_key(session_ref, principal);
        let key = created.as_deref().unwrap_or(session_ref);
        let record = self.vault.off_record_session(key).ok()??;
        if record.room.is_some() {
            return self.bind_for(key, principal).ok();
        }
        if record.entered_by != Some(*principal.as_bytes()) {
            return None;
        }
        self.bind(key).ok()
    }
}

impl OffRecordSession<'_> {
    /// The row `reference` names that this room holds as its own: the
    /// room's alias for it (`s<n>:<hash>`) or its 32 hex digits. `None` for
    /// any other ref, and for a row only base holds.
    ///
    /// # Errors
    ///
    /// Storage errors resolving the alias.
    pub(crate) fn room_row(&self, reference: &str) -> Result<Option<EntityId>> {
        let reference = reference.trim();
        let id = match crate::memory::room_short_ref(reference) {
            Some((alias, hash)) => {
                let view = self.read_view()?;
                let txn = self.vault.store.env.read_txn()?;
                let mut key = alias.as_bytes().to_vec();
                key.push(hash);
                view.short_ids
                    .get(&txn, &key)?
                    .and_then(|raw| <[u8; 16]>::try_from(&raw[..]).ok())
                    .and_then(|bytes| EntityId::from_bytes(bytes).ok())
            }
            None => EntityId::from_hex(reference).ok(),
        };
        match id {
            Some(id) if self.entry.overlay.contains_entity(&id)? => Ok(Some(id)),
            _ => Ok(None),
        }
    }

    /// A live editor's hold on `note`, a NOTE this room holds.
    pub(crate) fn note_handle(&self, note: EntityId) -> RoomNoteHandle {
        RoomNoteHandle {
            note,
            instance: Arc::downgrade(&self.entry),
        }
    }

    /// The scan checks this instance holds (FIX 4280): its NOTE reads' and
    /// births' crossings, which no vault row keeps.
    pub(crate) fn pending_scan_checks(&self) -> &crate::scan_check::PendingScanChecks {
        &self.entry.pending_scan_checks
    }
}

impl Vault {
    /// The room NOTE `note_ref` names in the stretch `session_ref` names,
    /// bound for `principal` ([`OffRecordSessionVault::bind_verified`]);
    /// `None` when it binds none or the room holds no such row.
    ///
    /// # Errors
    ///
    /// Storage errors resolving the room's alias.
    pub(crate) fn room_note(
        &self,
        session_ref: &str,
        principal: Option<EntityId>,
        note_ref: &str,
    ) -> Result<Option<RoomNote<'_>>> {
        let Some(session) = self
            .off_record_session_vault()
            .bind_verified(session_ref, principal)
        else {
            return Ok(None);
        };
        Ok(session
            .room_row(note_ref)?
            .map(|note| RoomNote { session, note }))
    }

    /// Whether a call of row `verb` with `input`, made for `principal` in the
    /// session `session_ref` names, serves a room NOTE, and so keeps no
    /// durable call or hook record (FIX 4280): `vault.notes.read`,
    /// `vault.notes.history` or `vault.notes.editor.bind` of a NOTE that
    /// room holds, `principal` verified in it ([`Self::room_note`]), or
    /// `vault.notes.editor.close` of `held`, a room hold the engine minted
    /// that its host keeps for the caller. Every other call, a vault NOTE's
    /// read inside a session included, keeps its records as it did; a
    /// session name alone never decides, and a storage error keeps them.
    #[must_use]
    pub fn room_note_call_for(
        &self,
        session_ref: Option<&str>,
        principal: Option<EntityId>,
        verb: &str,
        input: Option<&serde_json::Value>,
        held: Option<&RoomNoteHandle>,
    ) -> bool {
        if verb == ROOM_NOTE_CLOSE {
            return held.is_some();
        }
        if !ROOM_NOTE_READS.contains(&verb) {
            return false;
        }
        let note_ref = input
            .and_then(|input| input.get("note_ref"))
            .and_then(serde_json::Value::as_str);
        let (Some(session_ref), Some(note_ref)) = (session_ref, note_ref) else {
            return false;
        };
        self.room_note(session_ref, principal, note_ref)
            .is_ok_and(|room| room.is_some())
    }
}
