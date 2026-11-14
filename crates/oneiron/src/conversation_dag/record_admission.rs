//! Who reads a conversation's DAG records (FIX 8153, ARCH-0006a rule 2,
//! Engine 10-22).
//!
//! The record listing releases a conversation's HEAD, root and main line,
//! topology no row-by-row read bounds, so the conversation itself is
//! admitted first, under the caller's own credential-bound read: the lane
//! must read the conversation's row, and the reader must see it as its own
//! conversation list sees it. A group, channel or mirror shows only to a
//! member or on a live grant that opens its relationship; absent from the
//! reader's list is absent here. The vault owner reads every room.
//!
//! The same rule decides every door that serves a room's structure: its
//! row (roster, title, pins), its turns, its thread and DAG shape (L9-52,
//! Engine RULING L9-52-ROOM-STRUCTURE = A, 14 Nov 14:29). A TURN is judged
//! as its room is.

use std::collections::HashMap;

use heed::RoTxn;

use crate::claim::ScopedRead;
use crate::edge::EdgeActorClass;
use crate::error::{ClaimError, Error, Result};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

impl Vault {
    /// Whether `read`'s caller may read `conversation`'s DAG records: the
    /// lane reads its row, and its key is the vault owner's, or a narrower
    /// owner credential while he is still the bound owner, or its reader
    /// sees the conversation in its own list. An id that names no
    /// conversation is left to the listing, which refuses it as it does
    /// today.
    ///
    /// # Errors
    ///
    /// Storage errors, and the list's owner check that does not resolve
    /// (a broken authority root), as the read lane reports it.
    pub fn dag_records_admitted(
        &self,
        read: &ScopedRead<'_>,
        conversation: &EntityId,
    ) -> Result<bool> {
        // The lane's read takes its own snapshot, before this one opens.
        if !read.is_entity_readable(conversation)? {
            return Ok(false);
        }
        let txn = self.store.env.read_txn()?;
        if !is_live_conversation_in(&self.store, &txn, conversation)? {
            return Ok(true);
        }
        self.room_admits_in(read, &txn, conversation, conversation)
    }

    /// Whether `read`'s caller may read the room structure the row `id`
    /// holds, past the lane's own read of that row, which is the door's and
    /// is judged before this (L9-52). A live CONVERSATION is admitted as
    /// [`Self::dag_records_admitted`] admits it. A live TURN is admitted as
    /// its one room is, and the lane must read that room's row too. Any other
    /// row, and a TURN that names no live conversation, is left to the lane.
    /// A door answers a refused row as a missing one.
    ///
    /// # Errors
    ///
    /// Storage errors, and the list's owner check that does not resolve.
    pub fn room_structure_admitted(&self, read: &ScopedRead<'_>, id: &EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        self.room_structure_admitted_in_txn(read, &txn, id)
    }

    /// [`Self::room_structure_admitted`] in `txn`.
    pub(crate) fn room_structure_admitted_in_txn(
        &self,
        read: &ScopedRead<'_>,
        txn: &RoTxn<'_>,
        id: &EntityId,
    ) -> Result<bool> {
        match structure_room_in(&self.store, txn, id)? {
            Some(room) => self.room_admits_in(read, txn, id, &room),
            None => Ok(true),
        }
    }

    /// The ids of `ids` that [`Self::room_structure_admitted`] admits, in
    /// their order, judged in one snapshot with each room judged once. The
    /// lane's own read of each id is the door's, judged before this.
    ///
    /// # Errors
    ///
    /// As [`Self::room_structure_admitted`].
    pub fn room_structure_admitted_ids(
        &self,
        read: &ScopedRead<'_>,
        ids: Vec<EntityId>,
    ) -> Result<Vec<EntityId>> {
        let txn = self.store.env.read_txn()?;
        let mut rooms = HashMap::new();
        let mut kept = Vec::with_capacity(ids.len());
        for id in ids {
            let admitted = match structure_room_in(&self.store, &txn, &id)? {
                None => true,
                Some(room) => match rooms.get(&room) {
                    Some(admitted) => *admitted,
                    None => {
                        let admitted = self.room_admits_in(read, &txn, &id, &room)?;
                        rooms.insert(room, admitted);
                        admitted
                    }
                },
            };
            if admitted {
                kept.push(id);
            }
        }
        Ok(kept)
    }

    /// Whether the live conversation `room` admits `read`'s caller to the
    /// row `id`, the room itself or one of its turns: the vault owner, and
    /// a narrower owner credential while he is still the bound owner, read
    /// every room; anyone else needs the lane to read the room's row, and a
    /// reader that sees the room in its own conversation list.
    fn room_admits_in(
        &self,
        read: &ScopedRead<'_>,
        txn: &RoTxn<'_>,
        id: &EntityId,
        room: &EntityId,
    ) -> Result<bool> {
        let key = read.actor_key();
        if key.reads_as_vault_owner() || key.facets_owner_exempt_in(self, txn)? {
            return Ok(true);
        }
        if room != id && !read.is_entity_readable_in(txn, room)? {
            return Ok(false);
        }
        let reader = key
            .authenticated_person()
            .zip(reader_class(key.actor_class()));
        self.conversation_list_sees_in(txn, *room, reader)
            .map_err(|refusal| Error::Claim(ClaimError::ScopedReadOwnerNotLive(Box::new(refusal))))
    }
}

/// The room whose structure the row `id` holds: a live CONVERSATION's own
/// id, or the live conversation a live TURN was witnessed into. `None` for
/// any other row, and for a TURN that names no single live conversation.
fn structure_room_in(
    store: &impl crate::store::ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    match live_entity_row_in_txn(store, txn, id)? {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_CONVERSATION,
            ..
        } => Ok(Some(*id)),
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            ..
        } => match super::graph::named_room(store, txn, id)? {
            Ok(room) if is_live_conversation_in(store, txn, &room)? => Ok(Some(room)),
            _ => Ok(None),
        },
        _ => Ok(None),
    }
}

/// Whether `id` names a live CONVERSATION row in `txn`.
fn is_live_conversation_in(
    store: &impl crate::store::ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(matches!(
        live_entity_row_in_txn(store, txn, id)?,
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_CONVERSATION,
            ..
        }
    ))
}

impl Vault {
    /// The roster of `conversation` at `at`, as `read`'s caller may read it
    /// (FIX 8209): `None` when it may not read the room. The lane must read
    /// the room's row, as [`Self::dag_records_admitted`] asks. The vault
    /// owner, and a narrower owner credential while he is still the bound
    /// owner, read every roster; so does a reader that sees the room in its
    /// own conversation list, a member now or one on a live grant that opens
    /// the room's relationship. A reader that sat in the room at `at` reads
    /// that roster, its own history. The roster and every check but the
    /// lane's own read are judged in one snapshot.
    ///
    /// # Errors
    ///
    /// Storage errors; an id that names no conversation, as the ledger read
    /// refuses it; the list's owner check that does not resolve.
    pub fn room_roster_admitted(
        &self,
        read: &ScopedRead<'_>,
        conversation: &EntityId,
        at: u64,
    ) -> Result<Option<Vec<EntityId>>> {
        // The lane's read takes its own snapshot, before this one opens.
        if !read.is_entity_readable(conversation)? {
            return Ok(None);
        }
        let txn = self.store.env.read_txn()?;
        let roster = self.membership_at_in_txn(&txn, *conversation, at)?;
        let key = read.actor_key();
        if key.reads_as_vault_owner() || key.facets_owner_exempt_in(self, &txn)? {
            return Ok(Some(roster));
        }
        let reader = key
            .authenticated_person()
            .zip(reader_class(key.actor_class()));
        if reader.is_some_and(|(person, _)| roster.contains(&person)) {
            return Ok(Some(roster));
        }
        let sees = self
            .conversation_list_sees_in(&txn, *conversation, reader)
            .map_err(|refusal| {
                Error::Claim(ClaimError::ScopedReadOwnerNotLive(Box::new(refusal)))
            })?;
        Ok(sees.then_some(roster))
    }
}

/// The class a read key's caller reads as, as the server binds a
/// credential's: one that declares none is a person's.
fn reader_class(class: Option<&str>) -> Option<EdgeActorClass> {
    match class {
        None | Some("human") => Some(EdgeActorClass::Human),
        Some("agent") => Some(EdgeActorClass::Agent),
        Some("system") => Some(EdgeActorClass::System),
        Some(_) => None,
    }
}
