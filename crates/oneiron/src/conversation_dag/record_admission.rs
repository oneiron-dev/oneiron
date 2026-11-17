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
//! as its room is. A Direct conversation is no room (ARCH-0006a rule 2),
//! so its rows and turns read by the lane alone.

use std::cell::RefCell;
use std::collections::HashMap;

use heed::RoTxn;

use crate::claim::ScopedRead;
use crate::conversation::{ConversationBody, ConversationKind};
use crate::edge::EdgeActorClass;
use crate::error::{ClaimError, Error, Result};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::{EntityId, Vault};

impl Vault {
    /// Whether `read`'s caller may read `conversation`'s DAG records: the
    /// lane reads its row, and its key is the vault owner's, or a narrower
    /// owner credential while he is still the bound owner, or its reader
    /// sees the conversation in its own list. An id that names no room is
    /// left to the listing, which refuses it as it does today: one that
    /// names no conversation, or a Direct conversation, which is no room
    /// (ARCH-0006a rule 2) and reads by the lane alone.
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
        if !is_live_room_in(&self.store, &txn, conversation)? {
            return Ok(true);
        }
        self.room_admits_in(read, &txn, conversation, conversation)
    }

    /// Whether `read`'s caller may read the room structure the row `id`
    /// holds, past the lane's own read of that row, which is the door's and
    /// is judged before this (L9-52). A live room is admitted as
    /// [`Self::dag_records_admitted`] admits it. A live TURN is admitted as
    /// its one room is, and the lane must read that room's row too. Any other
    /// row, a Direct conversation, and a TURN that names no live room, is
    /// left to the lane. A door answers a refused row as a missing one.
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

    /// [`Self::room_structure_admitted_in_txn`] for a retrieval or search
    /// hit (FIX [ROOM-STRUCTURE-RETRIEVAL-HITS], L9-52): a room's row and its
    /// turns show only to a reader the room admits, as at every door. Each
    /// room is judged once per `verdicts`, which hold `read`'s judgments in
    /// `txn` alone, so a search that finds many turns of one room judges it
    /// once. The vault owner is admitted with no judgment, as
    /// [`Self::room_admits_in`] admits him to every room.
    ///
    /// # Errors
    ///
    /// As [`Self::room_structure_admitted`].
    pub(crate) fn room_structure_admitted_held_in(
        &self,
        read: &ScopedRead<'_>,
        txn: &RoTxn<'_>,
        id: &EntityId,
        verdicts: &RoomVerdicts,
    ) -> Result<bool> {
        if read.actor_key().reads_as_vault_owner() {
            return Ok(true);
        }
        let Some(room) = structure_room_in(&self.store, txn, id)? else {
            return Ok(true);
        };
        if let Some(admitted) = verdicts.0.borrow().get(&room).copied() {
            return Ok(admitted);
        }
        let admitted = self.room_admits_in(read, txn, id, &room)?;
        verdicts.0.borrow_mut().insert(room, admitted);
        Ok(admitted)
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

/// The room admissions one read holds in one serving txn, by room
/// ([`Vault::room_structure_admitted_held_in`]). A fresh value holds none;
/// a value never passes to another read or txn.
#[derive(Default)]
pub(crate) struct RoomVerdicts(RefCell<HashMap<EntityId, bool>>);

/// The room whose structure the row `id` holds: a live room's own id, or the
/// live room a live TURN was witnessed into. `None` for any other row, for a
/// Direct conversation, and for a TURN that names no single live room. A
/// Direct conversation is no room (ARCH-0006a rule 2), so its turns read by
/// the lane alone.
fn structure_room_in(
    store: &impl crate::store::ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<EntityId>> {
    match live_entity_row_in_txn(store, txn, id)? {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_CONVERSATION,
            body,
        } if is_room_body(&body) => Ok(Some(*id)),
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_CONVERSATION,
            ..
        } => Ok(None),
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            ..
        } => match super::graph::named_room(store, txn, id)? {
            Ok(room) if is_live_room_in(store, txn, &room)? => Ok(Some(room)),
            _ => Ok(None),
        },
        _ => Ok(None),
    }
}

/// Whether `id` names a live room in `txn`: a live CONVERSATION whose body
/// names a Group, Channel or Mirror.
fn is_live_room_in(
    store: &impl crate::store::ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    match live_entity_row_in_txn(store, txn, id)? {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_CONVERSATION,
            body,
        } => Ok(is_room_body(&body)),
        _ => Ok(false),
    }
}

/// Whether a live CONVERSATION body names a room: a Group, Channel or Mirror.
/// A Direct or Agent conversation is no room. An undecodable body fails
/// closed as a room.
fn is_room_body(body: &[u8]) -> bool {
    match ConversationBody::from_bytes(body) {
        Ok(decoded) => matches!(
            decoded.kind,
            ConversationKind::Group | ConversationKind::Channel | ConversationKind::Mirror
        ),
        Err(_) => true,
    }
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
