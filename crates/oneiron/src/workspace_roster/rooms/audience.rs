//! Private thread audiences (FIX 2951). ARCH-0006a, ruled 2026-09-23: "A
//! private thread names a narrower audience explicitly, the exception to
//! read following the room."
//!
//! # A birth fact on the root
//!
//! A thread's audience rides its first TURN's body under the door-owned
//! `room_thread` key: `{ root, audience }`. The root names the set, or
//! `null` for a thread that reads as its room does. Every later TURN of the
//! thread names the same root and `null`; readers consult the root. A trunk
//! TURN carries no key. No side table holds it, so a TURN never syncs ahead
//! of its own audience.
//!
//! # Fixed once stamped
//!
//! Nothing edits a stamped audience: there is no verb for it, and no admin,
//! host or owner widens it. No grant, mention, task, offer or Ready receipt
//! adds anyone to it. Reading or writing a private thread needs a place in
//! its audience and current room membership both; a thread a reader is off
//! reads as one that does not exist.

use super::*;
use crate::error::RecordError;
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON, ENTITY_TYPE_TURN,
};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The door-owned TURN body key a thread binding rides under.
pub(crate) const ROOM_THREAD_KEY: &str = "room_thread";

/// A thread TURN's birth binding: its thread's root and, on the root alone,
/// the audience the thread names (`None`: it reads as its room does).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThreadBinding {
    pub(crate) root: EntityId,
    pub(crate) audience: Option<BTreeSet<EntityId>>,
}

/// The binding a TURN's MessagePack `body` carries; `None` for a trunk
/// TURN, or a body that is no map and so names no thread. A binding that
/// does not decode, or an empty audience, is refused.
pub(crate) fn thread_binding(body: &[u8]) -> Result<Option<ThreadBinding>> {
    let mut bytes = body;
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut bytes) else {
        return Ok(None);
    };
    let mut values = fields
        .into_iter()
        .filter(|(key, _)| key.as_str() == Some(ROOM_THREAD_KEY));
    let Some((_, value)) = values.next() else {
        return Ok(None);
    };
    if !bytes.is_empty() || values.next().is_some() {
        return Err(invalid());
    }
    let binding: ThreadBinding = rmpv::ext::from_value(value).map_err(|_| invalid())?;
    if binding.audience.as_ref().is_some_and(BTreeSet::is_empty) {
        return Err(invalid());
    }
    Ok(Some(binding))
}

/// `body` with `binding` stamped on, as the write that births its TURN puts
/// it. A body that already carries the key is refused: only the door writes
/// it.
pub(crate) fn stamp_thread(body: &[u8], binding: &ThreadBinding) -> Result<Vec<u8>> {
    let mut bytes = body;
    let rmpv::Value::Map(mut fields) =
        rmpv::decode::read_value(&mut bytes).map_err(|_| invalid())?
    else {
        return Err(invalid());
    };
    if !bytes.is_empty()
        || fields
            .iter()
            .any(|(key, _)| key.as_str() == Some(ROOM_THREAD_KEY))
    {
        return Err(invalid());
    }
    fields.push((
        rmpv::Value::from(ROOM_THREAD_KEY),
        rmpv::ext::to_value(binding).map_err(|_| invalid())?,
    ));
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(fields)).map_err(|_| invalid())?;
    Ok(out)
}

/// Refuses a private audience `opener` cannot name for a new thread of
/// `room`: an empty one, one that leaves the opener out, or one naming
/// anyone who is not a live PERSON or AGENT_DEF among the room's members
/// now. A set naming every current member is still narrower than the room,
/// since a later member is not in it. The one policy point for what a
/// private thread may name.
pub(crate) fn validate_private_audience_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    opener: EntityId,
    audience: &BTreeSet<EntityId>,
) -> Result<()> {
    if audience.is_empty() || !audience.contains(&opener) {
        return Err(invalid());
    }
    let members = vault.room_audience_members_in_txn(txn, room)?;
    for id in audience {
        if !members.contains(id)
            || !live_entity_row_in_txn(&vault.store, txn, id)?.is_live()
            || !matches!(
                vault.get_entity_type_in_txn(txn, id)?,
                Some(ENTITY_TYPE_PERSON | ENTITY_TYPE_AGENT_DEF)
            )
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// What the root `root` of a thread in `room` names, read strictly: a live
/// TURN of `room` whose own binding names it. Anything else does not
/// resolve and reads as missing, so a turn that declares it is withheld,
/// never read as public.
fn root_audience_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    root: EntityId,
) -> Result<Option<BTreeSet<EntityId>>> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_TURN,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, &root)?
    else {
        return Err(Error::EntityNotFound);
    };
    match thread_binding(&body)? {
        Some(binding)
            if binding.root == root
                && crate::conversation_dag::conversation_of(&vault.store, txn, &root)? == room =>
        {
            Ok(binding.audience)
        }
        _ => Err(Error::EntityNotFound),
    }
}

/// The audience the thread holding `record`, a turn of `room`, names:
/// `None` for a trunk turn, a public thread's, or a record that is no TURN,
/// whose own read rules decide. A thread turn reads its root's binding; a
/// root that is gone or does not resolve is [`Error::EntityNotFound`], as
/// a missing `record` is.
pub(crate) fn thread_audience_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
) -> Result<Option<BTreeSet<EntityId>>> {
    let body = match live_entity_row_in_txn(&vault.store, txn, &record)? {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            body,
        } => body,
        LiveEntityRow::Live { .. } => return Ok(None),
        LiveEntityRow::Absent | LiveEntityRow::DeletedShell => return Err(Error::EntityNotFound),
    };
    match thread_binding(&body)? {
        None => Ok(None),
        Some(binding) => root_audience_in(vault, txn, room, binding.root),
    }
}

/// Whether `actor` reads and writes the thread holding `record` in `room`:
/// always off a private thread; on one, only from its audience and while it
/// is still one of the room's members. No host, owner, seat or receipt
/// standing stands in for either.
pub(crate) fn thread_audience_allows_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
    actor: EntityId,
) -> Result<bool> {
    Ok(match thread_audience_in(vault, txn, room, record)? {
        None => true,
        Some(ids) => {
            ids.contains(&actor) && vault.room_audience_members_in_txn(txn, room)?.contains(&actor)
        }
    })
}

/// Refuses `actor` off the audience of the thread holding `record` in
/// `room` ([`thread_audience_allows_in`]). A thread hidden from it, or one
/// whose root is gone, refuses as an unknown one does.
pub(crate) fn require_thread_audience_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
    actor: EntityId,
) -> Result<()> {
    match thread_audience_allows_in(vault, txn, room, record, actor) {
        Ok(true) => Ok(()),
        Ok(false) | Err(Error::EntityNotFound) => Err(invalid()),
        Err(error) => Err(error),
    }
}

/// `members` narrowed to the audience of the thread holding `record` in
/// `room`, or all of them off a private thread: the members a private
/// thread's ceiling binds. It seats no one.
pub(crate) fn thread_members_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
    members: &[EntityId],
) -> Result<Vec<EntityId>> {
    Ok(match thread_audience_in(vault, txn, room, record)? {
        None => members.to_vec(),
        Some(ids) => members
            .iter()
            .copied()
            .filter(|id| ids.contains(id))
            .collect(),
    })
}

/// Whether every one of `viewers` reads the thread rooted at `root`,
/// wherever it is: a public thread is read by anyone, a private one by its
/// audience while each is still a member of its room, and by no one when
/// there are no viewers. A root that is gone or does not resolve is read by
/// none.
pub(crate) fn thread_root_readable_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
    viewers: &[EntityId],
) -> Result<bool> {
    let room = match crate::conversation_dag::conversation_of(&vault.store, txn, &root) {
        Ok(room) => room,
        Err(Error::EntityNotFound | Error::Record(RecordError::InvalidConversationDag(_))) => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    let audience = match root_audience_in(vault, txn, room, root) {
        Ok(audience) => audience,
        Err(Error::EntityNotFound) => return Ok(false),
        Err(error) => return Err(error),
    };
    let Some(ids) = audience else {
        return Ok(true);
    };
    if viewers.is_empty() {
        return Ok(false);
    }
    let members = vault.room_audience_members_in_txn(txn, room)?;
    Ok(viewers
        .iter()
        .all(|viewer| ids.contains(viewer) && members.contains(viewer)))
}

/// Whether `actor` may write in the thread the stored record `id` sits in:
/// a TURN by its own binding, a MESSAGE by the TURN it is part of. True for
/// a record off any private thread, or one not stored yet.
pub(crate) fn record_thread_admits_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    actor: EntityId,
) -> Result<bool> {
    let turns = match vault.get_entity_type_in_txn(txn, &id)? {
        Some(ENTITY_TYPE_TURN) => vec![id],
        Some(ENTITY_TYPE_MESSAGE) => crate::conversation_dag::edge_ids(
            &vault.store,
            txn,
            &id,
            crate::edge::EdgeKind::PartOf,
            false,
            2,
        )?,
        _ => return Ok(true),
    };
    for turn in turns {
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            body,
        } = live_entity_row_in_txn(&vault.store, txn, &turn)?
        else {
            continue;
        };
        if let Some(binding) = thread_binding(&body)?
            && !thread_root_readable_in(vault, txn, binding.root, &[actor])?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Where a room turn reads, for one reader: on the room's lane, under its
/// private thread's own reader, or not at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ThreadPlace {
    /// A trunk turn, or one in a public thread.
    Room,
    /// A turn of the private thread rooted here, which this reader reads.
    Private(EntityId),
    /// A turn of a private thread this reader is off, or one whose root is
    /// gone.
    Withheld,
}

impl Memory<'_> {
    /// Where the room turn `turn` of `room` reads for this reader: a private
    /// thread reads only when the actor and, for a handle bound to a room
    /// turn, every member that turn discloses to stand in its audience.
    pub(crate) fn thread_place_in(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        turn: EntityId,
    ) -> Result<ThreadPlace> {
        let body = match live_entity_row_in_txn(&self.vault().store, txn, &turn)? {
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_TURN,
                body,
            } => body,
            _ => return Ok(ThreadPlace::Withheld),
        };
        let Some(binding) = thread_binding(&body)? else {
            return Ok(ThreadPlace::Room);
        };
        match root_audience_in(self.vault(), txn, room, binding.root) {
            Ok(None) => Ok(ThreadPlace::Room),
            Ok(Some(_)) if self.reads_thread_audience_in(txn, room, binding.root)? => {
                Ok(ThreadPlace::Private(binding.root))
            }
            Ok(Some(_)) | Err(Error::EntityNotFound) => Ok(ThreadPlace::Withheld),
            Err(error) => Err(error),
        }
    }

    /// Whether this reader stands in the audience of the thread holding
    /// `record` in `room`: the actor and, for a handle bound to a room turn,
    /// every member that turn discloses to. Meeting a thread's worlds and
    /// clearance alone would not keep a held disclosure inside it.
    pub(crate) fn reads_thread_audience_in(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        record: EntityId,
    ) -> Result<bool> {
        let held = self
            .room_turn()
            .into_iter()
            .flat_map(|turn| turn.roster.iter().copied());
        for reader in std::iter::once(self.actor()).chain(held) {
            if !thread_audience_allows_in(self.vault(), txn, room, record, reader)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
