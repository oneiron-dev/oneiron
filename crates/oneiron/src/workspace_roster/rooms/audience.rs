//! Private thread audiences (FIX 2951). ARCH-0006a, ruled 2026-09-23: "A
//! private thread names a narrower audience explicitly, the exception to
//! read following the room."
//!
//! # A birth fact on the root
//!
//! A thread's audience rides its first TURN's body under the door-owned
//! `room_thread` key: `{ root, room, anchor, audience }`. The root names the
//! set, or `null` for a thread that reads as its room does. Every later TURN
//! of the thread names the same root, room and anchor, and `null`; readers
//! consult the root. A trunk TURN carries no key. No side table holds it, so
//! a TURN never syncs ahead of its own audience, and a TURN a session
//! overlay stages carries the room it is read against (FIX 3122).
//!
//! # Fixed once stamped
//!
//! Nothing edits a stamped audience: there is no verb for it, and no admin,
//! host or owner widens it. No grant, mention, task, offer or Ready receipt
//! adds anyone to it. Reading or writing a private thread needs a place in
//! its audience and current room membership both; a thread a reader is off
//! reads as one that does not exist.

use super::*;
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON,
    ENTITY_TYPE_TURN,
};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The door-owned TURN body key a thread binding rides under.
pub(crate) const ROOM_THREAD_KEY: &str = "room_thread";

/// A thread TURN's birth binding: its thread's root, the room whose
/// membership it reads under, the trunk turn the thread hangs off and, on
/// the root alone, the audience the thread names (`None`: it reads as its
/// room does). The room is the canonical one, never a session's shell, and
/// every turn of a thread repeats its root's room and anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThreadBinding {
    pub(crate) root: EntityId,
    pub(crate) room: EntityId,
    pub(crate) anchor: Option<EntityId>,
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

/// Whether `ids` names `actor` (FIX 3123, Engine ruling A): by its own id,
/// or, for a pen, by the PERSON its stored subject anchor names now. Naming
/// one pen names no other pen of its person, and a pen anchored to an ORG,
/// or to no one, is named only by its own id. Read in the caller's
/// snapshot, never at the TURN's birth.
pub(crate) fn names_actor_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    ids: &BTreeSet<EntityId>,
    actor: EntityId,
) -> Result<bool> {
    if ids.contains(&actor) {
        return Ok(true);
    }
    if vault.get_entity_type_in_txn(txn, &actor)? != Some(ENTITY_TYPE_AGENT_DEF) {
        return Ok(false);
    }
    let at = crate::ports::job_recorded_at_in_txn(&vault.store, txn)?;
    Ok(
        crate::subject_model::actor_subject_anchor_in_txn(vault, txn, &actor, at)?
            .filter(|anchor| anchor.subject_kind == crate::subject_model::SubjectKind::Person)
            .is_some_and(|anchor| ids.contains(&anchor.subject_ref)),
    )
}

/// Refuses a private audience `opener` cannot name for a new thread of
/// `room`: an empty one, one that leaves the opener out, or one naming
/// anyone who is not a live PERSON or AGENT_DEF among the room's members
/// now. A pen is in a set, and among the members, that names its PERSON
/// ([`names_actor_in`]). A set naming every current member is still narrower than the room,
/// since a later member is not in it. The one policy point for what a
/// private thread may name.
pub(crate) fn validate_private_audience_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    opener: EntityId,
    audience: &BTreeSet<EntityId>,
) -> Result<()> {
    if audience.is_empty() || !names_actor_in(vault, txn, audience, opener)? {
        return Err(invalid());
    }
    let members: BTreeSet<_> = vault
        .room_audience_members_in_txn(txn, room)?
        .into_iter()
        .collect();
    for id in audience {
        if !names_actor_in(vault, txn, &members, *id)?
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
/// is still one of the room's members. A pen stands in both through the
/// PERSON it is anchored to ([`names_actor_in`]). No host, owner, seat or
/// receipt standing stands in for either.
pub(crate) fn thread_audience_allows_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
    actor: EntityId,
) -> Result<bool> {
    let Some(ids) = thread_audience_in(vault, txn, room, record)? else {
        return Ok(true);
    };
    let members: BTreeSet<_> = vault
        .room_audience_members_in_txn(txn, room)?
        .into_iter()
        .collect();
    Ok(names_actor_in(vault, txn, &ids, actor)? && names_actor_in(vault, txn, &members, actor)?)
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
/// thread's ceiling binds, a pen among them when its PERSON is named. It
/// seats no one.
pub(crate) fn thread_members_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
    members: &[EntityId],
) -> Result<Vec<EntityId>> {
    let Some(ids) = thread_audience_in(vault, txn, room, record)? else {
        return Ok(members.to_vec());
    };
    let mut kept = Vec::new();
    for &id in members {
        if names_actor_in(vault, txn, &ids, id)? {
            kept.push(id);
        }
    }
    Ok(kept)
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
    thread_root_readable_with_read_in(vault, &vault.store.read(), txn, root, viewers)
}

/// [`thread_root_readable_in`] with the root and its carrier read in `dbs`,
/// a session's composed view or base (FIX 3122): a live TURN whose own
/// binding names it, held by one live conversation, the room itself or a
/// stretch's shell. The audience is checked against the room the binding
/// names, on base, since authority reads base (ARCH-0052).
pub(crate) fn thread_root_readable_with_read_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
    viewers: &[EntityId],
) -> Result<bool> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_TURN,
        body,
    } = live_entity_row_in_txn(dbs, txn, &root)?
    else {
        return Ok(false);
    };
    let Some(binding) = thread_binding(&body)? else {
        return Ok(false);
    };
    if binding.root != root {
        return Ok(false);
    }
    let owners = crate::conversation_dag::edge_ids(
        dbs,
        txn,
        &root,
        crate::edge::EdgeKind::ChildOf,
        false,
        2,
    )?;
    if owners.len() != 1
        || !matches!(
            live_entity_row_in_txn(dbs, txn, &owners[0])?,
            LiveEntityRow::Live {
                entity_type: ENTITY_TYPE_CONVERSATION,
                ..
            }
        )
    {
        return Ok(false);
    }
    match private_members_readable_in(vault, txn, binding.room, binding.audience.as_ref(), viewers)
    {
        Err(Error::EntityNotFound) => Ok(false),
        result => result,
    }
}

/// Whether every one of `viewers` reads a thread of `room` naming
/// `audience`: anyone a public one (`None`), and a private one only from
/// its audience while each is still one of the room's members, a pen
/// through its PERSON ([`names_actor_in`]); no one when there are no
/// viewers. The one member rule a thread's root and a stretch's staged
/// thread turn both read.
pub(super) fn private_members_readable_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    audience: Option<&BTreeSet<EntityId>>,
    viewers: &[EntityId],
) -> Result<bool> {
    let Some(ids) = audience else {
        return Ok(true);
    };
    if viewers.is_empty() {
        return Ok(false);
    }
    let members: BTreeSet<_> = vault
        .room_audience_members_in_txn(txn, room)?
        .into_iter()
        .collect();
    for &viewer in viewers {
        if !names_actor_in(vault, txn, ids, viewer)?
            || !names_actor_in(vault, txn, &members, viewer)?
        {
            return Ok(false);
        }
    }
    Ok(true)
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
