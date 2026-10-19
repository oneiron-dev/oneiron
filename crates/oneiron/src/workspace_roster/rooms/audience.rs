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
//! # Edited by ordered events
//!
//! The root's audience is the thread's seed (FIX 5545, owner ruling
//! 2026-10-19). Anyone in the audience, and the vault's Owner or an Admin,
//! adds or removes people at any time: each edit is a TURN of the thread,
//! and readers fold the seed and the edits in TURN id order
//! ([`super::audience_events`]). An add shares the whole thread or its turns
//! from the add on, and a remove ends every read of that person's. One added
//! from a later turn on reads no turn before its add, the root included. No
//! grant, mention, task, offer or Ready receipt adds anyone. Reading or
//! writing a private thread needs a place in its audience and current room
//! membership both, save the vault's Owner or an Admin, whom a place in the
//! audience admits without a seat in the room; a thread a reader is off
//! reads as one that does not exist. The Owner and an Admin see that a
//! room's private threads exist, by root id alone.
//!
//! # Two rules
//!
//! Every check reads a private thread under one of two rules (FIX 5545,
//! Engine ruling 2026-10-19: one added "from now on" sees nothing from
//! before the add, the opener included).
//!
//! - CURRENT, the structural rule: whether an actor is in the thread now.
//!   Entry, rosters, ceilings, appends, recipients, mentions and
//!   participation read it, and so does every helper handed the root to
//!   name the thread.
//! - CONTENT, the strict rule: whether an actor reads one turn of it. The
//!   root is a turn like any other, so a member added from a later turn on
//!   reads none before its add. Every read of a turn's words meets it.
//!
//! A turn a member does not read for its add is still a place in the thread
//! for it: the thread lists, opens and folds over its other turns, with that
//! one kept as a bare node, never served ([`super::thread_reads`]).

use super::audience_doors::vault_owner_or_admin_in;
use super::audience_events::{FoldedAudience, fold_audience_in};
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

/// The audience the root `root` of a thread in `room` has now, its seed
/// with its edits folded in (FIX 5545), read strictly: a live TURN with one
/// live carrier whose own binding names it, carried by `room` or stamped
/// with `room` as its canonical room. A saved off-record stretch's root
/// keeps its stretch shell as carrier and the room in its binding (FIX
/// 3560). Anything else does not resolve and reads as missing, so a turn
/// that declares it is withheld, never read as public.
pub(super) fn root_audience_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    root: EntityId,
) -> Result<Option<FoldedAudience>> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_TURN,
        body,
    } = live_entity_row_in_txn(&vault.store, txn, &root)?
    else {
        return Err(Error::EntityNotFound);
    };
    match thread_binding(&body)? {
        Some(binding) if binding.root == root => {
            let carrier = crate::conversation_dag::conversation_of(&vault.store, txn, &root)?;
            if carrier == room || binding.room == room {
                binding
                    .audience
                    .map(|seed| fold_audience_in(vault, txn, root, &seed))
                    .transpose()
            } else {
                Err(Error::EntityNotFound)
            }
        }
        _ => Err(Error::EntityNotFound),
    }
}

/// Which of the two rules (module docs) a check reads a thread under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ThreadRule {
    /// CURRENT: who is in the thread now, whatever record of it is named.
    Current,
    /// CONTENT: who reads the turn named, the root included.
    Content,
    /// CURRENT for the root, which names the thread, and CONTENT for any
    /// other turn.
    ByRecord,
}

/// Who in the audience of the thread holding `record`, a turn of `room`,
/// reads it now (FIX 5545): the CURRENT audience when `record` is the root,
/// which names the thread, and for any other turn the CONTENT one, each
/// member but one added from a later turn on. `None` for a trunk turn, a
/// public thread's, or a record that is no TURN, whose own read rules
/// decide. A thread turn reads its root's binding and edits; a root that is
/// gone or does not resolve is [`Error::EntityNotFound`], as a missing
/// `record` is.
pub(crate) fn thread_audience_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
) -> Result<Option<BTreeSet<EntityId>>> {
    thread_audience_by_in(vault, txn, room, record, ThreadRule::ByRecord)
}

/// [`thread_audience_in`] under the CURRENT rule whatever record of the
/// thread is named: everyone in it now. What a root-addressed recipient or
/// mention check reads.
pub(crate) fn thread_audience_now_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
) -> Result<Option<BTreeSet<EntityId>>> {
    thread_audience_by_in(vault, txn, room, record, ThreadRule::Current)
}

/// [`thread_audience_in`] under `rule`.
fn thread_audience_by_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
    rule: ThreadRule,
) -> Result<Option<BTreeSet<EntityId>>> {
    let body = match live_entity_row_in_txn(&vault.store, txn, &record)? {
        LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            body,
        } => body,
        LiveEntityRow::Live { .. } => return Ok(None),
        LiveEntityRow::Absent | LiveEntityRow::DeletedShell => return Err(Error::EntityNotFound),
    };
    let Some(binding) = thread_binding(&body)? else {
        return Ok(None);
    };
    Ok(
        root_audience_in(vault, txn, room, binding.root)?.map(|folded| match rule {
            ThreadRule::Current => folded.current(),
            ThreadRule::ByRecord if record == binding.root => folded.current(),
            ThreadRule::ByRecord | ThreadRule::Content => folded.reading(record),
        }),
    )
}

/// Whether `actor` reads and writes the thread holding `record` in `room`:
/// always off a private thread; on one, only from the audience that reads
/// `record` ([`thread_audience_in`]: CURRENT for the root, CONTENT for any
/// other turn) and while it is still one of the room's members, or the
/// vault's Owner or an Admin (FIX 5545). A pen stands in each through the
/// PERSON it is anchored to ([`names_actor_in`]). No host, seat or receipt
/// standing stands in for the audience.
pub(crate) fn thread_audience_allows_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
    actor: EntityId,
) -> Result<bool> {
    audience_allows_by_in(vault, txn, room, record, actor, ThreadRule::ByRecord)
}

/// [`thread_audience_allows_in`] under `rule`.
fn audience_allows_by_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: EntityId,
    actor: EntityId,
    rule: ThreadRule,
) -> Result<bool> {
    let Some(ids) = thread_audience_by_in(vault, txn, room, record, rule)? else {
        return Ok(true);
    };
    let members: BTreeSet<_> = vault
        .room_audience_members_in_txn(txn, room)?
        .into_iter()
        .collect();
    Ok(names_actor_in(vault, txn, &ids, actor)?
        && (names_actor_in(vault, txn, &members, actor)?
            || vault_owner_or_admin_in(vault, txn, actor)?))
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
/// `room` that reads `record` ([`thread_audience_in`]), or all of them off
/// a private thread: the members a private thread's ceiling binds, a pen
/// among them when its PERSON is named. It seats no one.
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
/// wherever it is, under the CURRENT rule: a public thread is read by
/// anyone, a private one by its audience now while each is still a member
/// of its room, and by no one when there are no viewers. A root that is
/// gone or does not resolve is read by none. The root and its carrier are
/// read in `dbs`, a session's composed view or base (FIX 3122): a live TURN
/// whose own binding names it, held by one live conversation, the room
/// itself or a stretch's shell. The audience, its edits folded in, is
/// checked against the room the binding names, on base, since authority
/// reads base (ARCH-0052).
pub(crate) fn thread_root_readable_with_read_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
    viewers: &[EntityId],
) -> Result<bool> {
    thread_readable_by_in(vault, dbs, txn, root, None, viewers)
}

/// [`thread_root_readable_with_read_in`] for the turn `turn` of the thread
/// rooted at `root`, under the CONTENT rule (FIX 5545): each viewer added
/// from a later turn on reads no turn before its add, the root included.
pub(crate) fn thread_turn_readable_with_read_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
    turn: EntityId,
    viewers: &[EntityId],
) -> Result<bool> {
    thread_readable_by_in(vault, dbs, txn, root, Some(turn), viewers)
}

/// The two above in one: the thread's audience now for `turn` `None`, and
/// the audience that reads `turn` otherwise.
fn thread_readable_by_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
    turn: Option<EntityId>,
    viewers: &[EntityId],
) -> Result<bool> {
    let Some(binding) = resolved_root_in(dbs, txn, root)? else {
        return Ok(false);
    };
    let audience = binding
        .audience
        .map(|seed| fold_audience_in(vault, txn, root, &seed))
        .transpose()?
        .map(|folded| match turn {
            None => folded.current(),
            Some(turn) => folded.reading(turn),
        });
    match private_members_readable_in(vault, txn, binding.room, audience.as_ref(), viewers) {
        Err(Error::EntityNotFound) => Ok(false),
        result => result,
    }
}

/// The binding of the root `root` as `dbs` holds it, strictly: a live TURN
/// whose own binding names it, held by one live conversation. `None` for
/// anything else.
pub(super) fn resolved_root_in(
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    root: EntityId,
) -> Result<Option<ThreadBinding>> {
    let LiveEntityRow::Live {
        entity_type: ENTITY_TYPE_TURN,
        body,
    } = live_entity_row_in_txn(dbs, txn, &root)?
    else {
        return Ok(None);
    };
    let Some(binding) = thread_binding(&body)? else {
        return Ok(None);
    };
    if binding.root != root {
        return Ok(None);
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
        return Ok(None);
    }
    Ok(Some(binding))
}

/// Whether every one of `viewers` reads a thread of `room` naming
/// `audience`: anyone a public one (`None`), and a private one only from
/// its audience while each is still one of the room's members, or is the
/// vault's Owner or an Admin (FIX 5545), a pen through its PERSON
/// ([`names_actor_in`]); no one when there are no viewers. The one member
/// rule a thread's root and a stretch's staged thread turn both read.
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
            || !(names_actor_in(vault, txn, &members, viewer)?
                || vault_owner_or_admin_in(vault, txn, viewer)?)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether `actor` may write in the thread the stored record `id` sits in:
/// a TURN by its own binding, a MESSAGE by the TURN it is part of, each
/// TURN one `actor` reads under the CONTENT rule, the root included (FIX
/// 5545). True for a record off any private thread, or one not stored yet.
pub(crate) fn record_thread_admits_in(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    actor: EntityId,
) -> Result<bool> {
    record_thread_admits_with_read_in(vault, &vault.store.read(), txn, id, actor)
}

/// [`record_thread_admits_in`] with the record, the TURNs it is part of and
/// their roots read in `dbs`, a session's composed view or base (FIX 3122):
/// a turn a stretch staged meets its thread's CONTENT rule as one base holds
/// does (FIX 5653). The audience reads base.
pub(crate) fn record_thread_admits_with_read_in(
    vault: &Vault,
    dbs: &crate::store::StoreRead<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    actor: EntityId,
) -> Result<bool> {
    let kind = crate::ports::EntityStoreRead::port_entity_record(dbs, txn, &id)?
        .map(|row| row.entity_type);
    let turns = match kind {
        Some(ENTITY_TYPE_TURN) => vec![id],
        Some(ENTITY_TYPE_MESSAGE) => crate::conversation_dag::edge_ids(
            dbs,
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
        } = live_entity_row_in_txn(dbs, txn, &turn)?
        else {
            continue;
        };
        if let Some(binding) = thread_binding(&body)?
            && !thread_turn_readable_with_read_in(vault, dbs, txn, binding.root, turn, &[actor])?
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
    /// A turn of the private thread rooted here, which this reader reads;
    /// from [`Memory::thread_reach_in`], one of a thread it is in.
    Private(EntityId),
    /// A turn of a private thread this reader is off, or one whose root is
    /// gone.
    Withheld,
}

impl Memory<'_> {
    /// Where the room turn `turn` of `room` reads for this reader, under the
    /// CONTENT rule: a turn of a private thread reads only when this reader
    /// stands in the audience that reads that turn, the root included (FIX
    /// 5545). The gate a turn's words meet.
    pub(crate) fn thread_place_in(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        turn: EntityId,
    ) -> Result<ThreadPlace> {
        self.thread_place_by_in(txn, room, turn, ThreadRule::Content)
    }

    /// [`Self::thread_place_in`] under the CURRENT rule: the private thread
    /// `turn` sits in when this reader is in it now, whatever turn of it is
    /// named. Where a turn is placed, never whether its words read.
    pub(crate) fn thread_reach_in(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        turn: EntityId,
    ) -> Result<ThreadPlace> {
        self.thread_place_by_in(txn, room, turn, ThreadRule::Current)
    }

    /// [`Self::thread_place_in`] with this reader read under `rule`.
    fn thread_place_by_in(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        turn: EntityId,
        rule: ThreadRule,
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
            Ok(Some(_)) if self.reads_thread_by_in(txn, room, turn, rule)? => {
                Ok(ThreadPlace::Private(binding.root))
            }
            Ok(Some(_)) | Err(Error::EntityNotFound) => Ok(ThreadPlace::Withheld),
            Err(error) => Err(error),
        }
    }

    /// Whether this reader stands in the audience of the thread holding
    /// `record` in `room`: the actor in the audience that reads `record`
    /// ([`thread_audience_in`]: CURRENT for the root, which names the
    /// thread, CONTENT for any other turn) and, for a handle bound to a room
    /// turn, every member that turn discloses to in the thread's audience
    /// now (FIX 5545). A held member added from a later turn on does not
    /// withhold `record` from the actor. Meeting a thread's worlds and
    /// clearance alone would not keep a held disclosure inside it.
    pub(crate) fn reads_thread_audience_in(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        record: EntityId,
    ) -> Result<bool> {
        self.reads_thread_by_in(txn, room, record, ThreadRule::ByRecord)
    }

    /// [`Self::reads_thread_audience_in`] with the actor read under `rule`;
    /// the members a held turn discloses to read under CURRENT whatever it
    /// is.
    fn reads_thread_by_in(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        record: EntityId,
        rule: ThreadRule,
    ) -> Result<bool> {
        let vault = self.vault();
        if !audience_allows_by_in(vault, txn, room, record, self.actor(), rule)? {
            return Ok(false);
        }
        let Some(turn) = self.room_turn() else {
            return Ok(true);
        };
        for &reader in &turn.roster {
            if !audience_allows_by_in(vault, txn, room, record, reader, ThreadRule::Current)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl Vault {
    /// The room and thread the stored TURN `turn` sits in, as a join files
    /// them (FIX 3572): its birth binding's canonical room and its thread's
    /// root, the branch a thread-filed join and its receipt key by. `None`
    /// for a trunk TURN, whose place is its room alone, or for an id that is
    /// no live TURN here.
    pub fn turn_room_work(
        &self,
        turn: EntityId,
    ) -> Result<Option<crate::workspace_roster::RoomWork>> {
        let txn = self.store.env.read_txn()?;
        let LiveEntityRow::Live {
            entity_type: ENTITY_TYPE_TURN,
            body,
        } = live_entity_row_in_txn(&self.store, &txn, &turn)?
        else {
            return Ok(None);
        };
        Ok(
            thread_binding(&body)?.map(|binding| crate::workspace_roster::RoomWork {
                room: binding.room,
                branch: Some(binding.root),
            }),
        )
    }
}
