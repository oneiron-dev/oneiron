//! Thread participants (OF-529): one append-only stream of who took part in a
//! room or one of its threads, how, and since when.
//!
//! # People join by writing, agents by address or task
//!
//! A person joins a thread by writing in it: a write that passes today's room
//! gates records `Wrote`, and a person with no standing in a room files an
//! OF-531 join in the same transaction as the write. A person stands on its
//! seat or on a live Ready join, so a home room's join, which seats no one,
//! and a companion's, which stands on her principal, both count. An agent
//! never takes a room seat and never joins by writing: it stands on an
//! OF-531 Ready receipt, and takes part when it is named on a turn or holds
//! the thread's open TASK. It speaks, claims or appends only then, or by an
//! accepted offer card (ARCH-0006a, ruled 2026-09-23). Naming enrolls no
//! one, a TASK is never minted to let an agent in, and nothing here counts
//! or caps participants.
//!
//! # One stream, folded on read
//!
//! A fact is written once and never rewritten: a repeat keeps the first
//! `since`. There is no mutable participant set beside it; who may take part
//! now is read live from room standing and receipts, never from this stream.
//!
//! Entry: `record_participation_in_txn`.
//! Standing, admission and speech guards live in `admission`; fact and claimant types stay here.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::super::join_consent::{
    JoinDecision, JoinRequest, JoinSubject, RoomJoinHold, home_room_seats_in_txn,
    person_of_actor_in_txn, require_join_for_branch_in_txn,
};
use super::super::join_door::rooms_join_in_txn;
use super::super::join_receipt::JoinReceiptRef;
use super::fact_subject::FactSubject;
use super::{ProjectRoom, RoomTurn, invalid, require_member, room_in, turn_in};
use super::{TURNS, audience, hosting, offers};
use crate::agent_dispatch::SpendScopeId;
use crate::error::{ClaimError, Error, RecordError, Result};
use crate::memory::WitnessTurn;
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use crate::side_table::{self, LegacyJson, SideKey, SideTable};
use crate::store::Store;
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};

mod admission;
use self::admission::lacks;
pub(super) use self::admission::{
    addressable_agent_in_txn, admit_speech_in, joined, person_stands_in_txn,
    record_addressed_in_txn, require_speaker_in_txn, require_thread_audience_in,
};
pub(crate) use self::admission::{
    admit_participation_in_txn, agent_standing_in_txn, person_standing_in_txn,
    require_join_covering_in_txn,
};

/// Why a participant takes part in a room or thread.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JoinCause {
    /// A person wrote there; `turn` is its first turn.
    Wrote { turn: EntityId },
    /// An agent was named on `turn` and stood on a Ready receipt, when named
    /// or when its claim on that turn passed.
    Addressed { turn: EntityId },
    /// An agent holds `task`, an open TASK bound to the thread.
    Task { task: EntityId },
    /// The participant accepted an offer to join (OF-530).
    Offer { offer_id: String },
}

impl JoinCause {
    pub(super) const fn kind(&self) -> u8 {
        match self {
            Self::Wrote { .. } => 1,
            Self::Addressed { .. } => 2,
            Self::Task { .. } => 3,
            Self::Offer { .. } => 4,
        }
    }

    /// The cause's id in a key: its turn or task, or an offer id's digest.
    pub(super) fn key_id(&self) -> [u8; 16] {
        match self {
            Self::Wrote { turn } | Self::Addressed { turn } => *turn.as_bytes(),
            Self::Task { task } => *task.as_bytes(),
            Self::Offer { offer_id } => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"oneiron.rooms.participation.offer.v1");
                hasher.update(offer_id.as_bytes());
                let mut id = [0; 16];
                id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
                id
            }
        }
    }

    /// A first join is recorded once per subject and place: a later turn
    /// or naming adds no row. Each TASK and offer is its own fact.
    const fn first_only(&self) -> bool {
        matches!(self, Self::Wrote { .. } | Self::Addressed { .. })
    }
}

const fn subject_kind(subject: &JoinSubject) -> u8 {
    match subject {
        JoinSubject::Person(_) => 1,
        JoinSubject::Agent(_) => 2,
    }
}

/// One fact's key: room, thread (all zero for the room itself), subject kind
/// and id, or no one's digest (FIX 4228), cause kind and id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FactKey {
    pub(super) room: EntityId,
    pub(super) branch: [u8; 16],
    pub(super) subject: FactSubject,
    pub(super) cause: (u8, [u8; 16]),
}

const KEY_LEN: usize = 66;

impl SideKey for FactKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.room.as_bytes());
        out.extend_from_slice(&self.branch);
        out.push(self.subject.kind());
        out.extend_from_slice(&self.subject.key_id());
        out.push(self.cause.0);
        out.extend_from_slice(&self.cause.1);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != KEY_LEN {
            return None;
        }
        let id = |range: std::ops::Range<usize>| -> Option<[u8; 16]> {
            bytes.get(range)?.try_into().ok()
        };
        Some(Self {
            room: EntityId::from_bytes(id(0..16)?).ok()?,
            branch: id(16..32)?,
            subject: FactSubject::decode(bytes[32], id(33..49)?)?,
            cause: (bytes[49], id(50..66)?),
        })
    }
}

/// The key bytes every fact of `room`, or of its thread `branch`, starts with.
pub(super) fn place_prefix(room: EntityId, branch: Option<EntityId>) -> Vec<u8> {
    let mut out = Vec::with_capacity(KEY_LEN);
    out.extend_from_slice(room.as_bytes());
    out.extend_from_slice(&branch_bytes(branch));
    out
}

fn branch_bytes(branch: Option<EntityId>) -> [u8; 16] {
    branch.map_or([0; 16], |branch| *branch.as_bytes())
}

/// One fact as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fact {
    /// When it was recorded, on the store's recorded-at clock (unix seconds).
    pub(super) at: u64,
    /// The receipt the participant stood on, when it stood on one.
    pub(super) join_ref: Option<String>,
    /// The cause in full: the key holds an offer id only as a digest.
    pub(super) cause: JoinCause,
}

/// Every participation fact. Key: [`FactKey`].
pub(super) const FACTS: SideTable<FactKey, Fact, LegacyJson> =
    SideTable::new(&side_table::ROOMS_PARTICIPATION);

/// Records that `subject` took part in `room`, or in its thread `branch`,
/// for `cause`. The only writer of the stream. A fact already held keeps its
/// first `since`; a first join (`Wrote`, `Addressed`) is held once per
/// subject and place, whichever turn it names.
#[expect(
    clippy::too_many_arguments,
    reason = "one fact's place, subject, cause, receipt and time, in the caller's transaction"
)]
pub(crate) fn record_participation_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    subject: &JoinSubject,
    cause: &JoinCause,
    join_ref: Option<&JoinReceiptRef>,
    at: u64,
) -> Result<()> {
    let key = FactKey {
        room,
        branch: branch_bytes(branch),
        subject: FactSubject::Live(*subject),
        cause: (cause.kind(), cause.key_id()),
    };
    let held = if cause.first_only() {
        let mut prefix = place_prefix(room, branch);
        prefix.push(subject_kind(subject));
        prefix.extend_from_slice(subject.id().as_bytes());
        prefix.push(cause.kind());
        FACTS
            .iter_raw_from(&vault.store, txn, &prefix)?
            .next()
            .transpose()?
            .is_some()
    } else {
        FACTS.contains(&vault.store, txn, &key)?
    };
    if held {
        return Ok(());
    }
    FACTS.put(
        &vault.store,
        txn,
        &key,
        &Fact {
            at,
            join_ref: join_ref.map(|receipt| receipt.as_str().to_owned()),
            cause: cause.clone(),
        },
    )
}

/// Deletes every fact a room holds, with the room's other rows.
pub(super) fn delete_room_facts(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
) -> Result<()> {
    FACTS.delete_from(store, txn, room.as_bytes())?;
    Ok(())
}

/// Deletes every fact the thread of `room` rooted at `thread` holds, when
/// that root is erased; the room's own facts and its other threads' stay.
pub(super) fn delete_thread_facts(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    thread: EntityId,
) -> Result<()> {
    FACTS.delete_from(store, txn, &place_prefix(room, Some(thread)))?;
    Ok(())
}

/// Who takes part when `actor` acts: the PERSON behind it, or the agent it
/// is. A PERSON is itself. An AGENT_DEF with a live PERSON subject anchor is
/// that person's pen (a member's own actor, a companion's persona), so it
/// takes part as that PERSON: `actor.subject_ref` is the stored answer to who
/// stands behind an actor (ARCH-0063 R7), the same anchor OF-531 reads.
/// Every other AGENT_DEF (an ORG-anchored house mind, an unanchored team lead
/// or worker) is an agent. The actor class decides nothing: an AGENT_DEF
/// only ever carries `Agent`. Anything else takes part in no room. Claims
/// and bylines keep the original actor.
pub(crate) fn join_subject_for_actor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    at: u64,
) -> Result<JoinSubject> {
    match vault.get_entity_type_in_txn(txn, &actor)? {
        Some(ENTITY_TYPE_PERSON) => Ok(JoinSubject::Person(actor)),
        Some(ENTITY_TYPE_AGENT_DEF) => Ok(person_of_actor_in_txn(vault, txn, actor, at)?
            .map_or(JoinSubject::Agent(actor), JoinSubject::Person)),
        _ => Err(lacks("only a person or an agent takes part in a room")),
    }
}

/// [`join_subject_for_actor_in_txn`], or `None` for an actor that is neither
/// a PERSON nor an AGENT_DEF: upkeep and plumbing take part in no room.
pub(super) fn participant_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    at: u64,
) -> Result<Option<JoinSubject>> {
    match vault.get_entity_type_in_txn(txn, &actor)? {
        Some(ENTITY_TYPE_PERSON | ENTITY_TYPE_AGENT_DEF) => {
            join_subject_for_actor_in_txn(vault, txn, actor, at).map(Some)
        }
        _ => Ok(None),
    }
}

/// How an agent stands in a room or thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AgentStanding {
    /// A seat its room's own roster gives it: a project's agent leader or
    /// board member, seated by the project, never by a join.
    Seat,
    /// A Ready receipt re-proved against live facts just now.
    Receipt(JoinReceiptRef),
}

impl AgentStanding {
    pub(crate) fn receipt(&self) -> Option<&JoinReceiptRef> {
        match self {
            Self::Seat => None,
            Self::Receipt(receipt) => Some(receipt),
        }
    }
}

/// What [`admit_participation_in_txn`] let through: the place, the subject
/// its fact names and the receipt it stood on. The caller records it after
/// its own write, in the same transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Admitted {
    room: EntityId,
    branch: Option<EntityId>,
    /// `None` when the write records no fact: an agent's write, or an actor
    /// that takes part in no room.
    subject: Option<JoinSubject>,
    cause: JoinCause,
    join_ref: Option<JoinReceiptRef>,
}

impl Admitted {
    /// Records the admitted fact; a write that records none is a no-op.
    pub(crate) fn record_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        at: u64,
    ) -> Result<()> {
        let Some(subject) = &self.subject else {
            return Ok(());
        };
        record_participation_in_txn(
            vault,
            txn,
            self.room,
            self.branch,
            subject,
            &self.cause,
            self.join_ref.as_ref(),
            at,
        )
    }
}

/// The thread a room turn belongs to: its root, the stable id the thread's
/// joins and receipts name, never the moving tip. A root names its trunk
/// anchor and answers it, or nothing; a reply inherits its root by walking
/// `reply_to`. `None` for a trunk turn, or one whose chain reaches no root.
pub(super) fn thread_root_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: EntityId,
    mut reply_to: Option<EntityId>,
    mut thread_of: Option<EntityId>,
) -> Result<Option<EntityId>> {
    let mut id = turn;
    let mut seen = BTreeSet::new();
    loop {
        let Some(anchor) = thread_of else {
            return Ok(None);
        };
        let Some(parent) = reply_to.filter(|parent| *parent != anchor) else {
            return Ok(Some(id));
        };
        if !seen.insert(id) || seen.len() > 100_000 {
            return Err(invalid());
        }
        let row = turn_in(vault, txn, parent)?;
        id = parent;
        reply_to = row
            .reply_to
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?;
        thread_of = row
            .thread_of
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?;
    }
}

/// [`thread_root_in_txn`] for a stored turn.
pub(super) fn turn_root_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &RoomTurn,
) -> Result<Option<EntityId>> {
    thread_root_in_txn(
        vault,
        txn,
        EntityId::from_hex(&turn.turn_id)?,
        turn.reply_to
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?,
        turn.thread_of
            .as_deref()
            .map(EntityId::from_hex)
            .transpose()?,
    )
}

/// Whether `actor`, taking part as `subject`, reads the project room
/// `record`: from its seat, as before, or on a Ready receipt for the room,
/// an agent's or, through its pen, a person's (OF-417). A thread's receipt
/// opens no room-wide read.
pub(super) fn reads_room_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    record: &ProjectRoom,
    actor: EntityId,
    subject: Option<JoinSubject>,
) -> Result<bool> {
    if record.member_ids.contains(&actor.to_hex()) {
        return Ok(true);
    }
    let Some(subject) = subject else {
        return Ok(false);
    };
    if let JoinSubject::Person(_) = subject {
        return person_stands_in_txn(vault, txn, room, None, actor, Some(subject));
    }
    Ok(joined(require_join_covering_in_txn(
        vault, txn, room, None, &subject, None,
    ))?
    .is_some())
}

/// Whether `actor` hosts `room`, read live: its owner, or a member the room
/// policy lets delegate, the one standing that answers the room's admissions
/// and offers (OF-530). A host reads the room from that standing, off the
/// roster and with no receipt; it takes no seat and is no participant, and
/// its own grants still bound each read.
fn hosts_room_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<bool> {
    let host = WriteActor::new(actor, EdgeActorClass::Human);
    Ok(crate::conversation::room_host_in_txn(vault, txn, room, host)?.is_some())
}

/// The room read entry (OF-529): for a person its seat or a Ready receipt
/// for the room (OF-417), and for an agent its seat or a Ready receipt for
/// the room. The room's host reads it too ([`hosts_room_in_txn`]). Returns
/// the room as its project vouches for it.
pub(in crate::workspace_roster) fn require_reader(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<ProjectRoom> {
    let record = room_in(vault, txn, room)?;
    let subject = participant_in_txn(vault, txn, actor, vault.store.clock.now_recorded_at())?;
    if !reads_room_in_txn(vault, txn, room, &record, actor, subject)?
        && !hosts_room_in_txn(vault, txn, room, actor)?
    {
        return Err(invalid());
    }
    Ok(record)
}

/// The read entry for one thread `thread` of `room` (OF-529): a person reads
/// it as [`require_reader`] reads the room, and an agent from its seat or a
/// Ready receipt for that thread or for the room. A thread's receipt opens
/// that thread's read alone, never the room's or another thread's. The
/// room's host reads each of its threads, as it reads the room, except a
/// private one (FIX 2951), which only its audience reads. Last, the vault's
/// Owner or an Admin in a private thread's audience reads that thread with
/// no standing in the room (FIX 5638). Returns the room as its project
/// vouches for it.
pub(super) fn require_thread_reader(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    thread: EntityId,
    actor: EntityId,
) -> Result<ProjectRoom> {
    Ok(require_thread_standing(vault, txn, room, thread, actor)?.0)
}

/// [`require_thread_reader`], with whether `actor` reads `thread` off the
/// room: as the vault's Owner or an Admin in its private audience alone
/// ([`super::audience::privileged_private_thread_reader_in`]).
pub(super) fn require_thread_standing(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    thread: EntityId,
    actor: EntityId,
) -> Result<(ProjectRoom, bool)> {
    let record = room_in(vault, txn, room)?;
    require_thread_audience_in(vault, txn, room, Some(thread), actor)?;
    let subject = participant_in_txn(vault, txn, actor, vault.store.clock.now_recorded_at())?;
    let reads = match subject {
        Some(JoinSubject::Agent(agent)) => {
            agent_standing_in_txn(vault, txn, room, Some(thread), agent, None)?.is_some()
        }
        subject => reads_room_in_txn(vault, txn, room, &record, actor, subject)?,
    };
    if reads || hosts_room_in_txn(vault, txn, room, actor)? {
        return Ok((record, false));
    }
    if super::audience::privileged_private_thread_reader_in(vault, txn, room, thread, actor)? {
        return Ok((record, true));
    }
    Err(invalid())
}

/// Whether `actor` is an agent with no standing in `room` itself: no seat
/// and no Ready receipt for the room. Only such an agent reads a thread on
/// that thread's own receipt ([`require_thread_reader`]). Every other actor,
/// and a room this cannot vouch for, keeps the room read, which refuses or
/// serves as before.
pub(super) fn agent_off_room_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<bool> {
    let Ok(record) = room_in(vault, txn, room) else {
        return Ok(false);
    };
    let subject = participant_in_txn(vault, txn, actor, vault.store.clock.now_recorded_at())?;
    Ok(matches!(subject, Some(JoinSubject::Agent(_)))
        && !reads_room_in_txn(vault, txn, room, &record, actor, subject)?)
}

/// Who claims a room turn, and on what (OF-529).
pub(super) struct Claimant {
    room: EntityId,
    actor: EntityId,
    branch: Option<EntityId>,
    /// `None` for a person, who claims from its seat or its own Ready join.
    agent: Option<AgentStanding>,
}

impl Claimant {
    /// A person claims from its seat, or on its own live Ready join for the
    /// turn's thread or the room (OF-417). An agent claims on a Ready receipt
    /// for the turn's thread or the room, or the seat its project gives it;
    /// it never takes a seat to claim.
    pub(super) fn admit_in_txn(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        turn: &RoomTurn,
        actor: EntityId,
    ) -> Result<Self> {
        let branch = turn_root_in_txn(vault, txn, turn)?;
        // A private thread's turn is claimed from its audience alone (FIX
        // 2951), whatever seat or receipt the claimant holds.
        require_thread_audience_in(vault, txn, room, branch, actor)?;
        let now = vault.store.clock.now_recorded_at();
        let agent = match participant_in_txn(vault, txn, actor, now)? {
            Some(JoinSubject::Agent(agent)) => Some(
                agent_standing_in_txn(vault, txn, room, branch, agent, None)?
                    .ok_or_else(invalid)?,
            ),
            subject => {
                if !person_stands_in_txn(vault, txn, room, branch, actor, subject)? {
                    require_member(vault, txn, room, actor)?;
                }
                None
            }
        };
        Ok(Self {
            room,
            actor,
            branch,
            agent,
        })
    }

    /// Claiming a turn is speaking: see [`admit_speech_in`].
    pub(super) fn admit_speech_in(&self, vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<()> {
        admit_speech_in(vault, txn, self.room, self.actor, self.agent.as_ref())
    }

    /// Whether the claimant takes part as an agent, which claims only a
    /// turn it is named on or whose thread task it holds.
    pub(super) const fn is_agent(&self) -> bool {
        self.agent.is_some()
    }

    /// The open TASK of the claimed turn's thread this agent holds now: the
    /// task's stored assignee, re-read at every claim, so a reassigned or
    /// terminal task authorizes nothing new. No signed room rule allows an
    /// owner fallback, so the assignee alone holds it. A person holds none.
    pub(super) fn held_task_in_txn(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        turn: &RoomTurn,
    ) -> Result<Option<EntityId>> {
        if self.agent.is_none() {
            return Ok(None);
        }
        held_thread_task_in_txn(vault, txn, turn, self.actor)
    }

    /// Records the agent's participation once its claim passes: named on the
    /// turn, and holding the thread's task. A person's claim records nothing.
    pub(super) fn record_in_txn(
        &self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        turn: EntityId,
        named: bool,
        task: Option<EntityId>,
    ) -> Result<()> {
        let Some(standing) = &self.agent else {
            return Ok(());
        };
        let subject = JoinSubject::Agent(self.actor);
        let at = vault.store.clock.now_recorded_at();
        let causes = named
            .then_some(JoinCause::Addressed { turn })
            .into_iter()
            .chain(task.map(|task| JoinCause::Task { task }));
        for cause in causes {
            record_participation_in_txn(
                vault,
                txn,
                self.room,
                self.branch,
                &subject,
                &cause,
                standing.receipt(),
                at,
            )?;
        }
        Ok(())
    }
}

/// The open TASK of `turn`'s thread that `holder` holds now: the task's
/// stored assignee, re-read at every call, so a reassigned or terminal task
/// authorizes nothing new.
fn held_thread_task_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &RoomTurn,
    holder: EntityId,
) -> Result<Option<EntityId>> {
    for task in thread_tasks_in_txn(vault, txn, turn)? {
        match crate::task_verb::open_thread_task_holder_in(
            vault,
            txn,
            task,
            crate::gate::TaskHolderFallback::AssigneeOnly,
        ) {
            Ok(Some(held)) if held == holder => return Ok(Some(task)),
            Ok(_) | Err(Error::EntityNotFound) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(None)
}

/// The TASK ids bound along `turn`'s thread chain, from the turn up to its
/// root, where a thread's task binds.
fn thread_tasks_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    turn: &RoomTurn,
) -> Result<Vec<EntityId>> {
    let mut tasks = Vec::new();
    let mut current = Some(turn.clone());
    let mut seen = BTreeSet::new();
    while let Some(row) = current.take() {
        if !seen.insert(row.turn_id.clone()) || seen.len() > 100_000 {
            return Err(invalid());
        }
        for task in &row.task_ids {
            tasks.push(EntityId::from_hex(task)?);
        }
        if row.thread_of.is_none() || super::liveness::is_thread_root(&row) {
            break;
        }
        current = match row.reply_to.as_deref() {
            Some(parent) => Some(turn_in(vault, txn, EntityId::from_hex(parent)?)?),
            None => None,
        };
    }
    Ok(tasks)
}

/// Records `task`'s holder as a participant of the thread `row` belongs to,
/// when the holder is an agent standing on a Ready receipt there now;
/// otherwise its first passing claim records it. Binding a task mints none,
/// and a person holding one joins by writing.
pub(in crate::workspace_roster) fn record_bound_task_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    row: &RoomTurn,
    task: EntityId,
) -> Result<()> {
    let Some(holder) = crate::task_verb::open_thread_task_holder_in(
        vault,
        txn,
        task,
        crate::gate::TaskHolderFallback::AssigneeOnly,
    )?
    else {
        return Ok(());
    };
    let now = vault.store.clock.now_recorded_at();
    let Some(subject @ JoinSubject::Agent(_)) = participant_in_txn(vault, txn, holder, now)? else {
        return Ok(());
    };
    let branch = turn_root_in_txn(vault, txn, row)?;
    let Some(receipt) = joined(require_join_covering_in_txn(
        vault, txn, room, branch, &subject, None,
    ))?
    else {
        return Ok(());
    };
    record_participation_in_txn(
        vault,
        txn,
        room,
        branch,
        &subject,
        &JoinCause::Task { task },
        Some(&receipt),
        now,
    )
}
