//! Thread participants (OF-529): one append-only stream of who took part in a
//! room or one of its threads, how, and since when.
//!
//! # People join by writing, agents by address or task
//!
//! A person joins a thread by writing in it: a write that passes today's room
//! gates records `Wrote`, and a person with no standing in an ordinary room
//! files an OF-531 join in the same transaction as the write. An agent never
//! takes a room seat and never joins by writing: it stands on an OF-531 Ready
//! receipt, and takes part when it is named on a turn or holds the thread's
//! open TASK. Naming enrolls no one, a TASK is never minted to let an agent
//! in, and nothing here counts or caps participants.
//!
//! # One stream, folded on read
//!
//! A fact is written once and never rewritten: a repeat keeps the first
//! `since`. There is no mutable participant set beside it; who may take part
//! now is read live from room standing and receipts, never from this stream.

use serde::{Deserialize, Serialize};

use super::super::join_consent::{
    JoinDecision, JoinRequest, JoinSubject, home_room_seats_in_txn, person_of_actor_in_txn,
    require_join_for_branch_in_txn,
};
use super::super::join_door::rooms_join_in_txn;
use super::super::join_receipt::JoinReceiptRef;
use crate::agent_dispatch::SpendScopeId;
use crate::error::{ClaimError, Error, Result};
use crate::registry::{ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_PERSON};
use crate::side_table::{self, LegacyJson, SideKey, SideTable};
use crate::store::Store;
use crate::{EdgeActorClass, EntityId, Vault, WriteActor};

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
    const fn kind(&self) -> u8 {
        match self {
            Self::Wrote { .. } => 1,
            Self::Addressed { .. } => 2,
            Self::Task { .. } => 3,
            Self::Offer { .. } => 4,
        }
    }

    /// The cause's id in a key: its turn or task, or an offer id's digest.
    fn key_id(&self) -> [u8; 16] {
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
/// and id, cause kind and id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FactKey {
    pub(super) room: EntityId,
    pub(super) branch: [u8; 16],
    pub(super) subject: JoinSubject,
    pub(super) cause: (u8, [u8; 16]),
}

const KEY_LEN: usize = 66;

impl SideKey for FactKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.room.as_bytes());
        out.extend_from_slice(&self.branch);
        out.push(subject_kind(&self.subject));
        out.extend_from_slice(self.subject.id().as_bytes());
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
        let subject = EntityId::from_bytes(id(33..49)?).ok()?;
        Some(Self {
            room: EntityId::from_bytes(id(0..16)?).ok()?,
            branch: id(16..32)?,
            subject: match bytes[32] {
                1 => JoinSubject::Person(subject),
                2 => JoinSubject::Agent(subject),
                _ => return None,
            },
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
        subject: *subject,
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

/// The one rule for which Ready receipt covers a thread (OF-529). A thread
/// takes the receipt filed for it, or the one filed for its room: no thread
/// is narrower than its room in existing code (no private thread is stored),
/// so a room's receipt covers each of its threads. A thread's receipt never
/// covers the room or another thread. Each receipt is re-proved live by
/// OF-531's exact-key check.
pub(crate) fn require_join_covering_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    subject: &JoinSubject,
    scope: Option<&SpendScopeId>,
) -> Result<JoinReceiptRef> {
    if branch.is_some()
        && let Some(receipt) = joined(require_join_for_branch_in_txn(
            vault, txn, room, branch, subject, scope,
        ))?
    {
        return Ok(receipt);
    }
    require_join_for_branch_in_txn(vault, txn, room, None, subject, scope)
}

/// A receipt check's answer, with "not joined" as `None`.
pub(super) fn joined(proved: Result<JoinReceiptRef>) -> Result<Option<JoinReceiptRef>> {
    match proved {
        Ok(receipt) => Ok(Some(receipt)),
        Err(Error::Claim(ClaimError::ActorLacksClaimAuthority { .. })) => Ok(None),
        Err(error) => Err(error),
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

/// `agent`'s standing in `room`, or its thread `branch`: a Ready receipt
/// that covers it, or the seat a project roster already gives it. Paid work
/// (`scope`) stands only on a receipt carrying its payer's consent.
pub(crate) fn agent_standing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    agent: EntityId,
    scope: Option<&SpendScopeId>,
) -> Result<Option<AgentStanding>> {
    if scope.is_none()
        && vault
            .room_audience_members_in_txn(txn, room)?
            .contains(&agent)
    {
        return Ok(Some(AgentStanding::Seat));
    }
    Ok(joined(require_join_covering_in_txn(
        vault,
        txn,
        room,
        branch,
        &JoinSubject::Agent(agent),
        scope,
    ))?
    .map(AgentStanding::Receipt))
}

/// A person's standing in `room` today: a project home room's seat, or an
/// ordinary room's ledger seat or host role. `actor` is the pen it acts
/// through, when that is not the PERSON itself. `None` for a home room whose
/// roster does not seat it: only the project's board seats one there.
pub(crate) fn person_standing_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    person: EntityId,
    actor: Option<EntityId>,
) -> Result<Option<bool>> {
    let ids = || std::iter::once(person).chain(actor);
    if let Some((_, seats)) = home_room_seats_in_txn(vault, txn, room)? {
        return Ok(ids().any(|id| seats.contains(&id.to_hex())).then_some(true));
    }
    let members = vault.members_in_txn(txn, room)?;
    if ids().any(|id| members.contains(&id)) {
        return Ok(Some(true));
    }
    let own = WriteActor::new(person, EdgeActorClass::Human);
    Ok(Some(
        crate::conversation::room_host_in_txn(vault, txn, room, own)?.is_some(),
    ))
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

/// The one gate both write paths (a live DAG append, a room witness) call
/// before they write; the caller records the fact after its write, in the
/// same transaction, with [`Admitted::record_in_txn`].
///
/// A person with standing (today's room gates) writes on, and its write is
/// its thread join. A person with no standing in an ordinary room files an
/// OF-531 join for the room in this transaction, for nothing paid: Ready
/// seats it and the write goes on; a held join refuses the write with the
/// parties it waits on, and a refused one refuses it. A project home room
/// keeps its rule: only its board seats anyone, so a write there from off
/// its roster stays refused and files no join. An agent never joins by
/// writing: its write records nothing here, and its speech, claims and reads
/// stand on [`agent_standing_in_txn`]. For any other cause an agent must
/// stand there now.
#[expect(
    clippy::too_many_arguments,
    reason = "the place, the writer, its cause and paid scope, and the decision time"
)]
pub(crate) fn admit_participation_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    actor: WriteActor,
    cause: JoinCause,
    scope: Option<&SpendScopeId>,
    now: u64,
) -> Result<Admitted> {
    let mut admitted = Admitted {
        room,
        branch,
        subject: None,
        cause,
        join_ref: None,
    };
    let Some(subject) = participant_in_txn(vault, txn, actor.entity_ref(), now)? else {
        return Ok(admitted);
    };
    let writes = matches!(admitted.cause, JoinCause::Wrote { .. });
    match subject {
        JoinSubject::Agent(_) if writes => return Ok(admitted),
        JoinSubject::Agent(agent) => {
            let standing = agent_standing_in_txn(vault, txn, room, branch, agent, scope)?
                .ok_or_else(|| lacks("the agent has no Ready join in this room or thread"))?;
            admitted.join_ref = standing.receipt().cloned();
        }
        JoinSubject::Person(person) => {
            let pen = (person != actor.entity_ref()).then_some(actor.entity_ref());
            match person_standing_in_txn(vault, txn, room, person, pen)? {
                Some(true) => {}
                Some(false) if writes => {
                    admitted.join_ref =
                        Some(write_join_in_txn(vault, txn, room, person, actor, now)?);
                }
                Some(false) => return Err(lacks("the person has no standing in this room")),
                None => {
                    return Err(lacks(
                        "only the project's board seats a member of its home room",
                    ));
                }
            }
        }
    }
    admitted.subject = Some(subject);
    Ok(admitted)
}

/// Files the room join a person's first write in an ordinary room needs, in
/// the write's transaction, for nothing paid. Its intent key is the room and
/// the person, so `vault.rooms.join` with the same key files the same join
/// and holds it for the parties it waits on.
fn write_join_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    person: EntityId,
    caller: WriteActor,
    now: u64,
) -> Result<JoinReceiptRef> {
    let request = JoinRequest {
        room,
        branch: None,
        subject: JoinSubject::Person(person),
        paid: false,
        spend_scope: None,
        intent_key: format!("write:{}:{}", room.to_hex(), person.to_hex()),
    };
    let outcome = rooms_join_in_txn(vault, txn, &request, caller, now)?;
    match &outcome.decision.state {
        JoinDecision::Ready => JoinReceiptRef::parse(
            outcome
                .receipt_ref
                .as_deref()
                .ok_or(Error::CorruptedIndex("a Ready join has no receipt"))?,
        ),
        JoinDecision::Hold { needs } => Err(Error::InvalidConfig(format!(
            "the write waits on its room join, which holds on {}; vault.rooms.join with intent_key {} files it for those parties",
            json(needs)?,
            request.intent_key
        ))),
        JoinDecision::Refuse(refusal) => Err(Error::InvalidConfig(format!(
            "the write's room join is refused: {}",
            json(refusal)?
        ))),
    }
}

/// A join decision's typed parts, as the refusal carries them.
fn json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| Error::InvariantViolation("join decision encode"))
}

fn lacks(reason: &'static str) -> Error {
    Error::Claim(ClaimError::ActorLacksClaimAuthority { reason })
}
