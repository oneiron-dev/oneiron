//! The join receipt (OF-531): one typed record per join intent. It holds the
//! request, each party's recorded answer, the consents as last decided with
//! each granting party, and the participation a Ready decision committed. A
//! Ready receipt is the evidence later work in the room re-proves; it is
//! never a standing grant. A receipt still missing its subject's yes is an
//! invitation (OF-417): a board writer filed it for an unrelated person, and
//! it takes effect only once she accepts.

use std::ops::Bound;

use serde::{Deserialize, Serialize};

use super::join_consent::{
    ConsentPart, ConsentSet, JoinDecision, JoinRefusal, JoinRequest, JoinSubject, RequiredParty,
};
use crate::agent_dispatch::SpendScopeId;
use crate::conversation::HistoryChoice;
use crate::error::{Error, Result};
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};

/// One join intent's receipt. Key: its join ref.
pub(super) const JOINS: SideTable<String, JoinReceipt, LegacyJson> =
    SideTable::new(&side_table::ROOMS_JOIN);

/// The latest Ready receipt for one subject in one room or thread. Key:
/// [`ready_key`]; value: the join ref.
pub(super) const READY: SideTable<String, String, LegacyJson> =
    SideTable::new(&side_table::ROOMS_JOIN_READY);

const JOIN_REF_DOMAIN: &str = "oneiron.rooms.join.v1";
const RECEIPT_PREFIX: &str = "rooms.join:";

/// Whose act a roster row records: an actor, or no one once that actor was
/// erased (FIX 3520). It reads and writes as the actor's hex id, or as
/// [`ERASED_CALL_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterActor {
    Actor(EntityId),
    Erased,
}

impl RosterActor {
    /// Whether this is `actor`.
    #[must_use]
    pub fn is(self, actor: EntityId) -> bool {
        self == Self::Actor(actor)
    }

    /// The actor, while it is not erased.
    #[must_use]
    pub const fn id(self) -> Option<EntityId> {
        match self {
            Self::Actor(id) => Some(id),
            Self::Erased => None,
        }
    }

    /// Makes this no one when it is `actor`; whether it was.
    pub(super) fn forget(&mut self, actor: EntityId) -> bool {
        let named = self.is(actor);
        if named {
            *self = Self::Erased;
        }
        named
    }
}

impl Serialize for RosterActor {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Actor(id) => serializer.serialize_str(&id.to_hex()),
            Self::Erased => serializer.serialize_str(ERASED_CALL_IDENTITY),
        }
    }
}

impl<'de> Deserialize<'de> for RosterActor {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value == ERASED_CALL_IDENTITY {
            return Ok(Self::Erased);
        }
        EntityId::from_hex(&value)
            .map(Self::Actor)
            .map_err(serde::de::Error::custom)
    }
}

impl schemars::JsonSchema for RosterActor {
    fn schema_name() -> String {
        "RosterActor".to_owned()
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        <String as schemars::JsonSchema>::json_schema(generator)
    }
}

/// What an actor's erase does with a roster row whose remaining act waits on
/// that actor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterErase {
    /// The row goes, with the index rows that point at it.
    Delete,
    /// The row stays, and names no one where it named the actor.
    Keep,
}

/// A join no one settled that waits on an erased subject, principal or
/// party can never settle as it was filed, so an erase of that actor deletes
/// it (FIX 3520). Its filer alone is no one's consent: an invitation whose
/// inviter is erased stays and names no filer.
pub const ACTOR_ERASE_PENDING_JOIN: RosterErase = RosterErase::Delete;

/// Whether `id`'s entity is no actor, so its erase has no one to take out of
/// the roster rows.
pub(super) fn names_no_actor(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    if let Some(raw) = vault.get_raw_in(txn, id)?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
    {
        return Ok(!matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_PERSON
                | crate::registry::ENTITY_TYPE_MACHINE
                | crate::registry::ENTITY_TYPE_AGENT_DEF
        ));
    }
    Ok(false)
}

/// Erasing `actor` from the joins (FIX 3520). A join no one settled whose
/// remaining act waits on it goes, when [`ACTOR_ERASE_PENDING_JOIN`] says
/// so, with the open offer card that filed it. Every other join keeps its
/// row, its request and its times, and names no one where it named the
/// actor: its filer, its principal, each answer's party and answering
/// actor, and each consent's granting or refusing party. A recorded no
/// stays a no, so no older yes stands in for it, and an erased party's yes
/// no longer proves its consent when the join is decided again. A Ready
/// join whose subject is the actor proves nothing again, so its Ready row
/// goes. One-way, in the erase's own transaction. An id whose entity is no
/// actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a join row that cannot be read.
pub(crate) fn erase_join_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if names_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let store = &vault.store;
    let mut doomed = Vec::new();
    let mut erased = Vec::new();
    let mut ready = Vec::new();
    for (join_ref, mut receipt) in JOINS.scan(store, wtxn)? {
        if !receipt.is_settled()
            && ACTOR_ERASE_PENDING_JOIN == RosterErase::Delete
            && receipt.waits_on(*actor)
        {
            // A Ready row points only at a Ready receipt, so none points here.
            doomed.push((join_ref, receipt));
            continue;
        }
        let request = &receipt.request;
        if request.subject.id() == *actor && receipt.decision == JoinDecision::Ready {
            ready.push(ready_key(request.room, &request.subject, request.branch));
        }
        if receipt.forget(*actor) {
            erased.push((join_ref, receipt));
        }
    }
    for (join_ref, receipt) in &doomed {
        JOINS.delete(store, wtxn, join_ref)?;
        // An open offer card that filed this join can never settle now.
        super::rooms::drop_open_offer_in_txn(store, wtxn, join_ref, &receipt.request)?;
    }
    for (join_ref, receipt) in &erased {
        JOINS.put(store, wtxn, join_ref, receipt)?;
    }
    for key in &ready {
        READY.delete(store, wtxn, key)?;
    }
    Ok(())
}

/// A join receipt's reference: what later work freezes as the join it
/// proved.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JoinReceiptRef(String);

impl JoinReceiptRef {
    pub(super) fn for_join(join_ref: &str) -> Self {
        Self(format!("{RECEIPT_PREFIX}{join_ref}"))
    }

    /// Parses a stored reference: `rooms.join:` and a join ref.
    pub fn parse(value: &str) -> Result<Self> {
        value
            .strip_prefix(RECEIPT_PREFIX)
            .filter(|join_ref| is_join_ref(join_ref))
            .map(|_| Self(value.to_owned()))
            .ok_or_else(|| {
                Error::InvalidConfig("a join receipt ref is rooms.join: and a join ref".into())
            })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The join this receipt records.
    #[must_use]
    pub fn join_ref(&self) -> &str {
        &self.0[RECEIPT_PREFIX.len()..]
    }
}

/// A join ref: 64 lowercase hex.
pub(super) fn is_join_ref(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The join a request names: its room, thread, subject and intent key. The
/// same ref asked with another payload is one intent asked two ways.
pub(super) fn join_ref(request: &JoinRequest) -> Result<String> {
    digest(&(
        JOIN_REF_DOMAIN,
        request.room,
        request.branch,
        request.subject,
        &request.intent_key,
    ))
}

/// The digest of the whole request a join was filed with.
pub(super) fn intent_digest(request: &JoinRequest) -> Result<String> {
    digest(&(JOIN_REF_DOMAIN, request))
}

fn digest<T: Serialize>(value: &T) -> Result<String> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| Error::InvariantViolation("join request encode"))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// The Ready index key: the room, the subject, and the thread or `-`.
pub(super) fn ready_key(room: EntityId, subject: &JoinSubject, branch: Option<EntityId>) -> String {
    format!(
        "{}/{}/{}",
        room.to_hex(),
        subject.id().to_hex(),
        branch.map_or_else(|| "-".to_owned(), |branch| branch.to_hex())
    )
}

/// Deletes every join receipt a request for `room` filed, whatever its
/// decision, then the room's Ready index.
pub(super) fn delete_room_joins(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
) -> Result<()> {
    delete_joins_where(store, txn, |request| request.room == room)?;
    READY.delete_from(store, txn, format!("{}/", room.to_hex()).as_bytes())?;
    Ok(())
}

/// [`delete_room_joins`] for the one thread of `room` rooted at `thread`,
/// when that root is erased: the receipts filed for exactly that thread,
/// whatever their decision, then their Ready rows. A Ready key ends in its
/// thread ([`ready_key`]), so the room's prefix is read and only keys whose
/// last part is `thread` go; room-wide and sibling-thread rows stay.
pub(super) fn delete_thread_joins(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    thread: EntityId,
) -> Result<()> {
    delete_joins_where(store, txn, |request| {
        request.room == room && request.branch == Some(thread)
    })?;
    let suffix = format!("/{}", thread.to_hex());
    let ready: Vec<String> = READY
        .iter_from(store, txn, format!("{}/", room.to_hex()).as_bytes())?
        .filter_map(|row| match row {
            Ok((key, _)) => key.ends_with(&suffix).then_some(Ok(key)),
            Err(err) => Some(Err(err)),
        })
        .collect::<Result<_>>()?;
    for key in &ready {
        READY.delete(store, txn, key)?;
    }
    Ok(())
}

/// Deletes every join receipt whose request `doomed` names. JOINS is keyed by
/// join ref, not by room, so the sweep reads the whole table in keyset pages.
fn delete_joins_where(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    doomed: impl Fn(&JoinRequest) -> bool,
) -> Result<()> {
    let page_limit = super::rooms::PAGE_LIMIT;
    let mut after: Option<String> = None;
    loop {
        let start = after.as_ref().map_or(Bound::Unbounded, Bound::Excluded);
        let page: Vec<(String, JoinReceipt)> = JOINS
            .iter_range(store, txn, start, Bound::Unbounded)?
            .take(page_limit)
            .collect::<Result<_>>()?;
        for (join_ref, receipt) in &page {
            if doomed(&receipt.request) {
                JOINS.delete(store, txn, join_ref)?;
            }
        }
        if page.len() < page_limit {
            break;
        }
        after = page.last().map(|(join_ref, _)| join_ref.clone());
    }
    Ok(())
}

/// One party's answer, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedAnswer {
    pub part: ConsentPart,
    /// The party: the subject, the host's PERSON, or the payer's; no one
    /// once that party was erased.
    pub by: RosterActor,
    /// The actor that answered for that party; no one once it was erased.
    pub actor: RosterActor,
    pub grant: bool,
    /// The scope a payer's answer names.
    pub spend_scope: Option<SpendScopeId>,
    pub answer_ref: String,
    /// Unix seconds.
    pub at: u64,
}

/// What a Ready join committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinParticipation {
    /// The person joined the ordinary room's membership ledger.
    LedgerSeat,
    /// The person already sat in the room's ledger; nothing was appended.
    AlreadySeated,
    /// A project home room: only its board seats members, so the join seats
    /// no one and this receipt is the participation evidence.
    HomeRoomReceipt,
    /// A thread keeps no ledger of its own, and seating the room would widen
    /// past the thread: this receipt is the participation evidence.
    BranchReceipt,
    /// An agent never takes a room seat: this receipt is its participation
    /// evidence.
    AgentReceipt,
    /// A companion attends through her principal's live standing: a seat of
    /// her own would outlive it, so this receipt, re-proved on each use, is
    /// her participation evidence.
    PrincipalReceipt,
}

/// Everything a join was filed with: its receipt but the decision.
pub(super) struct JoinFiling {
    pub(super) join_ref: String,
    pub(super) intent_digest: String,
    pub(super) request: JoinRequest,
    pub(super) history: HistoryChoice,
    pub(super) filed_by: RosterActor,
    pub(super) principal: Option<RosterActor>,
    pub(super) answers: Vec<RecordedAnswer>,
    pub(super) filed_at: u64,
}

/// One join intent's typed record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JoinReceipt {
    pub join_ref: String,
    pub intent_digest: String,
    pub request: JoinRequest,
    /// The history a person's first entry into an ordinary room sees until
    /// the owner's P5 answer moves it (OF-365); a rejoin keeps the room's.
    #[serde(default)]
    pub history: HistoryChoice,
    /// The authenticated actor that filed it: the subject or its principal,
    /// or, for an invitation, the board writer whose roster write seated the
    /// subject; no one once that actor was erased.
    pub filed_by: RosterActor,
    /// For the vault's own agent: the live owner who filed for it, through
    /// whose standing it stands. An erased one stands as an owner no longer
    /// live does: the agent stands through the first live owner.
    pub principal: Option<RosterActor>,
    pub answers: Vec<RecordedAnswer>,
    /// The consents as last decided, each naming its granting party
    /// and evidence, or the party it waits on.
    pub consents: ConsentSet,
    pub decision: JoinDecision,
    pub participation: Option<JoinParticipation>,
    /// Unix seconds.
    pub filed_at: u64,
    /// Unix seconds.
    pub decided_at: u64,
}

impl JoinReceipt {
    /// Ready or refused: the intent is settled and replays as stored.
    #[must_use]
    pub fn is_settled(&self) -> bool {
        matches!(self.decision, JoinDecision::Ready | JoinDecision::Refuse(_))
    }

    /// The live owner the vault's own agent stands through, as the decision
    /// reads it.
    pub(super) fn principal_id(&self) -> Option<EntityId> {
        self.principal.and_then(RosterActor::id)
    }

    /// Whether this join's remaining act waits on `actor`: it is the
    /// subject, the principal, a party that answered or the actor that
    /// answered for one, or a party the hold waits on. Its filer alone is no
    /// one's consent.
    fn waits_on(&self, actor: EntityId) -> bool {
        let awaited = match &self.decision {
            JoinDecision::Hold { needs } => needs.iter().any(|need| match need.party {
                RequiredParty::Subject(subject) => subject.id() == actor,
                RequiredParty::Payer(payer) => payer == actor,
                _ => false,
            }),
            _ => false,
        };
        awaited
            || self.request.subject.id() == actor
            || self.principal.is_some_and(|principal| principal.is(actor))
            || self
                .answers
                .iter()
                .any(|answer| answer.by.is(actor) || answer.actor.is(actor))
    }

    /// Takes `actor` out of who this join records (FIX 3520): its filer, its
    /// principal, each answer's party and answering actor, and each
    /// consent's granting or refusing party name no one. Its request, its
    /// digests and its times stay. Whether it named the actor there.
    fn forget(&mut self, actor: EntityId) -> bool {
        let mut named = self.filed_by.forget(actor);
        if let Some(principal) = &mut self.principal {
            named |= principal.forget(actor);
        }
        for answer in &mut self.answers {
            named |= answer.by.forget(actor);
            named |= answer.actor.forget(actor);
        }
        named |= self.consents.forget(actor);
        if let JoinDecision::Refuse(JoinRefusal::Denied { party, .. }) = &mut self.decision {
            named |= party.forget(actor);
        }
        named
    }

    pub(super) fn into_filing(self) -> JoinFiling {
        JoinFiling {
            join_ref: self.join_ref,
            intent_digest: self.intent_digest,
            request: self.request,
            history: self.history,
            filed_by: self.filed_by,
            principal: self.principal,
            answers: self.answers,
            filed_at: self.filed_at,
        }
    }

    pub(super) fn decided(
        filing: JoinFiling,
        consents: ConsentSet,
        decision: JoinDecision,
        participation: Option<JoinParticipation>,
        now: u64,
    ) -> Self {
        Self {
            join_ref: filing.join_ref,
            intent_digest: filing.intent_digest,
            request: filing.request,
            history: filing.history,
            filed_by: filing.filed_by,
            principal: filing.principal,
            answers: filing.answers,
            consents,
            decision,
            participation,
            filed_at: filing.filed_at,
            decided_at: now,
        }
    }
}

impl Vault {
    /// The receipt of one join intent.
    pub fn join_receipt(&self, join_ref: &str) -> Result<Option<JoinReceipt>> {
        let txn = self.store.env.read_txn()?;
        JOINS.get(&self.store, &txn, &join_ref.to_owned())
    }
}
