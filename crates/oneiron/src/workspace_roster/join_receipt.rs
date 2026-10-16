//! The join receipt (OF-531): one typed record per join intent. It holds the
//! request, each party's recorded answer, the three consents as last decided
//! with each granting party, and the participation a Ready decision
//! committed. A Ready receipt is the evidence later work in the room
//! re-proves; it is never a standing grant.

use serde::{Deserialize, Serialize};

use super::join_consent::{ConsentPart, ConsentSet, JoinDecision, JoinRequest, JoinSubject};
use crate::agent_dispatch::SpendScopeId;
use crate::error::{Error, Result};
use crate::side_table::{self, LegacyJson, SideTable};
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

/// One party's answer, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedAnswer {
    pub part: ConsentPart,
    /// The party: the host's PERSON, or the payer's.
    pub by: EntityId,
    /// The actor that answered for that party.
    pub actor: EntityId,
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
}

/// Everything a join was filed with: its receipt but the decision.
pub(super) struct JoinFiling {
    pub(super) join_ref: String,
    pub(super) intent_digest: String,
    pub(super) request: JoinRequest,
    pub(super) filed_by: EntityId,
    pub(super) principal: Option<EntityId>,
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
    /// The authenticated actor that filed it: the subject or its principal.
    pub filed_by: EntityId,
    /// For the vault's own agent: the live owner who filed for it, through
    /// whose standing it stands.
    pub principal: Option<EntityId>,
    pub answers: Vec<RecordedAnswer>,
    /// The three consents as last decided, each naming its granting party
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

    pub(super) fn into_filing(self) -> JoinFiling {
        JoinFiling {
            join_ref: self.join_ref,
            intent_digest: self.intent_digest,
            request: self.request,
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
