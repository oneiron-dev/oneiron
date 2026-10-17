//! The reason-logged door to an agent's diary (OF-490, owner AGM-1+8).
//!
//! The owner's grant decides what can be read and downloaded: a `diary.read`
//! standing Grant names one reader and either the agent (its whole diary) or
//! the diary entries it covers. Owning the vault is no bypass; the owner
//! reads under a Grant like anyone else. Every read states a reason, kept in
//! the agent's own read log, where the agent sees it. An agent whose review
//! setting is on (on for Eiri; the host that provisions her turns it on by
//! her agent id) answers each reader's reason Y/N first, and one yes admits
//! one read. A vault export is a read with the reason `export`
//! (`crate::batch::export::EXPORT_DIARY_READ_REASON`). An agent
//! reading its own diary needs none of this.
//!
//! [`DiaryReadGate`] makes every decision, so the export writer and the
//! direct door below share one policy: `admit` each entry inside the
//! caller's read snapshot, then `finish` logs the reads, spends the yes they
//! used and opens a pending review for a read the agent has not answered.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use super::authorship::*;
use super::{Memory, MemoryError, MemoryResult};
use crate::agent_inbox_lens::{
    AgentInboxItemKind, AgentInboxLensItem, AgentInboxParticipant, InboxImpact,
};
use crate::consent::{
    ActionClass, ActionEnvelope, ActorBound, AuthenticatedOwner, ConsentReceipt, GrantBound,
};
use crate::edge::{EdgeActorClass, EdgeKind};
use crate::error::{Error, Result};
use crate::note::{NoteBody, NoteKind};
use crate::ports::EdgeDirection;
use crate::registry::ENTITY_TYPE_NOTE;
use crate::side_table::{self, Named, Raw, RawValue, SideTable};
use crate::{EntityId, Vault, WriteActor};
use serde::{Deserialize, Serialize};

/// The verb a diary-read Grant names.
pub const DIARY_READ_VERB: &str = "diary.read";
const REASON_MAX_BYTES: usize = 512;
const READS_LIMIT_DEFAULT: u32 = 50;
const READS_LIMIT_MAX: u32 = 500;
/// A review waiting on its agent ranks with the other rows that wait on it.
const REVIEW_INBOX_IMPACT: u16 = 100;

const DIARY_READ_REVIEW: SideTable<EntityId, DiaryReadReview, Raw> =
    SideTable::new(&side_table::DIARY_READ_REVIEW);
const DIARY_READ_LOG: SideTable<(EntityId, EntityId), DiaryReadRecord, Named> =
    SideTable::new(&side_table::DIARY_READ_LOG);
const DIARY_READ_REQUEST: SideTable<(EntityId, EntityId), DiaryReadRequest, Named> =
    SideTable::new(&side_table::DIARY_READ_REQUEST);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DiaryReadReview(bool);

impl RawValue for DiaryReadReview {
    fn to_raw(&self) -> std::result::Result<Vec<u8>, side_table::CodecError> {
        Ok(vec![u8::from(self.0)])
    }

    fn from_raw(bytes: &[u8]) -> std::result::Result<Self, side_table::CodecError> {
        match bytes {
            [0] => Ok(Self(false)),
            [1] => Ok(Self(true)),
            _ => Err(Error::CorruptedIndex("diary read review setting").into()),
        }
    }
}

/// One read of an agent's diary, as the agent sees it in its read log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DiaryReadRecord {
    pub read: EntityId,
    pub reader: EntityId,
    /// `human`, `agent` or `system`.
    pub reader_class: String,
    pub reason: String,
    pub at: u64,
    /// The entries the read returned.
    pub entries: Vec<EntityId>,
    /// The `diary.read` Grants that covered them.
    pub grants: Vec<String>,
    /// The review request whose yes admitted the read, when the agent reviews.
    pub request: Option<EntityId>,
    /// What the read opened: `diary` for diary entries, `pad` for sealed
    /// scratchpads.
    pub source: String,
}

/// Where one reader's stated reason stands in the agent's review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiaryReviewState {
    Pending,
    Approved,
    Declined,
    /// The yes admitted its one read.
    Used,
}

/// A reader's reason waiting on, or answered by, the agent's review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DiaryReadRequest {
    pub request: EntityId,
    pub reader: EntityId,
    pub reader_class: String,
    pub reason: String,
    pub asked_at: u64,
    pub state: DiaryReviewState,
    pub answered_at: Option<u64>,
    /// The read this request's yes admitted, once used.
    pub read: Option<EntityId>,
}

/// Why a diary entry stays out of a read.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DiaryReadHold {
    /// The agent reviews each read first and has not answered this one.
    PendingReview,
    /// The agent said no to this reader's reason.
    Declined,
    /// No `diary.read` Grant of the reader covers the entry.
    NotCovered,
}

/// Whether one entry is read, or why it is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiaryEntryAdmission {
    Read,
    Held(DiaryReadHold),
}

/// What a finished gate did for one agent's diary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiaryAgentRead {
    pub agent: EntityId,
    /// The read logged for the entries admitted, if any were.
    pub read: Option<EntityId>,
    pub entries: u64,
    /// The entries held, by why.
    pub held: Vec<(DiaryReadHold, u64)>,
    /// The review request standing for this reader's reason, if one does.
    pub request: Option<EntityId>,
    /// Whether a Grant covers the agent's whole diary.
    pub whole_diary: bool,
}

/// What a finished gate logged and held, one row per agent read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiaryReadReceipt {
    pub reason: String,
    pub agents: Vec<DiaryAgentRead>,
}

/// The one decision point for diary reads. `admit` is a pure read inside the
/// caller's snapshot; `finish` writes what the admissions mean.
pub struct DiaryReadGate {
    reader: WriteActor,
    reason: String,
    agents: BTreeMap<EntityId, AgentRead>,
}

struct AgentRead {
    whole: Option<String>,
    review: bool,
    request: Option<DiaryReadRequest>,
    read: Vec<EntityId>,
    grants: BTreeSet<String>,
    held: BTreeMap<DiaryReadHold, u64>,
}

impl AgentRead {
    fn load(
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        reader: WriteActor,
        reason: &str,
        agent: EntityId,
    ) -> Result<Self> {
        let whole = delegated_grant(
            vault,
            txn,
            &action_bound(vault, txn, reader, DIARY_READ_VERB, agent)?,
        )?;
        let review = agent_reviews_diary_reads_in_txn(vault, txn, &agent)?;
        let request = if review {
            standing_request_in_txn(vault, txn, agent, reader.entity_ref(), reason)?
        } else {
            None
        };
        Ok(Self {
            whole,
            review,
            request,
            read: Vec::new(),
            grants: BTreeSet::new(),
            held: BTreeMap::new(),
        })
    }
}

impl DiaryReadGate {
    /// A gate for `reader`'s reads, all stating `reason`.
    pub fn new(reader: WriteActor, reason: &str) -> Result<Self> {
        let reason = reason.trim();
        if reason.is_empty() || reason.len() > REASON_MAX_BYTES || reason.contains(['\n', '\r']) {
            return Err(authority_denied(
                "a diary read states its reason in one line of at most 512 bytes",
            ));
        }
        Ok(Self {
            reader,
            reason: reason.to_owned(),
            agents: BTreeMap::new(),
        })
    }

    /// Whether `entry`, a diary entry of `agent`, is read. The reader's
    /// whole-diary Grant covers every entry, an entry Grant only its own; a
    /// covered entry of an agent that reviews waits for its yes.
    pub fn admit(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
        entry: EntityId,
    ) -> Result<DiaryEntryAdmission> {
        let reader = self.reader;
        if agent == reader.entity_ref() {
            return Ok(DiaryEntryAdmission::Read);
        }
        let state = self.agent_in(vault, txn, agent)?;
        let grant = match &state.whole {
            Some(grant) => Some(grant.clone()),
            None => delegated_grant(
                vault,
                txn,
                &action_bound(vault, txn, reader, DIARY_READ_VERB, entry)?,
            )?,
        };
        let hold = match grant {
            None => Some(DiaryReadHold::NotCovered),
            Some(_) if !state.review => None,
            Some(_) => match state.request.as_ref().map(|request| request.state) {
                Some(DiaryReviewState::Approved) => None,
                Some(DiaryReviewState::Declined) => Some(DiaryReadHold::Declined),
                _ => Some(DiaryReadHold::PendingReview),
            },
        };
        Ok(match (hold, grant) {
            (None, Some(grant)) => {
                state.grants.insert(grant);
                state.read.push(entry);
                DiaryEntryAdmission::Read
            }
            (hold, _) => {
                let hold = hold.unwrap_or(DiaryReadHold::NotCovered);
                *state.held.entry(hold).or_default() += 1;
                DiaryEntryAdmission::Held(hold)
            }
        })
    }

    /// Loads `agent`'s standing for this reader without admitting an entry,
    /// so an empty diary still answers whether a Grant covers it.
    pub fn touch(&mut self, vault: &Vault, txn: &heed::RoTxn<'_>, agent: EntityId) -> Result<()> {
        if agent != self.reader.entity_ref() {
            self.agent_in(vault, txn, agent)?;
        }
        Ok(())
    }

    fn agent_in(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        agent: EntityId,
    ) -> Result<&mut AgentRead> {
        Ok(match self.agents.entry(agent) {
            Entry::Occupied(state) => state.into_mut(),
            Entry::Vacant(slot) => slot.insert(AgentRead::load(
                vault,
                txn,
                self.reader,
                &self.reason,
                agent,
            )?),
        })
    }

    /// Writes what the admissions mean, in its own write transaction.
    pub fn finish(self, vault: &Vault) -> Result<DiaryReadReceipt> {
        vault.with_write_txn_grouped(|txn| self.finish_in_txn(vault, txn))
    }

    /// Logs each agent's admitted entries as one read stating the reason,
    /// spends the yes that admitted it, and opens a pending review for a
    /// reader whose reason the agent has not answered.
    ///
    /// The admissions may come from an earlier snapshot (an export admits in
    /// its read snapshot), so each agent's standing is read again here: a
    /// Grant revoked, a review turned on, or a yes another read spent since
    /// then refuses the whole read before its bytes leave.
    pub fn finish_in_txn(
        self,
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<DiaryReadReceipt> {
        let at = vault.store.clock.now_recorded_at();
        let reader = self.reader.entity_ref();
        let reader_class = self.reader.actor_class().gate_actor_class();
        let mut agents = Vec::with_capacity(self.agents.len());
        for (agent, state) in self.agents {
            let now = AgentRead::load(vault, txn, self.reader, &self.reason, agent)?;
            if !state.read.is_empty() {
                let yes = !now.review
                    || now
                        .request
                        .as_ref()
                        .is_some_and(|request| request.state == DiaryReviewState::Approved);
                if !yes {
                    return Err(authority_denied(
                        "a diary read's yes was spent or withdrawn before the read finished",
                    ));
                }
                if now.whole.is_none() {
                    for entry in &state.read {
                        let bound = action_bound(vault, txn, self.reader, DIARY_READ_VERB, *entry)?;
                        if delegated_grant(vault, txn, &bound)?.is_none() {
                            return Err(authority_denied(
                                "a diary read's Grant was revoked before the read finished",
                            ));
                        }
                    }
                }
            }
            let mut request = now.request;
            let mut read_ref = None;
            if !state.read.is_empty() {
                let read = vault.store.clock.entity_id()?;
                let mut spent = None;
                if now.review
                    && let Some(yes) = request
                        .as_mut()
                        .filter(|request| request.state == DiaryReviewState::Approved)
                {
                    yes.state = DiaryReviewState::Used;
                    yes.read = Some(read);
                    DIARY_READ_REQUEST.put(&vault.store, txn, &(agent, yes.request), yes)?;
                    spent = Some(yes.request);
                }
                DIARY_READ_LOG.put(
                    &vault.store,
                    txn,
                    &(agent, read),
                    &DiaryReadRecord {
                        read,
                        reader,
                        reader_class: reader_class.to_owned(),
                        reason: self.reason.clone(),
                        at,
                        entries: state.read.clone(),
                        grants: state.grants.iter().cloned().collect(),
                        request: spent,
                        source: "diary".to_owned(),
                    },
                )?;
                read_ref = Some(read);
            }
            let standing = request
                .as_ref()
                .is_some_and(|request| request.state != DiaryReviewState::Used);
            if state.held.contains_key(&DiaryReadHold::PendingReview) && !standing {
                let row = DiaryReadRequest {
                    request: vault.store.clock.entity_id()?,
                    reader,
                    reader_class: reader_class.to_owned(),
                    reason: self.reason.clone(),
                    asked_at: at,
                    state: DiaryReviewState::Pending,
                    answered_at: None,
                    read: None,
                };
                DIARY_READ_REQUEST.put(&vault.store, txn, &(agent, row.request), &row)?;
                request = Some(row);
            }
            agents.push(DiaryAgentRead {
                agent,
                read: read_ref,
                entries: state.read.len() as u64,
                held: state.held.into_iter().collect(),
                request: request
                    .filter(|request| request.state != DiaryReviewState::Used)
                    .map(|request| request.request),
                whole_diary: now.whole.is_some(),
            });
        }
        Ok(DiaryReadReceipt {
            reason: self.reason,
            agents,
        })
    }
}

/// The live request standing for `reader`'s `reason`, newest first: one
/// pending, approved or declined, never one whose yes was spent.
fn standing_request_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
    reader: EntityId,
    reason: &str,
) -> Result<Option<DiaryReadRequest>> {
    Ok(DIARY_READ_REQUEST
        .scan_from(&vault.store, txn, agent.as_bytes())?
        .into_iter()
        .rev()
        .map(|(_, request)| request)
        .find(|request| {
            request.reader == reader
                && request.reason == reason
                && request.state != DiaryReviewState::Used
        }))
}

pub(crate) fn agent_reviews_diary_reads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: &EntityId,
) -> Result<bool> {
    Ok(DIARY_READ_REVIEW
        .get(&vault.store, txn, agent)?
        .is_some_and(|review| review.0))
}

/// The live diary entries `agent` wrote, oldest first, with their current
/// text and the time each was written.
pub(crate) fn diary_entries_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: EntityId,
) -> Result<Vec<(EntityId, NoteBody, u64)>> {
    let mut entries = Vec::new();
    for id in vault.filtered_edge_peers(
        txn,
        EdgeDirection::In,
        &agent,
        EdgeKind::AuthoredBy,
        Some(ENTITY_TYPE_NOTE),
    )? {
        if let Some((note, learned_at)) = live_note_in_txn(vault, txn, &id)?
            && note.kind == NoteKind::Diary
            && note.author_ref == agent
        {
            entries.push((id, note, learned_at));
        }
    }
    entries.sort_by_key(|(id, _, learned_at)| (*learned_at, *id));
    Ok(entries)
}

/// One live NOTE's current body and learned-at, read in `txn`.
fn live_note_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<Option<(NoteBody, u64)>> {
    if !crate::vault::live_entity_row_in_txn(&vault.store, txn, id)?.is_live()
        || vault.archive_tombstone_in_txn(txn, id)?.is_some()
    {
        return Ok(None);
    }
    let Some(raw) = vault.get_raw_in(txn, id)? else {
        return Ok(None);
    };
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or(Error::CorruptedIndex("diary entry header"))?;
    if header.entity_type != ENTITY_TYPE_NOTE {
        return Ok(None);
    }
    let bytes = &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    #[cfg(feature = "sync")]
    let resolved = crate::entity_doc::resolve_record_body(&vault.store, txn, id, bytes)?;
    #[cfg(feature = "sync")]
    let bytes = resolved.as_slice();
    let bytes = crate::note::live_body_in_txn(&vault.store, txn, id, ENTITY_TYPE_NOTE, bytes)?;
    let note = crate::note::decode_note_body_in_txn(&vault.store, txn, &bytes)?;
    Ok(Some((note, header.learned_at)))
}

impl Vault {
    /// Sets whether `agent` reviews each read of its diary first. The host
    /// that provisions Eiri turns it on for her agent id; absent means off.
    pub fn set_agent_diary_read_review(&self, agent: EntityId, on: bool) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            DIARY_READ_REVIEW.put(&self.store, txn, &agent, &DiaryReadReview(on))
        })
    }

    /// Whether `agent` reviews each read of its diary first.
    pub fn agent_diary_read_review(&self, agent: EntityId) -> Result<bool> {
        let txn = self.store.env.read_txn()?;
        agent_reviews_diary_reads_in_txn(self, &txn, &agent)
    }

    /// Each pending review as a row of its agent's INBOX: one unthreaded
    /// update per request, named by its `diary-read:` handle, until the agent
    /// answers it. The row says a reader is waiting; the reader and reason
    /// stay behind `self.memory.diary.reads`, and `self.memory.diary.review`
    /// answers it.
    pub(crate) fn diary_read_inbox_items(&self) -> Result<Vec<AgentInboxLensItem>> {
        let txn = self.store.env.read_txn()?;
        let mut items = Vec::new();
        for ((agent, request), row) in DIARY_READ_REQUEST.scan(&self.store, &txn)? {
            if row.state != DiaryReviewState::Pending {
                continue;
            }
            let handle = format!("diary-read:{}:{}", agent.to_hex(), request.to_hex());
            items.push(AgentInboxLensItem {
                item_id: handle.clone(),
                kind: AgentInboxItemKind::CoordinationUpdate,
                thread_ref: None,
                identity_ref: agent,
                actor_ref: agent,
                facet_ref: None,
                participants: vec![AgentInboxParticipant {
                    identity_ref: agent,
                    actor_ref: agent,
                }],
                impact: InboxImpact(REVIEW_INBOX_IMPACT),
                occurred_at: row.asked_at,
                receipt_ref: None,
                payload_ref: Some(handle),
                concern: None,
            });
        }
        Ok(items)
    }
}

/// One diary entry a read returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiaryEntry {
    pub id: EntityId,
    pub learned_at: u64,
    pub markdown: String,
}

/// What one direct diary read returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DiaryReadOutcome {
    /// The entries the reader's Grants cover; `read` names the log row (none
    /// for an agent reading its own diary or a covered empty one).
    Granted {
        read: Option<EntityId>,
        entries: Vec<DiaryEntry>,
    },
    /// The agent reviews reads first; `request` waits for its answer.
    PendingReview { request: EntityId },
    /// The agent said no to this reader's reason.
    Declined { request: EntityId },
    /// No `diary.read` Grant of the reader covers this diary.
    NotCovered,
}

/// `self.memory.diary.reads`'s input.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiaryReadsRequest {
    #[serde(default)]
    pub limit: Option<u32>,
}

/// `self.memory.diary.reads`'s answer: who read the agent's diary and why,
/// newest first, and the readers' reasons its review holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiaryReadsView {
    /// Whether the agent reviews each read first.
    pub review: bool,
    pub reads: Vec<DiaryReadRecord>,
    /// Requests not yet spent: pending, approved or declined.
    pub requests: Vec<DiaryReadRequest>,
}

/// `self.memory.diary.review`'s input: the agent's Y/N to one request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiaryReviewAnswer {
    pub request: String,
    pub approve: bool,
}

impl Memory<'_> {
    /// Reads `agent`'s diary as this caller, stating `reason`, in ONE
    /// transaction: the caller's `diary.read` Grants decide which entries it
    /// gets, the read lands in the agent's log, and an agent that reviews
    /// gets the reason to answer first. A person authenticates.
    pub fn read_agent_diary(
        &self,
        reader: Option<&AuthenticatedOwner>,
        agent: EntityId,
        reason: &str,
    ) -> MemoryResult<DiaryReadOutcome> {
        self.with_verified_actor_write_txn(|txn| {
            let actor = self.diary_reader_in_txn(txn, reader)?;
            let mut gate = DiaryReadGate::new(actor, reason)?;
            gate.touch(self.vault, txn, agent)?;
            let mut entries = Vec::new();
            for (id, note, learned_at) in diary_entries_in_txn(self.vault, txn, agent)? {
                if gate.admit(self.vault, txn, agent, id)? == DiaryEntryAdmission::Read {
                    entries.push(DiaryEntry {
                        id,
                        learned_at,
                        markdown: note.markdown,
                    });
                }
            }
            let receipt = gate.finish_in_txn(self.vault, txn)?;
            let Some(read) = receipt.agents.into_iter().next() else {
                return Ok(DiaryReadOutcome::Granted {
                    read: None,
                    entries,
                });
            };
            let held = |hold| read.held.iter().any(|(held, _)| *held == hold);
            Ok(match read.request {
                _ if read.read.is_some() || (read.whole_diary && read.held.is_empty()) => {
                    DiaryReadOutcome::Granted {
                        read: read.read,
                        entries,
                    }
                }
                Some(request) if held(DiaryReadHold::PendingReview) => {
                    DiaryReadOutcome::PendingReview { request }
                }
                Some(request) if held(DiaryReadHold::Declined) => {
                    DiaryReadOutcome::Declined { request }
                }
                _ => DiaryReadOutcome::NotCovered,
            })
        })
    }

    /// `self.memory.diary.reads`: this agent's read log and review requests.
    pub fn diary_reads(&self, input: &DiaryReadsRequest) -> MemoryResult<DiaryReadsView> {
        super::verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        let limit = input
            .limit
            .unwrap_or(READS_LIMIT_DEFAULT)
            .min(READS_LIMIT_MAX) as usize;
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let prefix = self.actor.as_bytes();
        let reads = DIARY_READ_LOG
            .scan_from(&self.vault.store, &txn, prefix)?
            .into_iter()
            .rev()
            .take(limit)
            .map(|(_, record)| record)
            .collect();
        let requests = DIARY_READ_REQUEST
            .scan_from(&self.vault.store, &txn, prefix)?
            .into_iter()
            .rev()
            .map(|(_, request)| request)
            .filter(|request| request.state != DiaryReviewState::Used)
            .take(limit)
            .collect();
        Ok(DiaryReadsView {
            review: agent_reviews_diary_reads_in_txn(self.vault, &txn, &self.actor)?,
            reads,
            requests,
        })
    }

    /// `self.memory.diary.review`: this agent's Y/N to a reader's reason.
    /// Only the diary's own agent answers; a spent yes stays spent.
    pub fn answer_diary_read(&self, input: &DiaryReviewAnswer) -> MemoryResult<DiaryReadRequest> {
        let request = EntityId::from_hex(&input.request)
            .map_err(|_| MemoryError::bad_request("request is not an entity id"))?;
        self.with_verified_actor_write_txn(|txn| {
            let key = (self.actor, request);
            let mut row = DIARY_READ_REQUEST
                .get(&self.vault.store, txn, &key)?
                .ok_or_else(|| MemoryError::not_found("no review request of this diary"))?;
            if row.state == DiaryReviewState::Used {
                return Err(MemoryError::bad_request(
                    "this yes already admitted its read",
                ));
            }
            row.state = if input.approve {
                DiaryReviewState::Approved
            } else {
                DiaryReviewState::Declined
            };
            row.answered_at = Some(self.vault.store.clock.now_recorded_at());
            DIARY_READ_REQUEST.put(&self.vault.store, txn, &key, &row)?;
            Ok(row)
        })
    }

    /// The owner sets whether `agent` reviews each read of its diary first.
    pub fn set_diary_read_review(
        &self,
        owner: &AuthenticatedOwner,
        agent: EntityId,
        on: bool,
    ) -> MemoryResult<()> {
        self.with_verified_actor_write_txn(|txn| {
            self.require_bound_owner_in_txn(txn, owner)?;
            DIARY_READ_REVIEW.put(&self.vault.store, txn, &agent, &DiaryReadReview(on))?;
            Ok(())
        })
    }

    /// The owner mints a `diary.read` Grant: `reader` reads `agent`'s whole
    /// diary, or only `entries` when any are named (each must be one of the
    /// agent's live diary entries).
    pub fn grant_diary_read(
        &self,
        owner: &AuthenticatedOwner,
        reader: WriteActor,
        agent: EntityId,
        entries: &[EntityId],
    ) -> MemoryResult<ConsentReceipt> {
        self.with_verified_actor_write_txn(|txn| {
            self.require_bound_owner_in_txn(txn, owner)?;
            verify_live_actor(self.vault, txn, reader)?;
            let bound = if entries.is_empty() {
                action_bound(self.vault, txn, reader, DIARY_READ_VERB, agent)?
            } else {
                for entry in entries {
                    let ours =
                        live_note_in_txn(self.vault, txn, entry)?.is_some_and(|(note, _)| {
                            note.kind == NoteKind::Diary && note.author_ref == agent
                        });
                    if !ours {
                        return Err(MemoryError::bad_request(format!(
                            "{} is not a live diary entry of this agent",
                            entry.to_hex()
                        )));
                    }
                }
                GrantBound::action(
                    ActorBound::new(reader.entity_ref().to_hex())?
                        .with_actor_class(reader.actor_class().gate_actor_class())?,
                    ActionClass::new(DIARY_READ_VERB)?,
                    ActionEnvelope::new(entries.iter().map(EntityId::to_hex))?
                        .with_target(root_id(self.vault, txn)?)?,
                )?
            };
            Ok(self.vault.create_standing_grant_in_txn(txn, owner, bound)?)
        })
    }

    fn require_bound_owner_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        owner: &AuthenticatedOwner,
    ) -> Result<()> {
        if self.actor != verify_owner(self.vault, txn, owner)?
            || self.actor_class != EdgeActorClass::Human
        {
            return Err(authority_denied("owner proof must name the bound caller"));
        }
        Ok(())
    }

    /// The reader this caller is: a person with their authentication, or a
    /// live agent or system actor.
    fn diary_reader_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        proof: Option<&AuthenticatedOwner>,
    ) -> Result<WriteActor> {
        let actor = WriteActor::new(self.actor, self.actor_class);
        match proof {
            Some(proof) => {
                if self.actor != proof.revalidate_person_in_txn(self.vault, txn)?
                    || self.actor_class != EdgeActorClass::Human
                {
                    return Err(authority_denied(
                        "diary-read authentication must name the bound human",
                    ));
                }
            }
            None if self.actor_class == EdgeActorClass::Human => {
                return Err(authority_denied(
                    "a person reads a diary with their authentication",
                ));
            }
            None => {}
        }
        verify_live_actor(self.vault, txn, actor)?;
        Ok(actor)
    }
}

impl Memory<'_> {
    /// Reads `agent`'s sealed scratchpads as this caller, stating `reason`, in
    /// ONE transaction (AGM-1+8, agent-mind §2.6). The ruled readers need no
    /// Grant: a live vault owner reads their agents' sealed pads, and the
    /// Coach reads a work agent's, never a companion's. The read lands in the
    /// agent's read log beside its diary reads, so the agent sees who read
    /// and why, and an agent that reviews reads answers the reason first. Any
    /// other reader is not covered: a health flag never grants access.
    pub fn read_agent_sealed_pads(
        &self,
        reader: Option<&AuthenticatedOwner>,
        agent: EntityId,
        reason: &str,
    ) -> MemoryResult<DiaryReadOutcome> {
        self.with_verified_actor_write_txn(|txn| {
            let actor = self.diary_reader_in_txn(txn, reader)?;
            let reason = DiaryReadGate::new(actor, reason)?.reason;
            let reader = actor.entity_ref();
            let ruled = reader == agent
                || (actor.actor_class() == EdgeActorClass::Human
                    && crate::policy_model::is_live_vault_owner_in_txn(self.vault, txn, &reader)?)
                || (reader == crate::dreamer_runner::authority::coach_actor_id()?
                    && self
                        .vault
                        .read_agent_definition_in_txn(txn, &agent)
                        .is_ok_and(|definition| {
                            !matches!(
                                definition.wake_cadence,
                                Some(crate::agent_def::AgentWakeCadence::Companion { .. })
                            )
                        }));
            if !ruled {
                return Ok(DiaryReadOutcome::NotCovered);
            }
            let review =
                reader != agent && agent_reviews_diary_reads_in_txn(self.vault, txn, &agent)?;
            let mut request = if review {
                standing_request_in_txn(self.vault, txn, agent, reader, &reason)?
            } else {
                None
            };
            let at = self.vault.store.clock.now_recorded_at();
            let reader_class = actor.actor_class().gate_actor_class();
            match request
                .as_ref()
                .map(|request| (request.state, request.request))
            {
                _ if !review => {}
                Some((DiaryReviewState::Approved, _)) => {}
                Some((DiaryReviewState::Declined, request)) => {
                    return Ok(DiaryReadOutcome::Declined { request });
                }
                Some((DiaryReviewState::Pending, request)) => {
                    return Ok(DiaryReadOutcome::PendingReview { request });
                }
                // A standing request is never a spent one.
                Some((DiaryReviewState::Used, _)) | None => {
                    let row = DiaryReadRequest {
                        request: self.vault.store.clock.entity_id()?,
                        reader,
                        reader_class: reader_class.to_owned(),
                        reason: reason.clone(),
                        asked_at: at,
                        state: DiaryReviewState::Pending,
                        answered_at: None,
                        read: None,
                    };
                    DIARY_READ_REQUEST.put(&self.vault.store, txn, &(agent, row.request), &row)?;
                    return Ok(DiaryReadOutcome::PendingReview {
                        request: row.request,
                    });
                }
            }
            let kind = NoteKind::Registered("scratchpad".to_owned());
            let mut entries = Vec::new();
            for pad in self.vault.sealed_scratchpads_in_txn(txn, agent)? {
                if let Some((note, learned_at)) = live_note_in_txn(self.vault, txn, &pad)?
                    && note.kind == kind
                    && note.author_ref == agent
                {
                    entries.push(DiaryEntry {
                        id: pad,
                        learned_at,
                        markdown: note.markdown,
                    });
                }
            }
            if reader == agent {
                return Ok(DiaryReadOutcome::Granted {
                    read: None,
                    entries,
                });
            }
            // Every read states its reason and is logged, an empty one too.
            let read = self.vault.store.clock.entity_id()?;
            let mut spent = None;
            if let Some(yes) = request.as_mut() {
                yes.state = DiaryReviewState::Used;
                yes.read = Some(read);
                DIARY_READ_REQUEST.put(&self.vault.store, txn, &(agent, yes.request), yes)?;
                spent = Some(yes.request);
            }
            DIARY_READ_LOG.put(
                &self.vault.store,
                txn,
                &(agent, read),
                &DiaryReadRecord {
                    read,
                    reader,
                    reader_class: reader_class.to_owned(),
                    reason,
                    at,
                    entries: entries.iter().map(|entry| entry.id).collect(),
                    grants: Vec::new(),
                    request: spent,
                    source: "pad".to_owned(),
                },
            )?;
            Ok(DiaryReadOutcome::Granted {
                read: Some(read),
                entries,
            })
        })
    }
}

/// One reader a `diary.read` Grant admits to an agent's diary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiaryReader {
    /// The reader, as the Grant names it.
    pub actor_ref: String,
    /// Its class, when the Grant pins one.
    pub actor_class: Option<String>,
    /// Whether a Grant covers the whole diary; else `entries` of its
    /// entries.
    pub whole: bool,
    pub entries: usize,
}

/// A ruled reader of an agent's sealed scratchpads, who needs no Grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealedPadReader {
    /// A live vault owner, for their own agents.
    Owner,
    /// The Coach's health check, for an agent that is not a companion.
    Coach,
}

/// Who may read an agent's diary and its sealed scratchpads: the list the
/// agent sees on its board (ARCH-0032 #private-reads: no secret readers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiaryReaderList {
    pub diary: Vec<DiaryReader>,
    pub sealed_pads: Vec<SealedPadReader>,
}

impl Memory<'_> {
    /// The ruled readers of this agent's sealed scratchpads, as
    /// `read_agent_sealed_pads` admits them: a live vault owner, and the
    /// Coach unless the agent is a companion.
    pub fn sealed_pad_readers(&self) -> MemoryResult<Vec<SealedPadReader>> {
        super::verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        let coach = self
            .vault
            .get_agent_definition(&self.actor)
            .is_ok_and(|definition| {
                definition.is_some_and(|definition| {
                    !matches!(
                        definition.wake_cadence,
                        Some(crate::agent_def::AgentWakeCadence::Companion { .. })
                    )
                })
            });
        Ok(std::iter::once(SealedPadReader::Owner)
            .chain(coach.then_some(SealedPadReader::Coach))
            .collect())
    }

    /// This agent's reader list. Its diary's readers are the actors that an
    /// active, owner-minted `diary.read` Grant admits, to the whole diary or
    /// to some of its entries, as [`DiaryReadGate`] admits them. Its sealed
    /// pads' readers are the ruled ones, as `read_agent_sealed_pads` admits
    /// them. An unrooted vault delegates no Grant, so its diary has none.
    pub fn diary_reader_list(&self) -> MemoryResult<DiaryReaderList> {
        let sealed_pads = self.sealed_pad_readers()?;
        let txn = self.vault.store.env.read_txn().map_err(Error::from)?;
        let agent = self.actor;
        let Ok(root) = root_id(self.vault, &txn) else {
            return Ok(DiaryReaderList {
                diary: Vec::new(),
                sealed_pads,
            });
        };
        let entries = diary_entries_in_txn(self.vault, &txn, agent)?;
        let mut diary: BTreeMap<(String, Option<String>), DiaryReader> = BTreeMap::new();
        for grant in self.vault.active_standing_consent_grants_in_txn(&txn)? {
            let bound = grant.bound();
            let Some(actor) = bound.actor() else {
                continue;
            };
            let covers = |target: EntityId| -> Result<bool> {
                let mut subject = ActorBound::new(actor.actor_ref())?;
                if let Some(class) = actor.actor_class() {
                    subject = subject.with_actor_class(class)?;
                }
                let required = GrantBound::action(
                    subject,
                    ActionClass::new(DIARY_READ_VERB)?,
                    ActionEnvelope::new([target.to_hex()])?.with_target(root.clone())?,
                )?;
                Ok(bound.contains(&required))
            };
            let whole = covers(agent)?;
            let mut covered = 0;
            if !whole {
                for (entry, _, _) in &entries {
                    covered += usize::from(covers(*entry)?);
                }
                if covered == 0 {
                    continue;
                }
            }
            // As `delegated_grant` admits: only an active Grant the root
            // owner minted delegates.
            let Some(row) = self
                .vault
                .consent_grant_in_txn(&txn, &bound.digest().to_hex())?
            else {
                continue;
            };
            // A minter that no longer reads as a live owner delegates nothing:
            // the gate's own check refuses it too.
            if !row.is_active()
                || !is_root_owner(self.vault, &txn, row.owner_stamp.actor).unwrap_or(false)
            {
                continue;
            }
            let key = (
                actor.actor_ref().to_owned(),
                actor.actor_class().map(str::to_owned),
            );
            let reader = diary.entry(key).or_insert_with(|| DiaryReader {
                actor_ref: actor.actor_ref().to_owned(),
                actor_class: actor.actor_class().map(str::to_owned),
                whole: false,
                entries: 0,
            });
            reader.whole |= whole;
            reader.entries = reader.entries.max(covered);
        }
        Ok(DiaryReaderList {
            diary: diary.into_values().collect(),
            sealed_pads,
        })
    }
}
