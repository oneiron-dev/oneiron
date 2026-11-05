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
use crate::edge::EdgeKind;
use crate::error::{Error, Result};
use crate::note::{NoteBody, NoteKind};
use crate::ports::EdgeDirection;
use crate::registry::ENTITY_TYPE_NOTE;
use crate::side_table::{self, Named, Raw, RawValue, SideTable};
use crate::{EntityId, Vault, WriteActor};
use serde::{Deserialize, Serialize};

mod doors;
mod log;

/// The verb a diary-read Grant names.
pub const DIARY_READ_VERB: &str = "diary.read";
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
    /// The ruled reader a sealed-pad read was admitted as, with no Grant:
    /// `owner`, `admin` or `coach`. `None` for a read `diary.read` Grants
    /// covered.
    pub ruled_reader: Option<SealedPadReader>,
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
    /// The ruled reader a sealed-pad read asks as, with no Grant: `owner`,
    /// `admin` or `coach`. `None` for a read `diary.read` Grants cover.
    pub ruled_reader: Option<SealedPadReader>,
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
        if reason.is_empty() || reason.contains(['\n', '\r']) {
            return Err(authority_denied(
                "a diary read states its reason in one non-empty line",
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
                        ruled_reader: None,
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
                    ruled_reader: None,
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
            && note.author_ref.is(agent)
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

/// One diary entry a read returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DiaryEntry {
    pub id: EntityId,
    pub learned_at: u64,
    pub markdown: String,
}

/// What one direct diary read returned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
    /// The newest rows to return; omitted reads the complete log. An
    /// explicit count stays the caller's own recent-window choice.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Also return spent (`Used`) review requests. Default false keeps
    /// `requests` as the unspent queue: pending, approved or declined.
    #[serde(default)]
    pub include_used: bool,
}

/// `self.memory.diary.reads`'s answer: who read the agent's diary and why,
/// newest first, and the readers' reasons its review holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiaryReadsView {
    /// Whether the agent reviews each read first.
    pub review: bool,
    pub reads: Vec<DiaryReadRecord>,
    /// The persisted review requests, newest first: pending, approved or
    /// declined, and spent ones too when the input asked with `include_used`.
    pub requests: Vec<DiaryReadRequest>,
}

/// `self.memory.diary.review`'s input: the agent's Y/N to one request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiaryReviewAnswer {
    pub request: String,
    pub approve: bool,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SealedPadReader {
    /// A live vault owner, for their own agents.
    Owner,
    /// An Admin of a work vault, through the logged access step; the
    /// companion's owner sees the log.
    Admin,
    /// The Coach's health check, for an agent that is not a companion.
    Coach,
}

/// Whether `reader` is an Admin of this vault and the vault is a work vault:
/// the roster's own standing test ([`crate::workspace_roster::vault_standing_in`],
/// an Admin grant over the shared vault, a pen through its PERSON) and the
/// vault's kind ([`crate::agent_def::VaultKind`]). A personal vault, the
/// `Personal` preset included, has no Admin reader.
fn work_vault_admin_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, reader: EntityId) -> Result<bool> {
    Ok(
        vault.vault_kind_in_txn(txn)? == crate::agent_def::VaultKind::Work
            && crate::workspace_roster::vault_standing_in(vault, txn, reader)?
                == Some(crate::memory::vault_standing::VaultStanding::Admin),
    )
}

/// Whether the Coach's health check reads `agent`'s sealed pads: a work
/// agent's, never a companion's. The agent's kind is the role it wakes as,
/// its definition's cadence dial or else the vault wake-policy row's absent
/// role ([`crate::dreamer_wake::AgentWakePolicy::role_of`]), so an agent
/// with no dial in a vault whose absent role is `companion` is a companion.
fn coach_reads_pads_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, agent: &EntityId) -> Result<bool> {
    let Ok(definition) = vault.read_agent_definition_in_txn(txn, agent) else {
        return Ok(false);
    };
    Ok(vault.agent_wake_role_in_txn(txn, &definition)?
        != crate::dreamer_wake::AgentWakeRole::Companion)
}

/// Who may read an agent's diary and its sealed scratchpads: the list the
/// agent sees on its board (ARCH-0032 #private-reads: no secret readers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiaryReaderList {
    pub diary: Vec<DiaryReader>,
    pub sealed_pads: Vec<SealedPadReader>,
}
