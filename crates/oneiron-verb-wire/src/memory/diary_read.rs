//! Moved from `crates/oneiron/src/memory/diary_read.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::btree_map::Entry;

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

/// `self.memory.diary.review`'s input: the agent's Y/N to one request.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiaryReviewAnswer {
    pub request: String,
    pub approve: bool,
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
