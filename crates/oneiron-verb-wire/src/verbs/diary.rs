//! Moved from `crates/oneiron/src/verbs/diary.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::diary_read::DiaryReadOutcome;
use crate::memory::diary_read::DiaryReadRecord;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;

/// `self.memory.diary.query`'s input: whose diary, and the one-line reason
/// the read states.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiaryQueryRequest {
    /// Whose diary, as 32 hex.
    pub agent: String,
    /// Why the caller reads; the agent sees it. One non-empty line.
    pub reason: String,
}

impl DiaryQueryRequest {
    /// Refuses an agent that is not an entity id, and a reason that is empty
    /// or more than one line.
    pub fn validate(&self) -> MemoryResult<()> {
        self.agent_id()?;
        let reason = self.reason.trim();
        if reason.is_empty() || reason.contains(['\n', '\r']) {
            return Err(MemoryError::bad_request("reason is one non-empty line"));
        }
        Ok(())
    }

    fn agent_id(&self) -> MemoryResult<EntityId> {
        EntityId::from_hex(&self.agent)
            .map_err(|_| MemoryError::bad_request("agent is not an entity id"))
    }
}

/// One diary entry a query returned: its NOTE, when it was written, and its
/// current text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DiaryQueryEntry {
    pub id: EntityId,
    pub learned_at: u64,
    pub markdown: String,
}

/// `self.memory.diary.query`'s answer: the door's [`DiaryReadOutcome`] on
/// the wire, in the same shape `POST /v1/owner/diary/read` answers. `state`
/// says which.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DiaryQueryOutcome {
    /// The entries the caller's Grants cover; `read` names the read-log row
    /// (none for an agent reading its own diary or a covered empty one).
    Granted {
        read: Option<EntityId>,
        entries: Vec<DiaryQueryEntry>,
    },
    /// The agent reviews reads first; `request` waits for its answer.
    PendingReview { request: EntityId },
    /// The agent said no to this caller's reason.
    Declined { request: EntityId },
    /// No `diary.read` Grant of the caller covers this diary.
    NotCovered,
}

impl From<DiaryReadOutcome> for DiaryQueryOutcome {
    fn from(outcome: DiaryReadOutcome) -> Self {
        match outcome {
            DiaryReadOutcome::Granted { read, entries } => Self::Granted {
                read,
                entries: entries
                    .into_iter()
                    .map(|entry| DiaryQueryEntry {
                        id: entry.id,
                        learned_at: entry.learned_at,
                        markdown: entry.markdown,
                    })
                    .collect(),
            },
            DiaryReadOutcome::PendingReview { request } => Self::PendingReview { request },
            DiaryReadOutcome::Declined { request } => Self::Declined { request },
            DiaryReadOutcome::NotCovered => Self::NotCovered,
        }
    }
}

/// `self.memory.pads.admin_reads`'s input: whose sealed pads.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdminPadReadsRequest {
    /// The agent, as 32 hex.
    pub agent: String,
}

/// `self.memory.pads.admin_reads`'s answer: each read a work vault's Admin
/// made of the agent's sealed pads, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AdminPadReadsView {
    pub reads: Vec<DiaryReadRecord>,
}
