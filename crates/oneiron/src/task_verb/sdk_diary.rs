//! `self.memory.diary.query`: the caller reads an agent's private diary,
//! stating a reason the agent sees in its read log (OF-490, ONE-2510). The
//! door is [`Memory::read_agent_diary`]: the caller's `diary.read` Grants
//! decide which entries it gets, an agent that reviews answers the reason
//! first, and a person reads with their authentication. This file is the
//! row's wire: its bounded input, and the door's outcome as a closed DTO a
//! remote client decodes.
use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::memory::{DiaryReadOutcome, Memory, MemoryError, MemoryResult};
use crate::{EdgeActorClass, EntityId};

/// The longest reason a diary read states, in bytes; the gate holds the same
/// bound.
const DIARY_QUERY_REASON_MAX_BYTES: usize = 512;

/// `self.memory.diary.query`'s input: whose diary, and the one-line reason
/// the read states.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiaryQueryRequest {
    /// Whose diary, as 32 hex.
    pub agent: String,
    /// Why the caller reads; the agent sees it. One line of at most 512
    /// bytes.
    pub reason: String,
}

impl DiaryQueryRequest {
    /// Refuses an agent that is not an entity id, and a reason that is empty,
    /// longer than 512 bytes or more than one line.
    pub fn validate(&self) -> MemoryResult<()> {
        self.agent_id()?;
        let reason = self.reason.trim();
        if reason.is_empty()
            || reason.len() > DIARY_QUERY_REASON_MAX_BYTES
            || reason.contains(['\n', '\r'])
        {
            return Err(MemoryError::bad_request(
                "reason is one non-empty line of at most 512 bytes",
            ));
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

/// `self.memory.diary.query` on a handle: reads as the handle's actor, under
/// the owner proof its host bound when the owner made this request in person
/// ([`Memory::with_owner_authorship`]), else the embedded owner's own proof
/// when the handle is that owner ([`Memory::embedded_owner`]), and none
/// otherwise. Any other person's surface is refused; an agent or system
/// reads as itself.
pub fn self_memory_diary_query_embedded(
    memory: &Memory<'_>,
    input: DiaryQueryRequest,
) -> MemoryResult<DiaryQueryOutcome> {
    let embedded = match memory.owner_authorship() {
        None if memory.actor_class() == EdgeActorClass::Human => {
            memory.embedded_owner("self.memory.diary.query").ok()
        }
        _ => None,
    };
    let proof = memory.owner_authorship().or(embedded.as_ref());
    diary_query_as(memory, proof, input)
}

/// `self.memory.diary.query` under `proof`: the server's host door passes the
/// owner proof the caller's credential carries, or none, and the gate decides.
pub fn diary_query_as(
    memory: &Memory<'_>,
    proof: Option<&AuthenticatedOwner>,
    input: DiaryQueryRequest,
) -> MemoryResult<DiaryQueryOutcome> {
    input.validate()?;
    let agent = input.agent_id()?;
    Ok(memory.read_agent_diary(proof, agent, &input.reason)?.into())
}
