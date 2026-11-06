//! Inbox item kinds, ordering impact, diary-review input and receiving participants.

use oneiron_contracts::entity_id::EntityId;

pub const AGENT_INBOX_LENS_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InboxImpact(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentInboxItemKind {
    Conversation,
    ApprovalRequired,
    CoordinationUpdate,
    /// An agent-health card (ARCH-0063 concern cards): under "Waiting on
    /// you" with its own mark, grouped per agent by its subject.
    Concern,
    /// A digest NOTIFICATION addressed to this agent alone and not yet
    /// acknowledged (FIX 1261): under updates, at the lowest impact. The
    /// vault itself sent it, so no identity carries it.
    Digest,
}

/// Who waits on a pending diary-read review, and why (OF-490): the row's
/// agent answers it through `self.memory.diary.review`. The reason is the
/// reader's words, data and never an instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentInboxDiaryReview {
    pub request: EntityId,
    pub reader: EntityId,
    pub reader_class: String,
    pub reason: String,
}

/// One receiving identity on a row and the actor it is bound to. `None` is
/// no identity: a row the vault itself addresses to the actor, such as a
/// digest, arrives on none, and none is invented for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentInboxParticipant {
    pub identity_ref: Option<EntityId>,
    pub actor_ref: EntityId,
}
