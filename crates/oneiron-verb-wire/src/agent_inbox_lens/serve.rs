//! Moved from `crates/oneiron/src/agent_inbox_lens/serve.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::edge::EdgeActorClass;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::inbox::view_values::AgentInboxItemKind;
use oneiron_store::inbox::view_values::InboxImpact;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboxLensRequest {
    #[serde(default)]
    pub identity: Option<String>,
    /// Owner view only; an ordinary reader always gets its own slice.
    #[serde(default)]
    pub agent: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub before_impact: Option<u16>,
    #[serde(default)]
    pub before_at: Option<u64>,
    #[serde(default)]
    pub before_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxLensPage {
    pub items: Vec<InboxLensRow>,
    pub concern_groups: Vec<InboxConcernGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxConcernGroup {
    pub agent: String,
    pub items: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InboxLensKind {
    Conversation,
    WaitingOnYou,
    CoordinationUpdate,
    Concern,
    /// A digest addressed to the reader alone (FIX 1261).
    Digest,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InboxLensPile {
    Conversations,
    WaitingOnYou,
    Updates,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxLensRow {
    pub item_id: String,
    pub kind: InboxLensKind,
    pub pile: InboxLensPile,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_ref: Option<String>,
    /// The receiving identity; absent on a row the vault itself sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    pub actor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facet: Option<String>,
    pub participants: Vec<InboxLensParticipant>,
    pub impact: u16,
    pub occurred_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
    /// The held outbound receipt's approve-once digest, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concern: Option<InboxLensConcern>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diary_review: Option<InboxLensDiaryReview>,
    /// Who the row is from, as 32 hex: the author of its newest inbound
    /// message with admitted provenance (FIX 9745); absent where none has.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    /// The widening a comm widen ask asks for (FIX 3901).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub widening: Option<crate::context_board::tasks::projection::ConsultWidening>,
    /// The reader's own read state of the row (OF-414): present only on the
    /// slice of the actor that reads it, whose state it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_state: Option<super::AgentInboxReadState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxLensParticipant {
    /// The receiving identity; absent on a row the vault itself sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    pub actor: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxLensConcern {
    pub agent: String,
    pub signal: String,
    pub tone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxLensDiaryReview {
    pub request: String,
    pub reader: String,
    pub reader_class: String,
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InboxRunGroupsRequest {
    #[serde(default)]
    pub limit: Option<usize>,
    /// A previous page's `next`: this page resumes after the groups that
    /// page served.
    #[serde(default)]
    pub after: Option<String>,
}
