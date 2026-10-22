//! Context-bearing text replies through the host's configured inference door.
use serde::{Deserialize, Serialize};

/// The conversation and reader whose admitted context reaches one configured model.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiReplyRequest {
    /// An exact configured model row, not a seat or a caller-selected route.
    pub model: String,
    pub conversation_id: String,
    pub message: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub reader: Option<AiReplyReader>,
    #[serde(default)]
    pub budget: Option<crate::code_run::vault_read::ContextPackBudgetControls>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub pinned_refs: Vec<String>,
    #[serde(default)]
    pub companion: Option<AiReplyCompanion>,
    #[serde(default)]
    pub standing: Option<AiReplyStanding>,
    #[serde(default)]
    pub reasoning_effort: Option<String>,
}

/// The existing optional-memory profile, which only narrows recall.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiReplyReader {
    pub definition: String,
    #[serde(default)]
    pub task_family: Option<String>,
}

/// Identity subjects for the existing scoped, score-free L2 evidence projection.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiReplyCompanion {
    #[serde(default)]
    pub person_ref: Option<String>,
    /// The PERSON at the relationship's other end (FIX 871).
    #[serde(default)]
    pub counterpart_person_ref: Option<String>,
    #[serde(default)]
    pub expression: Option<String>,
}

/// The existing standing-block reservation, never a replacement block supplied by a caller.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiReplyStanding {
    #[serde(default)]
    pub world_ref: Option<String>,
    pub token_budget: usize,
    #[serde(default)]
    pub block_tokens: Option<usize>,
}

/// The exact score-free evidence prefix sent before the dynamic board.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiReplyL2Base {
    pub content_hash: String,
    pub body: String,
}

/// A real buffered model reply and refs to its durable emit-time context, not a pack preview.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiReply {
    pub reply: String,
    pub model: String,
    pub receipt_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l2_base: Option<AiReplyL2Base>,
}
