//! Moved from `crates/oneiron/src/verbs/anonymous_chat.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::policy_model::verdict::PolicySkipReason;
use oneiron_model::llm::ModelId;
use oneiron_store::gate_decision::types::GateSystemNoticeRecord;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnonymousChatRequestTarget {
    #[default]
    HouseMind,
    PlainModel,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnonymousChatRequest {
    pub text: String,
    #[serde(default)]
    pub target: AnonymousChatRequestTarget,
    /// A configured provider model id, required only for plain_model.
    pub model: Option<ModelId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AnonymousChatResponse {
    Reply {
        content: String,
        notices: Vec<GateSystemNoticeRecord>,
        skipped_checks: Vec<AnonymousChatSkippedCheckView>,
        /// The same notices, in the same order, for the model's notice
        /// channel. Neither channel is a chat message or a retained turn.
        model_notices: Vec<GateSystemNoticeRecord>,
    },
    Blocked {
        input: bool,
        notice: Box<GateSystemNoticeRecord>,
        preceding_notices: Vec<GateSystemNoticeRecord>,
        reason: AnonymousChatBlockReasonView,
        model_notices: Vec<GateSystemNoticeRecord>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AnonymousChatSkippedCheckView {
    pub input: bool,
    pub reason: PolicySkipReason,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnonymousChatBlockReasonView {
    Policy,
    HumanReviewUnavailable,
}
