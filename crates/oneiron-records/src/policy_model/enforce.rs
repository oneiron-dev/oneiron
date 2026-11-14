//! Moved from `crates/oneiron/src/policy_model/enforce.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::policy_model::verdict::PolicyClassifyDecision;
use crate::policy_model::verdict::PolicyVerdictCategory;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEnforcementAction {
    Allow,
    Warn,
    Reword,
    Block,
    RouteToHelp,
    Hold,
    /// The owner plane's model did not answer. The content is delivered
    /// unread, because that plane is sovereign, and it is never reported as
    /// an `Allow`.
    Skipped,
}

impl PolicyEnforcementAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Reword => "reword",
            Self::Block => "block",
            Self::Hold => "hold",
            Self::RouteToHelp => "route_to_help",
            Self::Skipped => "skipped",
        }
    }

    const fn for_decision(decision: PolicyClassifyDecision) -> Self {
        match decision {
            PolicyClassifyDecision::Allow => Self::Allow,
            PolicyClassifyDecision::Warn => Self::Warn,
            PolicyClassifyDecision::Reword => Self::Reword,
            PolicyClassifyDecision::Block => Self::Block,
            PolicyClassifyDecision::Hold => Self::Hold,
            PolicyClassifyDecision::RouteToHelp => Self::RouteToHelp,
            PolicyClassifyDecision::Skipped(_) => Self::Skipped,
        }
    }

    /// Whether the caller must not deliver the content. `Warn` and `Skipped`
    /// deliver.
    #[must_use]
    pub const fn halts(self) -> bool {
        matches!(
            self,
            Self::Reword | Self::Block | Self::RouteToHelp | Self::Hold
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEnforcementVoice {
    Persona,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBargeInKill {
    pub cancel_tts: bool,
    pub flush_playout_buffer: bool,
    pub cancel_llm: bool,
}

impl PolicyBargeInKill {
    const fn full_flush() -> Self {
        Self {
            cancel_tts: true,
            flush_playout_buffer: true,
            cancel_llm: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyHelpRouting {
    pub category: PolicyVerdictCategory,
    pub message: String,
    pub diagnosis: Option<String>,
    pub persona_present: bool,
    /// Host-configured resources, not an engine-owned safety taxonomy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<oneiron_store::gate_decision::types::GateSystemNoticeAction>,
}
