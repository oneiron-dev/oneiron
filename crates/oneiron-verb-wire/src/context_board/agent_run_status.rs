//! Moved from `crates/oneiron/src/context_board/agent_run_status.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunStatus {
    Spawned,
    Working,
    NeedsInput,
    Delivered,
    Archived,
    Failed,
    Abandoned,
    /// Stopped by a cancel (an owner's or an operator's force, a lease the
    /// runtime fenced, or a cancel before it started), not by a fault.
    Cancelled,
}

impl AgentRunStatus {
    pub const RATIFIED_FLOW: [Self; 5] = [
        Self::Spawned,
        Self::Working,
        Self::NeedsInput,
        Self::Delivered,
        Self::Archived,
    ];

    pub const ALL: [Self; 8] = [
        Self::Spawned,
        Self::Working,
        Self::NeedsInput,
        Self::Delivered,
        Self::Archived,
        Self::Failed,
        Self::Abandoned,
        Self::Cancelled,
    ];

    pub const TERMINAL: [Self; 4] = [
        Self::Archived,
        Self::Failed,
        Self::Abandoned,
        Self::Cancelled,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Spawned => "spawned",
            Self::Working => "working",
            Self::NeedsInput => "needs_input",
            Self::Delivered => "delivered",
            Self::Archived => "archived",
            Self::Failed => "failed",
            Self::Abandoned => "abandoned",
            Self::Cancelled => "cancelled",
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Archived | Self::Failed | Self::Abandoned | Self::Cancelled
        )
    }

    #[must_use]
    pub const fn is_live_presence(self) -> bool {
        matches!(self, Self::Spawned | Self::Working | Self::NeedsInput)
    }

    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Spawned, Self::Spawned)
                | (Self::Working, Self::Working)
                | (Self::NeedsInput, Self::NeedsInput)
                | (Self::Delivered, Self::Delivered)
                | (Self::Archived, Self::Archived)
                | (Self::Failed, Self::Failed)
                | (Self::Abandoned, Self::Abandoned)
                | (Self::Cancelled, Self::Cancelled)
                | (
                    Self::Spawned,
                    Self::Working | Self::Failed | Self::Abandoned | Self::Cancelled
                )
                | (
                    Self::Working,
                    Self::NeedsInput
                        | Self::Delivered
                        | Self::Failed
                        | Self::Abandoned
                        | Self::Cancelled
                )
                | (
                    Self::NeedsInput,
                    Self::Working | Self::Failed | Self::Abandoned | Self::Cancelled
                )
                | (Self::Delivered, Self::Archived)
        )
    }
}
