//! Moved from `crates/oneiron/src/failure_ladder/task_terminal.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::RecordError;
use oneiron_base::error::Result;

/// Terminal outcomes for ANY executor. `Expired` (deadline passed) and
/// `Abandoned` (lease reclaimed / executor gone) stay distinct causes even
/// though both project onto the failed board lane.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TaskTerminalDisposition {
    Completed,
    Rejected,
    Failed,
    Expired,
    Abandoned,
    Cancelled,
}

impl TaskTerminalDisposition {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::Expired => "expired",
            Self::Abandoned => "abandoned",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn from_token(token: &str) -> Result<Self> {
        match token {
            "completed" => Ok(Self::Completed),
            "rejected" => Ok(Self::Rejected),
            "failed" => Ok(Self::Failed),
            "expired" => Ok(Self::Expired),
            "abandoned" => Ok(Self::Abandoned),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(Error::Record(RecordError::InvalidTaskBody(
                "tasks.terminal.disposition",
            ))),
        }
    }
}
