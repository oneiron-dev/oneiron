//! Moved from `crates/oneiron/src/consult_ladder/ladder_state.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Terminal ladder outcome. `Rejected` is a completed decision; `Failed` is
/// retry/infrastructure semantics. Collapsing them would erase the difference
/// between "the owner said no" and "the machine broke".
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LadderTerminalDisposition {
    Approved,
    Overridden,
    Rejected,
    Failed,
    Escalated,
    Countered,
    Abandoned,
}

impl LadderTerminalDisposition {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Overridden => "overridden",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::Escalated => "escalated",
            Self::Countered => "countered",
            Self::Abandoned => "abandoned",
        }
    }

    /// Parses one wire token, or `None` for an unknown one.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "approved" => Some(Self::Approved),
            "overridden" => Some(Self::Overridden),
            "rejected" => Some(Self::Rejected),
            "failed" => Some(Self::Failed),
            "escalated" => Some(Self::Escalated),
            "countered" => Some(Self::Countered),
            "abandoned" => Some(Self::Abandoned),
            _ => None,
        }
    }

    /// Whether this outcome leaves the TASK non-terminal. `Escalated` hands
    /// the case to a follow-on assignee, so ONE-1699 persists it as
    /// `Interrupted` rather than as a terminal record.
    #[must_use]
    pub const fn defers_to_follow_on(self) -> bool {
        matches!(self, Self::Escalated)
    }
}
