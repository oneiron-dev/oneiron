//! The refusal dial (OF-533) an agent definition stores: one position from
//! none to full, and the agent's explicit setting per domain.

use serde::{Deserialize, Serialize};

/// The pinned sub-map keys for a [`RefusalDial`], in encode order. Each is
/// the wire string of its [`RefusalDomain`].
pub const REFUSAL_DIAL_KEYS: [&str; 2] = ["bond", "logistics"];

/// What a refusal concerns. The agent names it when she refuses, and her dial
/// may sit differently for each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalDomain {
    /// The bond itself: what she is asked to be, or to do to it.
    Bond,
    /// The mechanics of the work: arrangements, errands, scheduling.
    Logistics,
}

impl RefusalDomain {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bond => REFUSAL_DIAL_KEYS[0],
            Self::Logistics => REFUSAL_DIAL_KEYS[1],
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "bond" => Some(Self::Bond),
            "logistics" => Some(Self::Logistics),
            _ => None,
        }
    }
}

