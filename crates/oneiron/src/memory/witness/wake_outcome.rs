//! What a landed turn's program wake came to (DOOR-141, FIX 9970): the
//! accepted turn's receipt says it, so a wake the turn could not record is
//! visible to its caller, not only logged. The turn is accepted either way;
//! a wake that fails rolls back alone.

use serde::{Deserialize, Serialize};

/// The outcome of the wake a landed turn owes its actor's armed programs.
/// A turn that owes none (off record, an import, a host door's turn, or one
/// that lands no new words) carries no outcome at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum TurnProgramWakeOutcome {
    /// The actor has no program armed: no wake is owed.
    NotArmed,
    /// The armed programs were judged and their wakes recorded in the turn's
    /// commit. `newly_recorded` counts the wakes this landing added; zero
    /// means none matched or each was already recorded, not that one failed.
    Evaluated {
        /// Wakes this landing recorded.
        newly_recorded: u32,
    },
    /// The turn's wake was not recorded, and no program wakes for it.
    Unpersisted {
        /// Why the wake was not recorded.
        reason: UnpersistedWakeReason,
    },
}

impl TurnProgramWakeOutcome {
    /// The outcome's wire name, as its `outcome` tag spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotArmed => "not_armed",
            Self::Evaluated { .. } => "evaluated",
            Self::Unpersisted { .. } => "unpersisted",
        }
    }
}

/// Why a turn's program wake was not recorded. It names the class of cause
/// only; the storage error and the caller's authority stay out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnpersistedWakeReason {
    /// The turn's caller seals no authority a program could run under (an
    /// operator root acting as nobody, a code run's call, a machine-signed
    /// write).
    NoAuthority,
    /// Reading the armed programs or writing the wake failed in storage.
    StorageFailure,
}

impl UnpersistedWakeReason {
    /// The reason's wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoAuthority => "no_authority",
            Self::StorageFailure => "storage_failure",
        }
    }
}
