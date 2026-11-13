//! Moved from `crates/oneiron/src/dreamer_runner/free_time/mod.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::dreamer_runner::free_time::cycle::FreeTimeCycleState;
pub use crate::dreamer_runner::free_time::doors::FreeTimeCycleRequest;
pub use crate::dreamer_runner::free_time::doors::FreeTimeCycleSummary;
pub use crate::dreamer_runner::free_time::doors::FreeTimeCycleView;
pub use crate::dreamer_runner::free_time::doors::FreeTimeCyclesPage;
pub use crate::dreamer_runner::free_time::doors::FreeTimeCyclesRequest;
pub use crate::dreamer_runner::free_time::doors::FreeTimeItemReceiptView;
pub use crate::dreamer_runner::free_time::doors::FreeTimeItemView;
pub use crate::dreamer_runner::free_time::doors::FreeTimeLabelSpend;
pub use crate::dreamer_runner::free_time::doors::FreeTimeNoteView;
pub use crate::dreamer_runner::free_time::doors::FreeTimePolicyRequest;
pub use crate::dreamer_runner::free_time::doors::FreeTimePolicyRow;
pub use crate::dreamer_runner::free_time::doors::FreeTimePolicyState;
pub use crate::dreamer_runner::free_time::doors::FreeTimePolicyView;
pub use crate::dreamer_runner::free_time::doors::FreeTimeSpendView;
pub use crate::dreamer_runner::free_time::policy::FreeTimeCadence;
pub use crate::dreamer_runner::free_time::policy::FreeTimeSchedule;
pub use crate::dreamer_runner::free_time::policy::FreeTimeSplit;
pub use crate::dreamer_runner::free_time::receipt::FreeTimeFloor;
pub use crate::dreamer_runner::free_time::receipt::FreeTimeItemOutcome;
use oneiron_model::llm::CallPurpose;
use serde::Deserialize;
use serde::Serialize;

/// The two kinds of an agent's free time, by the label its calls carry.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FreeTimeKind {
    /// `autonomy.for_human`: it thinks how to help its human, and what it
    /// suggests lands as a proposal.
    ForHuman,
    /// `autonomy.own_time`: its own reading, fun and rest. Nothing scores it.
    OwnTime,
}

impl FreeTimeKind {
    /// The purpose label every call of this kind carries.
    #[must_use]
    pub fn purpose(self) -> CallPurpose {
        match self {
            Self::ForHuman => CallPurpose::AutonomyForHuman,
            Self::OwnTime => CallPurpose::AutonomyOwnTime,
        }
    }

    /// The byte an item's id is derived with.
    const fn code(self) -> u8 {
        match self {
            Self::ForHuman => 1,
            Self::OwnTime => 2,
        }
    }
}
pub mod cycle;
pub mod doors;
pub mod policy;
pub mod receipt;
