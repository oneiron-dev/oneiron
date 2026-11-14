//! Moved from `crates/oneiron/src/dreamer_runner/free_time/doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::agent_dispatch::budget_doors::RunRungSettlement;
use crate::dreamer_runner::free_time::cycle::FreeTimeCycleState;
use crate::dreamer_runner::free_time::policy::FreeTimeSchedule;
use crate::dreamer_runner::free_time::policy::FreeTimeSplit;
use crate::dreamer_runner::free_time::receipt::FreeTimeFloor;
use crate::dreamer_runner::free_time::receipt::FreeTimeItemOutcome;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// One agent's free-time policy.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreeTimePolicyRequest {
    /// The agent definition, 32 hex.
    pub agent: String,
}

/// Whether an agent has a free-time policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FreeTimePolicyState {
    /// The owner set one: a cycle opens at each of its boundaries.
    Set,
    /// None is set: no cycle, no floor and no free-time spend, and the agent
    /// keeps its nightly dreaming.
    Disabled,
}

/// The owner's policy as the engine keeps it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimePolicyRow {
    /// The most one cycle may spend, in `unit`.
    pub total_units: u64,
    pub unit: String,
    pub schedule: FreeTimeSchedule,
    pub pinned_split: Option<FreeTimeSplit>,
    /// When the owner was shown the recurring cap and accepted it, in host
    /// milliseconds.
    pub cap_shown_at_ms: u64,
    /// The owner who set it, as the vault revalidated them, 32 hex; `None`
    /// once that owner was erased.
    pub set_by: Option<String>,
    /// Vault clock seconds.
    pub set_at: u64,
}

/// One agent's free-time policy and the revision a set or clear names.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimePolicyView {
    pub agent: String,
    pub state: FreeTimePolicyState,
    /// The revision a set or clear names as `expected_revision`: 0 while
    /// none is set.
    pub revision: u64,
    /// `None` while Disabled.
    pub policy: Option<FreeTimePolicyRow>,
}

/// One page of an agent's free-time cycles, newest first.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeCyclesRequest {
    /// The agent definition, 32 hex.
    pub agent: String,
    /// The `next` a previous page answered; absent for the newest page.
    #[serde(default)]
    pub cursor: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One cycle as a list shows it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimeCycleSummary {
    pub cycle: String,
    pub state: FreeTimeCycleState,
    pub policy_revision: u64,
    pub total_units: u64,
    /// Unix seconds: the boundary before this one, 0 when none was found.
    pub period_start: u64,
    /// Unix seconds: the owner-set boundary it opened at.
    pub boundary: u64,
    /// Unix seconds: the next boundary, at which it ends at the latest.
    pub next_boundary: Option<u64>,
    pub opened_at: u64,
    pub closed_at: Option<u64>,
    /// The floor, from the item receipts alone.
    pub floor: FreeTimeFloor,
    /// Whether every item receipt read; when not, the floor is Unknown.
    pub items_complete: bool,
    /// Whether the agent left its human a note.
    pub has_note: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimeCyclesPage {
    pub agent: String,
    pub cycles: Vec<FreeTimeCycleSummary>,
    /// The cursor of the next, older page; `None` when this page holds the
    /// agent's oldest cycle.
    pub next: Option<String>,
}

/// One cycle of one agent.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FreeTimeCycleRequest {
    /// The agent definition, 32 hex.
    pub agent: String,
    /// The cycle, 32 hex.
    pub cycle: String,
}

/// An item's terminal receipt: how it ended, never what it said.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimeItemReceiptView {
    pub outcome: FreeTimeItemOutcome,
    pub policy_revision: u64,
    /// The attempt that ran it, 32 hex; `None` for rest chosen with no
    /// attempt.
    pub attempt: Option<String>,
    /// The Proposed claim a for-human item landed, 32 hex.
    pub proposal: Option<String>,
    /// The code of a for-human item's read of its human's context that
    /// failed: the item ran on its own records. `None` when that context
    /// read, or there was none to read.
    pub context_unread: Option<String>,
    /// Vault clock seconds.
    pub at: u64,
}

/// The agent's own short note to its human, never its diary.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimeNoteView {
    pub author: String,
    /// Vault clock seconds.
    pub at: u64,
    pub text: String,
}

/// One label's spend records.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimeLabelSpend {
    /// The label its calls carried; `None` for a record that named none.
    pub purpose: Option<String>,
    /// Each settled physical call, oldest first, with its run, item and
    /// scope refs, its reserved and settled quantities and unit, its
    /// stamped provider cost when it was priced, and its `source`: `engine`
    /// or `posted`, the path that wrote its record. An unpriced call has no
    /// cost; it is never zero.
    pub settlements: Vec<RunRungSettlement>,
}

/// A cycle's spending records, by label. No total: an unpriced call would
/// make one a floor, never the bill.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FreeTimeSpendView {
    /// False when no usage ledger answered (an embedded vault, or a server
    /// that has not bound its usage ledger to an account): the spend is not
    /// known, and none of it reads as zero.
    pub metering_enabled: bool,
    /// Whether every stored spend record read. Always false while metering
    /// is off.
    pub complete: bool,
    pub by_label: Vec<FreeTimeLabelSpend>,
}

impl FreeTimeSpendView {
    /// The spend of a read no usage ledger answered.
    #[must_use]
    pub fn unmetered() -> Self {
        Self {
            metering_enabled: false,
            complete: false,
            by_label: Vec::new(),
        }
    }

    /// A cycle's spend from its settled calls, as a usage ledger read them;
    /// `complete` says every stored record read.
    #[must_use]
    pub fn metered(settlements: Vec<RunRungSettlement>, complete: bool) -> Self {
        let mut labels: BTreeMap<Option<String>, Vec<RunRungSettlement>> = BTreeMap::new();
        for settlement in settlements {
            labels
                .entry(settlement.purpose.clone())
                .or_default()
                .push(settlement);
        }
        Self {
            metering_enabled: true,
            complete,
            by_label: labels
                .into_iter()
                .map(|(purpose, settlements)| FreeTimeLabelSpend {
                    purpose,
                    settlements,
                })
                .collect(),
        }
    }
}
