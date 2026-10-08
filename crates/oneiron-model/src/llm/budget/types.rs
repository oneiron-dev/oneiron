//! Public budget DTOs and the exhaustion policy.

use serde::{Deserialize, Serialize};

use super::ledger::percent_used;
use super::templates::{BUDGET_LAND_PROMPT_TEMPLATE_ID, BUDGET_PLAN_PROMPT_TEMPLATE_ID};
use crate::llm::BudgetLease;

pub const DEFAULT_BUDGET_RESERVE_UNITS: u64 = 8_000;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BudgetExhaustionPolicy {
    #[default]
    Suspend,
    ContinueOnLocal,
    Overdraft {
        cap: u64,
    },
}

impl BudgetExhaustionPolicy {
    #[must_use]
    pub fn admission_cap(self, limit_units: u64) -> u64 {
        match self {
            Self::Suspend | Self::ContinueOnLocal => limit_units,
            Self::Overdraft { cap } => limit_units.saturating_add(cap),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetThreshold {
    Silent50,
    Plan80,
    Land95,
}

impl BudgetThreshold {
    #[must_use]
    pub fn percent(self) -> u64 {
        match self {
            Self::Silent50 => 50,
            Self::Plan80 => 80,
            Self::Land95 => 95,
        }
    }

    #[must_use]
    pub fn template_id(self) -> Option<&'static str> {
        match self {
            Self::Silent50 => None,
            Self::Plan80 => Some(BUDGET_PLAN_PROMPT_TEMPLATE_ID),
            Self::Land95 => Some(BUDGET_LAND_PROMPT_TEMPLATE_ID),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetSignalDeliveryChannel {
    SteeringQueueNextTurn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetSteeringSignal {
    pub threshold: BudgetThreshold,
    pub channel: BudgetSignalDeliveryChannel,
    pub template_id: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetLadderEvent {
    pub threshold: BudgetThreshold,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub steering: Option<BudgetSteeringSignal>,
    /// Which policy row of the EMITTING meter fired this event. `Some(i)` is
    /// the resolved row index of that meter's own policy table — effector
    /// key/compiled-cap rows (GOV-02) or LLM `BudgetPolicyTable` rows; `None`
    /// is a meter's global ladder. A call or dispatch matching several rows can
    /// cross the same threshold on more than one; the row identity keeps those
    /// events distinguishable so a steering consumer can dedupe or present
    /// per-dimension. Indices are only meaningful against the emitting meter's
    /// table: consumers keying off them, including the effector ladder emitters
    /// in `connector_key.rs`, already filter their own meter's events.
    /// Wire-compatible: absent when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_index: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetRead {
    #[serde(rename = "job_id")] // wire key pinned pre-rename (ONE-1714)
    pub attempt_id: String,
    pub limit_units: u64,
    pub cap_units: u64,
    pub used_units: u64,
    pub reserved_units: u64,
    pub remaining_units: u64,
    pub on_budget_exhausted: BudgetExhaustionPolicy,
    pub fired_thresholds: Vec<BudgetThreshold>,
}

impl BudgetRead {
    #[must_use]
    pub fn depleted_percent(&self) -> u64 {
        percent_used(
            self.used_units.saturating_add(self.reserved_units),
            self.limit_units,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetAdmission {
    pub lease: BudgetLease,
    pub read: BudgetRead,
    pub ladder_events: Vec<BudgetLadderEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetSettlement {
    pub read: BudgetRead,
    pub ladder_events: Vec<BudgetLadderEvent>,
}
