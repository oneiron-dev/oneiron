//! Own-rate advisory thresholds and first-crossing check records.

use serde::{Deserialize, Serialize};

/// What an own-rate window counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnRateKind {
    /// Task creates and asks by one actor.
    TaskCreate,
    /// Claims an agent wrote as Auto.
    AutoWrite,
    /// Wrong labels one reader filed on one weave link or item.
    WeaveCorrection,
    /// Consult fan-out requests by one actor, one count per request.
    ConsultFanout,
}

impl OwnRateKind {
    pub const fn token(self) -> &'static str {
        match self {
            Self::TaskCreate => "task_create",
            Self::AutoWrite => "auto_write",
            Self::WeaveCorrection => "weave_correction",
            Self::ConsultFanout => "consult_fanout",
        }
    }
}

/// An advisory threshold and the window it counts over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnRate {
    pub threshold: u64,
    pub window_seconds: u64,
}

/// OF-520 question at an own actor's first threshold crossing in one window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnRateCheck {
    pub kind: OwnRateKind,
    pub actor: String,
    pub window_started_at: u64,
    /// 0 for a count with no time window, such as every report on one link.
    pub window_seconds: u64,
    pub count: u64,
    pub threshold: u64,
}

impl OwnRateCheck {
    pub const KIND: &'static str = "own_rate_burst";
}
