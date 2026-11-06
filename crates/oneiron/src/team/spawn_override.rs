use serde::{Deserialize, Serialize};

/// One spawn field as the parent set it (ARCH-0079 #seed-pin): a seed sets
/// where the planner starts, with a weight counted in runs; a pin fixes the
/// value and the planner never overrides it. Unset fields are the planner's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SpawnOverride<T> {
    Seed { value: T, weight_runs: f64 },
    Pin { value: T },
}

impl<T> SpawnOverride<T> {
    #[must_use]
    pub const fn value(&self) -> &T {
        match self {
            Self::Seed { value, .. } | Self::Pin { value } => value,
        }
    }

    #[must_use]
    pub const fn is_pin(&self) -> bool {
        matches!(self, Self::Pin { .. })
    }

    /// Prior weight in runs; a pin is a seed of infinite weight.
    #[must_use]
    pub fn weight_runs(&self) -> f64 {
        match self {
            Self::Seed { weight_runs, .. } => *weight_runs,
            Self::Pin { .. } => f64::INFINITY,
        }
    }
}
