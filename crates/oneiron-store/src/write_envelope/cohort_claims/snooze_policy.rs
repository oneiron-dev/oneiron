//! Declarative pause dials carried by cohort records.

use serde::{Deserialize, Serialize};

/// The positive-later snooze, expressed as dials rather than scheduling code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnoozePolicyData {
    /// Shortest admissible pause.
    pub min_secs: u64,
    /// Pause taken when the reply names no date, counted from the reply.
    pub default_secs: u64,
    /// Longest admissible pause.
    pub max_secs: u64,
    /// Whether a fresh trigger also wakes the membership. Combined with a timed
    /// wake this drives CA-01's paused form with BOTH fields set.
    pub wake_on_new_trigger: bool,
    /// Always 0: re-entry restarts at touch 1.
    pub restart_touch_index: u32,
}

impl SnoozePolicyData {
    /// The snooze dials as JSON, the shape `defaults.json` and a preset carry.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "min_secs": self.min_secs,
            "default_secs": self.default_secs,
            "max_secs": self.max_secs,
            "wake_on_new_trigger": self.wake_on_new_trigger,
            "restart_touch_index": self.restart_touch_index,
        })
    }
}
