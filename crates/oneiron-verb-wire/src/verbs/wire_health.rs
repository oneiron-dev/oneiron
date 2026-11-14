//! Moved from `crates/oneiron/src/verbs/wire_health.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WireThresholds {
    pub window_secs: u64,
    pub per_verb: u64,
    pub per_actor: u64,
}

impl Default for WireThresholds {
    fn default() -> Self {
        Self {
            window_secs: 60,
            per_verb: 50_000_000,
            per_actor: 1_000_000,
        }
    }
}

impl WireThresholds {
    /// Every detection row and its window must be positive.
    pub fn validate(&self) -> Result<()> {
        if self.window_secs == 0 || self.per_verb == 0 || self.per_actor == 0 {
            Err(Error::InvalidConfig(
                "RC42 thresholds must be positive".into(),
            ))
        } else {
            Ok(())
        }
    }
}

/// The policy replaced and the policy installed by one owner edit.
#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WireThresholdsReceipt {
    pub previous: WireThresholds,
    pub thresholds: WireThresholds,
}
