//! Moved from `crates/oneiron/src/agent_dispatch/spend_record.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::agent_dispatch::spend_calibration::AgentSpendCalibration;
pub use crate::workspace_roster::spend_scope::SpendState;
use heed::RwTxn;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// The payer's consent a root scope carries (OF-531): this PERSON was shown
/// the root's cap and accepted it for this scope. Children inherit it by
/// walking to their root; it is never copied. A cap, a scope id or an attempt
/// id is never this evidence by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpendPayer {
    /// The PERSON whose funds the tree spends.
    pub party: EntityId,
    /// The actor that took the payer's yes: the payer's own PERSON, or an
    /// actor anchored to it. Checked against the stored binding, never a label;
    /// `None` once the actor that took the yes was erased.
    pub granted_by: Option<EntityId>,
    /// When the payer accepted the cap, in host milliseconds.
    pub at_ms: u64,
}

/// The local calibration state before one scope's sample was folded.
/// The wrapper distinguishes the first sample (`before: None`) from a scope
/// that never contributed a sample on this vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpendCalibrationSample {
    pub before: Option<AgentSpendCalibration>,
}

impl SpendCalibrationSample {
    pub fn ordinal(&self) -> u64 {
        self.before.as_ref().map_or(0, |row| row.samples)
    }
}

/// What a spend crossed. The lease's own Suspend is the stop; these steer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "signal", rename_all = "snake_case")]
pub enum SpendSignal {
    /// At most 5 percent of the binding hard cap is left: start no new work,
    /// save partial results. Returned at every spend from here on.
    WrapUp {
        available_units: u64,
        cap_units: u64,
    },
    /// Nothing is left under the binding hard cap.
    AtCap { cap_units: u64 },
}
