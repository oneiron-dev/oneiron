//! Moved from `crates/oneiron/src/runtime_hooks/lineage.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::register::Register;
use serde::Deserialize;
use serde::Serialize;

/// Why a check was raised.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Register,
)]
#[serde(rename_all = "snake_case")]
#[register("hook.check.reason")]
pub enum HookCheckReason {
    /// The same hook fired again inside its own causal chain.
    Cycle,
    /// The chain reached [`MAX_LINEAGE_DEPTH`].
    Depth,
}
