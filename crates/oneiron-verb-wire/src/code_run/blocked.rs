//! Moved from `crates/oneiron/src/code_run/blocked.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::register::Register;
use serde::Deserialize;
use serde::Serialize;

#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema, Register,
)]
#[serde(rename_all = "snake_case")]
#[register("blocked.category")]
pub enum BlockedCategory {
    Tool,
    Permission,
    Context,
    Environment,
}
