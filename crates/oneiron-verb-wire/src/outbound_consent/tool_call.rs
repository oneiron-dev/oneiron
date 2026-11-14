//! Moved from `crates/oneiron/src/outbound_consent/tool_call.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MutationIntent {
    #[default]
    Preview,
    ExplicitMutation,
}
