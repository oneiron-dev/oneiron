//! Moved from `crates/oneiron/src/verbs/self_verbs.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::dreamer_runner::maintenance::agent_health::steer::SteerReceipt;
pub use crate::dreamer_runner::maintenance::agent_health::steer::SteerRequest;
use serde::Deserialize;
use serde::Serialize;

/// `self.memory.diary`'s input: one private entry, and the kind of entry it
/// is (`reflection`, `daily`), when the agent names one.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiaryEntryRequest {
    pub content: String,
    #[serde(default)]
    pub kind: Option<String>,
}
