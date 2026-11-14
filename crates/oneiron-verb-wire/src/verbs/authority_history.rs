//! Moved from `crates/oneiron/src/verbs/authority_history.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::authority::clock_repair::AuthorityClockRepair;
pub use crate::authority::clock_repair::AuthorityClockRepairOutcome;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use serde::Serialize;

/// Full signed history, including quarantined forks, in parent-first export
/// order. Each entry is the original MessagePack envelope in standard base64,
/// not an audit row or a re-serialized signed payload. Import accepts any
/// arrival order and may carry only new entries whose parents are held.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorityHistory {
    pub entries: Vec<String>,
}

/// The content-addressed authority entry ids returned by the atomic import.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorityHistoryImported {
    pub entry_refs: Vec<String>,
}
