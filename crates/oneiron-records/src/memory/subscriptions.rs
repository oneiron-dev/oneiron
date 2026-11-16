//! Moved from `crates/oneiron/src/memory/subscriptions.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// Scope and retrieval constraints for a live memory view.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScopedView {
    pub world_ref: Option<String>,
    pub facet: Option<String>,
    pub filter: Option<Value>,
    pub query: Option<String>,
}
