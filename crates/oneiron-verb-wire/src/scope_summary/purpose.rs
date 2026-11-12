//! Moved from `crates/oneiron/src/scope_summary/purpose.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Result;
use oneiron_store::scope_summary::codec::invalid;
use serde::Deserialize;
use serde::Serialize;

/// A named purpose with host-editable descriptive text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SummaryPurpose {
    pub id: String,
    pub description: String,
}
