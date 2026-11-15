//! Moved from `crates/oneiron/src/llm/run_admission/resident_doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Every resident share on record: no selector names another vault's.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidentSharesRequest {}

/// One resident's share and its depletion on the allocation it last drew
/// on.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResidentShareView {
    pub resident: String,
    /// `None` is the default split.
    pub units: Option<u64>,
    pub pinned: bool,
    /// The allocation the counts are on, and its generation; `None` before
    /// any charge.
    pub allocation: Option<String>,
    pub allocation_generation: Option<u64>,
    pub used_units: u64,
    pub overdraft_units: u64,
    /// Settled calls that charged past the share.
    pub overdrafts: u64,
}

/// Every resident share on record, by resident.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResidentSharesView {
    pub residents: Vec<ResidentShareView>,
}
