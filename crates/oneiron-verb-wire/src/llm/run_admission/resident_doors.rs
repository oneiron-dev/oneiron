//! Moved from `crates/oneiron/src/llm/run_admission/resident_doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Every resident share on record: no selector names another vault's.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResidentSharesRequest {}

/// The owner's setting for one resident's share.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SetResidentShareRequest {
    /// The resident, as its entity id in hex.
    pub resident: String,
    /// The share in the allocation's unit; absent returns the resident to
    /// the default split of what the set shares leave.
    #[serde(default)]
    pub units: Option<u64>,
    /// Pinned, the share refuses the resident's new paid work once a call
    /// no longer fits it; soft, spend past it writes an overdraft receipt.
    #[serde(default)]
    pub pinned: bool,
    /// The unit of the walletless allocation the share governs (Engine
    /// RESIDENT-SHARE-UNIT = A). Absent names the host's one walletless
    /// unit; with none or several, the set is refused with `unit_required`.
    #[serde(default)]
    pub unit: Option<String>,
}

/// One resident's share in its block's unit, and its depletion on the
/// block's allocation (on the newest generation it drew on in that unit,
/// when no host account names the allocation).
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

/// Every resident share on record, one block per walletless unit.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ResidentSharesView {
    /// One block per walletless allocation the host selects; with none,
    /// one per unit a share or a charge is on record in.
    pub allocations: Vec<UnitSharesView>,
}

/// Every resident's share and depletion in one walletless unit.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct UnitSharesView {
    pub unit: String,
    pub residents: Vec<ResidentShareView>,
}
