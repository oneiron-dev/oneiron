//! Moved from `crates/oneiron/src/llm/budget/rsi_doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The vault RSI line itself: no selector names another vault's line.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RsiLineRequest {}

/// One named share of the token line, advisory unless pinned.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RsiShareView {
    pub label: String,
    pub units: u64,
    pub pinned: bool,
}

/// The token-denominated loop line.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RsiWorkLineView {
    pub unit: String,
    pub limit: u64,
    pub spent: u64,
    pub reserved: u64,
}

/// The exposure-denominated exploration line, independent of token spend.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RsiExposureLineView {
    pub unit: String,
    pub limit: u64,
    pub spent: u64,
    pub reserved: u64,
}

/// Both RSI lines, their shares and the hold that stops new loop work
/// without killing admitted work. Resource depletion reads here as
/// `suspended`, never as a terminal failure.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RsiLineView {
    pub work_line: RsiWorkLineView,
    pub shares: Vec<RsiShareView>,
    pub exposure_line: RsiExposureLineView,
    pub suspended: bool,
    /// The decision a top-up ran on: the owner's own proof, naming the
    /// asker's approved check-in it applied (2k10b). Absent on every other
    /// door's answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check_in: Option<crate::check_in::CheckInDecision>,
}
