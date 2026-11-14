//! Moved from `crates/oneiron/src/memory/claims/settle.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Why a committed settlement warns (FIX 7600).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SettleWarningCode {
    /// The approved claim's VAD consolidation failed after the commit: the
    /// settlement stands, and the claim's VAD is pending.
    VadPending,
}

/// A warning a committed settlement carries: a stable code, the claim it is
/// about and one human line (FIX 7600). The settlement it rides on is
/// durable; the warning names work still owed after it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SettleWarning {
    /// Why it warns.
    pub code: SettleWarningCode,
    /// The claim it is about (32 hex).
    pub claim_ref: String,
    /// One human line.
    pub detail: String,
}
