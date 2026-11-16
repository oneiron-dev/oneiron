//! Moved from `crates/oneiron/src/task_verb/comm_widen/revoke.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::authority::CommReach;
use serde::Deserialize;
use serde::Serialize;

/// What the owner's revocation of one run's stop-asking choice did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommWidenRevokeReceipt {
    /// The run whose choice it was, as 32 hex.
    pub attempt: String,
    /// The reach that choice approved.
    pub reach: CommReach,
    /// When its standing ended: now, or at an earlier revocation.
    pub revoked_at: u64,
    /// Whether this call ended it; `false` when an earlier one had.
    pub revoked: bool,
}
