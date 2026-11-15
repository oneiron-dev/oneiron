//! Moved from `crates/oneiron/src/receipt/grant.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Query for the OF-367 RS6.5 standing outbound-grants lens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingOutboundGrantsLensQuery {
    pub limit: usize,
    pub receipt_limit_per_grant: usize,
}

impl StandingOutboundGrantsLensQuery {
    #[must_use]
    pub const fn new(limit: usize, receipt_limit_per_grant: usize) -> Self {
        Self {
            limit,
            receipt_limit_per_grant,
        }
    }
}

/// Host-interpreted one-tap revoke command for a grants lens row: the
/// consent registry's revoke door.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingOutboundGrantRevokeAction {
    pub command: String,
    pub grant_ref: String,
}
