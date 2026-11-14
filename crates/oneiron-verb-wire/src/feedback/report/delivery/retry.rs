//! Moved from `crates/oneiron/src/feedback/report/delivery/retry.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// A new logical send for exactly the failed send the owner read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportDeliveryRetryRequest {
    /// The ISSUE, 32 hex.
    pub issue_ref: String,
    /// The current frozen send's exact reference from delivery status.
    pub expected_send_ref: String,
}
