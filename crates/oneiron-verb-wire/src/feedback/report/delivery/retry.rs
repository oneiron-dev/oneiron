//! Moved from `crates/oneiron/src/feedback/report/delivery/retry.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::feedback::report::delivery::ReportDeliveryKey;
use crate::feedback::report::delivery::ReportDeliveryRecord;
use crate::feedback::report::delivery::ReportFrozenSend;
use crate::feedback::report::validate_ref;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
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
