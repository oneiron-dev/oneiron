//! Moved from `crates/oneiron/src/receipt/admission.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionStatusRequest {
    /// The call's x-oneiron-invocation, 32 hex digits.
    pub intent_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReceiptsRequest {
    /// The exact set of authored invocation ids to reconcile, in reply order.
    pub intent_keys: Vec<String>,
}
