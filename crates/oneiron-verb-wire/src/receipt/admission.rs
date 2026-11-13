//! Moved from `crates/oneiron/src/receipt/admission.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::Arc;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdmissionStatus {
    /// Waiting for the existing fair line's permit, not for a health verdict.
    Queued,
    /// Running, or held by the verb's own typed ask. A health check never holds it.
    Held {
        reason: Option<String>,
    },
    Completed {
        result_digest: String,
    },
    Refused {
        code: String,
        reason: String,
    },
    /// The host stopped without observing settlement. Effects may have landed;
    /// this is not permission to replay the intent.
    Interrupted {
        reason: String,
    },
}

impl AdmissionStatus {
    fn terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed { .. } | Self::Refused { .. } | Self::Interrupted { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReceipt {
    pub receipt_ref: String,
    pub intent_key: String,
    pub verb: String,
    pub request_digest: String,
    pub accepted_at: u64,
    pub updated_at: u64,
    pub state: AdmissionStatus,
}
