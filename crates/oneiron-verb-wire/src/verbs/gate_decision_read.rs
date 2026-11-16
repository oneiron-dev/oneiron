//! Moved from `crates/oneiron/src/verbs/gate_decision_read.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The same wire fields as `ExplainGateNotice`, with an input/output schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GateDecisionReadNotice {
    pub notice_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_ref: Option<String>,
}

/// The explain door's screened answer, plus version, redaction time and screened
/// Grant/frontier data. `context` and `diff_handle` are deliberately not served:
/// FIX row GATE-DECISION-CONTEXT-RELEASE-RULE has no release rule for them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GateDecisionReadView {
    pub receipt_id: String,
    pub decided_at: u64,
    pub outcome: String,
    pub reason_codes: Vec<String>,
    pub receipt_reasons: Vec<String>,
    pub notices: Vec<GateDecisionReadNotice>,
    pub actor_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_ref: Option<String>,
    pub content_kind: String,
    pub policy_manifest_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_ref: Option<String>,
    pub version: u8,
    pub redacted_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ref: Option<String>,
    /// Only the decision's own actor or the vault owner may read this hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_frontier_hash: Option<String>,
}
