//! Moved from `crates/oneiron/src/policy_model/owner_rows/notifications.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_verb_wire::gate::owner_policy_mutation::PolicyRowScope;
use serde::Deserialize;
use serde::Serialize;

/// Recipient-owned delivery override. Absence inherits the manifest rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyNotificationMode {
    Inherit,
    PushAll,
    Digest,
    LogOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyQueuedNotification {
    pub receipt_id: String,
    pub recipient: String,
    pub author: String,
    /// Exact source policy scope and grant target, revalidated before delivery.
    pub scope: PolicyRowScope,
    pub grant_target: String,
    pub mode: PolicyNotificationMode,
    pub followup_task: Option<String>,
    /// Digest window shared by all pending changes for this recipient.
    #[serde(default)]
    pub digest_due_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyNotificationFailure {
    pub receipt_id: String,
    pub recipient: String,
    pub attempts: u64,
    pub last_attempt_at: u64,
    pub next_retry_at: u64,
    pub last_error_kind: String,
}

pub fn invalid() -> Error {
    Error::InvalidConfig("invalid owner policy notification row".to_owned())
}
