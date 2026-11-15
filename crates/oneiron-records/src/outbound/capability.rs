//! Moved from `crates/oneiron/src/outbound/capability.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Serialize;
use serde_json::Value;

/// Whether a verb may interrupt the recipient.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundInterruptionClass {
    Ambient,
    Interrupt,
}

/// Retry class consumed by the later dispatch/retry policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundRetryClass {
    IdempotentNative,
    IdempotentEmulated,
    NonIdempotentInterrupt,
    ReplaceIdempotent,
}

/// Delivery semantics consumed by edit/retract/dedupe routing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundDeliverySemanticsKind {
    FireAndForget,
    Editable,
    Retractable,
    Replaceable,
    ReactionTarget,
    Ephemeral,
}

/// Delivery behavior for one verb.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutboundDeliverySemantics {
    pub kind: OutboundDeliverySemanticsKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<&'static str>,
}

/// Platform permission status for a capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundPermissionState {
    Allowed,
    Conditional,
    ProviderReview,
}

/// The OF-327 capability-vs-permission split for one verb.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutboundCapabilityPermission {
    pub capability: bool,
    pub permission: OutboundPermissionState,
    pub policy_risk: bool,
    pub verified_at: &'static str,
    pub note: &'static str,
}

/// Seven-field outbound verb contract.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OutboundVerbContract {
    pub kind: String,
    pub channel_call: String,
    pub params: Value,
    pub interruption_class: OutboundInterruptionClass,
    pub delivery_semantics: OutboundDeliverySemantics,
    pub retry_class: OutboundRetryClass,
    #[serde(rename = "capability_vs_permission")]
    pub capability_vs_permission: OutboundCapabilityPermission,
}

/// How a retry of one admitted send may go once an attempt may have delivered
/// (FIX 8814): logical supersession is not provider retry safety.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutboundReplaySafety {
    /// The provider dedupes the send by the key the transport presents.
    ProviderKey,
    /// The send lands on the same target each time (an edit in place, an
    /// iMIP revision on its UID and SEQUENCE): a replay replaces, never adds.
    StableTarget,
    /// A replay can add a second delivery: an uncertain attempt is reconciled
    /// before any resend, never resent on its own.
    Reconcile,
}

/// The verb whose replacement is a new superseding message rather than an
/// edit of the original (FIX 8814): it carries no provider dedupe.
pub const SUPERSEDING_SEND_VERB: &str = "replace";

impl OutboundVerbContract {
    /// This verb's replay safety (FIX 8814): a provider-native key, a
    /// replacement that lands on a stable target, or neither. A superseding
    /// send is reconciled before any resend.
    pub fn replay_safety(&self) -> OutboundReplaySafety {
        match self.retry_class {
            OutboundRetryClass::IdempotentNative => OutboundReplaySafety::ProviderKey,
            OutboundRetryClass::ReplaceIdempotent if self.kind == SUPERSEDING_SEND_VERB => {
                OutboundReplaySafety::Reconcile
            }
            OutboundRetryClass::ReplaceIdempotent => OutboundReplaySafety::StableTarget,
            OutboundRetryClass::IdempotentEmulated | OutboundRetryClass::NonIdempotentInterrupt => {
                OutboundReplaySafety::Reconcile
            }
        }
    }
}

/// Per-connector capability manifest.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OutboundCapabilityManifest {
    pub manifest_version: &'static str,
    pub connector: String,
    pub connector_family: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family: Option<&'static str>,
    pub verified_at: &'static str,
    pub schema_on_demand: String,
    pub foreign_content_posture: &'static str,
    /// Message operations that project a delivered receipt to comm.last_touch.
    /// Connector-owned data, not an engine union of raw verb names.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub message_verbs: Vec<String>,
    pub verbs: Vec<OutboundVerbContract>,
}
