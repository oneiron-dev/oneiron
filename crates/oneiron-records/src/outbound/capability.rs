//! Moved from `crates/oneiron/src/outbound/capability.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Serialize;

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
