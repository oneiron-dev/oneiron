//! Typed recovery suggestions on a failed or uncertain outbound receipt (FIX
//! 7965): what the caller may do next, named as an action and never as the
//! provider's text. A sink may name its own; every failed or uncertain
//! receipt carries at least the engine's typed fallback.

use super::dispatch_types::{OutboundDispatchOutcome, OutboundExecutionOutcome};
use crate::receipt::ReceiptRecord;

/// The receipt field the suggestions are filed under: one JSON array of
/// `{"kind": ...}` objects, in the order they were named.
pub(crate) const RECOVERY_SUGGESTIONS_FIELD: &str = "recovery_suggestions";

/// One typed next step after an outbound send that did not certainly
/// deliver.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum OutboundRecoverySuggestion {
    /// The provider named when it takes this send again: no retry before
    /// `not_before`, in Unix seconds.
    RetryAfter { not_before: u64 },
    /// The send may have been delivered: reconcile it with the provider
    /// before any resend.
    ReconcileDelivery,
    /// The connector's connection or credential needs refreshing first.
    RefreshConnection,
    /// Inspect the channel's failure before deciding what to do.
    InspectChannelFailure,
}

impl OutboundRecoverySuggestion {
    /// The stable spelling the receipt files.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RetryAfter { .. } => "retry_after",
            Self::ReconcileDelivery => "reconcile_delivery",
            Self::RefreshConnection => "refresh_connection",
            Self::InspectChannelFailure => "inspect_channel_failure",
        }
    }

    fn to_json(self) -> serde_json::Value {
        match self {
            Self::RetryAfter { not_before } => {
                serde_json::json!({ "kind": self.as_str(), "not_before": not_before })
            }
            _ => serde_json::json!({ "kind": self.as_str() }),
        }
    }
}

/// The suggestions a receipt of `outcome` files: the sink's own when it
/// named any, else the engine's typed fallback. An uncertain send always
/// leads with reconciliation, never a blind retry; a definite failure the
/// provider gave a cool-down for names that time; any other failure asks
/// for its inspection. Every other outcome files none.
pub(super) fn recovery_suggestions_for(
    outcome: OutboundDispatchOutcome,
    execution: Option<&OutboundExecutionOutcome>,
    provider_retry_after_secs: Option<u64>,
    occurred_at: u64,
) -> Vec<OutboundRecoverySuggestion> {
    let uncertain = outcome == OutboundDispatchOutcome::Ambiguous
        || execution.is_some_and(|execution| execution.delivery_may_have_occurred);
    if !matches!(
        outcome,
        OutboundDispatchOutcome::Failed | OutboundDispatchOutcome::Ambiguous
    ) {
        return Vec::new();
    }
    let mut suggestions =
        execution.map_or_else(Vec::new, |execution| execution.recovery_suggestions.clone());
    if uncertain {
        suggestions.retain(|suggestion| {
            !matches!(suggestion, OutboundRecoverySuggestion::RetryAfter { .. })
        });
        if !suggestions.contains(&OutboundRecoverySuggestion::ReconcileDelivery) {
            suggestions.insert(0, OutboundRecoverySuggestion::ReconcileDelivery);
        }
        return suggestions;
    }
    if suggestions.is_empty() {
        suggestions.push(provider_retry_after_secs.map_or(
            OutboundRecoverySuggestion::InspectChannelFailure,
            |secs| OutboundRecoverySuggestion::RetryAfter {
                not_before: occurred_at.saturating_add(secs),
            },
        ));
    }
    suggestions
}

/// Files `suggestions` on `receipt` under [`RECOVERY_SUGGESTIONS_FIELD`];
/// none files nothing.
pub(super) fn append_recovery_suggestions(
    receipt: &mut ReceiptRecord,
    suggestions: &[OutboundRecoverySuggestion],
) {
    if suggestions.is_empty() {
        return;
    }
    let encoded = serde_json::Value::Array(
        suggestions
            .iter()
            .map(|suggestion| suggestion.to_json())
            .collect(),
    );
    receipt
        .fields
        .insert(RECOVERY_SUGGESTIONS_FIELD.to_owned(), encoded.to_string());
}
