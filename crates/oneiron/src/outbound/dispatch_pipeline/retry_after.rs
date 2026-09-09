//! Provider cool-down receipt/execution field names and whole-seconds parser.
use crate::outbound::dispatch_types::OutboundExecutionOutcome;
/// Receipt field carrying the connector provider's own stated cool-down, in
/// whole seconds from the dispatch instant.
pub(in crate::outbound) const PROVIDER_RETRY_AFTER_FIELD: &str = "provider_retry_after";
/// The execution field a connector adapter surfaces its cool-down on. Named
/// for the provider header it comes from, so an adapter reports what the
/// provider said rather than a value this engine invented.
pub(super) const PROVIDER_RETRY_AFTER_EXECUTION_FIELD: &str = "retry_after";
/// Whole seconds a provider asked this send to wait, if it asked at all.
///
/// A blank, negative, fractional, or otherwise unparseable value is NOT a
/// cool-down: it is dropped here so a malformed provider string can never
/// become a re-arm instant. The connector's raw text still reaches the receipt
/// unchanged, so the drop stays auditable.
pub(super) fn provider_retry_after_secs(execution: &OutboundExecutionOutcome) -> Option<u64> {
    execution
        .receipt_fields
        .get(PROVIDER_RETRY_AFTER_EXECUTION_FIELD)
        .and_then(|value| value.trim().parse::<u64>().ok())
}
