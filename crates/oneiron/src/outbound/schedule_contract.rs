//! Attempt kind used by schedule admission and connector execution.

/// Attempt-queue kind for bridge-scheduled outbound intents. Pending schedules
/// use the queue's kind-scoped dedupe index; delivered sends use the additive
/// durable client-idempotency index.
pub const BRIDGE_OUTBOUND_ATTEMPT_KIND: &str = "bridge.outbound.schedule";
