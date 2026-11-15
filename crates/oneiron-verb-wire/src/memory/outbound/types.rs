//! Moved from `crates/oneiron/src/memory/outbound/types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_delivery_vocabulary::delivery_window::schedule_context::OutboundScheduleContext;
use serde::Deserialize;
use serde::Serialize;

/// Receipt for one scheduled outbound intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OutboundIntentReceipt {
    /// Stable intent ref (`intent:<attempt-hex>`).
    pub intent_ref: String,
    /// Dispatch outcome (`held` expected on this schedule-only surface;
    /// `suppressed` on gate denial; `already_scheduled` for a pending schedule
    /// dedupe; `already_sent` for a durable delivered-send dedupe).
    pub outcome: String,
    /// Gate outcome (`allow`/`pending`/`deny`). On dedupe this re-surfaces
    /// the first schedule's outcome (absent only if its binding is missing).
    pub gate_outcome: Option<String>,
    /// Persisted gate decision ref (`gate:<hex>`), queryable via
    /// `Memory::receipts`. On dedupe this re-surfaces the first
    /// schedule's decision (absent only if its binding is missing).
    pub gate_decision_ref: Option<String>,
    /// Gate reason codes.
    pub gate_reason_codes: Vec<String>,
    /// While the gate holds the send for the owner (`gate_outcome`
    /// `pending`), the approve-once digest his one-time press must name to
    /// release it, 64 lower-hex (FIX 6424): set for a send whose family pins
    /// its own target (the communications connectors, `calendar.invite`).
    /// On dedupe this re-surfaces the first schedule's digest.
    pub approval_digest: Option<String>,
    /// True when the idempotency key coalesced onto an existing schedule.
    pub deduped: bool,
}
