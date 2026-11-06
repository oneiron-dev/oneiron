//! Outbound schedule DTOs: context, draft input, and intent receipt.

use serde::{Deserialize, Serialize};

pub use crate::delivery_window::OutboundScheduleContext;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundDraftInput {
    /// Verb (e.g. `send`).
    pub verb: String,
    /// Channel (e.g. `email`).
    pub channel: String,
    /// Delivery target (address/handle).
    pub target: String,
    /// Principal the send acts for, if delegated.
    pub on_behalf_of: Option<String>,
    /// Reference to the content entity to send.
    pub content_ref: Option<String>,
    /// Facade-enforced idempotency key: a second schedule with the same
    /// key coalesces instead of double-enqueueing.
    pub idempotency_key: Option<String>,
    /// Advisory dedupe key carried onto the receipt.
    pub dedupe_key: Option<String>,
    /// Trigger source: `commitment_timer_wake` | `gap_queue` |
    /// `agent_immediate`.
    pub trigger: String,
    /// What fired the trigger (commitment/session/queue ref).
    pub trigger_ref: String,
    /// Owning attempt/brief ref, if any.
    pub job_ref: Option<String>,
    /// Unix seconds; `None` ⇒ now.
    pub occurred_at: Option<u64>,
    /// The saved mention `target` came from, when the agent named the
    /// person (OF-123): the send refuses while that mention is unsettled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mention: Option<crate::outbound::MentionProvenance>,
}

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
    /// [`Memory::receipts`](crate::Memory::receipts). On dedupe this re-surfaces the first
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
