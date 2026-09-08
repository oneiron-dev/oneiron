//! Outbound schedule DTOs: context, draft input, and intent receipt.

use serde::{Deserialize, Serialize};

use super::super::{MemoryError, MemoryResult};
use crate::delivery_window::{DeliveryWindowApnsInterruptionLevel, DeliveryWindowResolvedLevel};
/// One outbound schedule request (BRIDGE-03; rides OF-327 — the bridge
/// never implements delivery).
/// Host-supplied clock authority frozen on a connector TASK. No counterparty timezone is read.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OutboundScheduleContext {
    pub utc_offset_minutes: Option<i16>,
    pub iana_timezone: Option<String>,
    pub human_explicit_instant: bool,
    pub apns_interruption_level: Option<DeliveryWindowApnsInterruptionLevel>,
    /// Host-resolved level for a compatibility verb whose manifest name alone
    /// cannot decide ambient vs interrupt (a `telegram|line|imessage` `send`).
    /// The engine never guesses this from the verb string.
    pub resolved_level: Option<DeliveryWindowResolvedLevel>,
}

impl OutboundScheduleContext {
    pub(super) fn validate(&self) -> MemoryResult<()> {
        if self.iana_timezone.is_some() && self.utc_offset_minutes.is_none() {
            return Err(MemoryError::bad_request_with(
                "iana_timezone requires utc_offset_minutes",
                &["Supply the current civil UTC offset."],
            ));
        }
        if self
            .utc_offset_minutes
            .is_some_and(|offset| !(-840..=840).contains(&offset))
        {
            return Err(MemoryError::bad_request_with(
                "utc_offset_minutes must be in -840..=840",
                &["Supply a current civil UTC offset."],
            ));
        }
        if self.iana_timezone.as_deref().is_some_and(|label| {
            label.trim().is_empty() || label.chars().any(char::is_control) || label.len() > 255
        }) {
            return Err(MemoryError::bad_request_with(
                "iana_timezone must be non-blank and contain no controls",
                &["Supply a valid IANA label as provenance."],
            ));
        }
        // A send cannot be both an APNs push and a resolved plain chat.
        if self.apns_interruption_level.is_some()
            && self
                .resolved_level
                .is_some_and(DeliveryWindowResolvedLevel::is_plain_chat)
        {
            return Err(MemoryError::bad_request_with(
                "an APNs push cannot resolve to plain chat",
                &["Drop the APNs level, or resolve the send as push."],
            ));
        }
        Ok(())
    }
}

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
}

/// Receipt for one scheduled outbound intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// [`Memory::receipts`]. On dedupe this re-surfaces the first
    /// schedule's decision (absent only if its binding is missing).
    pub gate_decision_ref: Option<String>,
    /// Gate reason codes.
    pub gate_reason_codes: Vec<String>,
    /// True when the idempotency key coalesced onto an existing schedule.
    pub deduped: bool,
}
