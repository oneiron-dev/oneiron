//! Moved from `crates/oneiron/src/memory/outbound/types.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_delivery_vocabulary::delivery_window::schedule_context::OutboundScheduleContext;
pub use oneiron_verb_wire::memory::outbound::types::OutboundIntentReceipt;
use serde::Deserialize;
use serde::Serialize;

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
    pub mention:
        Option<oneiron_verb_wire::dreamer_runner::maintenance::identity::MentionProvenance>,
}
