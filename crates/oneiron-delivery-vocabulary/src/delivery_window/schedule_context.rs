//! Host-supplied civil time and delivery level for an outbound schedule.

use oneiron_contracts::memory::{MemoryError, MemoryResult};

use super::{DeliveryWindowApnsInterruptionLevel, DeliveryWindowResolvedLevel};

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
    pub fn validate(&self) -> MemoryResult<()> {
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
