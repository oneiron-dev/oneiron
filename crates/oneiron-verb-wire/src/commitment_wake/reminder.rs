//! Moved from `crates/oneiron/src/commitment_wake/reminder.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_delivery_vocabulary::delivery_window::schedule_context::OutboundScheduleContext;
use oneiron_store::attempt_id::AttemptId;
use oneiron_store::config::context_spec::CONTEXT_SPEC_MAX_TEXT_BYTES;
use oneiron_store::config::context_spec::ContextSpec;
use serde::Deserialize;
use serde::Serialize;

/// The UTC offset, in whole minutes, the IANA `zone` observes at `at`; `None`
/// for a zone the embedded database does not know.
pub fn zone_offset_minutes_at(zone: &str, at: u64) -> Option<i16> {
    calendar::tz::ResolvedTimeZone::new(zone)
        .ok()?
        .offset_minutes_at(at)
}
