//! Moved from `crates/oneiron/src/calendar/connectors/seat.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::calendar::connectors::seat::CALENDAR_CONNECTOR_PULL_VERB;
pub use oneiron_verb_wire::calendar::connectors::seat::CALENDAR_CONNECTOR_WRITE_VERB;
pub use oneiron_verb_wire::calendar::connectors::seat::CalendarConnectorKillSwitchState;
pub use oneiron_verb_wire::calendar::connectors::seat::CalendarConnectorSeatConfig;
use serde::Deserialize;
use serde::Serialize;

/// The attempt payload one connector poll carries. Custody NAME only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarConnectorSyncPayload {
    /// The seat this attempt polls.
    pub config: CalendarConnectorSeatConfig,
    /// The provider cursor the run resumes from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// The instant at or after which the host should run this poll.
    pub not_before: u64,
}
