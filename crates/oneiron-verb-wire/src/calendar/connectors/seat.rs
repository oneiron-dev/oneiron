//! Moved from `crates/oneiron/src/calendar/connectors/seat.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Advertised verb: incremental read of the configured remote calendar.
pub const CALENDAR_CONNECTOR_PULL_VERB: &str = "calendar.connector.pull";

/// Advertised verb: conditional write to the configured remote calendar.
pub const CALENDAR_CONNECTOR_WRITE_VERB: &str = "calendar.connector.write";

/// The verbs a live seat advertises. A killed seat advertises none.
pub const CALENDAR_CONNECTOR_VERB_CATALOG: &[&str] =
    &[CALENDAR_CONNECTOR_PULL_VERB, CALENDAR_CONNECTOR_WRITE_VERB];

/// Upper bound for every bounded ref this module accepts.
pub const MAX_REF_BYTES: usize = 256;

/// One connector seat's configuration.
///
/// Carries the SECRET custody record NAME. No app password, OAuth token, or
/// credential-bearing URL has a field to live in here, and the hand-rolled
/// [`core::fmt::Debug`] below keeps it that way for every future field.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarConnectorSeatConfig {
    /// Stable seat identifier (host vocabulary).
    pub seat_ref: String,
    /// SECRET custody record name for this seat's provider credential.
    pub secret_ref: String,
    /// Foreign system identifier stamped on this seat's passports.
    pub system: String,
    /// The provider-side collection this seat reads and writes.
    pub calendar_ref: String,
    /// Lower bound of the re-enqueue cadence window, seconds.
    pub cadence_jitter_min_seconds: u32,
    /// Upper bound of the re-enqueue cadence window, seconds.
    pub cadence_jitter_max_seconds: u32,
}

impl core::fmt::Debug for CalendarConnectorSeatConfig {
    /// Prints stable non-secret identifiers only. `secret_ref` is an opaque
    /// custody NAME — the credential it points at is resolved below the
    /// transport seam and never enters this struct — so printing the name is
    /// safe and printing anything else is impossible: a field not written here
    /// does not exist here.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CalendarConnectorSeatConfig")
            .field("seat_ref", &self.seat_ref)
            .field("secret_ref", &self.secret_ref)
            .field("system", &self.system)
            .field("calendar_ref", &self.calendar_ref)
            .field(
                "cadence_jitter_min_seconds",
                &self.cadence_jitter_min_seconds,
            )
            .field(
                "cadence_jitter_max_seconds",
                &self.cadence_jitter_max_seconds,
            )
            .finish()
    }
}

/// The engaged half of a seat's kill switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarConnectorKillSwitchState {
    /// When the switch was thrown.
    pub killed_at: u64,
    /// The advertised verb catalog is empty while this holds.
    pub verbs_revoked: bool,
    /// No pull, write, or re-enqueue runs while this holds.
    pub polling_stopped: bool,
    /// Host-side reason ref. Never free-form credential-bearing text.
    pub reason_ref: String,
}
