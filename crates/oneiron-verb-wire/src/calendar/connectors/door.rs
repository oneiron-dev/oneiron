//! Moved from `crates/oneiron/src/calendar/connectors/door.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::calendar::connectors::seat::CalendarConnectorSeatConfig;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarConnectorConfigureRequest {
    pub config: CalendarConnectorSeatConfig,
    /// CalDAV discovery URL. Credentials belong in the named custody record.
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarConnectorRequest {
    pub seat_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarConnectorWriteRequest {
    pub seat_ref: String,
    pub event_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarConnectorKillRequest {
    pub seat_ref: String,
    pub reason_ref: String,
}

/// An HTTP mail submission service installed by the host's owner. It accepts
/// one RFC 5322 MIME message per POST; a 2xx means accepted for delivery.
/// The credential must have a read binding for `calendar.imip`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarImipTransportConfig {
    pub endpoint: String,
    pub secret_ref: String,
}
