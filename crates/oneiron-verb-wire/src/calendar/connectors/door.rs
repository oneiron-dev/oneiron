//! Moved from `crates/oneiron/src/calendar/connectors/door.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

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

/// `calendar.connector.release_hold`'s input: the booking EVENT whose calendar hold the owner
/// releases, and the confirm `vault.owner_confirm.preview` returned for this call.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarConnectorReleaseHoldRequest {
    pub event_ref: String,
    /// The confirm `vault.owner_confirm.preview` returned for this call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<String>,
}

/// Why the seat that wrote a held outbox row is out of service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CalendarHoldSeat {
    /// The seat is installed and its kill switch is engaged.
    Killed,
    /// No installed seat writes the row's scope: the seat was removed or its setup changed.
    Removed,
}

/// One write-outbox row that holds the pulls of a booking's EVENT while the seat that wrote it
/// is out of service: the calendar it names, why its seat is out, the SEQUENCE it staged, and
/// the row as it stands (its key, carrier instance and last move, each a release binds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarHoldRow {
    /// The calendar system the row writes to.
    pub system: String,
    /// The calendar the row writes to.
    pub calendar_ref: String,
    /// Why the writing seat is out of service.
    pub seat: CalendarHoldSeat,
    /// The SEQUENCE the row staged.
    pub sequence: u32,
    /// The row's key, 64 lowercase hex.
    pub outbox_id: String,
    /// The row's carrier instance, 32 lowercase hex.
    pub instance: String,
    /// When the row last moved, on the vault's recording clock.
    pub updated_at: u64,
}

/// `calendar.connector.release_hold`'s answer: the booking EVENT and each row whose hold the
/// owner released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarConnectorReleaseHoldReceipt {
    pub event_ref: String,
    pub released: Vec<CalendarHoldRow>,
}
