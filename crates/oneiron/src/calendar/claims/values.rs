//! Calendar claim value types with their wire-token impls.

use serde::{Deserialize, Serialize};

use super::predicates::{CONTENT_HASH_LEN, ICS_TRANSP_TRANSPARENT};
use crate::entity_id::EntityId;

/// How an EVENT's time is anchored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalendarTimeKind {
    /// Fixed instant.
    Absolute,
    /// Wall time plus an IANA zone.
    Zoned,
    /// Wall time with no zone; never coerced into another kind.
    Floating,
    /// Whole-day event.
    AllDay,
}

impl CalendarTimeKind {
    /// Wire token for this kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absolute => "absolute",
            Self::Zoned => "zoned",
            Self::Floating => "floating",
            Self::AllDay => "all_day",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "absolute" => Some(Self::Absolute),
            "zoned" => Some(Self::Zoned),
            "floating" => Some(Self::Floating),
            "all_day" => Some(Self::AllDay),
            _ => None,
        }
    }
}

/// Whether an EVENT consumes availability. Freebusy filters on this.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CalendarBusyTransparency {
    /// Consumes availability. The default when the field is missing.
    #[default]
    Busy,
    /// Does not consume availability.
    Free,
}

impl CalendarBusyTransparency {
    /// Wire token for this transparency.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Free => "free",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "busy" => Some(Self::Busy),
            "free" => Some(Self::Free),
            _ => None,
        }
    }

    /// Maps an ICS `TRANSP` property value at ingest.
    ///
    /// Missing or `TRANSP:OPAQUE` maps to [`Self::Busy`]; `TRANSP:TRANSPARENT`
    /// maps to [`Self::Free`]. Unknown vendor values fail closed to busy so an
    /// unrecognized token can never silently free up availability.
    #[must_use]
    pub fn from_ics_transp(transp: Option<&str>) -> Self {
        match transp {
            Some(ICS_TRANSP_TRANSPARENT) => Self::Free,
            _ => Self::Busy,
        }
    }
}

/// Value of a `calendar.time_kind` claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalendarTimeKindValue {
    /// How the EVENT's time is anchored.
    pub kind: CalendarTimeKind,
    /// Whether the EVENT consumes availability.
    pub busy_transparency: CalendarBusyTransparency,
}

/// Value of a `calendar.wall_time` claim: structural storage only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalendarWallTimeValue {
    /// Proleptic Gregorian year.
    pub y: i32,
    /// Month, 1-12.
    pub mo: u8,
    /// Day of month, 1-31.
    pub d: u8,
    /// Hour, 0-23.
    pub h: u8,
    /// Minute, 0-59.
    pub mi: u8,
    /// Second, 0-60 to admit a leap second.
    pub s: u8,
}

/// Where an EVENT came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalendarOrigin {
    /// Authored by the dreamer.
    Dreamer,
    /// Authored natively in this vault.
    Native,
    /// Imported from an external calendar.
    Imported,
}

impl CalendarOrigin {
    /// Wire token for this origin.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dreamer => "dreamer",
            Self::Native => "native",
            Self::Imported => "imported",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "dreamer" => Some(Self::Dreamer),
            "native" => Some(Self::Native),
            "imported" => Some(Self::Imported),
            _ => None,
        }
    }
}

/// Sync direction of one calendar passport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarPassportDirection {
    /// Read from the foreign system.
    Inbound,
    /// Written to the foreign system.
    Outbound,
    /// Both directions.
    TwoWay,
}

impl CalendarPassportDirection {
    /// Wire token for this direction.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
            Self::TwoWay => "two_way",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "inbound" => Some(Self::Inbound),
            "outbound" => Some(Self::Outbound),
            "two_way" => Some(Self::TwoWay),
            _ => None,
        }
    }

    /// Whether this direction participates in imported-absence cancellation.
    ///
    /// Only inbound-bearing passports report feed presence, so an outbound-only
    /// passport can never contribute an absence vote.
    #[must_use]
    pub const fn is_inbound_bearing(self) -> bool {
        matches!(self, Self::Inbound | Self::TwoWay)
    }
}

/// Whether one source still reports the EVENT in its feed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarPassportPresence {
    /// The source still reports this UID. The default when the field is missing.
    #[default]
    Live,
    /// The source's last complete feed omitted this UID.
    Absent,
}

impl CalendarPassportPresence {
    /// Wire token for this presence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Absent => "absent",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "live" => Some(Self::Live),
            "absent" => Some(Self::Absent),
            _ => None,
        }
    }
}

/// Value of a `calendar.passport` claim.
///
/// One live passport per (system x UID) via `supersede_claim`; CAL-02 owns the
/// UID index and the feed diff. The claim value is truth, the index is only a
/// lookup accelerator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarPassportValue {
    /// Foreign system identifier.
    pub system: String,
    /// Foreign UID within that system.
    pub uid: String,
    /// Last observed `SEQUENCE`.
    pub last_sequence: u32,
    /// Content hash of the last observed representation.
    pub content_hash: [u8; CONTENT_HASH_LEN],
    /// Sync direction for this source.
    pub direction: CalendarPassportDirection,
    /// When this source was last observed.
    pub last_seen_at: u64,
    /// Whether this source still reports the UID.
    pub presence: CalendarPassportPresence,
}

/// Value of a `calendar.series_master` claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarSeriesMasterValue {
    /// Verbatim RFC 5545 recurrence text.
    pub rrule: String,
    /// Series start instant.
    pub dtstart_utc: u64,
    /// IANA zone the recurrence expands in.
    pub tz: String,
}

/// Value of a `calendar.series_exception` claim.
///
/// The exception's identity is `(uid, original_start_utc)`, carried
/// self-contained so masking can compare the full key without a second read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarSeriesExceptionValue {
    /// The master EVENT this exception overrides.
    pub master_ref: EntityId,
    /// Series UID.
    pub uid: String,
    /// The occurrence start this exception replaces.
    pub original_start_utc: u64,
}

/// Value of a `calendar.successor` claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarSuccessorValue {
    /// The EVENT this one supersedes.
    pub predecessor_ref: EntityId,
}

/// Value of a `calendar.attendee` claim.
///
/// Role and partstat preserve vendor values verbatim: they are bounded and
/// non-empty, but never a closed enum, so soft state never becomes load-bearing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarAttendeeValue {
    /// Attendee identifier as the source expressed it.
    pub who: String,
    /// Vendor role token.
    pub role: String,
    /// Vendor participation-status token.
    pub partstat: String,
}

/// Confirmed/cancelled status of an EVENT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalendarStatus {
    /// The EVENT stands.
    Confirmed,
    /// The EVENT is cancelled. The EVENT row is never deleted.
    Cancelled,
}

impl CalendarStatus {
    /// Wire token for this status.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "confirmed" => Some(Self::Confirmed),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }
}

/// What recorded a [`CalendarStatus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalendarStatusBasis {
    /// An explicit cancellation arrived in a feed.
    ImportedCancel,
    /// Every live inbound passport reported absence.
    ImportedAbsence,
    /// The owner ruled.
    Owner,
    /// A booking flow recorded it.
    Booking,
}

impl CalendarStatusBasis {
    /// Wire token for this basis.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ImportedCancel => "imported_cancel",
            Self::ImportedAbsence => "imported_absence",
            Self::Owner => "owner",
            Self::Booking => "booking",
        }
    }

    /// Parses a wire token, rejecting anything outside the closed set.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "imported_cancel" => Some(Self::ImportedCancel),
            "imported_absence" => Some(Self::ImportedAbsence),
            "owner" => Some(Self::Owner),
            "booking" => Some(Self::Booking),
            _ => None,
        }
    }
}

/// Value of a `calendar.status` claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CalendarStatusValue {
    /// Confirmed or cancelled.
    pub status: CalendarStatus,
    /// What recorded it.
    pub basis: CalendarStatusBasis,
    /// When it was recorded.
    pub recorded_at: u64,
}
