//! Moved from `crates/oneiron/src/calendar/claims/values.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::calendar::claims::predicates::CONTENT_HASH_LEN;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Sync direction of one calendar passport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
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

/// The immutable archived ICS version a passport's imported content came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarPassportSource {
    /// The source BLOB_ARTIFACT, not a locator parsed from import metadata.
    pub artifact: EntityId,
    /// The exact version returned by the archive write or authorized read.
    pub version: u64,
}

impl CalendarPassportSource {
    pub fn blob_ref(self) -> String {
        format!("{}#v{}", self.artifact.to_hex(), self.version)
    }
}

/// Value of a `calendar.passport` claim.
///
/// One live passport per (system x UID) via `supersede_claim`; CAL-02 owns the
/// UID index and the feed diff. The claim value is truth, the index is only a
/// lookup accelerator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarPassportValue {
    /// Foreign system identifier.
    pub system: String,
    /// Foreign UID within that system.
    pub uid: String,
    /// Last observed `SEQUENCE`.
    pub last_sequence: u32,
    /// Content hash of the last observed representation.
    pub content_hash: [u8; CONTENT_HASH_LEN],
    /// Exact archived source of the applied content; absent for authored content
    /// or admissions that have no archived bytes. This is provenance, not authority.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<CalendarPassportSource>,
    /// Sync direction for this source.
    pub direction: CalendarPassportDirection,
    /// When this source was last observed.
    pub last_seen_at: u64,
    /// Whether this source still reports the UID.
    pub presence: CalendarPassportPresence,
}
