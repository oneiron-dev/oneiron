//! The `calendar.*` claim family (CAL-00).
//!
//! Mirrors the `comm.rs` constants/table/matcher/structural-validator pattern.
//! Every predicate in this family is a claim ON an EVENT entity: no entity type
//! byte, no `EdgeKind`, and no serialization profile is minted here.
//!
//! Two validation halves live in this module, because the engine's claim
//! chokepoints sit at two different layers:
//!
//! * [`validate_calendar_claim_structure`] is the byte-level half, wired into
//!   the write-only validator chain in `crate::claim`. It sees a decoded
//!   [`ClaimBody`] and no storage, so it enforces the subject *shape*
//!   (`ClaimSubject::Entity`) plus the exact value shapes.
//! * [`require_event_subject`] is the store-aware half, mirroring the
//!   `comm.rs` PERSON-subject precedent. Subject *existence* is already
//!   enforced generically at both write doors; this adds the EVENT type
//!   assertion for calendar writers without reopening the shared write path.
//!
//! Timezone resolution (CAL-01), RRULE parsing/expansion (CAL-03), and the
//! passport UID index plus feed diff (CAL-02) are deliberately out of scope:
//! this layer stores structure verbatim.

use rmpv::Value;

use crate::Vault;
use crate::claim::{ClaimBody, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_EVENT;

/// Time-kind and busy/free transparency for one EVENT.
pub const PREDICATE_CALENDAR_TIME_KIND: &str = "calendar.time_kind";
/// Structural wall-clock storage; IANA conversion belongs to CAL-01.
pub const PREDICATE_CALENDAR_WALL_TIME: &str = "calendar.wall_time";
/// IANA zone name, structurally bounded only at this layer.
pub const PREDICATE_CALENDAR_TZ: &str = "calendar.tz";
/// Verbatim RFC 5545 recurrence text; CAL-03 owns parsing.
pub const PREDICATE_CALENDAR_RRULE: &str = "calendar.rrule";
/// Series master link, carried as a claim rather than an edge.
pub const PREDICATE_CALENDAR_SERIES_MASTER: &str = "calendar.series_master";
/// Series exception link with self-contained `(uid, original_start_utc)` identity.
pub const PREDICATE_CALENDAR_SERIES_EXCEPTION: &str = "calendar.series_exception";
/// Replacement EVENT's link back to the EVENT it supersedes.
pub const PREDICATE_CALENDAR_SUCCESSOR: &str = "calendar.successor";
/// One attendee row, preserving vendor role/partstat values verbatim.
pub const PREDICATE_CALENDAR_ATTENDEE: &str = "calendar.attendee";
/// Conferencing URL for the EVENT.
pub const PREDICATE_CALENDAR_MEETING_LINK: &str = "calendar.meeting_link";
/// One live passport per (system x UID), superseded by CAL-02.
pub const PREDICATE_CALENDAR_PASSPORT: &str = "calendar.passport";
/// Claims-first implementation of the existing EVENT origin law.
pub const PREDICATE_CALENDAR_ORIGIN: &str = "calendar.origin";
/// Confirmed/cancelled status with the basis that recorded it.
pub const PREDICATE_CALENDAR_STATUS: &str = "calendar.status";

/// Complete `calendar.*` claim family minted at this layer.
///
/// Membership is an exact table, never a `calendar.` prefix match: an unknown
/// future `calendar.*` predicate must not be silently interpreted as one of
/// these classes. ONE-1789 appends `calendar.event_outcome` in its own diff.
pub const CALENDAR_CLAIM_PREDICATES: &[&str] = &[
    PREDICATE_CALENDAR_TIME_KIND,
    PREDICATE_CALENDAR_WALL_TIME,
    PREDICATE_CALENDAR_TZ,
    PREDICATE_CALENDAR_RRULE,
    PREDICATE_CALENDAR_SERIES_MASTER,
    PREDICATE_CALENDAR_SERIES_EXCEPTION,
    PREDICATE_CALENDAR_SUCCESSOR,
    PREDICATE_CALENDAR_ATTENDEE,
    PREDICATE_CALENDAR_MEETING_LINK,
    PREDICATE_CALENDAR_PASSPORT,
    PREDICATE_CALENDAR_ORIGIN,
    PREDICATE_CALENDAR_STATUS,
];

const KEY_KIND: &str = "kind";
const KEY_BUSY_TRANSPARENCY: &str = "busy_transparency";
const KEY_YEAR: &str = "y";
const KEY_MONTH: &str = "mo";
const KEY_DAY: &str = "d";
const KEY_HOUR: &str = "h";
const KEY_MINUTE: &str = "mi";
const KEY_SECOND: &str = "s";
const KEY_RRULE: &str = "rrule";
const KEY_DTSTART_UTC: &str = "dtstart_utc";
const KEY_TZ: &str = "tz";
const KEY_MASTER_REF: &str = "master_ref";
const KEY_UID: &str = "uid";
const KEY_ORIGINAL_START_UTC: &str = "original_start_utc";
const KEY_PREDECESSOR_REF: &str = "predecessor_ref";
const KEY_WHO: &str = "who";
const KEY_ROLE: &str = "role";
const KEY_PARTSTAT: &str = "partstat";
const KEY_SYSTEM: &str = "system";
const KEY_LAST_SEQUENCE: &str = "last_sequence";
const KEY_CONTENT_HASH: &str = "content_hash";
const KEY_DIRECTION: &str = "direction";
const KEY_LAST_SEEN_AT: &str = "last_seen_at";
const KEY_PRESENCE: &str = "presence";
const KEY_STATUS: &str = "status";
const KEY_BASIS: &str = "basis";
const KEY_RECORDED_AT: &str = "recorded_at";

/// Upper bound for every bounded text field in this family.
const MAX_TEXT_BYTES: usize = 512;
/// Upper bound for verbatim RFC 5545 recurrence text.
const MAX_RRULE_BYTES: usize = 2048;
/// Content hashes are SHA-256 sized.
const CONTENT_HASH_LEN: usize = 32;

/// ICS `TRANSP` property value mapping to [`CalendarBusyTransparency::Busy`].
pub const ICS_TRANSP_OPAQUE: &str = "OPAQUE";
/// ICS `TRANSP` property value mapping to [`CalendarBusyTransparency::Free`].
pub const ICS_TRANSP_TRANSPARENT: &str = "TRANSPARENT";

/// Write class for claims an engine projector records rather than a human asserts.
const WRITE_CLASS_RECORDED: &str = "recorded";
/// Write class for ordinary claims.
const WRITE_CLASS_ORDINARY: &str = "ordinary";

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// One pure-data descriptor row, mirroring ARCH-0057 §4 fields.
///
/// No descriptor runtime exists in engine Rust yet; this table is ready to
/// register when the registry lands and is authoritative documentation until then.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimClassDescriptorRow {
    /// The predicate this row describes.
    pub predicate: &'static str,
    /// One of `"recorded"`, `"human_ruled"`, or `"ordinary"`.
    pub write_class: &'static str,
    /// Whether writes are enforcement-gated.
    pub enforcement: bool,
    /// Whether the class is restrictive (consent-bearing).
    pub restrictive: bool,
    /// Whether only an engine projector may write the class.
    pub projector_only: bool,
}

/// Descriptor rows for the whole `calendar.*` family, one per predicate.
///
/// `calendar.passport` and `calendar.origin` are projector-recorded provenance;
/// every other predicate, including `calendar.status`, is ordinary. No calendar
/// class is enforcement-gated or restrictive: none of them is a consent surface.
#[must_use]
pub fn claim_class_descriptors() -> Vec<ClaimClassDescriptorRow> {
    CALENDAR_CLAIM_PREDICATES
        .iter()
        .map(|&predicate| {
            let projector_only = matches!(
                predicate,
                PREDICATE_CALENDAR_PASSPORT | PREDICATE_CALENDAR_ORIGIN
            );
            ClaimClassDescriptorRow {
                predicate,
                write_class: if projector_only {
                    WRITE_CLASS_RECORDED
                } else {
                    WRITE_CLASS_ORDINARY
                },
                enforcement: false,
                restrictive: false,
                projector_only,
            }
        })
        .collect()
}

/// Returns whether `predicate` belongs to the calendar claim family.
///
/// Exact-table membership, never a `calendar.` prefix match.
#[must_use]
pub fn is_calendar_claim_predicate(predicate: &str) -> bool {
    CALENDAR_CLAIM_PREDICATES.contains(&predicate)
}

/// Asserts that a calendar claim's subject is an existing EVENT row.
///
/// The byte-level validator chain cannot reach storage, so this is the
/// store-aware half of the EVENT-subject law, mirroring the `comm.rs`
/// PERSON-subject precedent. Calendar writers call it before staging a write;
/// generic subject-existence enforcement at the write doors stays unchanged.
///
/// Public because the writers that call it land in later CAL layers: CAL-02's
/// feed diff, CAL-04's invite path, and CAL-07's outcome path each assert the
/// subject here rather than re-deriving the EVENT rule.
#[must_use = "the EVENT-subject assertion must be propagated, not discarded"]
pub fn require_event_subject(vault: &Vault, subject: &EntityId) -> Result<()> {
    if vault.get_entity_type(subject)? != Some(ENTITY_TYPE_EVENT) {
        return Err(Error::EntityNotFound);
    }
    Ok(())
}

/// Validates one `calendar.*` claim subject and value shape.
///
/// Structural only: IANA zones are not resolved and RRULEs are not parsed at
/// this layer. Every value is an exact key set with no extras, except the two
/// documented back-compat defaults (`busy_transparency` and `presence`).
pub(crate) fn validate_calendar_claim_structure(body: &ClaimBody) -> Result<()> {
    if !matches!(body.subject, ClaimSubject::Entity(_)) {
        return Err(invalid_claim("calendar claim subject must be an entity"));
    }
    if !is_calendar_claim_predicate(&body.predicate) {
        return Err(invalid_claim("unknown calendar claim predicate"));
    }
    match body.predicate.as_str() {
        PREDICATE_CALENDAR_TIME_KIND => decode_time_kind_value(&body.value).map(|_| ()),
        PREDICATE_CALENDAR_WALL_TIME => decode_wall_time_value(&body.value).map(|_| ()),
        PREDICATE_CALENDAR_TZ => {
            validate_bounded_text(as_str(&body.value, "calendar.tz must be a string")?, "tz")
        }
        PREDICATE_CALENDAR_RRULE => {
            let rrule = as_str(&body.value, "calendar.rrule must be a string")?;
            validate_rrule_text(rrule)
        }
        PREDICATE_CALENDAR_SERIES_MASTER => decode_series_master_value(&body.value).map(|_| ()),
        PREDICATE_CALENDAR_SERIES_EXCEPTION => {
            decode_series_exception_value(&body.value).map(|_| ())
        }
        PREDICATE_CALENDAR_SUCCESSOR => decode_successor_value(&body.value).map(|_| ()),
        PREDICATE_CALENDAR_ATTENDEE => decode_attendee_value(&body.value).map(|_| ()),
        PREDICATE_CALENDAR_MEETING_LINK => {
            let link = as_str(&body.value, "calendar.meeting_link must be a string")?;
            validate_meeting_link(link)
        }
        PREDICATE_CALENDAR_PASSPORT => decode_passport_value(&body.value).map(|_| ()),
        PREDICATE_CALENDAR_ORIGIN => {
            let origin = as_str(&body.value, "calendar.origin must be a string")?;
            CalendarOrigin::parse(origin)
                .map(|_| ())
                .ok_or_else(|| invalid_claim("calendar.origin is invalid"))
        }
        PREDICATE_CALENDAR_STATUS => decode_status_value(&body.value).map(|_| ()),
        _ => unreachable!("predicate membership checked above"),
    }
}

/// Decodes a `calendar.time_kind` value.
///
/// A missing `busy_transparency` key decodes as [`CalendarBusyTransparency::Busy`]
/// for back-compat; new writes include it.
pub(crate) fn decode_time_kind_value(value: &Value) -> Result<CalendarTimeKindValue> {
    let entries = value_map(value)?;
    validate_keys(entries, &[KEY_KIND, KEY_BUSY_TRANSPARENCY], &[KEY_KIND])?;
    let kind = CalendarTimeKind::parse(required_string(entries, KEY_KIND)?)
        .ok_or_else(|| invalid_claim("calendar time_kind kind is invalid"))?;
    let busy_transparency = match optional_string(entries, KEY_BUSY_TRANSPARENCY)? {
        Some(token) => CalendarBusyTransparency::parse(token)
            .ok_or_else(|| invalid_claim("calendar busy_transparency is invalid"))?,
        None => CalendarBusyTransparency::default(),
    };
    Ok(CalendarTimeKindValue {
        kind,
        busy_transparency,
    })
}

/// Decodes a `calendar.wall_time` value.
///
/// Field ranges are checked structurally; this is storage, not a calendar
/// computation, so day-of-month is not validated against the month.
pub(crate) fn decode_wall_time_value(value: &Value) -> Result<CalendarWallTimeValue> {
    let entries = value_map(value)?;
    let keys = [
        KEY_YEAR, KEY_MONTH, KEY_DAY, KEY_HOUR, KEY_MINUTE, KEY_SECOND,
    ];
    validate_keys(entries, &keys, &keys)?;
    Ok(CalendarWallTimeValue {
        y: required_i32(entries, KEY_YEAR)?,
        mo: required_u8_in_range(entries, KEY_MONTH, 1, 12)?,
        d: required_u8_in_range(entries, KEY_DAY, 1, 31)?,
        h: required_u8_in_range(entries, KEY_HOUR, 0, 23)?,
        mi: required_u8_in_range(entries, KEY_MINUTE, 0, 59)?,
        s: required_u8_in_range(entries, KEY_SECOND, 0, 60)?,
    })
}

/// Decodes a `calendar.series_master` value.
pub(crate) fn decode_series_master_value(value: &Value) -> Result<CalendarSeriesMasterValue> {
    let entries = value_map(value)?;
    let keys = [KEY_RRULE, KEY_DTSTART_UTC, KEY_TZ];
    validate_keys(entries, &keys, &keys)?;
    let rrule = required_string(entries, KEY_RRULE)?;
    validate_rrule_text(rrule)?;
    let tz = required_string(entries, KEY_TZ)?;
    validate_bounded_text(tz, "tz")?;
    Ok(CalendarSeriesMasterValue {
        rrule: rrule.to_owned(),
        dtstart_utc: required_u64(entries, KEY_DTSTART_UTC)?,
        tz: tz.to_owned(),
    })
}

/// Decodes a `calendar.series_exception` value.
pub(crate) fn decode_series_exception_value(value: &Value) -> Result<CalendarSeriesExceptionValue> {
    let entries = value_map(value)?;
    let keys = [KEY_MASTER_REF, KEY_UID, KEY_ORIGINAL_START_UTC];
    validate_keys(entries, &keys, &keys)?;
    let uid = required_string(entries, KEY_UID)?;
    validate_bounded_text(uid, "uid")?;
    Ok(CalendarSeriesExceptionValue {
        master_ref: required_entity_ref(entries, KEY_MASTER_REF)?,
        uid: uid.to_owned(),
        original_start_utc: required_u64(entries, KEY_ORIGINAL_START_UTC)?,
    })
}

/// Decodes a `calendar.successor` value.
pub(crate) fn decode_successor_value(value: &Value) -> Result<CalendarSuccessorValue> {
    let entries = value_map(value)?;
    validate_keys(entries, &[KEY_PREDECESSOR_REF], &[KEY_PREDECESSOR_REF])?;
    Ok(CalendarSuccessorValue {
        predecessor_ref: required_entity_ref(entries, KEY_PREDECESSOR_REF)?,
    })
}

/// Decodes a `calendar.attendee` value, preserving vendor role/partstat text.
pub(crate) fn decode_attendee_value(value: &Value) -> Result<CalendarAttendeeValue> {
    let entries = value_map(value)?;
    let keys = [KEY_WHO, KEY_ROLE, KEY_PARTSTAT];
    validate_keys(entries, &keys, &keys)?;
    let who = required_string(entries, KEY_WHO)?;
    let role = required_string(entries, KEY_ROLE)?;
    let partstat = required_string(entries, KEY_PARTSTAT)?;
    validate_bounded_text(who, "who")?;
    validate_bounded_text(role, "role")?;
    validate_bounded_text(partstat, "partstat")?;
    Ok(CalendarAttendeeValue {
        who: who.to_owned(),
        role: role.to_owned(),
        partstat: partstat.to_owned(),
    })
}

/// Decodes a `calendar.passport` value.
///
/// A missing `presence` key decodes as [`CalendarPassportPresence::Live`] for
/// back-compat; new writes include it. The content hash is MessagePack binary
/// of exactly 32 bytes.
pub(crate) fn decode_passport_value(value: &Value) -> Result<CalendarPassportValue> {
    let entries = value_map(value)?;
    let required = [
        KEY_SYSTEM,
        KEY_UID,
        KEY_LAST_SEQUENCE,
        KEY_CONTENT_HASH,
        KEY_DIRECTION,
        KEY_LAST_SEEN_AT,
    ];
    let mut allowed = required.to_vec();
    allowed.push(KEY_PRESENCE);
    validate_keys(entries, &allowed, &required)?;
    let system = required_string(entries, KEY_SYSTEM)?;
    let uid = required_string(entries, KEY_UID)?;
    validate_bounded_text(system, "system")?;
    validate_bounded_text(uid, "uid")?;
    let direction = CalendarPassportDirection::parse(required_string(entries, KEY_DIRECTION)?)
        .ok_or_else(|| invalid_claim("calendar passport direction is invalid"))?;
    let presence = match optional_string(entries, KEY_PRESENCE)? {
        Some(token) => CalendarPassportPresence::parse(token)
            .ok_or_else(|| invalid_claim("calendar passport presence is invalid"))?,
        None => CalendarPassportPresence::default(),
    };
    Ok(CalendarPassportValue {
        system: system.to_owned(),
        uid: uid.to_owned(),
        last_sequence: required_u32(entries, KEY_LAST_SEQUENCE)?,
        content_hash: required_binary_32(entries, KEY_CONTENT_HASH)?,
        direction,
        last_seen_at: required_u64(entries, KEY_LAST_SEEN_AT)?,
        presence,
    })
}

/// Decodes a `calendar.status` value.
pub(crate) fn decode_status_value(value: &Value) -> Result<CalendarStatusValue> {
    let entries = value_map(value)?;
    let keys = [KEY_STATUS, KEY_BASIS, KEY_RECORDED_AT];
    validate_keys(entries, &keys, &keys)?;
    let status = CalendarStatus::parse(required_string(entries, KEY_STATUS)?)
        .ok_or_else(|| invalid_claim("calendar status is invalid"))?;
    let basis = CalendarStatusBasis::parse(required_string(entries, KEY_BASIS)?)
        .ok_or_else(|| invalid_claim("calendar status basis is invalid"))?;
    Ok(CalendarStatusValue {
        status,
        basis,
        recorded_at: required_u64(entries, KEY_RECORDED_AT)?,
    })
}

fn value_map(value: &Value) -> Result<&[(Value, Value)]> {
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(invalid_claim("calendar claim value must be a map")),
    }
}

fn as_str<'a>(value: &'a Value, reason: &'static str) -> Result<&'a str> {
    value.as_str().ok_or_else(|| invalid_claim(reason))
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a Value> {
    let mut matches = entries
        .iter()
        .filter_map(|(candidate, value)| (candidate.as_str() == Some(key)).then_some(value));
    let value = matches
        .next()
        .ok_or_else(|| invalid_claim("calendar value missing required key"))?;
    if matches.next().is_some() {
        return Err(invalid_claim("calendar value contains duplicate key"));
    }
    Ok(value)
}

fn optional_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<Option<&'a Value>> {
    if entries
        .iter()
        .any(|(candidate, _)| candidate.as_str() == Some(key))
    {
        return required_value(entries, key).map(Some);
    }
    Ok(None)
}

fn required_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<&'a str> {
    as_str(
        required_value(entries, key)?,
        "calendar value string invalid",
    )
}

fn optional_string<'a>(entries: &'a [(Value, Value)], key: &str) -> Result<Option<&'a str>> {
    optional_value(entries, key)?
        .map(|value| as_str(value, "calendar value string invalid"))
        .transpose()
}

fn required_u64(entries: &[(Value, Value)], key: &str) -> Result<u64> {
    required_value(entries, key)?
        .as_u64()
        .ok_or_else(|| invalid_claim("calendar value integer invalid"))
}

fn required_u32(entries: &[(Value, Value)], key: &str) -> Result<u32> {
    u32::try_from(required_u64(entries, key)?)
        .map_err(|_| invalid_claim("calendar value integer out of range"))
}

fn required_i32(entries: &[(Value, Value)], key: &str) -> Result<i32> {
    required_value(entries, key)?
        .as_i64()
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| invalid_claim("calendar value integer out of range"))
}

fn required_u8_in_range(entries: &[(Value, Value)], key: &str, min: u8, max: u8) -> Result<u8> {
    let value = u8::try_from(required_u64(entries, key)?)
        .map_err(|_| invalid_claim("calendar wall_time field out of range"))?;
    if value < min || value > max {
        return Err(invalid_claim("calendar wall_time field out of range"));
    }
    Ok(value)
}

fn required_binary_32(entries: &[(Value, Value)], key: &str) -> Result<[u8; CONTENT_HASH_LEN]> {
    let Value::Binary(bytes) = required_value(entries, key)? else {
        return Err(invalid_claim("calendar content_hash must be binary"));
    };
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_claim("calendar content_hash must be 32 bytes"))
}

fn required_entity_ref(entries: &[(Value, Value)], key: &str) -> Result<EntityId> {
    let hex = required_string(entries, key)?;
    let id =
        EntityId::from_hex(hex).map_err(|_| invalid_claim("calendar entity reference invalid"))?;
    if id.to_hex() != hex {
        return Err(invalid_claim("calendar entity reference invalid"));
    }
    Ok(id)
}

/// Rejects extra keys, missing required keys, and non-string keys.
///
/// `allowed` is the full key set; `required` is the subset that must be present.
/// The two differ only where a documented back-compat default exists.
fn validate_keys(entries: &[(Value, Value)], allowed: &[&str], required: &[&str]) -> Result<()> {
    if entries.len() > allowed.len() {
        return Err(invalid_claim("calendar value key set invalid"));
    }
    if entries
        .iter()
        .any(|(key, _)| key.as_str().is_none_or(|key| !allowed.contains(&key)))
    {
        return Err(invalid_claim("calendar value key set invalid"));
    }
    for key in required {
        required_value(entries, key)?;
    }
    Ok(())
}

/// Bounded, non-empty, control-character-free text.
fn validate_bounded_text(value: &str, _field: &'static str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(invalid_claim("calendar text field length invalid"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid_claim("calendar text field has control characters"));
    }
    Ok(())
}

/// Verbatim RFC 5545 text: bounded and non-empty, never parsed at this layer.
fn validate_rrule_text(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_RRULE_BYTES {
        return Err(invalid_claim("calendar rrule length invalid"));
    }
    if value
        .chars()
        .any(|c| c.is_control() && c != '\r' && c != '\n')
    {
        return Err(invalid_claim("calendar rrule has control characters"));
    }
    Ok(())
}

/// Structural URL validation. Tolerant extraction stays an adapter concern.
fn validate_meeting_link(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES {
        return Err(invalid_claim("calendar meeting_link length invalid"));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid_claim(
            "calendar meeting_link has control characters",
        ));
    }
    Ok(())
}

fn invalid_claim(reason: &'static str) -> Error {
    Error::InvalidClaimBody(reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::assert_matches;
    use std::collections::BTreeSet;

    use crate::claim::{
        ClaimApprovalStatus, ClaimLifecycleStatus, encode_claim_body, validate_claim_body_bytes,
    };
    use crate::config::VaultConfig;
    use crate::registry::ENTITY_TYPE_PERSON;
    use crate::temporal::TimeRange;
    use crate::test_util::{entity, open_test_vault_with};

    /// Subject EVENT for value-shape fixtures.
    const SUBJECT_SEED: u8 = 0x51;
    /// A second EVENT referenced by series/successor values.
    const REF_SEED: u8 = 0x52;

    fn subject() -> EntityId {
        entity(SUBJECT_SEED)
    }

    fn map(entries: &[(&str, Value)]) -> Value {
        Value::Map(
            entries
                .iter()
                .map(|(key, value)| (Value::from(*key), value.clone()))
                .collect(),
        )
    }

    fn body(predicate: &str, value: Value) -> ClaimBody {
        ClaimBody::new(
            predicate,
            ClaimSubject::Entity(subject()),
            value,
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        )
    }

    /// Round-trips through the same codec storage uses, then through the
    /// write-only validator chokepoint.
    fn through_chokepoint(body: &ClaimBody) -> Result<()> {
        validate_claim_body_bytes(&encode_claim_body(body)?, false)
    }

    fn canonical_time_kind() -> Value {
        map(&[
            (KEY_KIND, Value::from(CalendarTimeKind::Zoned.as_str())),
            (
                KEY_BUSY_TRANSPARENCY,
                Value::from(CalendarBusyTransparency::Busy.as_str()),
            ),
        ])
    }

    fn canonical_wall_time() -> Value {
        map(&[
            (KEY_YEAR, Value::from(2026)),
            (KEY_MONTH, Value::from(8)),
            (KEY_DAY, Value::from(5)),
            (KEY_HOUR, Value::from(14)),
            (KEY_MINUTE, Value::from(30)),
            (KEY_SECOND, Value::from(0)),
        ])
    }

    fn canonical_passport() -> Value {
        map(&[
            (KEY_SYSTEM, Value::from("google")),
            (KEY_UID, Value::from("uid-1@example.com")),
            (KEY_LAST_SEQUENCE, Value::from(3)),
            (KEY_CONTENT_HASH, Value::Binary(vec![7u8; CONTENT_HASH_LEN])),
            (
                KEY_DIRECTION,
                Value::from(CalendarPassportDirection::TwoWay.as_str()),
            ),
            (KEY_LAST_SEEN_AT, Value::from(1_754_400_000_u64)),
            (
                KEY_PRESENCE,
                Value::from(CalendarPassportPresence::Live.as_str()),
            ),
        ])
    }

    fn canonical_series_master() -> Value {
        map(&[
            (KEY_RRULE, Value::from("FREQ=WEEKLY;BYDAY=MO")),
            (KEY_DTSTART_UTC, Value::from(1_754_400_000_u64)),
            (KEY_TZ, Value::from("Europe/Warsaw")),
        ])
    }

    fn canonical_series_exception() -> Value {
        map(&[
            (KEY_MASTER_REF, Value::from(entity(REF_SEED).to_hex())),
            (KEY_UID, Value::from("uid-1@example.com")),
            (KEY_ORIGINAL_START_UTC, Value::from(1_754_400_000_u64)),
        ])
    }

    fn canonical_successor() -> Value {
        map(&[(KEY_PREDECESSOR_REF, Value::from(entity(REF_SEED).to_hex()))])
    }

    fn canonical_attendee() -> Value {
        map(&[
            (KEY_WHO, Value::from("mailto:person@example.com")),
            (KEY_ROLE, Value::from("REQ-PARTICIPANT")),
            (KEY_PARTSTAT, Value::from("ACCEPTED")),
        ])
    }

    fn canonical_status() -> Value {
        map(&[
            (KEY_STATUS, Value::from(CalendarStatus::Confirmed.as_str())),
            (KEY_BASIS, Value::from(CalendarStatusBasis::Owner.as_str())),
            (KEY_RECORDED_AT, Value::from(1_754_400_000_u64)),
        ])
    }

    /// One canonical value per predicate, in table order.
    fn canonical_values() -> Vec<(&'static str, Value)> {
        vec![
            (PREDICATE_CALENDAR_TIME_KIND, canonical_time_kind()),
            (PREDICATE_CALENDAR_WALL_TIME, canonical_wall_time()),
            (PREDICATE_CALENDAR_TZ, Value::from("Europe/Warsaw")),
            (
                PREDICATE_CALENDAR_RRULE,
                Value::from("FREQ=WEEKLY;BYDAY=MO"),
            ),
            (PREDICATE_CALENDAR_SERIES_MASTER, canonical_series_master()),
            (
                PREDICATE_CALENDAR_SERIES_EXCEPTION,
                canonical_series_exception(),
            ),
            (PREDICATE_CALENDAR_SUCCESSOR, canonical_successor()),
            (PREDICATE_CALENDAR_ATTENDEE, canonical_attendee()),
            (
                PREDICATE_CALENDAR_MEETING_LINK,
                Value::from("https://meet.example.com/abc-defg-hij"),
            ),
            (PREDICATE_CALENDAR_PASSPORT, canonical_passport()),
            (
                PREDICATE_CALENDAR_ORIGIN,
                Value::from(CalendarOrigin::Imported.as_str()),
            ),
            (PREDICATE_CALENDAR_STATUS, canonical_status()),
        ]
    }

    #[test]
    fn calendar_claim_predicate_table_is_exact() {
        let minted: BTreeSet<&str> = CALENDAR_CLAIM_PREDICATES.iter().copied().collect();
        let expected: BTreeSet<&str> = BTreeSet::from([
            "calendar.time_kind",
            "calendar.wall_time",
            "calendar.tz",
            "calendar.rrule",
            "calendar.series_master",
            "calendar.series_exception",
            "calendar.successor",
            "calendar.attendee",
            "calendar.meeting_link",
            "calendar.passport",
            "calendar.origin",
            "calendar.status",
        ]);
        // Set-compare scoped "at this layer": ONE-1789 appends
        // `calendar.event_outcome` and updates this test in its own diff.
        assert_eq!(minted, expected);
        // Once each: no duplicate rows hiding behind the set compare.
        assert_eq!(CALENDAR_CLAIM_PREDICATES.len(), minted.len());
        assert_eq!(CALENDAR_CLAIM_PREDICATES.len(), 12);

        for predicate in CALENDAR_CLAIM_PREDICATES {
            assert!(is_calendar_claim_predicate(predicate));
        }
        // Exact-table membership, never a `calendar.` prefix match.
        assert!(!is_calendar_claim_predicate("calendar.unknown"));
        assert!(!is_calendar_claim_predicate("calendar.event_outcome"));
        assert!(!is_calendar_claim_predicate("calendar."));
    }

    #[test]
    fn calendar_claims_require_event_subjects() -> Result<()> {
        // Half 1 (byte level): a non-entity subject is rejected structurally.
        let edge_subject = ClaimBody::new(
            PREDICATE_CALENDAR_ORIGIN,
            ClaimSubject::Edge {
                source: entity(REF_SEED),
                target: subject(),
                kind: crate::edge::EdgeKind::ClaimOf,
            },
            Value::from(CalendarOrigin::Native.as_str()),
            1.0,
            ClaimApprovalStatus::Approved,
            ClaimLifecycleStatus::Active,
        );
        assert_matches!(
            through_chokepoint(&edge_subject),
            Err(Error::InvalidClaimBody(
                "calendar claim subject must be an entity"
            ))
        );

        // Half 2 (store level): an entity subject that is not an EVENT row is
        // rejected. The byte validator cannot reach storage, so this is the
        // comm.rs-style family assertion.
        let mut config = VaultConfig::device();
        config.map_size = 16 * 1024 * 1024;
        config.dimensions = 4;
        config.embedding_model = None;
        let (_dir, vault) = open_test_vault_with(config);

        let event = subject();
        let person = entity(REF_SEED);
        let missing = entity(0x53);
        let occurred = TimeRange { start: 1, end: 1 };
        vault.put_entity(&event, ENTITY_TYPE_EVENT, occurred, 1, b"event")?;
        vault.put_entity(&person, ENTITY_TYPE_PERSON, occurred, 1, b"person")?;

        require_event_subject(&vault, &event)?;
        assert_matches!(
            require_event_subject(&vault, &person),
            Err(Error::EntityNotFound)
        );
        assert_matches!(
            require_event_subject(&vault, &missing),
            Err(Error::EntityNotFound)
        );
        Ok(())
    }

    #[test]
    fn calendar_claim_validator_accepts_canonical_shapes() -> Result<()> {
        for (predicate, value) in canonical_values() {
            through_chokepoint(&body(predicate, value))?;
        }
        Ok(())
    }

    #[test]
    fn calendar_claim_validator_rejects_malformed_shapes() {
        let reject = |predicate: &str, value: Value| {
            assert_matches!(
                through_chokepoint(&body(predicate, value)),
                Err(Error::InvalidClaimBody(_)),
                "{predicate} must reject this value"
            );
        };

        // Extra key on an exact map.
        let mut extra = canonical_status();
        if let Value::Map(entries) = &mut extra {
            entries.push((Value::from("surprise"), Value::from(1)));
        }
        reject(PREDICATE_CALENDAR_STATUS, extra);

        // Unknown key replacing a required one.
        reject(
            PREDICATE_CALENDAR_SUCCESSOR,
            map(&[("successor_ref", Value::from(entity(REF_SEED).to_hex()))]),
        );

        // Duplicate key.
        reject(
            PREDICATE_CALENDAR_SUCCESSOR,
            Value::Map(vec![
                (
                    Value::from(KEY_PREDECESSOR_REF),
                    Value::from(entity(REF_SEED).to_hex()),
                ),
                (
                    Value::from(KEY_PREDECESSOR_REF),
                    Value::from(entity(REF_SEED).to_hex()),
                ),
            ]),
        );

        // Wrong scalar types.
        reject(PREDICATE_CALENDAR_TZ, Value::from(7));
        reject(PREDICATE_CALENDAR_ORIGIN, Value::from(true));
        reject(
            PREDICATE_CALENDAR_STATUS,
            map(&[
                (KEY_STATUS, Value::from(CalendarStatus::Confirmed.as_str())),
                (KEY_BASIS, Value::from(CalendarStatusBasis::Owner.as_str())),
                (KEY_RECORDED_AT, Value::from("not-a-timestamp")),
            ]),
        );
        // A map where a scalar is required.
        reject(PREDICATE_CALENDAR_MEETING_LINK, Value::Map(Vec::new()));

        // Invalid closed-set strings.
        reject(
            PREDICATE_CALENDAR_TIME_KIND,
            map(&[
                (KEY_KIND, Value::from("relative")),
                (
                    KEY_BUSY_TRANSPARENCY,
                    Value::from(CalendarBusyTransparency::Busy.as_str()),
                ),
            ]),
        );
        reject(
            PREDICATE_CALENDAR_TIME_KIND,
            map(&[
                (KEY_KIND, Value::from(CalendarTimeKind::Zoned.as_str())),
                (KEY_BUSY_TRANSPARENCY, Value::from("maybe")),
            ]),
        );
        reject(PREDICATE_CALENDAR_ORIGIN, Value::from("synthesized"));
        reject(
            PREDICATE_CALENDAR_PASSPORT,
            passport_with(KEY_DIRECTION, Value::from("bidirectional")),
        );
        reject(
            PREDICATE_CALENDAR_PASSPORT,
            passport_with(KEY_PRESENCE, Value::from("gone")),
        );
        reject(
            PREDICATE_CALENDAR_STATUS,
            map(&[
                (KEY_STATUS, Value::from("tentative")),
                (KEY_BASIS, Value::from(CalendarStatusBasis::Owner.as_str())),
                (KEY_RECORDED_AT, Value::from(1_u64)),
            ]),
        );
        reject(
            PREDICATE_CALENDAR_STATUS,
            map(&[
                (KEY_STATUS, Value::from(CalendarStatus::Cancelled.as_str())),
                (KEY_BASIS, Value::from("imported")),
                (KEY_RECORDED_AT, Value::from(1_u64)),
            ]),
        );

        // Empty text.
        reject(PREDICATE_CALENDAR_TZ, Value::from(""));
        reject(PREDICATE_CALENDAR_RRULE, Value::from(""));
        reject(PREDICATE_CALENDAR_MEETING_LINK, Value::from(""));
        reject(
            PREDICATE_CALENDAR_ATTENDEE,
            map(&[
                (KEY_WHO, Value::from("")),
                (KEY_ROLE, Value::from("REQ-PARTICIPANT")),
                (KEY_PARTSTAT, Value::from("ACCEPTED")),
            ]),
        );
        // Control characters in a URL.
        reject(
            PREDICATE_CALENDAR_MEETING_LINK,
            Value::from("https://meet.example.com/a\u{0}b"),
        );

        // Invalid wall-date field ranges.
        for (key, bad) in [
            (KEY_MONTH, 0_u64),
            (KEY_MONTH, 13),
            (KEY_DAY, 0),
            (KEY_DAY, 32),
            (KEY_HOUR, 24),
            (KEY_MINUTE, 60),
            (KEY_SECOND, 61),
        ] {
            let mut value = canonical_wall_time();
            if let Value::Map(entries) = &mut value {
                for (candidate, slot) in entries.iter_mut() {
                    if candidate.as_str() == Some(key) {
                        *slot = Value::from(bad);
                    }
                }
            }
            reject(PREDICATE_CALENDAR_WALL_TIME, value);
        }

        // Non-32-byte passport hashes, and a non-binary hash.
        reject(
            PREDICATE_CALENDAR_PASSPORT,
            passport_with(KEY_CONTENT_HASH, Value::Binary(vec![7u8; 31])),
        );
        reject(
            PREDICATE_CALENDAR_PASSPORT,
            passport_with(KEY_CONTENT_HASH, Value::Binary(vec![7u8; 33])),
        );
        reject(
            PREDICATE_CALENDAR_PASSPORT,
            passport_with(KEY_CONTENT_HASH, Value::from("7".repeat(64))),
        );

        // Malformed entity references.
        reject(
            PREDICATE_CALENDAR_SUCCESSOR,
            map(&[(KEY_PREDECESSOR_REF, Value::from("not-hex"))]),
        );
    }

    fn passport_with(key: &str, replacement: Value) -> Value {
        let mut value = canonical_passport();
        if let Value::Map(entries) = &mut value {
            for (candidate, slot) in entries.iter_mut() {
                if candidate.as_str() == Some(key) {
                    *slot = replacement.clone();
                }
            }
        }
        value
    }

    #[test]
    fn calendar_time_kind_busy_transparency_contract_round_trips() -> Result<()> {
        // Canonical map keys, both wire tokens, every kind.
        for kind in [
            CalendarTimeKind::Absolute,
            CalendarTimeKind::Zoned,
            CalendarTimeKind::Floating,
            CalendarTimeKind::AllDay,
        ] {
            for transparency in [
                CalendarBusyTransparency::Busy,
                CalendarBusyTransparency::Free,
            ] {
                let value = map(&[
                    (KEY_KIND, Value::from(kind.as_str())),
                    (KEY_BUSY_TRANSPARENCY, Value::from(transparency.as_str())),
                ]);
                through_chokepoint(&body(PREDICATE_CALENDAR_TIME_KIND, value.clone()))?;
                assert_eq!(
                    decode_time_kind_value(&value)?,
                    CalendarTimeKindValue {
                        kind,
                        busy_transparency: transparency,
                    }
                );
            }
        }

        // Missing-field back-compat default is busy.
        let legacy = map(&[(KEY_KIND, Value::from(CalendarTimeKind::Floating.as_str()))]);
        through_chokepoint(&body(PREDICATE_CALENDAR_TIME_KIND, legacy.clone()))?;
        assert_eq!(
            decode_time_kind_value(&legacy)?,
            CalendarTimeKindValue {
                kind: CalendarTimeKind::Floating,
                busy_transparency: CalendarBusyTransparency::Busy,
            }
        );

        // Ingest mapping from ICS TRANSP.
        assert_eq!(
            CalendarBusyTransparency::from_ics_transp(Some(ICS_TRANSP_TRANSPARENT)),
            CalendarBusyTransparency::Free
        );
        assert_eq!(
            CalendarBusyTransparency::from_ics_transp(Some(ICS_TRANSP_OPAQUE)),
            CalendarBusyTransparency::Busy
        );
        assert_eq!(
            CalendarBusyTransparency::from_ics_transp(None),
            CalendarBusyTransparency::Busy
        );
        // Kinds are never coerced into one another.
        assert_eq!(
            CalendarTimeKind::parse("all_day"),
            Some(CalendarTimeKind::AllDay)
        );
        assert_eq!(CalendarTimeKind::parse("allday"), None);
        Ok(())
    }

    #[test]
    fn calendar_passport_contract_round_trips() -> Result<()> {
        // This test never builds the UID index: CAL-02 owns that.
        for direction in [
            CalendarPassportDirection::Inbound,
            CalendarPassportDirection::Outbound,
            CalendarPassportDirection::TwoWay,
        ] {
            for presence in [
                CalendarPassportPresence::Live,
                CalendarPassportPresence::Absent,
            ] {
                let mut value = passport_with(KEY_DIRECTION, Value::from(direction.as_str()));
                value = {
                    let mut rebuilt = value.clone();
                    if let Value::Map(entries) = &mut rebuilt {
                        for (candidate, slot) in entries.iter_mut() {
                            if candidate.as_str() == Some(KEY_PRESENCE) {
                                *slot = Value::from(presence.as_str());
                            }
                        }
                    }
                    rebuilt
                };
                through_chokepoint(&body(PREDICATE_CALENDAR_PASSPORT, value.clone()))?;
                assert_eq!(
                    decode_passport_value(&value)?,
                    CalendarPassportValue {
                        system: "google".to_owned(),
                        uid: "uid-1@example.com".to_owned(),
                        last_sequence: 3,
                        content_hash: [7u8; CONTENT_HASH_LEN],
                        direction,
                        last_seen_at: 1_754_400_000,
                        presence,
                    }
                );
            }
        }

        // Missing presence decodes as Live for back-compat.
        let legacy = map(&[
            (KEY_SYSTEM, Value::from("google")),
            (KEY_UID, Value::from("uid-1@example.com")),
            (KEY_LAST_SEQUENCE, Value::from(3)),
            (KEY_CONTENT_HASH, Value::Binary(vec![7u8; CONTENT_HASH_LEN])),
            (
                KEY_DIRECTION,
                Value::from(CalendarPassportDirection::Inbound.as_str()),
            ),
            (KEY_LAST_SEEN_AT, Value::from(1_754_400_000_u64)),
        ]);
        through_chokepoint(&body(PREDICATE_CALENDAR_PASSPORT, legacy.clone()))?;
        assert_eq!(
            decode_passport_value(&legacy)?.presence,
            CalendarPassportPresence::Live
        );

        // Only inbound-bearing passports vote in imported-absence cancellation.
        assert!(CalendarPassportDirection::Inbound.is_inbound_bearing());
        assert!(CalendarPassportDirection::TwoWay.is_inbound_bearing());
        assert!(!CalendarPassportDirection::Outbound.is_inbound_bearing());
        Ok(())
    }

    #[test]
    fn calendar_status_contract_round_trips() -> Result<()> {
        for status in [CalendarStatus::Confirmed, CalendarStatus::Cancelled] {
            for basis in [
                CalendarStatusBasis::ImportedCancel,
                CalendarStatusBasis::ImportedAbsence,
                CalendarStatusBasis::Owner,
                CalendarStatusBasis::Booking,
            ] {
                let value = map(&[
                    (KEY_STATUS, Value::from(status.as_str())),
                    (KEY_BASIS, Value::from(basis.as_str())),
                    (KEY_RECORDED_AT, Value::from(1_754_400_000_u64)),
                ]);
                through_chokepoint(&body(PREDICATE_CALENDAR_STATUS, value.clone()))?;
                assert_eq!(
                    decode_status_value(&value)?,
                    CalendarStatusValue {
                        status,
                        basis,
                        recorded_at: 1_754_400_000,
                    }
                );
            }
        }
        // Exact value: recorded_at is required, not optional.
        assert_matches!(
            decode_status_value(&map(&[
                (KEY_STATUS, Value::from(CalendarStatus::Cancelled.as_str())),
                (
                    KEY_BASIS,
                    Value::from(CalendarStatusBasis::ImportedAbsence.as_str())
                ),
            ])),
            Err(Error::InvalidClaimBody(_))
        );
        Ok(())
    }

    #[test]
    fn calendar_series_master_is_claim_shaped() -> Result<()> {
        let value = canonical_series_master();
        let body = body(PREDICATE_CALENDAR_SERIES_MASTER, value.clone());
        assert_matches!(body.subject, ClaimSubject::Entity(id) if id == subject());
        through_chokepoint(&body)?;
        assert_eq!(
            decode_series_master_value(&value)?,
            CalendarSeriesMasterValue {
                rrule: "FREQ=WEEKLY;BYDAY=MO".to_owned(),
                dtstart_utc: 1_754_400_000,
                tz: "Europe/Warsaw".to_owned(),
            }
        );
        // RRULE text is stored verbatim; CAL-03 owns parsing, so a
        // structurally-bounded but semantically odd rule still stores.
        through_chokepoint(&body_series_master("FREQ=SECONDLY;COUNT=1"))?;
        Ok(())
    }

    fn body_series_master(rrule: &str) -> ClaimBody {
        body(
            PREDICATE_CALENDAR_SERIES_MASTER,
            map(&[
                (KEY_RRULE, Value::from(rrule)),
                (KEY_DTSTART_UTC, Value::from(1_754_400_000_u64)),
                (KEY_TZ, Value::from("Europe/Warsaw")),
            ]),
        )
    }

    #[test]
    fn calendar_series_exception_is_claim_shaped() -> Result<()> {
        let value = canonical_series_exception();
        let body = body(PREDICATE_CALENDAR_SERIES_EXCEPTION, value.clone());
        assert_matches!(body.subject, ClaimSubject::Entity(id) if id == subject());
        through_chokepoint(&body)?;
        let decoded = decode_series_exception_value(&value)?;
        assert_eq!(
            decoded,
            CalendarSeriesExceptionValue {
                master_ref: entity(REF_SEED),
                uid: "uid-1@example.com".to_owned(),
                original_start_utc: 1_754_400_000,
            }
        );
        // Exception identity is self-contained: (uid, original_start_utc) is
        // carried by the claim value, so masking never needs a second read.
        assert_eq!(
            (decoded.uid.as_str(), decoded.original_start_utc),
            ("uid-1@example.com", 1_754_400_000)
        );
        Ok(())
    }

    #[test]
    fn calendar_successor_is_claim_shaped() -> Result<()> {
        let value = canonical_successor();
        let body = body(PREDICATE_CALENDAR_SUCCESSOR, value.clone());
        assert_matches!(body.subject, ClaimSubject::Entity(id) if id == subject());
        through_chokepoint(&body)?;
        assert_eq!(
            decode_successor_value(&value)?,
            CalendarSuccessorValue {
                predecessor_ref: entity(REF_SEED),
            }
        );
        Ok(())
    }

    #[test]
    fn calendar_descriptor_rows_cover_predicates_once() {
        let rows = claim_class_descriptors();
        let covered: BTreeSet<&str> = rows.iter().map(|row| row.predicate).collect();
        let predicates: BTreeSet<&str> = CALENDAR_CLAIM_PREDICATES.iter().copied().collect();
        // One-to-one: no predicate is missing and none is described twice.
        assert_eq!(covered, predicates);
        assert_eq!(rows.len(), covered.len());

        for row in &rows {
            assert!(
                !row.enforcement,
                "{} must not be enforcement-gated",
                row.predicate
            );
            assert!(
                !row.restrictive,
                "{} must not be restrictive",
                row.predicate
            );
            assert!(
                matches!(row.write_class, "recorded" | "human_ruled" | "ordinary"),
                "{} has write_class outside the allowed tokens",
                row.predicate
            );
            let expect_recorded = matches!(
                row.predicate,
                PREDICATE_CALENDAR_PASSPORT | PREDICATE_CALENDAR_ORIGIN
            );
            if expect_recorded {
                assert_eq!(row.write_class, "recorded", "{}", row.predicate);
                assert!(row.projector_only, "{}", row.predicate);
            } else {
                assert_eq!(row.write_class, "ordinary", "{}", row.predicate);
                assert!(!row.projector_only, "{}", row.predicate);
            }
        }
    }
}
