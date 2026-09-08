//! Calendar claim predicates, descriptor rows, and shared limits.

use crate::calendar::outcome::PREDICATE_CALENDAR_EVENT_OUTCOME;

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
/// these classes. `calendar.event_outcome` (CAL-07) is the one member whose
/// constant lives in a sibling module — [`super::outcome`] owns its semantics —
/// but the table, the validator, and the descriptor row stay here, so the family
/// still has exactly one home.
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
    PREDICATE_CALENDAR_EVENT_OUTCOME,
];

/// Upper bound for every bounded text field in this family.
pub(super) const MAX_TEXT_BYTES: usize = 512;

/// Upper bound for verbatim RFC 5545 recurrence text.
pub(super) const MAX_RRULE_BYTES: usize = 2048;

/// Content hashes are SHA-256 sized.
pub(super) const CONTENT_HASH_LEN: usize = 32;

/// ICS `TRANSP` property value mapping to [`CalendarBusyTransparency::Busy`].
pub const ICS_TRANSP_OPAQUE: &str = "OPAQUE";

/// ICS `TRANSP` property value mapping to [`CalendarBusyTransparency::Free`].
pub const ICS_TRANSP_TRANSPARENT: &str = "TRANSPARENT";

/// Write class for claims an engine projector records rather than a human asserts.
const WRITE_CLASS_RECORDED: &str = "recorded";

/// Write class for ordinary claims.
const WRITE_CLASS_ORDINARY: &str = "ordinary";

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
/// every other predicate, including `calendar.status` and
/// `calendar.event_outcome`, is ordinary — an outcome may be owner-attested, so
/// it is not projector-only. No calendar class is enforcement-gated or
/// restrictive: none of them is a consent surface.
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
