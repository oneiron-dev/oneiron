//! ICS (RFC 5545) codec: feed parse half plus iMIP emit half.
//!
//! The parse half (CAL-02, ONE-1784) turns a complete `.ics` feed body into
//! calendar-owned Rust rows. Parsing runs through the already-landed
//! `icalendar` dependency, but no `icalendar` type crosses a public signature
//! here — the crate's parser types stay private to this module, exactly like
//! the IANA database stays private to [`super::tz`].
//!
//! Three laws the parse half owns:
//!
//! * **Per-VEVENT hashing, never whole-feed.** [`ParsedVEvent::content_hash`]
//!   is SHA-256 over a deterministic canonical VEVENT representation, so one
//!   unchanged event in a changed feed still diffs as unchanged. `DTSTAMP` is
//!   excluded from the canonical form: it changes on every export and would
//!   make the same-SEQUENCE skip path unreachable.
//! * **Completeness before truth.** [`parse_ics_feed`] fails the whole feed
//!   unless the input is a complete `VCALENDAR` document (strict begin/end
//!   sentinel check plus a full parse). A truncated or malformed body is a
//!   typed [`super::CalendarError::IcsParse`], never a partial event set the
//!   diff could mistake for source absence.
//! * **Transparency is validated to the wire tokens.** `TRANSP` maps through
//!   [`super::claims::CalendarBusyTransparency::from_ics_transp`], which fails
//!   closed to busy for absent, opaque, or unknown values.
//!
//! Timezone handling: `DTSTART`/`DTEND` in UTC (`...Z`) form convert directly;
//! `TZID`-parametrized wall times cross the CAL-01 border
//! ([`super::tz::wall_to_utc`]); floating times (no `Z`, no `TZID`) convert
//! to `None` — the adapter never guesses a zone for them, and the runner
//! treats a missing instant as "no usable time", not as an error.
//!
//! The emit half (CAL-04, ONE-1786) is the mirror: it turns our meeting state
//! into the exact `text/calendar` bytes an iMIP part carries. `METHOD` is
//! always explicit, UID is rendered once with a strictly increasing SEQUENCE,
//! and the event's own zone label rides beside the UTC instants, validated
//! against the IANA database first. See [`emit_imip_ics`] and
//! [`ImipEmitRequest`].

mod emit;
mod parse;

pub use self::emit::{
    IMIP_EVENT_TZID_PROPERTY, IMIP_PRODUCT_ID, ImipEmitRequest, emit_imip_ics, persist_imip_blob,
};
pub use self::parse::{ParsedIcsFeed, ParsedVEvent, parse_ics_feed};

pub(crate) use self::parse::invite_organizer;

// Lets the moved bodies keep their `super::...` paths verbatim.
pub(super) use super::{invite, tz};
