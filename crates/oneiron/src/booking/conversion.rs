//! Renderer-neutral booking conversion data, derived only from public slots and owner copy.
//!
//! These are presentation hints, not another availability or booking authority.

use std::fmt::Write;

use serde::{Deserialize, Serialize};

use super::{BookingError, EventTypeKey, PublicBookingPageToken, RankedSlot, SlotMask};
use crate::calendar::tz::utc_to_wall;

#[doc(hidden)]
use oneiron_records::booking::conversion::safe_asset_path;
#[doc(hidden)]
pub use oneiron_records::booking::conversion::{
    BookingFaq, BookingLandingContent, BookingSlotPreview, BookingSnippetLink,
    BookingSnippetSelection, booking_slot_preview,
};

/// Generate bounded concrete linked times, never a naked URL or an
/// unverified wall-clock guess. This does not reserve the selected slots.
/// The trusted host supplies the public-face URL and renders copy around these
/// links; the engine supplies no product prose or per-vault JSON route.
pub fn booking_snippet_links(
    mask: &SlotMask,
    selected_start_utc: &[u64],
    visitor_tz: &str,
    page_token: &PublicBookingPageToken,
    public_page_url: &str,
) -> Result<Vec<BookingSnippetLink>, BookingError> {
    if selected_start_utc.is_empty()
        || selected_start_utc.len() > mask.slots.len().min(128)
        || selected_start_utc
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != selected_start_utc.len()
    {
        return Err(BookingError::Surface(
            "invalid booking snippet selection".to_owned(),
        ));
    }
    // The trusted host supplies its public-face URL, never the per-vault JSON
    // route. A query hint is added only after validating its exact capability.
    if !valid_public_page_url(public_page_url, page_token) || mask.event_type.0.trim().is_empty() {
        return Err(BookingError::Surface(
            "invalid public-face booking URL or hint".to_owned(),
        ));
    }
    super::project_at_rung(
        &[],
        super::DisclosureRung::Slots,
        super::SurfaceClass::Public,
        Some(mask),
    )?;
    // Check even for empty masks; an unknown zone must never silently use UTC.
    utc_to_wall(mask.window_start_utc, visitor_tz)
        .map_err(|_| BookingError::Surface("invalid booking snippet timezone".to_owned()))?;
    selected_start_utc
        .iter()
        .map(|start| {
            let slot = mask
                .slots
                .iter()
                .find(|slot| slot.start_utc == *start)
                .ok_or_else(|| {
                    BookingError::Surface("snippet time is not an offered slot".to_owned())
                })?;
            let wall = utc_to_wall(slot.start_utc, visitor_tz).map_err(|_| {
                BookingError::Surface("invalid booking snippet timezone".to_owned())
            })?;
            let utc = utc_to_wall(slot.start_utc, "UTC").map_err(|_| {
                BookingError::Surface("invalid booking snippet instant".to_owned())
            })?;
            Ok(BookingSnippetLink {
                label: format!(
                    "{:04}-{:02}-{:02} {:02}:{:02} {visitor_tz} ({:04}-{:02}-{:02} {:02}:{:02} UTC)",
                    wall.y, wall.mo, wall.d, wall.h, wall.mi,
                    utc.y, utc.mo, utc.d, utc.h, utc.mi
                ),
                href: format!(
                    "{public_page_url}?event_type={}&start_utc={}&end_utc={}&visitor_tz={}",
                    encode_component(&mask.event_type.0),
                    slot.start_utc,
                    slot.end_utc,
                    encode_component(visitor_tz),
                ),
            })
        })
        .collect()
}

/// Decode only this exact hint contract; the returned choice is not a booking
/// grant. A host still checks live availability and the lifecycle writer before
/// holding or confirming, even if it preselects the time in its own UI.
#[must_use]
pub fn booking_snippet_selection_from_url(
    href: &str,
    page_token: &PublicBookingPageToken,
) -> Option<BookingSnippetSelection> {
    let (page_url, query) = href.split_once('?')?;
    if !valid_public_page_url(page_url, page_token) {
        return None;
    }
    parse_booking_snippet_query(query)
}

/// The one closed query parser shared by host public-face links and the
/// engine's JSON model route. A query is a hint, never booking authority.
#[must_use]
pub fn parse_booking_snippet_query(query: &str) -> Option<BookingSnippetSelection> {
    // A query of any length (ABC row 67): a long event type's hint parses.
    let mut parts = query.split('&');
    let event_type = decode_component(parts.next()?.strip_prefix("event_type=")?)?;
    let start_utc = parts.next()?.strip_prefix("start_utc=")?.parse().ok()?;
    let end_utc = parts.next()?.strip_prefix("end_utc=")?.parse().ok()?;
    let visitor_tz = decode_component(parts.next()?.strip_prefix("visitor_tz=")?)?;
    if parts.next().is_some()
        || event_type.trim().is_empty()
        || start_utc >= end_utc
        || utc_to_wall(start_utc, &visitor_tz).is_err()
    {
        return None;
    }
    Some(BookingSnippetSelection {
        event_type: EventTypeKey(event_type),
        start_utc,
        end_utc,
        visitor_tz,
    })
}

fn valid_public_page_url(url: &str, page_token: &PublicBookingPageToken) -> bool {
    let Some(hex) = page_token.0.strip_prefix("bkp_") else {
        return false;
    };
    if hex.len() != 32
        || !hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return false;
    }
    url.strip_prefix("https://")
        .and_then(|rest| rest.split_once('/'))
        .is_some_and(|(host, path)| {
            !host.is_empty()
                && host.contains('.')
                && host.split('.').all(|label| {
                    !label.is_empty()
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
                && path.rsplit('/').next() == Some(page_token.0.as_str())
                && !path.starts_with('/')
                && !path.starts_with("public/booking/")
                && path
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-'))
        })
}

fn encode_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            write!(encoded, "%{byte:02X}").expect("string formatting cannot fail");
        }
    }
    encoded
}

fn decode_component(value: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut input = value.bytes();
    while let Some(byte) = input.next() {
        if byte == b'%' {
            let pair = [input.next()?, input.next()?];
            decoded.push(u8::from_str_radix(std::str::from_utf8(&pair).ok()?, 16).ok()?);
        } else {
            decoded.push(byte);
        }
    }
    let decoded = String::from_utf8(decoded).ok()?;
    (encode_component(&decoded) == value).then_some(decoded)
}

// BK-07's strict slot hint, configurable wake and live-vault due door extend
// the owner-authored landing/preview data without duplicating its authority.
#[path = "conversion/policy.rs"]
mod policy;
#[path = "conversion/ux.rs"]
mod ux;
pub use self::policy::{
    BookingConversionPolicy, BookingConversionPolicyRow, BookingPolicyPrecedence,
    BookingPolicyScope, resolve_booking_conversion_rows,
};
pub use self::ux::{
    BookingIntakeStages, BookingReminder, BookingShortlist, BookingSlotLinkHint,
    BookingSnippetCopy, ConfigurableReminderWake, ConversionError, MeetingLocation, ReminderAction,
    ReminderStep, RepeatNoShowOffer, ZonedBookingTime, booking_display_zones, booking_due_reminder,
    booking_intake_stages, booking_reminder_wakes, booking_reminders, booking_shortlist,
    booking_slots_snippet, booking_suggested_slot, booking_zoned_time, parse_booking_slot_link,
    repeat_no_show_offer,
};
