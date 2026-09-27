//! Renderer-neutral booking conversion data, derived only from public slots and owner copy.
//!
//! These are presentation hints, not another availability or booking authority.

use std::fmt::Write;

use serde::{Deserialize, Serialize};

use super::{BookingError, EventTypeKey, PublicBookingPageToken, RankedSlot, SlotMask};
use crate::calendar::tz::utc_to_wall;
use crate::lens::LensText;

/// Owner-authored content. A host chooses layout, localization and assets.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingLandingContent {
    pub photo_path: Option<String>,
    pub intro: String,
    pub faq: Vec<BookingFaq>,
    pub prep_path: Option<String>,
    /// The small pre-confirm subset; a host collects other intake after confirm.
    pub preconfirm_field_keys: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingFaq {
    pub question: String,
    pub answer: String,
}

impl BookingLandingContent {
    /// Checked both when the owner writes and when a public page is read.
    pub fn validate(&self) -> Result<(), BookingError> {
        let bounded = |text: &str, limit: usize| text.len() <= limit;
        if !bounded(&self.intro, 2048)
            || self.faq.len() > 8
            || self.faq.iter().any(|faq| {
                faq.question.trim().is_empty()
                    || faq.answer.trim().is_empty()
                    || !bounded(&faq.question, 256)
                    || !bounded(&faq.answer, 1024)
            })
            || self.preconfirm_field_keys.len() > 3
            || self
                .preconfirm_field_keys
                .iter()
                .enumerate()
                .any(|(index, key)| {
                    key.trim().is_empty()
                        || !bounded(key, 64)
                        || self.preconfirm_field_keys[..index].contains(key)
                })
            || [self.photo_path.as_deref(), self.prep_path.as_deref()]
                .into_iter()
                .flatten()
                .any(|path| !safe_asset_path(path))
        {
            return Err(BookingError::InvalidConfig(
                "public booking landing content is invalid or exceeds bounds".to_owned(),
            ));
        }
        // The public lens stores the entire object in one JSON MetaLine value.
        // Check those exact serialized bytes at the owner write/read door too:
        // raw length alone misses escaping of quotes and control characters.
        let json = serde_json::to_string(self).map_err(|_| {
            BookingError::InvalidConfig("public booking landing content cannot encode".to_owned())
        })?;
        LensText::new(json).map_err(|_| {
            BookingError::InvalidConfig(
                "public booking landing content exceeds lens bounds".to_owned(),
            )
        })?;
        Ok(())
    }
}

// Paths are inert same-origin asset references, not fetch instructions or redirects.
fn safe_asset_path(path: &str) -> bool {
    path.len() <= 512
        && path.starts_with('/')
        && !path.starts_with("//")
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
        && path
            .split('/')
            .skip(1)
            .all(|part| part != "." && part != "..")
        && !path.starts_with("/public/booking/")
}

/// A five-choice first view; the full Slots mask remains authoritative and
/// accessible for see-more. The recommended slot is one of these five.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingSlotPreview {
    pub visible: Vec<RankedSlot>,
    pub recommended_start_utc: Option<u64>,
    pub remaining_count: usize,
}

pub fn booking_slot_preview(mask: &SlotMask) -> BookingSlotPreview {
    let visible: Vec<_> = mask.slots.iter().take(5).cloned().collect();
    let recommended_start_utc = visible
        .iter()
        .max_by(|a, b| {
            a.rank
                .total_cmp(&b.rank)
                .then_with(|| b.start_utc.cmp(&a.start_utc))
        })
        .map(|slot| slot.start_utc);
    BookingSlotPreview {
        visible,
        recommended_start_utc,
        remaining_count: mask.slots.len().saturating_sub(5),
    }
}

/// A time and host-supplied public-face hyperlink for copy-paste messages.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingSnippetLink {
    pub label: String,
    pub href: String,
}

/// An inert, URL-carried choice. The host may use it to focus a page but must
/// re-solve and revalidate before any hold or confirm; it is not authority.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingSnippetSelection {
    pub event_type: EventTypeKey,
    pub start_utc: u64,
    pub visitor_tz: String,
}

/// Generate one or two concrete linked times, never a naked URL or an
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
    if !(1..=2).contains(&selected_start_utc.len())
        || selected_start_utc.len() == 2 && selected_start_utc[0] == selected_start_utc[1]
    {
        return Err(BookingError::Surface(
            "invalid booking snippet selection".to_owned(),
        ));
    }
    // The trusted host supplies its public-face URL, never the per-vault JSON
    // route. A query hint is added only after validating its exact capability.
    if !valid_public_page_url(public_page_url, page_token)
        || mask.event_type.0.trim().is_empty()
        || mask.event_type.0.len() > 64
        || visitor_tz.len() > 64
    {
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
                    "{public_page_url}?event_type={}&start_utc={}&visitor_tz={}",
                    encode_component(&mask.event_type.0),
                    slot.start_utc,
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
    let mut parts = query.split('&');
    let event_type = decode_component(parts.next()?.strip_prefix("event_type=")?)?;
    let start_utc = parts.next()?.strip_prefix("start_utc=")?.parse().ok()?;
    let visitor_tz = decode_component(parts.next()?.strip_prefix("visitor_tz=")?)?;
    if parts.next().is_some()
        || event_type.trim().is_empty()
        || event_type.len() > 64
        || visitor_tz.len() > 64
        || utc_to_wall(start_utc, &visitor_tz).is_err()
    {
        return None;
    }
    Some(BookingSnippetSelection {
        event_type: EventTypeKey(event_type),
        start_utc,
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

#[cfg(test)]
#[path = "conversion/tests.rs"]
mod tests;
