//! BK-07 conversion data. Pure plans only: the host owns copy, delivery,
//! intake collection, and the physical-meeting UI. No plan grants authority.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::booking::{PUBLIC_BOOKING_ROUTE_PREFIX, PublicBookingPageToken, RankedSlot};
use crate::calendar::tz::utc_to_wall;

/// Errors are explicit: invalid zone names and times never become UTC labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversionError {
    InvalidSlots,
    InvalidConfig,
    InvalidZone,
    InvalidOrigin,
    InvalidToken,
}

/// The first-ranked slot is the recommended one; the rest remain available
/// through a separate see-more action. Never re-rank the solver's answer.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BookingShortlist {
    pub recommended: Option<RankedSlot>,
    pub visible: Vec<RankedSlot>,
    pub more_count: usize,
}

/// Show three to five ranked slots, and keep the whole solver result available
/// for the host's separate availability query. Empty availability is valid.
pub fn booking_shortlist(
    slots: &[RankedSlot],
    visible_count: usize,
) -> Result<BookingShortlist, ConversionError> {
    if !(3..=5).contains(&visible_count) {
        return Err(ConversionError::InvalidConfig);
    }
    if slots
        .iter()
        .any(|slot| slot.start_utc >= slot.end_utc || !slot.rank.is_finite())
        || slots.windows(2).any(|pair| {
            pair[0].rank < pair[1].rank
                || (pair[0].rank == pair[1].rank
                    && (pair[0].start_utc, pair[0].end_utc) > (pair[1].start_utc, pair[1].end_utc))
        })
    {
        return Err(ConversionError::InvalidSlots);
    }
    Ok(BookingShortlist {
        recommended: slots.first().cloned(),
        visible: slots.iter().take(visible_count).cloned().collect(),
        more_count: slots.len().saturating_sub(visible_count),
    })
}

/// A link carries the configured event type, selected visitor zone, and one
/// half-open UTC slot. It is a hint only, never proof that the solver offered
/// the slot or that a hold is authorized.
#[derive(Clone, Debug, PartialEq)]
pub struct BookingSlotLinkHint {
    pub event_type: crate::booking::EventTypeKey,
    pub visitor_tz: String,
    pub start_utc: u64,
    pub end_utc: u64,
}

fn hex_text(value: &str) -> String {
    use std::fmt::Write;
    let mut hex = String::with_capacity(value.len() * 2);
    for byte in value.bytes() {
        write!(&mut hex, "{byte:02x}").expect("write to string");
    }
    hex
}

fn decode_hex_text(value: &str, max_bytes: usize) -> Option<String> {
    if value.is_empty()
        || value.len() > max_bytes * 2
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect::<Option<Vec<_>>>()?;
    String::from_utf8(bytes).ok()
}

/// Parse only the snippet generator's closed query shape. No arbitrary URL
/// or query member can become an operation argument or an event identifier.
#[must_use]
pub fn parse_booking_slot_link(query: Option<&str>) -> Option<BookingSlotLinkHint> {
    let mut parts = query.filter(|query| query.len() <= 512)?.split('&');
    let event_type = decode_hex_text(parts.next()?.strip_prefix("event_type=")?, 64)?;
    let visitor_tz = decode_hex_text(parts.next()?.strip_prefix("visitor_tz=")?, 64)?;
    let start_utc = parts
        .next()?
        .strip_prefix("start_utc=")?
        .parse::<u64>()
        .ok()?;
    let end_utc = parts
        .next()?
        .strip_prefix("end_utc=")?
        .parse::<u64>()
        .ok()?;
    if parts.next().is_some()
        || event_type.trim().is_empty()
        || start_utc >= end_utc
        || booking_zoned_time(start_utc, &visitor_tz).is_err()
    {
        return None;
    }
    Some(BookingSlotLinkHint {
        event_type: crate::booking::EventTypeKey(event_type),
        visitor_tz,
        start_utc,
        end_utc,
    })
}

/// A parsed hint selects only an exact slot in the fresh solver answer.
#[must_use]
pub fn booking_suggested_slot(
    slots: &[RankedSlot],
    hint: &BookingSlotLinkHint,
) -> Option<RankedSlot> {
    slots
        .iter()
        .find(|slot| slot.start_utc == hint.start_utc && slot.end_utc == hint.end_utc)
        .cloned()
}

/// Host-configured intake keys, split into the short confirm step and fields
/// collected after confirmation. The engine never treats this plan as a grant
/// to edit a confirmed event; a host must use an authorized write door.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookingIntakeStages {
    pub before_confirm: Vec<String>,
    pub after_confirm: Vec<String>,
}

pub fn booking_intake_stages(
    fields: &[String],
    before_confirm: usize,
) -> Result<BookingIntakeStages, ConversionError> {
    if !(2..=3).contains(&before_confirm) || fields.len() < before_confirm || fields.len() > 16 {
        return Err(ConversionError::InvalidConfig);
    }
    let mut unique = BTreeSet::new();
    for field in fields {
        if field.is_empty()
            || field.len() > 64
            || !field
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || !unique.insert(field)
        {
            return Err(ConversionError::InvalidConfig);
        }
    }
    Ok(BookingIntakeStages {
        before_confirm: fields[..before_confirm].to_vec(),
        after_confirm: fields[before_confirm..].to_vec(),
    })
}

/// A scheduled reminder is an instruction to the host's existing durable wake
/// and delivery path, not a delivery or a new timer. A wake must recheck the
/// booking's live status and deduplicate the attempt before sending.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BookingReminder {
    pub due_utc: u64,
    pub action: ReminderAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReminderAction {
    RescheduleFirst,
}

/// The two offset dials are owner configuration, not fixed copy or policy.
/// Overdue steps are omitted; a newly confirmed near-term meeting must not
/// receive an immediate stale reminder.
pub fn booking_reminders(
    start_utc: u64,
    now_utc: u64,
    first_before_secs: u64,
    second_before_secs: u64,
) -> Result<Vec<BookingReminder>, ConversionError> {
    if first_before_secs <= second_before_secs || second_before_secs == 0 {
        return Err(ConversionError::InvalidConfig);
    }
    Ok([first_before_secs, second_before_secs]
        .into_iter()
        .filter_map(|offset| start_utc.checked_sub(offset))
        .filter(|due| *due > now_utc)
        .map(|due_utc| BookingReminder {
            due_utc,
            action: ReminderAction::RescheduleFirst,
        })
        .collect())
}

/// Stable identity of a scheduled wake. The host REPLACES the wake on a move
/// and removes it on a cancel. A stale wake is refused again at fire time.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ReminderStep {
    First,
    Second,
}

impl ReminderStep {
    fn as_str(self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Second => "second",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurableReminderWake {
    /// The same id on reschedule, so no second schedule accumulates.
    pub id: String,
    /// Canonical hex, never an authority token or public page address.
    pub event_ref: String,
    pub expected_start_utc: u64,
    pub due_utc: u64,
    pub step: ReminderStep,
}

fn reminder_wake_id(event_ref: &crate::EntityId, step: ReminderStep) -> String {
    format!("booking.reminder.{}:{}", step.as_str(), event_ref.to_hex())
}

/// Map the two owner-configured offsets to stable per-booking host wakes.
/// Scheduling belongs to the host, through its existing durable wake service.
pub fn booking_reminder_wakes(
    event_ref: crate::EntityId,
    start_utc: u64,
    now_utc: u64,
    first_before_secs: u64,
    second_before_secs: u64,
) -> Result<Vec<ConfigurableReminderWake>, ConversionError> {
    let planned = booking_reminders(start_utc, now_utc, first_before_secs, second_before_secs)?;
    Ok(planned
        .into_iter()
        .map(|reminder| {
            let step = if start_utc - reminder.due_utc == first_before_secs {
                ReminderStep::First
            } else {
                ReminderStep::Second
            };
            ConfigurableReminderWake {
                id: reminder_wake_id(&event_ref, step),
                event_ref: event_ref.to_hex(),
                expected_start_utc: start_utc,
                due_utc: reminder.due_utc,
                step,
            }
        })
        .collect())
}

/// Recheck live booking truth when a host wake fires. This is only permission
/// to assemble a reschedule-first reminder; delivery still needs the ordinary
/// outbound authorization, one-shot dedupe, and a recipient-bound send.
///
/// # Errors
/// A corrupt or unreadable booking aborts the wake, never sends by default.
pub fn booking_due_reminder(
    vault: &crate::Vault,
    wake: &ConfigurableReminderWake,
    fired_at: u64,
) -> Result<Option<ReminderAction>, crate::booking::BookingError> {
    let event_ref = crate::EntityId::from_hex(&wake.event_ref).map_err(|_| {
        crate::booking::BookingError::InvalidConstraint("reminder EVENT id is invalid".to_owned())
    })?;
    if wake.event_ref != event_ref.to_hex()
        || wake.id != reminder_wake_id(&event_ref, wake.step)
        || wake.due_utc >= wake.expected_start_utc
        || fired_at < wake.due_utc
        || fired_at >= wake.expected_start_utc
    {
        return Ok(None);
    }
    // No independent read of the EVENT body or old snapshot: the lifecycle
    // reads its current status claim and occurrence in one read transaction.
    let current = crate::booking::lifecycle::confirmed_start_for_reminder(vault, &event_ref)?;
    Ok((current == Some(wake.expected_start_utc)).then_some(ReminderAction::RescheduleFirst))
}

/// A verified prior no-show may offer an extra step, never silently impose a
/// payment or pre-confirm OTP. Confirm-link remains an explicit owner opt-in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepeatNoShowOffer {
    Ordinary,
    ConfirmLink,
}

pub fn repeat_no_show_offer(
    prior_outcomes_for_contact: &[crate::calendar::outcome::EventOutcome],
    owner_enabled_confirm_link: bool,
) -> RepeatNoShowOffer {
    // Unknown (including silence), cancellations, and held calls are not
    // evidence of a no-show. The caller must resolve these outcomes from the
    // event ledger for the same contact, not from email-delivery silence.
    let verified_prior_no_shows = prior_outcomes_for_contact
        .iter()
        .filter(|outcome| **outcome == crate::calendar::outcome::EventOutcome::NoShow)
        .take(2)
        .count();
    if verified_prior_no_shows >= 2 && owner_enabled_confirm_link {
        RepeatNoShowOffer::ConfirmLink
    } else {
        RepeatNoShowOffer::Ordinary
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MeetingLocation {
    Remote,
    Physical,
}

/// The IANA identifier itself is the label (never an ambiguous abbreviation).
/// UTC is only an instant, not a fallback display zone. Both parties use the
/// calendar's single conversion border and the same instant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ZonedBookingTime {
    pub utc: u64,
    pub zone: String,
    pub local: String,
}

pub fn booking_zoned_time(utc: u64, zone: &str) -> Result<ZonedBookingTime, ConversionError> {
    let wall = utc_to_wall(utc, zone).map_err(|_| ConversionError::InvalidZone)?;
    Ok(ZonedBookingTime {
        utc,
        zone: zone.to_owned(),
        local: format!(
            "{:04}-{:02}-{:02} {:02}:{:02}",
            wall.y, wall.mo, wall.d, wall.h, wall.mi
        ),
    })
}

/// Lock only an in-person meeting to the stated physical-zone label. A remote
/// meeting must remain switchable, even when its host supplies a zone.
pub fn booking_display_zones(
    utc: u64,
    visitor_zone: &str,
    host_zone: &str,
    location: MeetingLocation,
    requested_lock: bool,
) -> Result<(ZonedBookingTime, ZonedBookingTime, bool), ConversionError> {
    if requested_lock && location != MeetingLocation::Physical {
        return Err(ConversionError::InvalidConfig);
    }
    Ok((
        booking_zoned_time(utc, visitor_zone)?,
        booking_zoned_time(utc, host_zone)?,
        requested_lock,
    ))
}

/// One copy-paste-ready message, supplied with host-owned prose and an HTTPS
/// origin. The slot choice is a hint for the host page, not a credential: the
/// booking verb must still re-solve and revalidate the selected instant.
/// Exactly one or two concrete times precede the optional page link.
pub fn booking_slots_snippet(
    origin: &str,
    page_token: &PublicBookingPageToken,
    event_type: &crate::booking::EventTypeKey,
    slots: &[RankedSlot],
    zone: &str,
    introduction: &str,
    optional_link_label: &str,
) -> Result<String, ConversionError> {
    let host = origin
        .strip_prefix("https://")
        .ok_or(ConversionError::InvalidOrigin)?;
    if host.is_empty()
        || host.starts_with('.')
        || !host.contains('.')
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        || host.split('.').any(str::is_empty)
    {
        return Err(ConversionError::InvalidOrigin);
    }
    let token = page_token
        .0
        .strip_prefix("bkp_")
        .ok_or(ConversionError::InvalidToken)?;
    if token.len() != 32
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ConversionError::InvalidToken);
    }
    if !(1..=2).contains(&slots.len())
        || event_type.0.trim().is_empty()
        || event_type.0.len() > 64
        || introduction.trim().is_empty()
        || optional_link_label.trim().is_empty()
        || introduction.len() > 4096
        || optional_link_label.len() > 256
        || slots
            .iter()
            .any(|s| s.start_utc >= s.end_utc || !s.rank.is_finite())
    {
        return Err(ConversionError::InvalidConfig);
    }
    let page = format!("{origin}{PUBLIC_BOOKING_ROUTE_PREFIX}/{}", page_token.0);
    let event_hex = hex_text(&event_type.0);
    let zone_hex = hex_text(zone);
    let mut lines = vec![introduction.to_owned()];
    for slot in slots {
        let local = booking_zoned_time(slot.start_utc, zone)?;
        lines.push(format!(
            "[{} ({})]({page}?event_type={event_hex}&visitor_tz={zone_hex}&start_utc={}&end_utc={})",
            local.local, local.zone, slot.start_utc, slot.end_utc
        ));
    }
    lines.push(format!(
        "[{}]({page})",
        escape_markdown_label(optional_link_label)
    ));
    Ok(lines.join("\n"))
}

fn escape_markdown_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('[', "\\[")
        .replace(']', "\\]")
}

#[cfg(test)]
#[path = "ux_tests.rs"]
mod tests;
