//! BK-07 conversion data. Pure plans only: the host owns copy, delivery,
//! intake collection, and the physical-meeting UI. No plan grants authority.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::booking::{PublicBookingPageToken, RankedSlot};
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

/// Show an owner-chosen ranked prefix within resolved vault policy, keeping
/// the whole solver result available
/// for the host's separate availability query. Empty availability is valid.
pub fn booking_shortlist(
    slots: &[RankedSlot],
    visible_count: usize,
    policy: &super::BookingConversionPolicy,
) -> Result<BookingShortlist, ConversionError> {
    if policy.validate().is_err() || visible_count == 0 || visible_count > policy.max_visible_slots
    {
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

/// An inert public-face link hint. The exact slot is re-solved at the JSON
/// model route and revalidated once more by the hold writer.
pub type BookingSlotLinkHint = super::BookingSnippetSelection;

/// Parse the same closed query contract used by the owner-supplied public-face
/// URL. A second incompatible snippet protocol must not be introduced here.
#[must_use]
pub fn parse_booking_slot_link(query: Option<&str>) -> Option<BookingSlotLinkHint> {
    super::parse_booking_snippet_query(query?)
}

/// Select only the exact solved half-open interval, never a time guessed by a
/// query string, even when its event type and display zone are valid.
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
    policy: &super::BookingConversionPolicy,
) -> Result<BookingIntakeStages, ConversionError> {
    if policy.validate().is_err()
        || before_confirm > policy.max_preconfirm_fields
        || fields.len() < before_confirm
        || fields.len() > policy.max_total_fields
    {
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

/// A scheduled reminder is host wake data, not a delivery or new timer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BookingReminder {
    pub due_utc: u64,
    pub action: ReminderAction,
    pub step: ReminderStep,
}

/// Copy/CTA posture chosen by a resolved notification-policy row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReminderAction {
    RescheduleFirst,
    Neutral,
}

/// The row chooses how many reminders, when they are due, and the CTA. An
/// overdue step is omitted; a near-term booking gets no stale wake.
pub fn booking_reminders(
    start_utc: u64,
    now_utc: u64,
    policy: &super::BookingConversionPolicy,
) -> Result<Vec<BookingReminder>, ConversionError> {
    policy
        .validate()
        .map_err(|_| ConversionError::InvalidConfig)?;
    Ok(policy
        .reminder_leads_secs
        .iter()
        .enumerate()
        .filter_map(|(index, lead)| {
            let due_utc = start_utc.checked_sub(*lead)?;
            (due_utc > now_utc).then_some(BookingReminder {
                due_utc,
                action: policy.reminder_action,
                step: ReminderStep(index as u8),
            })
        })
        .collect())
}

/// Stable index across moves; a configured policy may have zero to eight
/// reminder steps. The host replaces a wake with the same event/index id.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReminderStep(pub u8);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurableReminderWake {
    pub id: String,
    /// Canonical hex, never an authority token or public page address.
    pub event_ref: String,
    pub expected_start_utc: u64,
    pub due_utc: u64,
    pub step: ReminderStep,
    pub action: ReminderAction,
}

fn reminder_wake_id(event_ref: &crate::EntityId, step: ReminderStep) -> String {
    format!("booking.reminder.step-{}:{}", step.0, event_ref.to_hex())
}

/// Map resolved notification rows to stable per-booking host wakes.
pub fn booking_reminder_wakes(
    event_ref: crate::EntityId,
    start_utc: u64,
    now_utc: u64,
    policy: &super::BookingConversionPolicy,
) -> Result<Vec<ConfigurableReminderWake>, ConversionError> {
    Ok(booking_reminders(start_utc, now_utc, policy)?
        .into_iter()
        .map(|reminder| ConfigurableReminderWake {
            id: reminder_wake_id(&event_ref, reminder.step),
            event_ref: event_ref.to_hex(),
            expected_start_utc: start_utc,
            due_utc: reminder.due_utc,
            step: reminder.step,
            action: reminder.action,
        })
        .collect())
}

/// Recheck booking and resolved notification truth when a host wake fires.
/// Delivery still needs the ordinary outbound authorization and dedupe.
///
/// # Errors
/// A corrupt or unreadable booking or policy aborts the wake, never sends.
pub fn booking_due_reminder(
    vault: &crate::Vault,
    wake: &ConfigurableReminderWake,
    fired_at: u64,
    policy: &super::BookingConversionPolicy,
) -> Result<Option<ReminderAction>, crate::booking::BookingError> {
    let event_ref = crate::EntityId::from_hex(&wake.event_ref).map_err(|_| {
        crate::booking::BookingError::InvalidConstraint("reminder EVENT id is invalid".to_owned())
    })?;
    if wake.event_ref != event_ref.to_hex()
        || wake.id != reminder_wake_id(&event_ref, wake.step)
        || fired_at < wake.due_utc
        || fired_at >= wake.expected_start_utc
    {
        return Ok(None);
    }
    // The host supplies its latest vault-resolved row at the due door. A
    // changed schedule or CTA invalidates the older persisted wake.
    if !booking_reminder_wakes(event_ref, wake.expected_start_utc, 0, policy)
        .map_err(|_| {
            crate::booking::BookingError::InvalidConfig(
                "booking reminder policy is malformed".to_owned(),
            )
        })?
        .iter()
        .any(|planned| planned == wake)
    {
        return Ok(None);
    }
    let current = crate::booking::lifecycle::confirmed_start_for_reminder(vault, &event_ref)?;
    Ok((current == Some(wake.expected_start_utc)).then_some(wake.action))
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
    policy: &super::BookingConversionPolicy,
) -> RepeatNoShowOffer {
    // Unknown (including silence), cancellations, and held calls are not
    // evidence of a no-show. The caller must resolve these outcomes from the
    // event ledger for the same contact, not from email-delivery silence.
    let verified_prior_no_shows = prior_outcomes_for_contact
        .iter()
        .filter(|outcome| **outcome == crate::calendar::outcome::EventOutcome::NoShow)
        .take(policy.repeat_no_show_at)
        .count();
    if policy.validate().is_ok()
        && verified_prior_no_shows >= policy.repeat_no_show_at
        && owner_enabled_confirm_link
    {
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

/// Host-authored message prose. No executable prompt/copy is shipped.
#[derive(Clone, Copy, Debug)]
pub struct BookingSnippetCopy<'a> {
    pub introduction: &'a str,
    pub optional_link_label: &'a str,
}

/// One copy-paste-ready message for the host's human booking page. The
/// existing validated public-face link seam owns URL/token binding and the
/// offered slot check. This function only supplies owner-authored prose and
/// Markdown assembly, never a route to the engine's JSON model endpoint.
pub fn booking_slots_snippet(
    mask: &crate::booking::SlotMask,
    selected_starts_utc: &[u64],
    visitor_tz: &str,
    page_token: &PublicBookingPageToken,
    public_page_url: &str,
    copy: BookingSnippetCopy<'_>,
    policy: &super::BookingConversionPolicy,
) -> Result<String, crate::booking::BookingError> {
    policy.validate()?;
    if selected_starts_utc.is_empty()
        || selected_starts_utc.len() > policy.max_snippet_times
        || copy.introduction.trim().is_empty()
        || copy.optional_link_label.trim().is_empty()
        || copy.introduction.len() > 4096
        || copy.optional_link_label.len() > 256
    {
        return Err(crate::booking::BookingError::Surface(
            "booking snippet copy is missing or too large".to_owned(),
        ));
    }
    let links = super::booking_snippet_links(
        mask,
        selected_starts_utc,
        visitor_tz,
        page_token,
        public_page_url,
    )?;
    let mut lines = vec![copy.introduction.to_owned()];
    for link in links {
        lines.push(format!(
            "[{}]({})",
            escape_markdown_label(&link.label),
            link.href
        ));
    }
    lines.push(format!(
        "[{}]({public_page_url})",
        escape_markdown_label(copy.optional_link_label),
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
