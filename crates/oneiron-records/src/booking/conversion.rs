//! Moved from `crates/oneiron/src/booking/conversion.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::booking::constraint::SlotMask;
pub use crate::booking::conversion::policy::BookingConversionPolicy;
pub use crate::booking::conversion::policy::BookingConversionPolicyRow;
pub use crate::booking::conversion::policy::BookingPolicyPrecedence;
pub use crate::booking::conversion::policy::BookingPolicyScope;
pub use crate::booking::conversion::ux::BookingShortlist;
pub use crate::booking::conversion::ux::ConfigurableReminderWake;
pub use crate::booking::conversion::ux::ReminderAction;
pub use crate::booking::conversion::ux::ReminderStep;
pub use crate::booking::conversion::ux::ZonedBookingTime;
use oneiron_verb_wire::booking::constraint::BookingError;
use oneiron_verb_wire::booking::constraint::EventTypeKey;
use oneiron_verb_wire::booking::constraint::RankedSlot;
use serde::Deserialize;
use serde::Serialize;
use std::fmt::Write;

/// Owner-authored content. A host chooses layout, localization and assets.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingLandingContent {
    pub photo_path: Option<String>,
    pub intro: String,
    pub faq: Vec<BookingFaq>,
    pub prep_path: Option<String>,
    /// The pre-confirm subset; a host collects other intake after confirm.
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
        // Every configured FAQ and pre-confirm field is kept; only each item
        // is bounded.
        if !bounded(&self.intro, 2048)
            || self.faq.iter().any(|faq| {
                faq.question.trim().is_empty()
                    || faq.answer.trim().is_empty()
                    || !bounded(&faq.question, 256)
                    || !bounded(&faq.answer, 1024)
            })
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
        // The public lens carries the encoded whole across as many lens
        // texts as it takes (FIX 20663), so the whole is not bounded here.
        Ok(())
    }
}

// Paths are inert same-origin asset references, not fetch instructions or redirects.
pub fn safe_asset_path(path: &str) -> bool {
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
    /// Exact half-open end, so a query cannot swap duration or event type.
    pub end_utc: u64,
    pub visitor_tz: String,
}
pub mod policy;
pub mod ux;
