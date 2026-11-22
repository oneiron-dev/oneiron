//! Moved from `crates/oneiron/src/booking/anti_abuse/rules.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_verb_wire::booking::constraint::EventTypeKey;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use std::num::NonZeroU8;
use std::num::NonZeroU16;
use std::num::NonZeroU32;
use std::num::NonZeroU64;

// -------------------------------------------------------------------------
// Rule types (the keystone)
// -------------------------------------------------------------------------

/// A rule row's subject: an existing booking page, optionally narrowed to one
/// event type. A `None` event type applies page-wide.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BookingRuleScope {
    #[serde(with = "entity_ref_serde")]
    pub page_ref: EntityId,
    pub event_type: Option<EventTypeKey>,
}

/// The SHIP/SKIP/RESERVE control set. Reserve rows are stored off-by-default
/// policy, not active enforcement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum BookingAntiAbuseRule {
    /// Required open-text intake with a positive minimum length.
    RequiredIntake { min_chars: NonZeroU16 },
    /// Minimum notice the solver must honour, normal vs high-value.
    MinimumNotice {
        normal_secs: NonZeroU64,
        high_value_secs: NonZeroU64,
    },
    /// Honeypot plus a time-to-submit floor; violations are rejected as an
    /// indistinguishable HTTP 200 with no booking-side write.
    HoneypotAndSubmitFloor { min_submit_millis: NonZeroU64 },
    /// Slot-list listing: per-minute cap per IP plus the response cache TTL.
    SlotListRate {
        per_minute_per_ip: NonZeroU32,
        cache_ttl_secs: NonZeroU64,
    },
    /// Booking: per-minute cap plus the active-future-booking cap per email.
    BookRate {
        per_minute_per_ip: NonZeroU32,
        max_active_future_per_email: u8,
    },
    /// Holds: one active hold per session plus a per-IP minute cap.
    HoldRate {
        max_active_per_session: u8,
        per_minute_per_ip: NonZeroU32,
    },
    /// Email evidence prompts a correction; it never hard-blocks. The two
    /// counts say how many of the enabled checks must fail: at
    /// `prompt_at_failed_checks` the visitor is asked to correct the address,
    /// and at `quarantine_at_failed_checks` the submission goes to a
    /// pending-review record when a [`Self::QuarantineBorderline`] row is in
    /// scope (a prompt otherwise). A lower count is the tighter one. A row
    /// stored before the counts existed reads 1 and 2, the counts it was
    /// evaluated with, and a row holding those counts encodes as it did then.
    EmailPromptToCorrect {
        check_syntax: bool,
        check_mx: bool,
        check_disposable_domain: bool,
        #[serde(
            default = "email_prompt_at_failed_checks_default",
            skip_serializing_if = "is_email_prompt_at_failed_checks_default"
        )]
        prompt_at_failed_checks: NonZeroU8,
        #[serde(
            default = "email_quarantine_at_failed_checks_default",
            skip_serializing_if = "is_email_quarantine_at_failed_checks_default"
        )]
        quarantine_at_failed_checks: NonZeroU8,
    },
    /// Route borderline traffic to a pending-review record.
    QuarantineBorderline,
    /// Reserve: per-event-type email OTP. Stored policy only; defaults off.
    EmailOtpReserve { enabled: bool },
    /// Reserve: per-event-type tentative confirm link. Defaults off.
    TentativeConfirmLinkReserve {
        enabled: bool,
        expires_after_secs: NonZeroU64,
    },
}

/// The failed email checks that prompt a correction when a row names no
/// count: one, the count every row meant before it was a field.
pub const fn email_prompt_at_failed_checks_default() -> NonZeroU8 {
    NonZeroU8::MIN
}

/// The failed email checks that route a submission to quarantine when a row
/// names no count: two, the count every row meant before it was a field.
pub const fn email_quarantine_at_failed_checks_default() -> NonZeroU8 {
    NonZeroU8::new(2).expect("two is non-zero")
}

/// Serde skip predicate: a row holding the default prompt count says so by
/// omission, so it encodes as it did before the field existed.
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if hands the field by reference"
)]
fn is_email_prompt_at_failed_checks_default(count: &NonZeroU8) -> bool {
    *count == email_prompt_at_failed_checks_default()
}

/// Serde skip predicate for the quarantine count, as above.
#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde's skip_serializing_if hands the field by reference"
)]
fn is_email_quarantine_at_failed_checks_default(count: &NonZeroU8) -> bool {
    *count == email_quarantine_at_failed_checks_default()
}

/// Owner-chosen seed thresholds. Every value arrives as a constructor
/// argument; the module bakes no threshold of its own.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BookingAntiAbuseOwnerConfig {
    pub min_intake_chars: NonZeroU16,
    pub normal_notice_secs: NonZeroU64,
    pub high_value_notice_secs: NonZeroU64,
    pub min_submit_millis: NonZeroU64,
    pub slot_list_per_minute_per_ip: NonZeroU32,
    pub slot_list_cache_ttl_secs: NonZeroU64,
    pub book_per_minute_per_ip: NonZeroU32,
    pub max_active_future_per_email: u8,
    pub max_active_holds_per_session: u8,
    pub hold_per_minute_per_ip: NonZeroU32,
    pub tentative_confirm_ttl_secs: NonZeroU64,
}

/// A logged owner stamp: `stamp_ref` names the logged owner action, and the
/// binding equals [`booking_rule_row_version_hash`] of the exact proposed
/// row (version included).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BookingRuleOwnerStampBinding {
    #[serde(with = "entity_ref_serde")]
    pub stamp_ref: EntityId,
    pub proposed_row_version_hash: [u8; 32],
}

pub mod entity_ref_serde {
    use super::{Deserialize, Deserializer, EntityId, Serializer};

    pub fn serialize<S: Serializer>(value: &EntityId, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<EntityId, D::Error> {
        let hex = String::deserialize(deserializer)?;
        EntityId::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}
