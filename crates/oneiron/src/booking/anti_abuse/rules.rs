use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::storage::{
    ACTIVE_FUTURE_PER_EMAIL_CEIL, ACTIVE_FUTURE_PER_EMAIL_FLOOR, ROW_ID_MAX_LEN, RULE_KEY_DOMAIN,
    SLOT_LIST_CACHE_TTL_CEIL_SECS, SLOT_LIST_CACHE_TTL_FLOOR_SECS, hex_lower, refused,
};
// Referenced only by intra-doc links on the rule types; gated so the names are
// in scope for rustdoc without being unused imports.
#[cfg(doc)]
use super::amendment::{apply_rule_amendment, booking_rule_row_version_hash};
use crate::EntityId;
use crate::booking::lifecycle::digest_with;
use crate::booking::{BookingError, EventTypeKey};

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
    /// Email evidence prompts a correction; it never hard-blocks.
    EmailPromptToCorrect {
        check_syntax: bool,
        check_mx: bool,
        check_disposable_domain: bool,
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

/// One versioned rule row.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BookingAntiAbuseRuleRow {
    pub row_id: String,
    pub scope: BookingRuleScope,
    pub rule: BookingAntiAbuseRule,
    pub version: u64,
    pub amended_at: u64,
    #[serde(with = "entity_ref_serde")]
    pub amended_by: EntityId,
    /// Set by the amendment transaction when a loosening was stamped; never
    /// caller-supplied.
    #[serde(with = "opt_entity_ref_serde")]
    pub owner_stamp_ref: Option<EntityId>,
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

/// How a proposed row orders against the current one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmendmentDirection {
    Tightening,
    Equivalent,
    Loosening,
}

/// What a successful amendment stored, plus whether the owner must be shown
/// a notice. Every activation is owner-visible.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleAmendmentOutcome {
    pub stored: BookingAntiAbuseRuleRow,
    pub owner_notice_required: bool,
}

mod entity_ref_serde {
    use super::{Deserialize, Deserializer, EntityId, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &EntityId,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_hex())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<EntityId, D::Error> {
        let hex = String::deserialize(deserializer)?;
        EntityId::from_hex(&hex).map_err(serde::de::Error::custom)
    }
}

mod opt_entity_ref_serde {
    use super::{Deserialize, Deserializer, EntityId, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(
        value: &Option<EntityId>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.map(|id| id.to_hex()).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<EntityId>, D::Error> {
        match Option::<String>::deserialize(deserializer)? {
            None => Ok(None),
            Some(hex) => EntityId::from_hex(&hex)
                .map(Some)
                .map_err(serde::de::Error::custom),
        }
    }
}

// -------------------------------------------------------------------------
// Validation
// -------------------------------------------------------------------------

/// Validates one row: row-id shape, version, and the ratified per-variant
/// ranges. Ranges live in the validator — never as module constants an owner
/// could mistake for a picked threshold.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] when any field is out of range.
pub fn validate_rule_row(row: &BookingAntiAbuseRuleRow) -> Result<(), BookingError> {
    if row.row_id.is_empty() || row.row_id.len() > ROW_ID_MAX_LEN {
        return Err(refused("booking anti-abuse row id must be 1-128 chars"));
    }
    if !row.row_id.bytes().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'_' | b'-' | b':')
    }) {
        return Err(refused(
            "booking anti-abuse row id may use lowercase ascii, digits, '.', '_', '-', ':'",
        ));
    }
    if row.version == 0 {
        return Err(refused("booking anti-abuse rule versions start at 1"));
    }
    match &row.rule {
        BookingAntiAbuseRule::MinimumNotice {
            normal_secs,
            high_value_secs,
        } => {
            if normal_secs > high_value_secs {
                return Err(refused(
                    "normal minimum notice may not exceed the high-value notice",
                ));
            }
        }
        BookingAntiAbuseRule::SlotListRate { cache_ttl_secs, .. } => {
            check_slot_list_cache_ttl(cache_ttl_secs.get())?;
        }
        BookingAntiAbuseRule::BookRate {
            max_active_future_per_email,
            ..
        } => {
            if !(ACTIVE_FUTURE_PER_EMAIL_FLOOR..=ACTIVE_FUTURE_PER_EMAIL_CEIL)
                .contains(max_active_future_per_email)
            {
                return Err(refused(
                    "active future bookings per email must sit within 1-2",
                ));
            }
        }
        BookingAntiAbuseRule::HoldRate {
            max_active_per_session,
            ..
        } => {
            if *max_active_per_session == 0 {
                return Err(refused(
                    "the per-session active hold cap must admit at least one",
                ));
            }
        }
        BookingAntiAbuseRule::RequiredIntake { .. }
        | BookingAntiAbuseRule::HoneypotAndSubmitFloor { .. }
        | BookingAntiAbuseRule::EmailPromptToCorrect { .. }
        | BookingAntiAbuseRule::QuarantineBorderline
        | BookingAntiAbuseRule::EmailOtpReserve { .. }
        | BookingAntiAbuseRule::TentativeConfirmLinkReserve { .. } => {}
    }
    Ok(())
}

pub(super) fn check_slot_list_cache_ttl(ttl_secs: u64) -> Result<(), BookingError> {
    if !(SLOT_LIST_CACHE_TTL_FLOOR_SECS..=SLOT_LIST_CACHE_TTL_CEIL_SECS).contains(&ttl_secs) {
        return Err(refused(
            "slot-list response cache ttl must sit within 30-60 seconds",
        ));
    }
    Ok(())
}

// -------------------------------------------------------------------------
// Seed rows
// -------------------------------------------------------------------------

/// The stable rule-variant tag used in row ids.
pub fn booking_rule_variant_tag(rule: &BookingAntiAbuseRule) -> &'static str {
    match rule {
        BookingAntiAbuseRule::RequiredIntake { .. } => "required-intake",
        BookingAntiAbuseRule::MinimumNotice { .. } => "minimum-notice",
        BookingAntiAbuseRule::HoneypotAndSubmitFloor { .. } => "honeypot-submit-floor",
        BookingAntiAbuseRule::SlotListRate { .. } => "slot-list-rate",
        BookingAntiAbuseRule::BookRate { .. } => "book-rate",
        BookingAntiAbuseRule::HoldRate { .. } => "hold-rate",
        BookingAntiAbuseRule::EmailPromptToCorrect { .. } => "email-prompt-to-correct",
        BookingAntiAbuseRule::QuarantineBorderline => "quarantine-borderline",
        BookingAntiAbuseRule::EmailOtpReserve { .. } => "email-otp-reserve",
        BookingAntiAbuseRule::TentativeConfirmLinkReserve { .. } => {
            "tentative-confirm-link-reserve"
        }
    }
}

/// Deterministic row id for one (scope, variant) pair, so seed construction
/// is idempotent and competing ids for the same rule cannot fork. The FULL
/// page hex and the FULL domain-separated event-key digest go in: two
/// subjects that share a low-order prefix — sibling UUID-v7 pages minted in
/// one timestamp window, say — still own distinct rows.
pub fn booking_rule_row_id(scope: &BookingRuleScope, rule: &BookingAntiAbuseRule) -> String {
    let mut id = format!(
        "booking.anti_abuse.{}.{}",
        booking_rule_variant_tag(rule),
        scope.page_ref.to_hex()
    );
    if let Some(event_type) = &scope.event_type {
        let digest = digest_with(RULE_KEY_DOMAIN, event_type.0.as_bytes());
        id.push_str(".et-");
        id.push_str(&hex_lower(&digest));
    }
    id
}

/// Builds the full SHIP/RESERVE seed stack for one scope from owner-chosen
/// thresholds. Every control arrives as a constructor argument; the module
/// ships no threshold of its own. The reserve rows start with
/// `enabled = false`.
///
/// The returned rows are version 1 candidates, not yet stored; activation
/// goes through [`apply_rule_amendment`] with expected version 0 like every
/// other proposal.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] when any owner-chosen value falls
/// outside the ratified ranges.
pub fn default_booking_anti_abuse_rows(
    page_ref: EntityId,
    event_type: Option<EventTypeKey>,
    owner_config: &BookingAntiAbuseOwnerConfig,
) -> Result<Vec<BookingAntiAbuseRuleRow>, BookingError> {
    let scope = BookingRuleScope {
        page_ref,
        event_type,
    };
    let rules = [
        BookingAntiAbuseRule::RequiredIntake {
            min_chars: owner_config.min_intake_chars,
        },
        BookingAntiAbuseRule::MinimumNotice {
            normal_secs: owner_config.normal_notice_secs,
            high_value_secs: owner_config.high_value_notice_secs,
        },
        BookingAntiAbuseRule::HoneypotAndSubmitFloor {
            min_submit_millis: owner_config.min_submit_millis,
        },
        BookingAntiAbuseRule::SlotListRate {
            per_minute_per_ip: owner_config.slot_list_per_minute_per_ip,
            cache_ttl_secs: owner_config.slot_list_cache_ttl_secs,
        },
        BookingAntiAbuseRule::BookRate {
            per_minute_per_ip: owner_config.book_per_minute_per_ip,
            max_active_future_per_email: owner_config.max_active_future_per_email,
        },
        BookingAntiAbuseRule::HoldRate {
            max_active_per_session: owner_config.max_active_holds_per_session,
            per_minute_per_ip: owner_config.hold_per_minute_per_ip,
        },
        BookingAntiAbuseRule::EmailPromptToCorrect {
            check_syntax: true,
            check_mx: true,
            check_disposable_domain: true,
        },
        BookingAntiAbuseRule::QuarantineBorderline,
        BookingAntiAbuseRule::EmailOtpReserve { enabled: false },
        BookingAntiAbuseRule::TentativeConfirmLinkReserve {
            enabled: false,
            expires_after_secs: owner_config.tentative_confirm_ttl_secs,
        },
    ];
    let mut rows = Vec::with_capacity(rules.len());
    for rule in rules {
        let row = BookingAntiAbuseRuleRow {
            row_id: booking_rule_row_id(&scope, &rule),
            scope: scope.clone(),
            rule,
            version: 1,
            amended_at: 0,
            amended_by: page_ref,
            owner_stamp_ref: None,
        };
        validate_rule_row(&row)?;
        rows.push(row);
    }
    Ok(rows)
}
