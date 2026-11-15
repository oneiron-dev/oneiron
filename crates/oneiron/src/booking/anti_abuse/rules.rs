//! Booking anti-abuse rule vocabulary.
//! Entry: `BookingAntiAbuseRule`.
//! Defines its own items.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::storage::{ROW_ID_MAX_LEN, RULE_KEY_DOMAIN, hex_lower, refused};
// Referenced only by intra-doc links on the rule types; gated so the names are
// in scope for rustdoc without being unused imports.
#[cfg(doc)]
use super::amendment::{apply_rule_amendment, booking_rule_row_version_hash};
use crate::EntityId;
use crate::booking::lifecycle::digest_with;
use crate::booking::{BookingError, EventTypeKey};

#[doc(hidden)]
use oneiron_records::booking::anti_abuse::rules::entity_ref_serde;
#[doc(hidden)]
pub use oneiron_records::booking::anti_abuse::rules::{
    BookingAntiAbuseOwnerConfig, BookingAntiAbuseRule, BookingRuleOwnerStampBinding,
    BookingRuleScope,
};
#[doc(hidden)]
pub(crate) use oneiron_records::booking::anti_abuse::rules::{
    email_prompt_at_failed_checks_default, email_quarantine_at_failed_checks_default,
};

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

/// How a proposed row orders against the current one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AmendmentDirection {
    Tightening,
    Equivalent,
    Loosening,
}

/// What a successful amendment stored, plus whether the owner must be shown
/// a notice. Every activation and every retained proposal is owner-visible.
#[derive(Clone, Debug, PartialEq)]
pub struct RuleAmendmentOutcome {
    pub stored: BookingAntiAbuseRuleRow,
    pub owner_notice_required: bool,
    /// `false`: the change is retained as a proposal awaiting its holder
    /// (FIX 9627), and the active row is unchanged.
    pub activated: bool,
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
        BookingAntiAbuseRule::EmailPromptToCorrect {
            prompt_at_failed_checks,
            quarantine_at_failed_checks,
            ..
        } => {
            if prompt_at_failed_checks > quarantine_at_failed_checks {
                return Err(refused(
                    "the email prompt count may not exceed the email quarantine count",
                ));
            }
        }
        // The cache TTL and the per-email cap are the owner's to pick: no
        // compiled range binds them (FIX 9629). A cap of zero would admit no
        // booking at all, so it must admit one.
        BookingAntiAbuseRule::BookRate {
            max_active_future_per_email,
            ..
        } => {
            if *max_active_future_per_email == 0 {
                return Err(refused(
                    "the per-email active future booking cap must admit at least one",
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
        | BookingAntiAbuseRule::SlotListRate { .. }
        | BookingAntiAbuseRule::HoneypotAndSubmitFloor { .. }
        | BookingAntiAbuseRule::QuarantineBorderline
        | BookingAntiAbuseRule::EmailOtpReserve { .. }
        | BookingAntiAbuseRule::TentativeConfirmLinkReserve { .. } => {}
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
            prompt_at_failed_checks: email_prompt_at_failed_checks_default(),
            quarantine_at_failed_checks: email_quarantine_at_failed_checks_default(),
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
