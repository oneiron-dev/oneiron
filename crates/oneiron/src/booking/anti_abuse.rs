//! ONE-1817 [BK-06] booking anti-abuse rule rows.
//!
//! The booking-local SHIP/SKIP/RESERVE policy lives here as typed, versioned
//! rows in `vault_meta` under [`BOOKING_ANTI_ABUSE_META_PREFIX`] — a prefix
//! this lane alone writes. The row subject is an existing booking-page
//! [`EntityId`], optionally narrowed to the shared [`EventTypeKey`]; the
//! module allocates no entity kind and no static type byte.
//!
//! # Activation law
//!
//! Storage is private. The sole public activation path is
//! [`apply_rule_amendment`], a versioned compare-and-set transaction taken
//! under the booking writer. A provable tightening (or the first activation
//! of a row) stores immediately and emits an owner-visible notice. A
//! loosening — including any variant drift the comparator cannot order —
//! stores only behind an owner stamp whose binding equals
//! [`booking_rule_row_version_hash`] of the exact proposed row.
//!
//! # Evaluation
//!
//! [`evaluate_booking_request`] is pure: it reads rows plus caller-asserted
//! [`BookingRequestFacts`] and never touches storage, so the honeypot and
//! time-floor rejections it returns can be honoured without a single write.
//! The vault-backed pieces an HTTP guard needs on top — minute-window
//! counters, the slot-list response cache, owner notices, and the
//! pending-review quarantine record — are the pub functions below; they are
//! the only writer surface, and every one routes through the lifecycle's
//! `booking_writer` / `put_meta` / `read_meta_bytes` / `digest_with` helpers
//! so storage discipline stays in exactly one place.
//!
//! Regret asymmetry is deliberate: under-block and triage. Negative email
//! evidence prompts a correction; only multi-signal inconsistency routes to a
//! quarantine record, and nothing here is ever silently deleted. Interactive
//! challenge pages, client device probing, and bot-management services are
//! out of scope by design — email OTP and tentative-confirm-link are
//! per-event-type reserve rows that default off.

use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::booking::lifecycle::{booking_writer, digest_with, put_meta, read_meta_bytes};
use crate::booking::{BookingError, EventTypeKey};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use crate::store::{GateDecisionId, GateDecisionRecord, PendingGateConsentRecord};
use crate::temporal::TimeRange;
use crate::{EntityId, Vault};

// -------------------------------------------------------------------------
// Storage layout
// -------------------------------------------------------------------------

/// Booking-only `vault_meta` prefix. Every row this module stores — rule
/// rows, owner notices, rate counters, and the slot-list response cache —
/// lives under it. Quarantine records are the one deliberate exception:
/// those ride the gate's existing pending-consent rows so the inbox's
/// pending-review pattern can enumerate them.
pub const BOOKING_ANTI_ABUSE_META_PREFIX: &[u8] = b"booking:anti_abuse:v1:";

/// Key tags under the prefix, one byte-string per row family, kept distinct
/// so a prefix scan can pick out exactly one family.
const RULE_KEY_TAG: &[u8] = b"rule\x00";
const NOTICE_KEY_TAG: &[u8] = b"notice\x00";
const RATE_KEY_TAG: &[u8] = b"rate\x00";
const CACHE_KEY_TAG: &[u8] = b"cache\x00";

/// Wire-format version byte prepended to every encoded row (the same
/// version-then-rmp idiom the lifecycle rows use).
const ANTI_ABUSE_WIRE_VERSION: u8 = 0;

/// Domain tags for `digest_with`: persisted keys and hashes can never be
/// replayed across purposes because the domain differs.
const RULE_KEY_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.rule_key.v0";
const NOTICE_KEY_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.notice_key.v0";
const RATE_KEY_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.rate_key.v0";
const CACHE_KEY_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.cache_key.v0";
const ROW_VERSION_HASH_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.row_version_hash.v0";
const QUARANTINE_CLAIM_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.quarantine_claim.v0";
const IP_HASH_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.ip.v0";
const EMAIL_HASH_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.email.v0";
const SESSION_HASH_DOMAIN: &[u8] = b"oneiron.booking.anti_abuse.session.v0";

/// Ratified bounds for the slot-list response cache TTL (30-60 seconds).
/// These bound a value the owner picks; they are not a picked value.
const SLOT_LIST_CACHE_TTL_FLOOR_SECS: u64 = 30;
const SLOT_LIST_CACHE_TTL_CEIL_SECS: u64 = 60;

/// Ratified bounds for the per-email active-future-booking cap (1-2).
const ACTIVE_FUTURE_PER_EMAIL_FLOOR: u8 = 1;
const ACTIVE_FUTURE_PER_EMAIL_CEIL: u8 = 2;

/// One fixed window for every "per minute" counter, mirroring
/// `task_verb.rs`'s node-local window counter.
const RATE_WINDOW_SECS: u64 = 60;

/// Row-id shape: bounded, and tame enough to print in owner notices. One
/// full page hex plus one full event-key digest must always fit.
const ROW_ID_MAX_LEN: usize = 160;
/// Bound on a stored slot-list cache body so a handler bug cannot grow the
/// vault without limit.
const CACHE_BODY_MAX_LEN: usize = 512 * 1024;

/// The single reason code a booking quarantine record carries. It must pass
/// both gate store vets: the decision ledger requires a `gate.` prefix and
/// the pending-consent ledger requires `gate.pending.`.
const QUARANTINE_REASON_CODE: &str = "gate.pending.booking.anti_abuse.borderline";

/// Predicate of the minimal CLAIM body a quarantined submission leaves
/// behind: the durable content the owner reviews from the pending gate row.
/// The default policy manifest's `booking.` prefix rule rates it
/// normal-criticality, exactly like the lifecycle claims.
const QUARANTINE_CLAIM_PREDICATE: &str = "booking.submission_quarantine";

/// Synthetic run-id prefix stamped on quarantine pending rows. The inbox
/// group projection keys cards on a Dreamer run id; a quarantined submission
/// never has one, so the record carries this content-keyed id and
/// `resolve_run_identity` keeps the stamped id verbatim as the group key
/// when no Dreamer attempt rows anchor it.
const QUARANTINE_RUN_ID_PREFIX: &str = "booking.anti_abuse.quarantine.";

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

// -------------------------------------------------------------------------
// Errors
// -------------------------------------------------------------------------

/// A refused request: `BookingError` is ONE-1816's, and this lane adds no
/// variant to it. Same stance as the lifecycle verbs.
fn refused(detail: impl Into<String>) -> BookingError {
    BookingError::InvalidConstraint(detail.into())
}

/// Wraps an engine failure without restating the engine's error taxonomy.
fn engine_failure<E: Into<crate::Error>>(what: &str, error: E) -> BookingError {
    let error = error.into();
    BookingError::SlotOracle(format!("booking anti-abuse {what} failed: {error}"))
}

// -------------------------------------------------------------------------
// Wire codec and keys
// -------------------------------------------------------------------------

fn encode_row<T: Serialize>(value: &T) -> Result<Vec<u8>, BookingError> {
    let mut out = vec![ANTI_ABUSE_WIRE_VERSION];
    out.extend(
        rmp_serde::to_vec_named(value)
            .map_err(|error| refused(format!("booking anti-abuse row does not encode: {error}")))?,
    );
    Ok(out)
}

fn decode_row<T: DeserializeOwned>(raw: &[u8]) -> Result<T, BookingError> {
    let Some((&version, body)) = raw.split_first() else {
        return Err(refused("booking anti-abuse row is empty"));
    };
    if version != ANTI_ABUSE_WIRE_VERSION {
        return Err(refused("booking anti-abuse row version is unsupported"));
    }
    rmp_serde::from_slice(body)
        .map_err(|error| refused(format!("booking anti-abuse row does not decode: {error}")))
}

/// prefix + tag + domain-tagged digest: the one key shape for every family.
fn tagged_key(tag: &[u8], domain: &[u8], material: &[u8]) -> Vec<u8> {
    let digest = digest_with(domain, material);
    let mut key =
        Vec::with_capacity(BOOKING_ANTI_ABUSE_META_PREFIX.len() + tag.len() + digest.len());
    key.extend_from_slice(BOOKING_ANTI_ABUSE_META_PREFIX);
    key.extend_from_slice(tag);
    key.extend_from_slice(&digest);
    key
}

fn rule_row_key(row_id: &str) -> Vec<u8> {
    tagged_key(RULE_KEY_TAG, RULE_KEY_DOMAIN, row_id.as_bytes())
}

fn notice_key(row_id: &str, version: u64) -> Vec<u8> {
    let mut material = Vec::with_capacity(row_id.len() + 8);
    material.extend_from_slice(row_id.as_bytes());
    material.extend_from_slice(&version.to_be_bytes());
    tagged_key(NOTICE_KEY_TAG, NOTICE_KEY_DOMAIN, &material)
}

fn rate_counter_key(purpose: &[u8], material: &[u8]) -> Vec<u8> {
    let mut keyed = Vec::with_capacity(purpose.len() + 1 + material.len());
    keyed.extend_from_slice(purpose);
    keyed.push(0);
    keyed.extend_from_slice(material);
    tagged_key(RATE_KEY_TAG, RATE_KEY_DOMAIN, &keyed)
}

fn slot_list_cache_key(page_ref: &EntityId, event_type: Option<&EventTypeKey>) -> Vec<u8> {
    let mut material = Vec::new();
    material.extend_from_slice(page_ref.as_bytes());
    if let Some(event_type) = event_type {
        material.push(0);
        material.extend_from_slice(event_type.0.as_bytes());
    }
    tagged_key(CACHE_KEY_TAG, CACHE_KEY_DOMAIN, &material)
}

fn rule_scan_prefix() -> Vec<u8> {
    let mut prefix = Vec::with_capacity(BOOKING_ANTI_ABUSE_META_PREFIX.len() + RULE_KEY_TAG.len());
    prefix.extend_from_slice(BOOKING_ANTI_ABUSE_META_PREFIX);
    prefix.extend_from_slice(RULE_KEY_TAG);
    prefix
}

fn notice_scan_prefix() -> Vec<u8> {
    let mut prefix =
        Vec::with_capacity(BOOKING_ANTI_ABUSE_META_PREFIX.len() + NOTICE_KEY_TAG.len());
    prefix.extend_from_slice(BOOKING_ANTI_ABUSE_META_PREFIX);
    prefix.extend_from_slice(NOTICE_KEY_TAG);
    prefix
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0F)]));
    }
    out
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

fn check_slot_list_cache_ttl(ttl_secs: u64) -> Result<(), BookingError> {
    if !(SLOT_LIST_CACHE_TTL_FLOOR_SECS..=SLOT_LIST_CACHE_TTL_CEIL_SECS).contains(&ttl_secs) {
        return Err(refused(
            "slot-list response cache ttl must sit within 30-60 seconds",
        ));
    }
    Ok(())
}

// -------------------------------------------------------------------------
// Amendment direction
// -------------------------------------------------------------------------

/// Orders `proposed` against `current`. Any loosened axis, a variant drift,
/// or a scope change routes to the owner stamp; only a provable tightening
/// or an exact re-assertion activates automatically.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] when the proposal is malformed,
/// re-scopes the row, or fails to advance the version by exactly one.
pub fn amendment_direction(
    current: &BookingAntiAbuseRuleRow,
    proposed: &BookingAntiAbuseRuleRow,
) -> Result<AmendmentDirection, BookingError> {
    validate_rule_row(proposed)?;
    if proposed.row_id != current.row_id {
        return Err(refused("an amendment may not rename the rule row"));
    }
    if proposed.scope != current.scope {
        return Err(refused("an amendment may not re-scope the rule row"));
    }
    if proposed.version != current.version + 1 {
        return Err(refused("an amendment must advance the version by one"));
    }
    Ok(match rule_ordering(&current.rule, &proposed.rule) {
        RuleOrdering::Same => AmendmentDirection::Equivalent,
        RuleOrdering::Tighter => AmendmentDirection::Tightening,
        RuleOrdering::Looser | RuleOrdering::TighterAndLooser | RuleOrdering::Unorderable => {
            AmendmentDirection::Loosening
        }
    })
}

#[derive(Clone, Copy)]
enum RuleOrdering {
    Same,
    Tighter,
    Looser,
    TighterAndLooser,
    Unorderable,
}

fn fold_axis(ordering: &mut RuleOrdering, proposed: u64, current: u64, lower_is_tighter: bool) {
    if proposed == current {
        return;
    }
    let axis_tightened = if lower_is_tighter {
        proposed < current
    } else {
        proposed > current
    };
    *ordering = match (*ordering, axis_tightened) {
        (RuleOrdering::Same, true) | (RuleOrdering::Tighter, true) => RuleOrdering::Tighter,
        (RuleOrdering::Same, false) | (RuleOrdering::Looser, false) => RuleOrdering::Looser,
        (RuleOrdering::Tighter, false) | (RuleOrdering::Looser, true) => {
            RuleOrdering::TighterAndLooser
        }
        (RuleOrdering::TighterAndLooser, _) => RuleOrdering::TighterAndLooser,
        (RuleOrdering::Unorderable, _) => RuleOrdering::Unorderable,
    };
}

fn fold_flag(ordering: &mut RuleOrdering, proposed: bool, current: bool) {
    if proposed == current {
        return;
    }
    // Enabling a check is the tightening arm; disabling it is the loosening.
    fold_axis(ordering, u64::from(proposed), u64::from(current), false);
}

fn rule_ordering(current: &BookingAntiAbuseRule, proposed: &BookingAntiAbuseRule) -> RuleOrdering {
    use BookingAntiAbuseRule as Rule;
    let mut ordering = RuleOrdering::Same;
    match (current, proposed) {
        (
            Rule::RequiredIntake {
                min_chars: current_min,
            },
            Rule::RequiredIntake {
                min_chars: proposed_min,
            },
        ) => fold_axis(
            &mut ordering,
            proposed_min.get().into(),
            current_min.get().into(),
            false,
        ),
        (
            Rule::MinimumNotice {
                normal_secs: current_normal,
                high_value_secs: current_high,
            },
            Rule::MinimumNotice {
                normal_secs: proposed_normal,
                high_value_secs: proposed_high,
            },
        ) => {
            fold_axis(
                &mut ordering,
                proposed_normal.get(),
                current_normal.get(),
                false,
            );
            fold_axis(
                &mut ordering,
                proposed_high.get(),
                current_high.get(),
                false,
            );
        }
        (
            Rule::HoneypotAndSubmitFloor {
                min_submit_millis: current_floor,
            },
            Rule::HoneypotAndSubmitFloor {
                min_submit_millis: proposed_floor,
            },
        ) => fold_axis(
            &mut ordering,
            proposed_floor.get(),
            current_floor.get(),
            false,
        ),
        (
            Rule::SlotListRate {
                per_minute_per_ip: current_rate,
                cache_ttl_secs: _,
            },
            Rule::SlotListRate {
                per_minute_per_ip: proposed_rate,
                cache_ttl_secs: _,
            },
        ) => {
            // The cache TTL shapes freshness, not admission strictness, so a
            // TTL-only change is an equivalent re-assertion.
            fold_axis(
                &mut ordering,
                proposed_rate.get().into(),
                current_rate.get().into(),
                true,
            );
        }
        (
            Rule::BookRate {
                per_minute_per_ip: current_rate,
                max_active_future_per_email: current_cap,
            },
            Rule::BookRate {
                per_minute_per_ip: proposed_rate,
                max_active_future_per_email: proposed_cap,
            },
        ) => {
            fold_axis(
                &mut ordering,
                proposed_rate.get().into(),
                current_rate.get().into(),
                true,
            );
            fold_axis(
                &mut ordering,
                u64::from(*proposed_cap),
                u64::from(*current_cap),
                true,
            );
        }
        (
            Rule::HoldRate {
                max_active_per_session: current_cap,
                per_minute_per_ip: current_rate,
            },
            Rule::HoldRate {
                max_active_per_session: proposed_cap,
                per_minute_per_ip: proposed_rate,
            },
        ) => {
            fold_axis(
                &mut ordering,
                u64::from(*proposed_cap),
                u64::from(*current_cap),
                true,
            );
            fold_axis(
                &mut ordering,
                proposed_rate.get().into(),
                current_rate.get().into(),
                true,
            );
        }
        (
            Rule::EmailPromptToCorrect {
                check_syntax: current_syntax,
                check_mx: current_mx,
                check_disposable_domain: current_disposable,
            },
            Rule::EmailPromptToCorrect {
                check_syntax: proposed_syntax,
                check_mx: proposed_mx,
                check_disposable_domain: proposed_disposable,
            },
        ) => {
            fold_flag(&mut ordering, *proposed_syntax, *current_syntax);
            fold_flag(&mut ordering, *proposed_mx, *current_mx);
            fold_flag(&mut ordering, *proposed_disposable, *current_disposable);
        }
        (Rule::QuarantineBorderline, Rule::QuarantineBorderline) => {}
        (
            Rule::EmailOtpReserve { enabled: current },
            Rule::EmailOtpReserve { enabled: proposed },
        ) => fold_flag(&mut ordering, *proposed, *current),
        (
            Rule::TentativeConfirmLinkReserve {
                enabled: current_enabled,
                expires_after_secs: current_ttl,
            },
            Rule::TentativeConfirmLinkReserve {
                enabled: proposed_enabled,
                expires_after_secs: proposed_ttl,
            },
        ) => {
            fold_flag(&mut ordering, *proposed_enabled, *current_enabled);
            fold_axis(&mut ordering, proposed_ttl.get(), current_ttl.get(), true);
        }
        _ => return RuleOrdering::Unorderable,
    }
    ordering
}

/// Canonical hash of the exact proposed row, version and every field in it.
/// The owner stamp binds this value, so a stamp minted for one proposal can
/// never activate another.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] when the canonical form cannot encode.
pub fn booking_rule_row_version_hash(
    row: &BookingAntiAbuseRuleRow,
) -> Result<[u8; 32], BookingError> {
    Ok(digest_with(ROW_VERSION_HASH_DOMAIN, &encode_row(row)?))
}

// -------------------------------------------------------------------------
// Activation
// -------------------------------------------------------------------------

fn read_rule_row_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    row_id: &str,
) -> Result<Option<BookingAntiAbuseRuleRow>, BookingError> {
    let Some(raw) = read_meta_bytes(vault, rtxn, &rule_row_key(row_id))? else {
        return Ok(None);
    };
    decode_row(&raw).map(Some)
}

fn put_rule_row_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    row: &BookingAntiAbuseRuleRow,
) -> Result<(), BookingError> {
    let encoded = encode_row(row)?;
    put_meta(vault, wtxn, &rule_row_key(&row.row_id), &encoded)
}

/// The private write surface. [`apply_rule_amendment`] is the only caller;
/// no public path may store a rule row without the versioned transaction.
#[allow(dead_code)]
fn put_booking_anti_abuse_rule(
    vault: &Vault,
    row: &BookingAntiAbuseRuleRow,
) -> Result<(), BookingError> {
    booking_writer(vault, |wtxn| put_rule_row_in_txn(vault, wtxn, row))
}

fn write_notice_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    row: &BookingAntiAbuseRuleRow,
    direction: AmendmentDirection,
) -> Result<(), BookingError> {
    let token = match direction {
        AmendmentDirection::Tightening => "tightening",
        AmendmentDirection::Equivalent => "re-assertion",
        AmendmentDirection::Loosening => "owner-stamped loosening",
    };
    let notice = format!(
        "booking anti-abuse rule {} activated at version {} ({}) by {}",
        row.row_id,
        row.version,
        token,
        row.amended_by.to_hex()
    );
    let key = notice_key(&row.row_id, row.version);
    put_meta(vault, wtxn, &key, notice.as_bytes())
}

/// The sole public activation path: a versioned compare-and-set under the
/// booking writer.
///
/// `expected_current_version == 0` activates the row for the first time and
/// the proposal must be version 1. Otherwise the stored row must sit at
/// `expected_current_version`, the proposal must advance it by exactly one,
/// and the direction law applies: tightening and equivalent re-assertions
/// store immediately; a loosening requires `owner_stamp` whose binding
/// equals [`booking_rule_row_version_hash`] of the exact proposed row. The
/// stamp reference is recorded by the transaction — a caller-supplied
/// `owner_stamp_ref` is refused.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] on a stale expected version, a
/// malformed or out-of-order proposal, a stamp declined for loosening, or a
/// stamp that binds anything other than the exact proposed row and version.
pub fn apply_rule_amendment(
    vault: &Vault,
    expected_current_version: u64,
    proposed: BookingAntiAbuseRuleRow,
    owner_stamp: Option<&BookingRuleOwnerStampBinding>,
) -> Result<RuleAmendmentOutcome, BookingError> {
    validate_rule_row(&proposed)?;
    if proposed.row_id != booking_rule_row_id(&proposed.scope, &proposed.rule) {
        return Err(refused(
            "rule row id does not match its canonical scope and rule identity",
        ));
    }
    if proposed.owner_stamp_ref.is_some() {
        return Err(refused(
            "the stamp binding is a transaction input; it is never caller-stored on the row",
        ));
    }
    booking_writer(vault, |wtxn| {
        let current = read_rule_row_in_txn(vault, &*wtxn, &proposed.row_id)?;
        let (stored, direction) = match (expected_current_version, current) {
            (0, None) => {
                if proposed.version != 1 {
                    return Err(refused(
                        "a first activation must be version 1 with expected version 0",
                    ));
                }
                // Activating a control that did not exist is additive; it is
                // the tightening arm.
                (proposed, AmendmentDirection::Tightening)
            }
            (0, Some(current)) => {
                return Err(refused(format!(
                    "rule row already exists at version {}; amend with the current version",
                    current.version
                )));
            }
            (expected, None) => {
                return Err(refused(format!(
                    "no stored rule row matches expected version {expected}"
                )));
            }
            (expected, Some(current)) => {
                if current.version != expected {
                    return Err(refused(format!(
                        "expected current version {expected} is stale; row is at {}",
                        current.version
                    )));
                }
                let direction = amendment_direction(&current, &proposed)?;
                let stored = match direction {
                    AmendmentDirection::Loosening => {
                        let Some(stamp) = owner_stamp else {
                            return Err(refused(
                                "loosening requires a logged owner stamp binding the exact proposed row and version",
                            ));
                        };
                        let bound = booking_rule_row_version_hash(&proposed)?;
                        if stamp.proposed_row_version_hash != bound {
                            return Err(refused(
                                "owner stamp does not bind the exact proposed row and version",
                            ));
                        }
                        BookingAntiAbuseRuleRow {
                            owner_stamp_ref: Some(stamp.stamp_ref),
                            ..proposed
                        }
                    }
                    AmendmentDirection::Tightening | AmendmentDirection::Equivalent => proposed,
                };
                (stored, direction)
            }
        };
        put_rule_row_in_txn(vault, wtxn, &stored)?;
        write_notice_in_txn(vault, wtxn, &stored, direction)?;
        Ok(RuleAmendmentOutcome {
            stored,
            owner_notice_required: true,
        })
    })
}

/// Decodes every stored rule row under the booking prefix. Rule rows are
/// owner-configured and few, so the loaders below both start from one full
/// prefix scan and differ only in their scope predicate.
fn all_rule_rows(vault: &Vault) -> Result<Vec<BookingAntiAbuseRuleRow>, BookingError> {
    let rtxn = vault
        .store
        .env
        .read_txn()
        .map_err(|error| engine_failure("read transaction", error))?;
    let mut rows = Vec::new();
    let prefix = rule_scan_prefix();
    let iter = vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, &prefix)
        .map_err(|error| engine_failure("rule scan", error))?;
    for entry in iter {
        let (_, raw) = entry.map_err(|error| engine_failure("rule scan", error))?;
        rows.push(decode_row(&raw)?);
    }
    Ok(rows)
}

/// Lists the stored rule rows for one exact scope, ordered by row id — the
/// admin/listing view. Request enforcement wants the applicable union
/// instead: [`applicable_booking_anti_abuse_rules`].
///
/// # Errors
///
/// Storage and decode failures, wrapped per the lane's error stance.
pub fn booking_anti_abuse_rules(
    vault: &Vault,
    scope: &BookingRuleScope,
) -> Result<Vec<BookingAntiAbuseRuleRow>, BookingError> {
    let mut rows: Vec<BookingAntiAbuseRuleRow> = all_rule_rows(vault)?
        .into_iter()
        .filter(|row| row.scope == *scope)
        .collect();
    rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
    Ok(rows)
}

/// Lists every stored rule row that governs one request: the page-wide
/// (`event_type: None`) stack for `page_ref` PLUS, when the request names an
/// event type, that event type's exact stack — the same union the
/// evaluator's `scoped_rules` predicate keeps. The HTTP adapter's row
/// loaders go through this door, so a page-wide owner configuration cannot
/// silently stop applying the moment a request carries an event type.
///
/// # Errors
///
/// Storage and decode failures, wrapped per the lane's error stance.
pub fn applicable_booking_anti_abuse_rules(
    vault: &Vault,
    page_ref: &EntityId,
    event_type: &Option<EventTypeKey>,
) -> Result<Vec<BookingAntiAbuseRuleRow>, BookingError> {
    let rows = all_rule_rows(vault)?;
    let mut applicable: Vec<BookingAntiAbuseRuleRow> =
        scoped_rules(&rows, page_ref, event_type).cloned().collect();
    applicable.sort_by(|left, right| left.row_id.cmp(&right.row_id));
    Ok(applicable)
}

/// Every durable activation notice, oldest first by row id then text. The
/// owner-visible companion of [`apply_rule_amendment`]: every stored
/// activation leaves one notice row.
///
/// # Errors
///
/// Storage failures, and [`BookingError::InvalidConstraint`] when a notice is
/// not UTF-8.
pub fn booking_anti_abuse_notices(vault: &Vault) -> Result<Vec<String>, BookingError> {
    let rtxn = vault
        .store
        .env
        .read_txn()
        .map_err(|error| engine_failure("read transaction", error))?;
    let mut notices = Vec::new();
    let prefix = notice_scan_prefix();
    let iter = vault
        .store
        .vault_meta
        .prefix_iter(&rtxn, &prefix)
        .map_err(|error| engine_failure("notice scan", error))?;
    for entry in iter {
        let (_, raw) = entry.map_err(|error| engine_failure("notice scan", error))?;
        let notice = std::str::from_utf8(&raw)
            .map_err(|_| refused("booking anti-abuse notice is not utf-8"))?;
        notices.push(notice.to_owned());
    }
    notices.sort();
    Ok(notices)
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

// -------------------------------------------------------------------------
// Evaluation
// -------------------------------------------------------------------------

/// Evidence about one submitted email address. `mx_present` is tri-state:
/// `None` means the check was not performed and counts as no signal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmailValidationEvidence {
    pub syntax_valid: bool,
    pub mx_present: Option<bool>,
    pub disposable_domain: bool,
}

/// Caller-asserted facts about one incoming booking request. Identity
/// material arrives pre-hashed; raw addresses never reach this module.
#[derive(Clone, Debug, PartialEq)]
pub struct BookingRequestFacts {
    pub page_ref: EntityId,
    pub event_type: Option<EventTypeKey>,
    pub ip_hash: [u8; 32],
    pub email_hash: Option<[u8; 32]>,
    pub session_hash: Option<[u8; 32]>,
    pub started_at_millis: u64,
    pub submitted_at_millis: u64,
    pub honeypot_nonempty: bool,
    pub intake_chars: usize,
    pub active_future_bookings_for_email: u8,
    pub active_holds_for_session: u8,
    pub email: Option<EmailValidationEvidence>,
}

/// What the engine concludes about one request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BookingAbuseVerdict {
    Allow,
    /// Reject while answering exactly like an ordinary 200. The adapter
    /// performs no write and reveals nothing.
    SilentHttp200Reject,
    RateLimited {
        retry_after_secs: u64,
    },
    PromptCorrection {
        field: &'static str,
        message: String,
    },
    Quarantine {
        reason: String,
    },
}

fn scoped_rules<'r>(
    rows: &'r [BookingAntiAbuseRuleRow],
    page_ref: &EntityId,
    event_type: &Option<EventTypeKey>,
) -> impl Iterator<Item = &'r BookingAntiAbuseRuleRow> {
    rows.iter().filter(move |row| {
        row.scope.page_ref == *page_ref
            && (row.scope.event_type.is_none() || row.scope.event_type == *event_type)
    })
}

/// The strictest slot-list knobs across the rows in scope. A cache-TTL
/// difference resolves toward the shorter (fresher) window, matching the
/// under-block posture on listings.
#[must_use]
pub fn slot_list_rate_knobs(
    rows: &[BookingAntiAbuseRuleRow],
    page_ref: &EntityId,
    event_type: &Option<EventTypeKey>,
) -> Option<(NonZeroU32, NonZeroU64)> {
    let mut merged: Option<(NonZeroU32, NonZeroU64)> = None;
    for row in scoped_rules(rows, page_ref, event_type) {
        if let BookingAntiAbuseRule::SlotListRate {
            per_minute_per_ip,
            cache_ttl_secs,
        } = &row.rule
        {
            merged = Some(match merged {
                None => (*per_minute_per_ip, *cache_ttl_secs),
                Some((rate, ttl)) => (rate.min(*per_minute_per_ip), ttl.min(*cache_ttl_secs)),
            });
        }
    }
    merged
}

/// The strictest book knobs across the rows in scope.
#[must_use]
pub fn book_rate_knobs(
    rows: &[BookingAntiAbuseRuleRow],
    page_ref: &EntityId,
    event_type: &Option<EventTypeKey>,
) -> Option<(NonZeroU32, u8)> {
    let mut merged: Option<(NonZeroU32, u8)> = None;
    for row in scoped_rules(rows, page_ref, event_type) {
        if let BookingAntiAbuseRule::BookRate {
            per_minute_per_ip,
            max_active_future_per_email,
        } = &row.rule
        {
            merged = Some(match merged {
                None => (*per_minute_per_ip, *max_active_future_per_email),
                Some((rate, cap)) => (
                    rate.min(*per_minute_per_ip),
                    cap.min(*max_active_future_per_email),
                ),
            });
        }
    }
    merged
}

/// The strictest hold knobs across the rows in scope.
#[must_use]
pub fn hold_rate_knobs(
    rows: &[BookingAntiAbuseRuleRow],
    page_ref: &EntityId,
    event_type: &Option<EventTypeKey>,
) -> Option<(u8, NonZeroU32)> {
    let mut merged: Option<(u8, NonZeroU32)> = None;
    for row in scoped_rules(rows, page_ref, event_type) {
        if let BookingAntiAbuseRule::HoldRate {
            max_active_per_session,
            per_minute_per_ip,
        } = &row.rule
        {
            merged = Some(match merged {
                None => (*max_active_per_session, *per_minute_per_ip),
                Some((cap, rate)) => (
                    cap.min(*max_active_per_session),
                    rate.min(*per_minute_per_ip),
                ),
            });
        }
    }
    merged
}

/// Pure request evaluation over stored rows plus asserted facts. No storage
/// access, so a honeypot or time-floor hit can be honoured with zero writes.
///
/// Precedence: the silent bot signals first (they must reveal nothing), then
/// the correctable intake and email prompts, then the caps.
#[derive(Clone, Copy)]
enum BookingEvaluationScope {
    All,
    Book,
    Hold,
    SlotList,
}

fn rule_applies_to_evaluation(rule: &BookingAntiAbuseRule, scope: BookingEvaluationScope) -> bool {
    match scope {
        BookingEvaluationScope::All => true,
        // Confirmation owns the submit-time signals, contact correction,
        // quarantine, and active-booking cap. Its minute quota remains an
        // adapter concern below this pure evaluator.
        BookingEvaluationScope::Book => matches!(
            rule,
            BookingAntiAbuseRule::HoneypotAndSubmitFloor { .. }
                | BookingAntiAbuseRule::RequiredIntake { .. }
                | BookingAntiAbuseRule::EmailPromptToCorrect { .. }
                | BookingAntiAbuseRule::QuarantineBorderline
                | BookingAntiAbuseRule::BookRate { .. }
        ),
        // Slot lookup and hold creation have no form evidence. Their only
        // controls are their endpoint counters, consumed by the adapter.
        BookingEvaluationScope::Hold => false,
        BookingEvaluationScope::SlotList => {
            matches!(rule, BookingAntiAbuseRule::HoneypotAndSubmitFloor { .. })
        }
    }
}

fn evaluate_booking_request_for(
    rows: &[BookingAntiAbuseRuleRow],
    facts: &BookingRequestFacts,
    evaluation_scope: BookingEvaluationScope,
) -> BookingAbuseVerdict {
    let scoped: Vec<&BookingAntiAbuseRuleRow> =
        scoped_rules(rows, &facts.page_ref, &facts.event_type)
            .filter(|row| rule_applies_to_evaluation(&row.rule, evaluation_scope))
            .collect();

    // Honeypot and time-to-submit floor are ONE control family: both
    // signals answer with the same indistinguishable rejection, and both are
    // armed only by an activated `HoneypotAndSubmitFloor` row in scope — the
    // sole public activation path decides what fires. A filled honeypot
    // field with no such row is noise, never a rejection.
    let floor = scoped
        .iter()
        .filter_map(|row| match &row.rule {
            BookingAntiAbuseRule::HoneypotAndSubmitFloor { min_submit_millis } => {
                Some(min_submit_millis.get())
            }
            _ => None,
        })
        .max();
    if floor.is_some() && facts.honeypot_nonempty {
        return BookingAbuseVerdict::SilentHttp200Reject;
    }
    if let Some(floor_millis) = floor
        && facts
            .submitted_at_millis
            .saturating_sub(facts.started_at_millis)
            < floor_millis
    {
        return BookingAbuseVerdict::SilentHttp200Reject;
    }

    // Required open-text intake.
    let min_intake = scoped
        .iter()
        .filter_map(|row| match &row.rule {
            BookingAntiAbuseRule::RequiredIntake { min_chars } => Some(min_chars.get()),
            _ => None,
        })
        .max();
    if let Some(min_chars) = min_intake
        && facts.intake_chars < usize::from(min_chars)
    {
        return BookingAbuseVerdict::PromptCorrection {
            field: "intake",
            message: format!(
                "please tell the host a little more — at least {min_chars} characters"
            ),
        };
    }

    // Email evidence: prompts, never a hard block. A `None` MX reading is no
    // signal.
    let (mut check_syntax, mut check_mx, mut check_disposable) = (false, false, false);
    let mut quarantine_enabled = false;
    for row in &scoped {
        match &row.rule {
            BookingAntiAbuseRule::EmailPromptToCorrect {
                check_syntax: syntax,
                check_mx: mx,
                check_disposable_domain: disposable,
            } => {
                check_syntax |= syntax;
                check_mx |= mx;
                check_disposable |= disposable;
            }
            BookingAntiAbuseRule::QuarantineBorderline => quarantine_enabled = true,
            _ => {}
        }
    }
    if let Some(evidence) = &facts.email {
        let mut negatives: u8 = 0;
        if check_syntax && !evidence.syntax_valid {
            negatives += 1;
        }
        if check_mx && evidence.mx_present == Some(false) {
            negatives += 1;
        }
        if check_disposable && evidence.disposable_domain {
            negatives += 1;
        }
        if negatives >= 2 {
            if quarantine_enabled {
                return BookingAbuseVerdict::Quarantine {
                    reason: "booking contact evidence failed several independent checks".to_owned(),
                };
            }
            // Under-block when quarantine is not seeded: prompt instead.
            return BookingAbuseVerdict::PromptCorrection {
                field: "email",
                message: "that email address needs a second look — please correct it".to_owned(),
            };
        }
        if negatives == 1 {
            let message = if check_syntax && !evidence.syntax_valid {
                "that email address does not look complete — please check it"
            } else if check_mx && evidence.mx_present == Some(false) {
                "that email domain does not accept mail — please check for typos"
            } else {
                "please use a permanent email address so the host can reach you"
            };
            return BookingAbuseVerdict::PromptCorrection {
                field: "email",
                message: message.to_owned(),
            };
        }
    }

    // Hold squatter cap: at most the configured number of active holds per
    // session. Transient by nature, so it is a retry, not a record.
    if matches!(evaluation_scope, BookingEvaluationScope::All)
        && let Some((max_active_per_session, _)) =
            hold_rate_knobs(rows, &facts.page_ref, &facts.event_type)
        && facts.active_holds_for_session >= max_active_per_session
    {
        return BookingAbuseVerdict::RateLimited {
            retry_after_secs: RATE_WINDOW_SECS,
        };
    }

    // Active-future-booking cap per email: user-correctable (cancel one), so
    // it prompts rather than blocking or triaging.
    if matches!(
        evaluation_scope,
        BookingEvaluationScope::All | BookingEvaluationScope::Book
    ) && facts.email_hash.is_some()
        && let Some((_, max_active_future_per_email)) =
            book_rate_knobs(rows, &facts.page_ref, &facts.event_type)
        && facts.active_future_bookings_for_email >= max_active_future_per_email
    {
        return BookingAbuseVerdict::PromptCorrection {
            field: "email",
            message:
                "this address already holds the maximum active upcoming bookings — cancel one or let it pass first"
                    .to_owned(),
        };
    }

    BookingAbuseVerdict::Allow
}

/// Full evaluation retained for callers and engine tests.
#[must_use]
pub fn evaluate_booking_request(
    rows: &[BookingAntiAbuseRuleRow],
    facts: &BookingRequestFacts,
) -> BookingAbuseVerdict {
    evaluate_booking_request_for(rows, facts, BookingEvaluationScope::All)
}

/// Confirmation-specific evaluation; it deliberately excludes hold-session caps.
#[must_use]
pub fn evaluate_booking_book_request(
    rows: &[BookingAntiAbuseRuleRow],
    facts: &BookingRequestFacts,
) -> BookingAbuseVerdict {
    evaluate_booking_request_for(rows, facts, BookingEvaluationScope::Book)
}

/// Hold creation has only its endpoint quota, evaluated by the adapter.
#[must_use]
pub fn evaluate_booking_hold_request(
    rows: &[BookingAntiAbuseRuleRow],
    facts: &BookingRequestFacts,
) -> BookingAbuseVerdict {
    evaluate_booking_request_for(rows, facts, BookingEvaluationScope::Hold)
}

/// Slot listing has only its endpoint quota, evaluated by the adapter.
#[must_use]
pub fn evaluate_booking_slot_list_request(
    rows: &[BookingAntiAbuseRuleRow],
    facts: &BookingRequestFacts,
) -> BookingAbuseVerdict {
    evaluate_booking_request_for(rows, facts, BookingEvaluationScope::SlotList)
}

// -------------------------------------------------------------------------
// Request-key hashing (raw identity never touches persistence)
// -------------------------------------------------------------------------

/// Domain-tagged hash of a caller IP. Persisted rate keys derive from this,
/// never from the raw address.
#[must_use]
pub fn booking_ip_hash(ip: &str) -> [u8; 32] {
    digest_with(IP_HASH_DOMAIN, ip.as_bytes())
}

/// Domain-tagged hash of a normalized (trimmed, lowercased) email address.
#[must_use]
pub fn booking_email_hash(email: &str) -> [u8; 32] {
    digest_with(EMAIL_HASH_DOMAIN, email.trim().to_lowercase().as_bytes())
}

/// Domain-tagged hash of an opaque session identifier.
#[must_use]
pub fn booking_session_hash(session: &str) -> [u8; 32] {
    digest_with(SESSION_HASH_DOMAIN, session.as_bytes())
}

// -------------------------------------------------------------------------
// Rate counters
// -------------------------------------------------------------------------

/// Outcome of one minute-window counter observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BookingRateDecision {
    /// The request consumed one token.
    Allowed,
    /// The window is spent; no token was consumed, so a rejection is free.
    Exceeded { retry_after_secs: u64 },
}

/// One node-local window counter, mirroring `task_verb.rs`: key per
/// (purpose, material), value `{window, count}`, overwritten each window.
fn consume_rate_token(
    vault: &Vault,
    purpose: &[u8],
    material: &[u8],
    per_minute: NonZeroU32,
    now_secs: u64,
) -> Result<BookingRateDecision, BookingError> {
    booking_writer(vault, |wtxn| {
        let window = now_secs / RATE_WINDOW_SECS;
        let key = rate_counter_key(purpose, material);
        let count = match read_meta_bytes(vault, &*wtxn, &key)? {
            Some(raw) => {
                let stored: [u8; 16] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| refused("booking anti-abuse rate row is malformed"))?;
                let stored_window =
                    u64::from_le_bytes(stored[..8].try_into().expect("rate window"));
                if stored_window == window {
                    u64::from_le_bytes(stored[8..].try_into().expect("rate count"))
                } else {
                    0
                }
            }
            None => 0,
        };
        if count >= u64::from(per_minute.get()) {
            return Ok(BookingRateDecision::Exceeded {
                retry_after_secs: RATE_WINDOW_SECS - now_secs % RATE_WINDOW_SECS,
            });
        }
        let mut value = [0_u8; 16];
        value[..8].copy_from_slice(&window.to_le_bytes());
        value[8..].copy_from_slice(&count.saturating_add(1).to_le_bytes());
        put_meta(vault, wtxn, &key, &value)?;
        Ok(BookingRateDecision::Allowed)
    })
}

/// Consumes one slot-list token for this IP. Keyed by IP alone: a listing
/// request has not yet asserted an email.
///
/// # Errors
///
/// Storage failures.
pub fn observe_slot_list_request(
    vault: &Vault,
    ip_hash: &[u8; 32],
    per_minute_per_ip: NonZeroU32,
    now_secs: u64,
) -> Result<BookingRateDecision, BookingError> {
    consume_rate_token(vault, b"slot-list", ip_hash, per_minute_per_ip, now_secs)
}

/// Consumes one book token. When an email is available the key combines IP
/// and email, so two people behind one corporate NAT keep independent minute
/// budgets while repeat traffic from one IP+email shares one.
///
/// # Errors
///
/// Storage failures.
pub fn observe_book_request(
    vault: &Vault,
    ip_hash: &[u8; 32],
    email_hash: Option<&[u8; 32]>,
    per_minute_per_ip: NonZeroU32,
    now_secs: u64,
) -> Result<BookingRateDecision, BookingError> {
    let material = match email_hash {
        Some(email_hash) => {
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(ip_hash);
            combined.extend_from_slice(email_hash);
            combined
        }
        None => ip_hash.to_vec(),
    };
    consume_rate_token(vault, b"book", &material, per_minute_per_ip, now_secs)
}

/// Consumes one hold token for this IP.
///
/// # Errors
///
/// Storage failures.
pub fn observe_hold_request(
    vault: &Vault,
    ip_hash: &[u8; 32],
    per_minute_per_ip: NonZeroU32,
    now_secs: u64,
) -> Result<BookingRateDecision, BookingError> {
    consume_rate_token(vault, b"hold", ip_hash, per_minute_per_ip, now_secs)
}

// -------------------------------------------------------------------------
// Slot-list response cache
// -------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct SlotListCacheRow {
    stored_at: u64,
    ttl_secs: u64,
    body: Vec<u8>,
}

/// Reads the cached slot-list response for one scope, or `None` when the
/// entry is absent or older than its TTL.
///
/// # Errors
///
/// Storage and decode failures.
pub fn read_slot_list_cache(
    vault: &Vault,
    page_ref: &EntityId,
    event_type: Option<&EventTypeKey>,
    now_secs: u64,
) -> Result<Option<Vec<u8>>, BookingError> {
    let rtxn = vault
        .store
        .env
        .read_txn()
        .map_err(|error| engine_failure("read transaction", error))?;
    let Some(raw) = read_meta_bytes(vault, &rtxn, &slot_list_cache_key(page_ref, event_type))?
    else {
        return Ok(None);
    };
    let row: SlotListCacheRow = decode_row(&raw)?;
    if now_secs.saturating_sub(row.stored_at) >= row.ttl_secs {
        return Ok(None);
    }
    Ok(Some(row.body))
}

/// Stores one slot-list response under the booking-only prefix. The TTL must
/// sit inside the ratified 30-60 second window, which rule validation
/// already enforces; this is the same check at the write door.
///
/// # Errors
///
/// [`BookingError::InvalidConstraint`] on an out-of-window TTL or an
/// oversized body; storage failures otherwise.
pub fn write_slot_list_cache(
    vault: &Vault,
    page_ref: &EntityId,
    event_type: Option<&EventTypeKey>,
    body: &[u8],
    ttl_secs: NonZeroU64,
    now_secs: u64,
) -> Result<(), BookingError> {
    check_slot_list_cache_ttl(ttl_secs.get())?;
    if body.len() > CACHE_BODY_MAX_LEN {
        return Err(refused("slot-list cache body exceeds the 512 KiB bound"));
    }
    let row = SlotListCacheRow {
        stored_at: now_secs,
        ttl_secs: ttl_secs.get(),
        body: body.to_vec(),
    };
    let encoded = encode_row(&row)?;
    booking_writer(vault, |wtxn| {
        put_meta(
            vault,
            wtxn,
            &slot_list_cache_key(page_ref, event_type),
            &encoded,
        )
    })
}

// -------------------------------------------------------------------------
// Quarantine (pending-review record through the gate's own ledger rows)
// -------------------------------------------------------------------------

/// What a quarantined submission left behind: the owner-reviewable record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BookingQuarantineReceipt {
    /// The pending-consent row key bytes (also hexed into `claim_ref`).
    pub claim_id: [u8; 16],
    pub decision_id: [u8; 16],
    pub claim_ref: String,
    pub decision_ref: String,
    pub reason_codes: Vec<String>,
}

/// The review payload on the quarantine claim: hashed identity only — raw
/// addresses never cross into persistence here either.
fn quarantine_claim_value(facts: &BookingRequestFacts, reason: &str) -> rmpv::Value {
    let mut entries = vec![
        (
            rmpv::Value::from("page_ref"),
            rmpv::Value::from(facts.page_ref.to_hex()),
        ),
        (
            rmpv::Value::from("ip_hash"),
            rmpv::Value::from(hex_lower(&facts.ip_hash)),
        ),
        (
            rmpv::Value::from("submitted_at_millis"),
            rmpv::Value::from(facts.submitted_at_millis),
        ),
        (rmpv::Value::from("reason"), rmpv::Value::from(reason)),
    ];
    if let Some(event_type) = &facts.event_type {
        entries.push((
            rmpv::Value::from("event_type"),
            rmpv::Value::from(event_type.0.as_str()),
        ));
    }
    if let Some(email_hash) = &facts.email_hash {
        entries.push((
            rmpv::Value::from("email_hash"),
            rmpv::Value::from(hex_lower(email_hash)),
        ));
    }
    rmpv::Value::Map(entries)
}

/// Routes one borderline submission to a durable pending-review inbox card,
/// never silently deleting it.
///
/// Three rows land in ONE booking-writer transaction, all through existing
/// crate doors: a minimal CLAIM body for the quarantined submission (via
/// [`Vault::put_claim_in_txn`], the door the booking lifecycle's claim
/// helper uses), plus the gate's own `GateDecisionRecord` +
/// `PendingGateConsentRecord` pair — exactly what `inbox.rs` pending-group
/// construction reads. The pending row stamps a content-keyed synthetic run
/// id, and `resolve_run_identity` keeps it verbatim as the group key because
/// no Dreamer attempt rows anchor it; the `diff_handle` / frontier pair
/// binds the exact stored claim body through
/// [`crate::gate::claim_consent_binding_parts`], so an owner verdict from
/// the inbox verifies against this row instead of going stale on arrival.
///
/// The claim names the booking page as its subject through the ordinary
/// claim door, so the page the guard ran for must exist in the vault — the
/// same subject precondition the calendar outcome recorder takes. A request
/// against a page the vault does not hold surfaces as an engine error, not a
/// dropped record.
///
/// # Errors
///
/// Storage failures, claim-door rejections (including a missing page
/// subject), and consent-binding failures.
pub fn quarantine_borderline_submission(
    vault: &Vault,
    facts: &BookingRequestFacts,
    reason: &str,
) -> Result<BookingQuarantineReceipt, BookingError> {
    let mut material = Vec::new();
    material.extend_from_slice(facts.page_ref.as_bytes());
    material.extend_from_slice(&facts.ip_hash);
    if let Some(email_hash) = &facts.email_hash {
        material.extend_from_slice(email_hash);
    }
    // Submission timestamps are caller-controlled and must not create a new
    // quarantine identity on every retry.
    // F5: bind tagged event_type presence + value so cross-event submissions
    // mint distinct claim identities while exact-duplicate retries stay
    // idempotent. Presence tag (0x00 absent, 0x01 present) plus, when present,
    // length-delimited event_type bytes, framed before the variable-length
    // reason tail.
    match &facts.event_type {
        Some(event_type) => {
            material.push(0x01);
            let bytes = event_type.0.as_bytes();
            material.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            material.extend_from_slice(bytes);
        }
        None => material.push(0x00),
    }
    material.extend_from_slice(reason.as_bytes());
    let binding = digest_with(QUARANTINE_CLAIM_DOMAIN, &material);

    let mut claim_id = [0_u8; 16];
    claim_id.copy_from_slice(&binding[..16]);
    let claim_ref = EntityId::from_bytes(claim_id)
        .map_err(|error| engine_failure("quarantine claim id", error))?;
    let reason_codes = vec![QUARANTINE_REASON_CODE.to_owned()];
    // Content-derived identifiers make retry handling idempotent. Keep the
    // timestamp in a bounded, valid epoch range rather than trusting request time.
    let created_at =
        u64::from_be_bytes(binding[..8].try_into().expect("eight bytes")) % 4_102_444_800;
    let run_id = format!("{QUARANTINE_RUN_ID_PREFIX}{}", hex_lower(&claim_id));

    // The minimal durable CLAIM body the pending-review card renders. The
    // id and the value are both content-keyed, so a quarantine retried for
    // the very same submission re-states the row instead of forking it.
    let mut body = ClaimBody::new(
        QUARANTINE_CLAIM_PREDICATE,
        ClaimSubject::Entity(facts.page_ref),
        quarantine_claim_value(facts, reason),
        1.0,
        ClaimApprovalStatus::Proposed,
        ClaimLifecycleStatus::Active,
    );
    body.source = Some(ClaimSource::Observed);
    body.valid_from = Some(created_at);

    let decision_id = GateDecisionId::from_bytes(claim_id);
    let receipt = BookingQuarantineReceipt {
        claim_id,
        decision_id: decision_id.as_bytes(),
        claim_ref: hex_lower(&claim_id),
        decision_ref: decision_id.to_hex(),
        reason_codes: reason_codes.clone(),
    };
    booking_writer(vault, |wtxn| {
        if let Some(existing) = vault
            .store
            .pending_gate_consent_in_txn(&*wtxn, &claim_ref)
            .map_err(|error| engine_failure("quarantine pending read", error))?
        {
            // A pending review is the authoritative retry receipt; never
            // append another gate decision or replace its claim body.
            return Ok(BookingQuarantineReceipt {
                claim_id,
                decision_id: existing.decision_id.as_bytes(),
                claim_ref: hex_lower(&claim_id),
                decision_ref: existing.decision_id.to_hex(),
                reason_codes: existing.reason_codes,
            });
        }
        if vault
            .get_claim_in_txn(&*wtxn, &claim_ref)
            .map_err(|error| engine_failure("quarantine claim read", error))?
            .is_some()
        {
            // A content-keyed claim proves this submission was already
            // admitted; its pending row may since have been resolved.
            return Ok(receipt.clone());
        }
        // Consent binding over the exact stored body, computed against the
        // live policy read frontier: the inbox's accept door re-derives
        // precisely this pair before redeeming the row.
        let (diff_handle, read_frontier_hash) =
            crate::gate::claim_consent_binding_parts(&vault.store, wtxn, &body)
                .map_err(|error| engine_failure("quarantine consent binding", error))?;
        vault
            .put_claim_in_txn(
                wtxn,
                &claim_ref,
                &body,
                TimeRange {
                    start: created_at,
                    end: created_at,
                },
                created_at,
            )
            .map_err(|error| engine_failure("quarantine claim write", error))?;
        let decision = GateDecisionRecord {
            version: 0,
            decision_id,
            created_at,
            outcome: "pending".to_owned(),
            reason_codes: reason_codes.clone(),
            receipt_reasons: Vec::new(),
            system_notices: Vec::new(),
            actor_class: "booking.http_guard".to_owned(),
            actor_ref: None,
            content_kind: "booking.submission".to_owned(),
            policy_manifest_version: "booking.anti_abuse.v1".to_owned(),
            claim_id: Some(claim_id),
            grant_ref: None,
            diff_handle: diff_handle.clone(),
            read_frontier_hash,
            redacted_at: None,
        };
        let pending = PendingGateConsentRecord {
            version: 0,
            claim_id,
            decision_id,
            created_at,
            diff_handle,
            read_frontier_hash,
            reason_codes,
            dreamer_run_id: Some(run_id),
        };
        vault
            .store
            .append_gate_decision_in_txn(wtxn, &decision)
            .map_err(|error| engine_failure("quarantine decision append", error))?;
        vault
            .store
            .put_pending_gate_consent_in_txn(wtxn, &pending)
            .map_err(|error| engine_failure("quarantine pending record", error))?;
        Ok(receipt)
    })
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

// The module is named so `cargo test -p oneiron booking_anti_abuse` selects
// every test here (the ticket-gated command filters on the full test path,
// and `booking::anti_abuse::tests` does not contain the substring).
#[cfg(test)]
mod booking_anti_abuse_tests {
    use super::*;
    use crate::test_util::entity as id;

    const PAGE: u8 = 0x51;
    const OWNER: u8 = 0x52;
    const STAMP: u8 = 0x53;
    const OTHER_PAGE: u8 = 0x54;

    fn open_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("temp dir");
        let vault =
            Vault::open(dir.path(), crate::VaultConfig::default()).expect("open anti-abuse vault");
        (dir, vault)
    }

    fn nz16(value: u16) -> NonZeroU16 {
        match NonZeroU16::new(value) {
            Some(nz) => nz,
            None => panic!("fixture must be non-zero"),
        }
    }

    fn nz32(value: u32) -> NonZeroU32 {
        match NonZeroU32::new(value) {
            Some(nz) => nz,
            None => panic!("fixture must be non-zero"),
        }
    }

    fn nz64(value: u64) -> NonZeroU64 {
        match NonZeroU64::new(value) {
            Some(nz) => nz,
            None => panic!("fixture must be non-zero"),
        }
    }

    fn scope() -> BookingRuleScope {
        BookingRuleScope {
            page_ref: id(PAGE),
            event_type: Some(EventTypeKey("intro-call".to_owned())),
        }
    }

    /// Ratified owner-supplied values: 24h/48h notice, 120 slot-list
    /// lookups/min with a 45s cache, 10 books/min with one active future
    /// booking per email, one active hold per session behind a 30/min IP cap.
    fn owner_config() -> BookingAntiAbuseOwnerConfig {
        BookingAntiAbuseOwnerConfig {
            min_intake_chars: nz16(10),
            normal_notice_secs: nz64(86_400),
            high_value_notice_secs: nz64(172_800),
            min_submit_millis: nz64(1_500),
            slot_list_per_minute_per_ip: nz32(120),
            slot_list_cache_ttl_secs: nz64(45),
            book_per_minute_per_ip: nz32(10),
            max_active_future_per_email: 1,
            max_active_holds_per_session: 1,
            hold_per_minute_per_ip: nz32(30),
            tentative_confirm_ttl_secs: nz64(900),
        }
    }

    fn seed_rows() -> Vec<BookingAntiAbuseRuleRow> {
        default_booking_anti_abuse_rows(
            id(PAGE),
            Some(EventTypeKey("intro-call".to_owned())),
            &owner_config(),
        )
        .expect("seed rows validate")
    }

    fn install_rows(vault: &Vault, rows: &[BookingAntiAbuseRuleRow]) {
        for row in rows {
            let outcome = apply_rule_amendment(vault, 0, row.clone(), None).expect("install row");
            assert!(outcome.owner_notice_required);
        }
    }

    fn seed_rule(rule: &BookingAntiAbuseRule) -> BookingAntiAbuseRuleRow {
        let scope = scope();
        BookingAntiAbuseRuleRow {
            row_id: booking_rule_row_id(&scope, rule),
            scope,
            rule: rule.clone(),
            version: 1,
            amended_at: 1_777_777_777,
            amended_by: id(OWNER),
            owner_stamp_ref: None,
        }
    }

    fn facts() -> BookingRequestFacts {
        BookingRequestFacts {
            page_ref: id(PAGE),
            event_type: Some(EventTypeKey("intro-call".to_owned())),
            ip_hash: booking_ip_hash("203.0.113.10"),
            email_hash: None,
            session_hash: Some(booking_session_hash("sess-alpha")),
            started_at_millis: 1_000_000,
            submitted_at_millis: 1_000_000 + 5_000,
            honeypot_nonempty: false,
            intake_chars: 40,
            active_future_bookings_for_email: 0,
            active_holds_for_session: 0,
            email: None,
        }
    }

    fn amend_with(rule: &BookingAntiAbuseRule, version: u64) -> BookingAntiAbuseRuleRow {
        BookingAntiAbuseRuleRow {
            version,
            ..seed_rule(rule)
        }
    }

    #[test]
    fn owner_config_rows_cover_exact_ship_skip_reserve_stack() {
        let rows = seed_rows();
        assert_eq!(
            rows.len(),
            10,
            "eight SHIP controls plus two RESERVE rows, nothing else"
        );

        let mut required_intake = 0;
        let mut minimum_notice = 0;
        let mut honeypot_floor = 0;
        let mut slot_list_rate = 0;
        let mut book_rate = 0;
        let mut hold_rate = 0;
        let mut email_prompt = 0;
        let mut quarantine = 0;
        let mut otp_reserve = 0;
        let mut link_reserve = 0;
        for row in &rows {
            // This match is deliberately exhaustive: the SKIP stack ships by
            // absence, so the compiler proves the closed variant set carries
            // no interactive-challenge or client-probing control.
            match &row.rule {
                BookingAntiAbuseRule::RequiredIntake { min_chars } => {
                    required_intake += 1;
                    assert_eq!(min_chars.get(), 10);
                }
                BookingAntiAbuseRule::MinimumNotice { .. } => minimum_notice += 1,
                BookingAntiAbuseRule::HoneypotAndSubmitFloor { .. } => honeypot_floor += 1,
                BookingAntiAbuseRule::SlotListRate { .. } => slot_list_rate += 1,
                BookingAntiAbuseRule::BookRate { .. } => book_rate += 1,
                BookingAntiAbuseRule::HoldRate { .. } => hold_rate += 1,
                BookingAntiAbuseRule::EmailPromptToCorrect {
                    check_syntax,
                    check_mx,
                    check_disposable_domain,
                } => {
                    email_prompt += 1;
                    assert!(*check_syntax && *check_mx && *check_disposable_domain);
                }
                BookingAntiAbuseRule::QuarantineBorderline => quarantine += 1,
                BookingAntiAbuseRule::EmailOtpReserve { enabled } => {
                    otp_reserve += 1;
                    assert!(!enabled, "OTP reserve starts off");
                }
                BookingAntiAbuseRule::TentativeConfirmLinkReserve {
                    enabled,
                    expires_after_secs,
                } => {
                    link_reserve += 1;
                    assert!(!enabled, "confirm-link reserve starts off");
                    assert_eq!(expires_after_secs.get(), 900);
                }
            }
            validate_rule_row(row).expect("seed row must validate");
            assert!(row.owner_stamp_ref.is_none());
            assert_eq!(row.version, 1);
        }
        assert_eq!(
            (
                required_intake,
                minimum_notice,
                honeypot_floor,
                slot_list_rate,
                book_rate,
                hold_rate,
                email_prompt,
                quarantine,
                otp_reserve,
                link_reserve
            ),
            (1, 1, 1, 1, 1, 1, 1, 1, 1, 1),
            "exactly one SHIP row per control plus the two RESERVE rows"
        );
    }

    #[test]
    fn owner_config_thresholds_validate_ratified_ranges_without_constants() {
        let config = owner_config();
        let rows = seed_rows();
        let mut seen_slot = false;
        let mut seen_notice = false;
        let mut seen_book = false;
        let mut seen_hold = false;
        let mut seen_intake = false;
        let mut seen_floor = false;
        for row in &rows {
            match &row.rule {
                BookingAntiAbuseRule::SlotListRate {
                    per_minute_per_ip,
                    cache_ttl_secs,
                } => {
                    seen_slot = true;
                    assert_eq!(per_minute_per_ip.get(), 120);
                    assert_eq!(cache_ttl_secs.get(), 45);
                    assert_eq!(*per_minute_per_ip, config.slot_list_per_minute_per_ip);
                    assert_eq!(*cache_ttl_secs, config.slot_list_cache_ttl_secs);
                }
                BookingAntiAbuseRule::MinimumNotice {
                    normal_secs,
                    high_value_secs,
                } => {
                    seen_notice = true;
                    assert_eq!(normal_secs.get(), 86_400);
                    assert_eq!(high_value_secs.get(), 172_800);
                    assert_eq!(*normal_secs, config.normal_notice_secs);
                    assert_eq!(*high_value_secs, config.high_value_notice_secs);
                }
                BookingAntiAbuseRule::BookRate {
                    per_minute_per_ip,
                    max_active_future_per_email,
                } => {
                    seen_book = true;
                    assert_eq!(per_minute_per_ip.get(), 10);
                    assert_eq!(*max_active_future_per_email, 1);
                }
                BookingAntiAbuseRule::HoldRate {
                    max_active_per_session,
                    per_minute_per_ip,
                } => {
                    seen_hold = true;
                    assert_eq!(*max_active_per_session, 1);
                    assert_eq!(per_minute_per_ip.get(), 30);
                }
                BookingAntiAbuseRule::RequiredIntake { min_chars } => {
                    seen_intake = true;
                    assert_eq!(*min_chars, config.min_intake_chars);
                }
                BookingAntiAbuseRule::HoneypotAndSubmitFloor { min_submit_millis } => {
                    seen_floor = true;
                    assert_eq!(*min_submit_millis, config.min_submit_millis);
                }
                _ => {}
            }
        }
        assert!(
            seen_slot && seen_notice && seen_book && seen_hold && seen_intake && seen_floor,
            "every owner-chosen threshold preserved through construction"
        );

        // Nothing is baked: changing one constructor argument changes the row.
        let mut tuned = owner_config();
        tuned.slot_list_per_minute_per_ip = nz32(99);
        let retuned = default_booking_anti_abuse_rows(
            id(PAGE),
            Some(EventTypeKey("intro-call".to_owned())),
            &tuned,
        )
        .expect("retuned rows");
        let slot = retuned
            .iter()
            .find_map(|row| match &row.rule {
                BookingAntiAbuseRule::SlotListRate {
                    per_minute_per_ip, ..
                } => Some(*per_minute_per_ip),
                _ => None,
            })
            .expect("slot row");
        assert_eq!(slot.get(), 99);

        // Ratified ranges hold: cache TTL outside 30-60, inverted notice
        // dials, and an out-of-band email cap all refuse.
        for bad_ttl in [29_u64, 61] {
            let row = seed_rule(&BookingAntiAbuseRule::SlotListRate {
                per_minute_per_ip: nz32(120),
                cache_ttl_secs: nz64(bad_ttl),
            });
            assert!(
                validate_rule_row(&row).is_err(),
                "ttl {bad_ttl} must refuse"
            );
        }
        let inverted = seed_rule(&BookingAntiAbuseRule::MinimumNotice {
            normal_secs: nz64(200_000),
            high_value_secs: nz64(100_000),
        });
        assert!(validate_rule_row(&inverted).is_err());
        for bad_cap in [0_u8, 3] {
            let row = seed_rule(&BookingAntiAbuseRule::BookRate {
                per_minute_per_ip: nz32(10),
                max_active_future_per_email: bad_cap,
            });
            assert!(
                validate_rule_row(&row).is_err(),
                "cap {bad_cap} must refuse"
            );
        }
        let good_cap = seed_rule(&BookingAntiAbuseRule::BookRate {
            per_minute_per_ip: nz32(10),
            max_active_future_per_email: 2,
        });
        assert!(validate_rule_row(&good_cap).is_ok());
    }

    #[test]
    fn tightening_auto_applies_and_emits_notice() {
        let (_dir, vault) = open_vault();
        install_rows(&vault, &seed_rows());
        let row_id = booking_rule_row_id(
            &scope(),
            &BookingAntiAbuseRule::RequiredIntake {
                min_chars: nz16(10),
            },
        );

        let mut tighter = amend_with(
            &BookingAntiAbuseRule::RequiredIntake {
                min_chars: nz16(20),
            },
            2,
        );
        tighter.row_id.clone_from(&row_id);
        let outcome = apply_rule_amendment(&vault, 1, tighter.clone(), None).expect("tighten");
        assert!(outcome.owner_notice_required);
        assert_eq!(outcome.stored.version, 2);
        assert!(outcome.stored.owner_stamp_ref.is_none());

        let rows = booking_anti_abuse_rules(&vault, &scope()).expect("read rows");
        let stored = rows
            .iter()
            .find(|row| row.row_id == row_id)
            .expect("stored row");
        assert_eq!(
            stored.rule,
            BookingAntiAbuseRule::RequiredIntake {
                min_chars: nz16(20)
            }
        );
        assert_eq!(stored.version, 2);

        let notices = booking_anti_abuse_notices(&vault).expect("notices");
        let row_notices: Vec<&String> = notices
            .iter()
            .filter(|notice| notice.contains(&row_id))
            .collect();
        assert_eq!(row_notices.len(), 2, "one notice per activation");
        assert!(row_notices[0].contains("version 1 (tightening)"));
        assert!(row_notices[1].contains("version 2 (tightening)"));

        // The compare-and-set refuses a stale expected version.
        let stale = apply_rule_amendment(&vault, 1, tighter, None);
        assert!(stale.is_err(), "stale expected version must refuse");
    }

    #[test]
    fn loosening_requires_exact_row_version_stamp_hash() {
        let (_dir, vault) = open_vault();
        install_rows(&vault, &seed_rows());
        let row_id = booking_rule_row_id(
            &scope(),
            &BookingAntiAbuseRule::RequiredIntake {
                min_chars: nz16(10),
            },
        );

        let mut looser = amend_with(
            &BookingAntiAbuseRule::RequiredIntake { min_chars: nz16(4) },
            2,
        );
        looser.row_id.clone_from(&row_id);

        // No stamp: refused.
        assert!(
            apply_rule_amendment(&vault, 1, looser.clone(), None).is_err(),
            "a loosening without a stamp must refuse"
        );

        // A stamp bound to a different proposed row: refused.
        let other = amend_with(
            &BookingAntiAbuseRule::RequiredIntake { min_chars: nz16(6) },
            2,
        );
        let other_hash = booking_rule_row_version_hash(&other).expect("hash other");
        let wrong_row_stamp = BookingRuleOwnerStampBinding {
            stamp_ref: id(STAMP),
            proposed_row_version_hash: other_hash,
        };
        assert!(
            apply_rule_amendment(&vault, 1, looser.clone(), Some(&wrong_row_stamp)).is_err(),
            "a stamp bound to different rows must refuse"
        );

        // A stamp bound to the same rows but a different version: refused.
        let wrong_version = amend_with(
            &BookingAntiAbuseRule::RequiredIntake { min_chars: nz16(4) },
            3,
        );
        let wrong_version_stamp = BookingRuleOwnerStampBinding {
            stamp_ref: id(STAMP),
            proposed_row_version_hash: booking_rule_row_version_hash(&wrong_version)
                .expect("hash wrong version"),
        };
        assert!(
            apply_rule_amendment(&vault, 1, looser.clone(), Some(&wrong_version_stamp)).is_err(),
            "a stamp bound to a different version must refuse"
        );

        // Only the exact binding activates, and the transaction records it.
        let exact_hash = booking_rule_row_version_hash(&looser).expect("hash looser");
        let stamp = BookingRuleOwnerStampBinding {
            stamp_ref: id(STAMP),
            proposed_row_version_hash: exact_hash,
        };
        let outcome =
            apply_rule_amendment(&vault, 1, looser, Some(&stamp)).expect("stamped loosening");
        assert!(outcome.owner_notice_required);
        assert_eq!(outcome.stored.owner_stamp_ref, Some(id(STAMP)));
        assert_eq!(outcome.stored.version, 2);

        let rows = booking_anti_abuse_rules(&vault, &scope()).expect("read rows");
        let stored = rows
            .iter()
            .find(|row| row.row_id == row_id)
            .expect("stored row");
        assert_eq!(stored.owner_stamp_ref, Some(id(STAMP)));

        // No staged state lingers: a fresh proposal needs a fresh binding.
        let replay = amend_with(
            &BookingAntiAbuseRule::RequiredIntake { min_chars: nz16(2) },
            3,
        );
        let replay_bound_stamp = BookingRuleOwnerStampBinding {
            proposed_row_version_hash: booking_rule_row_version_hash(&replay).expect("hash replay"),
            ..stamp
        };
        assert!(
            apply_rule_amendment(&vault, 2, replay, Some(&replay_bound_stamp)).is_ok(),
            "a fresh stamp binds a fresh proposal; nothing pending exists to replay"
        );
    }

    #[test]
    fn put_rule_is_private_and_public_activation_is_amendment_only() {
        let (_dir, vault) = open_vault();
        let first = seed_rule(&BookingAntiAbuseRule::RequiredIntake {
            min_chars: nz16(10),
        });

        // First activation is a version-0-expected, version-1 proposal.
        assert!(apply_rule_amendment(&vault, 0, first.clone(), None).is_ok());

        // The private-put bypasses this module cannot offer: every wrong
        // version framing refuses, so only the versioned transaction stores.
        assert!(
            apply_rule_amendment(&vault, 0, first.clone(), None).is_err(),
            "re-creation through the version-0 door must refuse an existing row"
        );
        let mut v3 = first.clone();
        v3.version = 3;
        assert!(
            apply_rule_amendment(&vault, 1, v3, None).is_err(),
            "skipping a version must refuse"
        );
        let mut v1_again = first;
        v1_again.version = 1;
        assert!(
            apply_rule_amendment(&vault, 1, v1_again, None).is_err(),
            "restating version 1 must refuse"
        );
        let v2 = amend_with(
            &BookingAntiAbuseRule::RequiredIntake {
                min_chars: nz16(20),
            },
            2,
        );
        assert!(
            apply_rule_amendment(&vault, 5, v2, None).is_err(),
            "an expected version the store does not hold must refuse"
        );

        // What did land is exactly what the versioned transaction reports.
        let rows = booking_anti_abuse_rules(&vault, &scope()).expect("read rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].version, 1);
    }

    #[test]
    fn amendment_direction_orders_each_variant_axis() {
        let scope = scope();
        let current = BookingAntiAbuseRuleRow {
            row_id: booking_rule_row_id(
                &scope,
                &BookingAntiAbuseRule::MinimumNotice {
                    normal_secs: nz64(86_400),
                    high_value_secs: nz64(172_800),
                },
            ),
            scope: scope.clone(),
            rule: BookingAntiAbuseRule::MinimumNotice {
                normal_secs: nz64(86_400),
                high_value_secs: nz64(172_800),
            },
            version: 1,
            amended_at: 7,
            amended_by: id(OWNER),
            owner_stamp_ref: None,
        };
        let mut proposed = current.clone();
        proposed.version = 2;
        assert_eq!(
            amendment_direction(&current, &proposed).expect("ordered"),
            AmendmentDirection::Equivalent
        );

        proposed.rule = BookingAntiAbuseRule::MinimumNotice {
            normal_secs: nz64(100_000),
            high_value_secs: nz64(172_800),
        };
        assert_eq!(
            amendment_direction(&current, &proposed).expect("ordered"),
            AmendmentDirection::Tightening
        );

        proposed.rule = BookingAntiAbuseRule::MinimumNotice {
            normal_secs: nz64(100_000),
            high_value_secs: nz64(100_000),
        };
        assert_eq!(
            amendment_direction(&current, &proposed).expect("ordered"),
            AmendmentDirection::Loosening,
            "one loosened axis routes the whole amendment to the stamp"
        );

        // Variant drift is unorderable and therefore a stamp case.
        proposed.rule = BookingAntiAbuseRule::QuarantineBorderline;
        assert_eq!(
            amendment_direction(&current, &proposed).expect("ordered"),
            AmendmentDirection::Loosening
        );
        proposed.rule = BookingAntiAbuseRule::MinimumNotice {
            normal_secs: nz64(86_400),
            high_value_secs: nz64(172_800),
        };

        // Versions must advance by exactly one; scope and id are immutable.
        proposed.version = 3;
        assert!(amendment_direction(&current, &proposed).is_err());
        proposed.version = 2;
        proposed.scope = BookingRuleScope {
            page_ref: id(OTHER_PAGE),
            event_type: None,
        };
        assert!(amendment_direction(&current, &proposed).is_err());

        // Slot-list: lowering the minute cap tightens; a TTL-only move is an
        // equivalent re-assertion.
        let slot = BookingAntiAbuseRuleRow {
            row_id: booking_rule_row_id(
                &scope,
                &BookingAntiAbuseRule::SlotListRate {
                    per_minute_per_ip: nz32(120),
                    cache_ttl_secs: nz64(45),
                },
            ),
            scope,
            rule: BookingAntiAbuseRule::SlotListRate {
                per_minute_per_ip: nz32(120),
                cache_ttl_secs: nz64(45),
            },
            version: 1,
            amended_at: 7,
            amended_by: id(OWNER),
            owner_stamp_ref: None,
        };
        let mut slot_tighter = slot.clone();
        slot_tighter.version = 2;
        slot_tighter.rule = BookingAntiAbuseRule::SlotListRate {
            per_minute_per_ip: nz32(60),
            cache_ttl_secs: nz64(45),
        };
        assert_eq!(
            amendment_direction(&slot, &slot_tighter).expect("ordered"),
            AmendmentDirection::Tightening
        );
        let mut slot_refresh = slot.clone();
        slot_refresh.version = 2;
        slot_refresh.rule = BookingAntiAbuseRule::SlotListRate {
            per_minute_per_ip: nz32(120),
            cache_ttl_secs: nz64(30),
        };
        assert_eq!(
            amendment_direction(&slot, &slot_refresh).expect("ordered"),
            AmendmentDirection::Equivalent,
            "the cache TTL shapes freshness, not admission"
        );
    }

    #[test]
    fn version_hash_binds_the_exact_row_and_version() {
        let row = seed_rule(&BookingAntiAbuseRule::RequiredIntake {
            min_chars: nz16(10),
        });
        let hash = booking_rule_row_version_hash(&row).expect("hash");
        assert_eq!(hash, booking_rule_row_version_hash(&row).expect("hash"));

        let mut bumped = row.clone();
        bumped.version = 2;
        assert_ne!(hash, booking_rule_row_version_hash(&bumped).expect("hash"));

        let mut stamped_elsewhere = row;
        stamped_elsewhere.amended_at += 1;
        assert_ne!(
            hash,
            booking_rule_row_version_hash(&stamped_elsewhere).expect("hash"),
            "any field move re-keys the binding"
        );
    }

    #[test]
    fn invalid_email_prompts_but_does_not_hard_block() {
        let rows = vec![
            seed_rule(&BookingAntiAbuseRule::EmailPromptToCorrect {
                check_syntax: true,
                check_mx: true,
                check_disposable_domain: true,
            }),
            seed_rule(&BookingAntiAbuseRule::HoneypotAndSubmitFloor {
                min_submit_millis: nz64(1),
            }),
        ];
        let mut facts = facts();

        facts.email = Some(EmailValidationEvidence {
            syntax_valid: false,
            mx_present: Some(true),
            disposable_domain: false,
        });
        assert!(matches!(
            evaluate_booking_request(&rows, &facts),
            BookingAbuseVerdict::PromptCorrection { field: "email", .. }
        ));

        facts.email = Some(EmailValidationEvidence {
            syntax_valid: true,
            mx_present: Some(false),
            disposable_domain: false,
        });
        assert!(matches!(
            evaluate_booking_request(&rows, &facts),
            BookingAbuseVerdict::PromptCorrection { field: "email", .. }
        ));

        facts.email = Some(EmailValidationEvidence {
            syntax_valid: true,
            mx_present: Some(true),
            disposable_domain: true,
        });
        assert!(matches!(
            evaluate_booking_request(&rows, &facts),
            BookingAbuseVerdict::PromptCorrection { field: "email", .. }
        ));

        // An unperformed MX check is no signal: the request proceeds.
        facts.email = Some(EmailValidationEvidence {
            syntax_valid: true,
            mx_present: None,
            disposable_domain: false,
        });
        assert_eq!(
            evaluate_booking_request(&rows, &facts),
            BookingAbuseVerdict::Allow
        );

        // Multi-signal inconsistency without the quarantine row under-blocks
        // into a prompt rather than any permanent denial.
        facts.email = Some(EmailValidationEvidence {
            syntax_valid: false,
            mx_present: Some(false),
            disposable_domain: true,
        });
        let verdict = evaluate_booking_request(&rows, &facts);
        assert!(
            matches!(
                verdict,
                BookingAbuseVerdict::PromptCorrection { field: "email", .. }
            ),
            "never a hard block: {verdict:?}"
        );
    }

    #[test]
    fn borderline_submission_builds_pending_review_inbox_group() {
        let (_dir, vault) = open_vault();
        let rows = vec![
            seed_rule(&BookingAntiAbuseRule::EmailPromptToCorrect {
                check_syntax: true,
                check_mx: true,
                check_disposable_domain: true,
            }),
            seed_rule(&BookingAntiAbuseRule::QuarantineBorderline),
        ];
        let mut facts = facts();
        facts.email = Some(EmailValidationEvidence {
            syntax_valid: true,
            mx_present: Some(false),
            disposable_domain: true,
        });
        let verdict = evaluate_booking_request(&rows, &facts);
        let BookingAbuseVerdict::Quarantine { reason } = verdict else {
            panic!("two live negatives route to quarantine: {verdict:?}");
        };

        // The quarantine claim names the page as its subject through the
        // ordinary claim door, so the fixture page exists the way a
        // published booking page does.
        vault
            .put_entity(
                &facts.page_ref,
                crate::registry::ENTITY_TYPE_EVENT,
                crate::temporal::TimeRange { start: 1, end: 1 },
                1,
                b"booking page fixture",
            )
            .expect("page entity");
        let receipt =
            quarantine_borderline_submission(&vault, &facts, &reason).expect("quarantine");

        // The pending-review pattern, verified through the same store doors
        // `inbox.rs`'s pending-group construction reads and writes.
        let run_id = {
            let rtxn = vault.store.env.read_txn().expect("read txn");
            let claim = EntityId::from_bytes(receipt.claim_id).expect("claim id bytes");
            let pending = vault
                .store
                .pending_gate_consent_in_txn(&rtxn, &claim)
                .expect("pending read")
                .expect("pending row present");
            assert_eq!(pending.claim_id, receipt.claim_id);
            assert_eq!(pending.version, 0);
            assert!(
                !pending.diff_handle.is_empty(),
                "the consent binding handle the pattern requires"
            );
            assert_eq!(pending.reason_codes, receipt.reason_codes);
            assert!(
                pending
                    .reason_codes
                    .iter()
                    .all(|code| code.starts_with("gate.pending.")),
                "exactly the pending-review reason family the inbox pattern carries"
            );
            let decision = vault
                .store
                .gate_decision_in_txn(&rtxn, pending.decision_id)
                .expect("decision read")
                .expect("decision row present");
            assert_eq!(decision.outcome, "pending");
            assert_eq!(decision.claim_id, Some(receipt.claim_id));
            assert_eq!(
                decision.diff_handle, pending.diff_handle,
                "the decision and the pending row bind one claim body"
            );

            // The scan door behind pending-group enumeration still surfaces
            // the row.
            let scanned = vault
                .store
                .pending_gate_consents_in_txn(&rtxn, 50)
                .expect("pending scan");
            assert!(
                scanned.iter().any(|row| row.claim_id == receipt.claim_id),
                "the pending-review scan must enumerate the quarantined submission"
            );

            pending
                .dreamer_run_id
                .expect("a quarantine row stamps a pending-review run id")
        };

        // The minted CLAIM body is durable at the content-keyed id.
        let claim = EntityId::from_bytes(receipt.claim_id).expect("claim id bytes");
        let body = vault
            .get_claim(&claim)
            .expect("claim read")
            .expect("quarantine claim stored");
        assert_eq!(body.predicate, QUARANTINE_CLAIM_PREDICATE);
        assert_eq!(body.subject, ClaimSubject::Entity(facts.page_ref));
        assert_eq!(body.approval, ClaimApprovalStatus::Proposed);

        // Done-means: `Vault::inbox_groups` with a nonzero limit returns the
        // quarantined submission as a pending-review group member — not
        // merely a raw pending-scan row. Review-everything is the dial
        // stance that shows every open member; under the default
        // exceptions-only dial the card waits held, never lost.
        vault
            .set_inbox_review_dial(crate::inbox::InboxReviewDial::ReviewEverything)
            .expect("review dial");
        let groups = vault
            .inbox_groups(crate::inbox::InboxQuery::new(10))
            .expect("inbox groups");
        let group = groups
            .iter()
            .find(|group| group.run_id == run_id)
            .expect("the quarantine run projects a pending-review inbox group");
        assert!(
            group
                .members
                .iter()
                .any(|member| member.claim_id == receipt.claim_ref),
            "the quarantined claim surfaces as a pending-review card member: {groups:?}"
        );
        assert_eq!(group.new_claim_count, 1);
    }

    #[test]
    fn booking_rule_row_ids_bind_full_page_and_event_identity() {
        // Two pages sharing their first four id bytes — the prefix the old
        // derivation keyed on — must still own distinct rows.
        let mut head_a = [0x61_u8; 16];
        head_a[4..].copy_from_slice(&[0x00; 12]);
        let mut head_b = [0x61_u8; 16];
        head_b[4..].copy_from_slice(&[0xCC; 12]);
        let page_a = EntityId::from_bytes(head_a).expect("page a");
        let page_b = EntityId::from_bytes(head_b).expect("page b");
        let event = EventTypeKey("intro-call".to_owned());
        let rule = BookingAntiAbuseRule::SlotListRate {
            per_minute_per_ip: nz32(120),
            cache_ttl_secs: nz64(45),
        };
        let scope_a = BookingRuleScope {
            page_ref: page_a,
            event_type: Some(event.clone()),
        };
        let scope_b = BookingRuleScope {
            page_ref: page_b,
            event_type: Some(event.clone()),
        };

        let id_a = booking_rule_row_id(&scope_a, &rule);
        let id_b = booking_rule_row_id(&scope_b, &rule);
        assert_ne!(
            id_a, id_b,
            "prefix-colliding pages still own distinct row ids"
        );
        assert_ne!(
            rule_row_key(&id_a),
            rule_row_key(&id_b),
            "distinct ids never share a storage key"
        );

        // The full page hex and the full 32-byte event-key digest are bound —
        // no 8/4-hex truncation anywhere in the id.
        assert!(id_a.contains(&page_a.to_hex()));
        let event_digest = digest_with(RULE_KEY_DOMAIN, event.0.as_bytes());
        assert!(id_a.contains(&hex_lower(&event_digest)));
        assert!(id_a.len() <= ROW_ID_MAX_LEN);

        // Both pages activate their full stack at the expected first
        // version: the second page never trips the first page's
        // "already exists".
        let (_dir, vault) = open_vault();
        for page in [page_a, page_b] {
            let rows = default_booking_anti_abuse_rows(page, Some(event.clone()), &owner_config())
                .expect("seed rows");
            for row in rows {
                let outcome = apply_rule_amendment(&vault, 0, row, None).expect("activate");
                assert_eq!(outcome.stored.version, 1);
            }
        }
        let listed_a = booking_anti_abuse_rules(&vault, &scope_a).expect("list a");
        let listed_b = booking_anti_abuse_rules(&vault, &scope_b).expect("list b");
        assert_eq!(listed_a.len(), 10, "page a owns its ten rows");
        assert_eq!(listed_b.len(), 10, "page b owns its ten rows");
    }

    #[test]
    fn honeypot_signal_requires_an_activated_honeypot_floor_row() {
        let mut facts = facts();
        facts.honeypot_nonempty = true;

        // No rows at all: the honeypot signal must not invent a rejection —
        // the sole public activation path decides which controls fire.
        let verdict = evaluate_booking_request(&[], &facts);
        assert_ne!(
            verdict,
            BookingAbuseVerdict::SilentHttp200Reject,
            "an unactivated honeypot control must not fire: {verdict:?}"
        );

        // Rows in scope that omit HoneypotAndSubmitFloor: the same law.
        let rows = vec![seed_rule(&BookingAntiAbuseRule::RequiredIntake {
            min_chars: nz16(10),
        })];
        let verdict = evaluate_booking_request(&rows, &facts);
        assert_ne!(
            verdict,
            BookingAbuseVerdict::SilentHttp200Reject,
            "a scope without the honeypot row must not fire it: {verdict:?}"
        );

        // With the row activated, the control keeps its silent-200 shape.
        let rows = seed_rows();
        let verdict = evaluate_booking_request(&rows, &facts);
        assert_eq!(
            verdict,
            BookingAbuseVerdict::SilentHttp200Reject,
            "the activated honeypot row still rejects silently"
        );
    }

    #[test]
    fn slot_list_cache_window_is_bound_and_lazy_expiring() {
        let (_dir, vault) = open_vault();
        let page = id(PAGE);
        let event = EventTypeKey("intro-call".to_owned());
        let body = b"{\"slots\":[]}".to_vec();

        assert!(
            write_slot_list_cache(&vault, &page, Some(&event), &body, nz64(29), 1_000).is_err(),
            "TTL below the ratified window refuses"
        );
        assert!(
            write_slot_list_cache(&vault, &page, Some(&event), &body, nz64(61), 1_000).is_err(),
            "TTL above the ratified window refuses"
        );
        write_slot_list_cache(&vault, &page, Some(&event), &body, nz64(45), 1_000)
            .expect("cache write");

        assert_eq!(
            read_slot_list_cache(&vault, &page, Some(&event), 1_000).expect("read"),
            Some(body.clone())
        );
        assert_eq!(
            read_slot_list_cache(&vault, &page, Some(&event), 1_044).expect("read"),
            Some(body)
        );
        assert_eq!(
            read_slot_list_cache(&vault, &page, Some(&event), 1_045).expect("read"),
            None,
            "the 45s window closes exactly at 1_045"
        );

        let other_page = id(OTHER_PAGE);
        assert_eq!(
            read_slot_list_cache(&vault, &other_page, Some(&event), 1_000).expect("read"),
            None,
            "cache entries are scope-keyed"
        );
        assert_eq!(
            read_slot_list_cache(&vault, &page, None, 1_000).expect("read"),
            None,
            "page-wide and type-scoped entries never alias"
        );
    }

    #[test]
    fn rate_counters_window_rollover_and_reset() {
        let (_dir, vault) = open_vault();
        let ip = booking_ip_hash("198.51.100.7");
        assert_eq!(
            observe_slot_list_request(&vault, &ip, nz32(2), 120).expect("count"),
            BookingRateDecision::Allowed
        );
        assert_eq!(
            observe_slot_list_request(&vault, &ip, nz32(2), 150).expect("count"),
            BookingRateDecision::Allowed
        );
        let exceeded = observe_slot_list_request(&vault, &ip, nz32(2), 179).expect("count");
        assert_eq!(
            exceeded,
            BookingRateDecision::Exceeded {
                retry_after_secs: 60 - 179 % 60
            }
        );
        // A rejected request consumed nothing: re-asking in the same window
        // stays rejected rather than sneaking a token in.
        assert_eq!(
            observe_slot_list_request(&vault, &ip, nz32(2), 179).expect("count"),
            exceeded
        );
        // The next window overwrites the same key rather than stacking rows.
        assert_eq!(
            observe_slot_list_request(&vault, &ip, nz32(2), 180).expect("count"),
            BookingRateDecision::Allowed
        );
    }

    #[test]
    fn quarantine_claim_identity_binds_event_type_presence_and_value() {
        let (_dir, vault) = open_vault();
        let mut facts_a = facts();
        facts_a.event_type = Some(EventTypeKey("intro-call".to_owned()));
        let mut facts_b = facts();
        facts_b.event_type = Some(EventTypeKey("sales-call".to_owned()));
        let shared_millis = 1_700_000_000_000_u64;
        facts_a.submitted_at_millis = shared_millis;
        facts_b.submitted_at_millis = shared_millis;
        facts_a.email_hash = None;
        facts_b.email_hash = None;
        let reason = "quarantine-test";
        for facts in [&facts_a, &facts_b] {
            vault
                .put_entity(
                    &facts.page_ref,
                    crate::registry::ENTITY_TYPE_EVENT,
                    crate::temporal::TimeRange { start: 1, end: 1 },
                    1,
                    b"booking page fixture",
                )
                .ok();
        }
        let receipt_a =
            quarantine_borderline_submission(&vault, &facts_a, reason).expect("quarantine a");
        let receipt_b =
            quarantine_borderline_submission(&vault, &facts_b, reason).expect("quarantine b");
        assert_ne!(
            receipt_a.claim_id, receipt_b.claim_id,
            "distinct event types must mint distinct claim ids"
        );
        assert_ne!(
            receipt_a.claim_ref, receipt_b.claim_ref,
            "claim_ref hex must differ"
        );
        let run_a = format!(
            "{QUARANTINE_RUN_ID_PREFIX}{}",
            hex_lower(&receipt_a.claim_id)
        );
        let run_b = format!(
            "{QUARANTINE_RUN_ID_PREFIX}{}",
            hex_lower(&receipt_b.claim_id)
        );
        assert_ne!(run_a, run_b, "synthetic run ids must differ across events");
        {
            let rtxn = vault.store.env.read_txn().expect("read txn");
            let claim_a = EntityId::from_bytes(receipt_a.claim_id).expect("claim a bytes");
            let claim_b = EntityId::from_bytes(receipt_b.claim_id).expect("claim b bytes");
            let pending_a = vault
                .store
                .pending_gate_consent_in_txn(&rtxn, &claim_a)
                .expect("pending a read")
                .expect("pending a present");
            let pending_b = vault
                .store
                .pending_gate_consent_in_txn(&rtxn, &claim_b)
                .expect("pending b read")
                .expect("pending b present");
            assert_eq!(pending_a.claim_id, receipt_a.claim_id);
            assert_eq!(pending_b.claim_id, receipt_b.claim_id);
            assert_ne!(pending_a.decision_id, pending_b.decision_id);
        }
        {
            let claim_a = EntityId::from_bytes(receipt_a.claim_id).expect("claim a bytes");
            let claim_b = EntityId::from_bytes(receipt_b.claim_id).expect("claim b bytes");
            let body_a = vault
                .get_claim(&claim_a)
                .expect("claim a read")
                .expect("claim a present");
            let body_b = vault
                .get_claim(&claim_b)
                .expect("claim b read")
                .expect("claim b present");
            let val_a = body_a.value.clone();
            let val_b = body_b.value.clone();
            assert_ne!(val_a, val_b, "claim bodies must carry distinct event_type");
            let map_a = match val_a {
                rmpv::Value::Map(m) => m,
                _ => panic!("expected map"),
            };
            let map_b = match val_b {
                rmpv::Value::Map(m) => m,
                _ => panic!("expected map"),
            };
            let find_event = |map: &Vec<(rmpv::Value, rmpv::Value)>| {
                map.iter()
                    .find(|(k, _)| *k == rmpv::Value::from("event_type"))
                    .map(|(_, v)| v.clone())
            };
            assert_eq!(find_event(&map_a), Some(rmpv::Value::from("intro-call")));
            assert_eq!(find_event(&map_b), Some(rmpv::Value::from("sales-call")));
        }
        let mut facts_none = facts();
        facts_none.event_type = None;
        facts_none.submitted_at_millis = shared_millis;
        facts_none.email_hash = None;
        vault
            .put_entity(
                &facts_none.page_ref,
                crate::registry::ENTITY_TYPE_EVENT,
                crate::temporal::TimeRange { start: 1, end: 1 },
                1,
                b"booking page fixture",
            )
            .ok();
        let receipt_none =
            quarantine_borderline_submission(&vault, &facts_none, reason).expect("quarantine none");
        assert_ne!(
            receipt_a.claim_id, receipt_none.claim_id,
            "Some(event) vs None must give distinct claim ids"
        );
        let receipt_a2 =
            quarantine_borderline_submission(&vault, &facts_a, reason).expect("quarantine a retry");
        assert_eq!(
            receipt_a.claim_id, receipt_a2.claim_id,
            "exact-duplicate retry must be idempotent on claim_id"
        );
        assert_eq!(
            receipt_a.claim_ref, receipt_a2.claim_ref,
            "claim_ref must be stable"
        );
        {
            let rtxn = vault.store.env.read_txn().expect("read txn");
            let claim = EntityId::from_bytes(receipt_a.claim_id).expect("claim bytes");
            let pending = vault
                .store
                .pending_gate_consent_in_txn(&rtxn, &claim)
                .expect("pending read")
                .expect("pending present");
            assert_eq!(pending.claim_id, receipt_a.claim_id);
        }
    }

    #[test]
    fn quarantine_retry_after_rejection_replays_without_reappending() {
        let (_dir, vault) = open_vault();
        let facts = facts();
        vault
            .put_entity(
                &facts.page_ref,
                crate::registry::ENTITY_TYPE_EVENT,
                crate::temporal::TimeRange { start: 1, end: 1 },
                1,
                b"booking page fixture",
            )
            .expect("page entity");

        let receipt = quarantine_borderline_submission(&vault, &facts, "quarantine-test")
            .expect("initial quarantine");
        let claim_ref = EntityId::from_bytes(receipt.claim_id).expect("claim id");
        vault
            .with_write_txn(|wtxn| {
                vault.store.close_pending_gate_consent_in_txn(
                    wtxn,
                    &claim_ref,
                    2,
                    "rejected",
                    vec!["gate.pending.bundle_rejected".to_owned()],
                    None,
                )
            })
            .expect("close pending quarantine")
            .expect("rejection receipt");
        let decisions_before_retry = vault.gate_decisions(10).expect("decisions");

        let replay = quarantine_borderline_submission(&vault, &facts, "quarantine-test")
            .expect("retry after rejection replays");
        assert_eq!(replay, receipt, "the original receipt remains stable");
        assert_eq!(
            vault.gate_decisions(10).expect("decisions"),
            decisions_before_retry,
            "retry must not append a colliding pending decision"
        );
        let rtxn = vault.store.env.read_txn().expect("read txn");
        assert!(
            vault
                .store
                .pending_gate_consent_in_txn(&rtxn, &claim_ref)
                .expect("pending read")
                .is_none(),
            "retry must not resurrect the rejected pending row"
        );
    }

    #[test]
    fn booking_rule_storage_is_disjoint_from_campaign_compliance() {
        // Assertion needles are spelled as byte values so this source file
        // keeps exactly one line-level oracle hit: this test's own name.
        let lane_word = needle(&[0x63, 0x61, 0x6d, 0x70, 0x61, 0x69, 0x67, 0x6e]);
        let lane_mod = needle(&[0x63, 0x6f, 0x6d, 0x70, 0x6c, 0x69, 0x61, 0x6e, 0x63, 0x65]);
        let lane_prefix = needle(&[
            0x63, 0x61, 0x6d, 0x70, 0x61, 0x69, 0x67, 0x6e, 0x3a, 0x63, 0x6f, 0x6d, 0x70, 0x6c,
            0x69, 0x61, 0x6e, 0x63, 0x65, 0x3a,
        ]);
        let lane_crate_path = needle(&[
            0x63, 0x72, 0x61, 0x74, 0x65, 0x3a, 0x3a, 0x63, 0x61, 0x6d, 0x70, 0x61, 0x69, 0x67,
            0x6e,
        ]);
        let registry_file = needle(&[
            0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x72, 0x79, 0x2e, 0x72, 0x73,
        ]);

        let src = include_str!("anti_abuse.rs");
        let mut joined_token_lines = 0;
        for (number, line) in src.lines().enumerate() {
            assert!(
                !line.contains(&lane_crate_path),
                "no import from the other lane's module tree (line {})",
                number + 1
            );
            assert!(
                !line.contains(&registry_file),
                "no structural-registry pointer (line {})",
                number + 1
            );
            if line.contains(&lane_word) && line.contains(&lane_mod) {
                joined_token_lines += 1;
                assert!(
                    line.contains("booking_rule_storage_is_disjoint_from"),
                    "only this named disjointness assertion joins the two tokens (line {})",
                    number + 1
                );
            }
        }
        assert_eq!(
            joined_token_lines, 1,
            "this test's name is the single oracle-visible token join"
        );

        // The other lane's meta prefix neither nests nor is nested by ours.
        assert!(!BOOKING_ANTI_ABUSE_META_PREFIX.starts_with(lane_prefix.as_bytes()));
        assert!(
            !lane_prefix
                .as_bytes()
                .starts_with(BOOKING_ANTI_ABUSE_META_PREFIX)
        );
        assert_eq!(BOOKING_ANTI_ABUSE_META_PREFIX, b"booking:anti_abuse:v1:");

        // Behavioural arm: everything this module stores — rules plus the
        // per-activation notices — sits under the booking-only prefix, and
        // the rule rows round-trip through the public reader.
        let (_dir, vault) = open_vault();
        install_rows(&vault, &seed_rows());
        let rows = booking_anti_abuse_rules(&vault, &scope()).expect("read rows");
        assert_eq!(rows.len(), 10);
        let notices = booking_anti_abuse_notices(&vault).expect("notices");
        assert_eq!(notices.len(), 10);

        let rtxn = vault.store.env.read_txn().expect("read txn");
        let mut ours = 0;
        let iter = vault
            .store
            .vault_meta
            .prefix_iter(&rtxn, BOOKING_ANTI_ABUSE_META_PREFIX)
            .expect("prefix scan");
        for entry in iter {
            let (key, _) = entry.expect("meta row");
            assert!(key.starts_with(BOOKING_ANTI_ABUSE_META_PREFIX));
            ours += 1;
        }
        assert_eq!(ours, 20, "ten rule rows plus their ten activation notices");
    }

    fn needle(bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec()).expect("ascii needle")
    }
}
