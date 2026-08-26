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

mod amendment;
mod evaluation;
mod quarantine;
mod rate;
mod rules;
mod storage;

pub use self::amendment::{
    amendment_direction, applicable_booking_anti_abuse_rules, apply_rule_amendment,
    booking_anti_abuse_notices, booking_anti_abuse_rules, booking_rule_row_version_hash,
};
pub use self::evaluation::{
    BookingAbuseVerdict, BookingRequestFacts, EmailValidationEvidence, book_rate_knobs,
    booking_email_hash, booking_ip_hash, booking_session_hash, evaluate_booking_book_request,
    evaluate_booking_hold_request, evaluate_booking_request, evaluate_booking_slot_list_request,
    hold_rate_knobs, quarantine_claim_id, server_submission_fingerprint, slot_list_rate_knobs,
};
pub use self::quarantine::{
    BookingQuarantineAdmission, BookingQuarantineReceipt, admit_quarantine_submission,
    quarantine_borderline_submission,
};
pub use self::rate::{
    BookingRateDecision, observe_book_request, observe_hold_request, observe_quarantine_request,
    observe_slot_list_request, read_slot_list_cache, write_slot_list_cache,
};
pub use self::rules::{
    AmendmentDirection, BookingAntiAbuseOwnerConfig, BookingAntiAbuseRule, BookingAntiAbuseRuleRow,
    BookingRuleOwnerStampBinding, BookingRuleScope, RuleAmendmentOutcome, booking_rule_row_id,
    booking_rule_variant_tag, default_booking_anti_abuse_rows, validate_rule_row,
};
pub use self::storage::BOOKING_ANTI_ABUSE_META_PREFIX;

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

// The module is named so `cargo test -p oneiron booking_anti_abuse` selects
// every test here (the ticket-gated command filters on the full test path,
// and `booking::anti_abuse::tests` does not contain the substring).
#[cfg(test)]
#[path = "tests.rs"]
mod booking_anti_abuse_tests;

// The flat anti_abuse.rs module used to provide these names to the test module
// through `use super::*`; after the directory split the seam re-imports them so
// the extracted sibling `tests.rs` resolves exactly as it did inline.
#[cfg(test)]
use self::storage::{
    QUARANTINE_CLAIM_PREDICATE, QUARANTINE_RATE_DOMAIN, QUARANTINE_RUN_ID_PREFIX, RATE_KEY_TAG,
    ROW_ID_MAX_LEN, RULE_KEY_DOMAIN, hex_lower, notice_key, rate_counter_key, rule_row_key,
};
#[cfg(test)]
use crate::Vault;
#[cfg(test)]
use crate::booking::BookingError;
#[cfg(test)]
use crate::booking::lifecycle::{digest_with, read_meta_bytes};
#[cfg(test)]
use crate::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
// Named by the intra-doc links in this module's header as well as by the
// extracted sibling tests; the `doc` arm keeps the names in scope for rustdoc,
// which does not enable `cfg(test)`.
#[cfg(any(test, doc))]
use crate::EntityId;
#[cfg(any(test, doc))]
use crate::booking::EventTypeKey;
