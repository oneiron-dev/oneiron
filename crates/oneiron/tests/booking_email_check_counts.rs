//! The email-check counts of the `EmailPromptToCorrect` rule row (Engine
//! RULING BOOKING-THRESHOLD-HOME = A, 15 Nov 19:42; TASK 19:29 item 3).
//!
//! One failed email check prompts a correction and two route the submission
//! to quarantine. Main hard-codes both counts in the evaluator, so an owner
//! cannot pick them. The counts are now two fields of the row, with today's
//! values as their defaults: `prompt_at_failed_checks` (1) and
//! `quarantine_at_failed_checks` (2). A lower count is the tighter row, so an
//! amendment that lowers one takes effect at once and one that raises it
//! waits for the owner's stamp (ARCH-0062 §6).
//!
//! The stored change is "keep": a row stored before the fields existed reads
//! 1 and 2, and a row holding those counts encodes to the bytes it had
//! before, so its version hash and its manifest bytes do not move.
//!
//! The evaluator is pure, so these tests build rule rows and request facts
//! on public paths and need no vault. Main has no count fields, so the red
//! run is main plus the two fields (and their serde defaults) with main's
//! evaluator, comparator and validator.

use std::num::NonZeroU8;

use oneiron::EntityId;
use oneiron::booking::EventTypeKey;
use oneiron::booking::anti_abuse::{
    AmendmentDirection, BookingAbuseVerdict, BookingAntiAbuseRule, BookingAntiAbuseRuleRow,
    BookingRequestFacts, BookingRuleScope, EmailValidationEvidence, amendment_direction,
    booking_rule_row_id, evaluate_booking_book_request, validate_rule_row,
};
use serde::Serialize;

const PAGE: u8 = 0x51;
const OWNER: u8 = 0x52;

fn page() -> EntityId {
    EntityId::from_bytes([PAGE; 16]).expect("page id")
}

fn intro_call() -> EventTypeKey {
    EventTypeKey("intro-call".to_owned())
}

fn count(value: u8) -> NonZeroU8 {
    NonZeroU8::new(value).expect("a count is non-zero")
}

/// The email row with every check on and the given counts.
fn email_rule(prompt_at: u8, quarantine_at: u8) -> BookingAntiAbuseRule {
    BookingAntiAbuseRule::EmailPromptToCorrect {
        check_syntax: true,
        check_mx: true,
        check_disposable_domain: true,
        prompt_at_failed_checks: count(prompt_at),
        quarantine_at_failed_checks: count(quarantine_at),
    }
}

fn row(event_type: Option<EventTypeKey>, rule: BookingAntiAbuseRule) -> BookingAntiAbuseRuleRow {
    let scope = BookingRuleScope {
        page_ref: page(),
        event_type,
    };
    BookingAntiAbuseRuleRow {
        row_id: booking_rule_row_id(&scope, &rule),
        scope,
        rule,
        version: 1,
        amended_at: 1_777_777_777,
        amended_by: EntityId::from_bytes([OWNER; 16]).expect("owner id"),
        owner_stamp_ref: None,
    }
}

/// The page-wide email row with the given counts, plus the quarantine row.
fn page_rows(prompt_at: u8, quarantine_at: u8) -> Vec<BookingAntiAbuseRuleRow> {
    vec![
        row(None, email_rule(prompt_at, quarantine_at)),
        row(None, BookingAntiAbuseRule::QuarantineBorderline),
    ]
}

/// A confirmation whose address fails `failed` of the three checks: first
/// the disposable-domain check, then the MX check, then the syntax check.
fn facts(event_type: Option<EventTypeKey>, failed: u8) -> BookingRequestFacts {
    BookingRequestFacts {
        page_ref: page(),
        event_type,
        ip_hash: [1; 32],
        email_hash: Some([2; 32]),
        session_hash: Some([3; 32]),
        started_at_millis: 0,
        submitted_at_millis: 60_000,
        submission_fingerprint: [4; 32],
        selected_slot_hash: [5; 32],
        intake_content_hash: [6; 32],
        honeypot_nonempty: false,
        intake_chars: 200,
        active_future_bookings_for_email: 0,
        active_holds_for_session: 0,
        email: Some(EmailValidationEvidence {
            syntax_valid: failed < 3,
            mx_present: Some(failed < 2),
            disposable_domain: failed >= 1,
        }),
    }
}

fn is_quarantine(verdict: &BookingAbuseVerdict) -> bool {
    matches!(verdict, BookingAbuseVerdict::Quarantine { .. })
}

fn is_email_prompt(verdict: &BookingAbuseVerdict) -> bool {
    matches!(
        verdict,
        BookingAbuseVerdict::PromptCorrection { field: "email", .. }
    )
}

#[test]
fn a_row_that_quarantines_at_three_failed_checks_prompts_on_two() {
    let rows = page_rows(1, 3);
    let two = evaluate_booking_book_request(&rows, &facts(None, 2));
    assert!(
        is_email_prompt(&two),
        "two failed checks under a quarantine count of 3 prompt, got {two:?}"
    );
    let three = evaluate_booking_book_request(&rows, &facts(None, 3));
    assert!(
        is_quarantine(&three),
        "three failed checks meet a quarantine count of 3, got {three:?}"
    );
}

#[test]
fn a_row_that_prompts_at_two_failed_checks_lets_one_failed_check_book() {
    let rows = page_rows(2, 3);
    let one = evaluate_booking_book_request(&rows, &facts(None, 1));
    assert_eq!(
        one,
        BookingAbuseVerdict::Allow,
        "one failed check under a prompt count of 2 books"
    );
    let two = evaluate_booking_book_request(&rows, &facts(None, 2));
    assert!(
        is_email_prompt(&two),
        "two failed checks meet a prompt count of 2, got {two:?}"
    );
}

#[test]
fn the_seeded_counts_prompt_at_one_and_quarantine_at_two_failed_checks() {
    let rows = page_rows(1, 2);
    assert_eq!(
        evaluate_booking_book_request(&rows, &facts(None, 0)),
        BookingAbuseVerdict::Allow
    );
    let one = evaluate_booking_book_request(&rows, &facts(None, 1));
    assert!(
        is_email_prompt(&one),
        "one failed check prompts, got {one:?}"
    );
    let two = evaluate_booking_book_request(&rows, &facts(None, 2));
    assert!(
        is_quarantine(&two),
        "two failed checks quarantine, got {two:?}"
    );
    // With no quarantine row in scope, a met quarantine count prompts.
    let without_quarantine = vec![row(None, email_rule(1, 2))];
    let two = evaluate_booking_book_request(&without_quarantine, &facts(None, 2));
    assert!(
        is_email_prompt(&two),
        "with no quarantine row, two failed checks prompt, got {two:?}"
    );
}

#[test]
fn the_strictest_email_row_in_scope_decides_each_count() {
    // The page-wide row quarantines at 3; the intro call's own row keeps 2.
    let mut rows = page_rows(1, 3);
    rows.push(row(Some(intro_call()), email_rule(1, 2)));
    let intro = evaluate_booking_book_request(&rows, &facts(Some(intro_call()), 2));
    assert!(
        is_quarantine(&intro),
        "the intro call's stricter row quarantines at 2, got {intro:?}"
    );
    let other = EventTypeKey("long-consult".to_owned());
    let page_wide = evaluate_booking_book_request(&rows, &facts(Some(other), 2));
    assert!(
        is_email_prompt(&page_wide),
        "an event type with only the page-wide row prompts at 2, got {page_wide:?}"
    );
}

#[test]
fn lowering_an_email_count_tightens_and_raising_it_loosens() {
    let amend = |from: (u8, u8), to: (u8, u8)| {
        let current = row(None, email_rule(from.0, from.1));
        let mut proposed = row(None, email_rule(to.0, to.1));
        proposed.version = current.version + 1;
        amendment_direction(&current, &proposed).expect("an orderable amendment")
    };
    assert_eq!(amend((1, 2), (1, 3)), AmendmentDirection::Loosening);
    assert_eq!(amend((1, 3), (1, 2)), AmendmentDirection::Tightening);
    assert_eq!(amend((2, 2), (1, 2)), AmendmentDirection::Tightening);
    assert_eq!(amend((1, 2), (2, 2)), AmendmentDirection::Loosening);
    assert_eq!(amend((1, 2), (1, 2)), AmendmentDirection::Equivalent);
}

#[test]
fn a_prompt_count_above_the_quarantine_count_is_refused() {
    assert!(
        validate_rule_row(&row(None, email_rule(3, 2))).is_err(),
        "prompting at 3 while quarantining at 2 is refused"
    );
    validate_rule_row(&row(None, email_rule(2, 2))).expect("equal counts are valid");
}

/// The email row as main declares it, before the count fields.
#[derive(Serialize)]
enum RuleBeforeCounts {
    EmailPromptToCorrect {
        check_syntax: bool,
        check_mx: bool,
        check_disposable_domain: bool,
    },
}

#[test]
fn a_row_stored_without_counts_reads_one_and_two_and_encodes_as_before() {
    let before = rmp_serde::to_vec_named(&RuleBeforeCounts::EmailPromptToCorrect {
        check_syntax: true,
        check_mx: false,
        check_disposable_domain: true,
    })
    .expect("encode the row as main stores it");
    let read: BookingAntiAbuseRule =
        rmp_serde::from_slice(&before).expect("a row without counts decodes");
    assert_eq!(
        read,
        BookingAntiAbuseRule::EmailPromptToCorrect {
            check_syntax: true,
            check_mx: false,
            check_disposable_domain: true,
            prompt_at_failed_checks: count(1),
            quarantine_at_failed_checks: count(2),
        }
    );
    assert_eq!(
        rmp_serde::to_vec_named(&read).expect("encode the default counts"),
        before,
        "the default counts encode to main's bytes"
    );
    let picked = email_rule(2, 3);
    let bytes = rmp_serde::to_vec_named(&picked).expect("encode picked counts");
    assert_ne!(bytes, before);
    let back: BookingAntiAbuseRule = rmp_serde::from_slice(&bytes).expect("decode picked counts");
    assert_eq!(back, picked, "picked counts round-trip");
}
