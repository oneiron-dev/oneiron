//! INBOX-RESIDUE PR-3b-3a: the anti-abuse law of rung 2's send (ARCH-0062
//! :145-151; Engine RULING RUNG2-ONE-ADDRESS = A, 15 Nov 17:12).
//!
//! A visitor's press that asks the page's agent to continue by email spends
//! the agent's sending reputation, so the owner's rule row bounds it: a
//! per-minute cap per IP and a page-wide day budget. The module bakes no
//! threshold; with no row in scope there is no bucket to spend. The press is
//! no form fill, so it is judged on the visitor's address alone, and a
//! doubtful address prompts a correction and never quarantines. Loosening a
//! threshold takes the owner's stamp, as for every other row.
//!
//! Red on #8130: `BookingAntiAbuseRule::Rung2SendRate`, the owner config's
//! rung-2 thresholds, `rung2_send_rate_knobs`, `evaluate_rung2_send_request`,
//! `observe_rung2_send_request` and `observe_rung2_page_send` do not exist
//! there, so this file does not build.
//! `cargo test --locked -p oneiron --all-features --test booking_rung2_send_rate`.

use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use oneiron::booking::EventTypeKey;
use oneiron::booking::anti_abuse::{
    AmendmentDirection, BookingAbuseVerdict, BookingAntiAbuseOwnerConfig, BookingAntiAbuseRule,
    BookingAntiAbuseRuleRow, BookingRateDecision, BookingRequestFacts, EmailValidationEvidence,
    amendment_direction, booking_email_hash, booking_ip_hash, booking_session_hash,
    default_booking_anti_abuse_rows, evaluate_rung2_send_request, observe_hold_request,
    observe_rung2_page_send, observe_rung2_send_request, rung2_send_rate_knobs,
};
use oneiron::{EntityId, Vault, VaultConfig};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Maps any error into the test's error with the step that failed.
fn at<E: std::fmt::Debug>(step: &'static str) -> impl FnOnce(E) -> Box<dyn std::error::Error> {
    move |error| format!("{step}: {error:?}").into()
}

/// The start of one UTC day.
const DAY: u64 = 1_800_000_000 - 1_800_000_000 % 86_400;
const EVENT_TYPE: &str = "intro";

fn nz32(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).expect("a non-zero fixture value")
}

fn page() -> EntityId {
    EntityId::from_bytes([0x71; 16]).expect("page id")
}

/// The owner's thresholds, with the rung-2 pair where the owner chose it.
fn owner_config(
    rung2_per_minute_per_ip: Option<u32>,
    rung2_per_day_per_page: Option<u32>,
) -> BookingAntiAbuseOwnerConfig {
    BookingAntiAbuseOwnerConfig {
        min_intake_chars: NonZeroU16::new(10).expect("non-zero"),
        normal_notice_secs: NonZeroU64::new(86_400).expect("non-zero"),
        high_value_notice_secs: NonZeroU64::new(172_800).expect("non-zero"),
        min_submit_millis: NonZeroU64::new(1_500).expect("non-zero"),
        slot_list_per_minute_per_ip: nz32(120),
        slot_list_cache_ttl_secs: NonZeroU64::new(45).expect("non-zero"),
        book_per_minute_per_ip: nz32(10),
        max_active_future_per_email: 1,
        max_active_holds_per_session: 1,
        hold_per_minute_per_ip: nz32(30),
        tentative_confirm_ttl_secs: NonZeroU64::new(900).expect("non-zero"),
        rung2_send_per_minute_per_ip: rung2_per_minute_per_ip.map(nz32),
        rung2_send_per_day_per_page: rung2_per_day_per_page.map(nz32),
    }
}

/// The owner's full seed stack for `event_type` (page-wide with `None`).
fn seed(
    event_type: Option<&str>,
    rung2_per_minute_per_ip: Option<u32>,
    rung2_per_day_per_page: Option<u32>,
) -> TestResult<Vec<BookingAntiAbuseRuleRow>> {
    default_booking_anti_abuse_rows(
        page(),
        event_type.map(|key| EventTypeKey(key.to_owned())),
        &owner_config(rung2_per_minute_per_ip, rung2_per_day_per_page),
    )
    .map_err(at("seed the owner's stack"))
}

/// A visitor's rung-2 press on the page: no form, so no honeypot, no submit
/// clock and no intake; the address it names has `email` as its evidence.
fn press(email: EmailValidationEvidence) -> BookingRequestFacts {
    BookingRequestFacts {
        page_ref: page(),
        event_type: Some(EventTypeKey(EVENT_TYPE.to_owned())),
        ip_hash: booking_ip_hash("192.0.2.10"),
        email_hash: Some(booking_email_hash("yuki@example.com")),
        session_hash: Some(booking_session_hash("visitor-session-1")),
        started_at_millis: 0,
        submitted_at_millis: 0,
        submission_fingerprint: [0; 32],
        selected_slot_hash: [0; 32],
        intake_content_hash: [0; 32],
        honeypot_nonempty: true,
        intake_chars: 0,
        active_future_bookings_for_email: 0,
        active_holds_for_session: 0,
        email: Some(email),
    }
}

fn evidence(syntax_valid: bool, mx_present: Option<bool>) -> EmailValidationEvidence {
    EmailValidationEvidence {
        syntax_valid,
        mx_present,
        disposable_domain: false,
    }
}

fn rung2_row(rows: &[BookingAntiAbuseRuleRow]) -> Option<&BookingAntiAbuseRuleRow> {
    rows.iter()
        .find(|row| matches!(row.rule, BookingAntiAbuseRule::Rung2SendRate { .. }))
}

#[test]
fn the_owner_seeds_the_rung2_send_rate_with_both_thresholds_or_none() -> TestResult {
    let rows = seed(None, Some(5), Some(50))?;
    let row = rung2_row(&rows).ok_or("the seed stack carries the rung-2 row")?;
    assert_eq!(
        row.rule,
        BookingAntiAbuseRule::Rung2SendRate {
            per_minute_per_ip: nz32(5),
            per_day_per_page: nz32(50),
        },
        "the owner's thresholds, none of the module's"
    );
    assert!(
        row.row_id
            .starts_with("booking.anti_abuse.rung2-send-rate."),
        "{}",
        row.row_id
    );

    assert!(
        rung2_row(&seed(None, None, None)?).is_none(),
        "no thresholds, no row"
    );
    for (per_minute, per_day) in [(Some(5), None), (None, Some(50))] {
        assert!(
            default_booking_anti_abuse_rows(page(), None, &owner_config(per_minute, per_day))
                .is_err(),
            "half a pair is refused: {per_minute:?} {per_day:?}"
        );
    }
    Ok(())
}

#[test]
fn the_strictest_rung2_send_knobs_govern_an_event_type() -> TestResult {
    let event = Some(EventTypeKey(EVENT_TYPE.to_owned()));
    let other = Some(EventTypeKey("follow-up".to_owned()));
    let mut rows = seed(None, Some(5), Some(50))?;
    rows.extend(seed(Some(EVENT_TYPE), Some(10), Some(20))?);

    assert_eq!(
        rung2_send_rate_knobs(&rows, &page(), &event),
        Some((nz32(5), nz32(20))),
        "the page-wide minute cap and the event type's narrower day budget"
    );
    assert_eq!(
        rung2_send_rate_knobs(&rows, &page(), &other),
        Some((nz32(5), nz32(50)))
    );
    assert_eq!(
        rung2_send_rate_knobs(&seed(None, None, None)?, &page(), &event),
        None,
        "no row, no knobs"
    );
    Ok(())
}

#[test]
fn a_rung2_send_is_judged_on_the_visitors_address_alone() -> TestResult {
    let rows = seed(None, Some(5), Some(50))?;
    assert!(
        rows.iter()
            .any(|row| row.rule == BookingAntiAbuseRule::QuarantineBorderline),
        "the stack seeds quarantine"
    );

    assert_eq!(
        evaluate_rung2_send_request(&rows, &press(evidence(true, Some(true)))),
        BookingAbuseVerdict::Allow,
        "a filled honeypot, no submit time and no intake are no evidence on a press"
    );
    assert!(matches!(
        evaluate_rung2_send_request(&rows, &press(evidence(false, Some(true)))),
        BookingAbuseVerdict::PromptCorrection { field: "email", .. }
    ));
    assert!(
        matches!(
            evaluate_rung2_send_request(&rows, &press(evidence(false, Some(false)))),
            BookingAbuseVerdict::PromptCorrection { field: "email", .. }
        ),
        "two failed checks prompt; a press writes nothing a quarantine could keep"
    );
    Ok(())
}

#[test]
fn the_per_ip_minute_bucket_refuses_past_its_cap() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default()).map_err(at("open"))?;
    let ip = booking_ip_hash("192.0.2.10");
    let cap = nz32(2);
    for _ in 0..2 {
        assert_eq!(
            observe_rung2_send_request(&vault, &ip, cap, DAY + 5).map_err(at("press"))?,
            BookingRateDecision::Allowed
        );
    }
    assert_eq!(
        observe_rung2_send_request(&vault, &ip, cap, DAY + 5).map_err(at("press"))?,
        BookingRateDecision::Exceeded {
            retry_after_secs: 55
        }
    );
    assert_eq!(
        observe_hold_request(&vault, &ip, cap, DAY + 5).map_err(at("hold"))?,
        BookingRateDecision::Allowed,
        "the press spends its own bucket, not the hold's"
    );
    assert_eq!(
        observe_rung2_send_request(&vault, &booking_ip_hash("192.0.2.11"), cap, DAY + 5)
            .map_err(at("press"))?,
        BookingRateDecision::Allowed,
        "another IP"
    );
    assert_eq!(
        observe_rung2_send_request(&vault, &ip, cap, DAY + 60).map_err(at("press"))?,
        BookingRateDecision::Allowed,
        "the next minute"
    );
    Ok(())
}

#[test]
fn the_page_day_budget_spans_every_visitor_and_resets_the_next_day() -> TestResult {
    let dir = tempfile::tempdir()?;
    let vault = Vault::open(dir.path(), VaultConfig::default()).map_err(at("open"))?;
    let budget = nz32(2);
    assert_eq!(
        observe_rung2_page_send(&vault, &page(), budget, DAY + 60).map_err(at("send"))?,
        BookingRateDecision::Allowed
    );
    assert_eq!(
        observe_rung2_page_send(&vault, &page(), budget, DAY + 3_600).map_err(at("send"))?,
        BookingRateDecision::Allowed,
        "an hour later, from any visitor"
    );
    assert_eq!(
        observe_rung2_page_send(&vault, &page(), budget, DAY + 7_200).map_err(at("send"))?,
        BookingRateDecision::Exceeded {
            retry_after_secs: 86_400 - 7_200
        },
        "the day's budget is spent until the next UTC day"
    );
    let other_page = EntityId::from_bytes([0x72; 16]).expect("page id");
    assert_eq!(
        observe_rung2_page_send(&vault, &other_page, budget, DAY + 7_200).map_err(at("send"))?,
        BookingRateDecision::Allowed,
        "another page"
    );
    assert_eq!(
        observe_rung2_page_send(&vault, &page(), budget, DAY + 86_400).map_err(at("send"))?,
        BookingRateDecision::Allowed,
        "the next day"
    );
    Ok(())
}

#[test]
fn loosening_a_rung2_send_rate_needs_the_owners_stamp() -> TestResult {
    let rows = seed(None, Some(5), Some(50))?;
    let current = rung2_row(&rows).ok_or("the rung-2 row")?.clone();
    let proposed = |per_minute: u32, per_day: u32| BookingAntiAbuseRuleRow {
        rule: BookingAntiAbuseRule::Rung2SendRate {
            per_minute_per_ip: nz32(per_minute),
            per_day_per_page: nz32(per_day),
        },
        version: current.version + 1,
        ..current.clone()
    };
    for (per_minute, per_day, direction) in [
        (5, 50, AmendmentDirection::Equivalent),
        (3, 50, AmendmentDirection::Tightening),
        (5, 20, AmendmentDirection::Tightening),
        (8, 50, AmendmentDirection::Loosening),
        (5, 80, AmendmentDirection::Loosening),
        (3, 80, AmendmentDirection::Loosening),
    ] {
        assert_eq!(
            amendment_direction(&current, &proposed(per_minute, per_day))
                .map_err(at("order the amendment"))?,
            direction,
            "{per_minute}/min, {per_day}/day"
        );
    }
    Ok(())
}
