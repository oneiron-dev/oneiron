//! The two settle rules UC-09 PR E names once (PLAN-UC-09 row E;
//! UC09-SCHEDULE-RETRY-SHIFT = A): the delay before a failed tagging
//! marker's next retry, and the time a notice dispatcher retries a send it
//! keeps (FIX 11660). The expected numbers are today's: each test passes on
//! the base and on the head, where the delay comes from the Schedule's
//! `retry_after` and the kept-send time from one fn beside `retry_at`.
//!
//! Doors: `test_doors::settle_backoff`.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron --all-features --test settle_backoff_rules`.
#![cfg(oneiron_test_support)]

use oneiron::tagging::TaggingBackoff;
use oneiron::test_doors::settle_backoff::{kept_send_backoff_until, tagging_retry_delay_secs};

fn backoff(first_secs: u64, max_secs: u64) -> TaggingBackoff {
    TaggingBackoff {
        first_secs,
        max_secs,
    }
}

#[test]
fn tagging_default_delay_doubles_from_five_seconds_to_the_five_minute_cap() {
    assert_eq!(TaggingBackoff::default(), backoff(5, 300));
    let doubled = [5, 10, 20, 40, 80, 160];
    for prior in 0..=40_u32 {
        let expected = doubled.get(prior as usize).copied().unwrap_or(300);
        assert_eq!(
            tagging_retry_delay_secs(backoff(5, 300), prior),
            expected,
            "prior retries {prior}"
        );
    }
}

#[test]
fn tagging_delay_doubles_from_one_second_to_a_million_second_cap() {
    for prior in 0..=40_u32 {
        let expected = if prior < 20 {
            1_u64 << prior
        } else {
            1_000_000
        };
        assert_eq!(
            tagging_retry_delay_secs(backoff(1, 1_000_000), prior),
            expected,
            "prior retries {prior}"
        );
    }
}

#[test]
fn tagging_delay_saturates_past_sixty_three_doublings() {
    let uncapped = backoff(1, u64::MAX);
    assert_eq!(tagging_retry_delay_secs(uncapped, 62), 1_u64 << 62);
    assert_eq!(tagging_retry_delay_secs(uncapped, 63), 1_u64 << 63);
    assert_eq!(tagging_retry_delay_secs(uncapped, 64), u64::MAX);
    assert_eq!(tagging_retry_delay_secs(uncapped, u32::MAX), u64::MAX);
    assert_eq!(tagging_retry_delay_secs(backoff(5, u64::MAX), 62), u64::MAX);
    assert_eq!(tagging_retry_delay_secs(backoff(5, 300), u32::MAX), 300);
    assert_eq!(tagging_retry_delay_secs(backoff(0, 300), 3), 0);
}

#[test]
fn a_kept_send_waits_a_minute_and_never_retries_before_its_receipt_edge() {
    let now = 1_000;
    assert_eq!(kept_send_backoff_until(now, None), 1_060);
    assert_eq!(kept_send_backoff_until(now, Some(0)), 1_060);
    assert_eq!(kept_send_backoff_until(now, Some(500)), 1_060);
    assert_eq!(kept_send_backoff_until(now, Some(1_060)), 1_060);
    assert_eq!(kept_send_backoff_until(now, Some(1_061)), 1_061);
    assert_eq!(kept_send_backoff_until(now, Some(90_000)), 90_000);
    assert_eq!(kept_send_backoff_until(u64::MAX - 10, None), u64::MAX);
}
